// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/sunlight"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/tlog"
)

type bundleCandidate struct {
	relPath string
	sumDB   bool
}

// FetchEntryByIndex fetches the 256-entry bundle containing idx from baseURL and returns entry idx % 256.
// It supports C2SP tlog-tiles (tile/entries/...), partial tail bundles (.p/<rem> with fallback to full bundle),
// tile/data/... fallback, and SumDB record tiles (when baseURL contains "sum.golang.org" or tile/8/data/...).
func FetchEntryByIndex(ctx context.Context, httpClient *http.Client, baseURL string, idx, treeSize uint64) ([]byte, error) {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		return nil, errors.New("empty baseURL")
	}
	if treeSize > 0 && idx >= treeSize {
		return nil, fmt.Errorf("entry index %d out of bounds for tree size %d", idx, treeSize)
	}

	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL %q: %w", baseURL, err)
	}

	bIdx := idx / uint64(layout.EntryBundleWidth)
	offset := int(idx % uint64(layout.EntryBundleWidth))
	p := layout.PartialTileSize(0, bIdx, treeSize)
	isSumDB := strings.Contains(base, "sum.golang.org")

	var candidates []bundleCandidate
	addCandidate := func(rel string, sumDB bool) {
		for _, existing := range candidates {
			if existing.relPath == rel {
				return
			}
		}
		candidates = append(candidates, bundleCandidate{relPath: rel, sumDB: sumDB})
	}

	if isSumDB {
		if p != 0 {
			addCandidate(tlog.Tile{H: 8, L: -1, N: int64(bIdx), W: int(p)}.Path(), true)
		}
		addCandidate(tlog.Tile{H: 8, L: -1, N: int64(bIdx), W: 256}.Path(), true)
	}

	if p != 0 {
		entriesPartial := layout.EntriesPath(bIdx, p)
		addCandidate(entriesPartial, isSumDB)
	}
	entriesFull := layout.EntriesPath(bIdx, 0)
	addCandidate(entriesFull, isSumDB)

	if p != 0 {
		dataPartial := strings.Replace(layout.EntriesPath(bIdx, p), "tile/entries/", "tile/data/", 1)
		addCandidate(dataPartial, isSumDB)
	}
	dataFull := strings.Replace(entriesFull, "tile/entries/", "tile/data/", 1)
	addCandidate(dataFull, isSumDB)

	if !isSumDB {
		if p != 0 {
			addCandidate(tlog.Tile{H: 8, L: -1, N: int64(bIdx), W: int(p)}.Path(), true)
		}
		addCandidate(tlog.Tile{H: 8, L: -1, N: int64(bIdx), W: 256}.Path(), true)
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	var lastErr error
	for _, cand := range candidates {
		raw, found, fetchErr := readBundleResource(ctx, httpClient, u, cand.relPath)
		if fetchErr != nil {
			lastErr = fetchErr
			continue
		}
		if !found {
			continue
		}
		entry, parseErr := extractEntryFromBundle(raw, offset, cand.sumDB, strings.HasPrefix(cand.relPath, "tile/data/"))
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		return entry, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to fetch entry %d from %s: %w", idx, baseURL, lastErr)
	}
	return nil, fmt.Errorf("entry bundle for index %d not found at %s", idx, baseURL)
}

func readBundleResource(ctx context.Context, httpClient *http.Client, baseURL *url.URL, relPath string) ([]byte, bool, error) {
	if baseURL.Scheme == "" || baseURL.Scheme == "file" {
		root := baseURL.Path
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, false, nil
			}
			return nil, false, err
		}
		return data, true, nil
	}

	targetURL := baseURL.JoinPath(relPath).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "vindex/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP %s for %s", resp.Status, targetURL)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func extractEntryFromBundle(bundle []byte, offset int, sumDB bool, allowStaticCT bool) ([]byte, error) {
	if sumDB {
		rest := bundle
		for cur := 0; cur <= offset; cur++ {
			if len(rest) == 0 {
				return nil, fmt.Errorf("entry offset %d out of bounds in sumdb bundle (count %d)", offset, cur)
			}
			var entry, nextRest []byte
			if idx := bytes.Index(rest, []byte("\n\n")); idx >= 0 {
				entry, nextRest = rest[:idx+1], rest[idx+2:]
			} else {
				entry, nextRest = rest, nil
			}
			if cur == offset {
				return bytes.Clone(entry), nil
			}
			rest = nextRest
		}
	}

	var eb api.EntryBundle
	tileErr := eb.UnmarshalText(bundle)
	if tileErr == nil {
		if offset >= len(eb.Entries) {
			tileErr = fmt.Errorf("entry offset %d out of bounds in bundle (count %d)", offset, len(eb.Entries))
		} else {
			return bytes.Clone(eb.Entries[offset]), nil
		}
	}

	if allowStaticCT && tileErr != nil {
		rest := bundle
		for cur := 0; cur <= offset; cur++ {
			if len(rest) == 0 {
				return nil, fmt.Errorf("entry offset %d out of bounds in static-ct bundle (count %d)", offset, cur)
			}
			_, nextRest, err := sunlight.ReadTileLeaf(rest)
			if err != nil {
				return nil, tileErr
			}
			rawLeaf := rest[:len(rest)-len(nextRest)]
			if cur == offset {
				return bytes.Clone(rawLeaf), nil
			}
			rest = nextRest
		}
	}

	return nil, tileErr
}
