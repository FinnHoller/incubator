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

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/transparency-dev/tessera/api/layout"
)

func TestClonelog_Integration(t *testing.T) {
	const treeSize uint64 = 600 // 600 certs => 3 bundles (256, 256, 88)
	var transientFails atomic.Int32

	// Setup mock HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		cpContent := fmt.Sprintf("example.com/log\n%d\ncm9vdGhhc2g=\n", treeSize)
		_, _ = w.Write([]byte(cpContent))
	})

	bundleWidth := uint64(layout.EntryBundleWidth)
	numBundles := (treeSize + bundleWidth - 1) / bundleWidth

	for bIdx := uint64(0); bIdx < numBundles; bIdx++ {
		p := layout.PartialTileSize(0, bIdx, treeSize)
		relPath := "/" + layout.EntriesPath(bIdx, p)
		bIdxCopy := bIdx
		mux.HandleFunc(relPath, func(w http.ResponseWriter, r *http.Request) {
			// Fail first request to bundle 1 to test retry
			if bIdxCopy == 1 && transientFails.Add(1) == 1 {
				http.Error(w, "temporary error", http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(w, "tile_data_bundle_%d", bIdxCopy)
		})
	}

	ts := httptest.NewServer(mux)
	defer ts.Close()

	tempDir := t.TempDir()
	u, _ := url.Parse(ts.URL)

	var stats cloneStats
	client := ts.Client()

	// 1. Fetch and save checkpoint
	cpData, parsedSize, err := fetchAndSaveCheckpoint(context.Background(), client, u, tempDir, 3)
	if err != nil {
		t.Fatalf("fetchAndSaveCheckpoint failed: %v", err)
	}
	if parsedSize != treeSize {
		t.Fatalf("parsed treeSize = %d, want %d", parsedSize, treeSize)
	}
	if len(cpData) == 0 {
		t.Fatal("empty cpData")
	}

	// Verify checkpoint file exists
	savedCP, err := os.ReadFile(filepath.Join(tempDir, "checkpoint"))
	if err != nil {
		t.Fatalf("failed to read saved checkpoint: %v", err)
	}
	if string(savedCP) != string(cpData) {
		t.Fatalf("saved CP %q != %q", string(savedCP), string(cpData))
	}

	// 2. Download all bundles
	for bIdx := uint64(0); bIdx < numBundles; bIdx++ {
		if err := downloadBundle(context.Background(), client, u, tempDir, bIdx, treeSize, 3, &stats); err != nil {
			t.Fatalf("downloadBundle(%d) failed: %v", bIdx, err)
		}
	}

	if stats.downloadedTiles.Load() != numBundles {
		t.Fatalf("downloadedTiles = %d, want %d", stats.downloadedTiles.Load(), numBundles)
	}
	if stats.downloadedCerts.Load() != treeSize {
		t.Fatalf("downloadedCerts = %d, want %d", stats.downloadedCerts.Load(), treeSize)
	}

	// 3. Test skipping already-downloaded tiles on restart
	var statsRestart cloneStats
	for bIdx := uint64(0); bIdx < numBundles; bIdx++ {
		if err := downloadBundle(context.Background(), client, u, tempDir, bIdx, treeSize, 3, &statsRestart); err != nil {
			t.Fatalf("restart downloadBundle(%d) failed: %v", bIdx, err)
		}
	}
	if statsRestart.downloadedTiles.Load() != 0 {
		t.Fatalf("restart downloadedTiles = %d, want 0", statsRestart.downloadedTiles.Load())
	}
	if statsRestart.skippedTiles.Load() != numBundles {
		t.Fatalf("restart skippedTiles = %d, want %d", statsRestart.skippedTiles.Load(), numBundles)
	}
	if statsRestart.skippedCerts.Load() != treeSize {
		t.Fatalf("restart skippedCerts = %d, want %d", statsRestart.skippedCerts.Load(), treeSize)
	}
}
