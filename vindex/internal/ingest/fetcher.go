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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/sunlight"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
)

// LeafAdapter adapts any leaf-by-leaf fetcher to the TileFetcher interface.
type LeafAdapter struct {
	CheckpointFn func(ctx context.Context) (*Checkpoint, error)
	LeafFn       func(ctx context.Context, idx uint64) ([]byte, error)
	BundleSize   uint64
}

// Checkpoint calls CheckpointFn.
func (a *LeafAdapter) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	return a.CheckpointFn(ctx)
}

// Leaf calls LeafFn.
func (a *LeafAdapter) Leaf(ctx context.Context, idx uint64) ([]byte, error) {
	leaf, err := a.LeafFn(ctx, idx)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, err
	}
	return leaf, nil
}

// FetchTiles fetches bundles of leaves by calling LeafFn.
func (a *LeafAdapter) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error) {
	bundleSz := a.BundleSize
	if bundleSz == 0 {
		bundleSz = DefaultBundleSize
	}

	var bundles []*LeafBundle
	currIdx := startLeafIdx
	endIdx := startLeafIdx + count

	for currIdx < endIdx {
		bCount := bundleSz
		if currIdx+bCount > endIdx {
			bCount = endIdx - currIdx
		}
		leaves := make([][]byte, 0, bCount)
		for i := uint64(0); i < bCount; i++ {
			leaf, err := a.LeafFn(ctx, currIdx+i)
			if err != nil {
				metrics.InputFetchErrorsTotal.Inc()
				return nil, fmt.Errorf("failed to fetch leaf %d: %w", currIdx+i, err)
			}
			leaves = append(leaves, leaf)
		}
		bundles = append(bundles, &LeafBundle{
			BundleIdx:    currIdx / bundleSz,
			StartLeafIdx: currIdx,
			Leaves:       leaves,
		})
		currIdx += bCount
	}

	var totalLeaves int
	for _, b := range bundles {
		totalLeaves += len(b.Leaves)
	}
	metrics.LeavesDownloadedTotal.Add(float64(totalLeaves))

	return bundles, nil
}

// SetTreeSize sets the tree size for LeafAdapter (no-op).
func (a *LeafAdapter) SetTreeSize(_ uint64) {}

// TiledReader defines the low-level tile and entry bundle retrieval methods.
type TiledReader interface {
	ReadCheckpoint(ctx context.Context) ([]byte, error)
	ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error)
	ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error)
}

type tiledReader = TiledReader

type pooledReader interface {
	ReadTilePooled(ctx context.Context, l, i uint64, p uint8) ([]byte, *PooledBuffer, error)
	ReadEntryBundlePooled(ctx context.Context, i uint64, p uint8) ([]byte, *PooledBuffer, error)
}

// PooledFileFetcher wraps local filesystem tile reads with TieredBufferPool.
type PooledFileFetcher struct {
	Root string
	pool *TieredBufferPool
}

// NewPooledFileFetcher constructs a PooledFileFetcher using the provided pool.
func NewPooledFileFetcher(root string, pool *TieredBufferPool) *PooledFileFetcher {
	if pool == nil {
		pool = globalBufferPool
	}
	return &PooledFileFetcher{
		Root: root,
		pool: pool,
	}
}

func (f *PooledFileFetcher) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.Root, layout.CheckpointPath))
}

func (f *PooledFileFetcher) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	data, pBuf, err := f.ReadTilePooled(ctx, l, i, p)
	if err != nil {
		return nil, err
	}
	res := make([]byte, len(data))
	copy(res, data)
	pBuf.Release()
	return res, nil
}

func (f *PooledFileFetcher) ReadTilePooled(_ context.Context, l, i uint64, p uint8) ([]byte, *PooledBuffer, error) {
	tileRel := layout.TilePath(l, i, p)
	filePath := filepath.Join(f.Root, tileRel)
	data, pBuf, err := readPooledFile(filePath, f.pool)
	if err != nil && p != 0 && errors.Is(err, os.ErrNotExist) {
		fallbackRel := layout.TilePath(l, i, 0)
		return readPooledFile(filepath.Join(f.Root, fallbackRel), f.pool)
	}
	return data, pBuf, err
}

func (f *PooledFileFetcher) ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error) {
	data, pBuf, err := f.ReadEntryBundlePooled(ctx, i, p)
	if err != nil {
		return nil, err
	}
	res := make([]byte, len(data))
	copy(res, data)
	pBuf.Release()
	return res, nil
}

func (f *PooledFileFetcher) ReadEntryBundlePooled(_ context.Context, i uint64, p uint8) ([]byte, *PooledBuffer, error) {
	entriesRel := layout.EntriesPath(i, p)
	filePath := filepath.Join(f.Root, entriesRel)
	data, pBuf, err := readPooledFile(filePath, f.pool)
	if err != nil && p != 0 && errors.Is(err, os.ErrNotExist) {
		fallbackRel := layout.EntriesPath(i, 0)
		return readPooledFile(filepath.Join(f.Root, fallbackRel), f.pool)
	}
	return data, pBuf, err
}

type leafBundleCache struct {
	start  uint64
	leaves [][]byte
}

func (tc leafBundleCache) get(i uint64) []byte {
	end := tc.start + uint64(len(tc.leaves))
	if i >= tc.start && i < end {
		return tc.leaves[i-tc.start]
	}
	return nil
}

type upperTileKey struct {
	level uint64
	index uint64
	p     uint8
}

// TiledFetcher adapts a tlog-tiles or static-ct HTTP endpoint to the TileFetcher interface.
type TiledFetcher struct {
	mu               sync.Mutex
	fetcher          tiledReader
	policy           wire.Policy
	policyErr        error
	verifier         note.Verifier
	witnesses        []note.Verifier
	witnessThreshold int
	origin           string
	cache            leafBundleCache
	treeSize         uint64
	treeHash         [32]byte
	allowUnverified  bool
	baseURL          *url.URL
	httpClient       *http.Client
	isStaticCT       bool

	upperTileMu   sync.Mutex
	upperTileSize uint64
	upperTileHash [32]byte
	upperTiles    map[upperTileKey][]byte
}

// SetTreeSize sets the current tree size used for partial tile fetching.
func (f *TiledFetcher) SetTreeSize(size uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.treeSize != size {
		f.treeHash = [32]byte{}
	}
	f.treeSize = size
}

// SetTreeState sets both the target tree size and expected checkpoint root hash for tile verification.
func (f *TiledFetcher) SetTreeState(size uint64, hash [32]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.treeSize = size
	f.treeHash = hash
}

// SetAllowUnverifiedCheckpoints explicitly opts into accepting unsigned checkpoints (for local testing only).
func (f *TiledFetcher) SetAllowUnverifiedCheckpoints(allow bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowUnverified = allow
}

// SetPolicy configures an explicit wire.Policy for Checkpoint verification.
func (f *TiledFetcher) SetPolicy(policy wire.Policy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy = policy
	f.policyErr = nil
}

// SetWitnessPolicy configures optional witness cosignature quorum verification for Checkpoint.
// When threshold > 0, Checkpoint requires at least threshold distinct configured witnesses
// (excluding any witness colliding with the primary log verifier) to sign the checkpoint note.
func (f *TiledFetcher) SetWitnessPolicy(witnesses []note.Verifier, threshold int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.witnesses = slices.Clone(witnesses)
	f.witnessThreshold = threshold
	if threshold < 0 {
		f.policy = nil
		f.policyErr = fmt.Errorf("invalid negative witness threshold %d", threshold)
		return
	}
	if f.verifier != nil {
		pol, err := wire.BuildPolicy(f.origin, f.verifier, f.witnesses, threshold)
		f.policy = pol
		f.policyErr = err
	}
}

// TreeSize returns the current tree size.
func (f *TiledFetcher) TreeSize() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.treeSize
}

// SetStaticCT explicitly sets whether to fetch Static-CT entry bundles (tile/data) instead of standard tiles (tile/entries).
func (f *TiledFetcher) SetStaticCT(isStatic bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isStaticCT = isStatic
}

// IsStaticCT reports whether the fetcher is operating in Static-CT mode.
func (f *TiledFetcher) IsStaticCT() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.isStaticCT
}

// NewTiledFetcherWithReader creates a new TiledFetcher using a custom TiledReader.
func NewTiledFetcherWithReader(reader TiledReader, verifier note.Verifier, origin string) *TiledFetcher {
	var pol wire.Policy
	var polErr error
	if verifier != nil {
		pol, polErr = wire.BuildPolicy(origin, verifier, nil, 0)
	}
	return &TiledFetcher{
		fetcher:   reader,
		policy:    pol,
		policyErr: polErr,
		verifier:  verifier,
		origin:    origin,
	}
}

// NewTiledFetcher creates a new TiledFetcher pointing to a baseURL.
func NewTiledFetcher(baseURL *url.URL, verifier note.Verifier, origin string, httpClient *http.Client) (*TiledFetcher, error) {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        200,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}
	if origin == "" && verifier != nil {
		origin = verifier.Name()
	}

	var reader tiledReader
	if baseURL.Scheme == "file" {
		reader = NewPooledFileFetcher(baseURL.Path, globalBufferPool)
	} else {
		httpReader, err := tclient.NewHTTPFetcher(baseURL, httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP fetcher for %s: %w", baseURL.String(), err)
		}
		reader = httpReader
	}

	isStaticCT := (origin != "" && (strings.Contains(origin, "certificate.transparency") || strings.Contains(origin, "static-ct"))) ||
		(baseURL != nil && (strings.Contains(baseURL.Host, "certificate.transparency") || strings.Contains(baseURL.Path, "static-ct")))

	var pol wire.Policy
	var polErr error
	if verifier != nil {
		pol, polErr = wire.BuildPolicy(origin, verifier, nil, 0)
	}

	return &TiledFetcher{
		fetcher:    reader,
		policy:     pol,
		policyErr:  polErr,
		verifier:   verifier,
		origin:     origin,
		baseURL:    baseURL,
		httpClient: httpClient,
		isStaticCT: isStaticCT,
	}, nil
}

// Checkpoint reads and validates the latest checkpoint from the log.
func (f *TiledFetcher) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	rawCP, err := f.fetcher.ReadCheckpoint(ctx)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}

	f.mu.Lock()
	policy := f.policy
	policyErr := f.policyErr
	verifier := f.verifier
	origin := f.origin
	witnesses := f.witnesses
	witnessThreshold := f.witnessThreshold
	allowUnverified := f.allowUnverified
	f.mu.Unlock()

	if policy == nil && policyErr == nil && verifier != nil {
		if witnessThreshold < 0 {
			policyErr = fmt.Errorf("invalid negative witness threshold %d", witnessThreshold)
		} else {
			policy, policyErr = wire.BuildPolicy(origin, verifier, witnesses, witnessThreshold)
		}
	}

	if policyErr != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("invalid checkpoint policy: %w", policyErr)
	}

	var cpOrigin string
	var cpSize uint64
	var h [32]byte

	if policy != nil {
		cp, err := policy.Verify(rawCP)
		if err != nil {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("failed to verify checkpoint signature: %w", err)
		}
		cpOrigin = cp.Origin
		cpSize = cp.Size
		copy(h[:], cp.Hash)
	} else if verifier == nil && allowUnverified {
		parsed, err := wire.ParseCheckpointHeader(rawCP)
		if err != nil {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("failed to parse checkpoint header: %w", err)
		}
		cpOrigin = parsed.Origin
		cpSize = parsed.Size
		copy(h[:], parsed.Hash)
	} else {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, errors.New("checkpoint verification failed: nil verifier (call SetAllowUnverifiedCheckpoints(true) for local testing)")
	}

	f.mu.Lock()
	f.treeSize = cpSize
	f.treeHash = h
	f.mu.Unlock()

	return &Checkpoint{
		Raw:    rawCP,
		Origin: cpOrigin,
		Size:   cpSize,
		Hash:   h,
	}, nil
}

// Leaf retrieves a raw leaf from the log's entry bundles.
func (f *TiledFetcher) Leaf(ctx context.Context, idx uint64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if entry := f.cache.get(idx); entry != nil {
		return entry, nil
	}

	bIdx := idx / layout.EntryBundleWidth

	if f.isStaticCT {
		bundle, err := f.fetchStaticCTBundle(ctx, bIdx, f.treeSize, f.treeHash)
		if err != nil {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("failed to fetch static-ct bundle for leaf %d: %w", idx, err)
		}
		ti := idx % layout.EntryBundleWidth
		if int(ti) >= len(bundle.Leaves) {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("leaf %d out of bounds in bundle (size %d)", idx, len(bundle.Leaves))
		}
		f.cache = leafBundleCache{
			start:  idx - ti,
			leaves: bundle.Leaves,
		}
		return bundle.Leaves[ti], nil
	}

	bundle, err := tclient.GetEntryBundle(ctx, f.fetcher.ReadEntryBundle, bIdx, f.treeSize)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to fetch entry bundle for leaf %d: %w", idx, err)
	}

	p := layout.PartialTileSize(0, bIdx, f.treeSize)
	tileData, err := f.fetcher.ReadTile(ctx, 0, bIdx, p)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to fetch tree tile for leaf %d: %w", idx, err)
	}

	startLeafIdx := bIdx * layout.EntryBundleWidth
	if err := verifyBundleWithTile(&bundle, tileData, startLeafIdx); err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to authenticate entry bundle for leaf %d against tree tile: %w", idx, err)
	}
	if err := f.verifyTileAgainstTreeRoot(ctx, bIdx, startLeafIdx, len(bundle.Entries), tileData, f.treeSize, f.treeHash); err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to authenticate tree tile for leaf %d against checkpoint root: %w", idx, err)
	}

	ti := idx % layout.EntryBundleWidth
	if int(ti) >= len(bundle.Entries) {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("leaf %d out of bounds in bundle (size %d)", idx, len(bundle.Entries))
	}

	f.cache = leafBundleCache{
		start:  idx - ti,
		leaves: bundle.Entries,
	}

	return bundle.Entries[ti], nil
}

// FetchTiles retrieves bundles of leaves starting at startLeafIdx up to startLeafIdx+count.
func (f *TiledFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error) {
	if count == 0 {
		return nil, nil
	}
	bundleSz := uint64(layout.EntryBundleWidth)
	if bundleSz == 0 {
		bundleSz = 64
	}
	startBundle := startLeafIdx / bundleSz
	endLeaf := startLeafIdx + count
	endBundle := (endLeaf + bundleSz - 1) / bundleSz
	numBundles := endBundle - startBundle
	if numBundles == 0 {
		return nil, nil
	}

	f.mu.Lock()
	treeSize := f.treeSize
	treeHash := f.treeHash
	f.mu.Unlock()

	if treeSize > 0 {
		if startLeafIdx >= treeSize {
			return nil, nil
		}
		if endLeaf > treeSize {
			endLeaf = treeSize
		}
		endBundle = (endLeaf + bundleSz - 1) / bundleSz
		numBundles = endBundle - startBundle
		if numBundles == 0 {
			return nil, nil
		}
	}

	bundles := make([]*LeafBundle, numBundles)
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(50)

	for bIdx := startBundle; bIdx < endBundle; bIdx++ {
		bIdx := bIdx
		g.Go(func() error {
			if f.isStaticCT {
				bundle, err := f.fetchStaticCTBundle(gCtx, bIdx, treeSize, treeHash)
				if err != nil {
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("failed to fetch static-ct bundle %d: %w", bIdx, err)
				}
				bundles[bIdx-startBundle] = bundle
				return nil
			}

			var bundle api.EntryBundle
			var bundlePBuf *PooledBuffer
			if pr, ok := f.fetcher.(pooledReader); ok {
				p := layout.PartialTileSize(0, bIdx, treeSize)
				sRaw, pBuf, err := pr.ReadEntryBundlePooled(gCtx, bIdx, p)
				if err != nil {
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("failed to fetch entry bundle %d: %w", bIdx, err)
				}
				if err := bundle.UnmarshalText(sRaw); err != nil {
					pBuf.Release()
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("failed to parse EntryBundle at index %d: %w", bIdx, err)
				}
				bundlePBuf = pBuf
			} else {
				var err error
				bundle, err = tclient.GetEntryBundle(gCtx, f.fetcher.ReadEntryBundle, bIdx, treeSize)
				if err != nil {
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("failed to fetch entry bundle %d: %w", bIdx, err)
				}
			}

			p := layout.PartialTileSize(0, bIdx, treeSize)
			var tileData []byte
			var tileRelease func()
			if pr, ok := f.fetcher.(pooledReader); ok {
				tData, tPBuf, err := pr.ReadTilePooled(gCtx, 0, bIdx, p)
				if err != nil {
					if bundlePBuf != nil {
						bundlePBuf.Release()
					}
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("failed to fetch tree tile %d: %w", bIdx, err)
				}
				tileData = tData
				tileRelease = tPBuf.Release
			} else {
				tData, err := f.fetcher.ReadTile(gCtx, 0, bIdx, p)
				if err != nil {
					if bundlePBuf != nil {
						bundlePBuf.Release()
					}
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("failed to fetch tree tile %d: %w", bIdx, err)
				}
				tileData = tData
			}
			if tileRelease != nil {
				defer tileRelease()
			}

			bundleStartIdx := bIdx * bundleSz
			if err := verifyBundleWithTile(&bundle, tileData, bundleStartIdx); err != nil {
				if bundlePBuf != nil {
					bundlePBuf.Release()
				}
				metrics.InputFetchErrorsTotal.Inc()
				return fmt.Errorf("failed to authenticate entry bundle %d against tree tile: %w", bIdx, err)
			}
			if err := f.verifyTileAgainstTreeRoot(gCtx, bIdx, bundleStartIdx, len(bundle.Entries), tileData, treeSize, treeHash); err != nil {
				if bundlePBuf != nil {
					bundlePBuf.Release()
				}
				metrics.InputFetchErrorsTotal.Inc()
				return fmt.Errorf("failed to authenticate tree tile %d against checkpoint root: %w", bIdx, err)
			}
			bundles[bIdx-startBundle] = &LeafBundle{
				BundleIdx:    bIdx,
				StartLeafIdx: bundleStartIdx,
				Leaves:       bundle.Entries,
				PooledBuf:    bundlePBuf,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	var totalLeavesInBundles int
	for _, b := range bundles {
		if b != nil {
			totalLeavesInBundles += len(b.Leaves)
		}
	}
	metrics.LeavesDownloadedTotal.Add(float64(totalLeavesInBundles))

	return bundles, nil
}

func (f *TiledFetcher) readCachedTile(ctx context.Context, treeSize uint64, treeHash [32]byte, level, index uint64, p uint8) ([]byte, error) {
	key := upperTileKey{level: level, index: index, p: p}
	f.upperTileMu.Lock()
	if f.upperTileSize != treeSize || f.upperTileHash != treeHash || f.upperTiles == nil {
		f.upperTileSize = treeSize
		f.upperTileHash = treeHash
		f.upperTiles = make(map[upperTileKey][]byte)
	}
	if cached, ok := f.upperTiles[key]; ok {
		f.upperTileMu.Unlock()
		return cached, nil
	}
	f.upperTileMu.Unlock()

	data, err := f.fetcher.ReadTile(ctx, level, index, p)
	if err != nil {
		return nil, err
	}
	cloned := bytes.Clone(data)

	f.upperTileMu.Lock()
	if f.upperTileSize == treeSize && f.upperTileHash == treeHash && f.upperTiles != nil {
		f.upperTiles[key] = cloned
	}
	f.upperTileMu.Unlock()
	return cloned, nil
}

func (f *TiledFetcher) verifyTileAgainstTreeRoot(ctx context.Context, bIdx, bundleStartIdx uint64, numLeaves int, tileData []byte, treeSize uint64, treeHash [32]byte) error {
	if treeSize == 0 || treeHash == ([32]byte{}) || numLeaves == 0 {
		return nil
	}
	lastOffset := numLeaves - 1
	lastLeafIdx := bundleStartIdx + uint64(lastOffset)
	if lastLeafIdx >= treeSize {
		lastLeafIdx = treeSize - 1
		lastOffset = int(lastLeafIdx - bundleStartIdx)
	}
	if (lastOffset+1)*32 > len(tileData) {
		return fmt.Errorf("tile data length %d too short for leaf offset %d", len(tileData), lastOffset)
	}
	leafHash := tileData[lastOffset*32 : (lastOffset+1)*32]

	pb, err := tclient.NewProofBuilder(ctx, treeSize, func(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
		if level == 0 && index == bIdx {
			wantLen := (lastOffset + 1) * 32
			if len(tileData) > wantLen {
				return tileData[:wantLen], nil
			}
			return tileData, nil
		}
		return f.readCachedTile(ctx, treeSize, treeHash, level, index, p)
	})
	if err != nil {
		return fmt.Errorf("failed to create proof builder for tree size %d: %w", treeSize, err)
	}

	incProof, err := pb.InclusionProof(ctx, lastLeafIdx)
	if err != nil {
		return fmt.Errorf("failed to build inclusion proof for leaf %d (bundle %d): %w", lastLeafIdx, bIdx, err)
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, lastLeafIdx, treeSize, leafHash, incProof, treeHash[:]); err != nil {
		return fmt.Errorf("level-0 tile %d failed inclusion verification against checkpoint root %x: %w", bIdx, treeHash, err)
	}
	return nil
}

// ConsistencyProof builds a Merkle consistency proof between smaller and larger tree sizes.
func (f *TiledFetcher) ConsistencyProof(ctx context.Context, smaller, larger uint64) ([][]byte, error) {
	if smaller > larger {
		return nil, fmt.Errorf("smaller tree size (%d) exceeds larger tree size (%d)", smaller, larger)
	}
	if smaller == 0 || smaller == larger {
		return nil, nil
	}
	pb, err := tclient.NewProofBuilder(ctx, larger, f.fetcher.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder for consistency proof (%d -> %d): %w", smaller, larger, err)
	}
	return pb.ConsistencyProof(ctx, smaller, larger)
}

func (f *TiledFetcher) fetchStaticCTBundle(ctx context.Context, bIdx, treeSize uint64, treeHash [32]byte) (*LeafBundle, error) {
	p := layout.PartialTileSize(0, bIdx, treeSize)
	var tileData []byte
	var tileRelease func()
	if pr, ok := f.fetcher.(pooledReader); ok {
		tData, tPBuf, err := pr.ReadTilePooled(ctx, 0, bIdx, p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch tree tile %d: %w", bIdx, err)
		}
		tileData = tData
		tileRelease = tPBuf.Release
	} else {
		tData, err := f.fetcher.ReadTile(ctx, 0, bIdx, p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch tree tile %d: %w", bIdx, err)
		}
		tileData = tData
	}
	if tileRelease != nil {
		defer tileRelease()
	}

	dataTile, dataPBuf, err := f.readStaticCTDataTilePooled(ctx, bIdx, p)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data tile %d: %w", bIdx, err)
	}

	lb, err := parseAndVerifyStaticCTBundle(dataTile, tileData, bIdx)
	if err != nil {
		if dataPBuf != nil {
			dataPBuf.Release()
		}
		return nil, err
	}
	if err := f.verifyTileAgainstTreeRoot(ctx, bIdx, lb.StartLeafIdx, len(lb.Leaves), tileData, treeSize, treeHash); err != nil {
		if dataPBuf != nil {
			dataPBuf.Release()
		}
		return nil, fmt.Errorf("failed to authenticate static-ct tree tile %d against checkpoint root: %w", bIdx, err)
	}
	lb.PooledBuf = dataPBuf
	return lb, nil
}

func (f *TiledFetcher) readStaticCTDataTilePooled(ctx context.Context, bIdx uint64, p uint8) ([]byte, *PooledBuffer, error) {
	if f.baseURL == nil {
		return nil, nil, errors.New("cannot read static-ct data tile without baseURL")
	}
	tileRel := layout.TilePath(0, bIdx, p)
	if len(tileRel) < 7 {
		return nil, nil, fmt.Errorf("unexpected tile path %q", tileRel)
	}
	relPath := fmt.Sprintf("tile/data/%s", tileRel[7:])
	if f.baseURL.Scheme == "file" {
		filePath := filepath.Join(f.baseURL.Path, relPath)
		data, pBuf, err := readPooledFile(filePath, globalBufferPool)
		if err != nil && p != 0 && errors.Is(err, os.ErrNotExist) {
			fullRel := layout.TilePath(0, bIdx, 0)
			fullRelPath := fmt.Sprintf("tile/data/%s", fullRel[7:])
			data, pBuf, err = readPooledFile(filepath.Join(f.baseURL.Path, fullRelPath), globalBufferPool)
		}
		return data, pBuf, err
	}

	data, err := f.readStaticCTDataTile(ctx, bIdx, p)
	return data, nil, err
}

func (f *TiledFetcher) readStaticCTDataTile(ctx context.Context, bIdx uint64, p uint8) ([]byte, error) {
	if f.baseURL == nil {
		return nil, errors.New("cannot read static-ct data tile without baseURL")
	}
	tileRel := layout.TilePath(0, bIdx, p)
	if len(tileRel) < 7 {
		return nil, fmt.Errorf("unexpected tile path %q", tileRel)
	}
	relPath := fmt.Sprintf("tile/data/%s", tileRel[7:])
	if f.baseURL.Scheme == "file" {
		filePath := filepath.Join(f.baseURL.Path, relPath)
		data, err := os.ReadFile(filePath)
		if err != nil && p != 0 && errors.Is(err, os.ErrNotExist) {
			fullRel := layout.TilePath(0, bIdx, 0)
			fullRelPath := fmt.Sprintf("tile/data/%s", fullRel[7:])
			data, err = os.ReadFile(filepath.Join(f.baseURL.Path, fullRelPath))
		}
		return data, err
	}

	client := f.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	tileURL := f.baseURL.JoinPath(relPath).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vindex/1.0 (CT-Monitor)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound && p != 0 {
		fullRel := layout.TilePath(0, bIdx, 0)
		fullRelPath := fmt.Sprintf("tile/data/%s", fullRel[7:])
		fullURL := f.baseURL.JoinPath(fullRelPath).String()
		fullReq, fullErr := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if fullErr == nil {
			fullReq.Header.Set("User-Agent", "vindex/1.0 (CT-Monitor)")
			fullResp, fullErr := client.Do(fullReq)
			if fullErr == nil {
				defer func() { _ = fullResp.Body.Close() }()
				if fullResp.StatusCode == http.StatusOK {
					return io.ReadAll(fullResp.Body)
				}
			}
		}

		return nil, fmt.Errorf("unexpected HTTP status %s for %s", resp.Status, tileURL)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %s for %s", resp.Status, tileURL)
	}
	return io.ReadAll(resp.Body)
}

func parseAndVerifyStaticCTBundle(dataTile, treeTile []byte, bIdx uint64) (*LeafBundle, error) {
	rest := dataTile
	var leaves [][]byte
	idx := 0
	for len(rest) > 0 {
		leaf, remaining, err := sunlight.ReadTileLeaf(rest)
		if err != nil {
			return nil, fmt.Errorf("failed to parse static-ct leaf %d in bundle %d: %w", idx, bIdx, err)
		}
		if len(treeTile) < (idx+1)*32 {
			return nil, fmt.Errorf("static-ct tree tile length %d mismatch: too short for leaf %d in bundle %d", len(treeTile), idx, bIdx)
		}
		rawLeaf := rest[:len(rest)-len(remaining)]
		mtl := leaf.MerkleTreeLeaf()
		h := sha256.Sum256(append([]byte{0x00}, mtl...))
		expected := treeTile[idx*32 : (idx+1)*32]
		if !bytes.Equal(h[:], expected) {
			return nil, fmt.Errorf("leaf %d in bundle %d hash mismatch against tree tile", idx, bIdx)
		}
		leaves = append(leaves, rawLeaf)
		rest = remaining
		idx++
	}
	expectedTileLen := len(leaves) * 32
	if len(treeTile) != expectedTileLen {
		return nil, fmt.Errorf("static-ct tree tile length %d mismatch with leaf count %d in bundle %d (expected %d bytes)", len(treeTile), len(leaves), bIdx, expectedTileLen)
	}
	return &LeafBundle{
		BundleIdx:    bIdx,
		StartLeafIdx: bIdx * uint64(layout.EntryBundleWidth),
		Leaves:       leaves,
	}, nil
}

var rfc6962LeafPrefix = [1]byte{0x00}

func verifyBundleWithTile(bundle *api.EntryBundle, tileData []byte, startLeafIdx uint64) error {
	expectedTileLen := len(bundle.Entries) * 32
	if len(tileData) != expectedTileLen {
		return fmt.Errorf("tile data length %d mismatch with entry count %d (expected %d bytes)", len(tileData), len(bundle.Entries), expectedTileLen)
	}
	// Performance: instantiate a single SHA-256 hasher per bundle and reuse across leaves via Reset()
	// to avoid allocating a new hash.Hash and digest object per leaf (drops 256 allocs to 1 per bundle).
	h := sha256.New()
	var leafHash [sha256.Size]byte
	for j, leaf := range bundle.Entries {
		h.Reset()
		h.Write(rfc6962LeafPrefix[:])
		h.Write(leaf)
		h.Sum(leafHash[:0])
		expectedHash := tileData[j*32 : (j+1)*32]
		if !bytes.Equal(leafHash[:], expectedHash) {
			return fmt.Errorf("leaf %d hash mismatch: got %x, want %x", startLeafIdx+uint64(j), leafHash[:], expectedHash)
		}
	}
	return nil
}
