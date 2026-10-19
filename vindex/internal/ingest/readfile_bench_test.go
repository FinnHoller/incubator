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
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
)

func BenchmarkManagedTileCache_GetBundle(b *testing.B) {
	dir := b.TempDir()
	const bsz = 256
	const leafSize = 1024
	cache, err := NewManagedTileCache(dir, bsz)
	if err != nil {
		b.Fatalf("NewManagedTileCache failed: %v", err)
	}

	leaf := bytes.Repeat([]byte{0xab}, leafSize)
	bundle := &LeafBundle{
		BundleIdx:    42,
		StartLeafIdx: 42 * bsz,
		Leaves:       make([][]byte, bsz),
	}
	for i := range bundle.Leaves {
		bundle.Leaves[i] = leaf
	}
	if err := cache.PutBundle(bundle); err != nil {
		b.Fatalf("PutBundle failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(bsz * leafSize))

	for b.Loop() {
		got, err := cache.GetBundle(42)
		if err != nil {
			b.Fatalf("GetBundle failed: %v", err)
		}
		if len(got.Leaves) != bsz {
			b.Fatalf("unexpected leaves count: %d", len(got.Leaves))
		}
	}
}

func BenchmarkTiledFetcher_FetchTiles_File(b *testing.B) {
	dir := b.TempDir()
	const bsz = 256
	const leafSize = 1024
	hasher := rfc6962.DefaultHasher

	// Construct 10 valid Tessera entry bundles and Level 0 hash tiles
	const numBundles = 10
	leaf := bytes.Repeat([]byte{0xcd}, leafSize)

	for bIdx := uint64(0); bIdx < numBundles; bIdx++ {
		// 1. Write Level 0 hash tile: tile/0/x...
		tileRel := layout.TilePath(0, bIdx, 0)
		tilePath := filepath.Join(dir, tileRel)
		if err := os.MkdirAll(filepath.Dir(tilePath), 0755); err != nil {
			b.Fatalf("mkdir tile failed: %v", err)
		}
		tileData := make([]byte, bsz*32)
		for i := 0; i < bsz; i++ {
			h := hasher.HashLeaf(leaf)
			copy(tileData[i*32:(i+1)*32], h)
		}
		if err := os.WriteFile(tilePath, tileData, 0644); err != nil {
			b.Fatalf("write tile failed: %v", err)
		}

		// 2. Write entry bundle: tile/entries/x...
		entriesRel := layout.EntriesPath(bIdx, 0)
		entriesPath := filepath.Join(dir, entriesRel)
		if err := os.MkdirAll(filepath.Dir(entriesPath), 0755); err != nil {
			b.Fatalf("mkdir entries failed: %v", err)
		}
		var bundleBuf bytes.Buffer
		for i := 0; i < bsz; i++ {
			leafIdx := bIdx*bsz + uint64(i)
			bundleBuf.Write(tessera.NewEntry(leaf).MarshalBundleData(leafIdx))
		}
		if err := os.WriteFile(entriesPath, bundleBuf.Bytes(), 0644); err != nil {
			b.Fatalf("write entries failed: %v", err)
		}
	}

	u, err := url.Parse("file://" + dir)
	if err != nil {
		b.Fatalf("url.Parse failed: %v", err)
	}

	fetcher, err := NewTiledFetcher(u, nil, "test-log", nil)
	if err != nil {
		b.Fatalf("NewTiledFetcher failed: %v", err)
	}
	fetcher.SetTreeSize(numBundles * bsz)

	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(int64(numBundles * bsz * leafSize))

	for b.Loop() {
		bundles, err := fetcher.FetchTiles(ctx, 0, numBundles*bsz)
		if err != nil {
			b.Fatalf("FetchTiles failed: %v", err)
		}
		if len(bundles) != numBundles {
			b.Fatalf("expected %d bundles, got %d", numBundles, len(bundles))
		}
		for _, b := range bundles {
			b.Release()
		}
	}
}
