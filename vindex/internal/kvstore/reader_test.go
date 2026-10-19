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

package kvstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
)

func setupTestStore(t *testing.T) (*DB, *KVIndexer) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "db_reader_test")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	indexer := NewKVIndexer(db, ChunkSize)
	return db, indexer
}

func TestLookup_KeyNotFound(t *testing.T) {
	db, _ := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("nonexistent_key"))

	res, err := db.Lookup(keyHash, nil, 100, 1000)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if res == nil {
		t.Fatalf("Lookup returned nil result")
		return
	}
	if len(res.MatchedIndices) != 0 {
		t.Fatalf("expected 0 matched indices, got %v", res.MatchedIndices)
	}
	if res.Preceding != 0 {
		t.Fatalf("expected Preceding = 0, got %d", res.Preceding)
	}
}

func TestLookup_SingleChunk_ReversePagination(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("single_chunk_key"))

	// Indices within Chunk 0 (< 65536)
	indices := []uint64{10, 25, 50, 100, 250, 500}
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 1000); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Query full range (limit = 10 >= 6) -> returns all 6 entries, nextBefore = nil
	resAll, err := db.Lookup(keyHash, nil, 10, 1000)
	if err != nil {
		t.Fatalf("Lookup(before=nil, limit=10) failed: %v", err)
	}
	if !slices.Equal(resAll.MatchedIndices, indices) {
		t.Fatalf("Lookup(before=nil) = %v, want %v", resAll.MatchedIndices, indices)
	}
	if resAll.NextBefore != nil {
		t.Fatalf("Lookup(before=nil) NextBefore = %v, want nil", resAll.NextBefore)
	}
	if resAll.Preceding != 0 {
		t.Fatalf("Lookup(before=nil) Preceding = %d, want 0", resAll.Preceding)
	}

	// 2. Query with advisory limit = 3 (< 6 entries in Chunk 0).
	// With chunk-aligned paging (1.1.2), limit is an advisory hint and whole chunks
	// are returned without mid-chunk splitting or dynamic read-path SHA-256 hashing.
	resTip, err := db.Lookup(keyHash, nil, 3, 1000)
	if err != nil {
		t.Fatalf("Lookup(before=nil, limit=3) failed: %v", err)
	}
	if !slices.Equal(resTip.MatchedIndices, indices) {
		t.Fatalf("Lookup(before=nil, limit=3) MatchedIndices = %v, want full chunk %v", resTip.MatchedIndices, indices)
	}
	if resTip.NextBefore != nil {
		t.Fatalf("Lookup(before=nil, limit=3) NextBefore = %v, want nil", resTip.NextBefore)
	}
	if resTip.Preceding != 0 {
		t.Fatalf("Lookup(before=nil, limit=3) Preceding = %d, want 0", resTip.Preceding)
	}
}

func TestLookup_ChunkAlignedPaging_MultiChunk(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db_chunk_aligned")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const customChunkSize = 100
	db.SetChunkSize(customChunkSize)
	indexer := NewKVIndexer(db, customChunkSize)
	keyHash := sha256.Sum256([]byte("chunk_aligned_key"))

	// Chunk 0: [10, 20, 30]
	// Chunk 1: [110, 120, 130, 140, 150]
	indices := []uint64{10, 20, 30, 110, 120, 130, 140, 150}
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 200); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// Request limit = 2: Chunk 1 has 5 entries (> 2), so the whole Chunk 1 is returned
	// with Chunk 1's precomputed CompactRange covering Chunk 0 (3 entries).
	page1, err := db.Lookup(keyHash, nil, 2, 200)
	if err != nil {
		t.Fatalf("Page 1 Lookup failed: %v", err)
	}
	wantPage1 := []uint64{110, 120, 130, 140, 150}
	if !slices.Equal(page1.MatchedIndices, wantPage1) {
		t.Fatalf("Page 1 MatchedIndices = %v, want %v", page1.MatchedIndices, wantPage1)
	}
	if page1.NextBefore == nil || *page1.NextBefore != 110 {
		t.Fatalf("Page 1 NextBefore = %v, want 110", page1.NextBefore)
	}
	if page1.Preceding != 3 {
		t.Fatalf("Page 1 Preceding = %d, want 3", page1.Preceding)
	}
	expectedPrefixRoot := BatchRoot([][]byte{
		binary.BigEndian.AppendUint64(nil, 10),
		binary.BigEndian.AppendUint64(nil, 20),
		binary.BigEndian.AppendUint64(nil, 30),
	})
	cr := &CompactRange{Preceding: page1.Preceding, Hashes: page1.CompactRange}
	if cr.Root() != expectedPrefixRoot {
		t.Fatalf("Page 1 preceding root = %x, want %x", cr.Root(), expectedPrefixRoot)
	}

	// Page 2 (before = 110): returns Chunk 0 [10, 20, 30], NextBefore = nil
	page2, err := db.Lookup(keyHash, page1.NextBefore, 2, 200)
	if err != nil {
		t.Fatalf("Page 2 Lookup failed: %v", err)
	}
	wantPage2 := []uint64{10, 20, 30}
	if !slices.Equal(page2.MatchedIndices, wantPage2) {
		t.Fatalf("Page 2 MatchedIndices = %v, want %v", page2.MatchedIndices, wantPage2)
	}
	if page2.NextBefore != nil {
		t.Fatalf("Page 2 NextBefore = %v, want nil", page2.NextBefore)
	}
	if page2.Preceding != 0 {
		t.Fatalf("Page 2 Preceding = %d, want 0", page2.Preceding)
	}
}

func TestLookup_MaxChunksPerRequest_BoundedSparseKeys(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db_max_chunks")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const customChunkSize = 64
	db.SetChunkSize(customChunkSize)
	db.SetMaxChunksPerRequest(4)
	if db.MaxChunksPerRequest() != 4 {
		t.Fatalf("MaxChunksPerRequest = %d, want 4", db.MaxChunksPerRequest())
	}

	indexer := NewKVIndexer(db, customChunkSize)
	keyHash := sha256.Sum256([]byte("sparse_bounded_key"))

	// 10 chunks, 1 entry per chunk
	var wantAll []uint64
	for c := uint64(0); c < 10; c++ {
		wantAll = append(wantAll, c*customChunkSize+7)
	}
	maxLogSize := uint64(10 * customChunkSize)
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: wantAll,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, maxLogSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// Request limit = 100, but MaxChunksPerRequest = 4 caps each page to 4 chunks (4 entries).
	var collected []uint64
	var before *uint64
	pages := 0
	for {
		pages++
		res, err := db.Lookup(keyHash, before, 100, maxLogSize)
		if err != nil {
			t.Fatalf("page %d Lookup failed: %v", pages, err)
		}
		if len(res.MatchedIndices) > 4 {
			t.Fatalf("page %d returned %d entries, exceeding maxChunksPerRequest=4", pages, len(res.MatchedIndices))
		}
		collected = append(slices.Clone(res.MatchedIndices), collected...)
		if res.NextBefore == nil {
			break
		}
		before = res.NextBefore
	}
	if pages != 3 {
		t.Fatalf("expected 3 pages (4 + 4 + 2 chunks), got %d", pages)
	}
	if !slices.Equal(collected, wantAll) {
		t.Fatalf("collected = %v, want %v", collected, wantAll)
	}
}

func TestLookup_MultiChunkRollover(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("multichunk_key"))

	// Entries across Chunk 0, Chunk 1, Chunk 2
	indices := []uint64{
		10, 20, // Chunk 0
		ChunkSize + 5, ChunkSize + 50, // Chunk 1 (65541, 65586)
		2*ChunkSize + 1, 2*ChunkSize + 99, // Chunk 2 (131073, 131171)
	}

	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 3*ChunkSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Query full range
	resAll, err := db.Lookup(keyHash, nil, 100, 3*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=nil) failed: %v", err)
	}
	if !slices.Equal(resAll.MatchedIndices, indices) {
		t.Fatalf("Lookup(before=nil) MatchedIndices = %v, want %v", resAll.MatchedIndices, indices)
	}
	if resAll.Preceding != 0 {
		t.Fatalf("Lookup(before=nil) Preceding = %d, want 0", resAll.Preceding)
	}

	// 2. Query Tip page (limit = 2) -> returns Chunk 2 entries [131073, 131171]
	resTip, err := db.Lookup(keyHash, nil, 2, 3*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=nil, limit=2) failed: %v", err)
	}
	wantTipMatches := indices[4:] // Chunk 2
	if !slices.Equal(resTip.MatchedIndices, wantTipMatches) {
		t.Fatalf("Lookup(before=nil, limit=2) MatchedIndices = %v, want %v", resTip.MatchedIndices, wantTipMatches)
	}
	if resTip.Preceding != 4 {
		t.Fatalf("Lookup(before=nil, limit=2) Preceding = %d, want 4", resTip.Preceding)
	}
	if resTip.NextBefore == nil || *resTip.NextBefore != indices[4] {
		t.Fatalf("Lookup(before=nil, limit=2) NextBefore = %v, want %d", resTip.NextBefore, indices[4])
	}

	// 3. Query Page 2 (before = 131073, limit = 2) -> returns Chunk 1 entries
	resPage2, err := db.Lookup(keyHash, resTip.NextBefore, 2, 3*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=131073, limit=2) failed: %v", err)
	}
	wantPage2Matches := indices[2:4] // Chunk 1
	if !slices.Equal(resPage2.MatchedIndices, wantPage2Matches) {
		t.Fatalf("Lookup(before=131073, limit=2) MatchedIndices = %v, want %v", resPage2.MatchedIndices, wantPage2Matches)
	}
	if resPage2.Preceding != 2 {
		t.Fatalf("Lookup(before=131073, limit=2) Preceding = %d, want 2", resPage2.Preceding)
	}
}

func TestLookup_SparseChunks_NoDataDrop(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("sparse_chunk_key"))

	sparseIdx := 5*ChunkSize + 42
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: {sparseIdx},
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 6*ChunkSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Query with before = nil
	res0, err := db.Lookup(keyHash, nil, 100, 6*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=nil) failed: %v", err)
	}
	if len(res0.MatchedIndices) != 1 || res0.MatchedIndices[0] != sparseIdx {
		t.Fatalf("Lookup(before=nil) MatchedIndices = %v, want [%d]", res0.MatchedIndices, sparseIdx)
	}

	// 2. Query with before = sparseIdx + 1
	beforeVal := sparseIdx + 1
	resChunk1, err := db.Lookup(keyHash, &beforeVal, 100, 6*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=sparseIdx+1) failed: %v", err)
	}
	if len(resChunk1.MatchedIndices) != 1 || resChunk1.MatchedIndices[0] != sparseIdx {
		t.Fatalf("Lookup(before=sparseIdx+1) MatchedIndices = %v, want [%d]", resChunk1.MatchedIndices, sparseIdx)
	}

	// 3. Query with before = sparseIdx (strictly before sparseIdx -> empty)
	resBefore, err := db.Lookup(keyHash, &sparseIdx, 100, 6*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=sparseIdx) failed: %v", err)
	}
	if len(resBefore.MatchedIndices) != 0 {
		t.Fatalf("Lookup(before=sparseIdx) MatchedIndices = %v, want empty", resBefore.MatchedIndices)
	}
}

func TestLookup_WatermarkFiltering(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("watermark_key"))

	// Index batch with indices 10, 20, 30 at targetSize 50
	batch1 := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: {10, 20, 30},
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch1, nil, 50); err != nil {
		t.Fatalf("IndexMappedBatch batch1 failed: %v", err)
	}

	// Index in-flight batch with indices 60, 70 at targetSize 100
	batch2 := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: {60, 70},
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch2, nil, 100); err != nil {
		t.Fatalf("IndexMappedBatch batch2 failed: %v", err)
	}

	// Reader has serving size = 50. Indices 60, 70 should be filtered out.
	res, err := db.Lookup(keyHash, nil, 100, 50)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	wantIndices := []uint64{10, 20, 30}
	if !slices.Equal(res.MatchedIndices, wantIndices) {
		t.Fatalf("Lookup with maxInputLogSize=50 = %v, want %v", res.MatchedIndices, wantIndices)
	}
}

func TestLookup_NonDefaultChunkSize(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db_reader_custom_chunk")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const customChunkSize = 64
	db.SetChunkSize(customChunkSize)
	indexer := NewKVIndexer(db, customChunkSize)

	keyHash := sha256.Sum256([]byte("custom_chunk_key"))
	indices := []uint64{0, 65, 130} // 0 (chunk 0), 65 (chunk 1), 130 (chunk 2)
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 200); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	res, err := db.Lookup(keyHash, nil, 100, 200)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !slices.Equal(res.MatchedIndices, indices) {
		t.Fatalf("Lookup matched indices = %v, want %v", res.MatchedIndices, indices)
	}
}

func BenchmarkLookup_MultiChunk(b *testing.B) {
	ctx := context.Background()
	dir := filepath.Join(b.TempDir(), "db_reader_bench")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	const chunkSize = 1000
	db.SetChunkSize(chunkSize)
	indexer := NewKVIndexer(db, chunkSize)

	keyHash := sha256.Sum256([]byte("bench_multichunk_key"))
	// 50 chunks of 1000 entries = 50,000 entries
	totalEntries := 50000
	indices := make([]uint64, totalEntries)
	for i := range indices {
		indices[i] = uint64(i)
	}
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, uint64(totalEntries)); err != nil {
		b.Fatalf("IndexMappedBatch failed: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		res, err := db.Lookup(keyHash, nil, 100, uint64(totalEntries))
		if err != nil {
			b.Fatalf("Lookup failed: %v", err)
		}
		if len(res.MatchedIndices) == 0 {
			b.Fatalf("expected non-empty matches, got 0")
		}
	}
}

func BenchmarkLookup_AbsentKey_FlushedSSTables(b *testing.B) {
	ctx := context.Background()
	dir := filepath.Join(b.TempDir(), "db_bloom_bench")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	indexer := NewKVIndexer(db, ChunkSize)
	const numFlushes = 6
	const keysPerFlush = 2000

	for f := 0; f < numFlushes; f++ {
		keyMap := make(map[[32]byte][]uint64, keysPerFlush)
		startLeaf := uint64(f * keysPerFlush)
		for i := 0; i < keysPerFlush; i++ {
			var k [32]byte
			binary.BigEndian.PutUint64(k[:8], uint64(i*2)) // even keys only
			binary.BigEndian.PutUint64(k[8:16], uint64(f))
			keyMap[k] = []uint64{startLeaf + uint64(i)}
		}
		batch := &ingest.MappedBatch{
			StartLeafIdx: startLeaf,
			EndLeafIdx:   startLeaf + keysPerFlush,
			Count:        keysPerFlush,
			KeyMap:       keyMap,
		}
		if _, err := indexer.IndexMappedBatch(ctx, batch, nil, startLeaf+keysPerFlush); err != nil {
			b.Fatalf("IndexMappedBatch failed: %v", err)
		}
		if err := db.Sync(); err != nil {
			b.Fatalf("Sync failed: %v", err)
		}
	}

	absentKeys := make([][32]byte, 1024)
	for i := range absentKeys {
		binary.BigEndian.PutUint64(absentKeys[i][:8], uint64(i*2+1)) // odd keys fall between even keys across all SSTables
	}
	maxLogSize := uint64(numFlushes * keysPerFlush)

	b.ReportAllocs()
	var idx int
	for b.Loop() {
		res, err := db.Lookup(absentKeys[idx&1023], nil, 100, maxLogSize)
		if err != nil {
			b.Fatalf("Lookup failed: %v", err)
		}
		if len(res.MatchedIndices) != 0 {
			b.Fatalf("expected 0 matches, got %d", len(res.MatchedIndices))
		}
		idx++
	}
}

func BenchmarkLookup_HotChunk_ChunkAligned(b *testing.B) {
	ctx := context.Background()
	dir := filepath.Join(b.TempDir(), "db_hot_chunk_bench")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	indexer := NewKVIndexer(db, ChunkSize)
	keyHash := sha256.Sum256([]byte("bench_hot_chunk_5000"))

	const entriesInChunk = 5000
	indices := make([]uint64, entriesInChunk)
	for i := range indices {
		indices[i] = uint64(i * 10)
	}
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, ChunkSize); err != nil {
		b.Fatalf("IndexMappedBatch failed: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		res, err := db.Lookup(keyHash, nil, 100, ChunkSize)
		if err != nil {
			b.Fatalf("Lookup failed: %v", err)
		}
		if len(res.MatchedIndices) == 0 {
			b.Fatal("expected matches")
		}
	}
}

func BenchmarkLookup_SparseManyChunks_Bounded(b *testing.B) {
	ctx := context.Background()
	dir := filepath.Join(b.TempDir(), "db_sparse_chunks_bench")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	const chunkSize = 64
	db.SetChunkSize(chunkSize)
	indexer := NewKVIndexer(db, chunkSize)

	keyHash := sha256.Sum256([]byte("bench_sparse_500_chunks"))
	const numChunks = 500
	indices := make([]uint64, numChunks)
	for c := 0; c < numChunks; c++ {
		indices[c] = uint64(c*chunkSize + 1)
	}
	maxLogSize := uint64(numChunks * chunkSize)
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, maxLogSize); err != nil {
		b.Fatalf("IndexMappedBatch failed: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		res, err := db.Lookup(keyHash, nil, 1000, maxLogSize)
		if err != nil {
			b.Fatalf("Lookup failed: %v", err)
		}
		if len(res.MatchedIndices) == 0 {
			b.Fatal("expected matches")
		}
	}
}

func TestLookup_LimitBounds(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db_limit_bounds")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const customChunkSize = 4
	const totalChunks = 1200
	db.SetChunkSize(customChunkSize)
	db.SetMaxChunksPerRequest(2000)

	indexer := NewKVIndexer(db, customChunkSize)
	key := []byte("com.example.limits")
	keyHash := sha256.Sum256(key)

	indices := make([]uint64, totalChunks)
	for c := 0; c < totalChunks; c++ {
		indices[c] = uint64(c*customChunkSize + 1)
	}
	maxLogSize := uint64(totalChunks * customChunkSize)
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, maxLogSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// limit=1 must be preserved as 1 (NOT clamped upward to 100)
	res1, err := db.LookupKey(key, nil, 1, maxLogSize)
	if err != nil {
		t.Fatalf("LookupKey(limit=1) failed: %v", err)
	}
	if len(res1.MatchedIndices) != 1 {
		t.Fatalf("LookupKey(limit=1) returned %d indices, want 1", len(res1.MatchedIndices))
	}

	// limit=0 defaults to 100
	res0, err := db.LookupKey(key, nil, 0, maxLogSize)
	if err != nil {
		t.Fatalf("LookupKey(limit=0) failed: %v", err)
	}
	if len(res0.MatchedIndices) != 100 {
		t.Fatalf("LookupKey(limit=0) returned %d indices, want 100", len(res0.MatchedIndices))
	}

	// limit=5000 clamps downward to 1000
	res5000, err := db.LookupKey(key, nil, 5000, maxLogSize)
	if err != nil {
		t.Fatalf("LookupKey(limit=5000) failed: %v", err)
	}
	if len(res5000.MatchedIndices) != 1000 {
		t.Fatalf("LookupKey(limit=5000) returned %d indices, want 1000", len(res5000.MatchedIndices))
	}
}



