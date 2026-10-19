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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func computeExpectedValueRoot(indices []uint64) [sha256.Size]byte {
	var leaves [][]byte
	for _, idx := range indices {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], idx)
		leaves = append(leaves, b[:])
	}
	return BatchRoot(leaves)
}

func TestKVIndexer_SingleChunk(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, 256)

	key1 := sha256.Sum256([]byte("domain:example.com"))
	key2 := sha256.Sum256([]byte("domain:google.com"))

	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key1: {0, 5, 50},
			key2: {0, 10, 50},
		},
	}

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_data_v1"),
		Origin: "example.com/test",
		Size:   100,
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	if res.NewKVSize != 100 {
		t.Fatalf("NewKVSize = %d, want 100", res.NewKVSize)
	}

	// Verify metadata
	kvSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || kvSize != 100 {
		t.Fatalf("KeyMetaKVSize = %d (err: %v), want 100", kvSize, err)
	}

	kvCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(kvCP, targetCP.Raw) {
		t.Fatalf("KeyMetaKVCheckpoint = %s, want %s", string(kvCP), string(targetCP.Raw))
	}

	// Check value roots
	expectedKey1Root := computeExpectedValueRoot([]uint64{0, 5, 50})
	expectedKey2Root := computeExpectedValueRoot([]uint64{0, 10, 50})

	if res.ModifiedValueRoots[key1] != expectedKey1Root {
		t.Fatalf("key1 value root mismatch: got %x, want %x", res.ModifiedValueRoots[key1], expectedKey1Root)
	}
	if res.ModifiedValueRoots[key2] != expectedKey2Root {
		t.Fatalf("key2 value root mismatch: got %x, want %x", res.ModifiedValueRoots[key2], expectedKey2Root)
	}

	// Check GetValueRoot
	valueRoot1, err := idx.GetValueRoot(key1, 100)
	if err != nil || valueRoot1 != expectedKey1Root {
		t.Fatalf("GetValueRoot(key1) = %x (err: %v), want %x", valueRoot1, err, expectedKey1Root)
	}
}

func TestKVIndexer_MultiChunkRollover(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const chunkSize = 100
	idx := NewKVIndexer(db, chunkSize)

	key := sha256.Sum256([]byte("hot-key-multi-chunk"))

	// Create 350 occurrences: across chunks 0, 1, 2, 3
	var indices []uint64
	for i := uint64(0); i < 350; i++ {
		leafIdx := i * 3 // 0, 3, 6, ...
		indices = append(indices, leafIdx)
	}

	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        1050,
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("cp"),
		Origin: "test",
		Size:   1050,
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	expectedRoot := computeExpectedValueRoot(indices)
	if res.ModifiedValueRoots[key] != expectedRoot {
		t.Fatalf("ValueRoot mismatch: got %x, want %x", res.ModifiedValueRoots[key], expectedRoot)
	}

	valueRoot, err := idx.GetValueRoot(key, 1050)
	if err != nil || valueRoot != expectedRoot {
		t.Fatalf("GetValueRoot = %x (err: %v), want %x", valueRoot, err, expectedRoot)
	}

	// Verify active chunk is sought first via SeekPrefixGE
	prefix := EncodeChunkPrefix(key)
	iter, err := db.NewIter(nil)
	if err != nil {
		t.Fatalf("NewIter failed: %v", err)
	}
	defer func() { _ = iter.Close() }()

	if !iter.SeekPrefixGE(prefix) {
		t.Fatal("SeekPrefixGE failed to find key prefix")
	}

	// Latest leaf index is 349 * 3 = 1047, chunk = 1047 / 100 = 10
	_, activeChunkNum, err := DecodeChunkKey(iter.Key())
	if err != nil {
		t.Fatalf("DecodeChunkKey failed: %v", err)
	}
	expectedActiveChunk := uint64(349 * 3 / chunkSize)
	if activeChunkNum != expectedActiveChunk {
		t.Fatalf("active chunk num = %d, want %d", activeChunkNum, expectedActiveChunk)
	}
}

func TestKVIndexer_ValueRootIncrementalMatchesFull(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const chunkSize = 16
	idx := NewKVIndexer(db, chunkSize)

	key := sha256.Sum256([]byte("incremental_test_key"))

	var allIndices []uint64
	for batchNum := 0; batchNum < 10; batchNum++ {
		var batchIndices []uint64
		for i := 0; i < 25; i++ {
			leafIdx := uint64(batchNum*25 + i)
			allIndices = append(allIndices, leafIdx)
			batchIndices = append(batchIndices, leafIdx)
		}
		batch := &ingest.MappedBatch{
			BundleIdx:    uint64(batchNum),
			StartLeafIdx: uint64(batchNum * 25),
			Count:        25,
			KeyMap: map[[32]byte][]uint64{
				key: batchIndices,
			},
		}
		res, err := idx.IndexBatch(ctx, batch, nil)
		if err != nil {
			t.Fatalf("batch %d failed: %v", batchNum, err)
		}

		expectedRoot := computeExpectedValueRoot(allIndices)
		if res.ModifiedValueRoots[key] != expectedRoot {
			t.Fatalf("batch %d value root mismatch: got %x, want %x", batchNum, res.ModifiedValueRoots[key], expectedRoot)
		}
	}
}

func TestKVIndexer_ResumingBatches(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, 64)

	keyA := sha256.Sum256([]byte("A"))
	keyB := sha256.Sum256([]byte("B"))

	var keyA_1, keyB_1 []uint64
	for i := uint64(0); i < 50; i++ {
		if i%2 == 0 {
			keyA_1 = append(keyA_1, i)
		}
		if i%3 == 0 {
			keyB_1 = append(keyB_1, i)
		}
	}

	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			keyA: keyA_1,
			keyB: keyB_1,
		},
	}

	res1, err := idx.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("batch 1 failed: %v", err)
	}
	if res1.NewKVSize != 50 {
		t.Fatalf("NewKVSize = %d, want 50", res1.NewKVSize)
	}

	var keyA_2, keyB_2 []uint64
	for i := uint64(50); i < 100; i++ {
		if i%2 == 0 {
			keyA_2 = append(keyA_2, i)
		}
		if i%3 == 0 {
			keyB_2 = append(keyB_2, i)
		}
	}

	batch2 := &ingest.MappedBatch{
		BundleIdx:    1,
		StartLeafIdx: 50,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			keyA: keyA_2,
			keyB: keyB_2,
		},
	}

	res2, err := idx.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("batch 2 failed: %v", err)
	}
	if res2.NewKVSize != 100 {
		t.Fatalf("NewKVSize = %d, want 100", res2.NewKVSize)
	}

	var allKeyA []uint64
	for i := uint64(0); i < 100; i++ {
		if i%2 == 0 {
			allKeyA = append(allKeyA, i)
		}
	}
	expectedRootA := computeExpectedValueRoot(allKeyA)
	if res2.ModifiedValueRoots[keyA] != expectedRootA {
		t.Fatalf("Resumed keyA root mismatch: got %x, want %x", res2.ModifiedValueRoots[keyA], expectedRootA)
	}
}

func TestKVIndexer_GetValueRoot_WatermarkBoundary(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	key := sha256.Sum256([]byte("watermark-valueroot-key"))

	// Entries: 10, 30 in committed range (< 50), 60, 80 in in-flight range (>= 50)
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			key: {10, 30, 60, 80},
		},
	}
	if _, err := idx.IndexMappedBatch(ctx, batch, nil, 100); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Full root up to 100
	fullRoot, err := idx.GetValueRoot(key, 100)
	if err != nil {
		t.Fatalf("GetValueRoot(100) failed: %v", err)
	}
	expectedFullRoot := computeExpectedValueRoot([]uint64{10, 30, 60, 80})
	if fullRoot != expectedFullRoot {
		t.Fatalf("GetValueRoot(100) = %x, want %x", fullRoot, expectedFullRoot)
	}

	// 2. Filtered root up to 50 (should commit ONLY to [10, 30])
	filteredRoot, err := idx.GetValueRoot(key, 50)
	if err != nil {
		t.Fatalf("GetValueRoot(50) failed: %v", err)
	}
	expectedFilteredRoot := computeExpectedValueRoot([]uint64{10, 30})
	if filteredRoot != expectedFilteredRoot {
		t.Fatalf("GetValueRoot(50) = %x, want %x", filteredRoot, expectedFilteredRoot)
	}

	// 3. Filtered root before any occurrences (up to 5) -> should return EmptyRoot()
	emptyRoot, err := idx.GetValueRoot(key, 5)
	if err != nil {
		t.Fatalf("GetValueRoot(5) failed: %v", err)
	}
	if emptyRoot != EmptyRoot() {
		t.Fatalf("GetValueRoot(5) = %x, want empty root %x", emptyRoot, EmptyRoot())
	}
}

func TestKVIndexer_UnalignedBundleOffset_SyncAndCheckpoint(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_at_60967846"),
		Origin: "example.com/log",
		Size:   60967846,
	}

	key := sha256.Sum256([]byte("unaligned_key"))

	// Bundle starts at 60,964,864 (238144 * 256), but sync stream was [60,964,972, 60,967,846) with Count = 2,874
	batch := &ingest.MappedBatch{
		BundleIdx:    238144,
		StartLeafIdx: 60964864,
		EndLeafIdx:   60967846,
		Count:        2874,
		KeyMap: map[[32]byte][]uint64{
			key: {60964975, 60967800},
		},
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	if res.NewKVSize != 60967846 {
		t.Fatalf("NewKVSize = %d, want target size 60967846", res.NewKVSize)
	}

	// Verify durable m_kv_size
	kvSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || kvSize != 60967846 {
		t.Fatalf("KeyMetaKVSize = %d (err: %v), want 60967846", kvSize, err)
	}

	// Verify durable m_kv_checkpoint (asserts final batch synced with pebble.Sync)
	kvCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(kvCP, targetCP.Raw) {
		t.Fatalf("KeyMetaKVCheckpoint = %q (err: %v), want %q", string(kvCP), err, string(targetCP.Raw))
	}
}

func TestKVIndexer_ZeroEmissionTrailingLeaves_SyncAndCheckpoint(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_zero_emission"),
		Origin: "example.com/log",
		Size:   100,
	}

	// Trailing batch from 50 to 100 where NO mapper entries are produced (e.g. non-matching leaves)
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 50,
		EndLeafIdx:   100,
		Count:        50,
		KeyMap:       make(map[[32]byte][]uint64),
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	if res.NewKVSize != 100 {
		t.Fatalf("NewKVSize = %d, want target size 100", res.NewKVSize)
	}

	kvSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || kvSize != 100 {
		t.Fatalf("KeyMetaKVSize = %d (err: %v), want 100", kvSize, err)
	}

	kvCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(kvCP, targetCP.Raw) {
		t.Fatalf("KeyMetaKVCheckpoint = %q (err: %v), want %q", string(kvCP), err, string(targetCP.Raw))
	}
}

func TestKVIndexer_IntermediateVsFinalBatch_SyncBehavior(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_multi_batch"),
		Origin: "example.com/log",
		Size:   100,
	}

	key := sha256.Sum256([]byte("multi_batch_key"))

	// 1. Intermediate batch [0, 50)
	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   50,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20},
		},
	}
	res1, err := idx.IndexBatch(ctx, batch1, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch batch1 failed: %v", err)
	}
	if res1.NewKVSize != 50 {
		t.Fatalf("batch1 NewKVSize = %d, want 50", res1.NewKVSize)
	}
	kvSize1, _ := db.GetUint64(KeyMetaKVSize)
	if kvSize1 != 50 {
		t.Fatalf("KeyMetaKVSize after batch1 = %d, want 50", kvSize1)
	}
	kvCP1, _ := db.GetMetadata(KeyMetaKVCheckpoint)
	if len(kvCP1) != 0 {
		t.Fatalf("Intermediate batch must not write KeyMetaKVCheckpoint, got: %s", string(kvCP1))
	}

	// 2. Final batch [50, 100)
	batch2 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 50,
		EndLeafIdx:   100,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			key: {60, 70},
		},
	}
	res2, err := idx.IndexBatch(ctx, batch2, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch batch2 failed: %v", err)
	}
	if res2.NewKVSize != 100 {
		t.Fatalf("batch2 NewKVSize = %d, want 100", res2.NewKVSize)
	}
	kvSize2, _ := db.GetUint64(KeyMetaKVSize)
	if kvSize2 != 100 {
		t.Fatalf("KeyMetaKVSize after batch2 = %d, want 100", kvSize2)
	}
	kvCP2, _ := db.GetMetadata(KeyMetaKVCheckpoint)
	if !bytes.Equal(kvCP2, targetCP.Raw) {
		t.Fatalf("Final batch must write KeyMetaKVCheckpoint, got: %q", string(kvCP2))
	}
}

func TestKVIndexer_ActiveChunkCache(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	chunkSize := uint64(100)
	idx := NewKVIndexer(db, chunkSize)

	key := sha256.Sum256([]byte("hot_key_for_cache_test"))

	// Batch 1: leaves [0, 50), adds indices 10, 20
	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   50,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20},
		},
	}
	_, err := idx.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("batch1 failed: %v", err)
	}

	// Verify cache entry populated
	cached, ok := idx.currentCache[key]
	if !ok {
		t.Fatal("expected cache entry after batch1")
	}
	if cached.chunkNum != 0 {
		t.Fatalf("cached chunkNum = %d, want 0", cached.chunkNum)
	}
	if len(cached.record.RelativeIndices) != 2 {
		t.Fatalf("cached RelativeIndices len = %d, want 2", len(cached.record.RelativeIndices))
	}

	// Batch 2: leaves [50, 100), adds indices 60, 70 (must hit cache in chunk 0)
	batch2 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 50,
		EndLeafIdx:   100,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			key: {60, 70},
		},
	}
	res2, err := idx.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("batch2 failed: %v", err)
	}

	expectedValueRoot2 := computeExpectedValueRoot([]uint64{10, 20, 60, 70})
	if res2.ModifiedValueRoots[key] != expectedValueRoot2 {
		t.Fatalf("valueRoot mismatch: got %x, want %x", res2.ModifiedValueRoots[key], expectedValueRoot2)
	}

	// Batch 3: leaves [100, 200), adds index 120 (triggers rollover from chunk 0 to chunk 1)
	batch3 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 100,
		EndLeafIdx:   200,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key: {120},
		},
	}
	res3, err := idx.IndexBatch(ctx, batch3, nil)
	if err != nil {
		t.Fatalf("batch3 failed: %v", err)
	}

	expectedValueRoot3 := computeExpectedValueRoot([]uint64{10, 20, 60, 70, 120})
	if res3.ModifiedValueRoots[key] != expectedValueRoot3 {
		t.Fatalf("valueRoot mismatch after rollover: got %x, want %x", res3.ModifiedValueRoots[key], expectedValueRoot3)
	}

	cached3, ok := idx.currentCache[key]
	if !ok || cached3.chunkNum != 1 {
		t.Fatalf("expected cached chunkNum = 1 after rollover, got %v", cached3)
	}

	// Clear cache and verify GetValueRoot reconstructs correctly from Pebble
	idx.ClearCache()
	valueRootFromPebble, err := idx.GetValueRoot(key, 200)
	if err != nil {
		t.Fatalf("GetValueRoot failed: %v", err)
	}
	if valueRootFromPebble != expectedValueRoot3 {
		t.Fatalf("GetValueRoot from Pebble mismatch: got %x, want %x", valueRootFromPebble, expectedValueRoot3)
	}
}

func TestKVIndexer_TwoGenerationalCacheRotation(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := NewKVIndexer(db, 64)
	ctx := context.Background()

	// Insert hot key
	hotKey := sha256.Sum256([]byte("hot_key"))
	batch1 := &ingest.MappedBatch{
		StartLeafIdx: 0,
		EndLeafIdx:   10,
		Count:        10,
		KeyMap: map[[32]byte][]uint64{
			hotKey: {1, 2},
		},
	}
	if _, err := idx.IndexBatch(ctx, batch1, nil); err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	if _, ok := idx.currentCache[hotKey]; !ok {
		t.Fatal("hotKey not in currentCache")
	}

	// Populate maxGenChunkCacheSize keys to force cache generation swap
	for i := 0; i < maxGenChunkCacheSize+5; i++ {
		var k [32]byte
		binary.BigEndian.PutUint64(k[:], uint64(i+100))
		idx.currentCache[k] = activeChunkEntry{chunkNum: 0, record: &ChunkRecord{}}
	}

	// Trigger next batch to cause rotation
	batch2 := &ingest.MappedBatch{
		StartLeafIdx: 10,
		EndLeafIdx:   20,
		Count:        10,
		KeyMap: map[[32]byte][]uint64{
			hotKey: {15, 16},
		},
	}
	res2, err := idx.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("IndexBatch after rotation failed: %v", err)
	}

	expectedValueRoot := computeExpectedValueRoot([]uint64{1, 2, 15, 16})
	if res2.ModifiedValueRoots[hotKey] != expectedValueRoot {
		t.Fatalf("valueRoot mismatch after promotion: got %x, want %x", res2.ModifiedValueRoots[hotKey], expectedValueRoot)
	}

	// hotKey must now be promoted into currentCache
	if _, ok := idx.currentCache[hotKey]; !ok {
		t.Fatal("hotKey was not promoted to currentCache after access")
	}
}

func BenchmarkKVIndexer_IndexBatch_Zipfian(b *testing.B) {
	ctx := context.Background()
	dir := b.TempDir()
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := NewKVIndexer(db, 65536)

	// Pre-generate 100 hot keys (representing Zipfian top keys)
	hotKeys := make([][sha256.Size]byte, 100)
	for i := range hotKeys {
		hotKeys[i] = sha256.Sum256([]byte(fmt.Sprintf("hot_key_%d", i)))
	}

	b.ResetTimer()
	b.ReportAllocs()

	var leafOffset uint64
	for i := 0; i < b.N; i++ {
		batchKeyMap := make(map[[32]byte][]uint64, 50)
		for j := 0; j < 256; j++ {
			k := hotKeys[(i*256+j)%len(hotKeys)]
			batchKeyMap[k] = append(batchKeyMap[k], leafOffset+uint64(j))
		}
		batch := &ingest.MappedBatch{
			BundleIdx:    uint64(i),
			StartLeafIdx: leafOffset,
			EndLeafIdx:   leafOffset + 256,
			Count:        256,
			KeyMap:       batchKeyMap,
		}
		if _, err := idx.IndexBatch(ctx, batch, nil); err != nil {
			b.Fatalf("IndexBatch failed: %v", err)
		}
		leafOffset += 256
	}
}

func TestKVIndexer_Uint16MaxChunkBoundary(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize) // standard ChunkSize = 65536

	key := sha256.Sum256([]byte("chunk_boundary_key"))
	// Test occurrences crossing the 65536 uint16 max boundary
	// Chunk 0: 65534, 65535
	// Chunk 1: 65536, 65537
	indices := []uint64{ChunkSize - 2, ChunkSize - 1, ChunkSize, ChunkSize + 1}
	batch := &ingest.MappedBatch{
		Count: 70000,
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}

	res, err := idx.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	expectedRoot := computeExpectedValueRoot(indices)
	if res.ModifiedValueRoots[key] != expectedRoot {
		t.Fatalf("ModifiedValueRoots mismatch: got %x, want %x", res.ModifiedValueRoots[key], expectedRoot)
	}

	// Verify reader can query all indices across the rollover boundary
	lookupRes, err := db.Lookup(key, nil, 10, 70000)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !slices.Equal(lookupRes.MatchedIndices, indices) {
		t.Fatalf("Lookup returned %v, want %v", lookupRes.MatchedIndices, indices)
	}
}

func TestKVIndexer_NoPhantomChunk0_SparseFirstSeen(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	key := sha256.Sum256([]byte("sparse_first_seen_chunk_5"))
	firstLeaf := 5*ChunkSize + 42
	batch := &ingest.MappedBatch{
		StartLeafIdx: 5 * ChunkSize,
		EndLeafIdx:   6 * ChunkSize,
		Count:        uint32(ChunkSize),
		KeyMap: map[[32]byte][]uint64{
			key: {firstLeaf},
		},
	}

	if _, err := idx.IndexBatch(ctx, batch, nil); err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	// Verify only 1 chunk record exists in Pebble for key (chunk 5, NOT phantom chunk 0).
	prefix := EncodeChunkPrefix(key)
	iter, err := db.NewIter(nil)
	if err != nil {
		t.Fatalf("NewIter failed: %v", err)
	}
	defer func() { _ = iter.Close() }()

	var chunksFound []uint64
	for ok := iter.SeekPrefixGE(prefix); ok && bytes.HasPrefix(iter.Key(), prefix); ok = iter.Next() {
		_, cNum, err := DecodeChunkKey(iter.Key())
		if err != nil {
			t.Fatalf("DecodeChunkKey failed: %v", err)
		}
		chunksFound = append(chunksFound, cNum)
	}

	if !slices.Equal(chunksFound, []uint64{5}) {
		t.Fatalf("stored chunks for sparse key = %v, want [5] (no phantom chunk 0)", chunksFound)
	}
}

func TestKVIndexer_GetValueRoot_MultiChunkO1Seek(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const chunkSize = 64
	db.SetChunkSize(chunkSize)
	idx := NewKVIndexer(db, chunkSize)

	key := sha256.Sum256([]byte("multichunk_o1_valueroot"))
	// Occurrences in chunks 1, 3, and 5 (skipping chunk 0, 2, 4)
	indices := []uint64{
		1*chunkSize + 10, 1*chunkSize + 20,
		3*chunkSize + 5, 3*chunkSize + 15,
		5*chunkSize + 30, 5*chunkSize + 40,
	}
	maxLogSize := uint64(6 * chunkSize)
	batch := &ingest.MappedBatch{
		StartLeafIdx: 0,
		EndLeafIdx:   maxLogSize,
		Count:        uint32(maxLogSize),
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}
	if _, err := idx.IndexBatch(ctx, batch, nil); err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	for _, tc := range []struct {
		name      string
		watermark uint64
		wantSlice []uint64
	}{
		{name: "zero watermark", watermark: 0, wantSlice: nil},
		{name: "before chunk 1", watermark: 1*chunkSize + 5, wantSlice: nil},
		{name: "mid chunk 1", watermark: 1*chunkSize + 15, wantSlice: indices[:1]},
		{name: "in empty chunk 2", watermark: 2*chunkSize + 10, wantSlice: indices[:2]},
		{name: "in chunk 3 before first entry", watermark: 3*chunkSize + 2, wantSlice: indices[:2]},
		{name: "mid chunk 3", watermark: 3*chunkSize + 10, wantSlice: indices[:3]},
		{name: "in chunk 5 before first entry", watermark: 5*chunkSize + 10, wantSlice: indices[:4]},
		{name: "mid chunk 5", watermark: 5*chunkSize + 35, wantSlice: indices[:5]},
		{name: "full log", watermark: maxLogSize, wantSlice: indices},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := idx.GetValueRoot(key, tc.watermark)
			if err != nil {
				t.Fatalf("GetValueRoot(%d) failed: %v", tc.watermark, err)
			}
			want := EmptyRoot()
			if len(tc.wantSlice) > 0 {
				want = computeExpectedValueRoot(tc.wantSlice)
			}
			if got != want {
				t.Fatalf("GetValueRoot(%d) = %x, want %x", tc.watermark, got, want)
			}
		})
	}
}

func TestKVIndexer_AlreadyPersistedBatch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, 64)

	key := sha256.Sum256([]byte("already_persisted_key"))
	batch1 := &ingest.MappedBatch{
		Count: 100,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20},
		},
	}
	res1, err := idx.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("IndexBatch 1 failed: %v", err)
	}
	wantRoot := res1.ModifiedValueRoots[key]

	// Re-index with same batch where all indices are < persistedKVSize (100)
	batch2 := &ingest.MappedBatch{
		Count: 0,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20},
		},
	}
	res2, err := idx.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("IndexBatch 2 failed: %v", err)
	}
	if res2.ModifiedValueRoots[key] != wantRoot {
		t.Fatalf("value root mismatch on already persisted batch: got %x, want %x", res2.ModifiedValueRoots[key], wantRoot)
	}

	// Also test nil batch
	resNil, err := idx.IndexBatch(ctx, nil, nil)
	if err != nil || resNil.NewKVSize != 100 {
		t.Fatalf("unexpected IndexBatch(nil): res=%+v, err=%v", resNil, err)
	}
}

func TestKVIndexer_WorkerConfiguration(t *testing.T) {
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	wantDefault := DefaultKVIndexerWorkers()
	if idx.NumWorkers() != wantDefault {
		t.Fatalf("NewKVIndexer NumWorkers = %d, want default %d", idx.NumWorkers(), wantDefault)
	}

	idx.SetNumWorkers(4)
	if idx.NumWorkers() != 4 {
		t.Fatalf("NumWorkers after SetNumWorkers(4) = %d, want 4", idx.NumWorkers())
	}

	idx.SetNumWorkers(0)
	if idx.NumWorkers() != 1 {
		t.Fatalf("NumWorkers after SetNumWorkers(0) = %d, want minimum 1", idx.NumWorkers())
	}
}

func TestKVIndexer_GetValueRoots_Parallel(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const chunkSize = 32
	idx := NewKVIndexer(db, chunkSize)
	idx.SetNumWorkers(4)

	// Create 50 distinct keys with varied leaf indices
	const numKeys = 50
	keys := make([][sha256.Size]byte, numKeys)
	keyMap := make(map[[sha256.Size]byte][]uint64)
	expectedRoots := make(map[[sha256.Size]byte][sha256.Size]byte)

	for i := 0; i < numKeys; i++ {
		k := sha256.Sum256([]byte(fmt.Sprintf("parallel_key_%d", i)))
		keys[i] = k
		var indices []uint64
		// Some keys have 1 occurrence, some have 10, some span multiple chunks
		count := (i % 10) + 1
		for j := 0; j < count; j++ {
			indices = append(indices, uint64(i*5+j*20))
		}
		keyMap[k] = indices
		expectedRoots[k] = computeExpectedValueRoot(indices)
	}

	batch := &ingest.MappedBatch{
		Count:  1000,
		KeyMap: keyMap,
	}
	res, err := idx.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	// 1. GetValueRoots with empty keys
	emptyRes, err := idx.GetValueRoots(ctx, nil, 1000)
	if err != nil || len(emptyRes) != 0 {
		t.Fatalf("GetValueRoots(nil) = %v, err=%v, want empty map", emptyRes, err)
	}

	// 2. Parallel GetValueRoots across all 50 keys at tip
	roots, err := idx.GetValueRoots(ctx, keys, 1000)
	if err != nil {
		t.Fatalf("GetValueRoots failed: %v", err)
	}
	if len(roots) != numKeys {
		t.Fatalf("GetValueRoots returned %d keys, want %d", len(roots), numKeys)
	}
	for _, k := range keys {
		if roots[k] != expectedRoots[k] {
			t.Fatalf("GetValueRoots[%x] = %x, want %x", k, roots[k], expectedRoots[k])
		}
		if roots[k] != res.ModifiedValueRoots[k] {
			t.Fatalf("GetValueRoots[%x] = %x != IndexBatch root %x", k, roots[k], res.ModifiedValueRoots[k])
		}
	}
}

func BenchmarkKVIndexer_IncrementalIndex(b *testing.B) {
	ctx := context.Background()
	const numKeys = 200
	const batchesPerIter = 50

	keys := make([][sha256.Size]byte, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = sha256.Sum256([]byte(fmt.Sprintf("bench-key-%d", i)))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		dir := b.TempDir()
		db, err := Open(dir, &pebble.Options{})
		if err != nil {
			b.Fatalf("Open failed: %v", err)
		}
		idx := NewKVIndexer(db, ChunkSize)
		b.StartTimer()

		var leafIdx uint64
		for batchIdx := 0; batchIdx < batchesPerIter; batchIdx++ {
			keyMap := make(map[[32]byte][]uint64, numKeys)
			for i := 0; i < numKeys; i++ {
				keyMap[keys[i]] = []uint64{leafIdx}
				leafIdx++
			}
			batch := &ingest.MappedBatch{
				BundleIdx:    uint64(batchIdx),
				StartLeafIdx: leafIdx - uint64(numKeys),
				EndLeafIdx:   leafIdx,
				Count:        uint32(numKeys),
				KeyMap:       keyMap,
			}
			if _, err := idx.IndexBatch(ctx, batch, nil); err != nil {
				b.Fatalf("IndexBatch failed: %v", err)
			}
		}

		b.StopTimer()
		_ = db.Close()
		b.StartTimer()
	}
}

func BenchmarkKVIndexer_IndexBatch_1000Keys(b *testing.B) {
	for _, workers := range []int{1, 4, 8, 16} {
		b.Run(fmt.Sprintf("workers_%d", workers), func(b *testing.B) {
			ctx := context.Background()
			dir := b.TempDir()
			db, err := Open(dir, &pebble.Options{})
			if err != nil {
				b.Fatalf("Open failed: %v", err)
			}
			defer func() { _ = db.Close() }()

			idx := NewKVIndexer(db, 65536)
			idx.SetNumWorkers(workers)

			const numKeys = 1000
			keys := make([][sha256.Size]byte, numKeys)
			for i := range keys {
				keys[i] = sha256.Sum256([]byte(fmt.Sprintf("bench-key-%d", i)))
			}

			const targetSize = uint64(100000000)
			b.ResetTimer()
			b.ReportAllocs()

			var leafOffset uint64
			for i := 0; i < b.N; i++ {
				batchKeyMap := make(map[[32]byte][]uint64, numKeys)
				for j := 0; j < numKeys; j++ {
					batchKeyMap[keys[j]] = []uint64{leafOffset + uint64(j)}
				}
				batch := &ingest.MappedBatch{
					BundleIdx:    uint64(i),
					StartLeafIdx: leafOffset,
					EndLeafIdx:   leafOffset + uint64(numKeys),
					Count:        uint32(numKeys),
					KeyMap:       batchKeyMap,
				}
				if _, err := idx.IndexMappedBatch(ctx, batch, nil, targetSize); err != nil {
					b.Fatalf("IndexMappedBatch failed: %v", err)
				}
				leafOffset += uint64(numKeys)
			}
		})
	}
}

func BenchmarkKVIndexer_SparseFirstSeen_Chunk1(b *testing.B) {
	ctx := context.Background()
	dir := b.TempDir()
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := NewKVIndexer(db, ChunkSize)
	const keysPerBatch = 1000
	const targetSize = uint64(1 << 40)

	b.ReportAllocs()
	var batchNum uint64
	for b.Loop() {
		startLeaf := ChunkSize + batchNum*keysPerBatch
		keyMap := make(map[[32]byte][]uint64, keysPerBatch)
		for j := uint64(0); j < keysPerBatch; j++ {
			var k [32]byte
			binary.BigEndian.PutUint64(k[:8], batchNum)
			binary.BigEndian.PutUint64(k[8:16], j)
			keyMap[k] = []uint64{startLeaf + j}
		}
		batch := &ingest.MappedBatch{
			BundleIdx:    batchNum,
			StartLeafIdx: startLeaf,
			EndLeafIdx:   startLeaf + keysPerBatch,
			Count:        keysPerBatch,
			KeyMap:       keyMap,
		}
		if _, err := idx.IndexMappedBatch(ctx, batch, nil, targetSize); err != nil {
			b.Fatalf("IndexMappedBatch failed: %v", err)
		}
		batchNum++
	}
}

func BenchmarkGetValueRoot_100Chunks(b *testing.B) {
	ctx := context.Background()
	dir := b.TempDir()
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	const chunkSize = 64
	db.SetChunkSize(chunkSize)
	idx := NewKVIndexer(db, chunkSize)

	key := sha256.Sum256([]byte("bench-valueroot-100-chunks"))
	const numChunks = 100
	const entriesPerChunk = 50
	indices := make([]uint64, 0, numChunks*entriesPerChunk)
	for c := uint64(0); c < numChunks; c++ {
		for j := uint64(0); j < entriesPerChunk; j++ {
			indices = append(indices, c*chunkSize+j)
		}
	}
	maxLogSize := uint64(numChunks * chunkSize)
	batch := &ingest.MappedBatch{
		StartLeafIdx: 0,
		EndLeafIdx:   maxLogSize,
		Count:        uint32(maxLogSize),
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}
	if _, err := idx.IndexMappedBatch(ctx, batch, nil, maxLogSize); err != nil {
		b.Fatalf("IndexMappedBatch failed: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		vr, err := idx.GetValueRoot(key, maxLogSize)
		if err != nil {
			b.Fatalf("GetValueRoot failed: %v", err)
		}
		if vr == ([32]byte{}) {
			b.Fatal("empty value root")
		}
	}
}


