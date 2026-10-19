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
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
)

func TestInvertedPrefixComparer_Split(t *testing.T) {
	cmp := InvertedPrefixChunkComparer()

	var keyHash [32]byte
	copy(keyHash[:], []byte("01234567890123456789012345678901"))

	chunkKey := EncodeChunkKey(keyHash, 0)
	if got := cmp.Split(chunkKey); got != 33 {
		t.Fatalf("cmp.Split(chunkKey) = %d, want 33", got)
	}

	shortCKey := []byte("c_short")
	if got := cmp.Split(shortCKey); got != len(shortCKey) {
		t.Fatalf("cmp.Split(shortCKey) = %d, want %d", got, len(shortCKey))
	}

	metaKey := KeyMetaKVSize
	if got := cmp.Split(metaKey); got != len(metaKey) {
		t.Fatalf("cmp.Split(metaKey) = %d, want %d", got, len(metaKey))
	}
}

func TestDB_MetadataAccessors(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db_meta")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Initial reads
	val, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || val != nil {
		t.Fatalf("expected nil for missing key, got err=%v val=%v", err, val)
	}
	size, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || size != 0 {
		t.Fatalf("expected 0 for missing uint64, got err=%v size=%d", err, size)
	}

	// Writes
	if err := db.SetMetadata(KeyMetaKVCheckpoint, []byte("cp_raw_test_val")); err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}
	if err := db.SetUint64(KeyMetaKVSize, 123456789); err != nil {
		t.Fatalf("SetUint64 failed: %v", err)
	}

	// Verify reads
	gotCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(gotCP, []byte("cp_raw_test_val")) {
		t.Fatalf("GetMetadata mismatch: got %q, want %q (err: %v)", string(gotCP), "cp_raw_test_val", err)
	}
	gotSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || gotSize != 123456789 {
		t.Fatalf("GetUint64 mismatch: got %d, want 123456789 (err: %v)", gotSize, err)
	}
}

func TestDB_LoadKVState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db_state")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	// 1. Uninitialized state
	state, err := db.LoadKVState()
	if err != nil {
		t.Fatalf("LoadKVState failed on empty DB: %v", err)
	}
	if state.KVSize != 0 || state.KVCheckpoint != nil || state.TargetCheckpoint != nil {
		t.Fatalf("unexpected uninitialized state: %+v", state)
	}

	// 2. Populated state
	_ = db.SetUint64(KeyMetaKVSize, 500)
	_ = db.SetMetadata(KeyMetaKVCheckpoint, []byte("kv_cp_data"))
	_ = db.SetMetadata(KeyMetaTargetCheckpoint, []byte("target_cp_data"))

	state2, err := db.LoadKVState()
	if err != nil {
		t.Fatalf("LoadKVState failed: %v", err)
	}
	if state2.KVSize != 500 || string(state2.KVCheckpoint) != "kv_cp_data" || string(state2.TargetCheckpoint) != "target_cp_data" {
		t.Fatalf("unexpected populated state: %+v", state2)
	}
}

func TestDB_RecomputeValueRoot_And_GetValueRoot(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db_valueroot")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	keyHash := sha256.Sum256([]byte("valueroot_key"))
	idx := NewKVIndexer(db, 64)
	batch := &ingest.MappedBatch{
		Count: 50,
		KeyMap: map[[32]byte][]uint64{
			keyHash: {5, 15, 25},
		},
	}
	res, err := idx.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	wantRoot := res.ModifiedValueRoots[keyHash]

	// RecomputeValueRoot
	gotRoot1, err := db.RecomputeValueRoot(keyHash, 64)
	if err != nil || gotRoot1 != wantRoot {
		t.Fatalf("RecomputeValueRoot got %x (err: %v), want %x", gotRoot1, err, wantRoot)
	}

	// GetValueRoot
	gotRoot2, err := db.GetValueRoot(keyHash, 50)
	if err != nil || gotRoot2 != wantRoot {
		t.Fatalf("GetValueRoot got %x (err: %v), want %x", gotRoot2, err, wantRoot)
	}
}

func TestDB_WriteBatch_And_DeleteRange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db_batch_del")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	keyHash := sha256.Sum256([]byte("batch_key"))
	entries := map[[sha256.Size]byte][]uint64{
		keyHash: {10, 20},
	}
	if err := db.WriteBatch(entries, 30); err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}

	// Verify kv_size updated
	sz, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || sz != 30 {
		t.Fatalf("GetUint64 = %d, want 30", sz)
	}

	// Set raw keys and test DeleteRange
	pBatch := db.NewBatch()
	_ = pBatch.Set([]byte("k1"), []byte("v1"), nil)
	_ = pBatch.Set([]byte("k2"), []byte("v2"), nil)
	_ = pBatch.Set([]byte("k3"), []byte("v3"), nil)
	if err := db.Pebble().Apply(pBatch, pebble.Sync); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// DeleteRange [k1, k3) -> deletes k1, k2
	if err := db.DeleteRange([]byte("k1"), []byte("k3"), pebble.Sync); err != nil {
		t.Fatalf("DeleteRange failed: %v", err)
	}

	if _, closer, err := db.Pebble().Get([]byte("k1")); err != pebble.ErrNotFound {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatalf("expected ErrNotFound for k1, got %v", err)
	}
	if _, closer, err := db.Pebble().Get([]byte("k2")); err != pebble.ErrNotFound {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatalf("expected ErrNotFound for k2, got %v", err)
	}
	v3, closer, err := db.Pebble().Get([]byte("k3"))
	if err != nil || string(v3) != "v3" {
		t.Fatalf("Get(k3) = %q (err: %v), want v3", string(v3), err)
	}
	_ = closer.Close()
}

func TestDB_DoubleClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db_double_close")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// First close should succeed cleanly
	if err := db.Close(); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}

	// Second close must not panic (e.g. from double unref on cache)
	_ = db.Close()
}

func TestDB_MaxOpenFilesAndLevels(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db_open_files_auto")
	opts := &pebble.Options{}
	db, err := Open(dir, opts)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	if opts.MaxOpenFiles < 500 {
		t.Errorf("expected auto-tuned MaxOpenFiles >= 500, got %d", opts.MaxOpenFiles)
	}
	if len(opts.Levels) != 7 {
		t.Fatalf("expected 7 levels, got %d", len(opts.Levels))
	}
	if opts.Levels[2].TargetFileSize != 8<<20 {
		t.Errorf("expected L2 TargetFileSize 8MB, got %d", opts.Levels[2].TargetFileSize)
	}
	if opts.Levels[3].TargetFileSize != 16<<20 {
		t.Errorf("expected L3 TargetFileSize 16MB, got %d", opts.Levels[3].TargetFileSize)
	}

	// Explicit override should be preserved
	dir2 := filepath.Join(t.TempDir(), "db_open_files_explicit")
	opts2 := &pebble.Options{MaxOpenFiles: 2500}
	db2, err := Open(dir2, opts2)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db2.Close() }()

	if opts2.MaxOpenFiles != 2500 {
		t.Errorf("expected explicit MaxOpenFiles 2500, got %d", opts2.MaxOpenFiles)
	}
}


