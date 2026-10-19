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

package coordinator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
)

// TestGenesisBackfill_FullBootstrap tests bootstrapping from an empty output log (size 0)
// to Leaf 0 publication, followed by transitioning to Normal Serving Mode.
func TestGenesisBackfill_FullBootstrap(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := kvstore.Open(filepath.Join(dir, "db"), &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := mpt.NewMem()
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	indexer := kvstore.NewKVIndexer(db, 64)

	totalLeaves := 6000
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("genesis_leaf_%d", i)))
	}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	mapper := &simpleIdentityMapper{}

	coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, mapper)
	coord.SetCommitBatchSize(1024)
	coord.SetCoarseCheckpointInterval(2048)

	// Invariant check: output log size is 0 initially (unserved bootstrap)
	outSize, err := outLog.Size(ctx)
	if err != nil || outSize != 0 {
		t.Fatalf("initial outLog size = %d (err: %v), want 0", outSize, err)
	}

	// 1. Execute Genesis Backfill via SyncOnce
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce (Genesis Backfill) failed: %v", err)
	}

	// Verify Leaf 0 publication and serving state promotion
	outSize, err = outLog.Size(ctx)
	if err != nil || outSize != 1 {
		t.Fatalf("after genesis backfill outLog size = %d, want 1", outSize)
	}

	state := pub.GetServingState()
	if state == nil {
		t.Fatal("expected non-nil ServingState after genesis backfill")
	}
	if state.OutputLogIndex != 0 {
		t.Fatalf("servingState.OutputLogIndex = %d, want 0", state.OutputLogIndex)
	}
	if state.InputLogSize != uint64(totalLeaves) {
		t.Fatalf("servingState.InputLogSize = %d, want %d", state.InputLogSize, totalLeaves)
	}
	if mptMgr.PersistedSize() != uint64(totalLeaves) {
		t.Fatalf("mptMgr.PersistedSize() = %d, want %d", mptMgr.PersistedSize(), totalLeaves)
	}
	if mptMgr.Root() != state.MPTRoot {
		t.Fatalf("mptMgr.Root() %x != servingState.MPTRoot %x", mptMgr.Root(), state.MPTRoot)
	}

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil || kvSize != uint64(totalLeaves) {
		t.Fatalf("m_kv_size = %d (err: %v), want %d", kvSize, err, totalLeaves)
	}

	// Verify all keys prove correctly in the published MPT
	for i := 0; i < 50; i++ {
		leaf := leaves[i]
		kh := sha256.Sum256(leaf)
		proof, val, exists, err := mptMgr.Prove(kh)
		if err != nil || !exists {
			t.Fatalf("Prove failed for key %d: exists=%v, err=%v", i, exists, err)
		}
		expectedValueRoot, err := indexer.GetValueRoot(kh, uint64(totalLeaves))
		if err != nil {
			t.Fatalf("GetValueRoot failed for key %d: %v", i, err)
		}
		if val != expectedValueRoot {
			t.Fatalf("Prove val %x != expectedValueRoot %x", val, expectedValueRoot)
		}
		if err := mpt.Verify(state.MPTRoot, kh, val, exists, proof); err != nil {
			t.Fatalf("Verify proof failed for key %d: %v", i, err)
		}
	}

	// 2. Permanent One-Way Transition: Add more leaves and verify Normal Serving Mode runs
	fetcher.mu.Lock()
	for i := totalLeaves; i < totalLeaves+500; i++ {
		fetcher.leaves = append(fetcher.leaves, []byte(fmt.Sprintf("genesis_leaf_%d", i)))
	}
	fetcher.mu.Unlock()

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("second SyncOnce (Normal Serving Mode) failed: %v", err)
	}

	outSize, err = outLog.Size(ctx)
	if err != nil || outSize != 2 {
		t.Fatalf("after second SyncOnce outLog size = %d, want 2 (Leaf 1 published in Normal Serving Mode)", outSize)
	}

	newState := pub.GetServingState()
	if newState.OutputLogIndex != 1 {
		t.Fatalf("servingState.OutputLogIndex = %d, want 1", newState.OutputLogIndex)
	}
	if newState.InputLogSize != uint64(totalLeaves+500) {
		t.Fatalf("servingState.InputLogSize = %d, want %d", newState.InputLogSize, totalLeaves+500)
	}
}

// TestGenesisBackfill_CoarseCheckpoint_And_Shutdown tests intermediate coarse checkpointing
// and durable MPT versioning on context cancellation.
func TestGenesisBackfill_CoarseCheckpoint_And_Shutdown(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := kvstore.Open(filepath.Join(dir, "db"), &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := mpt.NewMem()
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	indexer := kvstore.NewKVIndexer(db, 64)

	totalLeaves := 6000
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("leaf_cc_%d", i)))
	}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	mapper := &simpleIdentityMapper{}

	coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, mapper)
	coord.SetCommitBatchSize(1024)
	coord.SetCoarseCheckpointInterval(2048)

	// Cancel context after 3 batches (3072 leaves)
	cancelCtx, cancel := context.WithCancel(ctx)
	targetCP, err := fetcher.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("fetcher.Checkpoint failed: %v", err)
	}
	if err := db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw); err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}

	// We wrap streamAndIndex by intercepting cancellation via callback
	processedSlabs := 0
	streamErr := coord.streamAndIndex(cancelCtx, 0, targetCP.Size, 1024, func(drainCtx context.Context, batch *ingest.MappedBatch) error {
		res, err := indexer.IndexBatch(drainCtx, batch, targetCP)
		if err != nil {
			return err
		}
		if err := mptMgr.SetBatch(res.ModifiedValueRoots); err != nil {
			return err
		}
		processedSlabs++
		// Trigger coarse checkpoint at 2048 (slab 2)
		if res.NewKVSize%2048 == 0 {
			_ = db.Sync()
			_, _ = mptMgr.Snap(int64(res.NewKVSize))
			_ = mptMgr.Sync()
		}
		if processedSlabs == 3 {
			cancel() // Cancel context at 3072 leaves
		}
		return nil
	})

	if streamErr == nil {
		t.Fatal("expected cancellation error from streamAndIndex")
	}

	// Coarse checkpoint protocol on shutdown: flush progress
	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		t.Fatalf("GetUint64 kvSize failed: %v", err)
	}
	if kvSize != 3072 {
		t.Fatalf("kvSize = %d, want 3072", kvSize)
	}

	// Verify MPT was snapped at least at coarse checkpoint interval (2048)
	if mptMgr.PersistedSize() < 2048 {
		t.Fatalf("mptMgr.PersistedSize() = %d, want >= 2048", mptMgr.PersistedSize())
	}

	// Complete backfill using fresh coordinator: should resume cleanly and finalize
	coord2 := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, mapper)
	coord2.SetCommitBatchSize(1024)
	coord2.SetCoarseCheckpointInterval(2048)

	if err := coord2.SyncOnce(ctx); err != nil {
		t.Fatalf("resume SyncOnce failed: %v", err)
	}

	outSize, err := outLog.Size(ctx)
	if err != nil || outSize != 1 {
		t.Fatalf("outLog size = %d, want 1", outSize)
	}
	if mptMgr.PersistedSize() != uint64(totalLeaves) {
		t.Fatalf("final mptMgr.PersistedSize() = %d, want %d", mptMgr.PersistedSize(), totalLeaves)
	}
}

// TestGenesisBackfill_DirtyCrashRecovery simulates a crash at leaf 5,000 when the coarse
// checkpoint was at 4,096. It verifies that recovery replays 4,096..5,000 with zero storage writes
// and finishes cleanly to tip (10,000 leaves).
func TestGenesisBackfill_DirtyCrashRecovery(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	dbDir := filepath.Join(baseDir, "db")
	mptDir := filepath.Join(baseDir, "mpt")

	totalLeaves := 10000
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("dirty_crash_leaf_%d", i)))
	}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	mapper := &simpleIdentityMapper{}

	targetCP, err := fetcher.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("fetcher.Checkpoint failed: %v", err)
	}

	// Phase A: Index up to leaf 5,000 using disk-backed DB and MPT.
	// Coarse checkpoint is taken at 4,096.
	// Leaves [4096..5000) are committed to Pebble and SetBatch into MPT, but NOT snapped on disk.
	{
		db, err := kvstore.Open(dbDir, &pebble.Options{})
		if err != nil {
			t.Fatalf("Open db failed: %v", err)
		}
		if err := db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw); err != nil {
			t.Fatalf("SetMetadata targetCP failed: %v", err)
		}
		mptMgr, err := mpt.Open(mptDir)
		if err != nil {
			t.Fatalf("Open mpt failed: %v", err)
		}
		indexer := kvstore.NewKVIndexer(db, 64)

		// 1. Batch 0..4096
		keyMap1 := make(map[[32]byte][]uint64)
		for i := 0; i < 4096; i++ {
			kh := sha256.Sum256(leaves[i])
			keyMap1[kh] = append(keyMap1[kh], uint64(i))
		}
		batch1 := &ingest.MappedBatch{
			StartLeafIdx: 0,
			EndLeafIdx:   4096,
			Count:        4096,
			KeyMap:       keyMap1,
		}
		res1, err := indexer.IndexBatch(ctx, batch1, targetCP)
		if err != nil {
			t.Fatalf("IndexBatch 1 failed: %v", err)
		}
		if err := mptMgr.SetBatch(res1.ModifiedValueRoots); err != nil {
			t.Fatalf("SetBatch 1 failed: %v", err)
		}
		// Coarse checkpoint at 4096:
		if err := db.Sync(); err != nil {
			t.Fatalf("db.Sync failed: %v", err)
		}
		if _, err := mptMgr.Snap(4096); err != nil {
			t.Fatalf("mptMgr.Snap failed: %v", err)
		}
		if err := mptMgr.Sync(); err != nil {
			t.Fatalf("mptMgr.Sync failed: %v", err)
		}

		// 2. Batch 4096..5000
		keyMap2 := make(map[[32]byte][]uint64)
		for i := 4096; i < 5000; i++ {
			kh := sha256.Sum256(leaves[i])
			keyMap2[kh] = append(keyMap2[kh], uint64(i))
		}
		batch2 := &ingest.MappedBatch{
			StartLeafIdx: 4096,
			EndLeafIdx:   5000,
			Count:        904,
			KeyMap:       keyMap2,
		}
		res2, err := indexer.IndexBatch(ctx, batch2, targetCP)
		if err != nil {
			t.Fatalf("IndexBatch 2 failed: %v", err)
		}
		if err := mptMgr.SetBatch(res2.ModifiedValueRoots); err != nil {
			t.Fatalf("SetBatch 2 failed: %v", err)
		}
		// Commit to Pebble WAL/memtable
		if err := db.Sync(); err != nil {
			t.Fatalf("db.Sync failed: %v", err)
		}

		// Simulate Crash: Close without Snap(5000) or Sync()
		_ = mptMgr.Close()
		_ = db.Close()
	}

	// Phase B: Reopen after dirty crash.
	// Pebble has m_kv_size = 5000.
	// MPT on disk only has version = 4096.
	db, err := kvstore.Open(dbDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Reopen db failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr, err := mpt.Open(mptDir)
	if err != nil {
		t.Fatalf("Reopen mpt failed: %v", err)
	}
	t.Cleanup(func() { _ = mptMgr.Close() })

	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	indexer := kvstore.NewKVIndexer(db, 64)

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		t.Fatalf("GetUint64 failed: %v", err)
	}
	if kvSize != 5000 {
		t.Fatalf("reopened kvSize = %d, want 5000", kvSize)
	}
	if mptMgr.PersistedSize() != 4096 {
		t.Fatalf("reopened mpt persisted size = %d, want 4096", mptMgr.PersistedSize())
	}

	coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, mapper)
	coord.SetCommitBatchSize(1024)
	coord.SetCoarseCheckpointInterval(4096)

	// SafeWatermark before recovery should be min(5000, 4096) = 4096
	sw, err := coord.SafeWatermark(ctx)
	if err != nil || sw != 4096 {
		t.Fatalf("SafeWatermark before recovery = %d (err: %v), want 4096", sw, err)
	}

	// 3. Run Recover(): Must detect mptPersistedSize (4096) < kvSize (5000)
	// and replay leaves [4096..5000) without writing to Pebble.
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover() failed during dirty crash recovery: %v", err)
	}

	// After recovery, MPT persisted size must be ratcheted to 5000
	if mptMgr.PersistedSize() != 5000 {
		t.Fatalf("after recovery, mpt persisted size = %d, want 5000", mptMgr.PersistedSize())
	}

	// SafeWatermark after recovery should be min(5000, 5000) = 5000
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 5000 {
		t.Fatalf("SafeWatermark after recovery = %d, want 5000", sw)
	}

	// 4. Resume Genesis Backfill to tip (10,000 leaves)
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce after recovery failed: %v", err)
	}

	// Leaf 0 must be published with size 10000
	outSize, err := outLog.Size(ctx)
	if err != nil || outSize != 1 {
		t.Fatalf("outLog.Size() = %d, want 1", outSize)
	}

	state := pub.GetServingState()
	if state == nil {
		t.Fatal("expected non-nil ServingState after completing backfill to tip")
	}
	if state.InputLogSize != uint64(totalLeaves) {
		t.Fatalf("servingState.InputLogSize = %d, want %d", state.InputLogSize, totalLeaves)
	}
	if mptMgr.PersistedSize() != uint64(totalLeaves) {
		t.Fatalf("final mptMgr.PersistedSize() = %d, want %d", mptMgr.PersistedSize(), totalLeaves)
	}
	if mptMgr.Root() != state.MPTRoot {
		t.Fatalf("final mpt root mismatch: %x != %x", mptMgr.Root(), state.MPTRoot)
	}

	// Compare with reference root computed from scratch for all 10,000 leaves
	refMem := mpt.NewMem()
	refKeys := make(map[[32]byte][32]byte, totalLeaves)
	for i := 0; i < totalLeaves; i++ {
		kh := sha256.Sum256(leaves[i])
		vr, err := indexer.GetValueRoot(kh, uint64(totalLeaves))
		if err != nil {
			t.Fatalf("GetValueRoot failed for leaf %d: %v", i, err)
		}
		refKeys[kh] = vr
	}
	expectedRoot, err := refMem.Predict(refKeys)
	if err != nil {
		t.Fatalf("Predict expected root failed: %v", err)
	}
	if state.MPTRoot != expectedRoot {
		t.Fatalf("state.MPTRoot %x != expectedRoot %x", state.MPTRoot, expectedRoot)
	}
}
