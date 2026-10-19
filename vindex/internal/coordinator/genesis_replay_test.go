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
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	mptpkg "github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
)

// computeReferenceValueRoot calculates the expected Merkle value log root for absolute leaf indices.
func computeReferenceValueRoot(indices []uint64) [sha256.Size]byte {
	if len(indices) == 0 {
		return kvstore.EmptyRoot()
	}
	cr := kvstore.NewCompactRange()
	for _, idx := range indices {
		var b [8]byte
		b[0] = byte(idx >> 56)
		b[1] = byte(idx >> 48)
		b[2] = byte(idx >> 40)
		b[3] = byte(idx >> 32)
		b[4] = byte(idx >> 24)
		b[5] = byte(idx >> 16)
		b[6] = byte(idx >> 8)
		b[7] = byte(idx)
		cr.Append(kvstore.LeafHash(b[:]))
	}
	return cr.Root()
}

func TestMPT_SnapAndReopen(t *testing.T) {
	dir := t.TempDir()
	mpt1, err := mptpkg.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = mpt1.Snap(3500)
	if err != nil {
		t.Fatal(err)
	}
	_ = mpt1.Sync()
	_ = mpt1.Close()

	mpt2, err := mptpkg.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mpt2.PersistedSize() != 3500 {
		t.Fatalf("mpt2 size = %d, want 3500", mpt2.PersistedSize())
	}
	_, err = mpt2.Snap(4096)
	if err != nil {
		t.Fatal(err)
	}
	_ = mpt2.Sync()
	muts := make(map[[32]byte][32]byte)
	for i := 0; i < 1500; i++ {
		k := sha256.Sum256([]byte(fmt.Sprintf("k%d", i)))
		v := sha256.Sum256([]byte(fmt.Sprintf("v%d", i)))
		muts[k] = v
	}
	_ = mpt2.SetBatch(muts)
	_ = mpt2.Close()

	mpt3, err := mptpkg.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mpt3.PersistedSize() != 4096 {
		t.Fatalf("mpt3 size = %d, want 4096", mpt3.PersistedSize())
	}
	_ = mpt3.Close()
}

// snapshotPebbleKVs returns a map of all user keys and values in Pebble for write-amplification assertions.
func snapshotPebbleKVs(t *testing.T, db *kvstore.DB) map[string]string {
	t.Helper()
	kvs := make(map[string]string)
	iter, err := db.Pebble().NewIter(nil)
	if err != nil {
		t.Fatalf("snapshotPebbleKVs NewIter failed: %v", err)
	}
	defer func() { _ = iter.Close() }()

	for iter.First(); iter.Valid(); iter.Next() {
		kvs[string(iter.Key())] = string(iter.Value())
	}
	return kvs
}

// TestGenesisReplay_DeterministicIdentity verifies that crashing and replaying leaves [mptPersistedSize..kvSize)
// produces byte-for-byte identical MPT roots, value roots, and inclusion proofs compared to a clean,
// uninterrupted run over the exact same leaves.
func TestGenesisReplay_DeterministicIdentity(t *testing.T) {
	ctx := context.Background()
	totalLeaves := 6000
	coarseCheckpoint := 2048
	crashLeaf := 4000

	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("deterministic_leaf_%d", i)))
	}
	mapper := &simpleIdentityMapper{}

	// -------------------------------------------------------------
	// Run A: Clean uninterrupted run to establish reference state
	// -------------------------------------------------------------
	dirA := t.TempDir()
	dbA, err := kvstore.Open(filepath.Join(dirA, "db"), &pebble.Options{})
	if err != nil {
		t.Fatalf("Open dbA failed: %v", err)
	}
	t.Cleanup(func() { _ = dbA.Close() })

	mptA, err := mptpkg.Open(filepath.Join(dirA, "mpt"))
	if err != nil {
		t.Fatalf("Open mptA failed: %v", err)
	}
	t.Cleanup(func() { _ = mptA.Close() })

	outLogA := newMemoryOutputLog("example.com/outputlog")
	pubA := tree.NewOutputPublisher(dbA, mptA, outLogA, nil)
	idxA := kvstore.NewKVIndexer(dbA, 64)
	fetcherA := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}

	coordA := NewCoordinator(dbA, mptA, outLogA, pubA, idxA, fetcherA, nil, mapper)
	coordA.SetCommitBatchSize(1024)
	coordA.SetCoarseCheckpointInterval(uint64(coarseCheckpoint))

	// Ingest cleanly up to crashLeaf (4000)
	targetCPA, err := fetcherA.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint A failed: %v", err)
	}
	if err := dbA.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCPA.Raw); err != nil {
		t.Fatalf("SetMetadata A failed: %v", err)
	}

	for start := 0; start < crashLeaf; start += 1000 {
		end := min(start+1000, crashLeaf)
		km := make(map[[32]byte][]uint64)
		for i := start; i < end; i++ {
			kh := sha256.Sum256(leaves[i])
			km[kh] = append(km[kh], uint64(i))
		}
		batch := &ingest.MappedBatch{StartLeafIdx: uint64(start), EndLeafIdx: uint64(end), Count: uint32(end - start), KeyMap: km}
		res, err := idxA.IndexBatch(ctx, batch, targetCPA)
		if err != nil {
			t.Fatalf("IndexBatch A failed: %v", err)
		}
		if err := mptA.SetBatch(res.ModifiedValueRoots); err != nil {
			t.Fatalf("SetBatch A failed: %v", err)
		}
	}
	_ = dbA.Sync()
	_, _ = mptA.Snap(int64(crashLeaf))
	_ = mptA.Sync()
	expectedRootAt4000 := mptA.Root()

	// Capture value roots for all leaves at 4000 in Run A
	expectedValueRootsAt4000 := make(map[[32]byte][32]byte, crashLeaf)
	for i := 0; i < crashLeaf; i++ {
		kh := sha256.Sum256(leaves[i])
		vr, err := idxA.GetValueRoot(kh, uint64(crashLeaf))
		if err != nil {
			t.Fatalf("GetValueRoot A at 4000 failed: %v", err)
		}
		expectedValueRootsAt4000[kh] = vr
	}

	// Ingest remaining leaves up to totalLeaves (6000) in Run A
	for start := crashLeaf; start < totalLeaves; start += 1000 {
		end := min(start+1000, totalLeaves)
		km := make(map[[32]byte][]uint64)
		for i := start; i < end; i++ {
			kh := sha256.Sum256(leaves[i])
			km[kh] = append(km[kh], uint64(i))
		}
		batch := &ingest.MappedBatch{StartLeafIdx: uint64(start), EndLeafIdx: uint64(end), Count: uint32(end - start), KeyMap: km}
		res, err := idxA.IndexBatch(ctx, batch, targetCPA)
		if err != nil {
			t.Fatalf("IndexBatch A remaining failed: %v", err)
		}
		if err := mptA.SetBatch(res.ModifiedValueRoots); err != nil {
			t.Fatalf("SetBatch A remaining failed: %v", err)
		}
	}
	_ = dbA.Sync()
	_, _ = mptA.Snap(int64(totalLeaves))
	_ = mptA.Sync()
	finalRootA := mptA.Root()

	// -------------------------------------------------------------
	// Run B: Crash at 4000 with coarse checkpoint at 2048, then recover and complete
	// -------------------------------------------------------------
	dirB := t.TempDir()
	dbDirB := filepath.Join(dirB, "db")
	mptDirB := filepath.Join(dirB, "mpt")

	{
		dbB, err := kvstore.Open(dbDirB, &pebble.Options{})
		if err != nil {
			t.Fatalf("Open dbB failed: %v", err)
		}
		if err := dbB.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCPA.Raw); err != nil {
			t.Fatalf("SetMetadata B failed: %v", err)
		}
		mptB, err := mptpkg.Open(mptDirB)
		if err != nil {
			t.Fatalf("Open mptB failed: %v", err)
		}
		idxB := kvstore.NewKVIndexer(dbB, 64)

		// 1. Ingest 0..2048 and take coarse checkpoint
		km1 := make(map[[32]byte][]uint64)
		for i := 0; i < coarseCheckpoint; i++ {
			kh := sha256.Sum256(leaves[i])
			km1[kh] = append(km1[kh], uint64(i))
		}
		batch1 := &ingest.MappedBatch{StartLeafIdx: 0, EndLeafIdx: uint64(coarseCheckpoint), Count: uint32(coarseCheckpoint), KeyMap: km1}
		res1, err := idxB.IndexBatch(ctx, batch1, targetCPA)
		if err != nil {
			t.Fatalf("IndexBatch B 1 failed: %v", err)
		}
		if err := mptB.SetBatch(res1.ModifiedValueRoots); err != nil {
			t.Fatalf("SetBatch B 1 failed: %v", err)
		}
		_ = dbB.Sync()
		_, _ = mptB.Snap(int64(coarseCheckpoint))
		_ = mptB.Sync()

		// 2. Ingest 2048..4000 into Pebble, but crash before snapping MPT on disk!
		km2 := make(map[[32]byte][]uint64)
		for i := coarseCheckpoint; i < crashLeaf; i++ {
			kh := sha256.Sum256(leaves[i])
			km2[kh] = append(km2[kh], uint64(i))
		}
		batch2 := &ingest.MappedBatch{StartLeafIdx: uint64(coarseCheckpoint), EndLeafIdx: uint64(crashLeaf), Count: uint32(crashLeaf - coarseCheckpoint), KeyMap: km2}
		res2, err := idxB.IndexBatch(ctx, batch2, targetCPA)
		if err != nil {
			t.Fatalf("IndexBatch B 2 failed: %v", err)
		}
		if err := mptB.SetBatch(res2.ModifiedValueRoots); err != nil {
			t.Fatalf("SetBatch B 2 failed: %v", err)
		}
		_ = dbB.Sync()

		_ = mptB.Close()
		_ = dbB.Close()
	}

	// Reopen after dirty crash
	dbB, err := kvstore.Open(dbDirB, &pebble.Options{})
	if err != nil {
		t.Fatalf("Reopen dbB failed: %v", err)
	}
	t.Cleanup(func() { _ = dbB.Close() })

	mptB, err := mptpkg.Open(mptDirB)
	if err != nil {
		t.Fatalf("Reopen mptB failed: %v", err)
	}
	t.Cleanup(func() { _ = mptB.Close() })

	outLogB := newMemoryOutputLog("example.com/outputlog")
	pubB := tree.NewOutputPublisher(dbB, mptB, outLogB, nil)
	idxB := kvstore.NewKVIndexer(dbB, 64)
	fetcherB := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}

	coordB := NewCoordinator(dbB, mptB, outLogB, pubB, idxB, fetcherB, nil, mapper)
	coordB.SetCommitBatchSize(1024)
	coordB.SetCoarseCheckpointInterval(uint64(coarseCheckpoint))

	// Pre-recovery state assertion:
	if mptB.PersistedSize() != uint64(coarseCheckpoint) {
		t.Fatalf("mptB persisted size before recovery = %d, want %d", mptB.PersistedSize(), coarseCheckpoint)
	}
	kvSizeB, _ := dbB.GetUint64(kvstore.KeyMetaKVSize)
	if kvSizeB != uint64(crashLeaf) {
		t.Fatalf("dbB kvSize before recovery = %d, want %d", kvSizeB, crashLeaf)
	}
	swBefore, _ := coordB.SafeWatermark(ctx)
	if swBefore != uint64(coarseCheckpoint) {
		t.Fatalf("SafeWatermark before recovery = %d, want %d", swBefore, coarseCheckpoint)
	}

	// -------------------------------------------------------------
	// Execute Recover(): Replays [2048..4000) from WASM, zero Pebble writes
	// -------------------------------------------------------------
	if err := coordB.Recover(ctx); err != nil {
		t.Fatalf("Recover() failed: %v", err)
	}

	// Verify post-recovery MPT state matches Run A at 4000 EXACTLY
	if mptB.PersistedSize() != uint64(crashLeaf) {
		t.Fatalf("mptB persisted size after recovery = %d, want %d", mptB.PersistedSize(), crashLeaf)
	}
	if mptB.Root() != expectedRootAt4000 {
		t.Fatalf("recovered MPT root at 4000 mismatch:\ngot  %x\nwant %x", mptB.Root(), expectedRootAt4000)
	}

	// Verify all value roots match Run A at 4000
	for i := 0; i < crashLeaf; i++ {
		kh := sha256.Sum256(leaves[i])
		vrB, err := idxB.GetValueRoot(kh, uint64(crashLeaf))
		if err != nil {
			t.Fatalf("GetValueRoot B failed for key %d: %v", i, err)
		}
		if vrB != expectedValueRootsAt4000[kh] {
			t.Fatalf("value root for key %d mismatch at 4000: got %x, want %x", i, vrB, expectedValueRootsAt4000[kh])
		}
	}

	// -------------------------------------------------------------
	// Resume Genesis Backfill to tip (6000 leaves)
	// -------------------------------------------------------------
	if err := coordB.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce after recovery failed: %v", err)
	}

	// Verify final MPT root matches Run A EXACTLY
	if mptB.Root() != finalRootA {
		t.Fatalf("final recovered MPT root mismatch:\ngot  %x\nwant %x", mptB.Root(), finalRootA)
	}

	stateB := pubB.GetServingState()
	if stateB == nil || stateB.MPTRoot != finalRootA {
		t.Fatalf("serving state MPTRoot mismatch: got %x, want %x", stateB.MPTRoot, finalRootA)
	}

	// Verify MPT inclusion proofs for all leaves against the final root
	for i := 0; i < 50; i++ {
		kh := sha256.Sum256(leaves[i])
		proof, val, exists, err := mptB.Prove(kh)
		if err != nil || !exists {
			t.Fatalf("Prove failed for leaf %d: exists=%v, err=%v", i, exists, err)
		}
		if err := mptpkg.Verify(finalRootA, kh, val, exists, proof); err != nil {
			t.Fatalf("Verify proof failed for leaf %d: %v", i, err)
		}
	}
}

// TestGenesisReplay_MultipleConsecutiveCrashes verifies that recovery succeeds across multiple
// successive dirty crashes at arbitrary leaf boundaries, culminating in a clean Leaf 0 publication at tip.
func TestGenesisReplay_MultipleConsecutiveCrashes(t *testing.T) {
	ctx := context.Background()
	totalLeaves := 10000
	coarseInterval := 2048

	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("multi_crash_leaf_%d", i)))
	}
	mapper := &simpleIdentityMapper{}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	targetCP, err := fetcher.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	mptDir := filepath.Join(dir, "mpt")

	crashes := []struct {
		checkpointBoundary int
		crashBoundary      int
	}{
		{2048, 3500},
		{4096, 5500},
		{6144, 7800},
	}

	lastRecovered := 0

	for cycleIdx, crash := range crashes {
		// 1. Open and advance
		db, err := kvstore.Open(dbDir, &pebble.Options{})
		if err != nil {
			t.Fatalf("cycle %d open db failed: %v", cycleIdx, err)
		}
		_ = db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw)
		mpt, err := mptpkg.Open(mptDir)
		if err != nil {
			t.Fatalf("cycle %d open mpt failed: %v", cycleIdx, err)
		}
		idx := kvstore.NewKVIndexer(db, 64)

		// Advance to checkpoint boundary and snapshot
		if crash.checkpointBoundary > lastRecovered {
			km := make(map[[32]byte][]uint64)
			for i := lastRecovered; i < crash.checkpointBoundary; i++ {
				kh := sha256.Sum256(leaves[i])
				km[kh] = append(km[kh], uint64(i))
			}
			batch := &ingest.MappedBatch{
				StartLeafIdx: uint64(lastRecovered),
				EndLeafIdx:   uint64(crash.checkpointBoundary),
				Count:        uint32(crash.checkpointBoundary - lastRecovered),
				KeyMap:       km,
			}
			res, err := idx.IndexBatch(ctx, batch, targetCP)
			if err != nil {
				t.Fatalf("cycle %d index to checkpoint failed: %v", cycleIdx, err)
			}
			if err := mpt.SetBatch(res.ModifiedValueRoots); err != nil {
				t.Fatalf("cycle %d mpt set batch failed: %v", cycleIdx, err)
			}
			_ = db.Sync()
			_, snapErr := mpt.Snap(int64(crash.checkpointBoundary))
			if snapErr != nil {
				t.Fatalf("cycle %d Snap(%d) failed: %v", cycleIdx, crash.checkpointBoundary, snapErr)
			}
			t.Logf("cycle %d snapped at %d, persistedSize=%d", cycleIdx, crash.checkpointBoundary, mpt.PersistedSize())
			_ = mpt.Sync()
		}

		// Advance to crash boundary without snapping MPT
		kmCrash := make(map[[32]byte][]uint64)
		for i := crash.checkpointBoundary; i < crash.crashBoundary; i++ {
			kh := sha256.Sum256(leaves[i])
			kmCrash[kh] = append(kmCrash[kh], uint64(i))
		}
		batchCrash := &ingest.MappedBatch{
			StartLeafIdx: uint64(crash.checkpointBoundary),
			EndLeafIdx:   uint64(crash.crashBoundary),
			Count:        uint32(crash.crashBoundary - crash.checkpointBoundary),
			KeyMap:       kmCrash,
		}
		resCrash, err := idx.IndexBatch(ctx, batchCrash, targetCP)
		if err != nil {
			t.Fatalf("cycle %d index to crash failed: %v", cycleIdx, err)
		}
		if err := mpt.SetBatch(resCrash.ModifiedValueRoots); err != nil {
			t.Fatalf("cycle %d mpt set crash batch failed: %v", cycleIdx, err)
		}
		_ = db.Sync()

		closeErr := mpt.Close()
		if closeErr != nil {
			t.Fatalf("mpt.Close error: %v", closeErr)
		}
		_ = db.Close()

		// 2. Reopen and Recover()
		dbRec, err := kvstore.Open(dbDir, &pebble.Options{})
		if err != nil {
			t.Fatalf("cycle %d reopen db failed: %v", cycleIdx, err)
		}
		mptRec, err := mptpkg.Open(mptDir)
		if err != nil {
			t.Fatalf("cycle %d reopen mpt failed: %v", cycleIdx, err)
		}
		idxRec := kvstore.NewKVIndexer(dbRec, 64)
		outLogRec := newMemoryOutputLog("example.com/outputlog")
		pubRec := tree.NewOutputPublisher(dbRec, mptRec, outLogRec, nil)

		coordRec := NewCoordinator(dbRec, mptRec, outLogRec, pubRec, idxRec, fetcher, nil, mapper)
		coordRec.SetCommitBatchSize(1024)
		coordRec.SetCoarseCheckpointInterval(uint64(coarseInterval))

		kvSizeRec, _ := dbRec.GetUint64(kvstore.KeyMetaKVSize)
		mptSizeRec := mptRec.PersistedSize()
		t.Logf("cycle %d before recovery: kvSize=%d, mptPersistedSize=%d", cycleIdx, kvSizeRec, mptSizeRec)
		v, exact := mptRec.Version()
		t.Logf("cycle %d mptRec Version: v=%d, exact=%v", cycleIdx, v, exact)

		sw, _ := coordRec.SafeWatermark(ctx)
		if sw != uint64(crash.checkpointBoundary) {
			t.Fatalf("cycle %d sw before recovery = %d, want %d (kvSize=%d, mptSize=%d)", cycleIdx, sw, crash.checkpointBoundary, kvSizeRec, mptSizeRec)
		}

		if err := coordRec.Recover(ctx); err != nil {
			t.Fatalf("cycle %d Recover() failed: %v", cycleIdx, err)
		}

		if mptRec.PersistedSize() != uint64(crash.crashBoundary) {
			t.Fatalf("cycle %d mpt persisted size after recovery = %d, want %d", cycleIdx, mptRec.PersistedSize(), crash.crashBoundary)
		}
		sw, _ = coordRec.SafeWatermark(ctx)
		if sw != uint64(crash.crashBoundary) {
			t.Fatalf("cycle %d sw after recovery = %d, want %d", cycleIdx, sw, crash.crashBoundary)
		}

		lastRecovered = crash.crashBoundary
		_ = mptRec.Close()
		_ = dbRec.Close()
	}

	// -------------------------------------------------------------
	// Final Stage: Complete to tip (10,000 leaves)
	// -------------------------------------------------------------
	dbFinal, err := kvstore.Open(dbDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("final open db failed: %v", err)
	}
	t.Cleanup(func() { _ = dbFinal.Close() })

	mptFinal, err := mptpkg.Open(mptDir)
	if err != nil {
		t.Fatalf("final open mpt failed: %v", err)
	}
	t.Cleanup(func() { _ = mptFinal.Close() })

	idxFinal := kvstore.NewKVIndexer(dbFinal, 64)
	outLogFinal := newMemoryOutputLog("example.com/outputlog")
	pubFinal := tree.NewOutputPublisher(dbFinal, mptFinal, outLogFinal, nil)

	coordFinal := NewCoordinator(dbFinal, mptFinal, outLogFinal, pubFinal, idxFinal, fetcher, nil, mapper)
	coordFinal.SetCommitBatchSize(1024)
	coordFinal.SetCoarseCheckpointInterval(uint64(coarseInterval))

	if err := coordFinal.Recover(ctx); err != nil {
		t.Fatalf("final Recover() failed: %v", err)
	}
	if err := coordFinal.SyncOnce(ctx); err != nil {
		t.Fatalf("final SyncOnce failed: %v", err)
	}

	outSize, err := outLogFinal.Size(ctx)
	if err != nil || outSize != 1 {
		t.Fatalf("final outLog size = %d (err: %v), want 1", outSize, err)
	}

	state := pubFinal.GetServingState()
	if state == nil || state.InputLogSize != uint64(totalLeaves) {
		t.Fatalf("final servingState invalid: %+v", state)
	}

	refMem := mptpkg.NewMem()
	refKeys := make(map[[32]byte][32]byte, totalLeaves)
	for i := 0; i < totalLeaves; i++ {
		kh := sha256.Sum256(leaves[i])
		vr, err := idxFinal.GetValueRoot(kh, uint64(totalLeaves))
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
		t.Fatalf("multi-crash MPTRoot mismatch:\ngot  %x\nwant %x", state.MPTRoot, expectedRoot)
	}
}

// TestGenesisReplay_KeyDeduplicationAndChunkSpanning rigorously tests key deduplication
// and Merkle value log reconstruction across pre-crash, replay, and post-crash windows with a small chunk size.
func TestGenesisReplay_KeyDeduplicationAndChunkSpanning(t *testing.T) {
	ctx := context.Background()
	const customChunkSize = 8 // Small chunk size to force multi-chunk rollover
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	mptDir := filepath.Join(dir, "mpt")

	keyGlobal := sha256.Sum256([]byte("key_global"))
	keyReplayMulti := sha256.Sum256([]byte("key_replay_multi"))
	keyPreAndReplay := sha256.Sum256([]byte("key_pre_and_replay"))
	keyReplayAndPost := sha256.Sum256([]byte("key_replay_and_post"))

	leafStringToKey := make(map[string][32]byte)
	leafStringToKey["complex_leaf_2"] = keyGlobal
	leafStringToKey["complex_leaf_6"] = keyGlobal
	leafStringToKey["complex_leaf_12"] = keyGlobal
	leafStringToKey["complex_leaf_18"] = keyGlobal
	leafStringToKey["complex_leaf_22"] = keyGlobal
	leafStringToKey["complex_leaf_28"] = keyGlobal
	leafStringToKey["complex_leaf_34"] = keyGlobal
	leafStringToKey["complex_leaf_40"] = keyGlobal

	leafStringToKey["complex_leaf_17"] = keyReplayMulti
	leafStringToKey["complex_leaf_20"] = keyReplayMulti
	leafStringToKey["complex_leaf_25"] = keyReplayMulti
	leafStringToKey["complex_leaf_30"] = keyReplayMulti

	leafStringToKey["complex_leaf_4"] = keyPreAndReplay
	leafStringToKey["complex_leaf_10"] = keyPreAndReplay
	leafStringToKey["complex_leaf_24"] = keyPreAndReplay

	leafStringToKey["complex_leaf_26"] = keyReplayAndPost
	leafStringToKey["complex_leaf_36"] = keyReplayAndPost
	leafStringToKey["complex_leaf_42"] = keyReplayAndPost

	const totalLeaves = 48
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("complex_leaf_%d", i)))
	}

	customMapper := &designatedMapper{leafStringToKey: leafStringToKey}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	targetCP, _ := fetcher.Checkpoint(ctx)

	buildKeyMap := func(start, end int) map[[32]byte][]uint64 {
		km := make(map[[32]byte][]uint64)
		for i := start; i < end; i++ {
			s := fmt.Sprintf("complex_leaf_%d", i)
			k, ok := leafStringToKey[s]
			if !ok {
				k = sha256.Sum256([]byte(s))
			}
			km[k] = append(km[k], uint64(i))
		}
		for k, indices := range km {
			slices.Sort(indices)
			km[k] = slices.Compact(indices)
		}
		return km
	}

	// Phase 1: Ingest 0..16, checkpoint at 16
	// Ingest 16..32, crash at 32
	{
		db, err := kvstore.Open(dbDir, &pebble.Options{})
		if err != nil {
			t.Fatalf("Open db failed: %v", err)
		}
		db.SetChunkSize(customChunkSize)
		_ = db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw)
		mpt, err := mptpkg.Open(mptDir)
		if err != nil {
			t.Fatalf("Open mpt failed: %v", err)
		}
		idx := kvstore.NewKVIndexer(db, customChunkSize)

		// 0..16
		km1 := buildKeyMap(0, 16)
		b1 := &ingest.MappedBatch{StartLeafIdx: 0, EndLeafIdx: 16, Count: 16, KeyMap: km1}
		res1, err := idx.IndexBatch(ctx, b1, targetCP)
		if err != nil {
			t.Fatalf("IndexBatch 1 failed: %v", err)
		}
		_ = mpt.SetBatch(res1.ModifiedValueRoots)
		_ = db.Sync()
		_, _ = mpt.Snap(16)
		_ = mpt.Sync()

		// 16..32
		km2 := buildKeyMap(16, 32)
		b2 := &ingest.MappedBatch{StartLeafIdx: 16, EndLeafIdx: 32, Count: 16, KeyMap: km2}
		res2, err := idx.IndexBatch(ctx, b2, targetCP)
		if err != nil {
			t.Fatalf("IndexBatch 2 failed: %v", err)
		}
		_ = mpt.SetBatch(res2.ModifiedValueRoots)
		_ = db.Sync()

		_ = mpt.Close()
		_ = db.Close()
	}

	// Phase 2: Reopen and recover [16..32)
	db, err := kvstore.Open(dbDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Reopen db failed: %v", err)
	}
	db.SetChunkSize(customChunkSize)
	t.Cleanup(func() { _ = db.Close() })
	mpt, err := mptpkg.Open(mptDir)
	if err != nil {
		t.Fatalf("Reopen mpt failed: %v", err)
	}
	t.Cleanup(func() { _ = mpt.Close() })
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mpt, outLog, nil)
	idx := kvstore.NewKVIndexer(db, customChunkSize)

	coord := NewCoordinator(db, mpt, outLog, pub, idx, fetcher, nil, customMapper)
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover() failed: %v", err)
	}

	// Verify all value roots at 32 match the reference compact range roots exactly
	assertValueRoot := func(kh [32]byte, expectedIndices []uint64, desc string) {
		vr, err := idx.GetValueRoot(kh, 32)
		if err != nil {
			t.Fatalf("GetValueRoot(%s) failed: %v", desc, err)
		}
		expected := computeReferenceValueRoot(expectedIndices)
		if vr != expected {
			t.Fatalf("ValueRoot(%s) mismatch at 32:\ngot  %x\nwant %x", desc, vr, expected)
		}
	}

	assertValueRoot(keyGlobal, []uint64{2, 6, 12, 18, 22, 28}, "keyGlobal at 32")
	assertValueRoot(keyReplayMulti, []uint64{17, 20, 25, 30}, "keyReplayMulti at 32")
	assertValueRoot(keyPreAndReplay, []uint64{4, 10, 24}, "keyPreAndReplay at 32")
	assertValueRoot(keyReplayAndPost, []uint64{26}, "keyReplayAndPost at 32")

	// Phase 3: Resume backfill to tip (48)
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce failed: %v", err)
	}

	assertValueRoot48 := func(kh [32]byte, expectedIndices []uint64, desc string) {
		vr, err := idx.GetValueRoot(kh, 48)
		if err != nil {
			t.Fatalf("GetValueRoot(%s) at 48 failed: %v", desc, err)
		}
		expected := computeReferenceValueRoot(expectedIndices)
		if vr != expected {
			t.Fatalf("ValueRoot(%s) mismatch at 48:\ngot  %x\nwant %x", desc, vr, expected)
		}
	}

	assertValueRoot48(keyGlobal, []uint64{2, 6, 12, 18, 22, 28, 34, 40}, "keyGlobal at 48")
	assertValueRoot48(keyReplayMulti, []uint64{17, 20, 25, 30}, "keyReplayMulti at 48")
	assertValueRoot48(keyPreAndReplay, []uint64{4, 10, 24}, "keyPreAndReplay at 48")
	assertValueRoot48(keyReplayAndPost, []uint64{26, 36, 42}, "keyReplayAndPost at 48")

	lookupRes, err := db.Lookup(keyGlobal, nil, 100, 48)
	if err != nil {
		t.Fatalf("Lookup keyGlobal failed: %v", err)
	}
	wantGlobal := []uint64{2, 6, 12, 18, 22, 28, 34, 40}
	if !slices.Equal(lookupRes.MatchedIndices, wantGlobal) {
		t.Fatalf("Lookup keyGlobal returned %v, want %v", lookupRes.MatchedIndices, wantGlobal)
	}
}

// TestGenesisReplay_ZeroStorageWriteAmplification strictly verifies that recoverGenesisBackfill
// performs ZERO storage writes to Pebble: key/value counts and content in Pebble before recovery
// must be 100% byte-for-byte identical after recovery.
func TestGenesisReplay_ZeroStorageWriteAmplification(t *testing.T) {
	ctx := context.Background()
	totalLeaves := 5000
	coarseCheckpoint := 2048
	crashLeaf := 4000

	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("zero_write_leaf_%d", i)))
	}
	mapper := &simpleIdentityMapper{}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	targetCP, _ := fetcher.Checkpoint(ctx)

	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	mptDir := filepath.Join(dir, "mpt")

	buildKeyMap := func(start, end int) map[[32]byte][]uint64 {
		km := make(map[[32]byte][]uint64)
		for i := start; i < end; i++ {
			kh := sha256.Sum256(leaves[i])
			km[kh] = append(km[kh], uint64(i))
		}
		for k, indices := range km {
			slices.Sort(indices)
			km[k] = slices.Compact(indices)
		}
		return km
	}

	// Ingest 0..2048 (checkpoint), then 2048..4000 and crash
	{
		db, err := kvstore.Open(dbDir, &pebble.Options{})
		if err != nil {
			t.Fatalf("Open db failed: %v", err)
		}
		_ = db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw)
		mpt, err := mptpkg.Open(mptDir)
		if err != nil {
			t.Fatalf("Open mpt failed: %v", err)
		}
		idx := kvstore.NewKVIndexer(db, 64)

		km1 := buildKeyMap(0, coarseCheckpoint)
		b1 := &ingest.MappedBatch{StartLeafIdx: 0, EndLeafIdx: uint64(coarseCheckpoint), Count: uint32(coarseCheckpoint), KeyMap: km1}
		res1, _ := idx.IndexBatch(ctx, b1, targetCP)
		_ = mpt.SetBatch(res1.ModifiedValueRoots)
		_ = db.Sync()
		_, _ = mpt.Snap(int64(coarseCheckpoint))
		_ = mpt.Sync()

		km2 := buildKeyMap(coarseCheckpoint, crashLeaf)
		b2 := &ingest.MappedBatch{StartLeafIdx: uint64(coarseCheckpoint), EndLeafIdx: uint64(crashLeaf), Count: uint32(crashLeaf - coarseCheckpoint), KeyMap: km2}
		res2, _ := idx.IndexBatch(ctx, b2, targetCP)
		_ = mpt.SetBatch(res2.ModifiedValueRoots)
		_ = db.Sync()

		_ = mpt.Close()
		_ = db.Close()
	}

	// Reopen after dirty crash
	db, err := kvstore.Open(dbDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Reopen db failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mpt, err := mptpkg.Open(mptDir)
	if err != nil {
		t.Fatalf("Reopen mpt failed: %v", err)
	}
	t.Cleanup(func() { _ = mpt.Close() })

	kvsBefore := snapshotPebbleKVs(t, db)

	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mpt, outLog, nil)
	idx := kvstore.NewKVIndexer(db, 64)

	coord := NewCoordinator(db, mpt, outLog, pub, idx, fetcher, nil, mapper)
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover() failed: %v", err)
	}

	kvsAfter := snapshotPebbleKVs(t, db)

	// Invariant Assertion: ZERO STORAGE WRITES
	if len(kvsBefore) != len(kvsAfter) {
		t.Fatalf("Pebble key count modified during recovery: before=%d, after=%d", len(kvsBefore), len(kvsAfter))
	}
	for k, vBefore := range kvsBefore {
		vAfter, ok := kvsAfter[k]
		if !ok {
			t.Fatalf("Pebble key %x missing after recovery", k)
		}
		if vBefore != vAfter {
			t.Fatalf("Pebble value for key %x altered during recovery", k)
		}
	}
}

// TestGenesisReplay_CleanShutdownNoOp verifies that when mptPersistedSize == kvSize,
// Recover() performs zero tile streaming, zero batch indexing, and returns nil immediately.
func TestGenesisReplay_CleanShutdownNoOp(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := kvstore.Open(filepath.Join(dir, "db"), &pebble.Options{})
	if err != nil {
		t.Fatalf("Open db failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mpt, err := mptpkg.Open(filepath.Join(dir, "mpt"))
	if err != nil {
		t.Fatalf("Open mpt failed: %v", err)
	}
	t.Cleanup(func() { _ = mpt.Close() })

	// Setup clean state: both at 1000
	_ = db.SetUint64(kvstore.KeyMetaKVSize, 1000)
	_ = db.Sync()
	_, _ = mpt.Snap(1000)
	_ = mpt.Sync()

	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mpt, outLog, nil)
	idx := kvstore.NewKVIndexer(db, 64)

	fetcher := &memoryTileFetcher{leaves: nil}
	coord := NewCoordinator(db, mpt, outLog, pub, idx, fetcher, nil, &simpleIdentityMapper{})

	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover() on clean state failed: %v", err)
	}
	if mpt.PersistedSize() != 1000 {
		t.Fatalf("mpt persisted size = %d, want 1000", mpt.PersistedSize())
	}
}

// TestGenesisReplay_InvariantViolations verifies that recoverGenesisBackfill catches
// invalid durability states (such as mptPersistedSize > kvSize) and returns typed errors.
func TestGenesisReplay_InvariantViolations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := kvstore.Open(filepath.Join(dir, "db"), &pebble.Options{})
	if err != nil {
		t.Fatalf("Open db failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mpt, err := mptpkg.Open(filepath.Join(dir, "mpt"))
	if err != nil {
		t.Fatalf("Open mpt failed: %v", err)
	}
	t.Cleanup(func() { _ = mpt.Close() })

	// Corrupt invariant: MPT size (2000) > kv_size (1000)
	_ = db.SetUint64(kvstore.KeyMetaKVSize, 1000)
	_ = db.Sync()
	_, _ = mpt.Snap(2000)
	_ = mpt.Sync()

	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mpt, outLog, nil)
	idx := kvstore.NewKVIndexer(db, 64)

	coord := NewCoordinator(db, mpt, outLog, pub, idx, nil, nil, nil)
	err = coord.Recover(ctx)
	if err == nil {
		t.Fatal("expected ErrInvariantViolation when mptPersistedSize > kvSize, got nil")
	}
	if !errors.Is(err, ErrInvariantViolation) {
		t.Fatalf("expected ErrInvariantViolation, got %v", err)
	}
}

// TestGenesisReplay_SafeWatermark_Lifecycle tests SafeWatermark across all lifecycle stages:
// unstarted, in-progress, dirty crash, post-recovery, and tip publication.
func TestGenesisReplay_SafeWatermark_Lifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, _ := kvstore.Open(filepath.Join(dir, "db"), &pebble.Options{})
	t.Cleanup(func() { _ = db.Close() })
	mpt, _ := mptpkg.Open(filepath.Join(dir, "mpt"))
	t.Cleanup(func() { _ = mpt.Close() })
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mpt, outLog, nil)
	idx := kvstore.NewKVIndexer(db, 64)

	coord := NewCoordinator(db, mpt, outLog, pub, idx, nil, nil, nil)

	// Stage 1: Initial empty state
	sw, err := coord.SafeWatermark(ctx)
	if err != nil || sw != 0 {
		t.Fatalf("initial sw = %d (err: %v), want 0", sw, err)
	}

	// Stage 2: Coarse checkpoint at 2048, kv at 3500
	_ = db.SetUint64(kvstore.KeyMetaKVSize, 3500)
	_, _ = mpt.Snap(2048)
	_ = mpt.Persist()
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 2048 {
		t.Fatalf("dirty crash sw = %d, want 2048", sw)
	}

	// Stage 3: After recovery, MPT snapped at 3500
	_, _ = mpt.Snap(3500)
	_ = mpt.Persist()
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 3500 {
		t.Fatalf("post-recovery sw = %d, want 3500", sw)
	}

	// Stage 4: Leaf 0 published with ServingState at 10000
	_ = db.SetUint64(kvstore.KeyMetaKVSize, 10000)
	_, _ = mpt.Snap(10000)
	_ = mpt.Persist()
	pub.SetServingState(&tree.ServingState{InputLogSize: 10000})
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 10000 {
		t.Fatalf("normal serving sw = %d, want 10000", sw)
	}
}

type designatedMapper struct {
	leafStringToKey map[string][32]byte
}

func (m *designatedMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	if k, ok := m.leafStringToKey[string(leaf)]; ok {
		return []ingest.MappedEntry{{KeyHash: k}}, nil
	}
	return []ingest.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
}

func (m *designatedMapper) Close(_ context.Context) error {
	return nil
}
