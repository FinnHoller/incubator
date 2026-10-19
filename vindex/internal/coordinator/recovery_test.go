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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/tessera/api"
	"golang.org/x/mod/sumdb/tlog"
)

type memoryOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
}

func newMemoryOutputLog(origin string) *memoryOutputLog {
	return &memoryOutputLog{origin: origin}
}

func (m *memoryOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return idx, []byte(rawCP), nil
}

func (m *memoryOutputLog) Size(_ context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.leaves)), nil
}

func (m *memoryOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx >= uint64(len(m.leaves)) {
		return nil, fmt.Errorf("index out of range %d >= %d", idx, len(m.leaves))
	}
	return m.leaves[idx], nil
}

func (m *memoryOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	size := uint64(len(m.leaves))
	root := kvstore.BatchRoot(m.leaves)
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))), nil
}

func (m *memoryOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var leafHashes [][sha256.Size]byte
	for _, l := range m.leaves[:treeSize] {
		leafHashes = append(leafHashes, kvstore.LeafHash(l))
	}

	var proof [][sha256.Size]byte
	var buildProof func(leaves [][sha256.Size]byte, idx uint64)
	buildProof = func(leaves [][sha256.Size]byte, idx uint64) {
		n := len(leaves)
		if n <= 1 {
			return
		}
		k := uint64(1) << (bits.Len(uint(n-1)) - 1)
		if idx < k {
			rightSubRoot := kvstore.BatchRootHashes(leaves[k:])
			buildProof(leaves[:k], idx)
			proof = append(proof, rightSubRoot)
		} else {
			leftSubRoot := kvstore.BatchRootHashes(leaves[:k])
			buildProof(leaves[k:], idx-k)
			proof = append(proof, leftSubRoot)
		}
	}

	buildProof(leafHashes, leafIdx)
	return proof, nil
}

type memoryTileFetcher struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
}

func (f *memoryTileFetcher) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	root := kvstore.BatchRoot(f.leaves)
	return &ingest.Checkpoint{
		Raw:    []byte(fmt.Sprintf("%s\n%d\n%x\n", f.origin, len(f.leaves), root)),
		Origin: f.origin,
		Size:   uint64(len(f.leaves)),
		Hash:   root,
	}, nil
}

func (f *memoryTileFetcher) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if idx >= uint64(len(f.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (len %d)", idx, len(f.leaves))
	}
	return f.leaves[idx], nil
}

func (f *memoryTileFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     f.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

type simpleIdentityMapper struct{}

func (m *simpleIdentityMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	kh := sha256.Sum256(leaf)
	return []ingest.MappedEntry{{KeyHash: kh}}, nil
}

func (m *simpleIdentityMapper) Close(_ context.Context) error { return nil }

func setupRecoveryEnvironment(t *testing.T) (*Coordinator, *kvstore.DB, *mpt.Manager, *tree.OutputPublisher, *kvstore.KVIndexer, *memoryOutputLog, *memoryTileFetcher) {
	t.Helper()
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := mpt.NewMem()
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	indexer := kvstore.NewKVIndexer(db, 64)

	var leaves [][]byte
	for i := 0; i < 200; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("leaf_recovery_%d", i)))
	}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	mapper := &simpleIdentityMapper{}

	coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, mapper)
	return coord, db, mptMgr, pub, indexer, outLog, fetcher
}

func TestRecovery_CleanStartup(t *testing.T) {
	ctx := context.Background()
	coord, _, _, pub, _, outLog, _ := setupRecoveryEnvironment(t)

	// Clean empty state
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover on clean empty state failed: %v", err)
	}

	if pub.GetServingState() != nil {
		t.Fatal("expected nil serving state for empty output log")
	}
	size, err := outLog.Size(ctx)
	if err != nil || size != 0 {
		t.Fatalf("outLog size = %d, want 0", size)
	}
}

func TestRecovery_Phase1InstantServing(t *testing.T) {
	ctx := context.Background()
	_, db, mptMgr, pub, indexer, outLog, _ := setupRecoveryEnvironment(t)

	// Ingest & publish batch of 50 leaves
	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			sha256.Sum256([]byte("leaf_recovery_0")): {0},
		},
	}
	res1, err := indexer.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/inputlog\n50\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   50,
		Hash:   make([]byte, 32),
	}
	state1, err := pub.PublishBatch(ctx, res1.ModifiedValueRoots, inputCP, rawInCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	// Persist MPT version 50
	if err := mptMgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// Simulate daemon restart: create new coordinator & publisher
	newPub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	newCoord := NewCoordinator(db, mptMgr, outLog, newPub, indexer, nil, nil, nil)

	// Run Phase 1
	matched, err := newCoord.Phase1(ctx)
	if err != nil {
		t.Fatalf("Phase1 failed: %v", err)
	}
	if !matched {
		t.Fatalf("Phase1 matched=%v; want true", matched)
	}

	restoredState := newPub.GetServingState()
	if restoredState == nil {
		t.Fatal("restored serving state is nil")
		return
	}
	if restoredState.InputLogSize != 50 {
		t.Fatalf("restored InputLogSize = %d, want 50", restoredState.InputLogSize)
	}
	if restoredState.MPTRoot != state1.MPTRoot {
		t.Fatalf("restored MPTRoot %x != original %x", restoredState.MPTRoot, state1.MPTRoot)
	}
}

func TestRecovery_Phase2ReplayCatchup(t *testing.T) {
	ctx := context.Background()
	_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)

	// Step 1: Ingest & Publish state at 50 leaves (MPT size 50)
	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			sha256.Sum256([]byte("leaf_recovery_10")): {10},
		},
	}
	res1, err := indexer.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	rawInCP1 := []byte("example.com/inputlog\n50\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP1 := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: make([]byte, 32)}
	_, err = pub.PublishBatch(ctx, res1.ModifiedValueRoots, inputCP1, rawInCP1)
	if err != nil {
		t.Fatalf("PublishBatch 1 failed: %v", err)
	}

	// Step 2: Publish state at 100 leaves to Output Log, BUT crash before MPT commit
	keyMap2 := make(map[[32]byte][]uint64)
	for i := 50; i < 100; i++ {
		kh := sha256.Sum256([]byte(fmt.Sprintf("leaf_recovery_%d", i)))
		keyMap2[kh] = append(keyMap2[kh], uint64(i))
	}
	batch2 := &ingest.MappedBatch{
		BundleIdx:    1,
		StartLeafIdx: 50,
		Count:        50,
		KeyMap:       keyMap2,
	}
	res2, err := indexer.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("IndexBatch 2 failed: %v", err)
	}
	inputCP2 := &log.Checkpoint{Origin: "example.com/inputlog", Size: 100, Hash: make([]byte, 32)}

	predictedRoot2, err := mptMgr.Predict(res2.ModifiedValueRoots)
	if err != nil {
		t.Fatalf("Predict failed: %v", err)
	}

	// Simulate output log leaf append without MPT mutation
	leafData2 := tree.FormatOutputLogLeaf(predictedRoot2, inputCP2)
	if _, _, err := outLog.Append(ctx, leafData2); err != nil {
		t.Fatalf("outLog.Append failed: %v", err)
	}

	// Step 3: Now MPT is at version 50, but Output Log is at version 100
	newPub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	newCoord := NewCoordinator(db, mptMgr, outLog, newPub, indexer, fetcher, nil, &simpleIdentityMapper{})

	if err := newCoord.Recover(ctx); err != nil {
		t.Fatalf("Recover failed during Phase 2 replay: %v", err)
	}

	restoredState := newPub.GetServingState()
	if restoredState == nil {
		t.Fatal("restored serving state is nil after Phase 2")
		return
	}
	if restoredState.InputLogSize != 100 {
		t.Fatalf("restored InputLogSize = %d, want 100", restoredState.InputLogSize)
	}
	if restoredState.MPTRoot != predictedRoot2 {
		t.Fatalf("restored MPTRoot %x != predicted tip root %x", restoredState.MPTRoot, predictedRoot2)
	}
}

func TestCoordinator_SyncOnce(t *testing.T) {
	ctx := context.Background()
	coord, db, _, pub, _, outLog, fetcher := setupRecoveryEnvironment(t)

	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	// 1. Initial SyncOnce for 200 leaves
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce failed: %v", err)
	}

	state := pub.GetServingState()
	if state == nil {
		t.Fatal("expected non-nil serving state after SyncOnce")
		return
	}
	if state.InputLogSize != 200 {
		t.Fatalf("InputLogSize = %d, want 200", state.InputLogSize)
	}

	outSize, err := outLog.Size(ctx)
	if err != nil || outSize != 1 {
		t.Fatalf("outLog.Size = %d, want 1", outSize)
	}

	// 2. Sync again without new data -> no-op
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce (no-op) failed: %v", err)
	}
	outSize2, _ := outLog.Size(ctx)
	if outSize2 != 1 {
		t.Fatalf("outLog.Size = %d after no-op SyncOnce, want 1", outSize2)
	}

	// 3. Append 50 more leaves to input log and sync
	fetcher.mu.Lock()
	for i := 200; i < 250; i++ {
		fetcher.leaves = append(fetcher.leaves, []byte(fmt.Sprintf("leaf_recovery_%d", i)))
	}
	fetcher.mu.Unlock()

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce (incremental) failed: %v", err)
	}
	state2 := pub.GetServingState()
	if state2.InputLogSize != 250 {
		t.Fatalf("state2.InputLogSize = %d, want 250", state2.InputLogSize)
	}
	outSize3, _ := outLog.Size(ctx)
	if outSize3 != 2 {
		t.Fatalf("outLog.Size = %d after second sync, want 2", outSize3)
	}

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil || kvSize != 250 {
		t.Fatalf("kvSize = %d, want 250", kvSize)
	}
}

func TestCoordinator_Run(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	coord, _, _, pub, _, _, _ := setupRecoveryEnvironment(t)

	if err := coord.Run(ctx, 10*time.Millisecond); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	state := pub.GetServingState()
	if state == nil || state.InputLogSize != 200 {
		t.Fatalf("expected state with size 200, got %v", state)
	}
}

func TestCoordinator_CommitBatchAggregation(t *testing.T) {
	ctx := context.Background()
	coord, db, mptMgr, pub, _, outLog, fetcher := setupRecoveryEnvironment(t)

	// Verify defaults and setter/getter
	if coord.CommitBatchSize() != DefaultCommitBatchSize {
		t.Fatalf("CommitBatchSize = %d, want %d", coord.CommitBatchSize(), DefaultCommitBatchSize)
	}
	coord.SetCommitBatchSize(64)
	if coord.CommitBatchSize() != 64 {
		t.Fatalf("CommitBatchSize = %d, want 64", coord.CommitBatchSize())
	}
	coord.SetCommitBatchSize(0) // resets to default
	if coord.CommitBatchSize() != DefaultCommitBatchSize {
		t.Fatalf("CommitBatchSize = %d after 0 reset, want %d", coord.CommitBatchSize(), DefaultCommitBatchSize)
	}
	coord.SetCommitBatchSize(64)

	// Initial SyncOnce for 200 leaves with commit batch size 64
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce failed: %v", err)
	}

	state := pub.GetServingState()
	if state == nil || state.InputLogSize != 200 {
		t.Fatalf("state.InputLogSize = %v, want 200", state)
	}

	// Output log should have exactly 1 commitment checkpoint
	outSize, err := outLog.Size(ctx)
	if err != nil || outSize != 1 {
		t.Fatalf("outLog.Size = %d, want 1", outSize)
	}

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil || kvSize != 200 {
		t.Fatalf("kvSize = %d, want 200", kvSize)
	}

	// Add 50 more leaves (total 250 leaves)
	fetcher.mu.Lock()
	for i := 200; i < 250; i++ {
		fetcher.leaves = append(fetcher.leaves, []byte(fmt.Sprintf("leaf_recovery_%d", i)))
	}
	fetcher.mu.Unlock()

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce incremental failed: %v", err)
	}

	state2 := pub.GetServingState()
	if state2 == nil || state2.InputLogSize != 250 {
		t.Fatalf("state2.InputLogSize = %v, want 250", state2)
	}

	outSize2, _ := outLog.Size(ctx)
	if outSize2 != 2 {
		t.Fatalf("outLog.Size = %d, want 2", outSize2)
	}

	kvSize2, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil || kvSize2 != 250 {
		t.Fatalf("kvSize2 = %d, want 250", kvSize2)
	}

	if mptMgr.PersistedSize() != 250 {
		t.Fatalf("mpt persisted size = %d, want 250", mptMgr.PersistedSize())
	}
}

func TestRecovery_LaggingMPT_FallbackToPhase2(t *testing.T) {
	ctx := context.Background()
	_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)

	// Step 1: Ingest & Publish state at 50 leaves (MPT persisted at 50)
	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			sha256.Sum256([]byte("leaf_recovery_lagging")): {10},
		},
	}
	res1, err := indexer.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	rawInCP1 := []byte("example.com/inputlog\n50\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP1 := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: make([]byte, 32)}
	_, err = pub.PublishBatch(ctx, res1.ModifiedValueRoots, inputCP1, rawInCP1)
	if err != nil {
		t.Fatalf("PublishBatch 1 failed: %v", err)
	}
	if err := mptMgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// Step 2: Ingest & Publish state at 100 leaves (Output Log tip is at 100), but do NOT persist MPT
	keyMap2 := make(map[[32]byte][]uint64)
	for i := 50; i < 100; i++ {
		kh := sha256.Sum256([]byte(fmt.Sprintf("leaf_recovery_%d", i)))
		keyMap2[kh] = append(keyMap2[kh], uint64(i))
	}
	batch2 := &ingest.MappedBatch{
		BundleIdx:    1,
		StartLeafIdx: 50,
		Count:        50,
		KeyMap:       keyMap2,
	}
	res2, err := indexer.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("IndexBatch 2 failed: %v", err)
	}
	rawInCP2 := []byte("example.com/inputlog\n100\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP2 := &log.Checkpoint{Origin: "example.com/inputlog", Size: 100, Hash: make([]byte, 32)}
	state2, err := pub.PublishBatch(ctx, res2.ModifiedValueRoots, inputCP2, rawInCP2)
	if err != nil {
		t.Fatalf("PublishBatch 2 failed: %v", err)
	}

	// Step 3: Simulate restart where MPT on disk is at version 50, while Output Log is at version 100
	mptOnDisk := mpt.NewMem()
	_, _ = mptOnDisk.CommitWithVersion(res1.ModifiedValueRoots, 50)
	_ = mptOnDisk.Persist()

	newPub := tree.NewOutputPublisher(db, mptOnDisk, outLog, nil)
	newCoord := NewCoordinator(db, mptOnDisk, outLog, newPub, indexer, fetcher, nil, &simpleIdentityMapper{})

	// Phase 1 must return matched=false because Tip is at 100 but MPT is at 50
	matched, err := newCoord.Phase1(ctx)
	if err != nil {
		t.Fatalf("Phase1 failed on lagging restart: %v", err)
	}
	if matched {
		t.Fatal("expected matched=false for lagging MPT against tip")
	}

	// Full Recover() must execute Phase 2 replay to tip and recover to state2
	if err := newCoord.Recover(ctx); err != nil {
		t.Fatalf("Recover failed on lagging restart: %v", err)
	}

	restoredState := newPub.GetServingState()
	if restoredState == nil {
		t.Fatal("restored serving state is nil")
		return
	}
	if restoredState.InputLogSize != 100 {
		t.Fatalf("restored InputLogSize = %d, want 100", restoredState.InputLogSize)
	}
	if restoredState.MPTRoot != state2.MPTRoot {
		t.Fatalf("restored MPTRoot %x != state2 MPTRoot %x", restoredState.MPTRoot, state2.MPTRoot)
	}
}

func TestRecovery_InvariantViolations(t *testing.T) {
	ctx := context.Background()

	t.Run("kv_size_less_than_output_log_tip", func(t *testing.T) {
		_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)
		// Setup Output Log tip at size 100
		inCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 100, Hash: make([]byte, 32)}
		leafData := tree.FormatOutputLogLeaf(sha256.Sum256([]byte("dummy_root")), inCP)
		if _, _, err := outLog.Append(ctx, leafData); err != nil {
			t.Fatalf("outLog.Append failed: %v", err)
		}
		// Set m_kv_size to 50 (< 100)
		if err := db.SetUint64(kvstore.KeyMetaKVSize, 50); err != nil {
			t.Fatalf("SetUint64 failed: %v", err)
		}

		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})
		err := coord.Recover(ctx)
		if err == nil || !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected ErrInvariantViolation, got %v", err)
		}
	})

	t.Run("kv_size_less_than_mpt_persisted_size", func(t *testing.T) {
		_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)
		// Setup Output Log tip at size 100
		inCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 100, Hash: make([]byte, 32)}
		leafData := tree.FormatOutputLogLeaf(sha256.Sum256([]byte("dummy_root")), inCP)
		if _, _, err := outLog.Append(ctx, leafData); err != nil {
			t.Fatalf("outLog.Append failed: %v", err)
		}
		// Set m_kv_size to 100
		if err := db.SetUint64(kvstore.KeyMetaKVSize, 100); err != nil {
			t.Fatalf("SetUint64 failed: %v", err)
		}
		// Commit MPT at version 150 (> kv_size 100)
		_, _ = mptMgr.CommitWithVersion(nil, 150)
		_ = mptMgr.Persist()

		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})
		err := coord.Recover(ctx)
		if err == nil || !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected ErrInvariantViolation, got %v", err)
		}
	})

	t.Run("mpt_persisted_size_greater_than_output_log_tip", func(t *testing.T) {
		_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)
		// Setup Output Log tip at size 50
		inCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: make([]byte, 32)}
		leafData := tree.FormatOutputLogLeaf(sha256.Sum256([]byte("dummy_root")), inCP)
		if _, _, err := outLog.Append(ctx, leafData); err != nil {
			t.Fatalf("outLog.Append failed: %v", err)
		}
		// Set m_kv_size to 100
		if err := db.SetUint64(kvstore.KeyMetaKVSize, 100); err != nil {
			t.Fatalf("SetUint64 failed: %v", err)
		}
		// Commit MPT at version 75 (> tip 50)
		_, _ = mptMgr.CommitWithVersion(nil, 75)
		_ = mptMgr.Persist()

		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})
		err := coord.Recover(ctx)
		if err == nil || !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected ErrInvariantViolation, got %v", err)
		}
	})

	t.Run("mpt_root_mismatch_at_equal_size", func(t *testing.T) {
		_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)
		// Setup Output Log tip at size 50 with a specific root
		inCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: make([]byte, 32)}
		tipRoot := sha256.Sum256([]byte("expected_tip_root"))
		leafData := tree.FormatOutputLogLeaf(tipRoot, inCP)
		if _, _, err := outLog.Append(ctx, leafData); err != nil {
			t.Fatalf("outLog.Append failed: %v", err)
		}
		// Set m_kv_size to 50
		if err := db.SetUint64(kvstore.KeyMetaKVSize, 50); err != nil {
			t.Fatalf("SetUint64 failed: %v", err)
		}
		// Commit MPT at version 50 with a different root
		_, _ = mptMgr.CommitWithVersion(map[[32]byte][32]byte{
			sha256.Sum256([]byte("k1")): sha256.Sum256([]byte("v1")),
		}, 50)
		_ = mptMgr.Persist()

		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})
		err := coord.Recover(ctx)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrRootMismatch) {
			t.Fatalf("expected errors.Is(err, ErrRootMismatch), got %v", err)
		}
		if !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected errors.Is(err, ErrInvariantViolation), got %v", err)
		}
	})

	t.Run("replayed_root_mismatch_against_tip", func(t *testing.T) {
		_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)
		// Tip at size 50 with an unachievable fraudulent root
		inCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: make([]byte, 32)}
		fraudulentRoot := sha256.Sum256([]byte("fraudulent_root_cannot_match"))
		leafData := tree.FormatOutputLogLeaf(fraudulentRoot, inCP)
		if _, _, err := outLog.Append(ctx, leafData); err != nil {
			t.Fatalf("outLog.Append failed: %v", err)
		}
		// Ingest 50 leaves into Pebble
		batch := &ingest.MappedBatch{
			BundleIdx:    0,
			StartLeafIdx: 0,
			Count:        50,
			KeyMap: map[[32]byte][]uint64{
				sha256.Sum256([]byte("leaf_recovery_0")): {0},
			},
		}
		if _, err := indexer.IndexBatch(ctx, batch, nil); err != nil {
			t.Fatalf("IndexBatch failed: %v", err)
		}

		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})
		err := coord.Recover(ctx)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrRootMismatch) {
			t.Fatalf("expected errors.Is(err, ErrRootMismatch), got %v", err)
		}
		if !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected errors.Is(err, ErrInvariantViolation), got %v", err)
		}
	})
}

func TestRecovery_CorruptedOutputLogLeaf(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name     string
		leafData []byte
	}{
		{
			name:     "missing_newline",
			leafData: []byte("only_one_line_here"),
		},
		{
			name:     "invalid_hex_root",
			leafData: []byte("not_a_valid_hex_string\nexample.com/inputlog\n50\nAAAA\n"),
		},
		{
			name:     "wrong_hex_root_length",
			leafData: []byte("abcd\nexample.com/inputlog\n50\nAAAA\n"),
		},
		{
			name:     "invalid_checkpoint_header",
			leafData: []byte(fmt.Sprintf("%x\ninvalid_checkpoint_without_size\n", sha256.Sum256([]byte("r")))),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)
			if _, _, err := outLog.Append(ctx, tc.leafData); err != nil {
				t.Fatalf("outLog.Append failed: %v", err)
			}

			coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})
			err := coord.Recover(ctx)
			if err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("expected ErrOutputLogCorrupted, got %v", err)
			}
		})
	}
}

func TestRecover_Phase3Catchup_MPTAndOutputLogAdvanced(t *testing.T) {
	ctx := context.Background()
	_, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)

	// Step 1: Initial state at 50 leaves (S_OUT = 50)
	keyMap1 := make(map[[32]byte][]uint64)
	for i := 0; i < 50; i++ {
		kh := sha256.Sum256([]byte(fmt.Sprintf("leaf_recovery_%d", i)))
		keyMap1[kh] = append(keyMap1[kh], uint64(i))
	}
	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   50,
		Count:        50,
		KeyMap:       keyMap1,
	}
	res1, err := indexer.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("IndexBatch 1 failed: %v", err)
	}
	rawInCP1 := []byte("example.com/inputlog\n50\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP1 := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: make([]byte, 32)}
	_, err = pub.PublishBatch(ctx, res1.ModifiedValueRoots, inputCP1, rawInCP1)
	if err != nil {
		t.Fatalf("PublishBatch 1 failed: %v", err)
	}
	if err := mptMgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// Step 2: Index intermediate batch [50 .. 75) into Pebble (m_kv_size = 75), but do NOT publish to Output Log (S_OUT remains 50)
	keyMap2 := make(map[[32]byte][]uint64)
	for i := 50; i < 75; i++ {
		kh := sha256.Sum256([]byte(fmt.Sprintf("leaf_recovery_%d", i)))
		keyMap2[kh] = append(keyMap2[kh], uint64(i))
	}
	batch2 := &ingest.MappedBatch{
		BundleIdx:    1,
		StartLeafIdx: 50,
		EndLeafIdx:   75,
		Count:        25,
		KeyMap:       keyMap2,
	}
	if _, err := indexer.IndexBatch(ctx, batch2, nil); err != nil {
		t.Fatalf("IndexBatch 2 failed: %v", err)
	}

	// Step 3: Set target checkpoint in DB to 150 (targetCP.Size = 150 > m_kv_size = 75 > S_OUT = 50)
	fetcher.mu.Lock()
	fetcher.leaves = fetcher.leaves[:150]
	fetcher.mu.Unlock()
	targetHash := kvstore.BatchRoot(fetcher.leaves[:150])
	rawTargetCP := []byte(fmt.Sprintf("example.com/inputlog\n150\n%s\n", base64.StdEncoding.EncodeToString(targetHash[:])))
	if err := db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, rawTargetCP); err != nil {
		t.Fatalf("SetMetadata targetCP failed: %v", err)
	}

	// Step 4: Simulate restart: new Coordinator & publisher
	newPub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	newCoord := NewCoordinator(db, mptMgr, outLog, newPub, indexer, fetcher, nil, &simpleIdentityMapper{})

	// Run Recover()
	if err := newCoord.Recover(ctx); err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	// Step 5: Run SyncOnce()
	if err := newCoord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce failed: %v", err)
	}

	// Step 6: Verify ServingState, Output Log, and MPT are advanced to 150
	servingState := newPub.GetServingState()
	if servingState == nil {
		t.Fatal("expected non-nil serving state after SyncOnce")
		return
	}
	if servingState.InputLogSize != 150 {
		t.Fatalf("servingState.InputLogSize = %d, want 150", servingState.InputLogSize)
	}

	outSize, err := outLog.Size(ctx)
	if err != nil {
		t.Fatalf("outLog.Size failed: %v", err)
	}
	if outSize != 2 {
		t.Fatalf("outLog size = %d, want 2 (one at 50, one at 150)", outSize)
	}

	if mptMgr.PersistedSize() != 150 {
		t.Fatalf("mpt persisted size = %d, want 150", mptMgr.PersistedSize())
	}

	// Compute expected MPT root for all 150 leaves
	allKeyValueRoots := make(map[[32]byte][32]byte)
	for i := 0; i < 150; i++ {
		kh := sha256.Sum256([]byte(fmt.Sprintf("leaf_recovery_%d", i)))
		vr, err := indexer.GetValueRoot(kh, 150)
		if err != nil {
			t.Fatalf("GetValueRoot failed for leaf %d: %v", i, err)
		}
		allKeyValueRoots[kh] = vr
	}
	expectedRoot, err := mptMgr.Predict(allKeyValueRoots)
	if err != nil {
		t.Fatalf("Predict expected root failed: %v", err)
	}
	if servingState.MPTRoot != expectedRoot {
		t.Fatalf("servingState.MPTRoot = %x, want %x", servingState.MPTRoot, expectedRoot)
	}
	if mptMgr.Root() != expectedRoot {
		t.Fatalf("mptMgr.Root = %x, want %x", mptMgr.Root(), expectedRoot)
	}
}

type partialRejectingReader struct {
	bundleBytes []byte
	tileBytes   []byte
}

func (r *partialRejectingReader) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (r *partialRejectingReader) ReadTile(_ context.Context, l, i uint64, p uint8) ([]byte, error) {
	if p == 0 {
		return nil, errors.New("tile reader: unexpected request for full tile (p=0), only partial tile p=50 is served")
	}
	if p != 50 {
		return nil, fmt.Errorf("unexpected partial tile size p=%d", p)
	}
	return r.tileBytes, nil
}

func (r *partialRejectingReader) ReadEntryBundle(_ context.Context, i uint64, p uint8) ([]byte, error) {
	if p == 0 {
		return nil, errors.New("tile reader: unexpected request for full entry bundle (p=0), only partial bundle p=50 is served")
	}
	if p != 50 {
		return nil, fmt.Errorf("unexpected partial entry bundle size p=%d", p)
	}
	return r.bundleBytes, nil
}

func TestRecover_Phase2PartialTileFetch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := mpt.NewMem()
	outLog := newMemoryOutputLog("example.com/outputlog")
	indexer := kvstore.NewKVIndexer(db, 64)

	// Ingest 50 leaves into Pebble KV store
	var bundle api.EntryBundle
	keyMap := make(map[[32]byte][]uint64)
	for i := 0; i < 50; i++ {
		leaf := []byte(fmt.Sprintf("leaf_partial_%d", i))
		bundle.Entries = append(bundle.Entries, leaf)
		kh := sha256.Sum256(leaf)
		keyMap[kh] = append(keyMap[kh], uint64(i))
	}
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   50,
		Count:        50,
		KeyMap:       keyMap,
	}
	res, err := indexer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	var bundleBytes []byte
	var tileBytes []byte
	for _, leaf := range bundle.Entries {
		bundleBytes = binary.BigEndian.AppendUint16(bundleBytes, uint16(len(leaf)))
		bundleBytes = append(bundleBytes, leaf...)
		h := tlog.RecordHash(leaf)
		tileBytes = append(tileBytes, h[:]...)
	}

	predictedRoot, err := mptMgr.Predict(res.ModifiedValueRoots)
	if err != nil {
		t.Fatalf("Predict failed: %v", err)
	}

	// Output log tip is at size 50 with predicted root and authentic input log root
	inRoot := kvstore.BatchRoot(bundle.Entries)
	inCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: inRoot[:]}
	leafData := tree.FormatOutputLogLeaf(predictedRoot, inCP)
	if _, _, err := outLog.Append(ctx, leafData); err != nil {
		t.Fatalf("outLog.Append failed: %v", err)
	}

	// MPT manager remains empty (persisted size 0 != tip 50), forcing Phase 2 replay
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	reader := &partialRejectingReader{
		bundleBytes: bundleBytes,
		tileBytes:   tileBytes,
	}
	fetcher := ingest.NewTiledFetcherWithReader(reader, nil, "example.com/inputlog")
	coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})

	// Recover must successfully fetch partial tile (p=50), verify against inRoot, and complete Phase 2 replay
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover failed during Phase 2 partial tile fetch: %v", err)
	}

	state := pub.GetServingState()
	if state == nil {
		t.Fatal("serving state is nil after Phase 2 recovery")
		return
	}
	if state.InputLogSize != 50 {
		t.Fatalf("state.InputLogSize = %d, want 50", state.InputLogSize)
	}
	if state.MPTRoot != predictedRoot {
		t.Fatalf("state.MPTRoot = %x, want %x", state.MPTRoot, predictedRoot)
	}
}

func TestRecovery_DirtyMPTAtEqualSize_ReplaysCleanly(t *testing.T) {
	ctx := context.Background()
	_, db, _, _, indexer, outLog, fetcher := setupRecoveryEnvironment(t)

	// Step 1: Ingest 50 leaves into Pebble and commit clean MPT at version 50 on disk
	mptDir := t.TempDir()
	mptMgr, err := mpt.Open(mptDir)
	if err != nil {
		t.Fatalf("tree.Open failed: %v", err)
	}

	keyMap := make(map[[32]byte][]uint64)
	for i := 0; i < 50; i++ {
		kh := sha256.Sum256([]byte(fmt.Sprintf("leaf_recovery_%d", i)))
		keyMap[kh] = append(keyMap[kh], uint64(i))
	}
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   50,
		Count:        50,
		KeyMap:       keyMap,
	}
	res, err := indexer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	inRoot := kvstore.BatchRoot(fetcher.leaves[:50])
	rawInCP := []byte("example.com/inputlog\n50\n" + base64.StdEncoding.EncodeToString(inRoot[:]) + "\n")
	inputCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: inRoot[:]}
	expectedState, err := pub.PublishBatch(ctx, res.ModifiedValueRoots, inputCP, rawInCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}
	if err := mptMgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// Step 2: Simulate a dirty uncommitted SetBatch mutation on one of the keys in [0..50) before crash
	k0 := sha256.Sum256([]byte("leaf_recovery_0"))
	if err := mptMgr.SetBatch(map[[32]byte][32]byte{k0: sha256.Sum256([]byte("dirty_uncommitted_valueroot"))}); err != nil {
		t.Fatalf("SetBatch failed: %v", err)
	}
	if err := mptMgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Step 3: Reopen dirty MPT on disk (PersistedSize() == 50 == targetInputSize, IsExact() == false)
	reopenedMPT, err := mpt.Open(mptDir)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() { _ = reopenedMPT.Close() }()
	if reopenedMPT.IsExact() {
		t.Fatal("expected reopenedMPT.IsExact() == false")
	}

	newPub := tree.NewOutputPublisher(db, reopenedMPT, outLog, nil)
	newCoord := NewCoordinator(db, reopenedMPT, outLog, newPub, indexer, fetcher, nil, &simpleIdentityMapper{})

	// Recover must NOT fail with false-positive ErrRootMismatch; it must replay [0..50) and restore clean state
	if err := newCoord.Recover(ctx); err != nil {
		t.Fatalf("Recover failed on dirty MPT at equal size: %v", err)
	}
	if !reopenedMPT.IsExact() {
		t.Fatal("expected reopenedMPT.IsExact() == true after Phase 2 replay")
	}
	if reopenedMPT.Root() != expectedState.MPTRoot {
		t.Fatalf("reopenedMPT.Root() = %x, want %x", reopenedMPT.Root(), expectedState.MPTRoot)
	}
}
