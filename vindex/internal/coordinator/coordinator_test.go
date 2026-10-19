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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestCoordinator_SafeWatermark_ClampedToFrom(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := kvstore.Open(filepath.Join(dir, "db"), &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr, err := mpt.Open(filepath.Join(dir, "mpt"))
	if err != nil {
		t.Fatalf("mpt.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = mptMgr.Close() })

	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	pub.SetFrom(500)
	idx := kvstore.NewKVIndexer(db, 64)

	coord := NewCoordinator(db, mptMgr, outLog, pub, idx, nil, nil, nil)

	// 1. Empty state (kvSize=0, mptPersistedSize=0) -> clamped to from (500)
	sw, err := coord.SafeWatermark(ctx)
	if err != nil || sw != 500 {
		t.Fatalf("empty state SafeWatermark = %d (err: %v), want 500", sw, err)
	}

	// 2. kvSize=800, mptPersistedSize=300 (< from=500) -> clamped to 500
	if err := db.SetUint64(kvstore.KeyMetaKVSize, 800); err != nil {
		t.Fatalf("SetUint64 failed: %v", err)
	}
	if _, err := mptMgr.Snap(300); err != nil {
		t.Fatalf("mptMgr.Snap(300) failed: %v", err)
	}
	if err := mptMgr.Persist(); err != nil {
		t.Fatalf("mptMgr.Persist() failed: %v", err)
	}
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 500 {
		t.Fatalf("below-from MPT SafeWatermark = %d (err: %v), want 500", sw, err)
	}

	// 3. kvSize=800, mptPersistedSize=700 (> from=500) -> min(800, 700) = 700
	if _, err := mptMgr.Snap(700); err != nil {
		t.Fatalf("mptMgr.Snap(700) failed: %v", err)
	}
	if err := mptMgr.Persist(); err != nil {
		t.Fatalf("mptMgr.Persist() failed: %v", err)
	}
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 700 {
		t.Fatalf("above-from SafeWatermark = %d (err: %v), want 700", sw, err)
	}
}

type configurableCPFetcher struct {
	cp     *ingest.Checkpoint
	leaves [][]byte
}

func (f *configurableCPFetcher) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	return f.cp, nil
}

func (f *configurableCPFetcher) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	if idx >= uint64(len(f.leaves)) {
		return nil, fmt.Errorf("leaf %d out of range", idx)
	}
	return f.leaves[idx], nil
}

func (f *configurableCPFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     f.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func makeRawCP(origin string, size uint64, hash [sha256.Size]byte) *ingest.Checkpoint {
	raw := (&log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hash[:],
	}).Marshal()
	return &ingest.Checkpoint{
		Raw:    raw,
		Origin: origin,
		Size:   size,
		Hash:   hash,
	}
}

func TestCoordinator_SyncOnce_RejectsTargetBelowFrom(t *testing.T) {
	ctx := context.Background()
	coord, db, _, pub, _, _, _ := setupRecoveryEnvironment(t)
	pub.SetFrom(250) // setupRecoveryEnvironment fetcher has 200 leaves (< 250)

	err := coord.SyncOnce(ctx)
	if err == nil || !strings.Contains(err.Error(), "below configured start index from") {
		t.Fatalf("expected error for targetCP.Size < from, got: %v", err)
	}

	if raw, mErr := db.GetMetadata(kvstore.KeyMetaTargetCheckpoint); mErr == nil && len(raw) > 0 {
		t.Fatalf("expected KeyMetaTargetCheckpoint not to be persisted when targetCP.Size < from, got %q", raw)
	}
}

func TestCoordinator_SyncOnce_RejectsRegressionAndSplitView(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/inputlog"

	t.Run("serving_state_regression_and_split_view", func(t *testing.T) {
		_, db, mptMgr, pub, indexer, outLog, _ := setupRecoveryEnvironment(t)
		leaves := make([][]byte, 100)
		for i := range leaves {
			leaves[i] = []byte(fmt.Sprintf("leaf_%d", i))
		}
		root100 := kvstore.BatchRoot(leaves)
		cp100 := makeRawCP(origin, 100, root100)

		fetcher := &configurableCPFetcher{cp: cp100, leaves: leaves}
		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})

		// Initial valid sync to 100
		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("initial SyncOnce(100) failed: %v", err)
		}
		savedRaw, err := db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
		if err != nil || !bytes.Equal(savedRaw, cp100.Raw) {
			t.Fatalf("expected KeyMetaTargetCheckpoint to match cp100.Raw, got %q (err: %v)", savedRaw, err)
		}

		// 1. Regression: targetCP.Size = 80 < prevCP.Size = 100
		fetcher.cp = makeRawCP(origin, 80, kvstore.BatchRoot(leaves[:80]))
		err = coord.SyncOnce(ctx)
		if err == nil || !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected ErrInvariantViolation on regression 100 -> 80, got: %v", err)
		}
		afterRegress, _ := db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
		if !bytes.Equal(afterRegress, cp100.Raw) {
			t.Fatal("KeyMetaTargetCheckpoint was overwritten despite checkpoint regression")
		}

		// 2. Equal-size split-view: targetCP.Size = 100 == prevCP.Size = 100, different hash
		forgedHash := sha256.Sum256([]byte("split_view_root_at_100"))
		fetcher.cp = makeRawCP(origin, 100, forgedHash)
		err = coord.SyncOnce(ctx)
		if err == nil || !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected ErrInvariantViolation on equal-size split-view, got: %v", err)
		}
		afterSplit, _ := db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
		if !bytes.Equal(afterSplit, cp100.Raw) {
			t.Fatal("KeyMetaTargetCheckpoint was overwritten despite equal-size split-view")
		}
	})

	t.Run("db_metadata_fallback_when_serving_state_nil", func(t *testing.T) {
		_, db, mptMgr, pub, indexer, outLog, _ := setupRecoveryEnvironment(t)
		origHash := sha256.Sum256([]byte("frozen_target_100"))
		origCP := makeRawCP(origin, 100, origHash)
		if err := db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, origCP.Raw); err != nil {
			t.Fatalf("SetMetadata failed: %v", err)
		}

		// Regression against persisted KeyMetaTargetCheckpoint when ServingState is nil
		fetcher := &configurableCPFetcher{cp: makeRawCP(origin, 90, sha256.Sum256([]byte("regressed_90")))}
		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, &simpleIdentityMapper{})
		if err := coord.SyncOnce(ctx); err == nil || !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected ErrInvariantViolation against persisted KeyMetaTargetCheckpoint regression, got: %v", err)
		}
		gotRaw, _ := db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
		if !bytes.Equal(gotRaw, origCP.Raw) {
			t.Fatal("KeyMetaTargetCheckpoint was overwritten on regression")
		}

		// Split-view against persisted KeyMetaTargetCheckpoint when ServingState is nil
		fetcher.cp = makeRawCP(origin, 100, sha256.Sum256([]byte("different_hash_at_100")))
		if err := coord.SyncOnce(ctx); err == nil || !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("expected ErrInvariantViolation against persisted KeyMetaTargetCheckpoint split-view, got: %v", err)
		}
		gotRaw, _ = db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
		if !bytes.Equal(gotRaw, origCP.Raw) {
			t.Fatal("KeyMetaTargetCheckpoint was overwritten on split-view")
		}
	})
}

func writeCoordinatorTiledFixture(t *testing.T, rootDir, origin string, leaves [][]byte, signer note.Signer) []byte {
	t.Helper()
	if err := os.RemoveAll(rootDir); err != nil {
		t.Fatalf("RemoveAll(%s) failed: %v", rootDir, err)
	}

	var hashes []tlog.Hash
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			out[i] = hashes[idx]
		}
		return out, nil
	})
	for idx, leaf := range leaves {
		sh, err := tlog.StoredHashes(int64(idx), leaf, hr)
		if err != nil {
			t.Fatalf("tlog.StoredHashes(%d) failed: %v", idx, err)
		}
		hashes = append(hashes, sh...)
	}

	treeSize := int64(len(leaves))
	rootHash, err := tlog.TreeHash(treeSize, hr)
	if err != nil {
		t.Fatalf("tlog.TreeHash(%d) failed: %v", treeSize, err)
	}

	for _, tile := range tlog.NewTiles(layout.TileHeight, 0, treeSize) {
		data, err := tlog.ReadTileData(tile, hr)
		if err != nil {
			t.Fatalf("tlog.ReadTileData(%+v) failed: %v", tile, err)
		}
		p := uint8(0)
		if tile.W < (1 << layout.TileHeight) {
			p = uint8(tile.W)
		}
		dst := filepath.Join(rootDir, layout.TilePath(uint64(tile.L), uint64(tile.N), p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	const bundleW = int(layout.EntryBundleWidth)
	for start := 0; start < len(leaves); start += bundleW {
		end := min(start+bundleW, len(leaves))
		bIdx := uint64(start / bundleW)
		count := end - start
		p := uint8(0)
		if count < bundleW {
			p = uint8(count)
		}
		var buf []byte
		for _, leaf := range leaves[start:end] {
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(leaf)))
			buf = append(buf, leaf...)
		}
		dst := filepath.Join(rootDir, layout.EntriesPath(bIdx, p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(dst, buf, 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	cpBody := (&log.Checkpoint{
		Origin: origin,
		Size:   uint64(treeSize),
		Hash:   rootHash[:],
	}).Marshal()
	rawCP, err := note.Sign(&note.Note{Text: string(cpBody)}, signer)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, layout.CheckpointPath), rawCP, 0o644); err != nil {
		t.Fatalf("WriteFile checkpoint failed: %v", err)
	}
	return rawCP
}

func TestCoordinator_SyncOnce_MerkleConsistencyVerification(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/tiledinput"

	skey, vkey, err := note.GenerateKey(nil, origin)
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("note.NewSigner failed: %v", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("note.NewVerifier failed: %v", err)
	}

	logDir := t.TempDir()
	dbDir := t.TempDir()
	db, err := kvstore.Open(dbDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := mpt.NewMem()
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	indexer := kvstore.NewKVIndexer(db, 64)

	leaves := make([][]byte, 300)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("consistent_leaf_%d", i))
	}

	// 1. Sync at size 100
	writeCoordinatorTiledFixture(t, logDir, origin, leaves[:100], signer)
	tf, err := ingest.NewTiledFetcher(&url.URL{Scheme: "file", Path: logDir}, verifier, origin, nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}
	coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, tf, nil, &simpleIdentityMapper{})

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(100) failed: %v", err)
	}

	// 2. Append-only progression 100 -> 300 passes Merkle consistency verification
	rawCP300 := writeCoordinatorTiledFixture(t, logDir, origin, leaves[:300], signer)
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(300) consistent progression failed: %v", err)
	}
	if state := pub.GetServingState(); state == nil || state.InputLogSize != 300 {
		t.Fatalf("ServingState after 300 sync = %+v, want InputLogSize=300", state)
	}

	// 3. Mutated history at size 400 (forked leaf 0) MUST fail Merkle consistency verification
	// BEFORE overwriting KeyMetaTargetCheckpoint!
	forkedLeaves := make([][]byte, 400)
	for i := range forkedLeaves {
		forkedLeaves[i] = []byte(fmt.Sprintf("consistent_leaf_%d", i))
	}
	forkedLeaves[0] = []byte("mutated_historical_leaf_0")
	writeCoordinatorTiledFixture(t, logDir, origin, forkedLeaves, signer)

	beforeErrs := testutil.ToFloat64(metrics.InputFetchErrorsTotal)
	err = coord.SyncOnce(ctx)
	if err == nil {
		t.Fatal("expected SyncOnce(400) to fail Merkle consistency check on mutated history, got nil")
	}
	if afterErrs := testutil.ToFloat64(metrics.InputFetchErrorsTotal); afterErrs <= beforeErrs {
		t.Fatalf("expected InputFetchErrorsTotal to increment on consistency failure: before=%v, after=%v", beforeErrs, afterErrs)
	}

	persistedTarget, mErr := db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
	if mErr != nil {
		t.Fatalf("GetMetadata(KeyMetaTargetCheckpoint) failed: %v", mErr)
	}
	if !bytes.Equal(persistedTarget, rawCP300) {
		t.Fatal("KeyMetaTargetCheckpoint was overwritten despite failed Merkle consistency verification")
	}
	if state := pub.GetServingState(); state == nil || state.InputLogSize != 300 {
		t.Fatalf("ServingState after rejected sync = %+v, want InputLogSize=300", state)
	}

	// 4. Missing tiles causing ConsistencyProof fetch failure also increments metric and preserves KeyMetaTargetCheckpoint
	validExpanded := make([][]byte, 350)
	for i := range validExpanded {
		validExpanded[i] = []byte(fmt.Sprintf("consistent_leaf_%d", i))
	}
	writeCoordinatorTiledFixture(t, logDir, origin, validExpanded, signer)
	// Delete tiles directory so ConsistencyProof fails while Checkpoint still reads signed checkpoint
	if err := os.RemoveAll(filepath.Join(logDir, "tile")); err != nil {
		t.Fatalf("RemoveAll tile dir failed: %v", err)
	}

	beforeErrs = testutil.ToFloat64(metrics.InputFetchErrorsTotal)
	if err := coord.SyncOnce(ctx); err == nil {
		t.Fatal("expected SyncOnce(350) to fail when ConsistencyProof cannot read tiles, got nil")
	}
	if afterErrs := testutil.ToFloat64(metrics.InputFetchErrorsTotal); afterErrs <= beforeErrs {
		t.Fatalf("expected InputFetchErrorsTotal to increment when ConsistencyProof fails: before=%v, after=%v", beforeErrs, afterErrs)
	}
	persistedTarget, _ = db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
	if !bytes.Equal(persistedTarget, rawCP300) {
		t.Fatal("KeyMetaTargetCheckpoint was overwritten despite failed ConsistencyProof fetch")
	}
}
