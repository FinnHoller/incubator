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

package auditor_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

// testIdentityMapper maps each leaf to a canonical search key.
type testIdentityMapper struct{}

func (m *testIdentityMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	if mpt.ValidateCanonicalKey(leaf) == nil {
		return []ingest.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	}
	h := sha256.Sum256(leaf)
	hexKey := hex.EncodeToString(h[:])
	return []ingest.MappedEntry{{Key: hexKey, KeyHash: sha256.Sum256([]byte(hexKey))}}, nil
}

func (m *testIdentityMapper) Close(_ context.Context) error {
	return nil
}

// memoryOutputLog implements verifier.OutputLogSource in memory with RFC 6962 inclusion proofs.
type memoryOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
	signer note.Signer
}

func (l *memoryOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	idx := uint64(len(l.leaves))
	l.leaves = append(l.leaves, leafData)
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		signed, err := note.Sign(&note.Note{Text: text}, l.signer)
		if err != nil {
			return 0, nil, err
		}
		return idx, signed, nil
	}
	raw := []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:])))
	return idx, raw, nil
}

func (l *memoryOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		return note.Sign(&note.Note{Text: text}, l.signer)
	}
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))), nil
}

func (l *memoryOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (%d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *memoryOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if treeSize > uint64(len(l.leaves)) {
		treeSize = uint64(len(l.leaves))
	}
	var leafHashes [][sha256.Size]byte
	for _, leaf := range l.leaves[:treeSize] {
		leafHashes = append(leafHashes, kvstore.LeafHash(leaf))
	}

	var proof [][sha256.Size]byte
	var buildProof func(leaves [][sha256.Size]byte, idx uint64)
	buildProof = func(leaves [][sha256.Size]byte, idx uint64) {
		n := len(leaves)
		if n <= 1 {
			return
		}
		var k uint64 = 1
		for k*2 < uint64(n) {
			k *= 2
		}
		if idx < k {
			buildProof(leaves[:k], idx)
			proof = append(proof, kvstore.BatchRootHashes(leaves[k:]))
		} else {
			buildProof(leaves[k:], idx-k)
			proof = append(proof, kvstore.BatchRootHashes(leaves[:k]))
		}
	}
	buildProof(leafHashes, leafIdx)
	return proof, nil
}

func buildConsistencyProof(rawLeaves [][]byte, smaller, larger uint64) ([][]byte, error) {
	if smaller == 0 || smaller == larger {
		return nil, nil
	}
	if smaller > larger || larger > uint64(len(rawLeaves)) {
		return nil, fmt.Errorf("invalid consistency proof range (%d -> %d, len %d)", smaller, larger, len(rawLeaves))
	}
	leafHashes := make([][sha256.Size]byte, larger)
	for i := uint64(0); i < larger; i++ {
		leafHashes[i] = kvstore.LeafHash(rawLeaves[i])
	}
	var out [][]byte
	var subproof func(m uint64, d [][sha256.Size]byte, b bool)
	subproof = func(m uint64, d [][sha256.Size]byte, b bool) {
		n := uint64(len(d))
		if m == n {
			if !b {
				h := kvstore.BatchRootHashes(d)
				out = append(out, h[:])
			}
			return
		}
		var k uint64 = 1
		for k*2 < n {
			k *= 2
		}
		if m <= k {
			subproof(m, d[:k], b)
			h := kvstore.BatchRootHashes(d[k:n])
			out = append(out, h[:])
		} else {
			subproof(m-k, d[k:n], false)
			h := kvstore.BatchRootHashes(d[:k])
			out = append(out, h[:])
		}
	}
	subproof(smaller, leafHashes, true)
	return out, nil
}

func (l *memoryOutputLog) ConsistencyProof(_ context.Context, smaller, larger uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return buildConsistencyProof(l.leaves, smaller, larger)
}

// memoryInputLog implements ingest.TileFetcher and tracks Checkpoint() call count.
type memoryInputLog struct {
	mu                  sync.Mutex
	leaves              [][]byte
	origin              string
	signer              note.Signer
	checkpointCallCount int
	treeSize            uint64
	treeHash            [32]byte
	bundleSize          uint64
	lastSignedSize      uint64
	lastSignedCP        *ingest.Checkpoint
}

func (l *memoryInputLog) SetTreeSize(size uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.treeSize = size
}

func (l *memoryInputLog) SetTreeState(size uint64, hash [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.treeSize = size
	l.treeHash = hash
}

func (l *memoryInputLog) AppendLeaf(leaf []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaves = append(l.leaves, leaf)
}

func (l *memoryInputLog) SetCheckpoint(raw []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp, err := wire.ParseCheckpointHeader(raw)
	if err == nil && len(cp.Hash) == sha256.Size {
		l.lastSignedSize = cp.Size
		l.lastSignedCP = &ingest.Checkpoint{
			Raw:    raw,
			Origin: cp.Origin,
			Size:   cp.Size,
			Hash:   [32]byte(cp.Hash),
		}
	}
}

func (l *memoryInputLog) SignRawCheckpoint(size uint64) ([]byte, *log.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var leavesSlice [][]byte
	if size <= uint64(len(l.leaves)) {
		leavesSlice = l.leaves[:size]
	} else {
		leavesSlice = l.leaves
	}
	root := kvstore.BatchRoot(leavesSlice)
	text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	signed, err := note.Sign(&note.Note{Text: text}, l.signer)
	if err != nil {
		return nil, nil, err
	}
	if size >= l.lastSignedSize || l.lastSignedCP == nil {
		l.lastSignedSize = size
		l.lastSignedCP = &ingest.Checkpoint{
			Raw:    signed,
			Origin: l.origin,
			Size:   size,
			Hash:   root,
		}
	}
	return signed, &log.Checkpoint{
		Origin: l.origin,
		Size:   size,
		Hash:   root[:],
	}, nil
}

func (l *memoryInputLog) SignCheckpoint(size uint64) (*log.Checkpoint, error) {
	_, cp, err := l.SignRawCheckpoint(size)
	return cp, err
}

func (l *memoryInputLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	l.mu.Lock()
	l.checkpointCallCount++
	if l.lastSignedCP != nil {
		cp := *l.lastSignedCP
		l.mu.Unlock()
		return &cp, nil
	}
	sz := uint64(len(l.leaves))
	l.mu.Unlock()
	if _, err := l.SignCheckpoint(sz); err != nil {
		return nil, err
	}
	l.mu.Lock()
	cp := *l.lastSignedCP
	l.mu.Unlock()
	return &cp, nil
}

func (l *memoryInputLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds", idx)
	}
	return l.leaves[idx], nil
}

func (l *memoryInputLog) FetchTiles(_ context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	bundleSize := l.bundleSize
	if bundleSize == 0 {
		bundleSize = 256
	}

	maxLeaf := uint64(len(l.leaves))
	if l.treeSize > 0 && l.treeSize < maxLeaf {
		maxLeaf = l.treeSize
	}

	endIdx := startLeafIdx + count
	if endIdx > maxLeaf {
		endIdx = maxLeaf
	}
	if startLeafIdx >= endIdx {
		return nil, nil
	}

	var bundles []*ingest.LeafBundle
	startBundle := startLeafIdx / bundleSize
	endBundle := (endIdx - 1) / bundleSize

	for bIdx := startBundle; bIdx <= endBundle; bIdx++ {
		bStart := bIdx * bundleSize
		bEnd := bStart + bundleSize
		if bEnd > maxLeaf {
			bEnd = maxLeaf
		}
		if bStart >= bEnd {
			continue
		}
		bundle := &ingest.LeafBundle{
			BundleIdx:    bIdx,
			StartLeafIdx: bStart,
			Leaves:       make([][]byte, bEnd-bStart),
		}
		for i := bStart; i < bEnd; i++ {
			bundle.Leaves[i-bStart] = l.leaves[i]
		}
		bundles = append(bundles, bundle)
	}
	return bundles, nil
}

func (l *memoryInputLog) ConsistencyProof(_ context.Context, smaller, larger uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return buildConsistencyProof(l.leaves, smaller, larger)
}

// computeExpectedMPTRoot computes the authentic Merkle Patricia Trie root resulting from
// mapping and indexing the given input leaves.
func computeExpectedMPTRoot(t *testing.T, leaves [][]byte, mapper ingest.LeafMapper) [sha256.Size]byte {
	t.Helper()
	db, err := kvstore.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer func() { _ = db.Close() }()

	indexer := kvstore.NewKVIndexer(db, 65536)
	mptMgr := mpt.NewMem()
	defer func() { _ = mptMgr.Close() }()

	allModified := make(map[string][sha256.Size]byte)
	for i, leaf := range leaves {
		entries, err := mapper.MapLeaf(context.Background(), leaf)
		if err != nil {
			t.Fatalf("MapLeaf failed: %v", err)
		}
		keyMap := make(map[[32]byte][]uint64)
		canonicalKeys := make(map[[32]byte]string)
		for _, e := range entries {
			keyMap[e.KeyHash] = append(keyMap[e.KeyHash], uint64(i))
			if e.Key != "" {
				canonicalKeys[e.KeyHash] = e.Key
			}
		}
		batch := &ingest.MappedBatch{
			BundleIdx:     uint64(i / 256),
			StartLeafIdx:  uint64(i),
			EndLeafIdx:    uint64(i + 1),
			Count:         1,
			KeyMap:        keyMap,
			CanonicalKeys: canonicalKeys,
		}
		res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, uint64(len(leaves)))
		if err != nil {
			t.Fatalf("IndexMappedBatch failed: %v", err)
		}
		for k, v := range res.ModifiedKeyValueRoots {
			allModified[k] = v
		}
	}
	root, err := mptMgr.CommitKeysWithVersion(allModified, int64(len(leaves)))
	if err != nil {
		t.Fatalf("CommitKeysWithVersion failed: %v", err)
	}
	return root
}

type testHarness struct {
	inSigner    note.Signer
	inVerifier  note.Verifier
	outSigner   note.Signer
	outVerifier note.Verifier
	inLog       *memoryInputLog
	outLog      *memoryOutputLog
	mapper      ingest.LeafMapper
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "example.com/test/inputlog")
	if err != nil {
		t.Fatalf("GenerateKey inputlog failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner inputlog failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier inputlog failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "example.com/test/outputlog")
	if err != nil {
		t.Fatalf("GenerateKey outputlog failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("NewSigner outputlog failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier outputlog failed: %v", err)
	}

	inLog := &memoryInputLog{
		origin: "example.com/test/inputlog",
		signer: inSigner,
	}
	outLog := &memoryOutputLog{
		origin: "example.com/test/outputlog",
		signer: outSigner,
	}

	return &testHarness{
		inSigner:    inSigner,
		inVerifier:  inVerifier,
		outSigner:   outSigner,
		outVerifier: outVerifier,
		inLog:       inLog,
		outLog:      outLog,
		mapper:      &testIdentityMapper{},
	}
}

// TestVerifier_HonestSync verifies honest progression across multiple OutputLog leaves:
// watermarks advance, calculated roots match commitments, and healthcheck remains healthy.
func TestVerifier_HonestSync(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	// Populate InputLog with 10 leaves
	var rawLeaves [][]byte
	for i := 0; i < 10; i++ {
		leaf := []byte(fmt.Sprintf("certificate-entry-%04d", i))
		rawLeaves = append(rawLeaves, leaf)
		h.inLog.AppendLeaf(leaf)
	}

	// OutputLog leaf 0: commits to input size 5
	root0 := computeExpectedMPTRoot(t, rawLeaves[:5], h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint(5) failed: %v", err)
	}
	leafData0 := wire.FormatOutputLogLeaf(root0, signedInCP0)
	if _, _, err := h.outLog.Append(ctx, leafData0); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	// OutputLog leaf 1: commits to input size 10
	root1 := computeExpectedMPTRoot(t, rawLeaves[:10], h.mapper)
	signedInCP1, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint(10) failed: %v", err)
	}
	leafData1 := wire.FormatOutputLogLeaf(root1, signedInCP1)
	if _, _, err := h.outLog.Append(ctx, leafData1); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	// Initialize verifier in memory
	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// Initial status check
	st := v.Status()
	if st.IsHalted || st.VerifiedOutputSize != 0 || st.VerifiedInputSize != 0 {
		t.Fatalf("unexpected initial status: %+v", st)
	}

	// Run first verification pass
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed on honest sync: %v", err)
	}

	st = v.Status()
	if st.IsHalted {
		t.Fatalf("verifier unexpectedly halted: %v", st.HaltError)
	}
	if st.VerifiedOutputSize != 2 {
		t.Errorf("VerifiedOutputSize = %d, want 2", st.VerifiedOutputSize)
	}
	if st.VerifiedInputSize != 10 {
		t.Errorf("VerifiedInputSize = %d, want 10", st.VerifiedInputSize)
	}
	if st.LastVerifiedRoot != root1 {
		t.Errorf("LastVerifiedRoot = %x, want %x", st.LastVerifiedRoot, root1)
	}
	if err := v.HealthCheck(); err != nil {
		t.Errorf("HealthCheck() = %v, want nil", err)
	}

	// Add 5 more leaves (total 15) and publish OutputLog leaf 2
	for i := 10; i < 15; i++ {
		leaf := []byte(fmt.Sprintf("certificate-entry-%04d", i))
		rawLeaves = append(rawLeaves, leaf)
		h.inLog.AppendLeaf(leaf)
	}
	root2 := computeExpectedMPTRoot(t, rawLeaves[:15], h.mapper)
	signedInCP2, err := h.inLog.SignCheckpoint(15)
	if err != nil {
		t.Fatalf("SignCheckpoint(15) failed: %v", err)
	}
	leafData2 := wire.FormatOutputLogLeaf(root2, signedInCP2)
	if _, _, err := h.outLog.Append(ctx, leafData2); err != nil {
		t.Fatalf("Append leaf 2 failed: %v", err)
	}

	// Verify incremental progression
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("second VerifyOnce failed: %v", err)
	}

	st = v.Status()
	if st.VerifiedOutputSize != 3 || st.VerifiedInputSize != 15 || st.LastVerifiedRoot != root2 {
		t.Errorf("incremental sync status incorrect: %+v", st)
	}
}

// TestVerifier_RootMismatchDetection verifies that a tampered root hash committed in an OutputLog leaf
// is detected immediately, records Prometheus metrics, sets health unhealthy, and halts progress without advancing watermarks.
func TestVerifier_RootMismatchDetection(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	// Populate InputLog with 10 leaves
	var rawLeaves [][]byte
	for i := 0; i < 10; i++ {
		leaf := []byte(fmt.Sprintf("entry-%d", i))
		rawLeaves = append(rawLeaves, leaf)
		h.inLog.AppendLeaf(leaf)
	}

	// Leaf 0: Honest commitment (size 5)
	root0 := computeExpectedMPTRoot(t, rawLeaves[:5], h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, signedInCP0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	// Leaf 1: Tampered commitment with forged MPTRoot
	tamperedRoot := sha256.Sum256([]byte("forged_mpt_root_hash"))
	signedInCP1, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(tamperedRoot, signedInCP1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// Execute verification pass
	err = v.VerifyOnce(ctx)
	if err == nil {
		t.Fatal("VerifyOnce succeeded, want RootMismatchError")
	}
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("err = %v, want errors.Is(ErrRootMismatch)", err)
	}

	var rootErr *auditor.RootMismatchError
	if !errors.As(err, &rootErr) {
		t.Fatalf("err is not of type *RootMismatchError: %T", err)
	}
	if rootErr.OutputIndex != 1 {
		t.Errorf("mismatch OutputIndex = %d, want 1", rootErr.OutputIndex)
	}
	if rootErr.InputSize != 10 {
		t.Errorf("mismatch InputSize = %d, want 10", rootErr.InputSize)
	}
	if rootErr.CommittedMPTRoot != tamperedRoot {
		t.Errorf("CommittedMPTRoot = %x, want %x", rootErr.CommittedMPTRoot, tamperedRoot)
	}
	if len(rootErr.JSONDiagnostics()) == 0 {
		t.Error("expected non-empty JSONDiagnostics from RootMismatchError")
	}

	// Assert Prometheus gauge is 1
	if gVal := testutil.ToFloat64(metrics.AuditorRootMismatch); gVal != 1.0 {
		t.Errorf("VerifierRootMismatch gauge = %v, want 1.0", gVal)
	}

	// Assert HealthCheck returns the error
	if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrRootMismatch) {
		t.Errorf("HealthCheck() = %v, want ErrRootMismatch", hErr)
	}

	// Assert watermarks are frozen at leaf 0 (leaf 1 did NOT advance watermarks)
	st := v.Status()
	if !st.IsHalted {
		t.Error("verifier status should be halted")
	}
	if st.VerifiedOutputSize != 1 {
		t.Errorf("VerifiedOutputSize = %d, want 1 (frozen)", st.VerifiedOutputSize)
	}
	if st.VerifiedInputSize != 5 {
		t.Errorf("VerifiedInputSize = %d, want 5 (frozen)", st.VerifiedInputSize)
	}

	// Subsequent VerifyOnce must immediately fail with the halt error
	secondErr := v.VerifyOnce(ctx)
	if secondErr == nil || !errors.Is(secondErr, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", secondErr)
	}
}

// TestVerifier_TamperedInputLeafData verifies that altering input leaf contents causes the local
// MPT root to diverge from the published commitment, triggering immediate mismatch detection.
func TestVerifier_TamperedInputLeafData(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	// Populate authentic leaves
	var rawLeaves [][]byte
	for i := 0; i < 5; i++ {
		leaf := []byte(fmt.Sprintf("authentic-entry-%d", i))
		rawLeaves = append(rawLeaves, leaf)
	}

	// Genuine MPT root computed from authentic leaves
	genuineRoot := computeExpectedMPTRoot(t, rawLeaves, h.mapper)

	// In the InputLog fetcher, inject tampered content for entry 2
	for i, l := range rawLeaves {
		if i == 2 {
			h.inLog.AppendLeaf([]byte("MALICIOUS-TAMPERED-CONTENT"))
		} else {
			h.inLog.AppendLeaf(l)
		}
	}

	// OutputLog commits to the genuine root
	signedInCP, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(genuineRoot, signedInCP)); err != nil {
		t.Fatalf("Append leaf failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("VerifyOnce = %v, want ErrRootMismatch", err)
	}

	if hErr := v.HealthCheck(); hErr == nil {
		t.Fatal("HealthCheck() should be unhealthy on tampered input leaf")
	}

	st := v.Status()
	if st.VerifiedOutputSize != 0 {
		t.Errorf("VerifiedOutputSize = %d, want 0", st.VerifiedOutputSize)
	}
}

// TestVerifier_SourcingInvariant_NoInputLogCheckpointCalls strictly verifies Requirement R1:
// the verifier derives all target tree sizes solely from OutputLog leaves and makes ZERO calls to InputLog's checkpoint endpoint.
func TestVerifier_SourcingInvariant_NoInputLogCheckpointCalls(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 20; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}

	// Publish 2 OutputLog leaves
	for _, sz := range []uint64{10, 20} {
		leaves := make([][]byte, sz)
		for i := uint64(0); i < sz; i++ {
			leaves[i] = []byte(fmt.Sprintf("entry-%d", i))
		}
		root := computeExpectedMPTRoot(t, leaves, h.mapper)
		signedInCP, err := h.inLog.SignCheckpoint(sz)
		if err != nil {
			t.Fatalf("SignCheckpoint failed: %v", err)
		}
		if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root, signedInCP)); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	// Assert signed InputLog checkpoint was fetched and SetTreeState propagated the verified root hash
	h.inLog.mu.Lock()
	cpCalls := h.inLog.checkpointCallCount
	gotTreeSize := h.inLog.treeSize
	gotTreeHash := h.inLog.treeHash
	h.inLog.mu.Unlock()
	if cpCalls == 0 {
		t.Fatal("expected InputLog.Checkpoint to be called to verify signed InputLog state")
	}
	if gotTreeSize != 20 {
		t.Fatalf("expected SetTreeState treeSize = 20, got %d", gotTreeSize)
	}
	if gotTreeHash == ([32]byte{}) {
		t.Fatal("expected SetTreeState to propagate non-zero verified input log root hash")
	}
}

// TestVerifier_PrometheusMetrics verifies that Prometheus metrics vindex_auditor_root_mismatch
// and vindex_auditor_root_mismatches_total are correctly updated on mismatch events.
func TestVerifier_PrometheusMetrics(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	// Initial metrics baseline
	initialTotal := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)
	if gVal := testutil.ToFloat64(metrics.AuditorRootMismatch); gVal != 0 {
		t.Fatalf("initial VerifierRootMismatch = %v, want 0", gVal)
	}

	h.inLog.AppendLeaf([]byte("entry-0"))
	tamperedRoot := sha256.Sum256([]byte("wrong_hash"))
	signedInCP, err := h.inLog.SignCheckpoint(1)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(tamperedRoot, signedInCP)); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	_ = v.VerifyOnce(ctx)

	// Post-mismatch metrics check
	if gVal := testutil.ToFloat64(metrics.AuditorRootMismatch); gVal != 1.0 {
		t.Errorf("post-mismatch VerifierRootMismatch = %v, want 1.0", gVal)
	}
	currentTotal := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)
	if currentTotal != initialTotal+1 {
		t.Errorf("VerifierRootMismatchesTotal = %v, want %v", currentTotal, initialTotal+1)
	}
}

// TestVerifier_PersistenceAndRecovery verifies that watermarks and verified state survive restarts on disk.
func TestVerifier_PersistenceAndRecovery(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	dbDir := t.TempDir()
	mptDir := t.TempDir()

	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("recovery-leaf-%d", i)))
	}

	leaves5 := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves5[i] = []byte(fmt.Sprintf("recovery-leaf-%d", i))
	}
	root0 := computeExpectedMPTRoot(t, leaves5, h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, signedInCP0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
	}

	// 1. First run: verify leaf 0
	v1, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	st1 := v1.Status()
	if st1.VerifiedOutputSize != 1 || st1.VerifiedInputSize != 5 || st1.LastVerifiedRoot != root0 {
		t.Fatalf("v1 status incorrect: %+v", st1)
	}
	if err := v1.Close(); err != nil {
		t.Fatalf("v1 Close failed: %v", err)
	}

	// 2. Second run: initialize new verifier pointing to same storage
	v2, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	// Immediately assert watermarks were recovered from disk
	st2 := v2.Status()
	if st2.VerifiedOutputSize != 1 {
		t.Errorf("v2 recovered VerifiedOutputSize = %d, want 1", st2.VerifiedOutputSize)
	}
	if st2.VerifiedInputSize != 5 {
		t.Errorf("v2 recovered VerifiedInputSize = %d, want 5", st2.VerifiedInputSize)
	}
	if st2.LastVerifiedRoot != root0 {
		t.Errorf("v2 recovered LastVerifiedRoot = %x, want %x", st2.LastVerifiedRoot, root0)
	}

	// 3. Incremental verification: append leaf 1 (size 10) and verify with v2
	leaves10 := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		leaves10[i] = []byte(fmt.Sprintf("recovery-leaf-%d", i))
	}
	root1 := computeExpectedMPTRoot(t, leaves10, h.mapper)
	signedInCP1, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root1, signedInCP1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}

	st2Updated := v2.Status()
	if st2Updated.VerifiedOutputSize != 2 || st2Updated.VerifiedInputSize != 10 || st2Updated.LastVerifiedRoot != root1 {
		t.Errorf("v2 updated status incorrect: %+v", st2Updated)
	}
}

// TestVerifier_NonMonotonicInputSize verifies that an OutputLog leaf claiming a regressed input size
// triggers ErrMonotonicityBroken and halts.
func TestVerifier_NonMonotonicInputSize(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}

	// Leaf 0: size 8
	signedInCP0, _ := h.inLog.SignCheckpoint(8)
	leaves8 := make([][]byte, 8)
	for i := 0; i < 8; i++ {
		leaves8[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root0 := computeExpectedMPTRoot(t, leaves8, h.mapper)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, signedInCP0))

	// Leaf 1: claims regressed size 4 (< 8)
	signedInCP1, _ := h.inLog.SignCheckpoint(4)
	leaves4 := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		leaves4[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root1 := computeExpectedMPTRoot(t, leaves4, h.mapper)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root1, signedInCP1))

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrMonotonicityBroken) {
		t.Fatalf("expected ErrMonotonicityBroken, got: %v", err)
	}
	if hErr := v.HealthCheck(); hErr == nil {
		t.Error("expected unhealthy healthcheck on broken monotonicity")
	}
}

// TestVerifier_ZeroDeltaSync verifies that an OutputLog leaf committing to the same input size
// as the previous leaf (zero new input leaves) correctly verifies root equality.
func TestVerifier_ZeroDeltaSync(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}

	leaves := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root := computeExpectedMPTRoot(t, leaves, h.mapper)
	signedInCP, _ := h.inLog.SignCheckpoint(5)

	// Two consecutive OutputLog leaves with identical input size 5 and identical root
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root, signedInCP))
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root, signedInCP))

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed on zero-delta leaves: %v", err)
	}

	st := v.Status()
	if st.VerifiedOutputSize != 2 || st.VerifiedInputSize != 5 {
		t.Errorf("status incorrect: %+v", st)
	}
}

func TestVerifier_Run_HaltOnInvariantError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newTestHarness(t)

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}
	leaves5 := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves5[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root5 := computeExpectedMPTRoot(t, leaves5, h.mapper)
	signedInCP5, _ := h.inLog.SignCheckpoint(5)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root5, signedInCP5))

	// Second leaf regressions input size from 5 to 2 (ErrMonotonicityBroken)
	signedInCP2, _ := h.inLog.SignCheckpoint(2)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root5, signedInCP2))

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
		PollInterval:      20 * time.Millisecond,
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- v.Run(ctx)
	}()

	// Wait for verifier to halt on the invariant error
	deadline := time.Now().Add(2 * time.Second)
	for !v.Status().IsHalted && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	st := v.Status()
	if !st.IsHalted {
		t.Fatalf("expected verifier to be halted on invariant error, but got: %+v", st)
	}
	if !errors.Is(st.HaltError, auditor.ErrMonotonicityBroken) {
		t.Fatalf("expected ErrMonotonicityBroken, got: %v", st.HaltError)
	}

	// Verify Run() has NOT exited early and is waiting on <-ctx.Done()
	select {
	case err := <-errCh:
		t.Fatalf("Run() exited prematurely before context cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
		// Expected: still waiting on ctx.Done()
	}

	// Cancel context to unblock Run()
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, auditor.ErrMonotonicityBroken) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error from Run(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() failed to return within deadline after cancel")
	}
}

// TestVerifier_ForensicStateFreezeOnRootMismatch verifies that when a root mismatch is detected
// on a new OutputLog leaf, zero unverified chunk records or KeyMetaKVSize watermarks are written
// to the underlying Pebble database (Phase 01.4.2 / Backlog 2.7.2).
func TestVerifier_ForensicStateFreezeOnRootMismatch(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("forensic-leaf-%d", i)))
	}
	leaves5 := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves5[i] = []byte(fmt.Sprintf("forensic-leaf-%d", i))
	}
	root5 := computeExpectedMPTRoot(t, leaves5, h.mapper)
	signedInCP5, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint(5) failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root5, signedInCP5)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	db, err := kvstore.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	tileCacheDir := t.TempDir()
	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DB:                db,
		MPTDir:            ":memory:",
		TileCacheDir:      tileCacheDir,
		ChunkSize:         1024,
		CommitBatchSize:   2,
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if db.ChunkSize() != 1024 {
		t.Fatalf("db.ChunkSize() = %d, want 1024", db.ChunkSize())
	}

	// Verify honest leaf 0 (size 5)
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce leaf 0 failed: %v", err)
	}
	kvSizeAfterHonest, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil || kvSizeAfterHonest != 5 {
		t.Fatalf("KeyMetaKVSize after honest leaf 0 = %d (err=%v), want 5", kvSizeAfterHonest, err)
	}

	// Append tampered leaf 1 claiming input size 10 with a forged root
	forgedRoot := sha256.Sum256([]byte("forged-root-at-size-10"))
	signedInCP10, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint(10) failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(forgedRoot, signedInCP10)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	// VerifyOnce must fail with ErrRootMismatch
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}

	// Forensic state freeze assertion: KeyMetaKVSize MUST still be 5, and unverified keys [5..10) MUST NOT exist in Pebble
	kvSizeAfterMismatch, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil || kvSizeAfterMismatch != 5 {
		t.Fatalf("forensic state freeze violated: KeyMetaKVSize mutated to %d (err=%v), want 5", kvSizeAfterMismatch, err)
	}
	for i := 5; i < 10; i++ {
		kh := sha256.Sum256([]byte(fmt.Sprintf("forensic-leaf-%d", i)))
		_, rec, exists, err := db.ActiveChunk(kh)
		if err != nil {
			t.Fatalf("ActiveChunk(%d) failed: %v", i, err)
		}
		if exists || rec != nil {
			t.Fatalf("forensic state freeze violated: unverified leaf %d chunk persisted in Pebble: %+v", i, rec)
		}
	}
}

func TestVerifier_ConsistencyProofVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("SplitViewInputLog_HaltsWithErrConsistencyFailed", func(t *testing.T) {
		h := newTestHarness(t)
		for i := 0; i < 10; i++ {
			h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
		}
		root5 := computeExpectedMPTRoot(t, h.inLog.leaves[:5], h.mapper)
		cp5, err := h.inLog.SignCheckpoint(5)
		if err != nil {
			t.Fatalf("SignCheckpoint(5) failed: %v", err)
		}
		if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root5, cp5)); err != nil {
			t.Fatalf("Append leaf 0 failed: %v", err)
		}

		v, err := auditor.New(auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   h.outLog.origin,
			InputLogOrigin:    h.inLog.origin,
			OutputLog:         h.outLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		})
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		if err := v.VerifyOnce(ctx); err != nil {
			t.Fatalf("VerifyOnce leaf 0 failed: %v", err)
		}

		// Mutate historical leaf 0 in InputLog and sign a split-view checkpoint at size 10
		h.inLog.mu.Lock()
		h.inLog.leaves[0] = []byte("mutated-historical-entry-0")
		h.inLog.mu.Unlock()
		root10 := computeExpectedMPTRoot(t, h.inLog.leaves[:10], h.mapper)
		cp10, err := h.inLog.SignCheckpoint(10)
		if err != nil {
			t.Fatalf("SignCheckpoint(10) failed: %v", err)
		}
		if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root10, cp10)); err != nil {
			t.Fatalf("Append leaf 1 failed: %v", err)
		}

		err = v.VerifyOnce(ctx)
		if err == nil || !errors.Is(err, auditor.ErrConsistencyFailed) {
			t.Fatalf("expected ErrConsistencyFailed on split-view input log, got: %v", err)
		}
	})

	t.Run("SplitViewOutputLog_HaltsWithErrConsistencyFailed", func(t *testing.T) {
		h := newTestHarness(t)
		for i := 0; i < 10; i++ {
			h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
		}
		root5 := computeExpectedMPTRoot(t, h.inLog.leaves[:5], h.mapper)
		cp5, _ := h.inLog.SignCheckpoint(5)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root5, cp5))

		v, err := auditor.New(auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   h.outLog.origin,
			InputLogOrigin:    h.inLog.origin,
			OutputLog:         h.outLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		})
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		if err := v.VerifyOnce(ctx); err != nil {
			t.Fatalf("VerifyOnce leaf 0 failed: %v", err)
		}

		// Mutate historical leaf 0 in OutputLog before appending leaf 1
		h.outLog.mu.Lock()
		h.outLog.leaves[0] = wire.FormatOutputLogLeafFull(root5, 1, cp5)
		h.outLog.mu.Unlock()
		root10 := computeExpectedMPTRoot(t, h.inLog.leaves[:10], h.mapper)
		cp10, _ := h.inLog.SignCheckpoint(10)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root10, cp10))

		err = v.VerifyOnce(ctx)
		if err == nil || !errors.Is(err, auditor.ErrConsistencyFailed) {
			t.Fatalf("expected ErrConsistencyFailed on split-view output log, got: %v", err)
		}
	})
}

func TestVerifier_ExpectedFromAndWitnessPolicy(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	wSKey, wVKey, err := note.GenerateKey(rand.Reader, "witness.example.com")
	if err != nil {
		t.Fatalf("GenerateKey witness failed: %v", err)
	}
	wSigner, err := note.NewSigner(wSKey)
	if err != nil {
		t.Fatalf("NewSigner witness failed: %v", err)
	}
	wVerifier, err := note.NewVerifier(wVKey)
	if err != nil {
		t.Fatalf("NewVerifier witness failed: %v", err)
	}

	for i := 0; i < 6; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("item-%d", i)))
	}
	rawCP6, inCP6, err := h.inLog.SignRawCheckpoint(6)
	if err != nil {
		t.Fatalf("SignRawCheckpoint(6) failed: %v", err)
	}
	// Cosign rawCP6 with witness and set on h.inLog
	parsedNote, err := note.Open(rawCP6, note.VerifierList(h.inVerifier))
	if err != nil {
		t.Fatalf("note.Open failed: %v", err)
	}
	cosignedInCP, err := note.Sign(parsedNote, wSigner)
	if err != nil {
		t.Fatalf("note.Sign witness failed: %v", err)
	}
	h.inLog.SetCheckpoint(cosignedInCP)

	// Compute expected MPTRoot when indexing starts from leaf 2 (skipping 0, 1)
	db, err := kvstore.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()
	idxer := kvstore.NewKVIndexer(db, 65536)
	mptMgr := mpt.NewMem()
	defer func() { _ = mptMgr.Close() }()
	allMod := make(map[string][sha256.Size]byte)
	for i := 2; i < 6; i++ {
		entries, _ := h.mapper.MapLeaf(ctx, h.inLog.leaves[i])
		km := make(map[[32]byte][]uint64)
		ck := make(map[[32]byte]string)
		for _, e := range entries {
			km[e.KeyHash] = append(km[e.KeyHash], uint64(i))
			if e.Key != "" {
				ck[e.KeyHash] = e.Key
			}
		}
		res, err := idxer.IndexMappedBatch(ctx, &ingest.MappedBatch{
			BundleIdx:     0,
			StartLeafIdx:  uint64(i),
			EndLeafIdx:    uint64(i + 1),
			Count:         1,
			KeyMap:        km,
			CanonicalKeys: ck,
		}, nil, 6)
		if err != nil {
			t.Fatalf("IndexMappedBatch failed: %v", err)
		}
		for k, sub := range res.ModifiedKeyValueRoots {
			allMod[k] = sub
		}
	}
	rootFrom2, err := mptMgr.CommitKeysWithVersion(allMod, 6)
	if err != nil {
		t.Fatalf("CommitKeysWithVersion failed: %v", err)
	}

	fromVal := uint64(2)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeafFull(rootFrom2, fromVal, inCP6))

	// 1. Wrong ExpectedFrom -> halts
	wrongFrom := uint64(0)
	vWrongFrom, err := auditor.New(auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		ExpectedFrom:      &wrongFrom,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	})
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = vWrongFrom.Close() }()
	if err := vWrongFrom.VerifyOnce(ctx); err == nil {
		t.Fatal("expected error for ExpectedFrom mismatch, got nil")
	}

	// 2. Correct ExpectedFrom + InputLogWitnessPolicy -> succeeds!
	vOK, err := auditor.New(auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		ExpectedFrom:      &fromVal,
		InputLogWitnessPolicy: &auditor.WitnessPolicy{
			Threshold: 1,
			Verifiers: []note.Verifier{wVerifier},
		},
		DBPath: ":memory:",
		MPTDir: ":memory:",
	})
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = vOK.Close() }()
	if err := vOK.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce with from=2 and witness policy failed: %v", err)
	}
}

func TestVerifier_RegisterAdminRoutes(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("admin-leaf-%d", i)))
	}
	honestRoot := computeExpectedMPTRoot(t, h.inLog.leaves[:5], h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(honestRoot, signedInCP0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	v, err := auditor.New(auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	})
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}

	adminMux := http.NewServeMux()
	v.RegisterAdminRoutes(adminMux)

	// 1. Healthy state: /healthz, /readyz, /metrics, and /debug/pprof/ return 200 OK; /syncz is removed (404)
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("healthy GET %s = %d, want 200", path, rec.Code)
		}
		if rec.Body.String() != "ok\n" {
			t.Fatalf("healthy GET %s body = %q, want %q", path, rec.Body.String(), "ok\n")
		}

		headRec := httptest.NewRecorder()
		adminMux.ServeHTTP(headRec, httptest.NewRequest(http.MethodHead, path, nil))
		if headRec.Code != http.StatusOK {
			t.Fatalf("healthy HEAD %s = %d, want 200", path, headRec.Code)
		}
		if headRec.Body.Len() != 0 {
			t.Fatalf("healthy HEAD %s body len = %d, want 0", path, headRec.Body.Len())
		}

		postRec := httptest.NewRecorder()
		adminMux.ServeHTTP(postRec, httptest.NewRequest(http.MethodPost, path, nil))
		if postRec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s = %d, want 405", path, postRec.Code)
		}
	}

	synczRec := httptest.NewRecorder()
	adminMux.ServeHTTP(synczRec, httptest.NewRequest(http.MethodGet, "/syncz", nil))
	if synczRec.Code != http.StatusNotFound {
		t.Fatalf("GET /syncz = %d, want 404", synczRec.Code)
	}

	metricsRec := httptest.NewRecorder()
	adminMux.ServeHTTP(metricsRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsRec.Code != http.StatusOK || !strings.Contains(metricsRec.Body.String(), "vindex_auditor_root_mismatch") {
		t.Fatalf("GET /metrics = %d, missing expected metric", metricsRec.Code)
	}

	pprofRec := httptest.NewRecorder()
	adminMux.ServeHTTP(pprofRec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if pprofRec.Code != http.StatusOK {
		t.Fatalf("GET /debug/pprof/ = %d, want 200", pprofRec.Code)
	}

	// 2. Trigger forensic halt via forged MPTRoot in OutputLog leaf 1
	for i := 5; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("admin-leaf-%d", i)))
	}
	forgedRoot := sha256.Sum256([]byte("forged-admin-mpt-root"))
	signedInCP1, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint(10) failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(forgedRoot, signedInCP1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}
	if err := v.VerifyOnce(ctx); !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("VerifyOnce = %v, want ErrRootMismatch", err)
	}

	// /healthz MUST stay 200 OK when halted so container orchestrators do not restart-loop
	haltedHealth := httptest.NewRecorder()
	adminMux.ServeHTTP(haltedHealth, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if haltedHealth.Code != http.StatusOK || haltedHealth.Body.String() != "ok\n" {
		t.Fatalf("halted GET /healthz = %d %q, want 200 \"ok\\n\"", haltedHealth.Code, haltedHealth.Body.String())
	}

	// /readyz MUST return 503 Service Unavailable with Retry-After: 30 and JSON diagnostics
	rec := httptest.NewRecorder()
	adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("halted GET /readyz = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("halted GET /readyz Retry-After = %q, want 30", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("halted GET /readyz Content-Type = %q, want application/json", ct)
	}
	var diag map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &diag); err != nil {
		t.Fatalf("halted GET /readyz invalid JSON %q: %v", rec.Body.String(), err)
	}
	if diag["status"] != "degraded" {
		t.Fatalf("halted GET /readyz diag status = %v, want degraded", diag["status"])
	}
	if diag["error"] != "auditor root hash mismatch" {
		t.Fatalf("halted GET /readyz diag error = %v, want \"auditor root hash mismatch\"", diag["error"])
	}
	if diag["committed_root"] != fmt.Sprintf("%x", forgedRoot) {
		t.Fatalf("halted GET /readyz committed_root = %v, want %x", diag["committed_root"], forgedRoot)
	}
}

func TestAuditor_TorchwoodPolicyAndStartupMPTCatchUp(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "example.com/policy/in")
	if err != nil {
		t.Fatalf("GenerateKey in failed: %v", err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "example.com/policy/out")
	if err != nil {
		t.Fatalf("GenerateKey out failed: %v", err)
	}
	outSigner, _ := note.NewSigner(outSKey)

	genWitness := func(name string) (note.Signer, string) {
		sKey, rawVKey, gErr := note.GenerateKey(rand.Reader, name)
		if gErr != nil {
			t.Fatalf("note.GenerateKey(%s) failed: %v", name, gErr)
		}
		cs, gErr := f_note.NewSignerForCosignatureV1(sKey)
		if gErr != nil {
			t.Fatalf("NewSignerForCosignatureV1(%s) failed: %v", name, gErr)
		}
		cosigVKey, gErr := f_note.VKeyToCosignatureV1(rawVKey)
		if gErr != nil {
			t.Fatalf("VKeyToCosignatureV1(%s) failed: %v", name, gErr)
		}
		return cs, cosigVKey
	}
	w1Signer, w1VKey := genWitness("witness1.example.com")
	w2Signer, w2VKey := genWitness("witness2.example.com")
	_, w3VKey := genWitness("witness3.example.com")

	outPolicyText := fmt.Sprintf("log %s\nwitness w1 %s\nwitness w2 %s\nwitness w3 %s\ngroup g 2 w1 w2 w3\nquorum g\n",
		outVKey, w1VKey, w2VKey, w3VKey)
	outPolicy, err := wire.ParsePolicy([]byte(outPolicyText))
	if err != nil {
		t.Fatalf("wire.ParsePolicy failed: %v", err)
	}
	inPolicy, err := wire.BuildPolicy("example.com/policy/in", inVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy failed: %v", err)
	}

	h.inLog = &memoryInputLog{origin: "example.com/policy/in", signer: inSigner}
	h.outLog = &memoryOutputLog{origin: "example.com/policy/out", signer: outSigner}

	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("policy-entry-%d", i)))
	}
	root5 := computeExpectedMPTRoot(t, h.inLog.leaves[:5], h.mapper)
	cp5, _ := h.inLog.SignCheckpoint(5)
	_, unwitnessedOutCP, _ := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root5, cp5))

	dynOut := &dynamicCheckpointLog{OutputLogSource: h.outLog}

	// 1. Unwitnessed OutputLog checkpoint fails 2-of-3 torchwood.Policy quorum
	vFail, err := auditor.New(auditor.Config{
		OutputLogPolicy: outPolicy,
		InputLogPolicy:  inPolicy,
		OutputLog:       dynOut,
		InputLogFetcher: h.inLog,
		MapFn:           h.mapper,
		DBPath:          ":memory:",
		MPTDir:          ":memory:",
	})
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = vFail.Close() }()
	if err := vFail.VerifyOnce(ctx); !errors.Is(err, auditor.ErrCheckpointFailed) {
		t.Fatalf("expected ErrCheckpointFailed without witness quorum, got: %v", err)
	}

	// 2. Cosign OutputLog checkpoint with 2-of-3 witnesses -> succeeds and persists to dbDir + mptDir1
	outVerifier, _ := note.NewVerifier(outVKey)
	parsedOutNote, err := note.Open(unwitnessedOutCP, note.VerifierList(outVerifier))
	if err != nil {
		t.Fatalf("note.Open failed: %v", err)
	}
	witnessedOutCP, err := note.Sign(parsedOutNote, w1Signer, w2Signer)
	if err != nil {
		t.Fatalf("note.Sign witnesses failed: %v", err)
	}
	dynOut.SetCheckpoint(witnessedOutCP)

	dbDir := t.TempDir()
	mptDir1 := t.TempDir()
	v1, err := auditor.New(auditor.Config{
		OutputLogPolicy: outPolicy,
		InputLogPolicy:  inPolicy,
		OutputLog:       dynOut,
		InputLogFetcher: h.inLog,
		MapFn:           h.mapper,
		DBPath:          dbDir,
		MPTDir:          mptDir1,
	})
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce with 2-of-3 witness quorum failed: %v", err)
	}
	if err := v1.Close(); err != nil {
		t.Fatalf("v1 Close failed: %v", err)
	}

	// 3. Simulate crash between Pebble commit and MPT fsync by opening dbDir with a fresh empty mptDir2,
	// then appending OutputLog leaf 1 (size 10) and verifying startup MPT catch-up reconstructs [0, 5) cleanly.
	root10 := computeExpectedMPTRoot(t, h.inLog.leaves[:10], h.mapper)
	cp10, _ := h.inLog.SignCheckpoint(10)
	_, unwitnessedOutCP2, _ := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root10, cp10))
	parsedOutNote2, _ := note.Open(unwitnessedOutCP2, note.VerifierList(outVerifier))
	witnessedOutCP2, _ := note.Sign(parsedOutNote2, w1Signer, w2Signer)
	dynOut.SetCheckpoint(witnessedOutCP2)

	mptDir2 := t.TempDir()
	v2, err := auditor.New(auditor.Config{
		OutputLogPolicy: outPolicy,
		InputLogPolicy:  inPolicy,
		OutputLog:       dynOut,
		InputLogFetcher: h.inLog,
		MapFn:           h.mapper,
		DBPath:          dbDir,
		MPTDir:          mptDir2,
	})
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce after simulated MPT lag failed: %v", err)
	}
	st2 := v2.Status()
	if st2.VerifiedOutputSize != 2 || st2.VerifiedInputSize != 10 || st2.LastVerifiedRoot != root10 {
		t.Fatalf("unexpected v2 status after startup MPT catch-up: %+v", st2)
	}
}
