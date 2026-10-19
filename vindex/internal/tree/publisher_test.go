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

package tree

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

type mockOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
}

func newMockOutputLog(origin string) *mockOutputLog {
	return &mockOutputLog{origin: origin}
}

func (m *mockOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n\n— test_sig\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return idx, []byte(rawCP), nil
}

func (m *mockOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if leafIdx >= uint64(len(m.leaves)) || treeSize > uint64(len(m.leaves)) {
		return nil, fmt.Errorf("invalid leafIdx %d or treeSize %d", leafIdx, treeSize)
	}
	// For testing, return mock sibling hashes
	var proof [][sha256.Size]byte
	if treeSize > 1 {
		proof = append(proof, sha256.Sum256([]byte("sibling_hash")))
	}
	return proof, nil
}

type mockWitness struct {
	witnessName string
}

func (w *mockWitness) Witness(_ context.Context, checkpoint []byte) ([]byte, error) {
	cosig := fmt.Sprintf("— %s cosig_valid\n", w.witnessName)
	return append(checkpoint, []byte(cosig)...), nil
}

func TestPublisher_PublishBatch(t *testing.T) {
	ctx := context.Background()
	mptMgr := mpt.NewMem()
	outLog := newMockOutputLog("example.com/outputlog")
	wit := &mockWitness{witnessName: "witness.alpha"}

	pub := NewOutputPublisher(nil, mptMgr, outLog, wit)

	key1 := sha256.Sum256([]byte("key1"))
	val1 := sha256.Sum256([]byte("val1"))
	valueRoots := map[[32]byte][32]byte{key1: val1}

	rawInputCP := []byte("example.com/inputlog\n1000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   1000,
		Hash:   make([]byte, 32),
	}

	state, err := pub.PublishBatch(ctx, valueRoots, inputCP, rawInputCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	if state.OutputLogIndex != 0 {
		t.Fatalf("OutputLogIndex = %d, want 0", state.OutputLogIndex)
	}
	if state.OutputLogSize != 1 {
		t.Fatalf("OutputLogSize = %d, want 1", state.OutputLogSize)
	}
	if state.InputLogSize != 1000 {
		t.Fatalf("InputLogSize = %d, want 1000", state.InputLogSize)
	}

	// Verify MPT has the updated key
	proof, val, exists, err := mptMgr.Prove(key1)
	if err != nil || !exists || val != val1 {
		t.Fatalf("Prove(key1) failed: exists=%v, val=%x (want %x), err=%v", exists, val, val1, err)
	}
	if err := mpt.Verify(state.MPTRoot, key1, val, true, proof); err != nil {
		t.Fatalf("Verify(key1) against MPTRoot failed: %v", err)
	}
}

func TestPublisher_PublishKeyBatch(t *testing.T) {
	ctx := context.Background()
	mptMgr := mpt.NewMem()
	outLog := newMockOutputLog("example.com/outputlog")
	wit := &mockWitness{witnessName: "witness.alpha"}

	pub := NewOutputPublisher(nil, mptMgr, outLog, wit)

	key1 := "com.google.mail."
	val1 := sha256.Sum256([]byte("val1"))
	valueRoots := map[string][32]byte{key1: val1}

	rawInputCP := []byte("example.com/inputlog\n1000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   1000,
		Hash:   make([]byte, 32),
	}

	state, err := pub.PublishKeyBatch(ctx, valueRoots, inputCP, rawInputCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	proof, val, exists, err := mptMgr.ProveKey([]byte(key1))
	if err != nil || !exists || val != val1 {
		t.Fatalf("ProveKey(%q) failed: exists=%v, val=%x, err=%v", key1, exists, val, err)
	}
	if err := mpt.VerifyKey(state.MPTRoot, []byte(key1), val, true, proof); err != nil {
		t.Fatalf("VerifyKey(%q) failed: %v", key1, err)
	}
}

type divergingOutputLog struct {
	*mockOutputLog
	mptMgr *mpt.Manager
}

func (d *divergingOutputLog) Append(ctx context.Context, leafData []byte) (uint64, []byte, error) {
	sneakKey := sha256.Sum256([]byte("sneaky_interfering_key"))
	sneakVal := sha256.Sum256([]byte("sneaky_interfering_val"))
	if _, err := d.mptMgr.Commit(map[[32]byte][32]byte{sneakKey: sneakVal}); err != nil {
		return 0, nil, err
	}
	return d.mockOutputLog.Append(ctx, leafData)
}

func TestPublishBatch_RootPredictionMismatch_Panics(t *testing.T) {
	ctx := context.Background()
	mptMgr := mpt.NewMem()
	outLog := newMockOutputLog("example.com/outputlog")
	wit := &mockWitness{witnessName: "witness.alpha"}

	divergeLog := &divergingOutputLog{
		mockOutputLog: outLog,
		mptMgr:        mptMgr,
	}

	pub := NewOutputPublisher(nil, mptMgr, divergeLog, wit)

	key1 := sha256.Sum256([]byte("key1"))
	val1 := sha256.Sum256([]byte("val1"))
	valueRoots := map[[32]byte][32]byte{key1: val1}

	rawInputCP := []byte("example.com/inputlog\n1000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   1000,
		Hash:   make([]byte, 32),
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected PublishBatch to panic on root prediction mismatch, but it did not panic")
		}
		panicMsg := fmt.Sprintf("%v", r)
		if !strings.Contains(panicMsg, "prediction mismatch") && !strings.Contains(panicMsg, "invariant violation") {
			t.Errorf("unexpected panic message: %s", panicMsg)
		}
	}()

	_, _ = pub.PublishBatch(ctx, valueRoots, inputCP, rawInputCP)
}

type failingWitness struct{}

func (f *failingWitness) Witness(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("witness connection refused")
}

func TestOutputPublisher_WitnessFailure(t *testing.T) {
	ctx := context.Background()
	mptMgr := mpt.NewMem()
	outLog := newMockOutputLog("example.com/outputlog")
	wit := &failingWitness{}

	pub := NewOutputPublisher(nil, mptMgr, outLog, wit)

	key1 := sha256.Sum256([]byte("key1"))
	val1 := sha256.Sum256([]byte("val1"))
	valueRoots := map[[32]byte][32]byte{key1: val1}

	rawInputCP := []byte("example.com/inputlog\n1000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   1000,
		Hash:   make([]byte, 32),
	}

	state, err := pub.PublishBatch(ctx, valueRoots, inputCP, rawInputCP)
	if err == nil {
		t.Fatal("expected error from PublishBatch with failing witness, got nil")
	}
	if state != nil {
		t.Fatalf("expected nil state, got %+v", state)
	}
	if pub.GetServingState() != nil {
		t.Fatal("expected nil serving state after witness failure")
	}
}

func TestOutputPublisher_GetAndSetServingState(t *testing.T) {
	mptMgr := mpt.NewMem()
	pub := NewOutputPublisher(nil, mptMgr, nil, nil)
	if pub.GetServingState() != nil {
		t.Fatal("expected initial serving state to be nil")
	}

	dummyState := &ServingState{
		InputLogSize:  42,
		RawCheckpoint: []byte("out.log\n1\nhash\n\n— wit1 sig1\n— wit2 sig2\n"),
	}
	pub.SetServingState(dummyState)
	if got := pub.GetServingState(); got != dummyState || got.InputLogSize != 42 {
		t.Fatalf("GetServingState = %+v, want dummyState", got)
	}

	pub.SetServingState(nil)
	if pub.GetServingState() != nil {
		t.Fatal("expected nil serving state after reset")
	}
}

type signedMockOutputLog struct {
	origin string
	signer note.Signer
	leaves [][]byte
}

func (m *signedMockOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	root := kvstore.BatchRoot(m.leaves)
	body := fmt.Sprintf("%s\n%d\n%s\n", m.origin, len(m.leaves), base64.StdEncoding.EncodeToString(root[:]))
	signed, err := note.Sign(&note.Note{Text: body}, m.signer)
	if err != nil {
		return 0, nil, err
	}
	return idx, signed, nil
}

func (m *signedMockOutputLog) InclusionProof(_ context.Context, _, _ uint64) ([][sha256.Size]byte, error) {
	return nil, nil
}

type signingMockWitness struct {
	signer note.Signer
}

func (w *signingMockWitness) Witness(_ context.Context, cp []byte) ([]byte, error) {
	n, err := note.Open(cp, note.VerifierList())
	if err != nil {
		var uErr *note.UnverifiedNoteError
		if n == nil && strings.Contains(err.Error(), "unverified") {
			_ = uErr
		}
	}
	parts := strings.SplitN(string(cp), "\n\n", 2)
	cosigned, err := note.Sign(&note.Note{Text: parts[0] + "\n"}, w.signer)
	if err != nil {
		return nil, err
	}
	cosigParts := strings.SplitN(string(cosigned), "\n\n", 2)
	return append(cp, []byte(cosigParts[1])...), nil
}

func TestOutputPublisher_SetOutputLogPolicy(t *testing.T) {
	ctx := context.Background()
	const outOrigin = "example.com/signed-outputlog"

	logSKey, logVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatalf("GenerateKey(log) failed: %v", err)
	}
	logSigner, _ := note.NewSigner(logSKey)
	logVerifier, _ := note.NewVerifier(logVKey)

	witSKey, witVKey, err := note.GenerateKey(rand.Reader, "witness.example/w1")
	if err != nil {
		t.Fatalf("GenerateKey(wit) failed: %v", err)
	}
	witSigner, _ := note.NewSigner(witSKey)
	witVerifier, _ := note.NewVerifier(witVKey)

	pol, err := wire.BuildPolicy(outOrigin, logVerifier, []note.Verifier{witVerifier}, 1)
	if err != nil {
		t.Fatalf("BuildPolicy failed: %v", err)
	}

	rawInputCP := []byte("example.com/inputlog\n100\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 100, Hash: make([]byte, 32)}
	val1 := sha256.Sum256([]byte("val1"))

	// 1. Without witness signature, policy must reject checkpoint
	mptMgr1 := mpt.NewMem()
	outLog1 := &signedMockOutputLog{origin: outOrigin, signer: logSigner}
	pub1 := NewOutputPublisher(nil, mptMgr1, outLog1, nil)
	pub1.SetOutputLogPolicy(pol)
	if _, err := pub1.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, inputCP, rawInputCP); err == nil {
		t.Fatal("expected PublishKeyBatch to fail when required witness signature is missing")
	}

	// 2. With valid witness signature, policy succeeds and promotes ServingState
	mptMgr2 := mpt.NewMem()
	outLog2 := &signedMockOutputLog{origin: outOrigin, signer: logSigner}
	pub2 := NewOutputPublisher(nil, mptMgr2, outLog2, &signingMockWitness{signer: witSigner})
	pub2.SetOutputLogPolicy(pol)
	state, err := pub2.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, inputCP, rawInputCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch with valid OutputLogPolicy failed: %v", err)
	}
	if _, err := pol.Verify(state.RawCheckpoint); err != nil {
		t.Fatalf("pol.Verify(state.RawCheckpoint) failed: %v", err)
	}
}

