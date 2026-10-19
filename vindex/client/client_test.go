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

package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

type testOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
	signer note.Signer
}

func (m *testOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	signedCP, err := note.Sign(&note.Note{Text: rawCP}, m.signer)
	if err != nil {
		return 0, nil, err
	}
	return idx, signedCP, nil
}

func (m *testOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
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
		k := uint64(1)
		for k*2 < uint64(n) {
			k *= 2
		}
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

type testKeys struct {
	outSigner   note.Signer
	outVerifier note.Verifier
	outVKey     string
	inSigner    note.Signer
	inVerifier  note.Verifier
	inVKey      string
}

func newTestKeys(t testing.TB) testKeys {
	t.Helper()
	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "example.com/output")
	if err != nil {
		t.Fatalf("note.GenerateKey(output) failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(output) failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(output) failed: %v", err)
	}

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "example.com/input")
	if err != nil {
		t.Fatalf("note.GenerateKey(input) failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(input) failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(input) failed: %v", err)
	}

	return testKeys{
		outSigner:   outSigner,
		outVerifier: outVerifier,
		outVKey:     outVKey,
		inSigner:    inSigner,
		inVerifier:  inVerifier,
		inVKey:      inVKey,
	}
}

func (k testKeys) clientConfig(t testing.TB) Config {
	t.Helper()
	outPol, err := SingleKeyPolicy("example.com/output", k.outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	return Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}
}

func (k testKeys) signInputCP(t testing.TB, size uint64) (*log.Checkpoint, []byte) {
	t.Helper()
	hash := sha256.Sum256(fmt.Appendf(nil, "input-root-%d", size))
	text := fmt.Sprintf("example.com/input\n%d\n%s\n", size, base64.StdEncoding.EncodeToString(hash[:]))
	signed, err := note.Sign(&note.Note{Text: text}, k.inSigner)
	if err != nil {
		t.Fatalf("note.Sign(input) failed: %v", err)
	}
	return &log.Checkpoint{
		Origin: "example.com/input",
		Size:   size,
		Hash:   hash[:],
	}, signed
}

func setupTestEnvironment(t testing.TB, chunkSize uint64) (*server.ReadServer, *kvstore.DB, *mpt.Manager, *tree.OutputPublisher, *kvstore.KVIndexer, testKeys) {
	t.Helper()
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keys := newTestKeys(t)
	mptMgr := mpt.NewMem()
	outLog := &testOutputLog{
		origin: "example.com/output",
		signer: keys.outSigner,
	}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	pub.SetInputOrigin("example.com/input")
	idxer := kvstore.NewKVIndexer(db, chunkSize)
	srv := server.NewReadServer(db, mptMgr, pub, chunkSize)

	return srv, db, mptMgr, pub, idxer, keys
}

func collectValuesNewestFirst(ctx context.Context, mk MatchedKey) ([]uint64, error) {
	var res []uint64
	for idx, err := range mk.Values(ctx) {
		if err != nil {
			return nil, err
		}
		res = append(res, idx)
	}
	return res, nil
}

func TestClient_PositiveInclusionAndNonInclusion(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)

	k1 := "target_key_1"
	k2 := "target_key_2"
	unmapped := "unmapped_key"
	kh1 := sha256.Sum256([]byte(k1))
	kh2 := sha256.Sum256([]byte(k2))

	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			kh1: {5, 20, 35},
			kh2: {10},
		},
		CanonicalKeys: map[[32]byte]string{
			kh1: k1,
			kh2: k2,
		},
	}

	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	inCP, rawInCP := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := New(ts.URL, keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	// 1. Inclusion test for k1
	kr1, err := cli.LookupKey(ctx, k1)
	if err != nil {
		t.Fatalf("LookupKey(k1) failed: %v", err)
	}
	if len(kr1.Keys) != 1 || kr1.Keys[0].Key != k1 {
		t.Fatalf("unexpected LookupResult for k1: %+v", kr1)
	}
	if kr1.InputSize != 100 || kr1.OutputSize != 1 || kr1.InputOrigin != "example.com/input" {
		t.Fatalf("unexpected metadata: in=%d out=%d origin=%q", kr1.InputSize, kr1.OutputSize, kr1.InputOrigin)
	}
	if kr1.MPTRoot == ([32]byte{}) || kr1.Keys[0].ValueRoot == ([32]byte{}) {
		t.Fatalf("expected non-zero MPTRoot and ValueRoot")
	}

	indices1, err := collectValuesNewestFirst(ctx, kr1.Keys[0])
	if err != nil {
		t.Fatalf("Values(k1) failed: %v", err)
	}
	if !slices.Equal(indices1, []uint64{35, 20, 5}) {
		t.Fatalf("Values(k1) = %v, want [35 20 5] (newest-first)", indices1)
	}

	// 2. Inclusion test for k2
	kr2, err := cli.LookupKey(ctx, k2)
	if err != nil {
		t.Fatalf("LookupKey(k2) failed: %v", err)
	}
	indices2, err := collectValuesNewestFirst(ctx, kr2.Keys[0])
	if err != nil {
		t.Fatalf("Values(k2) failed: %v", err)
	}
	if !slices.Equal(indices2, []uint64{10}) {
		t.Fatalf("Values(k2) = %v, want [10]", indices2)
	}

	// 3. Non-inclusion test for unmapped
	krNon, err := cli.LookupKey(ctx, unmapped)
	if err != nil {
		t.Fatalf("LookupKey(unmapped) failed: %v", err)
	}
	if len(krNon.Keys) != 0 {
		t.Fatalf("LookupKey(unmapped) unexpected response: %+v", krNon)
	}
}

func TestClient_PaginationContinuation(t *testing.T) {
	ctx := context.Background()
	const chunkSize = 10
	srv, db, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)
	db.SetChunkSize(chunkSize)

	keyStr := "paginated_key"
	kh := sha256.Sum256([]byte(keyStr))

	var indices []uint64
	for i := uint64(0); i < 250; i++ {
		indices = append(indices, i)
	}
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        250,
		KeyMap: map[[32]byte][]uint64{
			kh: indices,
		},
		CanonicalKeys: map[[32]byte]string{
			kh: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	inCP, rawInCP := keys.signInputCP(t, 250)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	var valuesReqs atomic.Int32
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/values") {
			valuesReqs.Add(1)
		}
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	kr, err := cli.LookupKey(ctx, keyStr)
	if err != nil {
		t.Fatalf("LookupKey failed: %v", err)
	}
	if len(kr.Keys) != 1 {
		t.Fatalf("expected 1 matched key, got %d", len(kr.Keys))
	}

	// 1. Early break after 5 items should fetch only 1 /values page
	var top5 []uint64
	for idx, err := range kr.Keys[0].Values(ctx) {
		if err != nil {
			t.Fatalf("Values early break failed: %v", err)
		}
		top5 = append(top5, idx)
		if len(top5) == 5 {
			break
		}
	}
	if !slices.Equal(top5, []uint64{249, 248, 247, 246, 245}) {
		t.Fatalf("top5 = %v, want [249 248 247 246 245]", top5)
	}
	if got := valuesReqs.Load(); got != 1 {
		t.Fatalf("expected 1 /values request on early break, got %d", got)
	}

	// 2. Full iteration walks all 3 pages newest-first (249 down to 0)
	valuesReqs.Store(0)
	allDesc, err := collectValuesNewestFirst(ctx, kr.Keys[0])
	if err != nil {
		t.Fatalf("full Values iteration failed: %v", err)
	}
	if got := valuesReqs.Load(); got != 3 {
		t.Fatalf("expected 3 /values page requests for 250 items (100+100+50), got %d", got)
	}
	wantDesc := slices.Clone(indices)
	slices.Reverse(wantDesc)
	if !slices.Equal(allDesc, wantDesc) {
		t.Fatalf("allDesc len=%d, want 250 newest-first", len(allDesc))
	}
}

func TestClient_NegativeTamperCases(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)

	keyStr := "tamper_key"
	key := sha256.Sum256([]byte(keyStr))
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20, 30},
		},
		CanonicalKeys: map[[32]byte]string{
			key: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	inCP, rawInCP := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	reqKeys := httptest.NewRequest(http.MethodGet, "/keys?key="+keyStr, nil)
	wKeys := httptest.NewRecorder()
	srv.HandleKeys(wKeys, reqKeys)
	if wKeys.Code != http.StatusOK {
		t.Fatalf("HandleKeys failed: %d", wKeys.Code)
	}
	validKeysBody := wKeys.Body.String()

	reqValues := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr+"&before=100", nil)
	wValues := httptest.NewRecorder()
	srv.HandleValues(wValues, reqValues)
	if wValues.Code != http.StatusOK {
		t.Fatalf("HandleValues failed: %d", wValues.Code)
	}
	validValuesBody := wValues.Body.String()

	cfg := keys.clientConfig(t)

	// Baseline check
	keysResp, err := VerifyKeysResponse([]byte(validKeysBody), keyStr, false, cfg)
	if err != nil {
		t.Fatalf("Baseline valid keys body failed verification: %v", err)
	}
	expectedValueRoot := keysResp.Keys[0].ValueRoot
	if _, err := VerifyValuesResponse([]byte(validValuesBody), expectedValueRoot, 0, 100); err != nil {
		t.Fatalf("Baseline valid values body failed verification: %v", err)
	}

	// Tamper 1: Corrupted Output Log Root in checkpoint
	tamperedCP := strings.Replace(validKeysBody, "example.com/output\n1\n", "example.com/output\n2\n", 1)
	if _, err := VerifyKeysResponse([]byte(tamperedCP), keyStr, false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Tampered checkpoint size should fail with ErrVerificationFailed, got %v", err)
	}

	// Tamper 2: Corrupted Output Log inclusion proof
	tamperedProof := strings.Replace(validKeysBody, "index 0\n", "index 0\nbm9uc2Vuc2VoYXNoCg==\n", 1)
	if _, err := VerifyKeysResponse([]byte(tamperedProof), keyStr, false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Tampered output log proof should fail with ErrVerificationFailed, got %v", err)
	}

	// Tamper 3: Tampered Index in values response
	tamperedIndices := strings.Replace(validValuesBody, "20\n", "21\n", 1)
	if _, err := VerifyValuesResponse([]byte(tamperedIndices), expectedValueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Tampered index value should fail with ErrVerificationFailed, got %v", err)
	}

	// Tamper 4: Unordered Indices
	unorderedIndices := strings.Replace(validValuesBody, "20\n30\n", "30\n20\n", 1)
	if _, err := VerifyValuesResponse([]byte(unorderedIndices), expectedValueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Unordered indices should fail with ErrVerificationFailed, got %v", err)
	}

	// Tamper 5: Index >= before
	outOfBoundsIndices := strings.Replace(validValuesBody, "30\n", "150\n", 1)
	if _, err := VerifyValuesResponse([]byte(outOfBoundsIndices), expectedValueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Out of bounds index >= before should fail with ErrVerificationFailed, got %v", err)
	}

	// Tamper 6: Corrupted MPT proof
	tamperedMPT := strings.Replace(validKeysBody, "c2sp.org/tlog-vindex-keys@v1\nproof\n", "c2sp.org/tlog-vindex-keys@v1\nproof AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n", 1)
	if _, err := VerifyKeysResponse([]byte(tamperedMPT), keyStr, false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Tampered MPT proof should fail with ErrVerificationFailed, got %v", err)
	}

	// Tamper 7: Missing mandatory section
	stanzas := strings.SplitN(validKeysBody, "\n\n", 2)
	if _, err := VerifyKeysResponse([]byte(stanzas[0]), keyStr, false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Missing binding proof section should fail with ErrVerificationFailed, got %v", err)
	}

	// Tamper 8: Empty indexed range (input_size == from) returning non-empty matches must be rejected with ErrVerificationFailed
	srvEmpty, _, _, pubEmpty, _, keysEmpty := setupTestEnvironment(t, chunkSize)
	pubEmpty.SetFrom(100)
	inCPEmpty, rawInCPEmpty := keysEmpty.signInputCP(t, 100)
	fakeVR := sha256.Sum256([]byte("forged-vr"))
	if _, err := pubEmpty.PublishKeyBatch(ctx, map[string][32]byte{keyStr: fakeVR}, inCPEmpty, rawInCPEmpty); err != nil {
		t.Fatalf("PublishKeyBatch empty range failed: %v", err)
	}
	wEmpty := httptest.NewRecorder()
	srvEmpty.HandleKeys(wEmpty, httptest.NewRequest(http.MethodGet, "/keys?key="+keyStr, nil))
	if _, err := VerifyKeysResponse(wEmpty.Body.Bytes(), keyStr, false, keysEmpty.clientConfig(t)); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when input_size == from has non-empty matches, got: %v", err)
	}
}

func TestClient_Values_ContinuationFaults(t *testing.T) {
	ctx := context.Background()
	const chunkSize = 100
	srv, db, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)
	db.SetChunkSize(chunkSize)

	keyStr := "mismatch_key"
	kh := sha256.Sum256([]byte(keyStr))
	var indices []uint64
	for i := uint64(0); i < 250; i++ {
		indices = append(indices, i*10)
	}
	batch := &ingest.MappedBatch{
		Count: 2500,
		KeyMap: map[[32]byte][]uint64{
			kh: indices,
		},
		CanonicalKeys: map[[32]byte]string{
			kh: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(t, 2500)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	var return404OnValues bool
	tamperedMux := http.NewServeMux()
	tamperedMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if return404OnValues && strings.HasPrefix(r.URL.Path, "/values") {
			http.Error(w, "missing values", http.StatusNotFound)
			return
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		body := rec.Body.String()
		if r.URL.Query().Get("before") == "1500" {
			body = strings.Replace(body, "\n1000\n", "\n1001\n", 1)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(body))
	})

	ts := httptest.NewServer(tamperedMux)
	defer ts.Close()

	cli, err := New(ts.URL, keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	kr, err := cli.LookupKey(ctx, keyStr)
	if err != nil {
		t.Fatalf("LookupKey failed: %v", err)
	}

	_, err = collectValuesNewestFirst(ctx, kr.Keys[0])
	if !errors.Is(err, ErrVerificationFailed) || !strings.Contains(err.Error(), "value log root mismatch") {
		t.Fatalf("expected ErrVerificationFailed value log root mismatch error, got: %v", err)
	}

	// Unexpected HTTP 404 on promised /values page must surface as ErrVerificationFailed
	return404OnValues = true
	_, err = collectValuesNewestFirst(ctx, kr.Keys[0])
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed on unexpected HTTP 404 for promised /values page, got: %v", err)
	}
}

func TestClient_PrefixLookupAndTwoSidedSoundness(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)

	kApex := "com.google."
	kMail := "com.google.mail."
	kDocs := "com.google.docs."
	kWild := "com.google.*."
	kSibling := "com.googleapis.www."

	khApex := sha256.Sum256([]byte(kApex))
	khMail := sha256.Sum256([]byte(kMail))
	khDocs := sha256.Sum256([]byte(kDocs))
	khWild := sha256.Sum256([]byte(kWild))
	khSibling := sha256.Sum256([]byte(kSibling))

	batch := &ingest.MappedBatch{
		Count: 100,
		KeyMap: map[[32]byte][]uint64{
			khApex:    {1, 10},
			khMail:    {2, 20, 30},
			khDocs:    {3},
			khWild:    {4, 40},
			khSibling: {99},
		},
		CanonicalKeys: map[[32]byte]string{
			khApex:    kApex,
			khMail:    kMail,
			khDocs:    kDocs,
			khWild:    kWild,
			khSibling: kSibling,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := keys.clientConfig(t)
	cli, err := New(ts.URL, cfg, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// 1. LookupPrefix("com.google.") -> must return 4 keys in ascending order and exclude "com.googleapis.www."
	prefixResp, err := cli.LookupPrefix(ctx, "com.google.")
	if err != nil {
		t.Fatalf("LookupPrefix failed: %v", err)
	}
	if len(prefixResp.Keys) != 4 {
		t.Fatalf("expected 4 matched keys, got %d: %+v", len(prefixResp.Keys), prefixResp.Keys)
	}
	wantOrder := []string{kApex, kWild, kDocs, kMail}
	for i, wantKey := range wantOrder {
		if prefixResp.Keys[i].Key != wantKey {
			t.Errorf("Keys[%d].Key = %q, want %q", i, prefixResp.Keys[i].Key, wantKey)
		}
		if prefixResp.Keys[i].ValueRoot == ([32]byte{}) {
			t.Errorf("Keys[%d].ValueRoot is zero", i)
		}
	}
	mailIndices, err := collectValuesNewestFirst(ctx, prefixResp.Keys[3])
	if err != nil {
		t.Fatalf("Values(kMail) failed: %v", err)
	}
	if !slices.Equal(mailIndices, []uint64{30, 20, 2}) {
		t.Errorf("unexpected indices for %s: %v, want [30 20 2]", kMail, mailIndices)
	}

	// 2. Non-existent prefix ("com.nonexistent.") -> verified empty subtree
	emptyPrefixResp, err := cli.LookupPrefix(ctx, "com.nonexistent.")
	if err != nil {
		t.Fatalf("LookupPrefix(com.nonexistent.) failed: %v", err)
	}
	if len(emptyPrefixResp.Keys) != 0 {
		t.Fatalf("expected 0 keys for nonexistent prefix, got %d", len(emptyPrefixResp.Keys))
	}

	// 3. Adversarial two-sided soundness check: broader prefix proof rejected
	req := httptest.NewRequest(http.MethodGet, "/keys?prefix=com.", nil)
	w := httptest.NewRecorder()
	srv.SetPrefixPolicy(nil)
	srv.HandleKeys(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleKeys(com.) failed: %d", w.Code)
	}
	if _, err := VerifyKeysResponse(w.Body.Bytes(), "com.google.", true, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("VerifyKeysResponse must reject broader subtree containing keys outside query prefix, got %v", err)
	}
	if _, err := VerifyKeysResponse(w.Body.Bytes(), "com.google.", false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("VerifyKeysResponse point lookup must reject response with multiple keys, got %v", err)
	}

	// 4. HTTP 413 maps to ErrTooManyKeys
	srv.SetMaxPrefixKeys(2)
	if _, err := cli.LookupPrefix(ctx, "com.google."); !errors.Is(err, ErrTooManyKeys) {
		t.Fatalf("expected ErrTooManyKeys on HTTP 413, got: %v", err)
	}
}

func TestClient_ValuesTruncationAndCompactRangeValidation(t *testing.T) {
	indices := []uint64{10, 20}
	valueRoot, err := wire.ComputeValueLogRoot(nil, 0, indices)
	if err != nil {
		t.Fatalf("ComputeValueLogRoot failed: %v", err)
	}

	// 1. Valid single-page values response (preceding 0)
	validBody := "c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n10\n20\n"
	if _, err := VerifyValuesResponse([]byte(validBody), valueRoot, 0, 100); err != nil {
		t.Fatalf("expected valid values response to pass, got: %v", err)
	}

	// 1b. Zero expectedValueRoot must be rejected by VerifyValuesResponse
	if _, err := VerifyValuesResponse([]byte(validBody), [32]byte{}, 0, 100); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected VerifyValuesResponse to reject zero expectedValueRoot, got %v", err)
	}

	// 2. Preceding 0 with non-empty hash lines -> rejected
	dummyHash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	extraHashBody := fmt.Sprintf("c2sp.org/tlog-vindex-values@v1\npreceding 0\n%s\n\n10\n20\n", dummyHash)
	if _, err := VerifyValuesResponse([]byte(extraHashBody), valueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected error when preceding 0 has hash lines, got %v", err)
	}

	// 3. Mismatched preceding > 0 with 0 hashes
	mismatchedBody := "c2sp.org/tlog-vindex-values@v1\npreceding 5\n\n10\n20\n"
	if _, err := VerifyValuesResponse([]byte(mismatchedBody), valueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected mismatched popcount error, got: %v", err)
	}

	// 4. Empty indices block -> rejected
	emptyIndicesBody := "c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n"
	if _, err := VerifyValuesResponse([]byte(emptyIndicesBody), valueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected error for empty indices block, got %v", err)
	}

	// 5. Preceding size > indices[0] - from (exceeds available range / upperBound)
	overflowBody := fmt.Sprintf("c2sp.org/tlog-vindex-values@v1\npreceding 64\n%s\n\n10\n20\n", dummyHash)
	if _, err := VerifyValuesResponse([]byte(overflowBody), valueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("expected exceed upperBound error, got: %v", err)
	}
}

func TestStateless_VerifyKeysAndValuesResponse(t *testing.T) {
	ctx := context.Background()
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, 64)
	pub.SetFrom(50)

	kTest := "com.example.stateless"
	khTest := sha256.Sum256([]byte(kTest))
	batch1 := &ingest.MappedBatch{
		StartLeafIdx: 50,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			khTest: {55, 60, 75},
		},
		CanonicalKeys: map[[32]byte]string{
			khTest: kTest,
		},
	}
	res1, err := idxer.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("IndexBatch 1 failed: %v", err)
	}
	inCP1, rawInCP1 := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res1.ModifiedKeyValueRoots, inCP1, rawInCP1); err != nil {
		t.Fatalf("PublishKeyBatch 1 failed: %v", err)
	}

	wKeys1 := httptest.NewRecorder()
	srv.HandleKeys(wKeys1, httptest.NewRequest(http.MethodGet, "/keys?key="+kTest, nil))
	if wKeys1.Code != http.StatusOK {
		t.Fatalf("HandleKeys 1 failed: %d", wKeys1.Code)
	}
	body1 := wKeys1.Body.Bytes()

	batch2 := &ingest.MappedBatch{
		StartLeafIdx: 100,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			khTest: {110},
		},
		CanonicalKeys: map[[32]byte]string{
			khTest: kTest,
		},
	}
	res2, err := idxer.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("IndexBatch 2 failed: %v", err)
	}
	inCP2, rawInCP2 := keys.signInputCP(t, 150)
	if _, err := pub.PublishKeyBatch(ctx, res2.ModifiedKeyValueRoots, inCP2, rawInCP2); err != nil {
		t.Fatalf("PublishKeyBatch 2 failed: %v", err)
	}

	wKeys2 := httptest.NewRecorder()
	srv.HandleKeys(wKeys2, httptest.NewRequest(http.MethodGet, "/keys?key="+kTest, nil))
	if wKeys2.Code != http.StatusOK {
		t.Fatalf("HandleKeys 2 failed: %d", wKeys2.Code)
	}
	body2 := wKeys2.Body.Bytes()

	cfg := keys.clientConfig(t)

	// Pure VerifyKeysResponse has zero state: verifying body2 (size 150) then body1 (size 100) both succeed!
	kr2, err := VerifyKeysResponse(body2, kTest, false, cfg)
	if err != nil {
		t.Fatalf("VerifyKeysResponse(body2) failed: %v", err)
	}
	if len(kr2.Keys) != 1 || kr2.From != 50 || kr2.InputSize != 150 || kr2.OutputSize != 2 {
		t.Fatalf("unexpected kr2: %+v", kr2)
	}
	if kr2.OutputRoot == ([32]byte{}) || kr2.InputRoot == ([32]byte{}) {
		t.Fatalf("expected non-zero OutputRoot and InputRoot on kr2")
	}

	kr1, err := VerifyKeysResponse(body1, kTest, false, cfg)
	if err != nil {
		t.Fatalf("stateless VerifyKeysResponse(body1) after body2 failed: %v", err)
	}
	if len(kr1.Keys) != 1 || kr1.From != 50 || kr1.InputSize != 100 || kr1.OutputSize != 1 {
		t.Fatalf("unexpected kr1: %+v", kr1)
	}

	// VerifyValuesResponse with from > 0 bounds:
	compHash := sha256.Sum256([]byte("compact-prefix-4"))
	pageIndices := []uint64{55, 58, 59}
	valRoot, err := wire.ComputeValueLogRoot([][32]byte{compHash}, 4, pageIndices)
	if err != nil {
		t.Fatalf("ComputeValueLogRoot failed: %v", err)
	}
	rawVals := wire.FormatValuesResponse(4, [][32]byte{compHash}, pageIndices)
	vr, err := VerifyValuesResponse(rawVals, valRoot, 50, 60)
	if err != nil {
		t.Fatalf("VerifyValuesResponse valid from=50 failed: %v", err)
	}
	nextBefore, nextRoot, ok := vr.NextPage()
	if !ok || nextBefore != 55 || vr.Preceding != 4 || nextRoot == ([32]byte{}) {
		t.Fatalf("unexpected ValuesResponse NextPage: before=%d root=%x ok=%v", nextBefore, nextRoot, ok)
	}

	// before <= from -> rejected with ErrVerificationFailed
	if _, err := VerifyValuesResponse(rawVals, valRoot, 50, 50); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when before == from, got: %v", err)
	}
	if _, err := VerifyValuesResponse(rawVals, valRoot, 60, 50); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when before < from, got: %v", err)
	}
	if _, err := VerifyValuesResponse(rawVals, valRoot, 0, 0); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when before == 0, got: %v", err)
	}

	// Indices[0] < from
	if _, err := VerifyValuesResponse(rawVals, valRoot, 56, 60); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when Indices[0] < from, got: %v", err)
	}

	// Preceding > Indices[0] - from
	if _, err := VerifyValuesResponse(rawVals, valRoot, 52, 60); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when Preceding > Indices[0]-from, got: %v", err)
	}

	// Tight bound len(Indices) == before - from - Preceding
	tightIndices := []uint64{54, 55, 56}
	tightRoot, err := wire.ComputeValueLogRoot([][32]byte{compHash}, 4, tightIndices)
	if err != nil {
		t.Fatalf("ComputeValueLogRoot tight failed: %v", err)
	}
	tightRaw := wire.FormatValuesResponse(4, [][32]byte{compHash}, tightIndices)
	if _, err := VerifyValuesResponse(tightRaw, tightRoot, 50, 57); err != nil {
		t.Fatalf("expected tight bound len(Indices) == before - from - Preceding to succeed, got: %v", err)
	}
}

func TestEncodeRFC3986Unreserved(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	if got := encodeRFC3986Unreserved(unreserved); got != unreserved {
		t.Fatalf("unreserved characters were modified:\n got:  %q\n want: %q", got, unreserved)
	}

	cases := []struct {
		in   string
		want string
	}{
		{"a+b", "a%2Bb"},
		{"~tilde~", "~tilde~"},
		{"pkg+v1~rc1/sub*key?x=1&y=2%z", "pkg%2Bv1~rc1%2Fsub%2Akey%3Fx%3D1%26y%3D2%25z"},
		{"space here", "space%20here"},
	}
	for _, tc := range cases {
		if got := encodeRFC3986Unreserved(tc.in); got != tc.want {
			t.Errorf("encodeRFC3986Unreserved(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	ctx := context.Background()
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, 64)
	specialKey := "pkg+v1.2_3-rc~final/mod"
	kh := sha256.Sum256([]byte(specialKey))
	res, err := idxer.IndexBatch(ctx, &ingest.MappedBatch{
		Count:         50,
		KeyMap:        map[[32]byte][]uint64{kh: {7, 42}},
		CanonicalKeys: map[[32]byte]string{kh: specialKey},
	}, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(t, 50)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	var capturedRawQueries []string
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRawQueries = append(capturedRawQueries, r.URL.RawQuery)
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	kr, err := cli.LookupKey(ctx, specialKey)
	if err != nil {
		t.Fatalf("LookupKey(%q) failed: %v", specialKey, err)
	}
	indices, err := collectValuesNewestFirst(ctx, kr.Keys[0])
	if err != nil {
		t.Fatalf("Values(%q) failed: %v", specialKey, err)
	}
	if !slices.Equal(indices, []uint64{42, 7}) {
		t.Fatalf("unexpected Values(%q) result: %v", specialKey, indices)
	}
	if len(capturedRawQueries) != 2 {
		t.Fatalf("expected 2 HTTP queries (/keys and /values), got %d", len(capturedRawQueries))
	}
	for _, rq := range capturedRawQueries {
		if !strings.Contains(rq, "pkg%2Bv1.2_3-rc~final%2Fmod") {
			t.Errorf("expected RFC 3986 unreserved encoding in RawQuery, got %q", rq)
		}
	}
}

func TestClient_TorchwoodPolicyWitnessQuorumAndRedirects(t *testing.T) {
	ctx := context.Background()

	genKey := func(name string) (note.Signer, note.Verifier, string) {
		sKey, vKey, err := note.GenerateKey(rand.Reader, name)
		if err != nil {
			t.Fatalf("note.GenerateKey(%s) failed: %v", name, err)
		}
		s, err := note.NewSigner(sKey)
		if err != nil {
			t.Fatalf("note.NewSigner(%s) failed: %v", name, err)
		}
		v, err := note.NewVerifier(vKey)
		if err != nil {
			t.Fatalf("note.NewVerifier(%s) failed: %v", name, err)
		}
		return s, v, vKey
	}

	genWitness := func(name string) (note.Signer, note.Verifier, string) {
		sKey, rawVKey, err := note.GenerateKey(rand.Reader, name)
		if err != nil {
			t.Fatalf("note.GenerateKey(%s) failed: %v", name, err)
		}
		cs, err := f_note.NewSignerForCosignatureV1(sKey)
		if err != nil {
			t.Fatalf("f_note.NewSignerForCosignatureV1(%s) failed: %v", name, err)
		}
		cosigVKey, err := f_note.VKeyToCosignatureV1(rawVKey)
		if err != nil {
			t.Fatalf("f_note.VKeyToCosignatureV1(%s) failed: %v", name, err)
		}
		cv, err := f_note.NewVerifier(cosigVKey)
		if err != nil {
			t.Fatalf("f_note.NewVerifier(%s) failed: %v", name, err)
		}
		return cs, cv, cosigVKey
	}

	outSigner, outVerifier, outVKey := genKey("example.com/output")
	w1Signer, w1Verifier, w1VKey := genWitness("witness1.example.com")
	w2Signer, w2Verifier, w2VKey := genWitness("witness2.example.com")
	_, w3Verifier, w3VKey := genWitness("witness3.example.com")

	// Build 2-of-3 witness policy both via WitnessPolicy helper and wire.ParsePolicy
	outWitnessPol, err := WitnessPolicy("example.com/output", outVerifier, []note.Verifier{w1Verifier, w2Verifier, w3Verifier}, 2)
	if err != nil {
		t.Fatalf("WitnessPolicy failed: %v", err)
	}

	policyText := fmt.Sprintf("log %s\nwitness w1 %s\nwitness w2 %s\nwitness w3 %s\ngroup g 2 w1 w2 w3\nquorum g\n",
		outVKey, w1VKey, w2VKey, w3VKey)
	parsedPol, err := wire.ParsePolicy([]byte(policyText))
	if err != nil {
		t.Fatalf("wire.ParsePolicy failed: %v", err)
	}

	// Build a valid /keys response signed by outSigner + witness cosigners
	mptMgr := mpt.NewMem()
	kTest := "com.google."
	vr := sha256.Sum256([]byte("vr-1"))
	mptRoot, err := mptMgr.CommitKeysWithVersion(map[string][32]byte{kTest: vr}, 50)
	if err != nil {
		t.Fatalf("CommitKeysWithVersion failed: %v", err)
	}
	mptProof, _, _, err := mptMgr.ProveKey([]byte(kTest))
	if err != nil {
		t.Fatalf("ProveKey failed: %v", err)
	}

	inHash := sha256.Sum256([]byte("in-root-50"))
	inCP := &log.Checkpoint{
		Origin: "example.com/input",
		Size:   50,
		Hash:   inHash[:],
	}

	rawOutLeaf := wire.FormatOutputLogLeafFull(mptRoot, 0, inCP)
	outRoot := wire.LeafHash(rawOutLeaf)
	outText := fmt.Sprintf("example.com/output\n1\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:]))

	buildKeysBody := func(signers ...note.Signer) []byte {
		outSigned, sErr := note.Sign(&note.Note{Text: outText}, signers...)
		if sErr != nil {
			t.Fatalf("note.Sign(output) failed: %v", sErr)
		}
		return wire.FormatKeysResponseFull(outSigned, 0, mptRoot, 0, inCP, nil, "inclusion", mptProof, []wire.KeyValueRoot{{Key: kTest, ValueRoot: vr}})
	}

	// 1. Only 1 witness signed -> fails 2-of-3 quorum with ErrVerificationFailed
	body1Witness := buildKeysBody(outSigner, w1Signer)
	if _, err := VerifyKeysResponse(body1Witness, kTest, false, Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outWitnessPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when 1-of-3 witnesses signed, got: %v", err)
	}

	// 2. 2 distinct witnesses signed -> passes both WitnessPolicy and torchwood.ParsePolicy
	body2Witnesses := buildKeysBody(outSigner, w1Signer, w2Signer)
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outWitnessPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}); err != nil {
		t.Fatalf("expected 2-of-3 WitnessPolicy to pass, got: %v", err)
	}
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         parsedPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}); err != nil {
		t.Fatalf("expected 2-of-3 torchwood.ParsePolicy to pass, got: %v", err)
	}

	// 3. Missing OutputLogPolicy, ExpectedOutputLogOrigin, or ExpectedInputLogOrigin rejected
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, Config{
		ExpectedOutputLogOrigin: "example.com/output",
		ExpectedInputLogOrigin:  "example.com/input",
	}); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when OutputLogPolicy is nil, got: %v", err)
	}
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, Config{
		OutputLogPolicy:        outWitnessPol,
		ExpectedInputLogOrigin: "example.com/input",
	}); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when ExpectedOutputLogOrigin is empty, got: %v", err)
	}
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outWitnessPol,
		ExpectedInputLogOrigin:  "wrong.example.com/input",
	}); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed on ExpectedInputLogOrigin mismatch, got: %v", err)
	}

	// 4. Invalid canonical query target rejected with ErrBadRequest
	if _, err := VerifyKeysResponse(body2Witnesses, "bad key with spaces", false, Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outWitnessPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on invalid target key, got: %v", err)
	}

	// 5. Client rejects 3xx HTTP redirects per tlog-vindex spec
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/keys?key=com.google.", http.StatusFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	redirectCli, err := New(ts.URL+"/redirect", Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outWitnessPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New redirectCli failed: %v", err)
	}
	if _, err := redirectCli.LookupKey(ctx, kTest); err == nil || !strings.Contains(err.Error(), "redirects (3xx) are forbidden") {
		t.Fatalf("expected LookupKey to reject 3xx redirect, got: %v", err)
	}
}

func TestClient_DependencyBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{range .Imports}}{{.}}\n{{end}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, string(out))
	}
	allowedExternal := map[string]bool{
		"golang.org/x/mod/sumdb/note":                                true,
		"github.com/transparency-dev/merkle/proof":                   true,
		"github.com/transparency-dev/merkle/rfc6962":                 true,
		"github.com/transparency-dev/incubator/vindex/internal/mpt":  true,
		"github.com/transparency-dev/incubator/vindex/internal/wire": true,
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if imp == "" || !strings.Contains(imp, ".") {
			continue // stdlib package
		}
		if !allowedExternal[imp] {
			t.Errorf("forbidden direct import in vindex/client: %q", imp)
		}
	}
}

func BenchmarkClient_VerifyKeysAndValues(b *testing.B) {
	ctx := context.Background()
	srv, _, _, pub, idxer, keys := setupTestEnvironment(b, 64)

	kApex := "com.google."
	kMail := "com.google.mail."
	kDocs := "com.google.docs."
	kWild := "com.google.*."

	khApex := sha256.Sum256([]byte(kApex))
	khMail := sha256.Sum256([]byte(kMail))
	khDocs := sha256.Sum256([]byte(kDocs))
	khWild := sha256.Sum256([]byte(kWild))

	var mailIndices []uint64
	for i := uint64(0); i < 128; i++ {
		mailIndices = append(mailIndices, i*10+1)
	}

	batch := &ingest.MappedBatch{
		Count: 2000,
		KeyMap: map[[32]byte][]uint64{
			khApex: {1, 10},
			khMail: mailIndices,
			khDocs: {3},
			khWild: {4, 40},
		},
		CanonicalKeys: map[[32]byte]string{
			khApex: kApex,
			khMail: kMail,
			khDocs: kDocs,
			khWild: kWild,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		b.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(b, 2000)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		b.Fatalf("PublishKeyBatch failed: %v", err)
	}

	wPoint := httptest.NewRecorder()
	srv.HandleKeys(wPoint, httptest.NewRequest(http.MethodGet, "/keys?key=com.google.mail.", nil))
	pointBytes := wPoint.Body.Bytes()

	wPrefix := httptest.NewRecorder()
	srv.HandleKeys(wPrefix, httptest.NewRequest(http.MethodGet, "/keys?prefix=com.google.", nil))
	prefixBytes := wPrefix.Body.Bytes()

	wValues := httptest.NewRecorder()
	srv.HandleValues(wValues, httptest.NewRequest(http.MethodGet, "/values?key=com.google.mail.&before=2000", nil))
	valuesBytes := wValues.Body.Bytes()

	cfg := keys.clientConfig(b)
	keysResp, err := VerifyKeysResponse(pointBytes, kMail, false, cfg)
	if err != nil {
		b.Fatalf("VerifyKeysResponse failed: %v", err)
	}
	mailValueRoot := keysResp.Keys[0].ValueRoot

	b.Run("VerifyKeysResponse_Point", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyKeysResponse(pointBytes, kMail, false, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("VerifyKeysResponse_Prefix4Keys", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyKeysResponse(prefixBytes, kApex, true, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("VerifyValuesResponse_ZeroMPTContinuation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyValuesResponse(valuesBytes, mailValueRoot, keysResp.From, 2000); err != nil {
				b.Fatal(err)
			}
		}
	})
}
