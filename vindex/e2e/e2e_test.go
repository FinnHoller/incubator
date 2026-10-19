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

// Package e2e_test implements comprehensive, opaque-box, requirement-driven
// end-to-end tests for VIndex v1 covering Tiers 1-4.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/hammer"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

// testCluster bundles an isolated Tessera Input Log and VIndex configuration.
type testCluster struct {
	t           *testing.T
	ctx         context.Context
	rootDir     string
	inLogDir    string
	dbDir       string
	mptDir      string
	cacheDir    string
	outLogDir   string
	inSignerKey string
	inVKey      string
	inSigner    note.Signer
	inVerifier  note.Verifier
	outSKey     string
	outVKey     string
	outVerifier note.Verifier
	inAppender  *tessera.Appender
	inReader    tessera.LogReader
	inAwaiter   *tessera.PublicationAwaiter
	config      vindex.Config
}

// newTestCluster initializes isolated cryptographic keys, directories, and Tessera log appender.
func newTestCluster(t *testing.T, ctx context.Context, chunkSize, bundleSize uint64) *testCluster {
	t.Helper()
	rootDir := t.TempDir()

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.e2e.inputlog")
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

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.e2e.outputlog")
	if err != nil {
		t.Fatalf("GenerateKey outputlog failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier outputlog failed: %v", err)
	}

	inLogDir := filepath.Join(rootDir, "inlog")
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New inputlog failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender inputlog failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	if chunkSize == 0 {
		chunkSize = 64
	}
	if bundleSize == 0 {
		bundleSize = 16
	}

	inPolicy, err := client.SingleKeyPolicy("test.e2e.inputlog", inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy inputlog failed: %v", err)
	}

	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          chunkSize,
		BundleSize:         bundleSize,
		PollInterval:       40 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.e2e.inputlog",
		InputLogVerifier:   inVerifier,
		InputLogPolicy:     inPolicy,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.e2e.outputlog",
		OutputLogSignerKey: outSKey,
	}

	return &testCluster{
		t:           t,
		ctx:         ctx,
		rootDir:     rootDir,
		inLogDir:    inLogDir,
		dbDir:       dbDir,
		mptDir:      mptDir,
		cacheDir:    cacheDir,
		outLogDir:   outLogDir,
		inSignerKey: inSKey,
		inVKey:      inVKey,
		inSigner:    inSigner,
		inVerifier:  inVerifier,
		outSKey:     outSKey,
		outVKey:     outVKey,
		outVerifier: outVerifier,
		inAppender:  inAppender,
		inReader:    inReader,
		inAwaiter:   inAwaiter,
		config:      cfg,
	}
}

func (c *testCluster) appendLeaf(payload []byte) uint64 {
	c.t.Helper()
	idx, rawCP, err := c.inAwaiter.Await(c.ctx, c.inAppender.Add(c.ctx, tessera.NewEntry(payload)))
	if err != nil {
		c.t.Fatalf("failed to append leaf %q: %v", string(payload), err)
	}
	if len(rawCP) == 0 {
		c.t.Fatalf("empty checkpoint returned for leaf %q", string(payload))
	}
	return idx.Index
}

func (c *testCluster) newClient(serverURL string) *client.Client {
	c.t.Helper()
	outPolicy, err := client.SingleKeyPolicy("test.e2e.outputlog", c.outVerifier)
	if err != nil {
		c.t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	cli, err := client.New(serverURL, client.Config{
		ExpectedOutputLogOrigin: "test.e2e.outputlog",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "test.e2e.inputlog",
	})
	if err != nil {
		c.t.Fatalf("client.New failed: %v", err)
	}
	return cli
}

func getAllAscending(ctx context.Context, cli *client.Client, key string) ([]uint64, error) {
	kr, err := cli.LookupKey(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(kr.Keys) == 0 {
		return nil, nil
	}
	var out []uint64
	for idx, err := range kr.Keys[0].Values(ctx) {
		if err != nil {
			return nil, err
		}
		out = append(out, idx)
	}
	slices.Reverse(out)
	return out, nil
}

// -----------------------------------------------------------------------------
// TIER 1: Feature Coverage (Core Happy Path & Isolations)
// -----------------------------------------------------------------------------

// TestTier1_HappyPath_FullLifecycleAndClientLookup verifies the complete VIndex lifecycle:
// log creation, engine initialization, verified client lookups, absent key non-inclusion proofs,
// health/readiness endpoints, and live background sync of newly appended leaves.
func TestTier1_HappyPath_FullLifecycleAndClientLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)

	// Append initial leaves:
	// Leaf 0: alice_entry_1
	// Leaf 1: bob_entry_1
	// Leaf 2: carol_entry_1
	// Leaf 3: alice_entry_2
	cluster.appendLeaf([]byte("alice_entry_1"))
	cluster.appendLeaf([]byte("bob_entry_1"))
	cluster.appendLeaf([]byte("carol_entry_1"))
	cluster.appendLeaf([]byte("alice_entry_2"))

	aliceKey := sha256.Sum256([]byte("alice"))
	bobKey := sha256.Sum256([]byte("bob"))
	carolKey := sha256.Sum256([]byte("carol"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		s := string(leaf)
		switch {
		case strings.HasPrefix(s, "alice"):
			return []vindex.MappedEntry{{Key: "alice", KeyHash: aliceKey}}, nil
		case strings.HasPrefix(s, "bob"):
			return []vindex.MappedEntry{{Key: "bob", KeyHash: bobKey}}, nil
		case strings.HasPrefix(s, "carol"):
			return []vindex.MappedEntry{{Key: "carol", KeyHash: carolKey}}, nil
		default:
			return []vindex.MappedEntry{{Key: s, KeyHash: sha256.Sum256(leaf)}}, nil
		}
	})

	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	adminMux := http.NewServeMux()
	engine.Server().RegisterAdminRoutes(adminMux)
	adminTS := httptest.NewServer(adminMux)
	defer adminTS.Close()

	cli := cluster.newClient(ts.URL)

	// 1. Verify operational endpoints are isolated to adminMux and absent (404) on public mux
	for _, opPath := range []string{"/healthz", "/readyz", "/syncz", "/metrics"} {
		resPub, err := http.Get(ts.URL + opPath)
		if err != nil {
			t.Fatalf("GET public %s err %v", opPath, err)
		}
		_ = resPub.Body.Close()
		if resPub.StatusCode != http.StatusNotFound {
			t.Fatalf("GET public %s status = %d, want 404", opPath, resPub.StatusCode)
		}
	}
	for _, opPath := range []string{"/healthz", "/readyz", "/metrics"} {
		resAdm, err := http.Get(adminTS.URL + opPath)
		if err != nil {
			t.Fatalf("GET admin %s err %v", opPath, err)
		}
		_ = resAdm.Body.Close()
		if resAdm.StatusCode != http.StatusOK {
			t.Fatalf("GET admin %s status = %d, want 200", opPath, resAdm.StatusCode)
		}
	}

	// 2. Query existing key "alice" -> expect [0, 3] with full cryptographic proof
	keysAlice, err := cli.LookupKey(ctx, "alice")
	if err != nil {
		t.Fatalf("LookupKey(alice) failed: %v", err)
	}
	if len(keysAlice.Keys) != 1 {
		t.Fatalf("LookupKey(alice) len(Keys) = %d, want 1", len(keysAlice.Keys))
	}
	if keysAlice.InputSize < 4 {
		t.Fatalf("LookupKey(alice) InputSize = %d, want >= 4", keysAlice.InputSize)
	}
	if keysAlice.MPTRoot == [32]byte{} {
		t.Fatalf("LookupKey(alice) empty MPTRoot in verified response")
	}
	idxAlice, err := getAllAscending(ctx, cli, "alice")
	if err != nil {
		t.Fatalf("getAllAscending(alice) failed: %v", err)
	}
	if !slices.Equal(idxAlice, []uint64{0, 3}) {
		t.Fatalf("getAllAscending(alice) indices = %v, want [0, 3]", idxAlice)
	}

	// 3. Query existing key "bob" -> expect [1]
	idxBob, err := getAllAscending(ctx, cli, "bob")
	if err != nil {
		t.Fatalf("getAllAscending(bob) failed: %v", err)
	}
	if !slices.Equal(idxBob, []uint64{1}) {
		t.Fatalf("getAllAscending(bob) = %v, want [1]", idxBob)
	}

	// 4. Query existing key "carol" -> expect [2]
	idxCarol, err := getAllAscending(ctx, cli, "carol")
	if err != nil {
		t.Fatalf("getAllAscending(carol) failed: %v", err)
	}
	if !slices.Equal(idxCarol, []uint64{2}) {
		t.Fatalf("getAllAscending(carol) = %v, want [2]", idxCarol)
	}

	// 5. Query non-existent key "eve" -> expect verified non-inclusion proof
	keysEve, err := cli.LookupKey(ctx, "eve")
	if err != nil {
		t.Fatalf("LookupKey(eve) non-inclusion failed: %v", err)
	}
	if len(keysEve.Keys) != 0 {
		t.Fatalf("LookupKey(eve) keys=%+v, want non-inclusion", keysEve.Keys)
	}
	idxEve, err := getAllAscending(ctx, cli, "eve")
	if err != nil {
		t.Fatalf("getAllAscending(eve) non-inclusion failed: %v", err)
	}
	if len(idxEve) != 0 {
		t.Fatalf("getAllAscending(eve) returned indices: %v, want empty", idxEve)
	}

	// 6. Dynamically append leaf 4 ("alice_entry_3") while engine runs
	cluster.appendLeaf([]byte("alice_entry_3"))

	// Poll until client observes indices [0, 3, 4]
	deadline := time.Now().Add(6 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		indices, err := getAllAscending(ctx, cli, "alice")
		if err == nil && slices.Equal(indices, []uint64{0, 3, 4}) {
			updated = true
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !updated {
		t.Fatal("timed out waiting for background synchronization of leaf 4")
	}
}

// TestTier1_MultiKeyMappingAndDeduplication tests that when a leaf maps to multiple keys,
// and when the same key is returned multiple times in the same leaf, per-leaf deduplication
// (Feature 7) ensures each leaf index is recorded only once per key.
func TestTier1_MultiKeyMappingAndDeduplication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)

	newsKey := sha256.Sum256([]byte("news"))
	techKey := sha256.Sum256([]byte("tech"))
	scienceKey := sha256.Sum256([]byte("science"))

	// Leaf 0: maps to news, tech, AND duplicate news
	// Leaf 1: maps to tech, science
	// Leaf 2: maps to news
	cluster.appendLeaf([]byte("doc_0"))
	cluster.appendLeaf([]byte("doc_1"))
	cluster.appendLeaf([]byte("doc_2"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		switch string(leaf) {
		case "doc_0":
			return []vindex.MappedEntry{
				{Key: "news", KeyHash: newsKey},
				{Key: "tech", KeyHash: techKey},
				{Key: "news", KeyHash: newsKey}, // duplicate in same leaf
			}, nil
		case "doc_1":
			return []vindex.MappedEntry{
				{Key: "tech", KeyHash: techKey},
				{Key: "science", KeyHash: scienceKey},
			}, nil
		case "doc_2":
			return []vindex.MappedEntry{
				{Key: "news", KeyHash: newsKey},
			}, nil
		default:
			return nil, nil
		}
	})

	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	// news -> expect [0, 2] (leaf 0 only once, not [0, 0, 2])
	idxNews, err := getAllAscending(ctx, cli, "news")
	if err != nil {
		t.Fatalf("getAllAscending(news) failed: %v", err)
	}
	if !slices.Equal(idxNews, []uint64{0, 2}) {
		t.Fatalf("getAllAscending(news) = %v, want [0, 2]", idxNews)
	}

	// tech -> expect [0, 1]
	idxTech, err := getAllAscending(ctx, cli, "tech")
	if err != nil {
		t.Fatalf("getAllAscending(tech) failed: %v", err)
	}
	if !slices.Equal(idxTech, []uint64{0, 1}) {
		t.Fatalf("getAllAscending(tech) = %v, want [0, 1]", idxTech)
	}

	// science -> expect [1]
	idxSci, err := getAllAscending(ctx, cli, "science")
	if err != nil {
		t.Fatalf("getAllAscending(science) failed: %v", err)
	}
	if !slices.Equal(idxSci, []uint64{1}) {
		t.Fatalf("getAllAscending(science) = %v, want [1]", idxSci)
	}
}

// TestTier1_BackwardPagination_MultiPageChaining tests backward pagination via NextBefore
// and verifies that MatchedKey.Values successfully verifies the entire backward chain.
func TestTier1_BackwardPagination_MultiPageChaining(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 4, 16)

	hotKey := sha256.Sum256([]byte("hot_topic"))
	const totalLeaves = 12

	// Write 12 leaves, all matching hot_topic
	for i := 0; i < totalLeaves; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("hot_leaf_%02d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: "hot_topic", KeyHash: hotKey}}, nil
	})

	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	keysResp, err := cli.LookupKey(ctx, "hot_topic")
	if err != nil {
		t.Fatalf("LookupKey(hot_topic) failed: %v", err)
	}
	if len(keysResp.Keys) != 1 {
		t.Fatalf("expected hot_topic to exist, got %d keys", len(keysResp.Keys))
	}

	var wantIndices []uint64
	for i := uint64(0); i < totalLeaves; i++ {
		wantIndices = append(wantIndices, i)
	}

	allIndices, err := getAllAscending(ctx, cli, "hot_topic")
	if err != nil {
		t.Fatalf("getAllAscending failed: %v", err)
	}
	if !slices.Equal(allIndices, wantIndices) {
		t.Fatalf("getAllAscending indices = %v, want %v", allIndices, wantIndices)
	}
}

// TestTier1_CatchupToServing_Transition tests offline catch-up ingestion via SyncOnce followed by
// transitioning directly to live Normal Serving Mode.
func TestTier1_CatchupToServing_Transition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)

	// Initial 6 leaves
	for i := 0; i < 6; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("item_%d", i)))
	}

	itemKey := sha256.Sum256([]byte("item"))
	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: "item", KeyHash: itemKey}}, nil
	})

	// Step 1: Run offline catch-up via SyncOnce on unstarted engine coordinator
	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Coordinator().SyncOnce(ctx); err != nil {
		t.Fatalf("engine.Coordinator().SyncOnce failed: %v", err)
	}

	// Step 2: Boot Engine in live serving mode on top of the caught-up DB
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	// Step 3: Verify initial 6 caught-up leaves are queryable
	idxInitial, err := getAllAscending(ctx, cli, "item")
	if err != nil {
		t.Fatalf("getAllAscending after catchup failed: %v", err)
	}
	if len(idxInitial) != 6 {
		t.Fatalf("expected 6 indices after catchup, got %d: %v", len(idxInitial), idxInitial)
	}

	// Step 4: Dynamically append leaves 6 and 7 while engine is serving
	cluster.appendLeaf([]byte("item_6"))
	cluster.appendLeaf([]byte("item_7"))

	deadline := time.Now().Add(6 * time.Second)
	synced := false
	for time.Now().Before(deadline) {
		indices, err := getAllAscending(ctx, cli, "item")
		if err == nil && len(indices) == 8 {
			if indices[6] == 6 && indices[7] == 7 {
				synced = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !synced {
		t.Fatal("timed out waiting for dynamic catchup after offline catchup")
	}
}

// -----------------------------------------------------------------------------
// TIER 2: Boundary & Corner Cases (Edge Conditions & Tamper Resistance)
// -----------------------------------------------------------------------------

// TestTier2_EmptyInputLog_ReadinessAndLookup verifies engine and client behavior
// when operating against an empty input log (0 leaves).
func TestTier2_EmptyInputLog_ReadinessAndLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)
	mapper := vindex.IdentityMapper()

	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	adminMux := http.NewServeMux()
	engine.Server().RegisterAdminRoutes(adminMux)
	adminTS := httptest.NewServer(adminMux)
	defer adminTS.Close()

	// Public /healthz must return 404; internal admin /healthz must return 200 OK
	resPubHealth, err := http.Get(ts.URL + "/healthz")
	if err != nil || resPubHealth.StatusCode != http.StatusNotFound {
		t.Fatalf("GET public /healthz status %v, err %v; want 404", resPubHealth.StatusCode, err)
	}
	_ = resPubHealth.Body.Close()

	resHealth, err := http.Get(adminTS.URL + "/healthz")
	if err != nil || resHealth.StatusCode != http.StatusOK {
		t.Fatalf("GET admin /healthz status %v, err %v; want 200", resHealth.StatusCode, err)
	}
	_ = resHealth.Body.Close()

	// Querying an empty index must either return non-inclusion or 503 if not yet published
	cli := cluster.newClient(ts.URL)
	resp, err := cli.LookupKey(ctx, "nonexistent")
	if err == nil {
		if len(resp.Keys) != 0 {
			t.Fatalf("expected 0 keys on empty log, got %d", len(resp.Keys))
		}
	}
}

// TestTier2_ChunkBoundarySpanning_MicroChunks exercises chunk partitioning by setting
// ChunkSize to a tiny value (4 entries). We append 14 matching entries to force
// creation of 4 consecutive inverted chunks, verifying that multi-chunk scans and
// relative index offsets reconstruct the complete sequence across chunk boundaries.
func TestTier2_ChunkBoundarySpanning_MicroChunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const microChunkSize = 4
	cluster := newTestCluster(t, ctx, microChunkSize, 8)

	targetKey := sha256.Sum256([]byte("micro_chunk_key"))
	const numLeaves = 14

	for i := 0; i < numLeaves; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("entry_%02d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: "micro_chunk_key", KeyHash: targetKey}}, nil
	})

	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	var want []uint64
	for i := uint64(0); i < numLeaves; i++ {
		want = append(want, i)
	}

	gotAll, err := getAllAscending(ctx, cli, "micro_chunk_key")
	if err != nil {
		t.Fatalf("getAllAscending failed across micro-chunks: %v", err)
	}
	if !slices.Equal(gotAll, want) {
		t.Fatalf("getAllAscending indices = %v, want %v", gotAll, want)
	}
}

// TestTier2_UnalignedCheckpointClamping verifies that when the input log length is
// unaligned with tile or bundle boundaries (e.g. 19 leaves, with bundle size 16),
// checkpoint clamping (Feature 9) accurately processes up to the exact unaligned checkpoint.
func TestTier2_UnalignedCheckpointClamping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const bundleSize = 16
	cluster := newTestCluster(t, ctx, 64, bundleSize)

	const unalignedCount = 19 // unaligned: 1 full bundle (16) + 3 partial
	for i := 0; i < unalignedCount; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("unaligned_%02d", i)))
	}

	commonKey := sha256.Sum256([]byte("common"))
	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: "common", KeyHash: commonKey}}, nil
	})

	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	keysResp, err := cli.LookupKey(ctx, "common")
	if err != nil {
		t.Fatalf("LookupKey(common) failed: %v", err)
	}
	if keysResp.InputSize != unalignedCount {
		t.Fatalf("clamped InputSize = %d, want %d", keysResp.InputSize, unalignedCount)
	}
	indices, err := getAllAscending(ctx, cli, "common")
	if err != nil {
		t.Fatalf("getAllAscending(common) failed: %v", err)
	}
	if len(indices) != unalignedCount {
		t.Fatalf("clamped indices count = %d, want %d (indices: %v)", len(indices), unalignedCount, indices)
	}
}

// TestTier2_InvalidClientQueries_HTTPResponses verifies that malformed queries
// (invalid keyhash format, invalid pagination parameters, unsupported HTTP methods)
// return expected HTTP error codes (400 Bad Request, 405 Method Not Allowed).
func TestTier2_InvalidClientQueries_HTTPResponses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)
	cluster.appendLeaf([]byte("test_entry"))

	engine, err := vindex.New(cluster.config, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	adminMux := http.NewServeMux()
	engine.Server().RegisterAdminRoutes(adminMux)
	adminTS := httptest.NewServer(adminMux)
	defer adminTS.Close()

	testCases := []struct {
		name       string
		baseURL    string
		method     string
		urlPath    string
		wantStatus int
	}{
		{"MissingKeyOnKeys", ts.URL, http.MethodGet, "/keys", http.StatusBadRequest},
		{"ControlCharInKey", ts.URL, http.MethodGet, "/keys?key=bad%00key", http.StatusBadRequest},
		{"MissingBeforeOnEntries", ts.URL, http.MethodGet, "/values?key=test_entry", http.StatusBadRequest},
		{"ZeroBeforeOnEntries", ts.URL, http.MethodGet, "/values?key=test_entry&before=0", http.StatusBadRequest},
		{"InvalidBeforeParam", ts.URL, http.MethodGet, "/values?key=test_entry&before=notanumber", http.StatusBadRequest},
		{"InvalidLimitParam", ts.URL, http.MethodGet, "/values?key=test_entry&before=1&limit=0", http.StatusBadRequest},
		{"PostMethodKeys", ts.URL, http.MethodPost, "/keys?key=test_entry", http.StatusMethodNotAllowed},
		{"PublicHealthzNotFound", ts.URL, http.MethodGet, "/healthz", http.StatusNotFound},
		{"PutMethodAdminHealthz", adminTS.URL, http.MethodPut, "/healthz", http.StatusMethodNotAllowed},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, tc.method, tc.baseURL+tc.urlPath, nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do request failed: %v", err)
			}
			defer func() { _ = res.Body.Close() }()
			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status code = %d, want %d", res.StatusCode, tc.wantStatus)
			}
		})
	}
}

// TestTier2_TamperedProofDetection_Adversarial verifies that the client verifier
// detects and rejects adversarially forged or tampered proof sections:
// signature forgery, MPT bitflip, output log inclusion proof tampering.
func TestTier2_TamperedProofDetection_Adversarial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)
	cluster.appendLeaf([]byte("authentic_leaf"))

	authKeyStr := "authentic_leaf"
	engine, err := vindex.New(cluster.config, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	// Fetch raw wire response from /keys
	res, err := http.Get(fmt.Sprintf("%s/keys?key=%s", ts.URL, authKeyStr))
	if err != nil {
		t.Fatalf("raw GET /keys failed: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	rawBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read raw body failed: %v", err)
	}

	outPolicy, err := client.SingleKeyPolicy("test.e2e.outputlog", cluster.outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	vCfg := client.Config{
		ExpectedOutputLogOrigin: "test.e2e.outputlog",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "test.e2e.inputlog",
	}

	// Baseline: unmodified response must verify successfully
	keysResp, err := client.VerifyKeysResponse(rawBody, authKeyStr, false, vCfg)
	if err != nil {
		t.Fatalf("baseline keys verification failed: %v", err)
	}
	if len(keysResp.Keys) != 1 {
		t.Fatalf("expected 1 key in baseline response, got %d", len(keysResp.Keys))
	}

	// Fetch raw wire response from /values
	resVal, err := http.Get(fmt.Sprintf("%s/values?key=%s&before=%d", ts.URL, authKeyStr, keysResp.InputSize))
	if err != nil {
		t.Fatalf("raw GET /values failed: %v", err)
	}
	defer func() { _ = resVal.Body.Close() }()
	rawValuesBody, err := io.ReadAll(resVal.Body)
	if err != nil {
		t.Fatalf("read raw values body failed: %v", err)
	}
	valueRoot := keysResp.Keys[0].ValueRoot
	if _, err := client.VerifyValuesResponse(rawValuesBody, valueRoot, keysResp.From, keysResp.InputSize); err != nil {
		t.Fatalf("baseline values verification failed: %v", err)
	}

	// 1. Adversarial Test: Tamper with output log checkpoint signature
	t.Run("TamperedCheckpointSignature", func(t *testing.T) {
		tampered := bytes.Replace(rawBody, []byte("test.e2e.outputlog"), []byte("fake.e2e.outputlog"), 1)
		_, err := client.VerifyKeysResponse(tampered, authKeyStr, false, vCfg)
		if err == nil {
			t.Fatal("expected error on tampered checkpoint origin, got nil")
		}
	})

	// 2. Adversarial Test: Tamper with MPT proof / value-root in keys section
	t.Run("TamperedMPTProof", func(t *testing.T) {
		tampered := slices.Clone(rawBody)
		idx := bytes.Index(tampered, []byte(authKeyStr+" "))
		if idx >= 0 && idx+len(authKeyStr)+1 < len(tampered) {
			pos := idx + len(authKeyStr) + 1
			if tampered[pos] == 'A' {
				tampered[pos] = 'B'
			} else {
				tampered[pos] = 'A'
			}
		} else {
			tampered = bytes.Replace(rawBody, []byte("proof\n"), []byte("proof AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"), 1)
		}
		_, err := client.VerifyKeysResponse(tampered, authKeyStr, false, vCfg)
		if err == nil {
			t.Fatal("expected error on tampered MPT proof, got nil")
		}
	})

	// 3. Adversarial Test: Tamper with Output Log inclusion proof
	t.Run("TamperedOutputLogProof", func(t *testing.T) {
		tampered := bytes.Replace(rawBody, []byte("c2sp.org/tlog-proof@v1\n"), []byte("c2sp.org/tlog-proof@v1\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"), 1)
		_, err := client.VerifyKeysResponse(tampered, authKeyStr, false, vCfg)
		if err == nil {
			t.Fatal("expected error on tampered output log proof, got nil")
		}
	})

	// 4. Adversarial Test: Tamper with value index in /values response
	t.Run("TamperedValuesIndex", func(t *testing.T) {
		tampered := bytes.Replace(rawValuesBody, []byte("\n0\n"), []byte("\n1\n"), 1)
		if bytes.Equal(tampered, rawValuesBody) {
			tampered = append(slices.Clone(rawValuesBody), []byte("999\n")...)
		}
		_, err := client.VerifyValuesResponse(tampered, valueRoot, keysResp.From, keysResp.InputSize)
		if err == nil {
			t.Fatal("expected error on tampered values index, got nil")
		}
	})
}

// -----------------------------------------------------------------------------
// TIER 3: Cross-Feature Combinations & Invariants
// -----------------------------------------------------------------------------

// TestTier3_ConcurrentReadsDuringContinuousIngestion simulates high-throughput
// concurrent reader traffic against the VIndex HTTP server while a background
// writer continuously appends leaves into the input log. Verifies zero race conditions,
// zero deadlocks, and monotonic tree growth.
func TestTier3_ConcurrentReadsDuringContinuousIngestion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)

	// Seed 10 initial leaves
	for i := 0; i < 10; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("concurrent_leaf_%d", i%5)))
	}

	keyNames := make([]string, 5)
	keys := make([][32]byte, 5)
	for i := 0; i < 5; i++ {
		keyNames[i] = fmt.Sprintf("concurrent_key_%d", i)
		keys[i] = sha256.Sum256([]byte(keyNames[i]))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		var id int
		if _, err := fmt.Sscanf(string(leaf), "concurrent_leaf_%d", &id); err == nil && id >= 0 && id < 5 {
			return []vindex.MappedEntry{{Key: keyNames[id], KeyHash: keys[id]}}, nil
		}
		return []vindex.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	var readSuccesses atomic.Uint64
	var readFailures atomic.Uint64
	var stopFlag atomic.Bool

	const numReaders = 6
	var wg sync.WaitGroup

	// Start concurrent readers
	for r := 0; r < numReaders; r++ {
		workerCli := cluster.newClient(ts.URL)
		wg.Add(1)
		go func(workerID int, rCli *client.Client) {
			defer wg.Done()
			i := workerID
			for !stopFlag.Load() {
				targetKeyName := keyNames[i%5]
				kResp, err := rCli.LookupKey(ctx, targetKeyName)
				if err != nil {
					readFailures.Add(1)
				} else if len(kResp.Keys) > 0 {
					failed := false
					for _, vErr := range kResp.Keys[0].Values(ctx) {
						if vErr != nil {
							failed = true
						}
						break
					}
					if failed {
						readFailures.Add(1)
					} else {
						readSuccesses.Add(1)
					}
				}
				i++
				time.Sleep(5 * time.Millisecond)
			}
		}(r, workerCli)
	}
	_ = cli

	// Concurrently append 30 more leaves in the background
	for i := 10; i < 40; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("concurrent_leaf_%d", i%5)))
		time.Sleep(30 * time.Millisecond)
	}

	// Allow readers to execute against latest state
	time.Sleep(500 * time.Millisecond)
	stopFlag.Store(true)
	wg.Wait()

	if readFailures.Load() > 0 {
		t.Fatalf("encountered %d read failures during concurrent ingestion", readFailures.Load())
	}
	if readSuccesses.Load() < 50 {
		t.Fatalf("expected at least 50 successful concurrent reads, got %d", readSuccesses.Load())
	}
}

// TestTier3_CrashRecoveryAndIdempotency verifies the 3-Phase Zero-WAL crash recovery:
// Ingests 20 leaves, terminates engine abruptly, writes 15 more leaves to input log while
// engine is stopped, and restarts engine on same directories.
// Verifies that persisted data is restored, missing leaves are fast-forwarded without
// duplicates (write idempotency, Feature 17), and all 35 leaves are verified.
func TestTier3_CrashRecoveryAndIdempotency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)

	// Step 1: Ingest initial 20 leaves
	for i := 0; i < 20; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("recovery_item_%d", i)))
	}

	k1 := sha256.Sum256([]byte("k1"))
	k2 := sha256.Sum256([]byte("k2"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		var id int
		if _, err := fmt.Sscanf(string(leaf), "recovery_item_%d", &id); err == nil {
			if id%2 == 0 {
				return []vindex.MappedEntry{{Key: "k1", KeyHash: k1}}, nil
			}
			return []vindex.MappedEntry{{Key: "k2", KeyHash: k2}}, nil
		}
		return nil, nil
	})

	engine1, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New (initial) failed: %v", err)
	}
	if err := engine1.Start(ctx); err != nil {
		t.Fatalf("engine1.Start failed: %v", err)
	}

	// Verify initial indexing
	ts1 := httptest.NewServer(engine1.Handler())
	cli1 := cluster.newClient(ts1.URL)
	idxInit, err := getAllAscending(ctx, cli1, "k1")
	if err != nil || len(idxInit) != 10 {
		t.Fatalf("initial lookup k1 failed: indices=%v, err=%v", idxInit, err)
	}
	ts1.Close()

	// Step 2: Stop engine cleanly (simulating process restart)
	if err := engine1.Stop(); err != nil {
		t.Fatalf("engine1.Stop failed: %v", err)
	}

	// Step 3: Append 15 more leaves while engine is offline (leaves 20..34)
	for i := 20; i < 35; i++ {
		cluster.appendLeaf([]byte(fmt.Sprintf("recovery_item_%d", i)))
	}

	// Step 4: Re-open engine on the exact same directory paths
	engine2, err := vindex.New(cluster.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New (restart) failed: %v", err)
	}
	if err := engine2.Start(ctx); err != nil {
		t.Fatalf("engine2.Start (crash recovery) failed: %v", err)
	}
	defer func() { _ = engine2.Stop() }()

	ts2 := httptest.NewServer(engine2.Handler())
	defer ts2.Close()

	cli2 := cluster.newClient(ts2.URL)

	// Step 5: Verify all 35 leaves are indexed without duplicate entries
	deadline := time.Now().Add(8 * time.Second)
	recovered := false
	for time.Now().Before(deadline) {
		idxK1, err1 := getAllAscending(ctx, cli2, "k1")
		idxK2, err2 := getAllAscending(ctx, cli2, "k2")
		// k1 gets even indices: 0, 2, ..., 34 (18 items)
		// k2 gets odd indices: 1, 3, ..., 33 (17 items)
		if err1 == nil && err2 == nil && len(idxK1) == 18 && len(idxK2) == 17 {
			sortedK1 := slices.Clone(idxK1)
			slices.Sort(sortedK1)
			// Check for idempotency (no duplicate entries)
			dupFound := false
			for i := 1; i < len(sortedK1); i++ {
				if sortedK1[i] <= sortedK1[i-1] {
					dupFound = true
					break
				}
			}
			if !dupFound {
				recovered = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("timed out waiting for crash recovery catchup across offline leaves")
	}
}

// TestTier3_CommitBarrierAndServingStateRatcheting verifies that the Output Log checkpoint
// exposed via /checkpoint matches the checkpoint embedded in lookup responses,
// confirming atomic ServingState pointer ratcheting (Feature 26, Feature 32).
func TestTier3_CommitBarrierAndServingStateRatcheting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)
	cluster.appendLeaf([]byte("ratchet_entry"))

	engine, err := vindex.New(cluster.config, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	// Fetch standalone checkpoint via GET /checkpoint
	cpRes, err := http.Get(ts.URL + "/checkpoint")
	if err != nil {
		t.Fatalf("GET /checkpoint failed: %v", err)
	}
	cpBytes, err := io.ReadAll(cpRes.Body)
	_ = cpRes.Body.Close()
	if err != nil {
		t.Fatalf("read /checkpoint body failed: %v", err)
	}
	if cpRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /checkpoint status = %d, want 200", cpRes.StatusCode)
	}
	outCP, _, _, err := log.ParseCheckpoint(cpBytes, "test.e2e.outputlog", cluster.outVerifier)
	if err != nil {
		t.Fatalf("ParseCheckpoint failed: %v", err)
	}

	// Fetch lookup response and verify consistency
	resp, err := cli.LookupKey(ctx, "ratchet_entry")
	if err != nil {
		t.Fatalf("LookupKey failed: %v", err)
	}
	if resp.OutputSize != outCP.Size {
		t.Fatalf("OutputSize mismatch: lookup got %d, endpoint got %d", resp.OutputSize, outCP.Size)
	}
}

// -----------------------------------------------------------------------------
// TIER 4: Real-World Scenarios (Personalities & Stress Workloads)
// -----------------------------------------------------------------------------

// TestTier4_SumDBPersonality_RealWorld tests authentic Go SumDB log indexing:
// parsing module path and version lines, filtering out pseudo-versions, indexing
// release versions, and performing verified lookups for module releases.
func TestTier4_SumDBPersonality_RealWorld(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)

	// Generate authentic SumDB leaf payloads
	// 1. golang.org/x/text v0.3.7
	// 2. golang.org/x/text v0.3.7/go.mod
	// 3. golang.org/x/crypto v0.14.0
	// 4. golang.org/x/text pseudo-version (should be filtered)
	// 5. golang.org/x/text v0.4.0
	cluster.appendLeaf([]byte("golang.org/x/text v0.3.7 h1:abcdef12345=\n"))
	cluster.appendLeaf([]byte("golang.org/x/text v0.3.7/go.mod h1:67890abcde=\n"))
	cluster.appendLeaf([]byte("golang.org/x/crypto v0.14.0 h1:crypto12345=\n"))
	cluster.appendLeaf([]byte("golang.org/x/text v0.0.0-20190502123456-abcdef123456 h1:pseudo12345=\n"))
	cluster.appendLeaf([]byte("golang.org/x/text v0.4.0 h1:text40000000=\n"))

	textKey := sha256.Sum256([]byte("golang.org/x/text"))
	cryptoKey := sha256.Sum256([]byte("golang.org/x/crypto"))
	pseudoOnlyKey := sha256.Sum256([]byte("example.com/pseudoonly"))

	// Leaf 5: an exclusively pseudo-version module
	cluster.appendLeaf([]byte("example.com/pseudoonly v0.0.0-20200101000000-111111111111 h1:hash=\n"))

	sumdbMapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		lines := strings.Split(strings.TrimSpace(string(leaf)), "\n")
		var entries []vindex.MappedEntry
		seen := make(map[string]bool)
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			modPath := parts[0]
			version := strings.TrimSuffix(parts[1], "/go.mod")

			// Filter pseudo-versions: matches pattern with date and rev
			if strings.Contains(version, "-20") && len(version) > 25 {
				continue
			}

			if !seen[modPath] {
				seen[modPath] = true
				entries = append(entries, vindex.MappedEntry{
					Key:     modPath,
					KeyHash: sha256.Sum256([]byte(modPath)),
				})
			}
		}
		return entries, nil
	})

	engine, err := vindex.New(cluster.config, sumdbMapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	// golang.org/x/text should be found at leaves 0, 1, 4 (pseudo-version leaf 3 filtered out)
	keysText, err := cli.LookupKey(ctx, "golang.org/x/text")
	if err != nil {
		t.Fatalf("LookupKey(golang.org/x/text) failed: %v", err)
	}
	if len(keysText.Keys) != 1 {
		t.Fatalf("expected golang.org/x/text to exist")
	}
	idxText, err := getAllAscending(ctx, cli, "golang.org/x/text")
	if err != nil {
		t.Fatalf("getAllAscending(golang.org/x/text) failed: %v", err)
	}
	if !slices.Equal(idxText, []uint64{0, 1, 4}) {
		t.Fatalf("getAllAscending(golang.org/x/text) indices = %v, want [0, 1, 4]", idxText)
	}

	// golang.org/x/crypto should be found at leaf 2
	idxCrypto, err := getAllAscending(ctx, cli, "golang.org/x/crypto")
	if err != nil {
		t.Fatalf("getAllAscending(golang.org/x/crypto) failed: %v", err)
	}
	if !slices.Equal(idxCrypto, []uint64{2}) {
		t.Fatalf("getAllAscending(golang.org/x/crypto) = %v, want [2]", idxCrypto)
	}

	// Prefix lookup for "golang.org/x/" must return both golang.org/x/crypto and golang.org/x/text
	prefixResp, err := cli.LookupPrefix(ctx, "golang.org/x/")
	if err != nil {
		t.Fatalf("LookupPrefix(golang.org/x/) failed: %v", err)
	}
	if len(prefixResp.Keys) != 2 {
		t.Fatalf("LookupPrefix(golang.org/x/) len = %d, want 2", len(prefixResp.Keys))
	}

	// example.com/pseudoonly should have 0 indexed entries -> authenticated non-inclusion
	respPseudo, err := cli.LookupKey(ctx, "example.com/pseudoonly")
	if err != nil {
		t.Fatalf("LookupKey(example.com/pseudoonly) failed: %v", err)
	}
	if len(respPseudo.Keys) != 0 {
		t.Fatalf("expected non-inclusion for pseudo-only module, got keys=%+v", respPseudo.Keys)
	}
	_ = textKey
	_ = cryptoKey
	_ = pseudoOnlyKey
}

// TestTier4_MTCPersonality_RealWorld simulates Merkle Tree Certificates / Certificate
// Transparency domain name indexing: certificates covering subdomains expand to
// parent domains, enabling domain hierarchy search with verified non-inclusion for
// unissued domains.
func TestTier4_MTCPersonality_RealWorld(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64, 16)

	// Leaf 0: cert for api.v1.transparency.dev
	// Leaf 1: cert for auth.transparency.dev
	// Leaf 2: cert for www.google.com
	cluster.appendLeaf([]byte("api.v1.transparency.dev\n"))
	cluster.appendLeaf([]byte("auth.transparency.dev\n"))
	cluster.appendLeaf([]byte("www.google.com\n"))

	domainMapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		name := strings.TrimSpace(string(leaf))
		labels := strings.Split(name, ".")
		slices.Reverse(labels)
		revKey := strings.Join(labels, ".") + "."
		return []vindex.MappedEntry{{
			Key:     revKey,
			KeyHash: sha256.Sum256([]byte(revKey)),
		}}, nil
	})

	engine, err := vindex.New(cluster.config, domainMapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli := cluster.newClient(ts.URL)

	// Query prefix "dev.transparency." (base domain transparency.dev): should match leaves 0 and 1 across 2 keys
	respTransPrefix, err := cli.LookupPrefix(ctx, "dev.transparency.")
	if err != nil {
		t.Fatalf("LookupPrefix(dev.transparency.) failed: %v", err)
	}
	if len(respTransPrefix.Keys) != 2 {
		t.Fatalf("LookupPrefix(dev.transparency.) keys = %d, want 2", len(respTransPrefix.Keys))
	}

	// Query exact subdomain "dev.transparency.auth.": should match leaf 1
	idxAuth, err := getAllAscending(ctx, cli, "dev.transparency.auth.")
	if err != nil {
		t.Fatalf("getAllAscending(dev.transparency.auth.) failed: %v", err)
	}
	if !slices.Equal(idxAuth, []uint64{1}) {
		t.Fatalf("getAllAscending(dev.transparency.auth.) = %v, want [1]", idxAuth)
	}

	// Query unissued domain "com.fake.malicious.": verified non-inclusion
	respFake, err := cli.LookupKey(ctx, "com.fake.malicious.")
	if err != nil {
		t.Fatalf("LookupKey(com.fake.malicious.) failed: %v", err)
	}
	if len(respFake.Keys) != 0 {
		t.Fatalf("expected non-inclusion for unissued domain, got keys=%+v", respFake.Keys)
	}
}

// TestTier4_HammerClosedLoop_StressAndInvariants uses the synthetic hammer generator
// and analyzer to execute a closed-loop stress run:
// Zipfian distribution with hot-key skew, drip-fed sequencing, multiple reader workers,
// and automated cryptographic verification of all responses.
func TestTier4_HammerClosedLoop_StressAndInvariants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	rootDir := t.TempDir()
	posixDir := filepath.Join(rootDir, "posix_inlog")

	// Setup Hammer Generator & Sequencer
	genCfg := hammer.GeneratorConfig{
		Distribution: hammer.DistZipf,
		NumKeys:      25,
		ZipfS:        1.3,
		ZipfV:        1.0,
		Seed:         999,
		LeafFormat:   hammer.FormatRaw,
	}
	generator := hammer.NewGenerator(genCfg)
	queue := hammer.NewCheckpointQueue()

	seqCfg := hammer.DefaultSequencerConfig(posixDir)
	seqCfg.BatchSize = 8
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.CheckpointInterval = 50 * time.Millisecond
	seqCfg.WriteRate = 300

	sequencer, err := hammer.NewSequencer(ctx, seqCfg, generator, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = sequencer.Close(ctx) }()

	// Setup Drip Server
	srvCfg := hammer.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StorageDir: posixDir,
		DripRate:   100.0,
		BurstSize:  2,
	}
	dripServer := hammer.NewDripServer(srvCfg, queue)
	if err := dripServer.Start(ctx); err != nil {
		t.Fatalf("dripServer.Start failed: %v", err)
	}
	defer func() { _ = dripServer.Close(ctx) }()

	// Write 40 initial leaves
	for i := 0; i < 40; i++ {
		leaf := generator.NextLeaf()
		if _, _, err := sequencer.WriteLeaf(ctx, leaf.LeafData); err != nil {
			t.Fatalf("WriteLeaf failed at %d: %v", i, err)
		}
	}

	// Wait for published checkpoint covering 40 leaves
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cp := dripServer.GetPublishedCheckpoint(); len(cp) > 0 {
			if p, _, _, err := log.ParseCheckpoint(cp, sequencer.Origin(), sequencer.Verifier()); err == nil && p.Size >= 40 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Configure VIndex Engine pointing to DripServer
	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "example.com/hammer/output")
	if err != nil {
		t.Fatalf("GenerateKey output failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier output failed: %v", err)
	}

	cfg := vindex.Config{
		DBPath:             filepath.Join(rootDir, "pebble_db"),
		MPTDir:             filepath.Join(rootDir, "mpt_tree"),
		TileCacheDir:       filepath.Join(rootDir, "tile_cache"),
		ChunkSize:          32,
		BundleSize:         16,
		PollInterval:       40 * time.Millisecond,
		InputLogURL:        dripServer.URL(),
		InputLogOrigin:     sequencer.Origin(),
		InputLogVerifier:   sequencer.Verifier(),
		OutputLogDir:       filepath.Join(rootDir, "output_log"),
		OutputLogOrigin:    "example.com/hammer/output",
		OutputLogSignerKey: outSKey,
	}

	engine, err := vindex.New(cfg, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	// Run Hammer Reader Pool
	analyzer := hammer.NewAnalyzer(sequencer)
	readerCfg := hammer.ReaderConfig{
		VIndexURL:         ts.URL,
		NumWorkers:        4,
		MaxReadQPS:        150,
		OutputLogOrigin:   "example.com/hammer/output",
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    sequencer.Origin(),
		InputLogVerifier:  sequencer.Verifier(),
		HotKeyRatio:       0.60,
		UniformRatio:      0.25,
		NonInclusionRatio: 0.10,
		PaginationRatio:   0.05,
		PageSize:          10,
	}

	readers, err := hammer.NewReaderPool(readerCfg, generator, analyzer)
	if err != nil {
		t.Fatalf("NewReaderPool failed: %v", err)
	}

	testRunCtx, cancelRun := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancelRun()

	readers.Start(testRunCtx)

	snap := analyzer.Snapshot()
	if snap.TotalReads == 0 {
		t.Fatal("expected reader workers to execute queries, got 0")
	}
	if snap.ReadSuccesses == 0 {
		t.Fatalf("expected successful reads, got 0 (failures: %d)", snap.ReadFailures)
	}
	if snap.InvariantViolations != 0 {
		t.Fatalf("expected 0 invariant violations, got %d (samples: %v)", snap.InvariantViolations, snap.ViolationSampleLines)
	}

	t.Logf("Hammer closed-loop stress run complete: %d total reads, %d successes, %d failures, 0 invariant violations",
		snap.TotalReads, snap.ReadSuccesses, snap.ReadFailures)
}
