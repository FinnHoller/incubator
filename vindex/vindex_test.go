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

package vindex_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func TestVIndex_PublicAPI(t *testing.T) {
	cfg := vindex.DefaultConfig()
	if cfg.ChunkSize == 0 || cfg.BundleSize == 0 {
		t.Fatalf("invalid default config: %+v", cfg)
	}

	mapper := vindex.IdentityMapper()
	entries, err := mapper.MapLeaf(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Key != "hello" || entries[0].KeyHash != sha256.Sum256([]byte("hello")) {
		t.Fatalf("unexpected canonical entries: %+v", entries)
	}

	nonCanonical := []byte("hello world\x00")
	ncEntries, err := mapper.MapLeaf(context.Background(), nonCanonical)
	if err != nil {
		t.Fatalf("MapLeaf(nonCanonical) failed: %v", err)
	}
	wantDigest := sha256.Sum256(nonCanonical)
	wantHexKey := hex.EncodeToString(wantDigest[:])
	if len(ncEntries) != 1 || ncEntries[0].Key != wantHexKey || ncEntries[0].KeyHash != sha256.Sum256([]byte(wantHexKey)) {
		t.Fatalf("unexpected non-canonical entries: %+v", ncEntries)
	}

	fnMapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	})
	fnEntries, err := fnMapper.MapLeaf(context.Background(), []byte("world"))
	if err != nil {
		t.Fatalf("FuncMapper failed: %v", err)
	}
	if len(fnEntries) != 1 || fnEntries[0].Key != "world" || fnEntries[0].KeyHash != sha256.Sum256([]byte("world")) {
		t.Fatalf("unexpected fnEntries: %+v", fnEntries)
	}
}

func TestEngine_Lifecycle_EndToEndIngestionAndLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Generate cryptographic signers and verifiers for Input and Output logs
	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.inputlog")
	if err != nil {
		t.Fatalf("failed to generate input log key: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("failed to create input log signer: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("failed to create input log verifier: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.outputlog")
	if err != nil {
		t.Fatalf("failed to generate output log key: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("failed to create output log verifier: %v", err)
	}

	// 2. Setup isolated storage directories
	rootDir := t.TempDir()
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")
	inLogDir := filepath.Join(rootDir, "inlog")

	// 3. Create POSIX-backed Tessera Input Log
	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("failed to initialize input log storage: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create input log appender: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	// Append initial 3 leaves:
	// Leaf 0: "apple_alpha"
	// Leaf 1: "banana_beta"
	// Leaf 2: "apple_gamma"
	appendLeaf := func(payload []byte) uint64 {
		idx, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(payload)))
		if err != nil {
			t.Fatalf("failed to append leaf %q: %v", string(payload), err)
		}
		if len(rawCP) == 0 {
			t.Fatalf("empty checkpoint after appending leaf %q", string(payload))
		}
		return idx.Index
	}

	idx0 := appendLeaf([]byte("apple_alpha"))
	idx1 := appendLeaf([]byte("banana_beta"))
	idx2 := appendLeaf([]byte("apple_gamma"))
	if idx0 != 0 || idx1 != 1 || idx2 != 2 {
		t.Fatalf("unexpected indices: %d, %d, %d", idx0, idx1, idx2)
	}

	// 4. Configure VIndex Engine
	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          64,
		BundleSize:         16,
		PollInterval:       50 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.inputlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.outputlog",
		OutputLogSignerKey: outSKey,
		PrefixPolicy:       server.AllowAllPrefixPolicy,
	}

	// Custom mapper categorizing "apple" and "banana"
	appleHash := sha256.Sum256([]byte("apple"))
	bananaHash := sha256.Sum256([]byte("banana"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		if bytes.HasPrefix(leaf, []byte("apple")) {
			return []vindex.MappedEntry{{Key: "apple", KeyHash: appleHash}}, nil
		}
		if bytes.HasPrefix(leaf, []byte("banana")) {
			return []vindex.MappedEntry{{Key: "banana", KeyHash: bananaHash}}, nil
		}
		return []vindex.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	})

	// 5. Instantiate Engine
	engine, err := vindex.New(cfg, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}

	// 6. Start Engine and verify initial recovery and sync
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	// 7. Expose Handler and AdminHandler via httptest.Server and query using Client
	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	adminTS := httptest.NewServer(engine.AdminHandler())
	defer adminTS.Close()

	// Verify removed routes return 404 while canonical / admin routes respond as specified
	for _, removedURL := range []string{
		ts.URL + "/vindex/v1/lookup",
		ts.URL + "/inputlog_checkpoint",
		adminTS.URL + "/syncz",
	} {
		resp, err := ts.Client().Get(removedURL)
		if err != nil {
			t.Fatalf("GET %s failed: %v", removedURL, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", removedURL, resp.StatusCode)
		}
	}
	for _, liveURL := range []string{
		ts.URL + "/checkpoint",
		adminTS.URL + "/healthz",
		adminTS.URL + "/readyz",
		adminTS.URL + "/metrics",
	} {
		resp, err := ts.Client().Get(liveURL)
		if err != nil {
			t.Fatalf("GET %s failed: %v", liveURL, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", liveURL, resp.StatusCode)
		}
	}

	outPolicy, err := client.SingleKeyPolicy("test.outputlog", outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(out) failed: %v", err)
	}
	verifierCfg := client.Config{
		ExpectedOutputLogOrigin: "test.outputlog",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "test.inputlog",
	}
	cli, err := client.New(ts.URL, verifierCfg, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	collectAscending := func(c *client.Client, key string) ([]uint64, error) {
		res, err := c.LookupKey(ctx, key)
		if err != nil {
			return nil, err
		}
		if len(res.Keys) == 0 {
			return nil, nil
		}
		var out []uint64
		for idx, err := range res.Keys[0].Values(ctx) {
			if err != nil {
				return nil, err
			}
			out = append(out, idx)
		}
		slices.Reverse(out)
		return out, nil
	}

	// Query "apple" -> expect indices [0, 2]
	indicesApple, err := collectAscending(cli, "apple")
	if err != nil {
		t.Fatalf("LookupKey/Values(apple) failed: %v", err)
	}
	if len(indicesApple) != 2 || indicesApple[0] != 0 || indicesApple[1] != 2 {
		t.Fatalf("LookupKey/Values(apple) indices = %v, want [0, 2]", indicesApple)
	}

	// Query prefix "a" -> expect match "apple"
	prefResp, err := cli.LookupPrefix(ctx, "a")
	if err != nil {
		t.Fatalf("LookupPrefix(a) failed: %v", err)
	}
	if len(prefResp.Keys) != 1 || prefResp.Keys[0].Key != "apple" {
		t.Fatalf("LookupPrefix(a) keys = %+v, want [apple]", prefResp.Keys)
	}

	// Query "banana" -> expect index [1]
	indicesBanana, err := collectAscending(cli, "banana")
	if err != nil {
		t.Fatalf("LookupKey/Values(banana) failed: %v", err)
	}
	if len(indicesBanana) != 1 || indicesBanana[0] != 1 {
		t.Fatalf("LookupKey/Values(banana) indices = %v, want [1]", indicesBanana)
	}

	// Query non-existent "cherry" -> expect non-inclusion
	krCherry, err := cli.LookupKey(ctx, "cherry")
	if err != nil {
		t.Fatalf("LookupKey(cherry) failed: %v", err)
	}
	if len(krCherry.Keys) != 0 {
		t.Fatalf("LookupKey(cherry) Keys = %+v, want empty", krCherry.Keys)
	}
	indicesCherry, err := collectAscending(cli, "cherry")
	if err != nil {
		t.Fatalf("LookupKey/Values(cherry) failed: %v", err)
	}
	if len(indicesCherry) != 0 {
		t.Fatalf("LookupKey/Values(cherry) returned non-empty indices: %v", indicesCherry)
	}

	// 8. Feed a new leaf into the input log dynamically while Engine is running
	idx3 := appendLeaf([]byte("apple_delta"))
	if idx3 != 3 {
		t.Fatalf("unexpected idx3 = %d, want 3", idx3)
	}

	// Poll until client sees updated indices [0, 2, 3]
	deadline := time.Now().Add(5 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		indices, err := collectAscending(cli, "apple")
		if err == nil && len(indices) == 3 {
			if indices[0] == 0 && indices[1] == 2 && indices[2] == 3 {
				updated = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !updated {
		t.Fatal("timed out waiting for background synchronization of dynamic leaf 3")
	}

	// 9. Stop Engine
	if err := engine.Stop(); err != nil {
		t.Fatalf("engine.Stop failed: %v", err)
	}

	// 10. Verify crash-recovery / persistent restart
	engine2, err := vindex.New(cfg, mapper)
	if err != nil {
		t.Fatalf("vindex.New (restart) failed: %v", err)
	}
	if err := engine2.Start(ctx); err != nil {
		t.Fatalf("engine2.Start failed: %v", err)
	}
	defer func() { _ = engine2.Stop() }()

	ts2 := httptest.NewServer(engine2.Handler())
	defer ts2.Close()

	cli2, err := client.New(ts2.URL, verifierCfg, client.WithHTTPClient(ts2.Client()))
	if err != nil {
		t.Fatalf("client.New (restart) failed: %v", err)
	}

	indicesRestart, err := collectAscending(cli2, "apple")
	if err != nil {
		t.Fatalf("LookupKey/Values(apple) after restart failed: %v", err)
	}
	if len(indicesRestart) != 3 {
		t.Fatalf("LookupKey/Values(apple) after restart: indices=%v (want [0, 2, 3])", indicesRestart)
	}
}

func TestEngine_InMemoryOutputLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rootDir := t.TempDir()
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	inLogDir := filepath.Join(rootDir, "inlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "inmem.inputlog")
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("tessera.NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })
	awaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, time.Millisecond)

	// Append 2 leaves
	_, _, err = awaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte("mem_leaf_0"))))
	if err != nil {
		t.Fatalf("append leaf 0 failed: %v", err)
	}
	_, _, err = awaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte("mem_leaf_1"))))
	if err != nil {
		t.Fatalf("append leaf 1 failed: %v", err)
	}

	inMemPolicy, err := client.SingleKeyPolicy("inmem.inputlog", inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(inmem) failed: %v", err)
	}
	// In-memory output log config with explicit InputLogPolicy
	cfg := vindex.Config{
		DBPath:         dbDir,
		MPTDir:         mptDir,
		TileCacheDir:   cacheDir,
		ChunkSize:      64,
		BundleSize:     16,
		PollInterval:   50 * time.Millisecond,
		InputLogURL:    fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin: "inmem.inputlog",
		InputLogPolicy: inMemPolicy,
	}

	engine, err := vindex.New(cfg, nil) // tests mapper == nil fallback to IdentityMapper
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	if engine.OutputLogVerifier() == nil {
		t.Fatal("expected non-nil OutputLogVerifier for in-memory output log")
	}

	outMemPolicy, err := client.SingleKeyPolicy("vindex.memory.outputlog", engine.OutputLogVerifier())
	if err != nil {
		t.Fatalf("SingleKeyPolicy(outmem) failed: %v", err)
	}
	cli, err := client.New(ts.URL, client.Config{
		ExpectedOutputLogOrigin: "vindex.memory.outputlog",
		OutputLogPolicy:         outMemPolicy,
		ExpectedInputLogOrigin:  "inmem.inputlog",
	}, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// Query canonical key "mem_leaf_0" emitted by IdentityMapper
	res0, err := cli.LookupKey(ctx, "mem_leaf_0")
	if err != nil {
		t.Fatalf("LookupKey failed: %v", err)
	}
	if len(res0.Keys) != 1 {
		t.Fatalf("expected 1 matched key, got %d", len(res0.Keys))
	}
	var indices0 []uint64
	for idx, err := range res0.Keys[0].Values(ctx) {
		if err != nil {
			t.Fatalf("Values failed: %v", err)
		}
		indices0 = append(indices0, idx)
	}
	if len(indices0) != 1 || indices0[0] != 0 {
		t.Fatalf("unexpected Values result: indices=%v", indices0)
	}
}

func TestEngine_Run_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	rootDir := t.TempDir()
	cfg := vindex.Config{
		DBPath:       filepath.Join(rootDir, "db"),
		MPTDir:       filepath.Join(rootDir, "mpt"),
		TileCacheDir: filepath.Join(rootDir, "cache"),
		PollInterval: 10 * time.Millisecond,
	}

	engine, err := vindex.New(cfg, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- engine.Run(ctx)
	}()

	cancel()

	err = <-runErrCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
}

func TestEngine_LifecycleGuardsAndGetters(t *testing.T) {
	ctx := context.Background()
	rootDir := t.TempDir()
	cfg := vindex.Config{
		DBPath:       filepath.Join(rootDir, "db"),
		MPTDir:       filepath.Join(rootDir, "mpt"),
		TileCacheDir: filepath.Join(rootDir, "cache"),
	}

	engine, err := vindex.New(cfg, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}

	// Verify getters
	if engine.DB() == nil {
		t.Error("engine.DB() is nil")
	}
	if engine.MPT() == nil {
		t.Error("engine.MPT() is nil")
	}
	if engine.Publisher() == nil {
		t.Error("engine.Publisher() is nil")
	}
	if engine.Coordinator() == nil {
		t.Error("engine.Coordinator() is nil")
	}
	if engine.Server() == nil {
		t.Error("engine.Server() is nil")
	}

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	// Guard: Start when already running
	if err := engine.Start(ctx); err == nil {
		t.Error("expected error calling Start() when running, got nil")
	}

	// Guard: Run when already running
	if err := engine.Run(ctx); err == nil {
		t.Error("expected error calling Run() when running, got nil")
	}

	// Close
	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close failed: %v", err)
	}

	// Close idempotency
	if err := engine.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}

	// Guard: Start when closed
	if err := engine.Start(ctx); err == nil {
		t.Error("expected error calling Start() after Close, got nil")
	}

	// Guard: Run when closed
	if err := engine.Run(ctx); err == nil {
		t.Error("expected error calling Run() after Close, got nil")
	}
}

func TestEngine_ConfigValidationErrors(t *testing.T) {
	rootDir := t.TempDir()

	// 1. Invalid OutputLogSignerKey
	cfg1 := vindex.Config{
		DBPath:             filepath.Join(rootDir, "db1"),
		MPTDir:             filepath.Join(rootDir, "mpt1"),
		TileCacheDir:       filepath.Join(rootDir, "cache1"),
		OutputLogDir:       filepath.Join(rootDir, "out1"),
		OutputLogSignerKey: "invalid_key_string",
	}
	if _, err := vindex.New(cfg1, nil); err == nil {
		t.Error("expected error for invalid OutputLogSignerKey, got nil")
	}

	// 2. Invalid InputLogURL
	cfg2 := vindex.Config{
		DBPath:       filepath.Join(rootDir, "db2"),
		MPTDir:       filepath.Join(rootDir, "mpt2"),
		TileCacheDir: filepath.Join(rootDir, "cache2"),
		InputLogURL:  "://invalid_url",
	}
	if _, err := vindex.New(cfg2, nil); err == nil {
		t.Error("expected error for invalid InputLogURL, got nil")
	}

	// 3. Partial OutputLog config (OutputLogDir set without OutputLogSignerKey)
	cfg3 := vindex.Config{
		DBPath:       filepath.Join(rootDir, "db3"),
		MPTDir:       filepath.Join(rootDir, "mpt3"),
		OutputLogDir: filepath.Join(rootDir, "out3"),
	}
	if _, err := vindex.New(cfg3, nil); err == nil {
		t.Error("expected error for OutputLogDir without OutputLogSignerKey, got nil")
	}

	// 4. Witnesses with ephemeral in-memory output log
	cfg4 := vindex.Config{
		DBPath:      filepath.Join(rootDir, "db4"),
		MPTDir:      filepath.Join(rootDir, "mpt4"),
		WitnessURLs: []string{"https://witness.example.com"},
	}
	if _, err := vindex.New(cfg4, nil); err == nil {
		t.Error("expected error for WitnessURLs with ephemeral output log, got nil")
	}

	// 5. Ephemeral in-memory output log rejected when persistent DB/MPT already has state
	db5 := filepath.Join(rootDir, "db5")
	mpt5 := filepath.Join(rootDir, "mpt5")
	out5 := filepath.Join(rootDir, "out5")
	skey5, _, err := note.GenerateKey(rand.Reader, "test.out5")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	eng5, err := vindex.New(vindex.Config{
		DBPath:             db5,
		MPTDir:             mpt5,
		OutputLogDir:       out5,
		OutputLogSignerKey: skey5,
	}, nil)
	if err != nil {
		t.Fatalf("vindex.New persistent failed: %v", err)
	}
	_, _ = eng5.MPT().CommitKeysWithVersion(nil, 10)
	_ = eng5.MPT().Persist()
	_ = eng5.Close()

	if _, err := vindex.New(vindex.Config{
		DBPath: db5,
		MPTDir: mpt5,
	}, nil); err == nil {
		t.Error("expected error opening non-empty persistent DB/MPT with ephemeral in-memory output log, got nil")
	}
}
