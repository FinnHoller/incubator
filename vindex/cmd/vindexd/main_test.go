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

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func newTestSignerKey(t *testing.T, origin string) (string, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("failed to generate note key: %v", err)
	}
	return skey, vkey
}

var (
	testWasmOnce sync.Once
	testWasmPath string
	testWasmErr  error
)

func getTestWasm(t *testing.T) string {
	t.Helper()
	testWasmOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "vindexd-wasm-*")
		if err != nil {
			testWasmErr = err
			return
		}
		wasmPath := filepath.Join(tmpDir, "starter.wasm")
		cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", wasmPath, "github.com/transparency-dev/incubator/vindex/mapfn/examples/starter")
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			testWasmErr = fmt.Errorf("failed to build starter wasm: %w\n%s", err, string(out))
			return
		}
		testWasmPath = wasmPath
	})
	if testWasmErr != nil {
		t.Fatalf("getTestWasm failed: %v", testWasmErr)
	}
	return testWasmPath
}

func TestVindexd_FlagValidation_Publisher(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	*mode = "publisher"

	// 1. Missing db_path
	*dbPath = ""
	err := run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--db_path flag is required") {
		t.Fatalf("expected missing db_path error, got: %v", err)
	}
	*dbPath = filepath.Join(tmpDir, "db")

	// 2. Missing wasm_path
	*wasmPath = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--wasm_path flag is required") {
		t.Fatalf("expected missing wasm_path error, got: %v", err)
	}
	*wasmPath = getTestWasm(t)

	// 3. Missing output_log_dir
	*outputLogDir = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--output_log_dir flag is required") {
		t.Fatalf("expected missing output_log_dir error, got: %v", err)
	}
	*outputLogDir = filepath.Join(tmpDir, "outputlog")

	// 4. Missing output_log_signer_key
	*outputLogSignerKey = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--output_log_signer_key flag is required") {
		t.Fatalf("expected missing output_log_signer_key error, got: %v", err)
	}
}

func TestVindexd_POSIXOutputLog_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	origin := "vindex.test.output"
	skey, _ := newTestSignerKey(t, origin)

	dbD := filepath.Join(tmpDir, "db")
	mptD := filepath.Join(tmpDir, "mpt")
	outD := filepath.Join(tmpDir, "outputlog")
	cacheD := filepath.Join(tmpDir, "tiles")

	*mode = "publisher"
	*dbPath = dbD
	*mptDir = mptD
	*outputLogDir = outD
	*outputLogSignerKey = skey
	*outputLogOrigin = origin
	*tileCacheDir = cacheD
	*wasmPath = getTestWasm(t)
	*wasmWorkers = 1
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""
	*inputLogURL = "" // no fetcher, run recovery and shutdown

	// Run publisher briefly in background
	runCtx, runCancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(runCtx)
	}()

	// Wait for initialization, verify checkpoint file exists on disk
	cpPath := filepath.Join(outD, "checkpoint")
	var cpBytes []byte
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(cpPath)
		if err == nil && len(data) > 0 {
			cpBytes = data
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	runCancel()
	if err := <-errCh; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("run failed: %v", err)
	}

	// Verify Tessera POSIX storage initialization on disk
	if len(cpBytes) == 0 {
		t.Fatalf("expected Tessera checkpoint to be written to %s", cpPath)
	}
	if !strings.Contains(string(cpBytes), origin) {
		t.Errorf("checkpoint header %q does not contain origin %q", string(cpBytes), origin)
	}
}

func TestVindexd_POSIXOutputLog_SyncAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tmpDir := t.TempDir()

	// 1. Create Input Log with Tessera POSIX
	inLogDir := filepath.Join(tmpDir, "inlog")
	inOrigin := "test.inlog"
	inSKey, inVKey := newTestSignerKey(t, inOrigin)
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	driver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 10*time.Millisecond)
	_, _, err = awaiter.Await(ctx, appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-0"))))
	if err != nil {
		t.Fatalf("appender.Add failed: %v", err)
	}
	_, _, err = awaiter.Await(ctx, appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-1"))))
	if err != nil {
		t.Fatalf("appender.Add failed: %v", err)
	}

	inServer := httptest.NewServer(http.FileServer(http.Dir(inLogDir)))
	defer inServer.Close()

	// 2. Setup VIndex Output Log keys and paths
	outOrigin := "test.outlog"
	outSKey, _ := newTestSignerKey(t, outOrigin)

	dbD := filepath.Join(tmpDir, "db")
	mptD := filepath.Join(tmpDir, "mpt")
	outD := filepath.Join(tmpDir, "outputlog")
	cacheD := filepath.Join(tmpDir, "tilecache")

	// 3. Run vindexd in oneshot mode
	*mode = "publisher"
	*dbPath = dbD
	*mptDir = mptD
	*outputLogDir = outD
	*outputLogSignerKey = outSKey
	*outputLogOrigin = outOrigin
	*tileCacheDir = cacheD
	*inputLogURL = inServer.URL
	*inputLogOrigin = inOrigin
	*inputLogPubKey = inVKey
	*wasmPath = getTestWasm(t)
	*wasmWorkers = 4
	*oneShot = true
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""

	if err := run(ctx); err != nil {
		t.Fatalf("first run (oneshot) failed: %v", err)
	}

	// Verify Output Log checkpoint on disk has size >= 1
	cpBytes, err := os.ReadFile(filepath.Join(outD, "checkpoint"))
	if err != nil {
		t.Fatalf("failed to read output log checkpoint: %v", err)
	}
	if !strings.Contains(string(cpBytes), outOrigin) {
		t.Fatalf("output checkpoint missing origin: %s", string(cpBytes))
	}

	// 4. Restart vindexd on same directory with oneshot mode to test persistence and recovery
	if err := run(ctx); err != nil {
		t.Fatalf("second run (recovery restart) failed: %v", err)
	}

	// 5. Verify HTTP serving of tiles from outputLogDir and operational listener separation
	boundListenAddr.Store(nil)
	boundMetricsAddr.Store(nil)
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = "127.0.0.1:0"
	t.Cleanup(func() { *metricsAddr = "" })
	*oneShot = false
	*pollInterval = 100 * time.Millisecond

	srvCtx, srvCancel := context.WithCancel(ctx)
	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- run(srvCtx)
	}()

	// Query /checkpoint and /tile/ endpoints from vindexd
	client := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		addrPtr := boundListenAddr.Load()
		mAddrPtr := boundMetricsAddr.Load()
		if addrPtr == nil || *addrPtr == "" || mAddrPtr == nil || *mAddrPtr == "" {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		resp, err = client.Get(fmt.Sprintf("http://%s/checkpoint", *addrPtr))
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp == nil || err != nil || resp.StatusCode != http.StatusOK {
		srvCancel()
		t.Fatalf("failed to query /checkpoint: %v, resp: %v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), outOrigin) {
		t.Errorf("read server /checkpoint body %q missing %q", string(body), outOrigin)
	}

	pubAddr := *boundListenAddr.Load()
	admAddr := *boundMetricsAddr.Load()

	// Operational endpoints must return 404 on the public --listen_addr
	for _, opPath := range []string{"/healthz", "/readyz", "/syncz", "/metrics", "/debug/pprof/"} {
		opResp, opErr := client.Get(fmt.Sprintf("http://%s%s", pubAddr, opPath))
		if opErr != nil {
			t.Fatalf("GET public %s failed: %v", opPath, opErr)
		}
		_ = opResp.Body.Close()
		if opResp.StatusCode != http.StatusNotFound {
			t.Errorf("GET public %s status = %d, want 404", opPath, opResp.StatusCode)
		}
	}

	// Operational endpoints must succeed on the internal --metrics_addr
	for _, opPath := range []string{"/healthz", "/readyz", "/metrics", "/debug/pprof/"} {
		opResp, opErr := client.Get(fmt.Sprintf("http://%s%s", admAddr, opPath))
		if opErr != nil {
			t.Fatalf("GET admin %s failed: %v", opPath, opErr)
		}
		_ = opResp.Body.Close()
		if opResp.StatusCode != http.StatusOK {
			t.Errorf("GET admin %s status = %d, want 200", opPath, opResp.StatusCode)
		}
	}

	srvCancel()
	if err := <-srvErrCh; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("server run error: %v", err)
	}
}

func TestVindexd_DBCacheSizeFlag(t *testing.T) {
	tmpDir := t.TempDir()
	origCache := *dbCacheSizeMB
	origMaxFiles := *dbMaxOpenFiles
	t.Cleanup(func() {
		*dbCacheSizeMB = origCache
		*dbMaxOpenFiles = origMaxFiles
	})

	*dbCacheSizeMB = 64
	*dbMaxOpenFiles = 1200

	pebbleOpts := &pebble.Options{}
	if *dbMaxOpenFiles > 0 {
		pebbleOpts.MaxOpenFiles = *dbMaxOpenFiles
	}
	if *dbCacheSizeMB > 0 {
		cache := pebble.NewCache(int64(*dbCacheSizeMB) << 20)
		defer cache.Unref()
		pebbleOpts.Cache = cache
	}
	db, err := kvstore.Open(filepath.Join(tmpDir, "db"), pebbleOpts)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	if pebbleOpts.MaxOpenFiles != 1200 {
		t.Errorf("expected MaxOpenFiles 1200, got %d", pebbleOpts.MaxOpenFiles)
	}
	if pebbleOpts.Cache.MaxSize() != int64(64)<<20 {
		t.Errorf("expected Cache.MaxSize 64MB (%d), got %d", int64(64)<<20, pebbleOpts.Cache.MaxSize())
	}
}

func TestVindexd_MTCVerifier_FlagAndInit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	mtcKey := "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	outOrigin := "vindex.test.output"
	skey, _ := newTestSignerKey(t, outOrigin)

	*mode = "publisher"
	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = filepath.Join(tmpDir, "mpt")
	*outputLogDir = filepath.Join(tmpDir, "outputlog")
	*outputLogSignerKey = skey
	*outputLogOrigin = outOrigin
	*wasmPath = getTestWasm(t)
	*wasmWorkers = 1
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""
	*inputLogURL = "https://bootstrap-mtca-shard3.cloudflareresearch.com"
	*inputLogOrigin = "bootstrap-mtca.cloudflareresearch.com/logs/shard3"

	// 1. Invalid MTC pubkey returns error
	*inputLogPubKey = "mtc+invalid+key"
	err := run(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid MTC verifier") {
		t.Fatalf("expected invalid MTC verifier error, got: %v", err)
	}

	// 2. Valid MTC pubkey initializes without error
	*inputLogPubKey = mtcKey
	cancel() // Cancel context so coordinator/run exits cleanly after initialization
	err = run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected clean run/exit on context cancel, got: %v", err)
	}
}

func TestVindexd_CleanDirs(t *testing.T) {
	tmpDir := t.TempDir()
	d1 := filepath.Join(tmpDir, "db")
	d2 := filepath.Join(tmpDir, "mpt")
	d3 := filepath.Join(tmpDir, "outlog")
	d4 := filepath.Join(tmpDir, "tiles")

	resetDirs := func() {
		for _, d := range []string{d1, d2, d3, d4} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatalf("MkdirAll failed: %v", err)
			}
			if err := os.WriteFile(filepath.Join(d, "canary.txt"), []byte("canary"), 0o644); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}
		}
	}
	resetDirs()

	origDB := *dbPath
	origMPT := *mptDir
	origOutLog := *outputLogDir
	origTiles := *tileCacheDir
	origClean := *cleanDirs
	origWASM := *wasmPath
	origKey := *outputLogSignerKey
	origMode := *mode
	t.Cleanup(func() {
		*dbPath = origDB
		*mptDir = origMPT
		*outputLogDir = origOutLog
		*tileCacheDir = origTiles
		*cleanDirs = origClean
		*wasmPath = origWASM
		*outputLogSignerKey = origKey
		*mode = origMode
	})

	*dbPath = d1
	*mptDir = d2
	*outputLogDir = d3
	*tileCacheDir = d4
	*cleanDirs = true
	*wasmPath = "" // Missing required flag
	*mode = "publisher"

	// 1. Verify invalid flags abort before wiping directories
	err := run(context.Background())
	if err == nil {
		t.Fatalf("expected error due to missing wasm_path, got nil")
	}
	for _, d := range []string{d1, d2, d3, d4} {
		canary := filepath.Join(d, "canary.txt")
		if _, err := os.Stat(canary); errors.Is(err, os.ErrNotExist) {
			t.Fatalf("destructive clean executed despite invalid flags: %q was deleted", canary)
		}
	}

	// 2. Verify clean in auditor mode is rejected to protect forensic state
	*mode = "auditor"
	if err := run(context.Background()); err == nil || !strings.Contains(err.Error(), "not permitted in auditor") {
		t.Fatalf("expected auditor mode --clean rejection, got: %v", err)
	}

	// 3. Verify cleanDirectories succeeds when executed
	*mode = "publisher"
	if err := cleanDirectories(); err != nil {
		t.Fatalf("cleanDirectories failed: %v", err)
	}
	for _, d := range []string{d1, d2, d3, d4} {
		canary := filepath.Join(d, "canary.txt")
		if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected %q to be deleted by cleanDirectories, but it still exists", canary)
		}
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			t.Errorf("expected %q to exist as an empty directory after cleanDirectories", d)
		}
	}
}

func TestVindexd_PathPrefixFlag(t *testing.T) {
	origPrefix := *pathPrefix
	t.Cleanup(func() {
		*pathPrefix = origPrefix
	})

	*pathPrefix = "/custom/prefix/"
	srv := server.NewReadServer(nil, nil, nil, 256)
	srv.SetPathPrefix(*pathPrefix)
	if srv.PathPrefix() != "/custom/prefix" {
		t.Fatalf("expected /custom/prefix, got %q", srv.PathPrefix())
	}
}

func TestVindexd_PrefixPolicy(t *testing.T) {
	allowPol, err := parsePrefixPolicy("allow")
	if err != nil {
		t.Fatalf("parsePrefixPolicy(allow) failed: %v", err)
	}
	if err := allowPol("any"); err != nil {
		t.Errorf("allow policy rejected prefix: %v", err)
	}

	nonePol, err := parsePrefixPolicy("none")
	if err != nil {
		t.Fatalf("parsePrefixPolicy(none) failed: %v", err)
	}
	if err := nonePol("com.example."); err == nil {
		t.Error("none policy accepted prefix, want error")
	}

	for _, alias := range []string{"reversed-dns", "domain"} {
		pol, err := parsePrefixPolicy(alias)
		if err != nil {
			t.Fatalf("parsePrefixPolicy(%q) failed: %v", alias, err)
		}
		validPrefixes := []string{
			"com.example.",
			"com.example.mail.",
			"uk.co.google.",
			"uk.co.google.maps.",
			"com.example.*.",
		}
		for _, p := range validPrefixes {
			if err := pol(p); err != nil {
				t.Errorf("policy(%q) rejected valid reversed-DNS prefix %q: %v", alias, p, err)
			}
		}

		invalidPrefixes := []string{
			"",
			".",
			"com.example",
			"com.",
			"uk.co.",
			"UK.CO.",
			"com.blogspot.",
			"com..example.",
			".com.example.",
			"com.*.",
		}
		for _, p := range invalidPrefixes {
			if err := pol(p); err == nil {
				t.Errorf("policy(%q) accepted invalid reversed-DNS prefix %q, want error", alias, p)
			}
		}
	}

	if _, err := parsePrefixPolicy("unknown"); err == nil {
		t.Error("expected error for unknown prefix policy")
	}
}
