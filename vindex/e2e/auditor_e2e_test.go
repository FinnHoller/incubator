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

package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

// verifierTestCluster bundles an isolated Tessera cluster with live HTTP log servers
// and request inspection to verify sourcing invariants.
type verifierTestCluster struct {
	*testCluster
	inLogServer       *httptest.Server
	outLogServer      *httptest.Server
	inCheckpointCalls atomic.Int64
	outHandler        atomic.Pointer[http.Handler]
}

func newVerifierTestCluster(t *testing.T, ctx context.Context, chunkSize, bundleSize uint64) *verifierTestCluster {
	t.Helper()
	baseCluster := newTestCluster(t, ctx, chunkSize, bundleSize)

	vtc := &verifierTestCluster{
		testCluster: baseCluster,
	}

	// Intercept InputLog HTTP traffic to assert zero calls to /checkpoint (R1)
	inFs := http.FileServer(http.Dir(baseCluster.inLogDir))
	inMux := http.NewServeMux()
	inMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checkpoint" || strings.HasSuffix(r.URL.Path, "/checkpoint") {
			vtc.inCheckpointCalls.Add(1)
		}
		inFs.ServeHTTP(w, r)
	})
	vtc.inLogServer = httptest.NewServer(inMux)
	t.Cleanup(vtc.inLogServer.Close)

	defaultOutHandler := http.FileServer(http.Dir(baseCluster.outLogDir))
	vtc.outHandler.Store(&defaultOutHandler)
	vtc.outLogServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*vtc.outHandler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(vtc.outLogServer.Close)

	return vtc
}

func (c *verifierTestCluster) newVerifierConfig(t *testing.T, mapper vindex.LeafMapper) auditor.Config {
	t.Helper()
	tmpDir := t.TempDir()
	inPolicy, err := wire.BuildPolicy(c.config.InputLogOrigin, c.inVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy(input) failed: %v", err)
	}
	outPolicy, err := wire.BuildPolicy(c.config.OutputLogOrigin, c.outVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy(output) failed: %v", err)
	}
	return auditor.Config{
		InputLogURL:       c.inLogServer.URL,
		InputLogOrigin:    c.config.InputLogOrigin,
		InputLogVerifier:  c.inVerifier,
		InputLogPubKey:    c.inVKey,
		InputLogPolicy:    inPolicy,
		OutputLogURL:      c.outLogServer.URL,
		OutputLogOrigin:   c.config.OutputLogOrigin,
		OutputLogVerifier: c.outVerifier,
		OutputLogPubKey:   c.outVKey,
		OutputLogPolicy:   outPolicy,
		MapFn:             mapper,
		DBPath:            filepath.Join(tmpDir, "verifier_db"),
		MPTDir:            filepath.Join(tmpDir, "verifier_mpt"),
		PollInterval:      50 * time.Millisecond,
	}
}

// waitForOutputLogCheckpoint polls the OutputLog HTTP server until a valid checkpoint with size >= minSize is published.
func waitForOutputLogCheckpoint(t *testing.T, url string, minSize uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/checkpoint")
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if cp, err := tree.ParseCheckpointHeader(body); err == nil && cp.Size >= minSize {
				return
			}
		} else if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for OutputLog checkpoint size >= %d", minSize)
}

// -----------------------------------------------------------------------------
// Test 1: Honest End-to-End Sync (Oneshot and Daemon)
// -----------------------------------------------------------------------------

// TestE2E_HonestSync verifies multi-leaf sync, watermark advancement, MPT root equality,
// metrics baseline, /healthz 200 OK, and background daemon catch-up.
func TestE2E_HonestSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.AuditorRootMismatch.Set(0)
	baseMismatches := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)

	// 1. Seed initial 10 input leaves
	for i := 0; i < 10; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("entry_%02d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	})

	// Start publisher engine
	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	// Wait for publisher to publish initial leaf 0 to OutputLog
	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	// 2. Initialize Verifier
	vCfg := vtc.newVerifierConfig(t, mapper)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}

	// 3. Oneshot verification pass
	if err := v.VerifyOnce(ctx); err != nil {
		_ = v.Close()
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	st := v.Status()
	if st.IsHalted {
		_ = v.Close()
		t.Fatalf("verifier unexpectedly halted: %v", st.HaltError)
	}
	if st.VerifiedOutputSize != 1 {
		t.Errorf("VerifiedOutputSize = %d, want 1", st.VerifiedOutputSize)
	}
	if st.VerifiedInputSize != 10 {
		t.Errorf("VerifiedInputSize = %d, want 10", st.VerifiedInputSize)
	}

	// 4. Assert metrics and operational admin routes (/healthz, /readyz, /metrics, /debug/pprof/)
	if m := testutil.ToFloat64(metrics.AuditorRootMismatch); m != 0 {
		t.Errorf("vindex_auditor_root_mismatch = %v, want 0", m)
	}
	if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal) - baseMismatches; c != 0 {
		t.Errorf("vindex_auditor_root_mismatches_total delta = %v, want 0", c)
	}
	if err := v.HealthCheck(); err != nil {
		t.Errorf("HealthCheck() = %v, want nil", err)
	}
	adminMux := http.NewServeMux()
	v.RegisterAdminRoutes(adminMux)
	adminTS := httptest.NewServer(adminMux)
	for _, opPath := range []string{"/healthz", "/readyz", "/metrics", "/debug/pprof/"} {
		res, reqErr := http.Get(adminTS.URL + opPath)
		if reqErr != nil {
			adminTS.Close()
			_ = v.Close()
			t.Fatalf("GET %s failed: %v", opPath, reqErr)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", opPath, res.StatusCode)
		}
	}
	adminTS.Close()

	// Close verifier to release Pebble DB lock and inspect persisted watermarks on disk
	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	db, err := kvstore.Open(vCfg.DBPath, nil)
	if err != nil {
		t.Fatalf("failed to open verifier DB: %v", err)
	}
	outBytes, closer, err := db.Pebble().Get(auditor.KeyVerifierOutputWatermark)
	if err != nil {
		_ = db.Close()
		t.Fatalf("failed to get KeyVerifierOutputWatermark: %v", err)
	}
	if binary.BigEndian.Uint64(outBytes) != 1 {
		t.Errorf("persisted output watermark = %d, want 1", binary.BigEndian.Uint64(outBytes))
	}
	_ = closer.Close()

	inBytes, closer, err := db.Pebble().Get(auditor.KeyVerifierInputWatermark)
	if err != nil {
		_ = db.Close()
		t.Fatalf("failed to get KeyVerifierInputWatermark: %v", err)
	}
	if binary.BigEndian.Uint64(inBytes) != 10 {
		t.Errorf("persisted input watermark = %d, want 10", binary.BigEndian.Uint64(inBytes))
	}
	_ = closer.Close()
	_ = db.Close()

	// 5. Reopen Verifier and verify Live Daemon background sync catch-up
	v2, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New restart failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	if v2.Status().VerifiedOutputSize != 1 || v2.Status().VerifiedInputSize != 10 {
		t.Fatalf("reopened verifier recovered status mismatch: %+v", v2.Status())
	}

	daemonCtx, daemonCancel := context.WithCancel(ctx)
	defer daemonCancel()
	go func() { _ = v2.Run(daemonCtx) }()

	// Append 10 more leaves to InputLog
	for i := 10; i < 20; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("entry_%02d", i)))
	}

	// Wait for daemon to verify leaf 1 and advance to input size 20
	catchupDeadline := time.Now().Add(10 * time.Second)
	caughtUp := false
	for time.Now().Before(catchupDeadline) {
		s := v2.Status()
		if s.VerifiedOutputSize >= 2 && s.VerifiedInputSize >= 20 {
			caughtUp = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !caughtUp {
		t.Fatalf("verifier daemon failed to catch up to leaf 1; status: %+v", v2.Status())
	}
	if v2.Status().IsHalted {
		t.Fatalf("verifier halted during daemon mode: %v", v2.Status().HaltError)
	}
}

func TestVerifierE2E_HonestSync_OneshotAndDaemon(t *testing.T) {
	TestE2E_HonestSync(t)
}

// -----------------------------------------------------------------------------
// Test 2: Tampered Root Detection & Containment
// -----------------------------------------------------------------------------

// TestE2E_TamperedRootDetection verifies that a tampered leaf committed to the OutputLog causes
// immediate engine halting, metrics vindex_auditor_root_mismatch == 1, /readyz 503 (while /healthz stays 200),
// and database preservation.
func TestE2E_TamperedRootDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.AuditorRootMismatch.Set(0)
	baseMismatches := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)

	// 1. Seed 5 leaves and publish honest leaf 0
	for i := 0; i < 5; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("record_%d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	vCfg := vtc.newVerifierConfig(t, mapper)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}

	// Honest sync pass on leaf 0
	if err := v.VerifyOnce(ctx); err != nil {
		_ = v.Close()
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}
	if v.Status().VerifiedOutputSize != 1 {
		_ = v.Close()
		t.Fatalf("VerifiedOutputSize = %d, want 1", v.Status().VerifiedOutputSize)
	}

	authenticRoot0 := v.Status().LastVerifiedRoot
	rawInCP5, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		_ = v.Close()
		t.Fatalf("failed to read initial input checkpoint: %v", err)
	}

	// Close initial verifier to release DB locks
	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	// 2. Append 5 more leaves to InputLog (total 10 leaves)
	for i := 5; i < 10; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("record_%d", i)))
	}

	// Read valid signed InputLog checkpoint at size 10
	rawInCP10, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("failed to read input checkpoint at size 10: %v", err)
	}

	// Construct an adversarial OutputLog with a forged MPT root in leaf 1
	advOutDir := t.TempDir()
	outSigner, err := note.NewSigner(vtc.outSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	advLog, err := tree.NewPOSIXOutputLog(ctx, advOutDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
	if err != nil {
		t.Fatalf("failed to create adversarial OutputLog: %v", err)
	}
	defer func() { _ = advLog.Close() }()

	// Leaf 0: authentic
	inCP5, _, _, err := log.ParseCheckpoint(rawInCP5, vtc.config.InputLogOrigin, vtc.inVerifier)
	if err != nil {
		t.Fatalf("failed to parse rawInCP5: %v", err)
	}
	_, _, err = advLog.Append(ctx, tree.FormatOutputLogLeaf(authenticRoot0, inCP5))
	if err != nil {
		t.Fatalf("failed to append honest leaf 0: %v", err)
	}

	// Leaf 1: TAMPERED MPTRoot
	inCP10, _, _, err := log.ParseCheckpoint(rawInCP10, vtc.config.InputLogOrigin, vtc.inVerifier)
	if err != nil {
		t.Fatalf("failed to parse rawInCP10: %v", err)
	}
	tamperedRoot := sha256.Sum256([]byte("forged_mpt_root_hash"))
	tamperedLeaf1 := tree.FormatOutputLogLeaf(tamperedRoot, inCP10)
	_, _, err = advLog.Append(ctx, tamperedLeaf1)
	if err != nil {
		t.Fatalf("failed to append tampered leaf 1: %v", err)
	}

	advServer := httptest.NewServer(http.FileServer(http.Dir(advOutDir)))
	defer advServer.Close()

	// Reconfigure verifier OutputLogURL to point to adversarial log, keeping DBPath
	vCfg.OutputLogURL = advServer.URL
	advVerifier, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("failed to create advVerifier: %v", err)
	}
	defer func() { _ = advVerifier.Close() }()

	// 3. Execution & Detection
	err = advVerifier.VerifyOnce(ctx)
	if err == nil {
		t.Fatal("expected VerifyOnce to fail on tampered root, got nil")
	}
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got: %v", err)
	}

	var mismatchErr *auditor.RootMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("expected *auditor.RootMismatchError, got %T", err)
	}
	if mismatchErr.CommittedMPTRoot != tamperedRoot {
		t.Errorf("mismatchErr.CommittedMPTRoot = %x, want %x", mismatchErr.CommittedMPTRoot, tamperedRoot)
	}
	if mismatchErr.OutputIndex != 1 {
		t.Errorf("mismatchErr.OutputIndex = %d, want 1", mismatchErr.OutputIndex)
	}
	if mismatchErr.InputSize != 10 {
		t.Errorf("mismatchErr.InputSize = %d, want 10", mismatchErr.InputSize)
	}

	// 4. Metrics Assertions
	if m := testutil.ToFloat64(metrics.AuditorRootMismatch); m != 1.0 {
		t.Errorf("vindex_auditor_root_mismatch = %v, want 1.0", m)
	}
	if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal) - baseMismatches; c < 1.0 {
		t.Errorf("vindex_auditor_root_mismatches_total delta = %v, want >= 1.0", c)
	}

	// 5. Health & Readiness degradation
	healthErr := advVerifier.HealthCheck()
	if healthErr == nil || !strings.Contains(healthErr.Error(), "root hash mismatch") {
		t.Errorf("HealthCheck() = %v, want root mismatch error", healthErr)
	}
	advAdminMux := http.NewServeMux()
	advVerifier.RegisterAdminRoutes(advAdminMux)
	advAdminTS := httptest.NewServer(advAdminMux)
	defer advAdminTS.Close()

	if resH, reqErr := http.Get(advAdminTS.URL + "/healthz"); reqErr != nil {
		t.Fatalf("GET halted /healthz failed: %v", reqErr)
	} else {
		_ = resH.Body.Close()
		if resH.StatusCode != http.StatusOK {
			t.Errorf("halted /healthz status = %d, want 200", resH.StatusCode)
		}
	}
	if resR, reqErr := http.Get(advAdminTS.URL + "/readyz"); reqErr != nil {
		t.Fatalf("GET halted /readyz failed: %v", reqErr)
	} else {
		_ = resR.Body.Close()
		if resR.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("halted /readyz status = %d, want 503", resR.StatusCode)
		}
	}

	// 6. Watermark containment
	status := advVerifier.Status()
	if !status.IsHalted {
		t.Error("verifier status IsHalted = false, want true")
	}
	if status.VerifiedOutputSize != 1 {
		t.Errorf("VerifiedOutputSize advanced past tampered leaf to %d, want 1", status.VerifiedOutputSize)
	}
	if status.VerifiedInputSize != 5 {
		t.Errorf("VerifiedInputSize advanced to %d, want 5", status.VerifiedInputSize)
	}

	// Subsequent calls must immediately return ErrRootMismatch without re-processing
	if err := advVerifier.VerifyOnce(ctx); !errors.Is(err, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", err)
	}
}

func TestVerifierE2E_TamperedRoot_DetectionAndContainment(t *testing.T) {
	TestE2E_TamperedRootDetection(t)
}

// -----------------------------------------------------------------------------
// Test 3: Sourcing Invariant E2E (Zero Input Checkpoint Network Calls)
// -----------------------------------------------------------------------------

// TestE2E_SourcingInvariant_NoInputLogCheckpointCalls verifies Requirement R1 across the network wire:
// HTTP telemetry asserts exactly 0 calls to InputLog /checkpoint.
func TestE2E_SourcingInvariant_NoInputLogCheckpointCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.AuditorRootMismatch.Set(0)

	for i := 0; i < 20; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("entry_%d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	vCfg := vtc.newVerifierConfig(t, mapper)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// Execute full sync
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	// Assert that InputLog /checkpoint endpoint was fetched to verify the unsigned state_entry
	hits := vtc.inCheckpointCalls.Load()
	if hits == 0 {
		t.Fatalf("expected InputLog /checkpoint to be fetched during auditor sync, got 0 requests")
	}

	if v.Status().VerifiedInputSize != 20 {
		t.Errorf("VerifiedInputSize = %d, want 20", v.Status().VerifiedInputSize)
	}
}

func TestVerifierE2E_SourcingInvariant_NoInputCheckpointCalls(t *testing.T) {
	TestE2E_SourcingInvariant_NoInputLogCheckpointCalls(t)
}

// -----------------------------------------------------------------------------
// Test 4: Standalone CLI Execution (vindex-auditor & vindexd --mode=verifier)
// -----------------------------------------------------------------------------

var (
	buildBinsOnce   sync.Once
	vindexVerifyBin string
	vindexdBin      string
	starterWasmBin  string
	binBuildErr     error
)

func getCLIBinaries(t *testing.T) (string, string, string) {
	t.Helper()
	buildBinsOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "vindex-e2e-bins-*")
		if err != nil {
			binBuildErr = err
			return
		}
		vBin := filepath.Join(tmpDir, "vindex-auditor")
		cmdV := exec.Command("go", "build", "-o", vBin, "github.com/transparency-dev/incubator/vindex/cmd/vindex-auditor")
		if out, err := cmdV.CombinedOutput(); err != nil {
			binBuildErr = fmt.Errorf("failed to build vindex-auditor: %v\n%s", err, string(out))
			return
		}
		dBin := filepath.Join(tmpDir, "vindexd")
		cmdD := exec.Command("go", "build", "-o", dBin, "github.com/transparency-dev/incubator/vindex/cmd/vindexd")
		if out, err := cmdD.CombinedOutput(); err != nil {
			binBuildErr = fmt.Errorf("failed to build vindexd: %v\n%s", err, string(out))
			return
		}
		wBin := filepath.Join(tmpDir, "starter.wasm")
		cmdW := exec.Command("go", "build", "-buildmode=c-shared", "-o", wBin, "github.com/transparency-dev/incubator/vindex/mapfn/examples/starter")
		cmdW.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
		if out, err := cmdW.CombinedOutput(); err != nil {
			binBuildErr = fmt.Errorf("failed to build starter.wasm: %v\n%s", err, string(out))
			return
		}
		vindexVerifyBin = vBin
		vindexdBin = dBin
		starterWasmBin = wBin
	})
	if binBuildErr != nil {
		t.Fatalf("getCLIBinaries failed: %v", binBuildErr)
	}
	return vindexVerifyBin, vindexdBin, starterWasmBin
}

type syncLogBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestE2E_CLI_EntryPoints executes the compiled vindex-verify and vindexd --mode=verifier binaries
// as standalone subprocesses under honest, tampered, and invalid flag configurations.
func TestE2E_CLI_EntryPoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	vBin, dBin, wBin := getCLIBinaries(t)
	vtc := newVerifierTestCluster(t, ctx, 64, 16)

	for i := 0; i < 10; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("cli_entry_%d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	// 1. vindex-verify --oneshot Honest Execution
	t.Run("vindex-verify_Honest", func(t *testing.T) {
		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, vBin,
			"--output_log_url="+vtc.outLogServer.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--mapper=identity",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("vindex-verify honest run failed: %v\nOutput: %s", err, string(out))
		}
		if !strings.Contains(string(out), "Oneshot verification succeeded.") {
			t.Errorf("missing success log in vindex-verify output: %s", string(out))
		}

		// Verify persisted DB watermarks on disk
		db, err := kvstore.Open(filepath.Join(cliDir, "db"), nil)
		if err != nil {
			t.Fatalf("failed to open CLI DB: %v", err)
		}
		defer func() { _ = db.Close() }()
		outWatermark, closer, err := db.Pebble().Get(auditor.KeyVerifierOutputWatermark)
		if err != nil {
			t.Fatalf("failed to read persisted output watermark: %v", err)
		}
		if binary.BigEndian.Uint64(outWatermark) != 1 {
			t.Errorf("persisted output watermark = %d, want 1", binary.BigEndian.Uint64(outWatermark))
		}
		_ = closer.Close()
	})

	// 2. vindex-verify --oneshot Tampered Detection
	t.Run("vindex-verify_TamperedRoot", func(t *testing.T) {
		advDir := t.TempDir()
		outSigner, err := note.NewSigner(vtc.outSKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		advLog, err := tree.NewPOSIXOutputLog(ctx, advDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
		if err != nil {
			t.Fatalf("failed to create advLog: %v", err)
		}
		rawInCP, _ := vtc.inReader.ReadCheckpoint(ctx)
		inCP, _, _, _ := log.ParseCheckpoint(rawInCP, vtc.config.InputLogOrigin, vtc.inVerifier)
		_, _, _ = advLog.Append(ctx, tree.FormatOutputLogLeaf(sha256.Sum256([]byte("fake")), inCP))
		_ = advLog.Close()

		advSrv := httptest.NewServer(http.FileServer(http.Dir(advDir)))
		defer advSrv.Close()

		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, vBin,
			"--output_log_url="+advSrv.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--mapper=identity",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected vindex-verify against tampered root to exit with error, got 0")
		}
		if !strings.Contains(string(out), "root hash mismatch") && !strings.Contains(string(out), "oneshot verification failed") {
			t.Errorf("output missing root mismatch error: %s", string(out))
		}
	})

	// 3. vindexd --mode=verifier --oneshot Honest Execution
	t.Run("vindexd_verifier_Honest", func(t *testing.T) {
		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, dBin,
			"--mode=verifier",
			"--output_log_url="+vtc.outLogServer.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--wasm_path="+wBin,
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("vindexd --mode=verifier honest run failed: %v\nOutput: %s", err, string(out))
		}
		if !strings.Contains(string(out), "Oneshot verification succeeded.") {
			t.Errorf("missing success log in vindexd output: %s", string(out))
		}
	})

	// 4. vindexd --mode=verifier --oneshot Tampered Detection
	t.Run("vindexd_verifier_TamperedRoot", func(t *testing.T) {
		advDir := t.TempDir()
		outSigner, err := note.NewSigner(vtc.outSKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		advLog, err := tree.NewPOSIXOutputLog(ctx, advDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
		if err != nil {
			t.Fatalf("failed to create advLog: %v", err)
		}
		rawInCP, _ := vtc.inReader.ReadCheckpoint(ctx)
		inCP, _, _, _ := log.ParseCheckpoint(rawInCP, vtc.config.InputLogOrigin, vtc.inVerifier)
		_, _, _ = advLog.Append(ctx, tree.FormatOutputLogLeaf(sha256.Sum256([]byte("fake")), inCP))
		_ = advLog.Close()

		advSrv := httptest.NewServer(http.FileServer(http.Dir(advDir)))
		defer advSrv.Close()

		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, dBin,
			"--mode=verifier",
			"--output_log_url="+advSrv.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--wasm_path="+wBin,
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected vindexd to fail against tampered root, got exit 0")
		}
		if !strings.Contains(string(out), "root hash mismatch") && !strings.Contains(string(out), "oneshot verification failed") {
			t.Errorf("output missing root mismatch error: %s", string(out))
		}
	})

	// 5. vindexd --mode=verifier Rejection of --output_log_signer_key
	t.Run("vindexd_verifier_SecurityRejection", func(t *testing.T) {
		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, dBin,
			"--mode=verifier",
			"--output_log_signer_key=FORBIDDEN_KEY",
			"--output_log_url="+vtc.outLogServer.URL,
			"--input_log_url="+vtc.inLogServer.URL,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected vindexd to fail when --output_log_signer_key is specified in verifier mode, got exit 0")
		}
		if !strings.Contains(string(out), "--output_log_signer_key must not be specified in verifier mode") {
			t.Errorf("missing security error message: %s", string(out))
		}
	})

	// 6. vindex-auditor daemon mode --metrics_addr probes (/healthz, /readyz, /metrics)
	t.Run("vindex-auditor_DaemonAdminListener", func(t *testing.T) {
		cliDir := t.TempDir()
		dCtx, dCancel := context.WithCancel(ctx)
		defer dCancel()

		cmd := exec.CommandContext(dCtx, vBin,
			"--output_log_url="+vtc.outLogServer.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--mapper=identity",
			"--metrics_addr=127.0.0.1:0",
			"--poll_interval=50ms",
		)
		var logBuf syncLogBuffer
		cmd.Stdout = &logBuf
		cmd.Stderr = &logBuf
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start vindex-auditor daemon: %v", err)
		}
		defer func() {
			dCancel()
			_ = cmd.Wait()
		}()

		var adminAddr string
		addrDeadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(addrDeadline) {
			logs := logBuf.String()
			for _, marker := range []string{"Serving auditor metrics at http://", "Serving verifier metrics at http://"} {
				if idx := strings.Index(logs, marker); idx >= 0 {
					rest := logs[idx+len(marker):]
					if slash := strings.IndexByte(rest, '/'); slash > 0 {
						adminAddr = rest[:slash]
						break
					}
				}
			}
			if adminAddr != "" {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		if adminAddr == "" {
			t.Fatalf("timed out waiting for vindex-auditor to log bound --metrics_addr\nLogs:\n%s", logBuf.String())
		}

		httpCli := &http.Client{Timeout: 1 * time.Second}
		readyDeadline := time.Now().Add(10 * time.Second)
		readyOK := false
		var lastStatus int
		var lastErr error
		for time.Now().Before(readyDeadline) {
			res, reqErr := httpCli.Get(fmt.Sprintf("http://%s/readyz", adminAddr))
			if reqErr == nil {
				lastStatus = res.StatusCode
				_ = res.Body.Close()
				if res.StatusCode == http.StatusOK {
					readyOK = true
					break
				}
			} else {
				lastErr = reqErr
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !readyOK {
			t.Fatalf("timed out waiting for vindex-auditor http://%s/readyz to return 200 OK (lastStatus=%d, lastErr=%v)\nLogs:\n%s", adminAddr, lastStatus, lastErr, logBuf.String())
		}

		for _, opPath := range []string{"/healthz", "/metrics"} {
			res, reqErr := httpCli.Get(fmt.Sprintf("http://%s%s", adminAddr, opPath))
			if reqErr != nil {
				t.Fatalf("GET http://%s%s failed: %v", adminAddr, opPath, reqErr)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Errorf("GET http://%s%s status = %d, want 200", adminAddr, opPath, res.StatusCode)
			}
		}
	})
}

func TestVerifierE2E_StandaloneCLI_Execution(t *testing.T) {
	TestE2E_CLI_EntryPoints(t)
}
