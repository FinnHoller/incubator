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
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

// trackingMapper wraps ingest.LeafMapper and tracks which leaf indices were mapped.
type trackingMapper struct {
	mu           sync.Mutex
	mappedLeaves []string
	callCount    int
}

func (m *trackingMapper) MapLeaf(ctx context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	m.mu.Lock()
	m.callCount++
	m.mappedLeaves = append(m.mappedLeaves, string(leaf))
	m.mu.Unlock()
	if mpt.ValidateCanonicalKey(leaf) == nil {
		return []ingest.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	}
	h := sha256.Sum256(leaf)
	hexKey := hex.EncodeToString(h[:])
	return []ingest.MappedEntry{{Key: hexKey, KeyHash: sha256.Sum256([]byte(hexKey))}}, nil
}

func (m *trackingMapper) Close(ctx context.Context) error {
	return nil
}

func (m *trackingMapper) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func (m *trackingMapper) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mappedLeaves = nil
	m.callCount = 0
}

// trackingInputLog wraps memoryInputLog and tracks requested leaf index ranges in FetchTiles.
type trackingInputLog struct {
	*memoryInputLog
	mu            sync.Mutex
	fetchedRanges [][2]uint64
	fetchedLeaves []uint64
}

func newTrackingInputLog(inLog *memoryInputLog) *trackingInputLog {
	return &trackingInputLog{
		memoryInputLog: inLog,
	}
}

func (t *trackingInputLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	t.mu.Lock()
	t.fetchedRanges = append(t.fetchedRanges, [2]uint64{startLeafIdx, startLeafIdx + count})
	for i := startLeafIdx; i < startLeafIdx+count; i++ {
		t.fetchedLeaves = append(t.fetchedLeaves, i)
	}
	t.mu.Unlock()
	return t.memoryInputLog.FetchTiles(ctx, startLeafIdx, count)
}

func (t *trackingInputLog) ResetTracking() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fetchedRanges = nil
	t.fetchedLeaves = nil
}

func (t *trackingInputLog) GetFetchedLeaves() []uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]uint64(nil), t.fetchedLeaves...)
}

// parseMetricsOutput extracts named metrics from Prometheus text exposition.
func parseMetricsOutput(body string) map[string]float64 {
	results := make(map[string]float64)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := parts[0]
			if val, err := strconv.ParseFloat(parts[1], 64); err == nil {
				results[name] = val
			}
		}
	}
	return results
}

// TestAdv_PersistenceNoDuplicateIndexing empirically tests:
// Stop verifier, restart on disk DB, ensure it resumes from watermarks without duplicate indexing.
func TestAdv_PersistenceNoDuplicateIndexing(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	trackerFetcher := newTrackingInputLog(h.inLog)
	trackerMapper := &trackingMapper{}

	dbDir := t.TempDir()
	mptDir := t.TempDir()

	// Prepare 15 leaves in total
	var rawLeaves [][]byte
	for i := 0; i < 15; i++ {
		leaf := []byte(fmt.Sprintf("disk-persist-leaf-%04d", i))
		rawLeaves = append(rawLeaves, leaf)
		trackerFetcher.AppendLeaf(leaf)
	}

	// Leaf 0 commits to first 5 leaves [0..5)
	root0 := computeExpectedMPTRoot(t, rawLeaves[:5], trackerMapper)
	cp0, err := trackerFetcher.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint(5) failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   trackerFetcher,
		MapFn:             trackerMapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
	}

	// --- Phase 1: First Run ---
	v1, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}

	trackerMapper.Reset()
	trackerFetcher.ResetTracking()

	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}

	st1 := v1.Status()
	if st1.VerifiedOutputSize != 1 || st1.VerifiedInputSize != 5 || st1.LastVerifiedRoot != root0 {
		t.Fatalf("v1 status incorrect: %+v", st1)
	}

	// Assert that leaves 0..4 were mapped
	mappedCount1 := trackerMapper.GetCallCount()
	if mappedCount1 != 5 {
		t.Fatalf("v1 mapped %d leaves, want 5", mappedCount1)
	}
	fetched1 := trackerFetcher.GetFetchedLeaves()
	if len(fetched1) != 5 {
		t.Fatalf("v1 fetched %d leaves, want 5", len(fetched1))
	}

	// Close v1
	if err := v1.Close(); err != nil {
		t.Fatalf("v1 Close failed: %v", err)
	}

	// --- Phase 2: Add OutputLog Leaf 1 (leaves 5..10) and Restart on Disk DB ---
	root1 := computeExpectedMPTRoot(t, rawLeaves[:10], trackerMapper)
	cp1, err := trackerFetcher.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint(10) failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root1, cp1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	// Reset trackers to monitor ONLY what happens during the restarted session
	trackerMapper.Reset()
	trackerFetcher.ResetTracking()

	v2, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}

	// Verify watermarks were recovered from disk before running VerifyOnce
	st2Initial := v2.Status()
	if st2Initial.VerifiedOutputSize != 1 {
		t.Fatalf("v2 recovered VerifiedOutputSize = %d, want 1", st2Initial.VerifiedOutputSize)
	}
	if st2Initial.VerifiedInputSize != 5 {
		t.Fatalf("v2 recovered VerifiedInputSize = %d, want 5", st2Initial.VerifiedInputSize)
	}
	if st2Initial.LastVerifiedRoot != root0 {
		t.Fatalf("v2 recovered LastVerifiedRoot = %x, want %x", st2Initial.LastVerifiedRoot, root0)
	}

	// Run verification on v2
	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}

	st2Updated := v2.Status()
	if st2Updated.VerifiedOutputSize != 2 || st2Updated.VerifiedInputSize != 10 || st2Updated.LastVerifiedRoot != root1 {
		t.Fatalf("v2 status after sync incorrect: %+v", st2Updated)
	}

	// CRITICAL ASSERTION: Ensure NO DUPLICATE INDEXING or duplicate mapping occurred
	mappedCount2 := trackerMapper.GetCallCount()
	if mappedCount2 != 5 {
		t.Fatalf("v2 mapped %d leaves, want exactly 5 new leaves (no duplicates of leaves 0..4)", mappedCount2)
	}

	fetched2 := trackerFetcher.GetFetchedLeaves()
	for _, idx := range fetched2 {
		if idx < 5 {
			t.Fatalf("DUPLICATE FETCH DETECTED: leaf index %d was fetched during resume (watermark was 5)", idx)
		}
		if idx >= 10 {
			t.Fatalf("OUT-OF-BOUNDS FETCH DETECTED: leaf index %d was fetched beyond target size 10", idx)
		}
	}

	// --- Phase 3: Zero-Delta Restart (already caught up) ---
	if err := v2.Close(); err != nil {
		t.Fatalf("v2 Close failed: %v", err)
	}

	trackerMapper.Reset()
	trackerFetcher.ResetTracking()

	v3, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v3 New failed: %v", err)
	}
	defer func() { _ = v3.Close() }()

	st3 := v3.Status()
	if st3.VerifiedOutputSize != 2 || st3.VerifiedInputSize != 10 {
		t.Fatalf("v3 recovered status incorrect: %+v", st3)
	}

	// Calling VerifyOnce with no new output log leaves must do ZERO fetches and ZERO mappings
	if err := v3.VerifyOnce(ctx); err != nil {
		t.Fatalf("v3 VerifyOnce failed on zero delta: %v", err)
	}

	if count := trackerMapper.GetCallCount(); count != 0 {
		t.Fatalf("zero-delta run mapped %d leaves, want 0", count)
	}
	if fetched := trackerFetcher.GetFetchedLeaves(); len(fetched) != 0 {
		t.Fatalf("zero-delta run fetched %d leaves, want 0", len(fetched))
	}
}

// TestAdv_PrometheusMetricsScraping verifies vindex_auditor_root_mismatch and
// vindex_auditor_root_mismatches_total via Prometheus HTTP exposition scraping.
func TestAdv_PrometheusMetricsScraping(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	h.inLog.AppendLeaf([]byte("metrics-test-leaf-0"))

	// Format OutputLog leaf 0 with mismatched root
	wrongRoot := sha256.Sum256([]byte("intentionally-wrong-mpt-root"))
	cp, err := h.inLog.SignCheckpoint(1)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(wrongRoot, cp)); err != nil {
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

	metricsHandler := promhttp.Handler()

	// Scrape metrics before mismatch
	recBefore := httptest.NewRecorder()
	metricsHandler.ServeHTTP(recBefore, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recBefore.Code != http.StatusOK {
		t.Fatalf("GET /metrics before mismatch status = %d, want 200", recBefore.Code)
	}
	mBefore := parseMetricsOutput(recBefore.Body.String())

	gaugeBefore, ok := mBefore["vindex_auditor_root_mismatch"]
	if !ok {
		t.Fatal("metric 'vindex_auditor_root_mismatch' not found in scraped /metrics output before mismatch")
	}
	if gaugeBefore != 0.0 {
		t.Fatalf("vindex_auditor_root_mismatch = %v before mismatch, want 0.0", gaugeBefore)
	}

	counterBefore := mBefore["vindex_auditor_root_mismatches_total"]

	// Trigger mismatch via VerifyOnce
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}

	// Scrape metrics after mismatch
	recAfter := httptest.NewRecorder()
	metricsHandler.ServeHTTP(recAfter, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recAfter.Code != http.StatusOK {
		t.Fatalf("GET /metrics after mismatch status = %d, want 200", recAfter.Code)
	}
	mAfter := parseMetricsOutput(recAfter.Body.String())

	gaugeAfter, ok := mAfter["vindex_auditor_root_mismatch"]
	if !ok {
		t.Fatal("metric 'vindex_auditor_root_mismatch' not found in scraped /metrics output after mismatch")
	}
	if gaugeAfter != 1.0 {
		t.Fatalf("vindex_auditor_root_mismatch = %v after mismatch, want 1.0", gaugeAfter)
	}

	counterAfter, ok := mAfter["vindex_auditor_root_mismatches_total"]
	if !ok {
		t.Fatal("metric 'vindex_auditor_root_mismatches_total' not found in scraped /metrics output after mismatch")
	}
	if counterAfter != counterBefore+1 {
		t.Fatalf("vindex_auditor_root_mismatches_total = %v, want %v (incremented by 1)", counterAfter, counterBefore+1)
	}
}

// TestAdv_ConcurrentHealthCheckStress tests concurrent verification and health probing.
// HealthCheck() only inspects isHalted and haltErr, which are synchronized via stateMu.
func TestAdv_ConcurrentHealthCheckStress(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("stress-leaf-%d", i)))
	}
	leaves := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves[i] = []byte(fmt.Sprintf("stress-leaf-%d", i))
	}
	root0 := computeExpectedMPTRoot(t, leaves, h.mapper)
	cp0, _ := h.inLog.SignCheckpoint(5)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp0))

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
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	var wg sync.WaitGroup
	// 10 concurrent callers of VerifyOnce
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = v.VerifyOnce(ctx)
		}()
	}
	// 10 concurrent callers of HealthCheck
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = v.HealthCheck()
		}()
	}
	wg.Wait()

	if err := v.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
}

// TestAdv_StatusDataRace verifies there is no data race between VerifyOnce() updating
// verifiedInputSize / verifiedOutputSize and Status() reading them.
func TestAdv_StatusDataRace(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("status-race-leaf-%d", i)))
	}
	leaves := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves[i] = []byte(fmt.Sprintf("status-race-leaf-%d", i))
	}
	root0 := computeExpectedMPTRoot(t, leaves, h.mapper)
	cp0, _ := h.inLog.SignCheckpoint(5)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp0))

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
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	var wg sync.WaitGroup
	// Concurrent callers of VerifyOnce and Status()
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = v.VerifyOnce(ctx)
		}()
		go func() {
			defer wg.Done()
			_ = v.Status()
		}()
	}
	wg.Wait()
}
