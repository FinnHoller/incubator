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

package hammer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsSnapshot represents a point-in-time metrics summary.
type MetricsSnapshot struct {
	Timestamp            time.Time
	Elapsed              time.Duration
	LeavesWritten        uint64
	WriteQPS             float64
	CheckpointsCreated   uint64
	SequencerTreeSize    uint64
	ServingTreeSize      uint64
	IngestionLag         int64
	TotalReads           uint64
	ReadSuccesses        uint64
	ReadFailures         uint64
	ReadQPS              float64
	LatencyP50           time.Duration
	LatencyP90           time.Duration
	LatencyP99           time.Duration
	LatencyMax           time.Duration
	InvariantViolations  uint64
	ViolationSampleLines []string
}

// Analyzer aggregates telemetry and renders terminal dashboards.
type Analyzer struct {
	mu                  sync.Mutex
	sequencer           *Sequencer
	totalReads          uint64
	readSuccesses       uint64
	readFailures        uint64
	servingTreeSize     uint64
	invariantViolations uint64
	violations          []string
	latencies           []time.Duration
	recentLatencies     []time.Duration
	lastLeavesWritten   uint64
	lastTotalReads      uint64
	lastTickTime        time.Time
	startTime           time.Time
}

// NewAnalyzer creates a new Analyzer instance.
func NewAnalyzer(seq *Sequencer) *Analyzer {
	now := time.Now()
	return &Analyzer{
		sequencer:    seq,
		startTime:    now,
		lastTickTime: now,
	}
}

// SetSequencer attaches or updates the active sequencer.
func (a *Analyzer) SetSequencer(seq *Sequencer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sequencer = seq
}

// RecordReadSuccess records a successful verifiable read.
func (a *Analyzer) RecordReadSuccess(latency time.Duration, servingTreeSize uint64) {
	atomic.AddUint64(&a.totalReads, 1)
	atomic.AddUint64(&a.readSuccesses, 1)

	a.mu.Lock()
	if servingTreeSize > a.servingTreeSize {
		a.servingTreeSize = servingTreeSize
	}
	a.recentLatencies = append(a.recentLatencies, latency)
	a.latencies = append(a.latencies, latency)
	a.mu.Unlock()
}

// RecordReadError records a failed read attempt.
func (a *Analyzer) RecordReadError(err error, latency time.Duration) {
	atomic.AddUint64(&a.totalReads, 1)
	atomic.AddUint64(&a.readFailures, 1)

	a.mu.Lock()
	a.recentLatencies = append(a.recentLatencies, latency)
	a.latencies = append(a.latencies, latency)
	if len(a.violations) < 20 {
		a.violations = append(a.violations, fmt.Sprintf("ReadError: %v", err))
	}
	a.mu.Unlock()
}

// RecordInvariantViolation records a critical invariant assertion failure.
func (a *Analyzer) RecordInvariantViolation(msg string) {
	atomic.AddUint64(&a.invariantViolations, 1)

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.violations) < 20 {
		a.violations = append(a.violations, msg)
	}
}

// InvariantViolationCount returns the total number of invariant violations.
func (a *Analyzer) InvariantViolationCount() uint64 {
	return atomic.LoadUint64(&a.invariantViolations)
}

// Snapshot returns the current aggregated metrics.
func (a *Analyzer) Snapshot() MetricsSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(a.startTime)
	tickDelta := now.Sub(a.lastTickTime).Seconds()
	if tickDelta <= 0 {
		tickDelta = 1.0
	}

	var seqStats SequencerStats
	if a.sequencer != nil {
		seqStats = a.sequencer.Stats()
	}

	writeDelta := seqStats.LeavesWritten - a.lastLeavesWritten
	writeQPS := float64(writeDelta) / tickDelta
	a.lastLeavesWritten = seqStats.LeavesWritten

	totalReads := atomic.LoadUint64(&a.totalReads)
	readDelta := totalReads - a.lastTotalReads
	readQPS := float64(readDelta) / tickDelta
	a.lastTotalReads = totalReads
	a.lastTickTime = now

	p50, p90, p99, maxLat := calculatePercentiles(a.recentLatencies)
	a.recentLatencies = nil // Reset for next window

	ingestLag := int64(seqStats.LatestTreeSize) - int64(a.servingTreeSize)
	if ingestLag < 0 {
		ingestLag = 0
	}

	return MetricsSnapshot{
		Timestamp:            now,
		Elapsed:              elapsed,
		LeavesWritten:        seqStats.LeavesWritten,
		WriteQPS:             writeQPS,
		CheckpointsCreated:   seqStats.CheckpointsCreated,
		SequencerTreeSize:    seqStats.LatestTreeSize,
		ServingTreeSize:      a.servingTreeSize,
		IngestionLag:         ingestLag,
		TotalReads:           totalReads,
		ReadSuccesses:        atomic.LoadUint64(&a.readSuccesses),
		ReadFailures:         atomic.LoadUint64(&a.readFailures),
		ReadQPS:              readQPS,
		LatencyP50:           p50,
		LatencyP90:           p90,
		LatencyP99:           p99,
		LatencyMax:           maxLat,
		InvariantViolations:  atomic.LoadUint64(&a.invariantViolations),
		ViolationSampleLines: append([]string(nil), a.violations...),
	}
}

func calculatePercentiles(lats []time.Duration) (p50, p90, p99, max time.Duration) {
	if len(lats) == 0 {
		return 0, 0, 0, 0
	}
	sorted := make([]time.Duration, len(lats))
	copy(sorted, lats)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	n := len(sorted)
	p50 = sorted[n*50/100]
	p90 = sorted[n*90/100]
	p99 = sorted[n*99/100]
	max = sorted[n-1]
	return
}

// RunDashboard periodically prints live terminal status updates until ctx is cancelled.
func (a *Analyzer) RunDashboard(ctx context.Context, refreshInterval time.Duration) {
	if refreshInterval <= 0 {
		refreshInterval = 1 * time.Second
	}
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := a.Snapshot()
			a.renderLine(snap)
		}
	}
}

func (a *Analyzer) renderLine(s MetricsSnapshot) {
	status := "HEALTHY"
	if s.InvariantViolations > 0 {
		status = fmt.Sprintf("FAIL (%d Invariant Violations)", s.InvariantViolations)
	} else if s.ReadFailures > 0 {
		status = fmt.Sprintf("WARN (%d Errors)", s.ReadFailures)
	}

	fmt.Printf("[%04.0fs] Status: %-10s | Writes: %6.1f/s (Tot: %d, Tree: %d) | Reads: %6.1f/s (Tot: %d, Ok: %d, Err: %d) | Lag: %d | Lat: P50=%v P90=%v P99=%v\n",
		s.Elapsed.Seconds(),
		status,
		s.WriteQPS, s.LeavesWritten, s.SequencerTreeSize,
		s.ReadQPS, s.TotalReads, s.ReadSuccesses, s.ReadFailures,
		s.IngestionLag,
		s.LatencyP50.Round(time.Microsecond),
		s.LatencyP90.Round(time.Microsecond),
		s.LatencyP99.Round(time.Microsecond),
	)
}

// RunStats contains the finalized metrics of a completed hammer run.
type RunStats struct {
	Duration            time.Duration
	LeavesWritten       uint64
	InputLogSize        uint64
	WriteQPS            float64
	CheckpointsCreated  uint64
	ServingTreeSize     uint64
	TotalReads          uint64
	ReadSuccesses       uint64
	ReadFailures        uint64
	ReadQPS             float64
	LatencyP50          time.Duration
	LatencyP90          time.Duration
	LatencyP99          time.Duration
	LatencyMax          time.Duration
	InvariantViolations uint64
	ViolationSamples    []string
}

// ExportStats returns a complete RunStats snapshot of the hammer execution.
func (a *Analyzer) ExportStats() RunStats {
	a.mu.Lock()
	totalLat := append([]time.Duration(nil), a.latencies...)
	violations := append([]string(nil), a.violations...)
	servingSize := a.servingTreeSize
	a.mu.Unlock()

	dur := time.Since(a.startTime)
	secs := dur.Seconds()

	var seqStats SequencerStats
	if a.sequencer != nil {
		seqStats = a.sequencer.Stats()
	}

	totReads := atomic.LoadUint64(&a.totalReads)
	totSuccess := atomic.LoadUint64(&a.readSuccesses)
	totFails := atomic.LoadUint64(&a.readFailures)
	invViolations := atomic.LoadUint64(&a.invariantViolations)

	var writeQPS, readQPS float64
	if secs > 0 {
		writeQPS = float64(seqStats.LeavesWritten) / secs
		readQPS = float64(totReads) / secs
	}

	p50, p90, p99, maxLat := calculatePercentiles(totalLat)

	return RunStats{
		Duration:            dur,
		LeavesWritten:       seqStats.LeavesWritten,
		InputLogSize:        seqStats.LatestTreeSize,
		WriteQPS:            writeQPS,
		CheckpointsCreated:  seqStats.CheckpointsCreated,
		ServingTreeSize:     servingSize,
		TotalReads:          totReads,
		ReadSuccesses:       totSuccess,
		ReadFailures:        totFails,
		ReadQPS:             readQPS,
		LatencyP50:          p50,
		LatencyP90:          p90,
		LatencyP99:          p99,
		LatencyMax:          maxLat,
		InvariantViolations: invViolations,
		ViolationSamples:    violations,
	}
}

// PrintSummary prints a comprehensive end-of-run summary report.
func (a *Analyzer) PrintSummary() {
	stats := a.ExportStats()

	fmt.Println("\n========================== HAMMER RUN SUMMARY ==========================")
	fmt.Printf("Duration:               %v\n", stats.Duration.Round(time.Millisecond))
	fmt.Printf("Leaves Written:         %d (%.1f writes/sec)\n", stats.LeavesWritten, stats.WriteQPS)
	fmt.Printf("Checkpoints Produced:   %d\n", stats.CheckpointsCreated)
	fmt.Printf("Input Log Tree Size:    %d\n", stats.InputLogSize)
	fmt.Printf("Serving Tree Size:      %d\n", stats.ServingTreeSize)
	fmt.Printf("Total Read Lookups:     %d (%.1f reads/sec)\n", stats.TotalReads, stats.ReadQPS)
	fmt.Printf("Successful Reads:       %d\n", stats.ReadSuccesses)
	fmt.Printf("Failed Reads:           %d\n", stats.ReadFailures)
	fmt.Printf("Latency Overall:        P50=%v  P90=%v  P99=%v  Max=%v\n",
		stats.LatencyP50.Round(time.Microsecond),
		stats.LatencyP90.Round(time.Microsecond),
		stats.LatencyP99.Round(time.Microsecond),
		stats.LatencyMax.Round(time.Microsecond),
	)
	fmt.Printf("Invariant Violations:   %d\n", stats.InvariantViolations)

	if len(stats.ViolationSamples) > 0 {
		fmt.Println("\nViolation / Error Samples:")
		for i, v := range stats.ViolationSamples {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(stats.ViolationSamples)-10)
				break
			}
			fmt.Printf("  - %s\n", strings.TrimSpace(v))
		}
	}
	fmt.Println("========================================================================")
}
