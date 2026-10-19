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

package hammer_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/hammer"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
)

type benchResult struct {
	Name                string
	Leaves              uint64
	Duration            time.Duration
	Throughput          float64
	ReadQPS             float64
	SuccessRate         float64
	P50Latency          time.Duration
	P90Latency          time.Duration
	P99Latency          time.Duration
	MaxLatency          time.Duration
	InvariantViolations uint64
	DBSizeBytes         int64
	TileCacheSizeBytes  int64
}

func dirSize(path string) int64 {
	var size int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				size += info.Size()
			}
		}
		return nil
	})
	return size
}

func runBenchmarkScenario(t *testing.T, name string, numLeaves uint64, readQPS float64, format hammer.LeafFormat, ctMin, ctMax int) benchResult {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rootDir := t.TempDir()
	posixDir := filepath.Join(rootDir, "posix_inlog")
	pebbleDir := filepath.Join(rootDir, "pebble_db")
	mptDir := filepath.Join(rootDir, "mpt_tree")
	outLogDir := filepath.Join(rootDir, "outlog")
	tileCacheDir := filepath.Join(rootDir, "tilecache")

	for _, d := range []string{posixDir, pebbleDir, mptDir, outLogDir, tileCacheDir} {
		_ = os.MkdirAll(d, 0o755)
	}

	// 1. Setup Generator & Sequencer
	genCfg := hammer.GeneratorConfig{
		Distribution: hammer.DistZipf,
		NumKeys:      10000,
		ZipfS:        1.2,
		ZipfV:        1.0,
		Seed:         42,
		LeafFormat:   format,
		CTMinDomains: ctMin,
		CTMaxDomains: ctMax,
	}
	generator := hammer.NewGenerator(genCfg)
	queue := hammer.NewCheckpointQueue()

	seqCfg := hammer.DefaultSequencerConfig(posixDir)
	seqCfg.BatchSize = 256
	seqCfg.BatchTimeout = 5 * time.Millisecond
	seqCfg.CheckpointInterval = 50 * time.Millisecond
	seqCfg.WriteRate = 0 // unconstrained
	seqCfg.WriteGoal = numLeaves

	sequencer, err := hammer.NewSequencer(ctx, seqCfg, generator, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = sequencer.Close(ctx) }()

	// 2. Setup Drip Server
	srvCfg := hammer.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StorageDir: posixDir,
		DripRate:   50.0,
		BurstSize:  5,
	}
	dripServer := hammer.NewDripServer(srvCfg, queue)
	if err := dripServer.Start(ctx); err != nil {
		t.Fatalf("dripServer.Start failed: %v", err)
	}
	defer func() { _ = dripServer.Close(ctx) }()

	// 3. Setup VIndex Daemon components
	db, err := kvstore.Open(pebbleDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	mptMgr, err := mpt.Open(mptDir)
	if err != nil {
		t.Fatalf("mpt.Open failed: %v", err)
	}
	defer func() { _ = mptMgr.Close() }()

	outLog := newTestOutputLog(t, "example.com/vindex/output")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	pub.SetInputOrigin(sequencer.Origin())
	const chunkSize = 65536
	idxer := kvstore.NewKVIndexer(db, chunkSize)

	inputURL, err := url.Parse(dripServer.URL())
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}

	fetcher, err := hammer.NewTiledFetcher(inputURL, sequencer.Verifier(), sequencer.Origin(), http.DefaultClient)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}

	var mapper ingest.LeafMapper
	if format == hammer.FormatCT {
		mapper = &ctMapper{}
	} else {
		mapper = &identityMapper{}
	}

	tileCache, err := ingest.NewManagedTileCache(tileCacheDir, 0)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	tileReaper := ingest.NewTileReaper(db, mptMgr, tileCache)
	go func() {
		_ = tileReaper.Run(ctx, 1*time.Second)
	}()

	pipeline := ingest.NewPipeline(fetcher, tileCache, mapper, 0)

	// 4. Start Read Server
	readSrv := server.NewReadServer(db, mptMgr, pub, chunkSize)
	readMux := http.NewServeMux()
	readSrv.RegisterRoutes(readMux)
	vindexHTTP := httptest.NewServer(readMux)
	defer vindexHTTP.Close()

	// 5. Start Analyzer & Reader Pool (if readQPS > 0)
	analyzer := hammer.NewAnalyzer(sequencer)
	if readQPS > 0 {
		readerCfg := hammer.ReaderConfig{
			VIndexURL:         vindexHTTP.URL,
			NumWorkers:        8,
			MaxReadQPS:        readQPS,
			OutputLogOrigin:   "example.com/vindex/output",
			OutputLogVerifier: outLog.verifier,
			InputLogOrigin:    sequencer.Origin(),
			InputLogVerifier:  sequencer.Verifier(),
			HotKeyRatio:       0.60,
			UniformRatio:      0.25,
			NonInclusionRatio: 0.10,
			PaginationRatio:   0.05,
			PageSize:          100,
		}
		readers, err := hammer.NewReaderPool(readerCfg, generator, analyzer)
		if err != nil {
			t.Fatalf("NewReaderPool failed: %v", err)
		}
		go readers.Start(ctx)
	}

	// 6. Run Sequencer in background
	go func() {
		_ = sequencer.RunLoop(ctx)
	}()

	startTime := time.Now()

	// 7. Ingestion & Indexing Loop until numLeaves reached
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	var indexedLeaves uint64
Loop:
	for indexedLeaves < numLeaves {
		select {
		case <-ctx.Done():
			break Loop
		case <-ticker.C:
			targetCP, err := fetcher.Checkpoint(ctx)
			if err != nil || targetCP == nil {
				continue
			}

			kvSize, _ := db.GetUint64(kvstore.KeyMetaKVSize)
			if kvSize < targetCP.Size {
				toIndex := targetCP.Size
				if toIndex > numLeaves {
					toIndex = numLeaves
				}
				batchChan, errChan := pipeline.StreamBatches(ctx, kvSize, toIndex)
				for batch := range batchChan {
					res, err := idxer.IndexBatch(ctx, batch, targetCP)
					if err != nil {
						t.Fatalf("IndexBatch failed: %v", err)
					}
					logCP := &log.Checkpoint{
						Origin: targetCP.Origin,
						Size:   res.NewKVSize,
						Hash:   targetCP.Hash[:],
					}
					_, err = pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, logCP, targetCP.Raw)
					if err != nil {
						t.Fatalf("PublishKeyBatch failed: %v", err)
					}
					indexedLeaves = res.NewKVSize
				}
				if err := <-errChan; err != nil {
					t.Fatalf("StreamBatches error: %v", err)
				}
			}
		}
	}

	duration := time.Since(startTime)
	throughput := float64(numLeaves) / duration.Seconds()

	snap := analyzer.Snapshot()
	var successRate float64
	if snap.TotalReads > 0 {
		successRate = float64(snap.ReadSuccesses) / float64(snap.TotalReads) * 100.0
	} else {
		successRate = 100.0
	}

	res := benchResult{
		Name:                name,
		Leaves:              numLeaves,
		Duration:            duration,
		Throughput:          throughput,
		ReadQPS:             snap.ReadQPS,
		SuccessRate:         successRate,
		P50Latency:          snap.LatencyP50,
		P90Latency:          snap.LatencyP90,
		P99Latency:          snap.LatencyP99,
		MaxLatency:          snap.LatencyMax,
		InvariantViolations: snap.InvariantViolations,
		DBSizeBytes:         dirSize(pebbleDir),
		TileCacheSizeBytes:  dirSize(tileCacheDir),
	}

	return res
}

type ctMapper struct{}

func (m *ctMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	lines := strings.Split(strings.TrimSpace(string(leaf)), "\n")
	seen := make(map[[32]byte]bool)
	var entries []ingest.MappedEntry
	for _, l := range lines {
		parts := strings.Split(l, ".")
		if len(parts) >= 2 {
			etld1 := strings.Join(parts[len(parts)-2:], ".")
			kh := sha256.Sum256([]byte(etld1))
			if !seen[kh] {
				seen[kh] = true
				entries = append(entries, ingest.MappedEntry{Key: etld1, KeyHash: kh})
			}
		}
	}
	return entries, nil
}

func (m *ctMapper) Close(_ context.Context) error { return nil }

func TestBenchmark_Synthetic1to1_Suite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark suite in short mode")
	}

	const numLeaves = 2000
	qpsLevels := []float64{0, 1, 10, 100}

	var results []benchResult
	for _, qps := range qpsLevels {
		name := fmt.Sprintf("1-to-1 Synthetic @ %.0f Read QPS", qps)
		t.Logf("Starting benchmark: %s (%d leaves)...", name, numLeaves)
		res := runBenchmarkScenario(t, name, numLeaves, qps, hammer.FormatRaw, 1, 1)
		results = append(results, res)
		t.Logf("Completed %s: Duration=%v, Throughput=%.1f leaves/s, P50=%v, P99=%v, Violations=%d",
			name, res.Duration, res.Throughput, res.P50Latency, res.P99Latency, res.InvariantViolations)
	}

	// CT-style 1-to-N fanout @ 100 QPS
	t.Logf("Starting benchmark: CT-Style 1-to-N @ 100 Read QPS (%d leaves)...", numLeaves)
	ctRes := runBenchmarkScenario(t, "CT-Style 1-to-N @ 100 Read QPS", numLeaves, 100, hammer.FormatCT, 1, 5)
	results = append(results, ctRes)
	t.Logf("Completed CT-Style: Duration=%v, Throughput=%.1f leaves/s, P50=%v, P99=%v, Violations=%d",
		ctRes.Duration, ctRes.Throughput, ctRes.P50Latency, ctRes.P99Latency, ctRes.InvariantViolations)

	fmt.Println("\n=========================================================================================================")
	fmt.Println("VINDEX ZERO-WAL BENCHMARK RESULTS")
	fmt.Println("=========================================================================================================")
	for _, r := range results {
		fmt.Printf("%-35s | Duration: %8.2fs | Throughput: %9.1f leaves/s | Read QPS: %5.1f | P50: %8v | P99: %8v | Violations: %d | DB Size: %6.2f MB | Cache Size: %6.2f MB\n",
			r.Name, r.Duration.Seconds(), r.Throughput, r.ReadQPS, r.P50Latency, r.P99Latency, r.InvariantViolations,
			float64(r.DBSizeBytes)/(1024*1024), float64(r.TileCacheSizeBytes)/(1024*1024))
	}
	fmt.Println("=========================================================================================================")
}
