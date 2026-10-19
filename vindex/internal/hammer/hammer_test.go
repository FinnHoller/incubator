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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/hammer"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"golang.org/x/mod/sumdb/note"
)

func TestGenerator_Distributions(t *testing.T) {
	t.Run("Zipfian Skew", func(t *testing.T) {
		cfg := hammer.GeneratorConfig{
			Distribution: hammer.DistZipf,
			NumKeys:      100,
			ZipfS:        1.5,
			ZipfV:        1.0,
			Seed:         12345,
			LeafFormat:   hammer.FormatRaw,
		}
		gen := hammer.NewGenerator(cfg)

		counts := make(map[string]int)
		for i := 0; i < 1000; i++ {
			entry := gen.NextLeaf()
			counts[entry.Key]++
		}

		// Top key should have significantly higher count than tail
		hotKey := hammer.KeyForID(0)
		if counts[hotKey] < 50 {
			t.Fatalf("expected hot key %s to have high count (>50), got %d", hotKey, counts[hotKey])
		}
	})

	t.Run("Uniform Distribution", func(t *testing.T) {
		cfg := hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      20,
			Seed:         54321,
			LeafFormat:   hammer.FormatRaw,
		}
		gen := hammer.NewGenerator(cfg)

		counts := make(map[string]int)
		for i := 0; i < 1000; i++ {
			entry := gen.NextLeaf()
			counts[entry.Key]++
		}

		if len(counts) != 20 {
			t.Fatalf("expected all 20 keys to be hit under uniform, got %d", len(counts))
		}
	})

	t.Run("NonInclusion Keys", func(t *testing.T) {
		cfg := hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      50,
			Seed:         999,
		}
		gen := hammer.NewGenerator(cfg)

		for i := 0; i < 20; i++ {
			nonKey, nonHash := gen.SampleNonInclusionKey()
			if nonHash != sha256.Sum256([]byte(nonKey)) {
				t.Fatalf("hash mismatch for non-inclusion key %s", nonKey)
			}
			// Must not match any valid key ID in [0, 50)
			for id := uint64(0); id < 50; id++ {
				if nonKey == hammer.KeyForID(id) {
					t.Fatalf("non-inclusion key %s matched existing key ID %d", nonKey, id)
				}
			}
		}
	})

	t.Run("SumDB Leaf Format", func(t *testing.T) {
		cfg := hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      10,
			Seed:         101,
			LeafFormat:   hammer.FormatSumDB,
		}
		gen := hammer.NewGenerator(cfg)
		entry := gen.NextLeaf()

		if len(entry.LeafData) == 0 {
			t.Fatal("empty leaf data generated")
		}
		var mod, ver, h string
		if _, err := fmt.Sscanf(string(entry.LeafData), "%s %s %s", &mod, &ver, &h); err != nil {
			t.Fatalf("failed to parse SumDB leaf format: %v (raw: %q)", err, string(entry.LeafData))
		}
	})

	t.Run("CT Leaf Format", func(t *testing.T) {
		cfg := hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      20,
			Seed:         202,
			LeafFormat:   hammer.FormatCT,
			CTMinDomains: 2,
			CTMaxDomains: 5,
		}
		gen := hammer.NewGenerator(cfg)
		entry := gen.NextLeaf()

		if len(entry.LeafData) == 0 {
			t.Fatal("empty leaf data generated")
		}
		lines := strings.Split(strings.TrimSpace(string(entry.LeafData)), "\n")
		if len(lines) < 2 || len(lines) > 5 {
			t.Fatalf("expected 2-5 lines, got %d (lines: %q)", len(lines), lines)
		}
		for _, line := range lines {
			if !strings.HasPrefix(line, "sub-") || !strings.Contains(line, ".domain-") || !strings.HasSuffix(line, ".com") {
				t.Fatalf("unexpected subdomain format: %q", line)
			}
		}

		key, keyHash := gen.SampleExistingKey()
		if !strings.HasPrefix(key, "domain-") || !strings.HasSuffix(key, ".com") {
			t.Fatalf("unexpected SampleExistingKey: %q", key)
		}
		if keyHash != sha256.Sum256([]byte(key)) {
			t.Fatalf("keyHash mismatch for %q", key)
		}
	})
}

func TestSequencer_AppendAndPublish(t *testing.T) {
	ctx := t.Context()
	tempDir := t.TempDir()

	genCfg := hammer.DefaultGeneratorConfig()
	genCfg.NumKeys = 100
	gen := hammer.NewGenerator(genCfg)

	queue := hammer.NewCheckpointQueue()
	seqCfg := hammer.DefaultSequencerConfig(tempDir)
	seqCfg.BatchSize = 10
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.CheckpointInterval = 100 * time.Millisecond

	seq, err := hammer.NewSequencer(ctx, seqCfg, gen, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() {
		_ = seq.Close(ctx)
	}()

	// Write 25 leaves
	for i := 0; i < 25; i++ {
		leaf := gen.NextLeaf()
		idx, rawCP, err := seq.WriteLeaf(ctx, leaf.LeafData)
		if err != nil {
			t.Fatalf("WriteLeaf %d failed: %v", i, err)
		}
		if idx != uint64(i) {
			t.Fatalf("expected leaf index %d, got %d", i, idx)
		}
		if len(rawCP) == 0 {
			t.Fatalf("empty checkpoint returned for leaf %d", i)
		}
	}

	stats := seq.Stats()
	if stats.LeavesWritten != 25 {
		t.Fatalf("stats.LeavesWritten = %d, want 25", stats.LeavesWritten)
	}
	if stats.LatestTreeSize != 25 {
		t.Fatalf("stats.LatestTreeSize = %d, want 25", stats.LatestTreeSize)
	}

	if queue.Len() == 0 {
		t.Fatal("expected checkpoints in queue")
	}

	latestCP, ok := queue.PeekLatest()
	if !ok || len(latestCP) == 0 {
		t.Fatal("failed to peek latest checkpoint")
	}

	parsed, _, _, err := log.ParseCheckpoint(latestCP, seq.Origin(), seq.Verifier())
	if err != nil {
		t.Fatalf("ParseCheckpoint failed: %v", err)
	}
	if parsed.Size != 25 {
		t.Fatalf("checkpoint size = %d, want 25", parsed.Size)
	}
}

func TestDripServer_DripAndBurst(t *testing.T) {
	ctx := t.Context()
	tempDir := t.TempDir()

	queue := hammer.NewCheckpointQueue()
	cp1 := []byte("example.com/hammer\n10\nhash1\n")
	cp2 := []byte("example.com/hammer\n20\nhash2\n")
	cp3 := []byte("example.com/hammer\n30\nhash3\n")

	queue.Enqueue(cp1)
	queue.Enqueue(cp2)
	queue.Enqueue(cp3)

	srvCfg := hammer.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StorageDir: tempDir,
		DripRate:   50.0,
		BurstSize:  1,
	}

	srv := hammer.NewDripServer(srvCfg, queue)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("DripServer.Start failed: %v", err)
	}
	defer func() {
		_ = srv.Close(ctx)
	}()

	// Wait for drip scheduler to pop
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(srv.URL() + "/checkpoint")
	if err != nil {
		t.Fatalf("GET /checkpoint failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /checkpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty checkpoint body")
	}
}

type testOutputLog struct {
	mu       sync.Mutex
	leaves   [][]byte
	origin   string
	signer   note.Signer
	verifier note.Verifier
}

func newTestOutputLog(t testing.TB, origin string) *testOutputLog {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("note.GenerateKey(%s) failed: %v", origin, err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("note.NewSigner(%s) failed: %v", origin, err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("note.NewVerifier(%s) failed: %v", origin, err)
	}
	return &testOutputLog{
		origin:   origin,
		signer:   signer,
		verifier: verifier,
	}
}

func (l *testOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	idx := uint64(len(l.leaves))
	l.leaves = append(l.leaves, leafData)
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	signedCP, err := note.Sign(&note.Note{Text: rawCP}, l.signer)
	if err != nil {
		return 0, nil, err
	}
	return idx, signedCP, nil
}

func (l *testOutputLog) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves)), nil
}

func (l *testOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("out of bounds")
	}
	return l.leaves[idx], nil
}

func (l *testOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return note.Sign(&note.Note{Text: rawCP}, l.signer)
}

func (l *testOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

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
		k := uint64(1) << (bits.Len(uint(n-1)) - 1)
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

type identityMapper struct{}

func (m *identityMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	if mpt.ValidateCanonicalKey(leaf) == nil {
		return []ingest.MappedEntry{{Key: string(leaf), KeyHash: sha256.Sum256(leaf)}}, nil
	}
	kh := sha256.Sum256(leaf)
	hexKey := hex.EncodeToString(kh[:])
	return []ingest.MappedEntry{{Key: hexKey, KeyHash: sha256.Sum256([]byte(hexKey))}}, nil
}

func (m *identityMapper) Close(_ context.Context) error { return nil }

func TestEndToEnd_HammerWithVIndex(t *testing.T) {
	ctx := t.Context()
	rootDir := t.TempDir()

	posixDir := filepath.Join(rootDir, "posix_inlog")
	pebbleDir := filepath.Join(rootDir, "pebble_db")
	mptDir := filepath.Join(rootDir, "mpt_tree")

	// 1. Setup Hammer Generator & Sequencer
	genCfg := hammer.GeneratorConfig{
		Distribution: hammer.DistZipf,
		NumKeys:      20,
		ZipfS:        1.3,
		ZipfV:        1.0,
		Seed:         42,
		LeafFormat:   hammer.FormatRaw,
	}
	generator := hammer.NewGenerator(genCfg)
	queue := hammer.NewCheckpointQueue()

	seqCfg := hammer.DefaultSequencerConfig(posixDir)
	seqCfg.BatchSize = 8
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.CheckpointInterval = 100 * time.Millisecond
	seqCfg.WriteRate = 200

	sequencer, err := hammer.NewSequencer(ctx, seqCfg, generator, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() {
		_ = sequencer.Close(ctx)
	}()

	// 2. Setup Drip Server
	srvCfg := hammer.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StorageDir: posixDir,
		DripRate:   50.0,
		BurstSize:  1,
	}
	dripServer := hammer.NewDripServer(srvCfg, queue)
	if err := dripServer.Start(ctx); err != nil {
		t.Fatalf("dripServer.Start failed: %v", err)
	}
	defer func() {
		_ = dripServer.Close(ctx)
	}()

	// 3. Write 50 initial leaves to the input log
	for i := 0; i < 50; i++ {
		leaf := generator.NextLeaf()
		_, _, err := sequencer.WriteLeaf(ctx, leaf.LeafData)
		if err != nil {
			t.Fatalf("WriteLeaf failed at %d: %v", i, err)
		}
	}

	// Wait for drip server to publish the latest checkpoint covering all 50 leaves
	for {
		if cp := dripServer.GetPublishedCheckpoint(); len(cp) > 0 {
			if p, _, _, err := log.ParseCheckpoint(cp, sequencer.Origin(), sequencer.Verifier()); err == nil && p.Size >= 50 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 4. Setup VIndex Daemon components (Storage, MPT, Ingest, Indexer, Publisher, Read Server)
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
	const chunkSize = 16
	idxer := kvstore.NewKVIndexer(db, chunkSize)

	inputURL, err := url.Parse(dripServer.URL())
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}

	fetcher, err := hammer.NewTiledFetcher(inputURL, sequencer.Verifier(), sequencer.Origin(), http.DefaultClient)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}

	mapper := &identityMapper{}
	tileCache, err := ingest.NewManagedTileCache(filepath.Join(rootDir, "tilecache"), 0)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	coord := coordinator.NewCoordinator(db, mptMgr, outLog, pub, idxer, fetcher, tileCache, mapper)
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("coord.Recover failed: %v", err)
	}
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("coord.SyncOnce failed: %v", err)
	}

	// Step 5: Start VIndex Read Server
	readSrv := server.NewReadServer(db, mptMgr, pub, chunkSize)
	readSrv.SetPrefixPolicy(func(prefix string) error {
		if len(prefix) < 3 {
			return fmt.Errorf("prefix %q shorter than 3 bytes", prefix)
		}
		return nil
	})
	readMux := http.NewServeMux()
	readSrv.RegisterRoutes(readMux)
	vindexHTTP := httptest.NewServer(readMux)
	defer vindexHTTP.Close()

	// Step 6: Start Hammer Analyzer & Reader Pool
	analyzer := hammer.NewAnalyzer(sequencer)

	readerCfg := hammer.ReaderConfig{
		VIndexURL:         vindexHTTP.URL,
		NumWorkers:        4,
		MaxReadQPS:        100,
		OutputLogOrigin:   "example.com/vindex/output",
		OutputLogVerifier: outLog.verifier,
		InputLogOrigin:    sequencer.Origin(),
		InputLogVerifier:  sequencer.Verifier(),
		HotKeyRatio:       0.50,
		UniformRatio:      0.25,
		NonInclusionRatio: 0.10,
		PaginationRatio:   0.15,
		PrefixRatio:       0.15,
		PageSize:          10,
	}

	readers, err := hammer.NewReaderPool(readerCfg, generator, analyzer)
	if err != nil {
		t.Fatalf("NewReaderPool failed: %v", err)
	}

	// Run reader workers concurrently for 300ms
	testCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()

	readers.Start(testCtx)

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

	t.Logf("Hammer E2E test completed: %d total reads, %d successes, %d failures, 0 invariant violations",
		snap.TotalReads, snap.ReadSuccesses, snap.ReadFailures)
}

func TestSequencer_WriteGoal(t *testing.T) {
	ctx := t.Context()
	tempDir := t.TempDir()

	genCfg := hammer.DefaultGeneratorConfig()
	gen := hammer.NewGenerator(genCfg)

	queue := hammer.NewCheckpointQueue()
	seqCfg := hammer.DefaultSequencerConfig(tempDir)
	seqCfg.BatchSize = 8
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.WriteRate = 0 // unconstrained tight loop
	seqCfg.WriteGoal = 25

	seq, err := hammer.NewSequencer(ctx, seqCfg, gen, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() {
		_ = seq.Close(ctx)
	}()

	if err := seq.RunLoop(ctx); err != nil {
		t.Fatalf("RunLoop failed: %v", err)
	}

	stats := seq.Stats()
	if stats.LeavesWritten != 25 {
		t.Fatalf("stats.LeavesWritten = %d, want 25", stats.LeavesWritten)
	}
	if stats.LatestTreeSize != 25 {
		t.Fatalf("stats.LatestTreeSize = %d, want 25", stats.LatestTreeSize)
	}

	latestCP, ok := queue.PeekLatest()
	if !ok {
		t.Fatal("expected published checkpoint in queue")
	}
	parsed, _, _, err := log.ParseCheckpoint(latestCP, seq.Origin(), seq.Verifier())
	if err != nil {
		t.Fatalf("ParseCheckpoint failed: %v", err)
	}
	if parsed.Size != 25 {
		t.Fatalf("checkpoint size = %d, want 25", parsed.Size)
	}
}

func TestAnalyzer_ExportStats(t *testing.T) {
	ctx := t.Context()
	tempDir := t.TempDir()

	gen := hammer.NewGenerator(hammer.DefaultGeneratorConfig())
	queue := hammer.NewCheckpointQueue()
	seqCfg := hammer.DefaultSequencerConfig(tempDir)
	seq, err := hammer.NewSequencer(ctx, seqCfg, gen, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = seq.Close(ctx) }()

	analyzer := hammer.NewAnalyzer(seq)

	// Record reads
	analyzer.RecordReadSuccess(100*time.Microsecond, 50)
	analyzer.RecordReadSuccess(200*time.Microsecond, 60)
	analyzer.RecordReadSuccess(500*time.Microsecond, 60)
	analyzer.RecordReadError(fmt.Errorf("simulated timeout"), 1*time.Millisecond)
	analyzer.RecordInvariantViolation("test violation 1")

	stats := analyzer.ExportStats()
	if stats.TotalReads != 4 {
		t.Fatalf("stats.TotalReads = %d, want 4", stats.TotalReads)
	}
	if stats.ReadSuccesses != 3 {
		t.Fatalf("stats.ReadSuccesses = %d, want 3", stats.ReadSuccesses)
	}
	if stats.ReadFailures != 1 {
		t.Fatalf("stats.ReadFailures = %d, want 1", stats.ReadFailures)
	}
	if stats.ServingTreeSize != 60 {
		t.Fatalf("stats.ServingTreeSize = %d, want 60", stats.ServingTreeSize)
	}
	if stats.InvariantViolations != 1 {
		t.Fatalf("stats.InvariantViolations = %d, want 1", stats.InvariantViolations)
	}
	if len(stats.ViolationSamples) != 2 {
		t.Fatalf("len(stats.ViolationSamples) = %d, want 2", len(stats.ViolationSamples))
	}
	if stats.LatencyMax != 1*time.Millisecond {
		t.Fatalf("stats.LatencyMax = %v, want 1ms", stats.LatencyMax)
	}
	if stats.Duration <= 0 {
		t.Fatalf("stats.Duration = %v, want > 0", stats.Duration)
	}
}
