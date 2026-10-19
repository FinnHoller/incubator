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

package client_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

// In-memory brute force oracle for differential verification
type readOracle struct {
	mu      sync.RWMutex
	indices map[string][]uint64
}

func newOracle() *readOracle {
	return &readOracle{
		indices: make(map[string][]uint64),
	}
}

func (o *readOracle) record(key string, idx uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.indices[key] = append(o.indices[key], idx)
}

func (o *readOracle) getAll(key string) []uint64 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return slices.Clone(o.indices[key])
}

func makeClientConfig(t *testing.T, outOrigin string, outV note.Verifier, inOrigin string) client.Config {
	t.Helper()
	outPol, err := client.SingleKeyPolicy(outOrigin, outV)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(out) failed: %v", err)
	}
	return client.Config{
		ExpectedOutputLogOrigin: outOrigin,
		OutputLogPolicy:         outPol,
		ExpectedInputLogOrigin:  inOrigin,
	}
}

func collectValuesAscending(ctx context.Context, mk client.MatchedKey) ([]uint64, error) {
	var desc []uint64
	for idx, err := range mk.Values(ctx) {
		if err != nil {
			return nil, err
		}
		if len(desc) > 0 && idx >= desc[len(desc)-1] {
			return nil, fmt.Errorf("indices not strictly descending: %v then %d", desc, idx)
		}
		desc = append(desc, idx)
	}
	slices.Reverse(desc)
	return desc, nil
}

// TestStress_DifferentialLookupAndPagination tests client LookupKey and MatchedKey.Values
// against an independent oracle across multi-chunk datasets.
func TestStress_DifferentialLookupAndPagination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const chunkSize = 8 // Tiny chunk size: forces chunks every 8 entries!
	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.stress.inlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.stress.outlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	oracle := newOracle()

	const (
		key1      = "key_1"
		key2      = "key_2"
		keyExact  = "key_chunk_exact"
		keyPlus1  = "key_chunk_plus_1"
		keyDouble = "key_chunk_double"
		keyHeavy  = "key_heavy"
		keySparse = "key_sparse"
		keyAbsent = "key_absent_never_indexed"
	)

	var sequence []string
	sequence = append(sequence, key1)
	for i := 0; i < 2; i++ {
		sequence = append(sequence, key2)
	}
	for i := 0; i < 8; i++ {
		sequence = append(sequence, keyExact)
	}
	for i := 0; i < 9; i++ {
		sequence = append(sequence, keyPlus1)
	}
	for i := 0; i < 16; i++ {
		sequence = append(sequence, keyDouble)
	}
	for i := 0; i < 50; i++ {
		sequence = append(sequence, keyHeavy)
		if i%10 == 0 {
			sequence = append(sequence, keySparse)
		}
	}

	for i, keyName := range sequence {
		leafData := []byte(fmt.Sprintf("%s_leaf_%d", keyName, i))
		idx, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(leafData)))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("failed to append leaf %d: %v", i, err)
		}
		oracle.record(keyName, idx.Index)
	}

	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          chunkSize,
		BundleSize:         8,
		PollInterval:       30 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.stress.inlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.stress.outlog",
		OutputLogSignerKey: outSKey,
	}

	knownKeys := []string{key1, key2, keyExact, keyPlus1, keyDouble, keyHeavy, keySparse}
	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		s := string(leaf)
		for _, kName := range knownKeys {
			prefix := kName + "_"
			if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
				return []vindex.MappedEntry{{Key: kName, KeyHash: sha256.Sum256([]byte(kName))}}, nil
			}
		}
		h := sha256.Sum256(leaf)
		hexKey := hex.EncodeToString(h[:])
		return []vindex.MappedEntry{{Key: hexKey, KeyHash: sha256.Sum256([]byte(hexKey))}}, nil
	})

	engine, err := vindex.New(cfg, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli, err := client.New(ts.URL, makeClientConfig(t, "test.stress.outlog", outVerifier, "test.stress.inlog"), client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// 1. Non-inclusion verification
	t.Run("NonInclusion_AbsentKey", func(t *testing.T) {
		kr, err := cli.LookupKey(ctx, keyAbsent)
		if err != nil {
			t.Fatalf("LookupKey non-inclusion failed: %v", err)
		}
		if len(kr.Keys) != 0 {
			t.Fatalf("expected non-inclusion with 0 keys, got %+v", kr)
		}
	})

	// 2. Comprehensive differential check on LookupKey + Values
	for _, kName := range knownKeys {
		t.Run("LookupValues_"+kName, func(t *testing.T) {
			expected := oracle.getAll(kName)
			if len(expected) == 0 {
				t.Fatalf("oracle has 0 entries for %s", kName)
			}

			kr, err := cli.LookupKey(ctx, kName)
			if err != nil {
				t.Fatalf("LookupKey(%s) failed: %v", kName, err)
			}
			if len(kr.Keys) != 1 {
				t.Fatalf("expected 1 matched key for %s, got %d", kName, len(kr.Keys))
			}

			indices, err := collectValuesAscending(ctx, kr.Keys[0])
			if err != nil {
				t.Fatalf("Values(%s) failed: %v", kName, err)
			}
			if !slices.Equal(indices, expected) {
				t.Fatalf("Values(%s) mismatch:\n got:  %v\n want: %v", kName, indices, expected)
			}
		})
	}
}

// TestStress_HighConcurrencyReadPath subjects the engine and client to parallel reader goroutines
// performing simultaneous lookups and backward pagination while asserting 0 data races and 0 proof failures.
func TestStress_HighConcurrencyReadPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	const chunkSize = 16
	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.stress.concurr.inlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.stress.concurr.outlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	const numKeys = 10
	keyNames := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keyNames[i] = fmt.Sprintf("concurr_key_%d", i)
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		var kID int
		if _, err := fmt.Sscanf(string(leaf), "entry_key_%d", &kID); err == nil && kID >= 0 && kID < numKeys {
			kn := keyNames[kID]
			return []vindex.MappedEntry{{Key: kn, KeyHash: sha256.Sum256([]byte(kn))}}, nil
		}
		h := sha256.Sum256(leaf)
		hexKey := hex.EncodeToString(h[:])
		return []vindex.MappedEntry{{Key: hexKey, KeyHash: sha256.Sum256([]byte(hexKey))}}, nil
	})

	for i := 0; i < 100; i++ {
		kID := i % numKeys
		leafData := []byte(fmt.Sprintf("entry_key_%d_%d", kID, i))
		_, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(leafData)))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("append leaf %d failed: %v", i, err)
		}
	}

	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          chunkSize,
		BundleSize:         16,
		PollInterval:       20 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.stress.concurr.inlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.stress.concurr.outlog",
		OutputLogSignerKey: outSKey,
	}

	engine, err := vindex.New(cfg, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli, err := client.New(ts.URL, makeClientConfig(t, "test.stress.concurr.outlog", outVerifier, "test.stress.concurr.inlog"), client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	const numWorkers = 20
	const iterationsPerWorker = 30
	var totalSuccess atomic.Uint64
	var totalFail atomic.Uint64

	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startBarrier

			for it := 0; it < iterationsPerWorker; it++ {
				kID := (workerID + it) % numKeys
				key := keyNames[kID]

				switch it % 3 {
				case 0:
					kr, err := cli.LookupKey(ctx, key)
					if err != nil || len(kr.Keys) != 1 {
						totalFail.Add(1)
						continue
					}
					var gotFirst bool
					for _, vErr := range kr.Keys[0].Values(ctx) {
						if vErr == nil {
							gotFirst = true
						}
						break
					}
					if !gotFirst {
						totalFail.Add(1)
					} else {
						totalSuccess.Add(1)
					}
				case 1:
					kr, err := cli.LookupKey(ctx, key)
					if err != nil || len(kr.Keys) != 1 {
						totalFail.Add(1)
						continue
					}
					indices, err := collectValuesAscending(ctx, kr.Keys[0])
					if err != nil || len(indices) != 10 {
						totalFail.Add(1)
					} else {
						totalSuccess.Add(1)
					}
				case 2:
					fakeKey := fmt.Sprintf("non_existent_%d_%d", workerID, it)
					kr, err := cli.LookupKey(ctx, fakeKey)
					if err != nil || len(kr.Keys) != 0 {
						totalFail.Add(1)
					} else {
						totalSuccess.Add(1)
					}
				}
			}
		}(w)
	}

	close(startBarrier)
	wg.Wait()

	if totalFail.Load() > 0 {
		t.Fatalf("encountered %d failures during concurrent read stress", totalFail.Load())
	}
	expectedSuccess := uint64(numWorkers * iterationsPerWorker)
	if totalSuccess.Load() != expectedSuccess {
		t.Fatalf("totalSuccess = %d, want %d", totalSuccess.Load(), expectedSuccess)
	}
}

// TestStress_ConcurrentWriterAndBackwardPaginator stresses backward pagination while
// the engine is actively ingesting and publishing new batches in the background.
func TestStress_ConcurrentWriterAndBackwardPaginator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	const chunkSize = 8
	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.stress.writer.inlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.stress.writer.outlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	const dynamicKey = "dynamic_hot_key"
	dynamicKeyHash := sha256.Sum256([]byte(dynamicKey))

	mapper := vindex.FuncMapper(func(_ context.Context, _ []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{Key: dynamicKey, KeyHash: dynamicKeyHash}}, nil
	})

	for i := 0; i < 20; i++ {
		_, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte(fmt.Sprintf("initial_%d", i)))))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("seed leaf %d failed: %v", i, err)
		}
	}

	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          chunkSize,
		BundleSize:         8,
		PollInterval:       20 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.stress.writer.inlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.stress.writer.outlog",
		OutputLogSignerKey: outSKey,
	}

	engine, err := vindex.New(cfg, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	var stopFlag atomic.Bool
	var totalReads atomic.Uint64
	var readErrors atomic.Uint64
	var lastSeenCount atomic.Uint64

	var wg sync.WaitGroup
	cliCfg := makeClientConfig(t, "test.stress.writer.outlog", outVerifier, "test.stress.writer.inlog")

	const numReaders = 4
	for r := 0; r < numReaders; r++ {
		readerCli, err := client.New(ts.URL, cliCfg, client.WithHTTPClient(ts.Client()))
		if err != nil {
			t.Fatalf("client.New failed: %v", err)
		}
		wg.Add(1)
		go func(rID int, cli *client.Client) {
			defer wg.Done()
			for !stopFlag.Load() {
				kr, err := cli.LookupKey(ctx, dynamicKey)
				if err != nil {
					t.Errorf("reader %d LookupKey failed: %v", rID, err)
					readErrors.Add(1)
					continue
				}
				if len(kr.Keys) == 0 {
					time.Sleep(5 * time.Millisecond)
					continue
				}
				indices, err := collectValuesAscending(ctx, kr.Keys[0])
				if err != nil {
					t.Errorf("reader %d Values failed: %v", rID, err)
					readErrors.Add(1)
				} else if len(indices) > 0 {
					totalReads.Add(1)
					cnt := uint64(len(indices))
					for {
						curr := lastSeenCount.Load()
						if cnt <= curr || lastSeenCount.CompareAndSwap(curr, cnt) {
							break
						}
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
		}(r, readerCli)
	}

	for i := 20; i < 50; i++ {
		_, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte(fmt.Sprintf("dyn_%d", i)))))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("append dyn leaf %d failed: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)
	stopFlag.Store(true)
	wg.Wait()

	if readErrors.Load() > 0 {
		t.Fatalf("encountered %d read errors during continuous ingestion pagination", readErrors.Load())
	}
	if totalReads.Load() < 10 {
		t.Fatalf("expected >= 10 reads, got %d", totalReads.Load())
	}
	if lastSeenCount.Load() < 30 {
		t.Fatalf("expected lastSeenCount >= 30, got %d", lastSeenCount.Load())
	}
}
