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
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/incubator/vindex/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// ReaderConfig configures the concurrent reader pool.
type ReaderConfig struct {
	VIndexURL         string
	NumWorkers        int
	MaxReadQPS        float64
	OutputLogOrigin   string
	OutputLogVerifier note.Verifier
	OutputLogPolicy   client.CheckpointPolicy
	InputLogOrigin    string
	InputLogVerifier  note.Verifier
	InputLogPolicy    client.CheckpointPolicy
	HotKeyRatio       float64
	UniformRatio      float64
	NonInclusionRatio float64
	PaginationRatio   float64
	PrefixRatio       float64
	PageSize          uint64
}

// DefaultReaderConfig returns default configuration for readers.
func DefaultReaderConfig(vindexURL string) ReaderConfig {
	return ReaderConfig{
		VIndexURL:         vindexURL,
		NumWorkers:        8,
		MaxReadQPS:        200,
		HotKeyRatio:       0.60,
		UniformRatio:      0.25,
		NonInclusionRatio: 0.10,
		PaginationRatio:   0.05,
		PageSize:          100,
	}
}

// KeyHistory tracks prior lookup results for monotonicity verification.
type KeyHistory struct {
	LastTreeSize uint64
	Indices      []uint64
}

// ReaderPool manages concurrent reader workers querying vindexd with cryptographic verification.
type ReaderPool struct {
	cfg          ReaderConfig
	generator    *Generator
	clients      []*client.Client
	analyzer     *Analyzer
	mu           sync.RWMutex
	hasFrom      bool
	verifiedFrom uint64
	history      map[[sha256.Size]byte]KeyHistory
	totalReads   uint64
	stopCh       chan struct{}
}

// NewReaderPool creates a new ReaderPool instance.
func NewReaderPool(cfg ReaderConfig, gen *Generator, an *Analyzer) (*ReaderPool, error) {
	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = 8
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 100
	}

	outPolicy := cfg.OutputLogPolicy
	if outPolicy == nil && cfg.OutputLogVerifier != nil {
		var err error
		outPolicy, err = client.SingleKeyPolicy(cfg.OutputLogOrigin, cfg.OutputLogVerifier)
		if err != nil {
			return nil, fmt.Errorf("failed to construct output log policy: %w", err)
		}
	}

	cliCfg := client.Config{
		ExpectedOutputLogOrigin: cfg.OutputLogOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  cfg.InputLogOrigin,
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.NumWorkers * 4,
			MaxIdleConnsPerHost: cfg.NumWorkers * 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	clients := make([]*client.Client, cfg.NumWorkers)
	for i := 0; i < cfg.NumWorkers; i++ {
		cli, err := client.New(cfg.VIndexURL, cliCfg, client.WithHTTPClient(httpClient))
		if err != nil {
			return nil, fmt.Errorf("failed to create client: %w", err)
		}
		clients[i] = cli
	}

	return &ReaderPool{
		cfg:       cfg,
		generator: gen,
		clients:   clients,
		analyzer:  an,
		history:   make(map[[sha256.Size]byte]KeyHistory),
		stopCh:    make(chan struct{}),
	}, nil
}

// Start launches worker goroutines and runs until ctx is cancelled.
func (p *ReaderPool) Start(ctx context.Context) {
	// Wait for vindexd to publish its initial serving state
	probeKey, _ := p.generator.SampleNonInclusionKey()
	if _, err := p.clients[0].LookupKey(ctx, probeKey); err == nil {
		goto Ready
	}
	{
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		timeout := time.NewTimer(15 * time.Second)
		defer timeout.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timeout.C:
				return
			case <-ticker.C:
				if _, err := p.clients[0].LookupKey(ctx, probeKey); err == nil {
					goto Ready
				}
			}
		}
	}
Ready:

	var wg sync.WaitGroup

	// Global rate limiter across workers
	var rateLimiter <-chan time.Time
	if p.cfg.MaxReadQPS > 0 {
		interval := time.Duration(float64(time.Second) / p.cfg.MaxReadQPS)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	for i := 0; i < p.cfg.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int, cli *client.Client) {
			defer wg.Done()
			p.runWorker(ctx, workerID, cli, rateLimiter)
		}(i, p.clients[i])
	}

	<-ctx.Done()
	wg.Wait()
}

func (p *ReaderPool) runWorker(ctx context.Context, workerID int, cli *client.Client, rateLimiter <-chan time.Time) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID*1000)))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if rateLimiter != nil {
			select {
			case <-ctx.Done():
				return
			case <-rateLimiter:
			}
		}

		p.executeOneQuery(ctx, cli, rng)
	}
}

func isCryptographicOrConsistencyFault(err error) bool {
	return errors.Is(err, client.ErrVerificationFailed)
}

func (p *ReaderPool) verifyHorizon(from uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.hasFrom {
		p.hasFrom = true
		p.verifiedFrom = from
		return
	}
	if from != p.verifiedFrom {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("HorizonViolation: index start horizon changed from %d to %d", p.verifiedFrom, from))
		}
	}
}

func (p *ReaderPool) executeOneQuery(ctx context.Context, cli *client.Client, rng *rand.Rand) {
	dice := rng.Float64()
	if p.cfg.PrefixRatio > 0 && dice < p.cfg.PrefixRatio {
		p.executePrefixQuery(ctx, cli, rng)
		return
	}
	// Rescale remaining dice into [0, 1)
	if p.cfg.PrefixRatio > 0 && p.cfg.PrefixRatio < 1.0 {
		dice = (dice - p.cfg.PrefixRatio) / (1.0 - p.cfg.PrefixRatio)
	}

	var queryType string
	var keyStr string
	var keyHash [sha256.Size]byte
	var isNonInclusion bool
	var isPagination bool

	if dice < p.cfg.HotKeyRatio {
		queryType = "hot"
		keyStr, keyHash = p.generator.SampleHotKey()
	} else if dice < p.cfg.HotKeyRatio+p.cfg.UniformRatio {
		queryType = "uniform"
		keyStr, keyHash = p.generator.SampleExistingKey()
	} else if dice < p.cfg.HotKeyRatio+p.cfg.UniformRatio+p.cfg.NonInclusionRatio {
		queryType = "non_inclusion"
		keyStr, keyHash = p.generator.SampleNonInclusionKey()
		isNonInclusion = true
	} else {
		queryType = "pagination"
		keyStr, keyHash = p.generator.SampleHotKey()
		isPagination = true
	}

	start := time.Now()
	var kr *client.LookupResult
	var indices []uint64
	var isComplete bool
	var err error

	kr, err = cli.LookupKey(ctx, keyStr)
	if err == nil {
		p.verifyHorizon(kr.From)
		isComplete = true
		if len(kr.Keys) > 0 {
			var revIndices []uint64
			for idx, vErr := range kr.Keys[0].Values(ctx) {
				if vErr != nil {
					err = vErr
					break
				}
				revIndices = append(revIndices, idx)
				if !isPagination && uint64(len(revIndices)) >= p.cfg.PageSize {
					isComplete = false
					break
				}
			}
			if err == nil {
				slices.Reverse(revIndices)
				indices = revIndices
			}
		}
	}
	latency := time.Since(start)

	atomic.AddUint64(&p.totalReads, 1)

	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if p.analyzer != nil {
			p.analyzer.RecordReadError(err, latency)
			if isCryptographicOrConsistencyFault(err) {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("CryptographicViolation [%s] key %s: %v", queryType, keyStr, err))
			}
		}
		klog.V(2).Infof("Read error [%s] key %s: %v", queryType, keyStr, err)
		return
	}

	// Update serving lag telemetry
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, kr.InputSize)
	}

	// Verify non-inclusion invariant
	if isNonInclusion {
		if len(kr.Keys) > 0 {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("NonInclusionViolation: key %s exists in response with %d indices", keyStr, len(indices)))
			}
			return
		}
		if len(indices) > 0 {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("NonInclusionViolation: key %s returned non-empty indices: %v", keyStr, indices))
			}
			return
		}
		return
	}

	// Verify index bounds and intra-response sort order
	if !slices.IsSorted(indices) {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("SortViolation: indices not sorted for key %s: %v", keyStr, indices))
		}
		return
	}
	for _, idx := range indices {
		if idx >= kr.InputSize {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("BoundsViolation: index %d >= InputSize %d for key %s", idx, kr.InputSize, keyStr))
			}
			return
		}
	}

	// Verify monotonicity
	p.verifyMonotonicity(keyHash, keyStr, kr.InputSize, indices, isComplete)
}

func (p *ReaderPool) executePrefixQuery(ctx context.Context, cli *client.Client, rng *rand.Rand) {
	isNonInc := rng.Intn(4) == 0
	var prefix string
	if isNonInc {
		nonKey, _ := p.generator.SampleNonInclusionKey()
		prefix = nonKey
	} else {
		sampleKey, _ := p.generator.SampleHotKey()
		prefix = sampleKey
	}

	start := time.Now()
	var inputSize uint64
	kr, err := cli.LookupPrefix(ctx, prefix)
	if err == nil {
		p.verifyHorizon(kr.From)
		inputSize = kr.InputSize
		if isNonInc && len(kr.Keys) > 0 {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("PrefixNonInclusionViolation: prefix %s matched %d keys", prefix, len(kr.Keys)))
			}
		}
		fetchValues := rng.Intn(2) == 1
		for _, m := range kr.Keys {
			if !strings.HasPrefix(m.Key, prefix) {
				if p.analyzer != nil {
					p.analyzer.RecordInvariantViolation(fmt.Sprintf("PrefixMatchViolation: key %s does not have prefix %s", m.Key, prefix))
				}
			}
			if fetchValues {
				var revIndices []uint64
				for idx, vErr := range m.Values(ctx) {
					if vErr != nil {
						err = vErr
						break
					}
					revIndices = append(revIndices, idx)
				}
				if err != nil {
					break
				}
				slices.Reverse(revIndices)
				kh := sha256.Sum256([]byte(m.Key))
				p.verifyMonotonicity(kh, m.Key, kr.InputSize, revIndices, true)
			}
		}
	}
	latency := time.Since(start)
	atomic.AddUint64(&p.totalReads, 1)

	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if p.analyzer != nil {
			p.analyzer.RecordReadError(err, latency)
			if isCryptographicOrConsistencyFault(err) {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("CryptographicViolation [prefix] %s: %v", prefix, err))
			}
		}
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, inputSize)
	}
}

func (p *ReaderPool) verifyMonotonicity(keyHash [sha256.Size]byte, keyStr string, inputLogSize uint64, indices []uint64, isComplete bool) {
	if !isComplete {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	hist, exists := p.history[keyHash]
	if !exists {
		p.history[keyHash] = KeyHistory{
			LastTreeSize: inputLogSize,
			Indices:      slices.Clone(indices),
		}
		return
	}

	// 1. Verify that the total count of indices never shrinks as the log advances.
	if len(indices) < len(hist.Indices) && inputLogSize >= hist.LastTreeSize {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("MonotonicityViolation: key %s indices shrank from %d (size %d) to %d (size %d)", keyStr, len(hist.Indices), hist.LastTreeSize, len(indices), inputLogSize))
		}
		return
	}

	// 2. Verify prefix consistency: previously observed history must match the new history prefix identically.
	checkLen := min(len(indices), len(hist.Indices))
	if !slices.Equal(indices[:checkLen], hist.Indices[:checkLen]) {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("MonotonicityViolation: key %s prefix mismatch: old %v, new %v", keyStr, hist.Indices[:checkLen], indices[:checkLen]))
		}
		return
	}

	if inputLogSize >= hist.LastTreeSize {
		p.history[keyHash] = KeyHistory{
			LastTreeSize: inputLogSize,
			Indices:      slices.Clone(indices),
		}
	}
}
