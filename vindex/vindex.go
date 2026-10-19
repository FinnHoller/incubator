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

// Package vindex provides the public embedder API and configuration for the Verifiable Index.
package vindex

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// MappedEntry represents a single search key and optional value produced by a LeafMapper.
type MappedEntry = wasmhost.MappedEntry

// LeafMapper maps a raw Input Log leaf payload to a set of searchable MappedEntry records.
type LeafMapper = wasmhost.LeafMapper

// Config defines the configuration for running or embedding a Verifiable Index node.
type Config struct {
	DBPath             string
	MPTDir             string
	TileCacheDir       string
	ChunkSize          uint64
	BundleSize         uint64
	Workers            int
	FetchWorkers       int
	FetchBatchBundles  int
	PollInterval       time.Duration
	InputLogURL        string
	InputLogOrigin     string
	InputLogVerifier   note.Verifier
	InputLogPolicy     wire.Policy
	OutputLogDir       string
	OutputLogOrigin    string
	OutputLogSignerKey string
	WitnessURLs        []string
	WitnessPubKeys     []string
	PrefixPolicy       server.PrefixPolicy
	MaxPrefixKeys      int
	From               uint64
}

// DefaultConfig returns standard default configuration values.
func DefaultConfig() Config {
	workers := runtime.GOMAXPROCS(0) - 1
	if workers < 1 {
		workers = 1
	}
	return Config{
		ChunkSize:         kvstore.ChunkSize,
		BundleSize:        ingest.DefaultBundleSize,
		Workers:           workers,
		FetchWorkers:      ingest.DefaultFetchWorkers(),
		FetchBatchBundles: ingest.DefaultFetchBatchBundles(),
		PollInterval:      10 * time.Second,
		MaxPrefixKeys:     server.DefaultMaxPrefixKeys,
	}
}

type identityMapper struct{}

func (m *identityMapper) MapLeaf(_ context.Context, leaf []byte) ([]MappedEntry, error) {
	if mpt.ValidateCanonicalKey(leaf) == nil {
		return []MappedEntry{{
			Key:     string(leaf),
			KeyHash: sha256.Sum256(leaf),
		}}, nil
	}
	h := sha256.Sum256(leaf)
	hexKey := hex.EncodeToString(h[:])
	return []MappedEntry{{
		Key:     hexKey,
		KeyHash: sha256.Sum256([]byte(hexKey)),
	}}, nil
}

func (m *identityMapper) Close(_ context.Context) error { return nil }

// IdentityMapper creates a default LeafMapper that treats canonical ASCII leaf bytes directly as the
// search key, falling back to the lowercase hex-encoded SHA-256 leaf digest for non-canonical bytes.
func IdentityMapper() LeafMapper {
	return &identityMapper{}
}

type funcMapper struct {
	fn func(ctx context.Context, leaf []byte) ([]MappedEntry, error)
}

func (m *funcMapper) MapLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	return m.fn(ctx, leaf)
}

func (m *funcMapper) Close(_ context.Context) error { return nil }

// FuncMapper adapts a Go mapping function to the LeafMapper interface.
func FuncMapper(fn func(ctx context.Context, leaf []byte) ([]MappedEntry, error)) LeafMapper {
	return &funcMapper{fn: fn}
}

// Engine encapsulates the full Verifiable Index storage, MPT, coordinator, and HTTP server subsystems.
type Engine struct {
	cfg         Config
	db          *kvstore.DB
	mptMgr      *mpt.Manager
	cache       *ingest.ManagedTileCache
	indexer     *kvstore.KVIndexer
	outLog      coordinator.OutputLogReader
	outVerifier note.Verifier
	pub         *tree.OutputPublisher
	fetcher     ingest.TileFetcher
	mapper      LeafMapper
	coord       *coordinator.Coordinator
	server      *server.ReadServer
	reaper      *ingest.TileReaper

	mu      sync.Mutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
	closed  bool
}

// New initializes and wires all Engine subsystems.
func New(cfg Config, mapper LeafMapper) (*Engine, error) {
	if cfg.OutputLogDir != "" && cfg.OutputLogSignerKey == "" {
		return nil, errors.New("OutputLogSignerKey must be set when OutputLogDir is configured")
	}
	if cfg.OutputLogDir == "" && (len(cfg.WitnessURLs) > 0 || len(cfg.WitnessPubKeys) > 0) {
		return nil, errors.New("witnesses cannot be configured with an ephemeral in-memory output log")
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = kvstore.ChunkSize
	}
	if cfg.BundleSize == 0 {
		cfg.BundleSize = ingest.DefaultBundleSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.GOMAXPROCS(0) - 1
		if cfg.Workers < 1 {
			cfg.Workers = 1
		}
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	if mapper == nil {
		mapper = IdentityMapper()
	}

	// 1. Open Pebble KV store
	db, err := kvstore.Open(cfg.DBPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open KV store at %q: %w", cfg.DBPath, err)
	}
	db.SetChunkSize(cfg.ChunkSize)

	// 2. Open Merkle Patricia Trie Manager
	mptMgr, err := mpt.Open(cfg.MPTDir)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to open MPT at %q: %w", cfg.MPTDir, err)
	}

	// 3. Initialize Managed Tile Cache
	cache, err := ingest.NewManagedTileCache(cfg.TileCacheDir, cfg.BundleSize)
	if err != nil {
		_ = mptMgr.Close()
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize tile cache at %q: %w", cfg.TileCacheDir, err)
	}

	// 4. Initialize KV Indexer
	indexer := kvstore.NewKVIndexer(db, cfg.ChunkSize)
	if cfg.Workers == 1 {
		indexer.SetNumWorkers(1)
	}

	// 5. Initialize Output Log
	var outLog coordinator.OutputLogReader
	var outVerifier note.Verifier
	if cfg.OutputLogDir != "" {
		var signer note.Signer
		if s, v, err := fnote.NewEd25519SignerVerifier(cfg.OutputLogSignerKey); err == nil {
			signer = s
			outVerifier = v
		} else {
			s, err := note.NewSigner(cfg.OutputLogSignerKey)
			if err != nil {
				_ = mptMgr.Close()
				_ = db.Close()
				return nil, fmt.Errorf("failed to parse output log signer key: %w", err)
			}
			signer = s
		}
		origin := cfg.OutputLogOrigin
		if origin == "" {
			origin = signer.Name()
		}
		posixOpts := []tree.POSIXOption{tree.WithOrigin(origin)}
		if len(cfg.WitnessURLs) > 0 || len(cfg.WitnessPubKeys) > 0 {
			wg, err := tree.BuildWitnessGroup(cfg.WitnessURLs, cfg.WitnessPubKeys)
			if err != nil {
				_ = mptMgr.Close()
				_ = db.Close()
				return nil, fmt.Errorf("failed to build witness group: %w", err)
			}
			posixOpts = append(posixOpts, tree.WithDefaultWitnessGroup(wg))
		}
		posixLog, err := tree.NewPOSIXOutputLog(context.Background(), cfg.OutputLogDir, signer, posixOpts...)
		if err != nil {
			_ = mptMgr.Close()
			_ = db.Close()
			return nil, fmt.Errorf("failed to open POSIX output log at %q: %w", cfg.OutputLogDir, err)
		}
		outLog = posixLog
	} else {
		kvSize, _ := db.GetUint64(kvstore.KeyMetaKVSize)
		if kvSize > 0 || mptMgr.PersistedSize() > 0 || !mptMgr.IsExact() {
			_ = mptMgr.Close()
			_ = db.Close()
			return nil, errors.New("cannot use ephemeral in-memory output log with existing persistent DB or MPT state; configure OutputLogDir and OutputLogSignerKey")
		}
		origin := cfg.OutputLogOrigin
		var signer note.Signer
		if cfg.OutputLogSignerKey != "" {
			if s, v, err := fnote.NewEd25519SignerVerifier(cfg.OutputLogSignerKey); err == nil {
				signer = s
				outVerifier = v
			} else {
				s, err := note.NewSigner(cfg.OutputLogSignerKey)
				if err != nil {
					_ = mptMgr.Close()
					_ = db.Close()
					return nil, fmt.Errorf("failed to parse output log signer key: %w", err)
				}
				signer = s
			}
			if origin == "" {
				origin = signer.Name()
			}
		} else {
			if origin == "" {
				origin = "vindex.memory.outputlog"
			}
			skey, vkey, err := note.GenerateKey(rand.Reader, origin)
			if err != nil {
				_ = mptMgr.Close()
				_ = db.Close()
				return nil, fmt.Errorf("failed to generate ephemeral output log key: %w", err)
			}
			s, err := note.NewSigner(skey)
			if err != nil {
				_ = mptMgr.Close()
				_ = db.Close()
				return nil, fmt.Errorf("failed to create ephemeral output log signer: %w", err)
			}
			v, err := note.NewVerifier(vkey)
			if err != nil {
				_ = mptMgr.Close()
				_ = db.Close()
				return nil, fmt.Errorf("failed to create ephemeral output log verifier: %w", err)
			}
			signer = s
			outVerifier = v
		}
		outLog = newMemoryOutputLog(origin, signer)
	}

	// 6. Initialize Output Publisher
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	if cfg.InputLogOrigin != "" {
		pub.SetInputOrigin(cfg.InputLogOrigin)
	}
	if cfg.From > 0 {
		pub.SetFrom(cfg.From)
	}

	// 7. Initialize Input Log Tile Fetcher if configured
	var fetcher ingest.TileFetcher
	if cfg.InputLogURL != "" {
		u, err := url.Parse(cfg.InputLogURL)
		if err != nil {
			if closer, ok := outLog.(io.Closer); ok {
				_ = closer.Close()
			}
			_ = mptMgr.Close()
			_ = db.Close()
			return nil, fmt.Errorf("invalid input log URL %q: %w", cfg.InputLogURL, err)
		}
		inPolicy := cfg.InputLogPolicy
		if inPolicy == nil && cfg.InputLogVerifier != nil {
			pol, err := wire.BuildPolicy(cfg.InputLogOrigin, cfg.InputLogVerifier, nil, 0)
			if err != nil {
				if closer, ok := outLog.(io.Closer); ok {
					_ = closer.Close()
				}
				_ = mptMgr.Close()
				_ = db.Close()
				return nil, fmt.Errorf("failed to build input log policy: %w", err)
			}
			inPolicy = pol
		}
		tFetcher, err := ingest.NewTiledFetcher(u, cfg.InputLogVerifier, cfg.InputLogOrigin, nil)
		if err != nil {
			if closer, ok := outLog.(io.Closer); ok {
				_ = closer.Close()
			}
			_ = mptMgr.Close()
			_ = db.Close()
			return nil, fmt.Errorf("failed to create tile fetcher for %q: %w", cfg.InputLogURL, err)
		}
		if inPolicy != nil {
			tFetcher.SetPolicy(inPolicy)
		}
		fetcher = tFetcher
	}

	// 8. Initialize Ingestion Pipeline
	var pipeline *ingest.IngestionPipeline
	if fetcher != nil && mapper != nil {
		pipeline = ingest.NewPipeline(fetcher, cache, mapper, cfg.Workers)
		if cfg.FetchWorkers > 0 {
			pipeline.SetFetchWorkers(cfg.FetchWorkers)
		}
		if cfg.FetchBatchBundles > 0 {
			pipeline.SetFetchBatchBundles(cfg.FetchBatchBundles)
		}
	}

	// 9. Initialize Coordinator
	coord := coordinator.NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, cache, mapper)
	coord.SetWorkers(cfg.Workers)
	if pipeline != nil {
		coord.SetPipeline(pipeline)
	}
	if cfg.FetchWorkers > 0 {
		coord.SetFetchWorkers(cfg.FetchWorkers)
	}
	if cfg.FetchBatchBundles > 0 {
		coord.SetFetchBatchBundles(cfg.FetchBatchBundles)
	}

	// 10. Initialize HTTP Read Server
	srv := server.NewReadServer(db, mptMgr, pub, cfg.ChunkSize)
	srv.SetReadyChecker(coord.ReadinessCheck)
	if cfg.PrefixPolicy != nil {
		srv.SetPrefixPolicy(cfg.PrefixPolicy)
	}
	if cfg.MaxPrefixKeys > 0 {
		srv.SetMaxPrefixKeys(cfg.MaxPrefixKeys)
	}

	// 11. Initialize Tile Reaper
	reaper := ingest.NewTileReaper(db, mptMgr, cache)
	reaper.SetWatermarkFunc(coord.SafeWatermark)

	return &Engine{
		cfg:         cfg,
		db:          db,
		mptMgr:      mptMgr,
		cache:       cache,
		indexer:     indexer,
		outLog:      outLog,
		outVerifier: outVerifier,
		pub:         pub,
		fetcher:     fetcher,
		mapper:      mapper,
		coord:       coord,
		server:      srv,
		reaper:      reaper,
	}, nil
}

// Start executes startup crash recovery and starts background synchronization and tile reaping loops.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return errors.New("engine is closed")
	}
	if e.running {
		return errors.New("engine is already running")
	}

	// Phase 1-3 Recovery
	if err := e.coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}

	// Initial synchronous catch-up
	if e.fetcher != nil {
		if err := e.coord.SyncOnce(ctx); err != nil {
			if errors.Is(err, ingest.ErrWasmHalt) || errors.Is(err, ingest.ErrInvalidMemory) || errors.Is(err, ingest.ErrMalformedOutput) || errors.Is(err, ingest.ErrUnalignedOutput) || errors.Is(err, coordinator.ErrInvariantViolation) || errors.Is(err, coordinator.ErrRootMismatch) {
				return fmt.Errorf("fatal initial sync error: %w", err)
			}
			klog.Warningf("Initial sync error: %v", err)
		}
	}

	bgCtx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.running = true

	pollInterval := e.cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}

	// Background polling sync loop
	if e.fetcher != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			ticker := time.NewTicker(pollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-bgCtx.Done():
					return
				case <-ticker.C:
					if err := e.coord.SyncOnce(bgCtx); err != nil {
						if errors.Is(err, ingest.ErrWasmHalt) || errors.Is(err, ingest.ErrInvalidMemory) || errors.Is(err, ingest.ErrMalformedOutput) || errors.Is(err, ingest.ErrUnalignedOutput) || errors.Is(err, coordinator.ErrInvariantViolation) || errors.Is(err, coordinator.ErrRootMismatch) {
							klog.Errorf("Fatal background sync error, halting engine: %v", err)
							cancel()
							return
						}
						klog.Warningf("Background sync error: %v", err)
					}
				}
			}
		}()
	}

	// Background tile reaper loop
	if e.reaper != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			_ = e.reaper.Run(bgCtx, 60*time.Second)
		}()
	}

	return nil
}

// Run executes startup recovery and runs the coordinator synchronization loop synchronously until ctx is canceled.
func (e *Engine) Run(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("engine is closed")
	}
	if e.running {
		e.mu.Unlock()
		return errors.New("engine is already running")
	}
	e.running = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	if e.reaper != nil {
		reaperCtx, reaperCancel := context.WithCancel(ctx)
		defer reaperCancel()
		go func() {
			_ = e.reaper.Run(reaperCtx, 60*time.Second)
		}()
	}

	pollInterval := e.cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	return e.coord.Run(ctx, pollInterval)
}

// Stop gracefully halts background loops and closes all storage and MPT resources.
func (e *Engine) Stop() error {
	return e.Close()
}

// Close gracefully closes the engine, halting background loops and releasing resources.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}
	e.closed = true

	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	e.running = false

	var errs []error

	if closer, ok := e.outLog.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close output log: %w", err))
		}
	}

	if e.mptMgr != nil {
		if err := e.mptMgr.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close MPT: %w", err))
		}
	}

	if e.db != nil {
		if err := e.db.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close KV store: %w", err))
		}
	}

	if e.mapper != nil {
		if err := e.mapper.Close(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("failed to close mapper: %w", err))
		}
	}

	return errors.Join(errs...)
}

// Handler returns an http.Handler exposing the public read server endpoints (/keys, /values, /checkpoint, etc.).
func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	if e.server != nil {
		e.server.RegisterRoutes(mux)
	}
	return mux
}

// AdminHandler returns an http.Handler exposing the internal operational endpoints (/healthz, /readyz, /metrics, /debug/pprof/*).
func (e *Engine) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	if e.server != nil {
		e.server.RegisterAdminRoutes(mux)
	}
	return mux
}

// OutputLogVerifier returns the note.Verifier for the Output Log when available (including ephemeral in-memory output logs).
func (e *Engine) OutputLogVerifier() note.Verifier {
	return e.outVerifier
}

// DB returns the underlying KV database.
func (e *Engine) DB() *kvstore.DB {
	return e.db
}

// MPT returns the underlying MPT manager.
func (e *Engine) MPT() *mpt.Manager {
	return e.mptMgr
}

// Publisher returns the Output Publisher.
func (e *Engine) Publisher() *tree.OutputPublisher {
	return e.pub
}

// Coordinator returns the recovery and ingestion Coordinator.
func (e *Engine) Coordinator() *coordinator.Coordinator {
	return e.coord
}

// Server returns the ReadServer.
func (e *Engine) Server() *server.ReadServer {
	return e.server
}

// memoryOutputLog is an in-memory, ephemeral implementation of OutputLogReader and OutputPublisher
// used for testing and in-memory engine instances when OutputLogDir is not configured.
// Production deployments must configure OutputLogDir and OutputLogSignerKey to use POSIXOutputLog.
type memoryOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
	signer note.Signer
}

func newMemoryOutputLog(origin string, signer note.Signer) *memoryOutputLog {
	return &memoryOutputLog{
		origin: origin,
		signer: signer,
	}
}

func (m *memoryOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	signedCP, err := note.Sign(&note.Note{Text: rawCP}, m.signer)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to sign in-memory output log checkpoint: %w", err)
	}
	return idx, signedCP, nil
}

func (m *memoryOutputLog) Size(_ context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.leaves)), nil
}

func (m *memoryOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx >= uint64(len(m.leaves)) {
		return nil, fmt.Errorf("index out of range %d >= %d", idx, len(m.leaves))
	}
	return m.leaves[idx], nil
}

func (m *memoryOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	size := uint64(len(m.leaves))
	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	signedCP, err := note.Sign(&note.Note{Text: rawCP}, m.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign in-memory output log checkpoint: %w", err)
	}
	return signedCP, nil
}

func (m *memoryOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var leafHashes [][sha256.Size]byte
	for _, l := range m.leaves[:treeSize] {
		leafHashes = append(leafHashes, kvstore.LeafHash(l))
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
			rightSubRoot := kvstore.BatchRootHashes(leaves[k:])
			buildProof(leaves[:k], idx)
			proof = append(proof, rightSubRoot)
		} else {
			leftSubRoot := kvstore.BatchRootHashes(leaves[:k])
			buildProof(leaves[k:], idx-k)
			proof = append(proof, leftSubRoot)
		}
	}

	buildProof(leafHashes, leafIdx)
	return proof, nil
}
