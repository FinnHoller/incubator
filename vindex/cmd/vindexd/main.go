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

// vindexd is the Verifiable Index daemon.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	mode                     = flag.String("mode", "publisher", "Daemon operation mode: 'publisher' (default), 'auditor', or 'verifier'.")
	inputLogURL              = flag.String("input_log_url", "", "Base URL of the Input Log.")
	inputLogOrigin           = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	inputLogPubKey           = flag.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification (standard note or mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>).")
	inputLogPolicy           = flag.String("input_log_policy", "", "Path to C2SP tlog-policy file for Input Log checkpoint verification.")
	insecureSkipVerify       = flag.Bool("insecure_skip_verify", false, "Allow unverified Input Log checkpoints when --input_log_policy and --input_log_pubkey are unset (for local testing only).")
	outputLogDir             = flag.String("output_log_dir", "", "Path for local Output Log storage.")
	outputLogOrigin          = flag.String("output_log_origin", "", "Origin string for Output Log. If unset, defaults to signer name.")
	outputLogSignerKey       = flag.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints.")
	witnessURLs              = flag.String("witness_urls", "", "Comma-separated list of witness HTTP base URLs for Output Log cosigning.")
	witnessPubKeys           = flag.String("witness_pubkeys", "", "Comma-separated list of witness verifier public keys matching --witness_urls.")
	outputLogURL             = flag.String("output_log_url", "", "Base URL of Output Log to verify (auditor/verifier mode).")
	outputLogPubKey          = flag.String("output_log_pubkey", "", "Public key for Output Log checkpoint verification (auditor/verifier mode).")
	outputLogPolicy          = flag.String("output_log_policy", "", "Path to C2SP tlog-policy file for Output Log checkpoint verification (auditor/verifier mode).")
	oneShot                  = flag.Bool("oneshot", false, "Run synchronization once against log tip and exit (supported in publisher, auditor, and verifier modes).")
	dbPath                   = flag.String("db_path", "", "NVMe path for Pebble DB (Disk A).")
	mptDir                   = flag.String("mpt_dir", "", "Isolated NVMe path for MPT mmap files (Disk B).")
	wasmPath                 = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary (required).")
	listenAddr               = flag.String("listen_addr", ":8080", "Public HTTP Read Server address.")
	metricsAddr              = flag.String("metrics_addr", ":9090", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof.")
	pathPrefix               = flag.String("path_prefix", "", "Base URL path prefix to host vindex endpoints under (e.g. '/indices/sumdb' or 'indices/sumdb'). Defaults to empty (root).")
	chunkSize                = flag.Uint64("chunk_size", 65536, "Logical chunk size.")
	commitBatchSize          = flag.Uint64("commit_batch_size", 4096, "Number of leaves accumulated per batch commit.")
	tileCacheDir             = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval             = flag.Duration("poll_interval", 10*time.Second, "Ingestion polling interval.")
	disableReaper            = flag.Bool("disable_reaper", false, "Disable background tile cache reaper to keep tiles cached indefinitely.")
	kvIndexerWorkers         = flag.Int("kv_indexer_workers", 0, "Number of worker goroutines for parallel key indexing (0 = auto).")
	fetchBatchBundles        = flag.Int("fetch_batch_bundles", 50, "Number of leaf bundles fetched per worker batch in Stage 1 (defaults to 50, ~12,800 leaves).")
	dbMaxOpenFiles           = flag.Int("db_max_open_files", 0, "Maximum open files for Pebble DB (0 auto-tunes based on system ulimit -n).")
	dbCacheSizeMB            = flag.Int("db_cache_size_mb", 512, "Pebble block cache size in megabytes (defaults to 512 MB, recommend 4096-16384 on large memory hosts).")
	enableUI                 = flag.Bool("enable_ui", true, "Set to true to serve the single-page HTML UI at / and /index.html.")
	wasmWorkers              = flag.Int("wasm_workers", 0, "Number of concurrent WASM worker instances (0 = auto).")
	fetchWorkers             = flag.Int("fetch_workers", 4, "Number of concurrent tile fetch workers (defaults to 4, 1 disables parallel fetching).")
	inputLogType             = flag.String("input_log_type", "auto", "Input log layout type: 'auto', 'tessera', or 'static-ct'.")
	mutexProfileFraction     = flag.Int("mutex_profile_fraction", 0, "If > 0, enable mutex contention profiling sampling 1/N events.")
	blockProfileRate         = flag.Int("block_profile_rate", 0, "If > 0, enable goroutine blocking profiling with nanosecond rate.")
	cleanDirs                = flag.Bool("clean", false, "Clean db_path, mpt_dir, output_log_dir, and tile_cache_dir on startup.")
	backfillMaxPendingKeys   = flag.Int("backfill_max_pending_keys", 50000000, "Maximum deduplicated keys buffered in memory during Genesis Backfill before flushing to MPT (defaults to 50,000,000, ~5.5 GB RAM).")
	coarseCheckpointInterval = flag.Int("coarse_checkpoint_interval", 50000000, "Maximum leaves between coarse checkpoints during Genesis Backfill (defaults to 50,000,000).")
	prefixPolicyFlag         = flag.String("prefix_policy", "allow", "Prefix query policy for /keys?prefix=<prefix>: 'allow' (default), 'reversed-dns' ('domain', eTLD+1 Public Suffix List), or 'none'.")
	maxPrefixKeysFlag        = flag.Int("max_prefix_keys", server.DefaultMaxPrefixKeys, "Maximum matching keys returned by a single /keys?prefix=<prefix> query before returning HTTP 413.")
	fromFlag                 = flag.Uint64("from", 0, "Starting Input Log leaf index (from) for Output Log commitments and auditor verification.")

	boundListenAddr  atomic.Pointer[string]
	boundMetricsAddr atomic.Pointer[string]
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *mutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(*mutexProfileFraction)
	}
	if *blockProfileRate > 0 {
		runtime.SetBlockProfileRate(*blockProfileRate)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("vindexd failed: %v", err)
	}
}

func validatePublisherFlags() error {
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}
	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}
	if *outputLogDir == "" {
		return errors.New("--output_log_dir flag is required in publisher mode")
	}
	if *outputLogSignerKey == "" {
		return errors.New("--output_log_signer_key flag is required in publisher mode")
	}
	return nil
}

func cleanDirectories() error {
	for _, d := range []string{*dbPath, *mptDir, *outputLogDir, *tileCacheDir} {
		if d != "" {
			if err := os.RemoveAll(d); err != nil {
				return fmt.Errorf("failed to clean directory %q: %w", d, err)
			}
			if err := os.MkdirAll(d, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %q: %w", d, err)
			}
		}
	}
	return nil
}

func run(ctx context.Context) error {
	switch strings.ToLower(*mode) {
	case "publisher", "coordinator", "":
		if err := validatePublisherFlags(); err != nil {
			return err
		}
		if *cleanDirs {
			if err := cleanDirectories(); err != nil {
				return err
			}
		}
		return runPublisher(ctx)
	case "auditor", "verifier":
		if *cleanDirs {
			return errors.New("--clean is not permitted in auditor or verifier mode to protect forensic state")
		}
		return runAuditor(ctx)
	default:
		return fmt.Errorf("unknown mode %q: expected 'publisher', 'auditor', or 'verifier'", *mode)
	}
}

func runPublisher(ctx context.Context) error {
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}

	// 1. Open Pebble DB
	pebbleOpts := &pebble.Options{}
	if *dbMaxOpenFiles > 0 {
		pebbleOpts.MaxOpenFiles = *dbMaxOpenFiles
	}
	if *dbCacheSizeMB > 0 {
		cache := pebble.NewCache(int64(*dbCacheSizeMB) << 20)
		defer cache.Unref()
		pebbleOpts.Cache = cache
	}
	db, err := kvstore.Open(*dbPath, pebbleOpts)
	if err != nil {
		return fmt.Errorf("failed to open Pebble DB at %q: %w", *dbPath, err)
	}
	defer func() { _ = db.Close() }()
	if *chunkSize > 0 {
		db.SetChunkSize(*chunkSize)
	}

	// 2. Start Internal Operational & Public Read HTTP Servers immediately so /healthz (200 OK)
	// and /readyz (503 JSON) on --metrics_addr respond while MPT mmap files are opening and
	// 3-phase crash recovery is running.
	prefixPolicy, err := parsePrefixPolicy(*prefixPolicyFlag)
	if err != nil {
		return err
	}
	readSrv := server.NewReadServer(db, nil, nil, *chunkSize)
	readSrv.SetEnableUI(*enableUI)
	readSrv.SetPathPrefix(*pathPrefix)
	readSrv.SetPrefixPolicy(prefixPolicy)
	readSrv.SetMaxPrefixKeys(*maxPrefixKeysFlag)

	if *metricsAddr != "" {
		metricsMux := http.NewServeMux()
		readSrv.RegisterAdminRoutes(metricsMux)
		metricsServer := &http.Server{
			Addr:    *metricsAddr,
			Handler: metricsMux,
		}
		metricsLn, err := net.Listen("tcp", *metricsAddr)
		if err != nil {
			return fmt.Errorf("failed to bind metrics_addr %q: %w", *metricsAddr, err)
		}
		actualMetricsAddr := metricsLn.Addr().String()
		boundMetricsAddr.Store(&actualMetricsAddr)
		go func() {
			klog.Infof("Serving internal operational endpoints (/metrics, /healthz, /readyz, pprof) at http://%s", actualMetricsAddr)
			if err := metricsServer.Serve(metricsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				klog.Errorf("Metrics server error: %v", err)
			}
		}()
		defer func() { _ = metricsServer.Close() }()
	}

	readMux := http.NewServeMux()
	readSrv.RegisterRoutesWithOutputLog(readMux, *outputLogDir)
	httpServer := &http.Server{
		Addr:    *listenAddr,
		Handler: readMux,
	}

	readLn, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind listen_addr %q: %w", *listenAddr, err)
	}
	actualAddr := readLn.Addr().String()
	boundListenAddr.Store(&actualAddr)
	go func() {
		klog.Infof("Serving VIndex Read API at http://%s", actualAddr)
		if err := httpServer.Serve(readLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Errorf("Read server error: %v", err)
		}
	}()
	defer func() { _ = httpServer.Close() }()

	// 3. Open MPT Manager
	mptMgr, err := mpt.Open(*mptDir)
	if err != nil {
		return fmt.Errorf("failed to open MPT at %q: %w", *mptDir, err)
	}
	defer func() { _ = mptMgr.Close() }()

	// 4. Setup Mapper
	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}
	leafMapper, closeMapper, err := initMapper(ctx, *wasmPath, *wasmWorkers)
	if err != nil {
		return err
	}
	if closeMapper != nil {
		defer closeMapper()
	}

	// 5. Setup Output Log
	if *outputLogDir == "" {
		return errors.New("--output_log_dir flag is required in publisher mode")
	}
	if *outputLogSignerKey == "" {
		return errors.New("--output_log_signer_key flag is required in publisher mode")
	}

	signerKey := *outputLogSignerKey
	keyBytes, fErr := os.ReadFile(signerKey)
	if fErr == nil {
		signerKey = string(bytes.TrimSpace(keyBytes))
	}
	signer, err := note.NewSigner(signerKey)
	if err != nil {
		return fmt.Errorf("failed to construct output log signer: %w", err)
	}

	var posixOpts []tree.POSIXOption
	if *outputLogOrigin != "" {
		posixOpts = append(posixOpts, tree.WithOrigin(*outputLogOrigin))
	}
	if strings.TrimSpace(*witnessURLs) != "" || strings.TrimSpace(*witnessPubKeys) != "" {
		urls := splitNonEmptyCSV(*witnessURLs)
		pubKeys := splitNonEmptyCSV(*witnessPubKeys)
		wg, err := tree.BuildWitnessGroup(urls, pubKeys)
		if err != nil {
			return fmt.Errorf("failed to build witness group: %w", err)
		}
		posixOpts = append(posixOpts, tree.WithDefaultWitnessGroup(wg))
	}

	outputLog, err := tree.NewPOSIXOutputLog(ctx, *outputLogDir, signer, posixOpts...)
	if err != nil {
		return fmt.Errorf("failed to open POSIX output log at %q: %w", *outputLogDir, err)
	}
	defer func() { _ = outputLog.Close() }()

	pub := tree.NewOutputPublisher(db, mptMgr, outputLog, nil)
	if *inputLogOrigin != "" {
		pub.SetInputOrigin(*inputLogOrigin)
	}
	if *fromFlag > 0 {
		pub.SetFrom(*fromFlag)
	}
	idxer := kvstore.NewKVIndexer(db, *chunkSize)
	if *kvIndexerWorkers > 0 {
		idxer.SetNumWorkers(*kvIndexerWorkers)
	}

	// 6. Setup Tile Cache & Fetcher
	if *tileCacheDir == "" {
		klog.Warning("--tile_cache_dir is not set; local disk tile caching is disabled. Historical crash recovery will require re-fetching from upstream.")
	}
	tileCache, err := ingest.NewManagedTileCache(*tileCacheDir, 0)
	if err != nil {
		return fmt.Errorf("failed to initialize tile cache: %w", err)
	}
	if sz, err := tileCache.DirSize(); err == nil {
		metrics.TileCacheBytes.Set(float64(sz))
	}

	var fetcher ingest.TileFetcher
	if *inputLogURL != "" {
		u, err := url.Parse(*inputLogURL)
		if err != nil {
			return fmt.Errorf("invalid input log URL %q: %w", *inputLogURL, err)
		}

		var inVerifier note.Verifier
		var inPolicy wire.Policy
		if strings.TrimSpace(*inputLogPolicy) != "" {
			p, err := wire.ParsePolicyOrVerifier(*inputLogPolicy, *inputLogPubKey, *inputLogOrigin, nil, 0)
			if err != nil {
				return fmt.Errorf("failed to parse input log policy: %w", err)
			}
			inPolicy = p
		} else if strings.TrimSpace(*inputLogPubKey) != "" {
			v, err := wire.ParseVerifier(*inputLogPubKey)
			if err != nil {
				return fmt.Errorf("failed to create input log verifier: %w", err)
			}
			inVerifier = v
			origin := *inputLogOrigin
			if origin == "" {
				origin = v.Name()
			}
			pub.SetInputOrigin(origin)
			p, err := wire.ParsePolicyOrVerifier("", *inputLogPubKey, origin, nil, 0)
			if err != nil {
				return fmt.Errorf("failed to build input log policy: %w", err)
			}
			inPolicy = p
		} else if !*insecureSkipVerify {
			return errors.New("--input_log_policy or --input_log_pubkey is required when --input_log_url is set (or set --insecure_skip_verify for local testing)")
		}

		tf, err := ingest.NewTiledFetcher(u, inVerifier, *inputLogOrigin, nil)
		if err != nil {
			return fmt.Errorf("failed to create input log fetcher: %w", err)
		}
		if inPolicy != nil {
			tf.SetPolicy(inPolicy)
		} else if *insecureSkipVerify {
			tf.SetAllowUnverifiedCheckpoints(true)
		}
		switch strings.ToLower(*inputLogType) {
		case "static-ct", "ct":
			tf.SetStaticCT(true)
		case "tessera":
			tf.SetStaticCT(false)
		case "auto", "":
			// retain auto-detected value
		default:
			return fmt.Errorf("unknown input_log_type %q: expected 'auto', 'tessera', or 'static-ct'", *inputLogType)
		}
		fetcher = tf
	}

	// 7. Run 3-Phase Crash Recovery
	coord := coordinator.NewCoordinator(db, mptMgr, outputLog, pub, idxer, fetcher, tileCache, leafMapper)
	if *wasmWorkers > 0 {
		coord.SetWorkers(*wasmWorkers)
	}
	if *fetchWorkers > 0 {
		coord.SetFetchWorkers(*fetchWorkers)
	}
	if *fetchBatchBundles > 0 {
		coord.SetFetchBatchBundles(*fetchBatchBundles)
	}
	if *backfillMaxPendingKeys > 0 {
		coord.SetBackfillMaxPendingKeys(uint64(*backfillMaxPendingKeys))
	}
	if *coarseCheckpointInterval > 0 {
		coord.SetCoarseCheckpointInterval(uint64(*coarseCheckpointInterval))
	}
	if *commitBatchSize > 0 {
		coord.SetCommitBatchSize(*commitBatchSize)
	}
	readSrv.SetReadyChecker(coord.ReadinessCheck)

	klog.Info("Running 3-phase startup recovery...")
	if err := coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	readSrv.SetBackend(mptMgr, pub)
	klog.Info("Startup recovery completed successfully.")

	// 8. Start Background Tile Reaper
	if !*disableReaper {
		tileReaper := ingest.NewTileReaper(db, mptMgr, tileCache)
		tileReaper.SetWatermarkFunc(coord.SafeWatermark)
		go func() {
			_ = tileReaper.Run(ctx, 60*time.Second)
		}()
	} else {
		klog.Info("Tile cache reaper disabled via --disable_reaper; cached tiles will be retained indefinitely.")
	}

	// 9. Start Ingestion & Commit Pipeline Loop
	if fetcher != nil {
		if *oneShot {
			klog.Info("Running oneshot publisher sync...")
			syncStart := time.Now()
			if err := coord.SyncOnce(ctx); err != nil {
				return fmt.Errorf("oneshot publisher sync failed: %w", err)
			}
			elapsed := time.Since(syncStart)
			klog.Infof("Oneshot publisher sync completed in %v.", elapsed)
			return nil
		}
		klog.Infof("Starting zero-WAL ingestion pipeline polling %q every %v", *inputLogURL, *pollInterval)
		if err := coord.Run(ctx, *pollInterval); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("coordinator run failed: %w", err)
		}
	} else {
		<-ctx.Done()
	}

	klog.Info("Shutting down vindexd gracefully...")
	return nil
}

func runAuditor(ctx context.Context) error {
	if *outputLogSignerKey != "" {
		return errors.New("security invariant violation: --output_log_signer_key must not be specified in verifier mode; verifiers/auditors must never sign output logs")
	}
	if *outputLogURL == "" {
		return errors.New("--output_log_url is required in verifier mode")
	}
	if *inputLogURL == "" {
		return errors.New("--input_log_url is required in verifier mode")
	}
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}
	if *mptDir == "" {
		return errors.New("--mpt_dir flag is required")
	}

	resolvedInPubKey, err := resolveKey(*inputLogPubKey)
	if err != nil {
		return fmt.Errorf("failed to resolve input log pubkey: %w", err)
	}
	resolvedOutPubKey, err := resolveKey(*outputLogPubKey)
	if err != nil {
		return fmt.Errorf("failed to resolve output log pubkey: %w", err)
	}

	var witnessVerifiers []note.Verifier
	for _, wk := range splitNonEmptyCSV(*witnessPubKeys) {
		wv, err := wire.ParseWitnessVerifier(wk)
		if err != nil {
			return fmt.Errorf("failed to parse witness verifier %q: %w", wk, err)
		}
		witnessVerifiers = append(witnessVerifiers, wv)
	}

	var inPolicy wire.Policy
	if strings.TrimSpace(*inputLogPolicy) != "" || resolvedInPubKey != "" {
		p, err := wire.ParsePolicyOrVerifier(*inputLogPolicy, resolvedInPubKey, *inputLogOrigin, nil, 0)
		if err != nil {
			return fmt.Errorf("failed to build input log policy: %w", err)
		}
		inPolicy = p
	}

	var outPolicy wire.Policy
	if strings.TrimSpace(*outputLogPolicy) != "" || resolvedOutPubKey != "" {
		p, err := wire.ParsePolicyOrVerifier(*outputLogPolicy, resolvedOutPubKey, *outputLogOrigin, witnessVerifiers, len(witnessVerifiers))
		if err != nil {
			return fmt.Errorf("failed to build output log policy: %w", err)
		}
		outPolicy = p
	}

	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}
	leafMapper, closeMapper, err := initMapper(ctx, *wasmPath, *wasmWorkers)
	if err != nil {
		return err
	}
	if closeMapper != nil {
		defer closeMapper()
	}

	cfg := auditor.Config{
		InputLogURL:     *inputLogURL,
		InputLogPubKey:  resolvedInPubKey,
		InputLogOrigin:  *inputLogOrigin,
		InputLogPolicy:  inPolicy,
		OutputLogURL:    *outputLogURL,
		OutputLogPubKey: resolvedOutPubKey,
		OutputLogOrigin: *outputLogOrigin,
		OutputLogPolicy: outPolicy,
		MapFn:           leafMapper,
		DBPath:          *dbPath,
		MPTDir:          *mptDir,
		TileCacheDir:    *tileCacheDir,
		MetricsAddr:     *metricsAddr,
		PollInterval:    *pollInterval,
		ChunkSize:       *chunkSize,
		CommitBatchSize: *commitBatchSize,
	}
	if isFlagPassed("from") {
		fromVal := *fromFlag
		cfg.ExpectedFrom = &fromVal
	}

	v, err := auditor.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize auditor engine: %w", err)
	}
	defer func() { _ = v.Close() }()

	if *oneShot {
		klog.Info("Running oneshot verification...")
		if err := v.VerifyOnce(ctx); err != nil {
			return fmt.Errorf("oneshot verification failed: %w", err)
		}
		klog.Info("Oneshot verification succeeded.")
		return nil
	}

	klog.Infof("Starting auditor daemon (poll interval: %v)...", *pollInterval)
	return v.Run(ctx)
}

func resolveKey(keyOrPath string) (string, error) {
	keyOrPath = strings.TrimSpace(keyOrPath)
	if keyOrPath == "" {
		return "", nil
	}
	if data, err := os.ReadFile(keyOrPath); err == nil {
		return string(bytes.TrimSpace(data)), nil
	}
	return keyOrPath, nil
}

func splitNonEmptyCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func initMapper(ctx context.Context, wasm string, numWorkers int) (ingest.LeafMapper, func(), error) {
	if wasm == "" {
		return nil, nil, errors.New("--wasm_path flag is required")
	}
	wasmBytes, err := os.ReadFile(wasm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read WASM binary %q: %w", wasm, err)
	}
	host, err := wasmhost.NewWASMHost(ctx, wasmBytes, numWorkers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize WASM host: %w", err)
	}
	return host, func() { _ = host.Close(ctx) }, nil
}
