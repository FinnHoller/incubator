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

// mtcindex brings up a verifiable index for the Merkle Tree Certificates (MTC) log.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/publicsuffix"
	"k8s.io/klog/v2"
)

var (
	logURL             = flag.String("log_url", "https://bootstrap-mtca-shard3.cloudflareresearch.com/", "Base URL of the MTC log")
	origin             = flag.String("origin", "bootstrap-mtca.cloudflareresearch.com/logs/shard3", "The expected origin string in the checkpoint")
	keyName            = flag.String("key_name", "oid/1.3.6.1.4.1.44363.47.1.44363.48.8", "The key name used in the checkpoint signature")
	logPublicKey       = flag.String("log_public_key", "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=", "The log's public key, base64 encoded raw 32-byte Ed25519 key")
	cosignerID         = flag.String("cosigner_id", "44363.48.9", "The relative OID of the cosigner")
	logID              = flag.String("log_id", "44363.48.8", "The relative OID of the log")
	storageDir         = flag.String("storage_dir", "", "Root directory for storage (required)")
	listenAddr         = flag.String("listen_addr", ":8088", "HTTP Read Server address")
	listen             = flag.String("listen", "", "Alias for listen_addr")
	metricsAddr        = flag.String("metrics_addr", "", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof (optional)")
	outputLogDir       = flag.String("output_log_dir", "", "Path for local Output Log storage")
	outputLogOrigin    = flag.String("output_log_origin", "MTCIndex", "Origin string for the Output Log")
	outputLogSignerKey = flag.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints")
	oneShot            = flag.Bool("oneshot", false, "Run once and exit")
	pollInterval       = flag.Duration("poll_interval", 10*time.Second, "Polling interval for input log updates")
	chunkSize          = flag.Uint64("chunk_size", 65536, "Logical chunk size for inverted index")
	enableUI           = flag.Bool("enable_ui", true, "Set to true to serve the single-page HTML UI at / and /index.html")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("Run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *storageDir == "" {
		return errors.New("storage_dir must be set")
	}

	pebbleDir := filepath.Join(*storageDir, "pebble")
	mptDir := filepath.Join(*storageDir, "mpt")
	outLogDir := *outputLogDir
	if outLogDir == "" {
		outLogDir = filepath.Join(*storageDir, "outputlog")
	}
	tileCacheDir := filepath.Join(*storageDir, "tilecache")

	for _, d := range []string{pebbleDir, mptDir, outLogDir, tileCacheDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", d, err)
		}
	}

	// 1. Storage DB
	db, err := kvstore.Open(pebbleDir, &pebble.Options{})
	if err != nil {
		return fmt.Errorf("failed to open Pebble DB at %q: %w", pebbleDir, err)
	}
	defer func() { _ = db.Close() }()

	// 2. MPT Manager
	mptMgr, err := mpt.Open(mptDir)
	if err != nil {
		return fmt.Errorf("failed to open MPT at %q: %w", mptDir, err)
	}
	defer func() { _ = mptMgr.Close() }()

	// 3. Leaf Mapper
	leafMapper := &mtcLeafMapper{}
	defer func() { _ = leafMapper.Close(ctx) }()

	// 4. Output Log
	signer := getOutputLogSigner()
	outputLog, err := newLocalOutputLog(*outputLogOrigin, outLogDir, signer)
	if err != nil {
		return fmt.Errorf("failed to initialize output log: %w", err)
	}

	pub := tree.NewOutputPublisher(db, mptMgr, outputLog, nil)
	pub.SetInputOrigin(*origin)
	idxer := kvstore.NewKVIndexer(db, *chunkSize)

	// Setup Tile Cache
	tileCache, err := ingest.NewManagedTileCache(tileCacheDir, 0)
	if err != nil {
		return fmt.Errorf("failed to create tile cache: %w", err)
	}

	// Setup MTC Verifier & Input Log Fetcher
	pubKeyBytes, err := base64.StdEncoding.DecodeString(*logPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode log_public_key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid log_public_key size: %d, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	mtcVerifier, err := mtc.NewMTCVerifier(*keyName, pubKey, *cosignerID, *logID)
	if err != nil {
		return fmt.Errorf("failed to create MTCVerifier: %w", err)
	}

	parsedLogURL, err := url.Parse(*logURL)
	if err != nil {
		return fmt.Errorf("failed to parse log_url: %w", err)
	}

	fetcher, err := ingest.NewTiledFetcher(parsedLogURL, mtcVerifier, *origin, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to create input log fetcher: %w", err)
	}

	// 5. Crash Recovery
	coord := coordinator.NewCoordinator(db, mptMgr, outputLog, pub, idxer, fetcher, tileCache, leafMapper)
	klog.Info("Running startup recovery...")
	if err := coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	klog.Info("Startup recovery completed.")

	// 6. Initialize ReadServer & Internal Operational Server
	readSrv := server.NewReadServer(db, mptMgr, pub, *chunkSize)
	readSrv.SetEnableUI(*enableUI)
	readSrv.SetPrefixPolicy(reversedDNSPrefixPolicy)
	readSrv.SetReadyChecker(coord.ReadinessCheck)

	if *metricsAddr != "" {
		metricsMux := http.NewServeMux()
		readSrv.RegisterAdminRoutes(metricsMux)
		metricsLn, err := net.Listen("tcp", *metricsAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on metrics_addr %s: %w", *metricsAddr, err)
		}
		metricsServer := &http.Server{
			Handler: metricsMux,
		}
		go func() {
			klog.Infof("Serving internal operational endpoints at http://%s", metricsLn.Addr().String())
			if err := metricsServer.Serve(metricsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				klog.Errorf("Metrics server error: %v", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = metricsServer.Shutdown(shutdownCtx)
		}()
	}

	// 7. Public HTTP Read Server
	mux := http.NewServeMux()
	readSrv.RegisterRoutes(mux)

	olfs := http.FileServer(http.Dir(outLogDir))
	mux.Handle("/outputlog/", http.StripPrefix("/outputlog/", olfs))

	srvAddr := *listenAddr
	if *listen != "" {
		srvAddr = *listen
	}

	listener, err := net.Listen("tcp", srvAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", srvAddr, err)
	}

	httpServer := &http.Server{
		Handler: mux,
	}
	go func() {
		klog.Infof("Started HTTP server listening on %s", listener.Addr().String())
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Errorf("HTTP server error: %v", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	// 8. Background Tile Reaper
	tileReaper := ingest.NewTileReaper(db, mptMgr, tileCache)
	go func() {
		_ = tileReaper.Run(ctx, 60*time.Second)
	}()

	// 9. Ingestion & Polling Loop
	if *oneShot {
		if err := coord.SyncOnce(ctx); err != nil {
			return fmt.Errorf("failed to update index: %w", err)
		}
		klog.Info("Oneshot index build complete.")
		return nil
	}

	if err := coord.Run(ctx, *pollInterval); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("coordinator run failed: %w", err)
	}

	klog.Info("Shutting down mtcindex gracefully...")
	return nil
}

type localOutputLog struct {
	mu     sync.Mutex
	origin string
	dir    string
	signer note.Signer
	leaves [][]byte
}

func newLocalOutputLog(origin, dir string, signer note.Signer) (*localOutputLog, error) {
	l := &localOutputLog{
		origin: origin,
		dir:    dir,
		signer: signer,
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create output log directory: %w", err)
		}
		leavesPath := filepath.Join(dir, "leaves.dat")
		if data, err := os.ReadFile(leavesPath); err == nil {
			offset := 0
			for offset < len(data) {
				if offset+4 > len(data) {
					break
				}
				leafLen := binary.BigEndian.Uint32(data[offset : offset+4])
				offset += 4
				if offset+int(leafLen) > len(data) {
					break
				}
				leaf := make([]byte, leafLen)
				copy(leaf, data[offset:offset+int(leafLen)])
				offset += int(leafLen)
				l.leaves = append(l.leaves, leaf)
			}
		}
	}
	return l, nil
}

func (l *localOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	idx := uint64(len(l.leaves))
	leafCopy := append([]byte(nil), leafData...)
	l.leaves = append(l.leaves, leafCopy)
	size := uint64(len(l.leaves))

	root := kvstore.BatchRoot(l.leaves)
	var rawCP []byte
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		signed, err := note.Sign(&note.Note{Text: text}, l.signer)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to sign checkpoint note: %w", err)
		}
		rawCP = signed
	} else {
		rawCP = []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:])))
	}

	if l.dir != "" {
		leavesPath := filepath.Join(l.dir, "leaves.dat")
		f, err := os.OpenFile(leavesPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(leafData)))
			_, _ = f.Write(lenBuf[:])
			_, _ = f.Write(leafData)
			_ = f.Close()
		}
		_ = os.WriteFile(filepath.Join(l.dir, "checkpoint"), rawCP, 0o644)
	}

	return idx, rawCP, nil
}

func (l *localOutputLog) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves)), nil
}

func (l *localOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *localOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		return note.Sign(&note.Note{Text: text}, l.signer)
	}
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))), nil
}

func (l *localOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if treeSize > uint64(len(l.leaves)) {
		return nil, fmt.Errorf("treeSize %d > current size %d", treeSize, len(l.leaves))
	}
	if leafIdx >= treeSize {
		return nil, fmt.Errorf("leafIdx %d >= treeSize %d", leafIdx, treeSize)
	}

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

func getOutputLogSigner() note.Signer {
	var privKey string
	if len(*outputLogSignerKey) > 0 {
		keyBytes, err := os.ReadFile(*outputLogSignerKey)
		if err == nil {
			privKey = string(keyBytes)
		} else {
			privKey = *outputLogSignerKey
		}
	} else {
		privKey = os.Getenv("OUTPUT_LOG_PRIVATE_KEY")
	}
	if len(privKey) == 0 {
		return nil
	}
	s, _, err := fnote.NewEd25519SignerVerifier(privKey)
	if err != nil {
		s2, err2 := note.NewSigner(privKey)
		if err2 != nil {
			klog.Exitf("Failed to construct note signer: %v", err2)
		}
		return s2
	}
	return s
}

type mtcLeafMapper struct{}

func (m *mtcLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	var entries []ingest.MappedEntry
	mtc.ExtractDomainNames(leaf, func(name string) {
		entries = append(entries, ingest.MappedEntry{
			Key:     name,
			KeyHash: sha256.Sum256([]byte(name)),
		})
	})
	return entries, nil
}

func (m *mtcLeafMapper) Close(_ context.Context) error {
	return nil
}

var _ ingest.LeafMapper = (*mtcLeafMapper)(nil)

func reversedDNSPrefixPolicy(prefix string) error {
	if prefix == "" || !strings.HasSuffix(prefix, ".") {
		return errors.New("reversed-dns prefix must end with a label delimiter '.' (e.g. 'com.example.')")
	}
	trimmed := strings.TrimSuffix(prefix, ".")
	if trimmed == "" || strings.HasPrefix(trimmed, ".") || strings.Contains(trimmed, "..") {
		return fmt.Errorf("invalid reversed-dns prefix %q: empty domain label", prefix)
	}
	revLabels := strings.Split(trimmed, ".")
	fwdLabels := make([]string, len(revLabels))
	for i, lbl := range revLabels {
		lower := strings.ToLower(lbl)
		if lower != lbl {
			return fmt.Errorf("invalid reversed-dns prefix %q: domain labels must be lowercase", prefix)
		}
		if lbl == "*" {
			if i != len(revLabels)-1 {
				return fmt.Errorf("invalid reversed-dns prefix %q: wildcard '*' only permitted as leaf-most label", prefix)
			}
			fwdLabels[len(revLabels)-1-i] = "wildcard"
			continue
		}
		if strings.Contains(lbl, "*") {
			return fmt.Errorf("invalid reversed-dns prefix %q: partial wildcard label %q not permitted", prefix, lbl)
		}
		fwdLabels[len(revLabels)-1-i] = lower
	}
	domain := strings.Join(fwdLabels, ".")
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil || etldPlusOne == "" {
		return fmt.Errorf("prefix %q (%s) is broader than an eTLD+1 registrable domain", prefix, domain)
	}
	return nil
}
