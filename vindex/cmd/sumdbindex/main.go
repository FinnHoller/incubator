// Copyright 2025 Google LLC. All Rights Reserved.
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

// sumdbindex brings up a verifiable index for the Go SumDB.
// This requires a proxy to be running to bridge to a tlog-tiles API.
// See the README for usage details.
package main

import (
	"bytes"
	"context"
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
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/sumdb"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	outputLogPrivKeyFile = flag.String("output_log_private_key_path", "", "Location of private key file. If unset, uses the contents of the OUTPUT_LOG_PRIVATE_KEY environment variable.")
	outputLogOrigin      = flag.String("output_log_origin", "SumDBIndex", "Origin string for the Output Log.")
	storageDir           = flag.String("storage_dir", "", "Root directory in which to store the data for the index and output log.")
	witnessSigs          = flag.Uint("witnesses", 0, "Number of witness signatures required on the SumDB checkpoint. Setting this will pull checkpoints from the transparency-dev prod distributor.")
	listen               = flag.String("listen", ":8088", "Address to set up HTTP server listening on.")
	metricsAddr          = flag.String("metrics_addr", "", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof (optional).")

	oneShot          = flag.Bool("oneshot", false, "Set to true to build the map once and then exit.")
	inputOverrideUrl = flag.String("input_override_url", "", "Set this to read from a different URL than the local proxy. Supports file paths. Intended for performance testing. Note this log MUST be presented as tlog-tiles format.")
	chunkSize        = flag.Uint64("chunk_size", 65536, "Logical chunk size for inverted index.")
	pollInterval     = flag.Duration("poll_interval", 10*time.Second, "Polling interval for input log updates.")
	enableUI         = flag.Bool("enable_ui", true, "Set to true to serve the single-page HTML UI at / and /index.html.")
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
	outputLogDir := filepath.Join(*storageDir, "outputlog")
	tileCacheDir := filepath.Join(*storageDir, "tilecache")

	for _, d := range []string{pebbleDir, mptDir, outputLogDir, tileCacheDir} {
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
	leafMapper := &SumDBLeafMapper{}

	// 4. Output Log
	signer := getOutputLogSigner()
	outputLog, err := newLocalOutputLog(*outputLogOrigin, outputLogDir, signer)
	if err != nil {
		return fmt.Errorf("failed to initialize output log: %w", err)
	}

	pub := tree.NewOutputPublisher(db, mptMgr, outputLog, nil)
	pub.SetInputOrigin("go.sum database tree")
	idxer := kvstore.NewKVIndexer(db, *chunkSize)

	// Setup Tile Cache
	tileCache, err := ingest.NewManagedTileCache(tileCacheDir, 0)
	if err != nil {
		return fmt.Errorf("failed to create tile cache: %w", err)
	}

	// 5. Proxy & HTTP Server
	sumProxy := sumdb.NewProxy(sumdb.ProxyOpts{
		PathPrefix:  "/inputlog/",
		WitnessSigs: *witnessSigs,
	})

	readSrv := server.NewReadServer(db, mptMgr, pub, *chunkSize)
	readSrv.SetEnableUI(*enableUI)

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

	mux := http.NewServeMux()
	readSrv.RegisterRoutes(mux)
	mux.Handle("/inputlog/", sumProxy)

	olfs := http.FileServer(http.Dir(outputLogDir))
	mux.Handle("/outputlog/", http.StripPrefix("/outputlog/", olfs))

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", *listen, err)
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

	// 6. Setup Input Log Fetcher
	sumV, err := note.NewVerifier("sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8")
	if err != nil {
		return fmt.Errorf("failed to construct SumDB verifier: %w", err)
	}

	inPath := fmt.Sprintf("http://127.0.0.1:%d/inputlog/", listener.Addr().(*net.TCPAddr).Port)
	if *inputOverrideUrl != "" {
		inPath = *inputOverrideUrl
	}
	sumUrl, err := url.Parse(inPath)
	if err != nil {
		return fmt.Errorf("invalid input log URL %q: %w", inPath, err)
	}

	fetcher, err := ingest.NewTiledFetcher(sumUrl, sumV, "go.sum database tree", http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to create input log fetcher: %w", err)
	}

	// 7. Crash Recovery & Coordinator
	coord := coordinator.NewCoordinator(db, mptMgr, outputLog, pub, idxer, fetcher, tileCache, leafMapper)
	readSrv.SetReadyChecker(coord.ReadinessCheck)
	klog.Info("Running startup recovery...")
	if err := coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	klog.Info("Startup recovery completed.")

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

	klog.Info("Shutting down sumdbindex gracefully...")
	return nil
}

// SumDBLeafMapper implements ingest.LeafMapper for SumDB module parsing.
type SumDBLeafMapper struct{}

func (m *SumDBLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	key, ok := extractSumDBModuleKey(leaf)
	if !ok {
		return nil, nil
	}
	return []ingest.MappedEntry{{
		Key:     key,
		KeyHash: sha256.Sum256([]byte(key)),
	}}, nil
}

func (m *SumDBLeafMapper) Close(_ context.Context) error {
	return nil
}

func extractSumDBModuleBytes(data []byte) ([]byte, string, bool) {
	modEnd := bytes.IndexByte(data, ' ')
	if modEnd <= 0 {
		return nil, "", false
	}

	verStart := modEnd + 1
	verLen := bytes.IndexByte(data[verStart:], ' ')
	if verLen == -1 {
		return nil, "", false
	}
	verBytes := bytes.TrimSuffix(data[verStart:verStart+verLen], []byte("/go.mod"))

	// Fast zero-allocation pseudo-version filter
	if isPseudoVersion(verBytes) {
		return nil, "", false
	}

	rawMod := data[:modEnd]
	if isSimpleLowercaseModulePath(rawMod) {
		if len(rawMod) > 1024 {
			return nil, "", false
		}
		return rawMod, "", true
	}
	escaped, err := module.EscapePath(string(rawMod))
	if err != nil || escaped == "" || len(escaped) > 1024 {
		return nil, "", false
	}
	return nil, escaped, true
}

func isPseudoVersion(v []byte) bool {
	if len(v) < 30 || v[0] != 'v' {
		return false
	}
	if idx := bytes.IndexByte(v, '+'); idx != -1 {
		build := v[idx+1:]
		if len(build) == 0 {
			return false
		}
		for _, b := range build {
			if !isIdentChar(b) && b != '.' {
				return false
			}
		}
		v = v[:idx]
	}
	lastDash := bytes.LastIndexByte(v, '-')
	if lastDash == -1 {
		return false
	}
	rev := v[lastDash+1:]
	if len(rev) == 0 {
		return false
	}
	for _, b := range rev {
		if !isAlnum(b) {
			return false
		}
	}
	rest := v[:lastDash]
	secondDash := bytes.LastIndexByte(rest, '-')
	if secondDash == -1 {
		return false
	}
	var timestamp, prefix []byte
	dotAfterDash := bytes.LastIndexByte(rest[secondDash:], '.')
	if dotAfterDash != -1 {
		dotPos := secondDash + dotAfterDash
		timestamp = rest[dotPos+1:]
		prefix = rest[:dotPos]
	} else {
		timestamp = rest[secondDash+1:]
		prefix = rest[:secondDash]
	}
	if len(timestamp) != 14 {
		return false
	}
	for _, b := range timestamp {
		if b < '0' || b > '9' {
			return false
		}
	}
	if dotAfterDash == -1 {
		return isMajorDotZeroDotZero(prefix)
	}
	if !bytes.HasSuffix(prefix, []byte(".0")) && !bytes.HasSuffix(prefix, []byte("-0")) {
		return false
	}
	dashIdx := bytes.IndexByte(prefix, '-')
	if dashIdx == -1 {
		return false
	}
	return isBaseSemver(prefix[:dashIdx])
}

func isMajorDotZeroDotZero(s []byte) bool {
	if len(s) < 6 || s[0] != 'v' || !bytes.HasSuffix(s, []byte(".0.0")) {
		return false
	}
	major := s[1 : len(s)-4]
	if len(major) == 0 || (len(major) > 1 && major[0] == '0') {
		return false
	}
	for _, b := range major {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func isBaseSemver(s []byte) bool {
	if len(s) < 6 || s[0] != 'v' {
		return false
	}
	s = s[1:]
	dot1 := bytes.IndexByte(s, '.')
	if dot1 <= 0 {
		return false
	}
	major := s[:dot1]
	if len(major) > 1 && major[0] == '0' {
		return false
	}
	for _, b := range major {
		if b < '0' || b > '9' {
			return false
		}
	}
	s = s[dot1+1:]
	dot2 := bytes.IndexByte(s, '.')
	if dot2 <= 0 {
		return false
	}
	minor := s[:dot2]
	if len(minor) > 1 && minor[0] == '0' {
		return false
	}
	for _, b := range minor {
		if b < '0' || b > '9' {
			return false
		}
	}
	patch := s[dot2+1:]
	if len(patch) == 0 || (len(patch) > 1 && patch[0] == '0') {
		return false
	}
	for _, b := range patch {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentChar(b byte) bool {
	return isAlnum(b) || b == '-'
}

func extractSumDBModuleKey(data []byte) (string, bool) {
	rawMod, escaped, ok := extractSumDBModuleBytes(data)
	if !ok {
		return "", false
	}
	if escaped != "" {
		return escaped, true
	}
	return string(rawMod), true
}

func mapFn(data []byte) [][32]byte {
	rawMod, escaped, ok := extractSumDBModuleBytes(data)
	if !ok {
		return nil
	}
	if escaped != "" {
		return [][32]byte{sha256.Sum256([]byte(escaped))}
	}
	return [][32]byte{sha256.Sum256(rawMod)}
}

func isSimpleLowercaseModulePath(p []byte) bool {
	if len(p) == 0 || p[0] == '/' || p[len(p)-1] == '/' || p[len(p)-1] == '.' {
		return false
	}
	hasDotInFirstElem := false
	inFirstElem := true
	segStart := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			if i == segStart || p[i-1] == '.' {
				return false
			}
			inFirstElem = false
			segStart = i + 1
			continue
		}
		if c == '.' {
			if i == segStart || (i+1 < len(p) && p[i+1] == '.') {
				return false
			}
			if inFirstElem {
				hasDotInFirstElem = true
			}
			continue
		}
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return hasDotInFirstElem
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

func (l *localOutputLog) Checkpoint(ctx context.Context) ([]byte, error) {
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
	var err error
	if len(*outputLogPrivKeyFile) > 0 {
		privKey, err = getKeyFile(*outputLogPrivKeyFile)
		if err != nil {
			klog.Exitf("Unable to get private key: %v", err)
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

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}
