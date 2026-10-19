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

// Package server provides HTTP read endpoints for the Verifiable Index wire protocol.
package server

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
)

//go:embed index.html
var defaultIndexHTML []byte

const (
	defaultLookupLimit   uint64 = 100
	DefaultMaxPrefixKeys int    = 10000
)

// HealthChecker determines whether the server or underlying subsystems are healthy.
// It returns nil if healthy, or an error detailing the health failure.
type HealthChecker func() error

// CleanPathPrefix cleans and normalizes a URL path prefix.
// It ensures a leading slash and strips any trailing slashes.
// An empty or "/" prefix is returned as "".
func CleanPathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return ""
	}
	return "/" + prefix
}

// ReadServer serves HTTP lookup and checkpoint queries.
type ReadServer struct {
	backendMu     sync.RWMutex
	store         kvstore.IndexStore
	mptMgr        *mpt.Manager
	publisher     *tree.OutputPublisher
	chunkSize     uint64
	enableUI      bool
	pathPrefix    string
	prefixPolicy  PrefixPolicy
	maxPrefixKeys int
	healthMu      sync.RWMutex
	healthChecker HealthChecker
	readyChecker  HealthChecker
}

// NewReadServer creates a new ReadServer instance.
func NewReadServer(store kvstore.IndexStore, mptMgr *mpt.Manager, pub *tree.OutputPublisher, chunkSize uint64) *ReadServer {
	if chunkSize == 0 {
		chunkSize = kvstore.ChunkSize
	}
	if store != nil {
		store.SetChunkSize(chunkSize)
	}
	return &ReadServer{
		store:         store,
		mptMgr:        mptMgr,
		publisher:     pub,
		chunkSize:     chunkSize,
		enableUI:      true,
		prefixPolicy:  AllowAllPrefixPolicy,
		maxPrefixKeys: DefaultMaxPrefixKeys,
	}
}

// SetPrefixPolicy configures the policy function invoked before executing ?prefix=<prefix> queries on /keys.
func (s *ReadServer) SetPrefixPolicy(policy PrefixPolicy) {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	s.prefixPolicy = policy
}

// SetMaxPrefixKeys configures the maximum number of keys a ?prefix=<prefix> query on /keys may return before failing with HTTP 413.
func (s *ReadServer) SetMaxPrefixKeys(maxKeys int) {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	if maxKeys <= 0 {
		maxKeys = DefaultMaxPrefixKeys
	}
	s.maxPrefixKeys = maxKeys
}

// SetBackend attaches or updates the MPT Manager and OutputPublisher after asynchronous initialization.
func (s *ReadServer) SetBackend(mptMgr *mpt.Manager, pub *tree.OutputPublisher) {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	s.mptMgr = mptMgr
	s.publisher = pub
}

func (s *ReadServer) getBackend() (*mpt.Manager, *tree.OutputPublisher) {
	s.backendMu.RLock()
	defer s.backendMu.RUnlock()
	return s.mptMgr, s.publisher
}

// ChunkSize returns the configured chunk capacity.
func (s *ReadServer) ChunkSize() uint64 {
	if s.chunkSize == 0 {
		return kvstore.ChunkSize
	}
	return s.chunkSize
}

// SetEnableUI configures whether the single-page HTML UI is served.
func (s *ReadServer) SetEnableUI(enable bool) {
	s.enableUI = enable
}

// SetPathPrefix configures the URL path prefix under which endpoints are served.
func (s *ReadServer) SetPathPrefix(prefix string) {
	s.pathPrefix = CleanPathPrefix(prefix)
}

// PathPrefix returns the normalized path prefix.
func (s *ReadServer) PathPrefix() string {
	return s.pathPrefix
}

// Publisher returns the underlying OutputPublisher.
func (s *ReadServer) Publisher() *tree.OutputPublisher {
	_, pub := s.getBackend()
	return pub
}

// SetHealthChecker registers a dynamic health check callback for /healthz. If hc is nil,
// the server defaults to returning healthy (HTTP 200 "ok\n").
func (s *ReadServer) SetHealthChecker(hc HealthChecker) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	s.healthChecker = hc
}

// SetReadyChecker registers a dynamic readiness check callback for /readyz.
func (s *ReadServer) SetReadyChecker(rc HealthChecker) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	s.readyChecker = rc
}

// RegisterRoutes registers public HTTP endpoints on the provided ServeMux.
// If s.PathPrefix() is non-empty, routes are mounted under the prefix.
func (s *ReadServer) RegisterRoutes(mux *http.ServeMux) {
	s.RegisterRoutesWithOutputLog(mux, "")
}

// RegisterAdminRoutes registers internal operational endpoints (/healthz, /readyz, /metrics, /debug/pprof/*)
// onto an internal administrative/metrics ServeMux (--metrics_addr).
func (s *ReadServer) RegisterAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.HandleHealthz)
	mux.HandleFunc("/readyz", s.HandleReadyz)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// RegisterRoutesWithOutputLog registers public HTTP endpoints and optionally mounts output log tile servers.
// If outputLogDir is non-empty, /tile/ is served from that directory.
// If s.PathPrefix() is non-empty, all routes (including tile servers) are mounted under the prefix.
func (s *ReadServer) RegisterRoutesWithOutputLog(mux *http.ServeMux, outputLogDir string) {
	prefix := s.pathPrefix
	if prefix == "" {
		s.registerEndpoints(mux, outputLogDir)
		return
	}

	// Internal sub-mux with clean un-prefixed routes
	subMux := http.NewServeMux()
	s.registerEndpoints(subMux, outputLogDir)

	// Mount under prefix (strip prefix so handlers match root paths)
	mux.Handle(prefix+"/", http.StripPrefix(prefix, subMux))

	// Serve UI directly on /prefix without 3xx redirect (C2SP tlog-vindex forbids 3xx redirects)
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		if !s.enableUI {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(defaultIndexHTML)
		}
	})
}

func (s *ReadServer) registerEndpoints(mux *http.ServeMux, outputLogDir string) {
	if s.enableUI {
		mux.HandleFunc("/", s.HandleUI)
		mux.HandleFunc("/index.html", s.HandleUI)
	}

	mux.HandleFunc("/checkpoint", s.HandleCheckpoint)
	mux.HandleFunc("/keys", s.HandleKeys)
	mux.HandleFunc("/values", s.HandleValues)

	if outputLogDir != "" {
		mux.Handle("/tile/", http.FileServer(http.Dir(outputLogDir)))
	}
}

// HandleUI handles GET / and /index.html requests serving the single-page HTML UI.
func (s *ReadServer) HandleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(defaultIndexHTML)
	}
}

// HandleCheckpoint handles GET /checkpoint.
func (s *ReadServer) HandleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, pub := s.getBackend()
	if pub == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "checkpoint not ready", http.StatusServiceUnavailable)
		return
	}
	state := pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "checkpoint not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(state.RawCheckpoint)
}

// HandleHealthz handles GET /healthz (liveness probe).
func (s *ReadServer) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.healthMu.RLock()
	hc := s.healthChecker
	s.healthMu.RUnlock()

	if hc != nil {
		if err := hc(); err != nil {
			http.Error(w, fmt.Sprintf("unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// HandleReadyz handles GET /readyz (readiness probe).
func (s *ReadServer) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.healthMu.RLock()
	rc := s.readyChecker
	if rc == nil {
		rc = s.healthChecker
	}
	s.healthMu.RUnlock()
	if rc != nil {
		if err := rc(); err != nil {
			w.Header().Set("Retry-After", "30")
			type jsonDiagnosticsProvider interface {
				JSONDiagnostics() []byte
			}
			if diag, ok := err.(jsonDiagnosticsProvider); ok {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write(diag.JSONDiagnostics())
				return
			}
			http.Error(w, fmt.Sprintf("unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
	}
	mptMgr, pub := s.getBackend()
	if mptMgr == nil || pub == nil {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n"))
		return
	}
	state := pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// HandleKeys handles GET /keys?key=<key> or GET /keys?prefix=<prefix> queries.
// Point mode (?key=<key>) proves exact inclusion or non-inclusion in the MPT.
// Prefix mode (?prefix=<prefix>) validates the prefix against the configured PrefixPolicy, proves
// the prefix path, and scans up to maxPrefixKeys matching (key, valueRoot) pairs from the MPT.
func (s *ReadServer) HandleKeys(w http.ResponseWriter, r *http.Request) {
	startLookup := time.Now()
	defer func() {
		metrics.LookupLatencySeconds.Observe(time.Since(startLookup).Seconds())
	}()

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyStr, isPrefix, err := parseKeysQuery(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
		return
	}

	s.backendMu.RLock()
	mptMgr := s.mptMgr
	pub := s.publisher
	policy := s.prefixPolicy
	maxKeys := s.maxPrefixKeys
	s.backendMu.RUnlock()

	if isPrefix && policy != nil {
		if err := policy(keyStr); err != nil {
			http.Error(w, fmt.Sprintf("prefix rejected by policy: %v", err), http.StatusBadRequest)
			return
		}
	}

	if mptMgr == nil || pub == nil {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n"))
		return
	}
	if pub.GetServingState() == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}

	if !isPrefix {
		mptMgr.RLock()
		state := pub.GetServingState()
		if state == nil {
			mptMgr.RUnlock()
			w.Header().Set("Retry-After", "30")
			http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
			return
		}
		proof, val, exists, err := mptMgr.ProveKeyLocked([]byte(keyStr))
		mptMgr.RUnlock()

		if err != nil {
			http.Error(w, fmt.Sprintf("failed to generate MPT key proof: %v", err), http.StatusInternalServerError)
			return
		}

		var respBytes []byte
		if !exists {
			respBytes = FormatKeysResponse(state, "non-inclusion", proof, nil)
		} else {
			respBytes = FormatKeysResponse(state, "inclusion", proof, []mpt.PrefixKeyVal{{Key: keyStr, ValueRoot: val}})
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
		return
	}

	if maxKeys <= 0 {
		maxKeys = DefaultMaxPrefixKeys
	}

	mptMgr.RLock()
	state := pub.GetServingState()
	if state == nil {
		mptMgr.RUnlock()
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}
	proof, matches, err := mptMgr.ProvePrefixLocked([]byte(keyStr), maxKeys)
	mptMgr.RUnlock()

	if errors.Is(err, mpt.ErrPrefixTooManyKeys) {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate MPT prefix proof: %v", err), http.StatusInternalServerError)
		return
	}

	respBytes := FormatKeysResponse(state, "prefix", proof, matches)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func parseStrictPositiveUint64(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty integer")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, errors.New("leading zeroes not allowed")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("non-digit character")
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("must be a positive integer > 0")
	}
	return v, nil
}

// HandleValues handles GET /values?key=<key>&before=<before> queries.
// It hashes <key> with SHA-256 and queries Pebble directly without acquiring any MPT read lock.
func (s *ReadServer) HandleValues(w http.ResponseWriter, r *http.Request) {
	startLookup := time.Now()
	defer func() {
		metrics.LookupLatencySeconds.Observe(time.Since(startLookup).Seconds())
	}()

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q, err := parseRFC3986Query(r.URL.RawQuery)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid query: %v", err), http.StatusBadRequest)
		return
	}
	for k := range q {
		if k != "key" && k != "before" {
			http.Error(w, fmt.Sprintf("unknown query parameter %q", k), http.StatusBadRequest)
			return
		}
	}

	keyStr, err := extractCanonicalKey(q)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
		return
	}

	beforeVals, hasBefore := q["before"]
	if len(beforeVals) > 1 {
		http.Error(w, "duplicate before parameter not allowed", http.StatusBadRequest)
		return
	}
	if !hasBefore || beforeVals[0] == "" {
		http.Error(w, "missing required before parameter", http.StatusBadRequest)
		return
	}
	beforeStr := beforeVals[0]
	parsedBefore, err := parseStrictPositiveUint64(beforeStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid before parameter %q: %v", beforeStr, err), http.StatusBadRequest)
		return
	}

	limit := defaultLookupLimit

	if s.store == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "storage not initialized", http.StatusServiceUnavailable)
		return
	}

	// Lock-free atomic pointer check on OutputPublisher serving state (zero MPT lock acquisitions).
	_, pub := s.getBackend()
	if pub == nil {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n"))
		return
	}
	state := pub.GetServingState()
	if state == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}

	if parsedBefore > state.InputLogSize {
		w.Header().Set("Retry-After", "30")
		http.Error(w, fmt.Sprintf("before (%d) exceeds indexed input log size (%d)", parsedBefore, state.InputLogSize), http.StatusServiceUnavailable)
		return
	}

	keyHash := sha256.Sum256([]byte(keyStr))
	lookupRes, err := s.store.Lookup(keyHash, &parsedBefore, limit, state.InputLogSize)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to lookup key in storage: %v", err), http.StatusInternalServerError)
		return
	}
	if (lookupRes == nil || len(lookupRes.MatchedIndices) == 0) && len(keyStr) == 64 {
		hasCanonical := false
		if ckStore, ok := s.store.(interface{ HasCanonicalKeys() bool }); ok {
			hasCanonical = ckStore.HasCanonicalKeys()
		}
		if !hasCanonical {
			if rawBytes, decErr := hex.DecodeString(keyStr); decErr == nil && len(rawBytes) == sha256.Size {
				var rawKeyHash [sha256.Size]byte
				copy(rawKeyHash[:], rawBytes)
				if altRes, altErr := s.store.Lookup(rawKeyHash, &parsedBefore, limit, state.InputLogSize); altErr == nil && altRes != nil && len(altRes.MatchedIndices) > 0 {
					lookupRes = altRes
				}
			}
		}
	}

	if lookupRes == nil || len(lookupRes.MatchedIndices) == 0 {
		http.Error(w, "no entries found before requested index", http.StatusNotFound)
		return
	}

	matchedIndices := lookupRes.MatchedIndices
	nextBefore := lookupRes.NextBefore
	var prefixCompactRange *kvstore.CompactRange
	if lookupRes.Preceding > 0 || len(lookupRes.CompactRange) > 0 {
		prefixCompactRange = &kvstore.CompactRange{
			Preceding: lookupRes.Preceding,
			Hashes:    slices.Clone(lookupRes.CompactRange),
		}
	}

	metrics.LookupResultsReturned.Observe(float64(len(matchedIndices)))

	respBytes := FormatValuesResponse(matchedIndices, prefixCompactRange, nextBefore)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}
