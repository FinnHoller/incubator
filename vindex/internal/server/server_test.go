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

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
)

type mockOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
}

func (m *mockOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n\n— test_sig\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return idx, []byte(rawCP), nil
}

func (m *mockOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	var proof [][sha256.Size]byte
	if treeSize > 1 {
		proof = append(proof, sha256.Sum256([]byte("sibling")))
	}
	return proof, nil
}

func setupTestServer(t *testing.T, chunkSize uint64) (*ReadServer, *kvstore.DB, *mpt.Manager, *tree.OutputPublisher) {
	t.Helper()
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := mpt.NewMem()
	outLog := &mockOutputLog{origin: "example.com/output"}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	srv := NewReadServer(db, mptMgr, pub, chunkSize)
	return srv, db, mptMgr, pub
}

func TestReadServer_CheckpointsAndCutRoutes(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)

	// Before serving state initialized -> 503
	req := httptest.NewRequest(http.MethodGet, "/checkpoint", nil)
	w := httptest.NewRecorder()
	srv.HandleCheckpoint(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("HandleCheckpoint uninitialized = %d, want 503", w.Code)
	}

	// Initialize serving state
	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err := pub.Publish(context.Background(), rawInCP, 500, nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Output log checkpoint via /checkpoint
	mux := http.NewServeMux()
	srv.RegisterRoutesWithOutputLog(mux, t.TempDir())
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /checkpoint = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "example.com/output") {
		t.Fatalf("HandleCheckpoint body missing origin: %s", w.Body.String())
	}

	// Non-spec legacy public routes and unknown paths must return 404 Not Found
	for _, removedPath := range []string{
		"/vindex/v1/checkpoint",
		"/vindex/v1/inputlog_checkpoint",
		"/inputlog_checkpoint",
		"/vindex/v1/keys?key=test",
		"/vindex/v1/values?key=test&before=1",
		"/vindex/keys?key=test",
		"/entries?key=test&before=1",
		"/outputlog/checkpoint",
		"/keys/test",
		"/unknown-route",
	} {
		remW := httptest.NewRecorder()
		mux.ServeHTTP(remW, httptest.NewRequest(http.MethodGet, removedPath, nil))
		if remW.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404 Not Found", removedPath, remW.Code)
		}
	}
}

func TestReadServer_HealthAndReadiness(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)

	// Healthz probe -> always 200 OK for GET
	hReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	hW := httptest.NewRecorder()
	srv.HandleHealthz(hW, hReq)
	if hW.Code != http.StatusOK {
		t.Fatalf("HandleHealthz GET = %d, want 200", hW.Code)
	}

	// Healthz probe with POST -> 405
	hPostReq := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	hPostW := httptest.NewRecorder()
	srv.HandleHealthz(hPostW, hPostReq)
	if hPostW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HandleHealthz POST = %d, want 405", hPostW.Code)
	}

	// Readyz before initialization -> 503
	rReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rW := httptest.NewRecorder()
	srv.HandleReadyz(rW, rReq)
	if rW.Code != http.StatusServiceUnavailable {
		t.Fatalf("HandleReadyz uninitialized = %d, want 503", rW.Code)
	}

	// Readyz with POST -> 405
	rPostReq := httptest.NewRequest(http.MethodPost, "/readyz", nil)
	rPostW := httptest.NewRecorder()
	srv.HandleReadyz(rPostW, rPostReq)
	if rPostW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HandleReadyz POST = %d, want 405", rPostW.Code)
	}

	// Initialize serving state
	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err := pub.Publish(context.Background(), rawInCP, 500, nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Readyz after initialization -> 200 OK
	rW2 := httptest.NewRecorder()
	srv.HandleReadyz(rW2, rReq)
	if rW2.Code != http.StatusOK {
		t.Fatalf("HandleReadyz initialized = %d, want 200", rW2.Code)
	}
}

func TestReadServer_AsyncBackendAndGenesisBackfillDiagnostics(t *testing.T) {
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// 1. Start ReadServer before MPT/OutputPublisher are attached (mptMgr == nil, pub == nil)
	srv := NewReadServer(db, nil, nil, 256)

	// /healthz must immediately return 200 OK
	hW := httptest.NewRecorder()
	srv.HandleHealthz(hW, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if hW.Code != http.StatusOK {
		t.Fatalf("HandleHealthz before backend attach = %d, want 200", hW.Code)
	}

	// /readyz and /keys must return 503 with Retry-After: 30 and JSON mpt_initializing
	for _, endpoint := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/readyz", srv.HandleReadyz},
		{"/keys?key=testkey", srv.HandleKeys},
	} {
		w := httptest.NewRecorder()
		endpoint.handler(w, httptest.NewRequest(http.MethodGet, endpoint.path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s before backend attach = %d, want 503", endpoint.path, w.Code)
		}
		if w.Header().Get("Retry-After") != "30" {
			t.Fatalf("%s Retry-After = %q, want 30", endpoint.path, w.Header().Get("Retry-After"))
		}
		if !strings.Contains(w.Body.String(), `"status":"mpt_initializing"`) {
			t.Fatalf("%s body = %q, want mpt_initializing JSON", endpoint.path, w.Body.String())
		}
	}

	// 2. Attach backend and ReadyChecker simulating Genesis Backfill in progress
	mptMgr := mpt.NewMem()
	outLog := &mockOutputLog{origin: "example.com/output"}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	srv.SetReadyChecker(func() error {
		return fmt.Errorf(`{"status":"genesis_backfill","genesis_backfill":true,"leaves_indexed":500,"target_leaves":10000}`)
	})
	srv.SetBackend(mptMgr, pub)

	rW := httptest.NewRecorder()
	srv.HandleReadyz(rW, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rW.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz during genesis backfill = %d, want 503", rW.Code)
	}
	if !strings.Contains(rW.Body.String(), `"genesis_backfill":true`) {
		t.Fatalf("/readyz body = %q, want genesis_backfill JSON", rW.Body.String())
	}
}

func TestReadServer_MetricsEndpoint(t *testing.T) {
	srv := NewReadServer(nil, nil, nil, 64)

	// Public mux must NOT expose /healthz, /readyz, /syncz, or /metrics (returns 404 Not Found).
	publicMux := http.NewServeMux()
	srv.RegisterRoutes(publicMux)
	for _, adminPath := range []string{"/healthz", "/readyz", "/syncz", "/metrics"} {
		pubReq := httptest.NewRequest(http.MethodGet, adminPath, nil)
		pubW := httptest.NewRecorder()
		publicMux.ServeHTTP(pubW, pubReq)
		if pubW.Code != http.StatusNotFound {
			t.Fatalf("public mux GET %s status = %d, want 404 Not Found", adminPath, pubW.Code)
		}
	}

	mux := http.NewServeMux()
	srv.RegisterAdminRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	expectedMetrics := []string{
		"vindex_input_tree_size",
		"vindex_kv_committed_size",
		"vindex_output_tree_size",
		"vindex_serving_tree_size",
		"vindex_leaves_downloaded_total",
		"vindex_leaves_mapped_total",
		"vindex_leaves_indexed_total",
		"vindex_keys_mapped_total",
		"vindex_input_fetch_errors_total",
		"vindex_witness_signatures_count",
		"vindex_witness_errors_total",
		"vindex_tile_cache_bytes",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(body, m) {
			t.Errorf("/metrics missing expected metric %q", m)
		}
	}
}
func TestReadServer_CustomChunkSize(t *testing.T) {
	const customChunkSize = 64
	srv, db, _, pub := setupTestServer(t, customChunkSize)
	indexer := kvstore.NewKVIndexer(db, customChunkSize)

	keyStr := "custom_chunk_test.com"
	key := sha256.Sum256([]byte(keyStr))
	indices := []uint64{0, 65, 130}
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
		CanonicalKeys: map[[32]byte]string{
			key: keyStr,
		},
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 200)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n200\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 200, Hash: make([]byte, 32)}
	_, err = pub.PublishKeyBatch(context.Background(), res.ModifiedKeyValueRoots, inCP, rawInCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr+"&before=200", nil)
	w := httptest.NewRecorder()
	srv.HandleValues(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HandleValues status = %d, want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("HandleValues Cache-Control = %q, want public, max-age=31536000, immutable", cc)
	}

	body := w.Body.String()
	for _, idx := range indices {
		expectedLine := fmt.Sprintf("%d", idx)
		found := false
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == expectedLine {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("HandleValues response missing index %d: %s", idx, body)
		}
	}
}

func TestReadServer_UI(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// GET /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET / content-type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "VIndex Web") {
		t.Fatalf("GET / body does not contain 'VIndex Web': %s", w.Body.String())
	}

	// GET /index.html
	req2 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("GET /index.html status = %d, want 200", w2.Code)
	}

	// Test disabling UI
	srvDisabled, _, _, _ := setupTestServer(t, 256)
	srvDisabled.SetEnableUI(false)
	muxDisabled := http.NewServeMux()
	srvDisabled.RegisterRoutes(muxDisabled)

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	w3 := httptest.NewRecorder()
	muxDisabled.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("GET / with disabled UI status = %d, want 404", w3.Code)
	}
}

func TestCleanPathPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", ""},
		{"///", ""},
		{"  ", ""},
		{"indices/sumdb", "/indices/sumdb"},
		{"/indices/sumdb", "/indices/sumdb"},
		{"/indices/sumdb/", "/indices/sumdb"},
		{"///indices/sumdb///", "/indices/sumdb"},
	}

	for _, tc := range tests {
		got := CleanPathPrefix(tc.input)
		if got != tc.want {
			t.Errorf("CleanPathPrefix(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReadServer_PathPrefix(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)
	srv.SetPathPrefix("/indices/sumdb")

	rawInCP := []byte("example.com/input\n500\n" + strings.Repeat("A", 44) + "\n")
	_, err := pub.Publish(context.Background(), rawInCP, 500, nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// 1. Root-level /indices/sumdb serves UI directly with 200 OK (no 3xx redirect per C2SP tlog-vindex)
	reqNoRedirect := httptest.NewRequest(http.MethodGet, "/indices/sumdb", nil)
	recNoRedirect := httptest.NewRecorder()
	mux.ServeHTTP(recNoRedirect, reqNoRedirect)
	if recNoRedirect.Code != http.StatusOK {
		t.Fatalf("GET /indices/sumdb = %d, want 200 (no 3xx redirect)", recNoRedirect.Code)
	}

	// 2. Prefixed Checkpoint: /indices/sumdb/checkpoint
	reqCP := httptest.NewRequest(http.MethodGet, "/indices/sumdb/checkpoint", nil)
	recCP := httptest.NewRecorder()
	mux.ServeHTTP(recCP, reqCP)
	if recCP.Code != http.StatusOK {
		t.Fatalf("GET /indices/sumdb/checkpoint = %d, want 200", recCP.Code)
	}

	// 3. Unprefixed Checkpoint should 404
	reqOldCP := httptest.NewRequest(http.MethodGet, "/checkpoint", nil)
	recOldCP := httptest.NewRecorder()
	mux.ServeHTTP(recOldCP, reqOldCP)
	if recOldCP.Code != http.StatusNotFound {
		t.Fatalf("GET /checkpoint without prefix = %d, want 404", recOldCP.Code)
	}

	// 4. Prefixed UI: /indices/sumdb/
	reqUI := httptest.NewRequest(http.MethodGet, "/indices/sumdb/", nil)
	recUI := httptest.NewRecorder()
	mux.ServeHTTP(recUI, reqUI)
	if recUI.Code != http.StatusOK {
		t.Fatalf("GET /indices/sumdb/ = %d, want 200", recUI.Code)
	}

	// 5. Operational routes (/healthz, /readyz, /metrics, /debug/pprof/) must 404 on public mux (both root and prefixed),
	// /syncz must 404 everywhere, and operational routes serve 200 OK only on the separate admin mux.
	for _, blockedPath := range []string{
		"/healthz", "/readyz", "/syncz", "/metrics", "/debug/pprof/",
		"/indices/sumdb/healthz", "/indices/sumdb/readyz", "/indices/sumdb/syncz", "/indices/sumdb/metrics", "/indices/sumdb/debug/pprof/",
	} {
		reqBlocked := httptest.NewRequest(http.MethodGet, blockedPath, nil)
		recBlocked := httptest.NewRecorder()
		mux.ServeHTTP(recBlocked, reqBlocked)
		if recBlocked.Code != http.StatusNotFound {
			t.Fatalf("public mux GET %s = %d, want 404 Not Found", blockedPath, recBlocked.Code)
		}
	}

	adminMux := http.NewServeMux()
	srv.RegisterAdminRoutes(adminMux)
	for _, adminPath := range []string{"/healthz", "/readyz", "/metrics", "/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol"} {
		reqAdmin := httptest.NewRequest(http.MethodGet, adminPath, nil)
		recAdmin := httptest.NewRecorder()
		adminMux.ServeHTTP(recAdmin, reqAdmin)
		if recAdmin.Code != http.StatusOK {
			t.Fatalf("admin mux GET %s = %d, want 200 OK", adminPath, recAdmin.Code)
		}
	}
	recSyncz := httptest.NewRecorder()
	adminMux.ServeHTTP(recSyncz, httptest.NewRequest(http.MethodGet, "/syncz", nil))
	if recSyncz.Code != http.StatusNotFound {
		t.Fatalf("admin mux GET /syncz = %d, want 404 Not Found", recSyncz.Code)
	}
}

func TestReadServer_RegisterRoutesWithOutputLog(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)
	srv.SetPathPrefix("/myindex")

	tmpDir := t.TempDir()
	tilePath := filepath.Join(tmpDir, "tile", "test.txt")
	if err := os.MkdirAll(filepath.Dir(tilePath), 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(tilePath, []byte("tile content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutesWithOutputLog(mux, tmpDir)

	// Fetch tile under prefix: /myindex/tile/test.txt
	req := httptest.NewRequest(http.MethodGet, "/myindex/tile/test.txt", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /myindex/tile/test.txt = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "tile content" {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func TestReadServer_HandleKeys_PointAndPrefix(t *testing.T) {
	const chunkSize = 100
	srv, db, _, pub := setupTestServer(t, chunkSize)
	db.SetChunkSize(chunkSize)
	testDomainPolicy := func(prefix string) error {
		if !strings.HasSuffix(prefix, ".") {
			return fmt.Errorf("prefix %q must end with dot", prefix)
		}
		labels := strings.Split(strings.TrimSuffix(prefix, "."), ".")
		if len(labels) > 0 && labels[len(labels)-1] == "*" {
			labels = labels[:len(labels)-1]
		}
		if len(labels) < 2 {
			return fmt.Errorf("prefix %q too broad", prefix)
		}
		for _, lbl := range labels {
			if lbl == "" {
				return fmt.Errorf("empty label in %q", prefix)
			}
			for i := 0; i < len(lbl); i++ {
				c := lbl[i]
				isLower := c >= 'a' && c <= 'z'
				isDigit := c >= '0' && c <= '9'
				if !isLower && !isDigit && c != '-' && c != '_' {
					return fmt.Errorf("invalid label char in %q", prefix)
				}
			}
		}
		return nil
	}
	srv.SetPrefixPolicy(testDomainPolicy)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

	domainKeys := []string{
		"com.google.",
		"com.google.*.",
		"com.google.docs.",
		"com.google.mail.",
		"com.googleapis.",
	}
	keyMap := make(map[[32]byte][]uint64, len(domainKeys))
	canonMap := make(map[[32]byte]string, len(domainKeys))
	for i, dk := range domainKeys {
		kh := sha256.Sum256([]byte(dk))
		keyMap[kh] = []uint64{uint64(i * 10), uint64(i*10 + 5)}
		canonMap[kh] = dk
	}

	batch := &ingest.MappedBatch{
		KeyMap:        keyMap,
		CanonicalKeys: canonMap,
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 500)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 500, Hash: make([]byte, 32)}
	if _, err := pub.PublishKeyBatch(context.Background(), res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// 1. Point lookup inclusion (via query param ?key= on /keys)
	t.Run("point_inclusion", func(t *testing.T) {
		urlStr := "/keys?key=com.google.mail."
		req := httptest.NewRequest(http.MethodGet, urlStr, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200: %s", urlStr, w.Code, w.Body.String())
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("GET %s Cache-Control = %q, want no-store", urlStr, cc)
		}
		body := w.Body.String()
		if !strings.HasPrefix(body, "c2sp.org/tlog-vindex-keys@v1\nproof ") {
			t.Fatalf("missing tlog-vindex-keys header and proof line: %s", body)
		}
		vr := res.ModifiedKeyValueRoots["com.google.mail."]
		wantValueRoot := base64.StdEncoding.EncodeToString(vr[:])
		if !strings.Contains(body, "\ncom.google.mail. "+wantValueRoot+"\n\nc2sp.org/tlog-proof@v1\n") {
			t.Fatalf("keys section mismatch, got:\n%s", body)
		}
	})

	// 2. Point lookup non-inclusion
	t.Run("point_non_inclusion", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/keys?key=com.google.absent.", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		stanzas := strings.SplitN(body, "\n\nc2sp.org/tlog-proof@v1\n", 2)
		if len(stanzas) != 2 {
			t.Fatalf("expected 2 stanzas, got:\n%s", body)
		}
		keyLines := strings.Split(stanzas[0], "\n")
		if len(keyLines) != 2 || !strings.HasPrefix(keyLines[1], "proof") {
			t.Fatalf("expected non-inclusion response with only header and proof line, got:\n%s", stanzas[0])
		}
	})

	// 3. Prefix discovery matching 4 keys in ascending order
	t.Run("prefix_discovery_matches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/keys?prefix=com.google.", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.HasPrefix(body, "c2sp.org/tlog-vindex-keys@v1\nproof") {
			t.Fatalf("missing tlog-vindex-keys header and proof line: %s", body)
		}
		for _, wantKey := range []string{"com.google.", "com.google.*.", "com.google.docs.", "com.google.mail."} {
			if !strings.Contains(body, "\n"+wantKey+" ") {
				t.Errorf("missing expected key %q in prefix response:\n%s", wantKey, body)
			}
		}
		if strings.Contains(body, "com.googleapis.") {
			t.Errorf("unexpected sibling key com.googleapis. in prefix response:\n%s", body)
		}
	})

	// 4. Empty prefix discovery
	t.Run("prefix_discovery_empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/keys?prefix=com.nonexistent.", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		stanzas := strings.SplitN(body, "\n\nc2sp.org/tlog-proof@v1\n", 2)
		if len(stanzas) != 2 {
			t.Fatalf("expected 2 stanzas, got:\n%s", body)
		}
		keyLines := strings.Split(stanzas[0], "\n")
		if len(keyLines) != 2 || !strings.HasPrefix(keyLines[1], "proof") {
			t.Fatalf("expected empty prefix key-list block with only header and proof line, got:\n%s", stanzas[0])
		}
	})

	// 5. Prefix policy rejections and query param validation
	t.Run("prefix_policy_rejections", func(t *testing.T) {
		for _, badPrefix := range []string{
			"com.",
			"com.*.",
			"com.g*o.",
			"com.*google.",
			"com.Google.",
			"com.foo$bar.",
			"com.google", // missing trailing dot
		} {
			req := httptest.NewRequest(http.MethodGet, "/keys?prefix="+badPrefix, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("GET /keys?prefix=%s status = %d, want 400", badPrefix, w.Code)
			}
		}
		// Reject both key and prefix, empty key/prefix, or missing both
		for _, badURL := range []string{
			"/keys?key=com.google.&prefix=com.google.",
			"/keys?key=",
			"/keys?prefix=",
			"/keys",
		} {
			req := httptest.NewRequest(http.MethodGet, badURL, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("GET %s status = %d, want 400", badURL, w.Code)
			}
		}
		// Valid prefixes under custom policy
		for _, goodPrefix := range []string{
			"uk.co.bbc.news.",
			"io.github.myorg.",
			"com.google.*.",
		} {
			req := httptest.NewRequest(http.MethodGet, "/keys?prefix="+goodPrefix, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("GET /keys?prefix=%s status = %d, want 200: %s", goodPrefix, w.Code, w.Body.String())
			}
		}
		// DisallowPrefixPolicy rejects all prefixes, AllowAllPrefixPolicy accepts single-char prefix
		srv.SetPrefixPolicy(DisallowPrefixPolicy)
		wDis := httptest.NewRecorder()
		mux.ServeHTTP(wDis, httptest.NewRequest(http.MethodGet, "/keys?prefix=com.google.", nil))
		if wDis.Code != http.StatusBadRequest {
			t.Errorf("DisallowPrefixPolicy status = %d, want 400", wDis.Code)
		}
		srv.SetPrefixPolicy(AllowAllPrefixPolicy)
		wAll := httptest.NewRecorder()
		mux.ServeHTTP(wAll, httptest.NewRequest(http.MethodGet, "/keys?prefix=c", nil))
		if wAll.Code != http.StatusOK {
			t.Errorf("AllowAllPrefixPolicy status = %d, want 200", wAll.Code)
		}
		srv.SetPrefixPolicy(testDomainPolicy)
	})

	// 6. Prefix cardinality limit (HTTP 413 Content Too Large)
	t.Run("prefix_cardinality_cap_413", func(t *testing.T) {
		srv.SetMaxPrefixKeys(3)
		defer srv.SetMaxPrefixKeys(DefaultMaxPrefixKeys)

		req := httptest.NewRequest(http.MethodGet, "/keys?prefix=com.google.", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 Content Too Large", w.Code)
		}
	})
}

func TestReadServer_HandleValues_LockFreeAndPagination(t *testing.T) {
	const chunkSize = 100
	srv, db, mptMgr, pub := setupTestServer(t, chunkSize)
	db.SetChunkSize(chunkSize)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

	// Use a key containing slashes (like a Go module path) to verify query & path extraction
	keyStr := "github.com/google/uuid"
	keyHash := sha256.Sum256([]byte(keyStr))
	var indices []uint64
	for i := uint64(0); i < 150; i++ {
		indices = append(indices, i*2)
	}

	batch := &ingest.MappedBatch{
		KeyMap:        map[[32]byte][]uint64{keyHash: indices},
		CanonicalKeys: map[[32]byte]string{keyHash: keyStr},
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 500)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 500, Hash: make([]byte, 32)}
	if _, err := pub.PublishKeyBatch(context.Background(), res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// 1. Missing mandatory 'before' parameter -> HTTP 400
	reqNoBefore := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr, nil)
	wNoBefore := httptest.NewRecorder()
	mux.ServeHTTP(wNoBefore, reqNoBefore)
	if wNoBefore.Code != http.StatusBadRequest {
		t.Fatalf("missing before status = %d, want 400", wNoBefore.Code)
	}

	// 1b. Non-canonical 'before' (leading zeroes, 0) or unknown parameters ('limit') -> HTTP 400
	for _, badQuery := range []string{
		"before=0",
		"before=0500",
		"before=500&limit=50",
		"before=500&extra=1",
	} {
		reqBad := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr+"&"+badQuery, nil)
		wBad := httptest.NewRecorder()
		mux.ServeHTTP(wBad, reqBad)
		if wBad.Code != http.StatusBadRequest {
			t.Fatalf("query %s status = %d, want 400", badQuery, wBad.Code)
		}
	}

	// 1c. 'before' exceeding Input Log size (500) -> HTTP 503 Service Unavailable with Retry-After: 30
	reqFuture := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr+"&before=501", nil)
	wFuture := httptest.NewRecorder()
	mux.ServeHTTP(wFuture, reqFuture)
	if wFuture.Code != http.StatusServiceUnavailable {
		t.Fatalf("before > inputLogSize status = %d, want 503", wFuture.Code)
	}
	if wFuture.Header().Get("Retry-After") != "30" {
		t.Fatalf("Retry-After = %q, want 30", wFuture.Header().Get("Retry-After"))
	}

	// 1d. Non-existent key -> HTTP 404 Not Found
	reqNotFound := httptest.NewRequest(http.MethodGet, "/values?key=nonexistent&before=500", nil)
	wNotFound := httptest.NewRecorder()
	mux.ServeHTTP(wNotFound, reqNotFound)
	if wNotFound.Code != http.StatusNotFound {
		t.Fatalf("non-existent key status = %d, want 404", wNotFound.Code)
	}

	// 1e. Querying /values with the 64-char hex digest of a preimage key must return 404 Not Found
	hexOfPreimageKey := fmt.Sprintf("%x", sha256.Sum256([]byte(keyStr)))
	reqHexDigest := httptest.NewRequest(http.MethodGet, "/values?key="+hexOfPreimageKey+"&before=500", nil)
	wHexDigest := httptest.NewRecorder()
	mux.ServeHTTP(wHexDigest, reqHexDigest)
	if wHexDigest.Code != http.StatusNotFound {
		t.Fatalf("64-char hex digest of preimage key status = %d, want 404", wHexDigest.Code)
	}

	// 2. Hold exclusive write lock on mptMgr while calling HandleValues to prove zero MPT lock acquisition!
	mptMgr.Lock()
	reqPage1 := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr+"&before=500", nil)
	wPage1 := httptest.NewRecorder()
	mux.ServeHTTP(wPage1, reqPage1)
	mptMgr.Unlock()

	if wPage1.Code != http.StatusOK {
		t.Fatalf("Page 1 status = %d, want 200: %s", wPage1.Code, wPage1.Body.String())
	}
	body1 := wPage1.Body.String()
	if !strings.HasPrefix(body1, "c2sp.org/tlog-vindex-values@v1\npreceding 50\n") {
		t.Fatalf("expected tlog-vindex-values@v1 with preceding 50, got:\n%s", body1)
	}
	if !strings.Contains(body1, "\n\n100\n") {
		t.Fatalf("expected ascending indices starting at 100, got:\n%s", body1)
	}

	// 3. Page 2: before=100 -> reaches start of value log (preceding == 0, omits hash lines)
	reqPage2 := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr+"&before=100", nil)
	wPage2 := httptest.NewRecorder()
	mux.ServeHTTP(wPage2, reqPage2)
	if wPage2.Code != http.StatusOK {
		t.Fatalf("Page 2 status = %d, want 200", wPage2.Code)
	}
	body2 := wPage2.Body.String()
	if !strings.HasPrefix(body2, "c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n0\n") {
		t.Fatalf("expected preceding 0 with no hash lines and indices starting at 0, got:\n%s", body2)
	}
}

func TestReadServer_RFC3986QueryParsing(t *testing.T) {
	const chunkSize = 100
	srv, db, _, pub := setupTestServer(t, chunkSize)
	db.SetChunkSize(chunkSize)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

	plusKey := "golang.org/x/mod+v1"
	plusHash := sha256.Sum256([]byte(plusKey))
	batch := &ingest.MappedBatch{
		KeyMap:        map[[32]byte][]uint64{plusHash: {7, 42}},
		CanonicalKeys: map[[32]byte]string{plusHash: plusKey},
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 100)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n100\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 100, Hash: make([]byte, 32)}
	if _, err := pub.PublishKeyBatch(context.Background(), res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	vr := res.ModifiedKeyValueRoots[plusKey]
	wantValueRoot := base64.StdEncoding.EncodeToString(vr[:])

	t.Run("plus_key_encoded_and_literal", func(t *testing.T) {
		for _, target := range []string{
			"/keys?key=golang.org%2Fx%2Fmod%2Bv1",
			"/keys?key=golang.org/x/mod+v1",
		} {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200: %s", target, w.Code, w.Body.String())
			}
			body := w.Body.String()
			wantLine := "\n" + plusKey + " " + wantValueRoot + "\n\nc2sp.org/tlog-proof@v1\n"
			if !strings.Contains(body, wantLine) {
				t.Fatalf("GET %s missing inclusion line %q in body:\n%s", target, wantLine, body)
			}
		}

		for _, target := range []string{
			"/keys?prefix=golang.org%2Fx%2Fmod%2B",
			"/keys?prefix=golang.org/x/mod+",
		} {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200: %s", target, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "\n"+plusKey+" "+wantValueRoot+"\n") {
				t.Fatalf("GET %s missing prefix match for %q:\n%s", target, plusKey, w.Body.String())
			}
		}

		for _, target := range []string{
			"/values?key=golang.org%2Fx%2Fmod%2Bv1&before=100",
			"/values?key=golang.org/x/mod+v1&before=100",
		} {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200: %s", target, w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, "\n\n7\n42\n") {
				t.Fatalf("GET %s unexpected body:\n%s", target, body)
			}
		}
	})

	t.Run("malformed_percent_escapes_and_duplicates_rejected", func(t *testing.T) {
		badTargets := []string{
			"/keys?key=bad%ZZ",
			"/keys?key=bad%2",
			"/keys?key=bad%",
			"/keys?prefix=com.example.%GG",
			"/keys?key=valid&other=1",
			"/keys?key=valid&other=%ZZ",
			"/keys?%ZZ=1&key=valid",
			"/keys?key=a&key=b",
			"/keys?prefix=a.&prefix=b.",
			"/keys?key=valid&",
			"/values?key=bad%ZZ&before=1",
			"/values?key=bad%2&before=1",
			"/values?key=valid&before=1%ZZ",
			"/values?key=valid&before=1&other=%ZZ",
			"/values?key=valid&before=1&other=1",
			"/values?key=valid&before=1&before=2",
			"/values?key=valid&before=2&limit=10",
			"/values?key=valid&before=2&limit=10&limit=20",
			"/values?key=valid&key=other&before=2",
		}
		for _, target := range badTargets {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("GET %s status = %d, want 400: %s", target, w.Code, w.Body.String())
			}
		}
	})
}

func BenchmarkReadServer_TwoEndpointVsCombined(b *testing.B) {
	dir := b.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("kvstore.Open failed: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })

	const chunkSize = 1024
	db.SetChunkSize(chunkSize)
	mptMgr := mpt.NewMem()
	outLog := &mockOutputLog{origin: "example.com/output"}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	srv := NewReadServer(db, mptMgr, pub, chunkSize)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

	keyMap := make(map[[32]byte][]uint64, 500)
	canonMap := make(map[[32]byte]string, 500)
	for i := 0; i < 500; i++ {
		var k string
		if i < 25 {
			k = fmt.Sprintf("com.google.sub%03d.", i)
		} else {
			k = fmt.Sprintf("org.other%03d.svc.", i)
		}
		kh := sha256.Sum256([]byte(k))
		indices := make([]uint64, 64)
		for j := range indices {
			indices[j] = uint64(j*10 + (i % 7))
		}
		keyMap[kh] = indices
		canonMap[kh] = k
	}

	batch := &ingest.MappedBatch{
		KeyMap:        keyMap,
		CanonicalKeys: canonMap,
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 10000)
	if err != nil {
		b.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n10000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 10000, Hash: make([]byte, 32)}
	targetKey := "com.google.sub000."
	if _, err := pub.PublishKeyBatch(context.Background(), res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		b.Fatalf("PublishKeyBatch failed: %v", err)
	}

	b.Run("HandleKeys_Point", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/keys?key="+targetKey, nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			srv.HandleKeys(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})

	b.Run("HandleKeys_Prefix25", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/keys?prefix=com.google.", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			srv.HandleKeys(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})

	b.Run("HandleValues_LockFree", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/values?key="+targetKey+"&before=10000", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			srv.HandleValues(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})
}
