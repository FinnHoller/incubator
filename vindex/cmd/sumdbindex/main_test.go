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

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"golang.org/x/mod/sumdb/note"
)

var exampleLeaf = []byte(`golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
`)

var pseudoVersionLeaf = []byte(`github.com/transparency-dev/tessera v0.0.0-20240222160914-411202e8d356 h1:4jV/qA6RzP7Z6s+/vQ0W2RjM3FjC6B2M3r8=
github.com/transparency-dev/tessera v0.0.0-20240222160914-411202e8d356/go.mod h1:T/Ym+5H1e28Qv6iMzT3w=
`)

var releaseCandidateLeaf = []byte(`github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s v1.7.0-rc1 h1:f1nwnVa7t5Ftd+BPef/V/Y8XxT1Sdiif0cdIo/8R9i0=
github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s v1.7.0-rc1/go.mod h1:CuxOEw4CmUSK44owsXWkZ6Njh0G/gfboQoLl9hn1Voo=`)

func TestMapFn(t *testing.T) {
	for _, tc := range []struct {
		name string
		leaf []byte
		want [][32]byte
	}{
		{
			name: "valid",
			leaf: exampleLeaf,
			want: [][32]byte{sha256.Sum256([]byte("golang.org/x/text"))},
		},
		{
			name: "pseudo_version",
			leaf: pseudoVersionLeaf,
			want: nil,
		},
		{
			name: "release_candidate",
			leaf: releaseCandidateLeaf,
			want: [][32]byte{sha256.Sum256([]byte("github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s"))},
		},
		{
			name: "empty_leaf",
			leaf: []byte{},
			want: nil,
		},
		{
			name: "no_spaces",
			leaf: []byte("invalidleafwithnospaces"),
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapFn(tc.leaf)
			if len(got) != len(tc.want) {
				t.Fatalf("mapFn() returned %d keys, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !bytes.Equal(got[i][:], tc.want[i][:]) {
					t.Errorf("mapFn()[%d] = %x, want %x", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSumDBLeafMapper(t *testing.T) {
	ctx := context.Background()
	mapper := &SumDBLeafMapper{}
	defer func() {
		if err := mapper.Close(ctx); err != nil {
			t.Errorf("mapper.Close failed: %v", err)
		}
	}()

	// 1. Valid leaf
	entries, err := mapper.MapLeaf(ctx, exampleLeaf)
	if err != nil {
		t.Fatalf("MapLeaf(exampleLeaf) unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("MapLeaf(exampleLeaf) got %d entries, want 1", len(entries))
	}
	wantHash := sha256.Sum256([]byte("golang.org/x/text"))
	if entries[0].Key != "golang.org/x/text" {
		t.Errorf("MapLeaf(exampleLeaf) key = %q, want %q", entries[0].Key, "golang.org/x/text")
	}
	if entries[0].KeyHash != wantHash {
		t.Errorf("MapLeaf(exampleLeaf) key hash = %x, want %x", entries[0].KeyHash, wantHash)
	}

	// 2. Pseudo version (should be dropped)
	pseudoEntries, err := mapper.MapLeaf(ctx, pseudoVersionLeaf)
	if err != nil {
		t.Fatalf("MapLeaf(pseudoVersionLeaf) unexpected error: %v", err)
	}
	if len(pseudoEntries) != 0 {
		t.Errorf("MapLeaf(pseudoVersionLeaf) got %d entries, want 0", len(pseudoEntries))
	}

	// 3. Release candidate
	rcEntries, err := mapper.MapLeaf(ctx, releaseCandidateLeaf)
	if err != nil {
		t.Fatalf("MapLeaf(releaseCandidateLeaf) unexpected error: %v", err)
	}
	if len(rcEntries) != 1 {
		t.Fatalf("MapLeaf(releaseCandidateLeaf) got %d entries, want 1", len(rcEntries))
	}
	wantRCHash := sha256.Sum256([]byte("github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s"))
	if rcEntries[0].KeyHash != wantRCHash {
		t.Errorf("MapLeaf(releaseCandidateLeaf) key hash = %x, want %x", rcEntries[0].KeyHash, wantRCHash)
	}

	// 4. Case-escaped module path via module.EscapePath
	upperLeaf := []byte("github.com/Azure/azure-sdk-for-go v1.0.0 h1:abc=\n")
	upperEntries, err := mapper.MapLeaf(ctx, upperLeaf)
	if err != nil {
		t.Fatalf("MapLeaf(upperLeaf) unexpected error: %v", err)
	}
	if len(upperEntries) != 1 || upperEntries[0].Key != "github.com/!azure/azure-sdk-for-go" {
		t.Errorf("MapLeaf(upperLeaf) got %+v, want key github.com/!azure/azure-sdk-for-go", upperEntries)
	}
}

type testInputLog struct {
	mu     sync.Mutex
	origin string
	signer note.Signer
	leaves [][]byte
}

func (l *testInputLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	var rawCP []byte
	if l.signer != nil {
		var err error
		rawCP, err = note.Sign(&note.Note{Text: text}, l.signer)
		if err != nil {
			return nil, err
		}
	} else {
		rawCP = []byte(text)
	}
	return &ingest.Checkpoint{
		Raw:    rawCP,
		Origin: l.origin,
		Size:   size,
		Hash:   root,
	}, nil
}

func (l *testInputLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *testInputLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     l.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func (l *testInputLog) InclusionProof(_ context.Context, idx, treeSize uint64) ([][sha256.Size]byte, error) {
	return nil, nil
}

func TestSumDBIndex_Integration(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	db, err := kvstore.Open(tempDir+"/pebble", &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	mptMgr, err := mpt.Open(tempDir + "/mpt")
	if err != nil {
		t.Fatalf("mpt.Open failed: %v", err)
	}
	defer func() { _ = mptMgr.Close() }()

	inSKey, _, err := note.GenerateKey(rand.Reader, "sum.golang.org")
	if err != nil {
		t.Fatalf("note.GenerateKey(input) failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(input) failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "SumDBIndex")
	if err != nil {
		t.Fatalf("note.GenerateKey(output) failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(output) failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(output) failed: %v", err)
	}

	mockInputLog := &testInputLog{
		origin: "go.sum database tree",
		signer: inSigner,
		leaves: [][]byte{
			exampleLeaf,          // idx 0 -> golang.org/x/text
			pseudoVersionLeaf,    // idx 1 -> dropped (pseudo version)
			releaseCandidateLeaf, // idx 2 -> github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s
		},
	}

	outLog, err := newLocalOutputLog("SumDBIndex", tempDir+"/outputlog", outSigner)
	if err != nil {
		t.Fatalf("newLocalOutputLog failed: %v", err)
	}

	const chunkSize = 16
	leafMapper := &SumDBLeafMapper{}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	pub.SetInputOrigin("go.sum database tree")
	idxer := kvstore.NewKVIndexer(db, chunkSize)

	tileCache, err := ingest.NewManagedTileCache(tempDir+"/tilecache", 0)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	coord := coordinator.NewCoordinator(db, mptMgr, outLog, pub, idxer, mockInputLog, tileCache, leafMapper)
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("coord.Recover failed: %v", err)
	}

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("coord.SyncOnce failed: %v", err)
	}

	readSrv := server.NewReadServer(db, mptMgr, pub, chunkSize)
	mux := http.NewServeMux()
	readSrv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	adminMux := http.NewServeMux()
	readSrv.RegisterAdminRoutes(adminMux)
	adminTS := httptest.NewServer(adminMux)
	defer adminTS.Close()

	if res, err := ts.Client().Get(ts.URL + "/healthz"); err != nil {
		t.Fatalf("GET public /healthz failed: %v", err)
	} else {
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("public /healthz status = %d, want 404", res.StatusCode)
		}
	}
	if res, err := adminTS.Client().Get(adminTS.URL + "/healthz"); err != nil {
		t.Fatalf("GET admin /healthz failed: %v", err)
	} else {
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("admin /healthz status = %d, want 200", res.StatusCode)
		}
	}

	outPolicy, err := client.SingleKeyPolicy("SumDBIndex", outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	cli, err := client.New(ts.URL, client.Config{
		ExpectedOutputLogOrigin: "SumDBIndex",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "go.sum database tree",
	}, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// 1. Lookup "golang.org/x/text"
	keysText, err := cli.LookupKey(ctx, "golang.org/x/text")
	if err != nil {
		t.Fatalf("cli.LookupKey(golang.org/x/text) failed: %v", err)
	}
	if len(keysText.Keys) != 1 {
		t.Fatal("golang.org/x/text should exist in index")
	}
	var idxText []uint64
	for idx, err := range keysText.Keys[0].Values(ctx) {
		if err != nil {
			t.Fatalf("Values(golang.org/x/text) failed: %v", err)
		}
		idxText = append(idxText, idx)
	}
	if len(idxText) != 1 || idxText[0] != 0 {
		t.Fatalf("golang.org/x/text indices = %v, want [0]", idxText)
	}

	// 2. Lookup "github.com/transparency-dev/tessera" (pseudo-version should not be in index)
	keysTessera, err := cli.LookupKey(ctx, "github.com/transparency-dev/tessera")
	if err != nil {
		t.Fatalf("cli.LookupKey(github.com/transparency-dev/tessera) failed: %v", err)
	}
	if len(keysTessera.Keys) != 0 {
		t.Fatalf("github.com/transparency-dev/tessera pseudo-version should not exist in index: got %+v", keysTessera.Keys)
	}

	// 3. Lookup "github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s"
	keysRC, err := cli.LookupKey(ctx, "github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s")
	if err != nil {
		t.Fatalf("cli.LookupKey(rc) failed: %v", err)
	}
	if len(keysRC.Keys) != 1 {
		t.Fatal("release candidate module should exist in index")
	}
	var idxRC []uint64
	for idx, err := range keysRC.Keys[0].Values(ctx) {
		if err != nil {
			t.Fatalf("Values(rc) failed: %v", err)
		}
		idxRC = append(idxRC, idx)
	}
	if len(idxRC) != 1 || idxRC[0] != 2 {
		t.Fatalf("release candidate indices = %v, want [2]", idxRC)
	}

	// 4. Lookup unknown key (verified non-inclusion)
	keysUnknown, err := cli.LookupKey(ctx, "nonexistent/module")
	if err != nil {
		t.Fatalf("cli.LookupKey(nonexistent/module) failed: %v", err)
	}
	if len(keysUnknown.Keys) != 0 {
		t.Fatalf("nonexistent/module should not exist: keys=%+v", keysUnknown.Keys)
	}
}

func BenchmarkMapFn(b *testing.B) {
	for b.Loop() {
		mapFn(exampleLeaf)
		mapFn(pseudoVersionLeaf)
		mapFn(releaseCandidateLeaf)
	}
}
