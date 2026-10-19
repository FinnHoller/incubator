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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"golang.org/x/mod/sumdb/note"
)

type testMTCLeafMapper struct{}

func (m *testMTCLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	var entries []ingest.MappedEntry
	mtc.ExtractDomainNames(leaf, func(name string) {
		entries = append(entries, ingest.MappedEntry{
			Key:     name,
			KeyHash: sha256.Sum256([]byte(name)),
		})
	})
	return entries, nil
}

func (m *testMTCLeafMapper) Close(_ context.Context) error {
	return nil
}

func marshalMTCEntry(dnsNames []string) ([]byte, error) {
	rawNames := []asn1.RawValue{}
	for _, name := range dnsNames {
		rawNames = append(rawNames, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	sanValue, err := asn1.Marshal(rawNames)
	if err != nil {
		return nil, err
	}

	ext := struct {
		Id       asn1.ObjectIdentifier
		Critical bool `asn1:"optional,default:false"`
		Value    []byte
	}{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: sanValue,
	}
	extBytes, err := asn1.Marshal(ext)
	if err != nil {
		return nil, err
	}

	entry := mtc.TBSCertificateLogEntry{
		Extensions: []asn1.RawValue{{FullBytes: extBytes}},
	}

	entryBytes, err := asn1.Marshal(entry)
	if err != nil {
		return nil, err
	}

	return append([]byte{0, 1}, entryBytes...), nil
}

type testMTCInputLog struct {
	mu     sync.Mutex
	origin string
	signer note.Signer
	leaves [][]byte
}

func (l *testMTCInputLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	rawCP, err := note.Sign(&note.Note{Text: text}, l.signer)
	if err != nil {
		return nil, err
	}
	return &ingest.Checkpoint{
		Raw:    rawCP,
		Origin: l.origin,
		Size:   size,
		Hash:   root,
	}, nil
}

func (l *testMTCInputLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *testMTCInputLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     l.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func (l *testMTCInputLog) InclusionProof(_ context.Context, _, _ uint64) ([][sha256.Size]byte, error) {
	return nil, nil
}

type localOutputLog struct {
	mu     sync.Mutex
	origin string
	signer note.Signer
	leaves [][]byte
}

func (l *localOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	idx := uint64(len(l.leaves))
	leafCopy := append([]byte(nil), leafData...)
	l.leaves = append(l.leaves, leafCopy)
	size := uint64(len(l.leaves))

	root := kvstore.BatchRoot(l.leaves)
	text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	rawCP, err := note.Sign(&note.Note{Text: text}, l.signer)
	if err != nil {
		return 0, nil, err
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
		return nil, fmt.Errorf("leaf index %d out of bounds", idx)
	}
	return l.leaves[idx], nil
}

func (l *localOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return note.Sign(&note.Note{Text: text}, l.signer)
}

func (l *localOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
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

func TestMTCVerify_Integration(t *testing.T) {
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

	leaf0, err := marshalMTCEntry([]string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatalf("failed to create leaf0: %v", err)
	}
	leaf1, err := marshalMTCEntry([]string{"service.corp.example.co.uk", "*.service.corp.example.co.uk"})
	if err != nil {
		t.Fatalf("failed to create leaf1: %v", err)
	}

	inSKey, _, err := note.GenerateKey(rand.Reader, "bootstrap-mtca.cloudflareresearch.com/logs/shard3")
	if err != nil {
		t.Fatalf("note.GenerateKey(input) failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(input) failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "MTCIndex")
	if err != nil {
		t.Fatalf("note.GenerateKey(output) failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(output) failed: %v", err)
	}

	mockInputLog := &testMTCInputLog{
		origin: "bootstrap-mtca.cloudflareresearch.com/logs/shard3",
		signer: inSigner,
		leaves: [][]byte{
			leaf0,
			leaf1,
		},
	}

	outLog := &localOutputLog{
		origin: "MTCIndex",
		signer: outSigner,
	}
	const chunkSize = 16
	leafMapper := &testMTCLeafMapper{}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	pub.SetInputOrigin(mockInputLog.origin)
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

	// 1. Verify existing domain "example.com"
	*vindexURL = ts.URL
	*outLogOrigin = "MTCIndex"
	*outLogPubKey = outVKey
	*inLogOrigin = "bootstrap-mtca.cloudflareresearch.com/logs/shard3"
	*domain = "example.com"

	if err := run(ctx); err != nil {
		t.Fatalf("run() for example.com failed: %v", err)
	}

	// 2. Verify prefix query under "example.com"
	*prefixQuery = true
	err = run(ctx)
	*prefixQuery = false
	if err != nil {
		t.Fatalf("run() with --prefix for example.com failed: %v", err)
	}

	// 2. Verify subdomain "service.corp.example.co.uk"
	*domain = "service.corp.example.co.uk"
	if err := run(ctx); err != nil {
		t.Fatalf("run() for service.corp.example.co.uk failed: %v", err)
	}

	// 3. Verify wildcard "*.service.corp.example.co.uk"
	*domain = "*.service.corp.example.co.uk"
	if err := run(ctx); err != nil {
		t.Fatalf("run() for *.service.corp.example.co.uk failed: %v", err)
	}

	// 4. Verify non-existent domain "notfound.org"
	*domain = "notfound.org"
	if err := run(ctx); err != nil {
		t.Fatalf("run() for notfound.org failed: %v", err)
	}

	// 5. Verify error on empty domain
	*domain = ""
	if err := run(ctx); err == nil {
		t.Fatal("expected error on empty domain, got nil")
	}
}
