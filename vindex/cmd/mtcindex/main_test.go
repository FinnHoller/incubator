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
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"golang.org/x/mod/sumdb/note"
)

// helper to marshal TBSCertificateLogEntry
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

func TestMTCIndex_Integration(t *testing.T) {
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
	leaf1, err := marshalMTCEntry([]string{"deep.maps.google.co.uk"})
	if err != nil {
		t.Fatalf("failed to create leaf1: %v", err)
	}
	leaf2, err := marshalMTCEntry([]string{"MAPS.GOOGLE.COM"})
	if err != nil {
		t.Fatalf("failed to create leaf2: %v", err)
	}

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "bootstrap-mtca.cloudflareresearch.com/logs/shard3")
	if err != nil {
		t.Fatalf("note.GenerateKey(input) failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(input) failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(input) failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "MTCIndex")
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
	_ = inVKey
	_ = inVerifier

	mockInputLog := &testMTCInputLog{
		origin: "bootstrap-mtca.cloudflareresearch.com/logs/shard3",
		signer: inSigner,
		leaves: [][]byte{
			leaf0, // idx 0 -> example.com
			leaf1, // idx 1 -> deep.maps.google.co.uk, maps.google.co.uk, google.co.uk
			leaf2, // idx 2 -> maps.google.com, google.com
		},
	}

	outLog, err := newLocalOutputLog("MTCIndex", tempDir+"/outputlog", outSigner)
	if err != nil {
		t.Fatalf("newLocalOutputLog failed: %v", err)
	}

	const chunkSize = 16
	leafMapper := &mtcLeafMapper{}
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
	readSrv.SetPrefixPolicy(reversedDNSPrefixPolicy)
	mux := http.NewServeMux()
	readSrv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	adminMux := http.NewServeMux()
	readSrv.RegisterAdminRoutes(adminMux)
	adminTS := httptest.NewServer(adminMux)
	defer adminTS.Close()

	if res, err := ts.Client().Get(ts.URL + "/metrics"); err != nil {
		t.Fatalf("GET public /metrics failed: %v", err)
	} else {
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("public /metrics status = %d, want 404", res.StatusCode)
		}
	}
	if res, err := adminTS.Client().Get(adminTS.URL + "/metrics"); err != nil {
		t.Fatalf("GET admin /metrics failed: %v", err)
	} else {
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("admin /metrics status = %d, want 200", res.StatusCode)
		}
	}

	outPolicy, err := client.SingleKeyPolicy("MTCIndex", outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	cli, err := client.New(ts.URL, client.Config{
		ExpectedOutputLogOrigin: "MTCIndex",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  mockInputLog.origin,
	}, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	assertKeyIndices := func(key string, want []uint64) {
		t.Helper()
		kResp, err := cli.LookupKey(ctx, key)
		if err != nil {
			t.Fatalf("cli.LookupKey(%s) failed: %v", key, err)
		}
		if len(kResp.Keys) != 1 {
			t.Fatalf("%s should exist in index", key)
		}
		var rev []uint64
		for idx, err := range kResp.Keys[0].Values(ctx) {
			if err != nil {
				t.Fatalf("Values(%s) failed: %v", key, err)
			}
			rev = append(rev, idx)
		}
		got := make([]uint64, len(rev))
		for i, v := range rev {
			got[len(rev)-1-i] = v
		}
		if len(got) != len(want) {
			t.Fatalf("%s indices = %v, want %v", key, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s indices[%d] = %d, want %d", key, i, got[i], want[i])
			}
		}
	}

	// 1. Lookup "com.example."
	assertKeyIndices("com.example.", []uint64{0})

	// 2. Lookup "com.example.*." (wildcard preserved separately from apex)
	assertKeyIndices("com.example.*.", []uint64{0})

	// 3. Lookup "uk.co.google.maps.deep."
	assertKeyIndices("uk.co.google.maps.deep.", []uint64{1})

	// 4. Lookup "com.google.maps." (from MAPS.GOOGLE.COM)
	assertKeyIndices("com.google.maps.", []uint64{2})

	// 5. Lookup unknown key (verified non-inclusion)
	respUnknown, err := cli.LookupKey(ctx, "org.example.nonexistent.")
	if err != nil {
		t.Fatalf("cli.LookupKey(org.example.nonexistent.) failed: %v", err)
	}
	if len(respUnknown.Keys) != 0 {
		t.Fatalf("org.example.nonexistent. should not exist: keys=%+v", respUnknown.Keys)
	}

	// 6. Prefix policy enforcement (reject TLD 'com.', accept eTLD+1 'com.example.')
	if _, err := cli.LookupPrefix(ctx, "com."); err == nil {
		t.Fatal("expected LookupPrefix('com.') to be rejected by reversedDNSPrefixPolicy")
	}
	pResp, err := cli.LookupPrefix(ctx, "com.example.")
	if err != nil {
		t.Fatalf("LookupPrefix('com.example.') failed: %v", err)
	}
	if len(pResp.Keys) != 2 {
		t.Fatalf("LookupPrefix('com.example.') got %d keys, want 2", len(pResp.Keys))
	}
}
