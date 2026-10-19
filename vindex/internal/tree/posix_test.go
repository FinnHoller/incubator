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

package tree_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
)

func newTestSigner(t *testing.T) note.Signer {
	t.Helper()
	skey, _, err := note.GenerateKey(rand.Reader, "outputlog.test")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return s
}

func TestNewPOSIXOutputLog_Validation(t *testing.T) {
	ctx := context.Background()
	signer := newTestSigner(t)
	tmpDir := t.TempDir()

	t.Run("nil signer", func(t *testing.T) {
		log, err := tree.NewPOSIXOutputLog(ctx, tmpDir, nil)
		if err == nil {
			if log != nil {
				_ = log.Close()
			}
			t.Fatal("expected error with nil signer, got nil")
		}
	})

	t.Run("empty storageDir", func(t *testing.T) {
		log, err := tree.NewPOSIXOutputLog(ctx, "", signer)
		if err == nil {
			if log != nil {
				_ = log.Close()
			}
			t.Fatal("expected error with empty storageDir, got nil")
		}
	})

	t.Run("origin mismatch", func(t *testing.T) {
		log, err := tree.NewPOSIXOutputLog(ctx, tmpDir, signer, tree.WithOrigin("mismatched.origin"))
		if err == nil {
			if log != nil {
				_ = log.Close()
			}
			t.Fatal("expected error with mismatched origin, got nil")
		}
	})

	t.Run("BuildWitnessGroup validation", func(t *testing.T) {
		_, vkey, err := note.GenerateKey(rand.Reader, "witness.test")
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		if _, err := tree.BuildWitnessGroup([]string{"https://witness.example.com/"}, []string{vkey}); err != nil {
			t.Fatalf("BuildWitnessGroup valid failed: %v", err)
		}
		if _, err := tree.BuildWitnessGroup([]string{"https://witness.example.com/"}, nil); err == nil {
			t.Fatal("expected error for mismatched urls/pubKeys length, got nil")
		}
		if _, err := tree.BuildWitnessGroup([]string{"://bad_url"}, []string{vkey}); err == nil {
			t.Fatal("expected error for invalid witness URL, got nil")
		}
	})
}

func TestPOSIXOutputLog_LifecycleAndVerification(t *testing.T) {
	ctx := context.Background()
	signer := newTestSigner(t)
	tmpDir := t.TempDir()

	outLog, err := tree.NewPOSIXOutputLog(ctx, tmpDir, signer,
		tree.WithOrigin("outputlog.test"),
		tree.WithBatchMaxSize(1),
		tree.WithBatchMaxAge(time.Millisecond),
		tree.WithCheckpointInterval(100*time.Millisecond),
		tree.WithPollPeriod(5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewPOSIXOutputLog failed: %v", err)
	}
	defer func() {
		if err := outLog.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	// Initial state checks
	size, err := outLog.Size(ctx)
	if err != nil {
		t.Fatalf("Size() on empty log failed: %v", err)
	}
	if size != 0 {
		t.Fatalf("Size() on empty log = %d, want 0", size)
	}

	rawCP, err := outLog.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint() on empty log failed: %v", err)
	}
	if rawCP != nil {
		parsedCP, err := tree.ParseCheckpointHeader(rawCP)
		if err != nil {
			t.Fatalf("ParseCheckpointHeader on initial checkpoint failed: %v", err)
		}
		if parsedCP.Size != 0 {
			t.Fatalf("initial checkpoint size = %d, want 0", parsedCP.Size)
		}
	}

	// Append 5 leaves
	leaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
		[]byte("leaf-4"),
	}

	for i, leaf := range leaves {
		leafIdx, cpBytes, appendErr := outLog.Append(ctx, leaf)
		if appendErr != nil {
			t.Fatalf("Append(%d) failed: %v", i, appendErr)
		}
		if leafIdx != uint64(i) {
			t.Fatalf("Append(%d) leafIdx = %d, want %d", i, leafIdx, i)
		}
		if len(cpBytes) == 0 {
			t.Fatalf("Append(%d) returned empty checkpoint", i)
		}
	}

	// Check size and checkpoint after appends
	size, err = outLog.Size(ctx)
	if err != nil {
		t.Fatalf("Size() failed: %v", err)
	}
	if size != uint64(len(leaves)) {
		t.Fatalf("Size() = %d, want %d", size, len(leaves))
	}

	rawCP, err = outLog.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint() failed: %v", err)
	}
	parsedCP, err := tree.ParseCheckpointHeader(rawCP)
	if err != nil {
		t.Fatalf("ParseCheckpointHeader failed: %v", err)
	}
	if parsedCP.Size != uint64(len(leaves)) {
		t.Fatalf("parsed checkpoint size = %d, want %d", parsedCP.Size, len(leaves))
	}

	// Verify GetLeaf and InclusionProof for each leaf
	for i, wantLeaf := range leaves {
		gotLeaf, getErr := outLog.GetLeaf(ctx, uint64(i))
		if getErr != nil {
			t.Fatalf("GetLeaf(%d) failed: %v", i, getErr)
		}
		if !bytes.Equal(gotLeaf, wantLeaf) {
			t.Fatalf("GetLeaf(%d) = %q, want %q", i, gotLeaf, wantLeaf)
		}

		proofHashes, proofErr := outLog.InclusionProof(ctx, uint64(i), parsedCP.Size)
		if proofErr != nil {
			t.Fatalf("InclusionProof(%d, %d) failed: %v", i, parsedCP.Size, proofErr)
		}

		rawProof := make([][]byte, len(proofHashes))
		for pIdx, h := range proofHashes {
			rawProof[pIdx] = h[:]
		}
		leafHash := rfc6962.DefaultHasher.HashLeaf(wantLeaf)
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(i), parsedCP.Size, leafHash, rawProof, parsedCP.Hash); err != nil {
			t.Fatalf("VerifyInclusion failed for leaf %d: %v", i, err)
		}
	}

	// Out of bounds GetLeaf
	if _, err := outLog.GetLeaf(ctx, uint64(len(leaves))); err == nil {
		t.Fatal("GetLeaf(out_of_bounds) expected error, got nil")
	}

	// Out of bounds InclusionProof
	if _, err := outLog.InclusionProof(ctx, uint64(len(leaves)), parsedCP.Size); err == nil {
		t.Fatal("InclusionProof(leafIdx >= treeSize) expected error, got nil")
	}

	// Close idempotency
	if err := outLog.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := outLog.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestPOSIXOutputLog_SpanningEntryBundles(t *testing.T) {
	ctx := context.Background()
	signer := newTestSigner(t)
	tmpDir := t.TempDir()

	outLog, err := tree.NewPOSIXOutputLog(ctx, tmpDir, signer,
		tree.WithBatchMaxSize(256),
		tree.WithBatchMaxAge(10*time.Millisecond),
		tree.WithCheckpointInterval(100*time.Millisecond),
		tree.WithPollPeriod(5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewPOSIXOutputLog failed: %v", err)
	}
	defer func() {
		_ = outLog.Close()
	}()

	numEntries := 270
	leaves := make([][]byte, numEntries)
	for i := 0; i < numEntries; i++ {
		leaves[i] = []byte(fmt.Sprintf("bundle-entry-%04d", i))
	}
	indices := make([]uint64, numEntries)

	var g errgroup.Group
	for i := 0; i < numEntries; i++ {
		idx := i
		g.Go(func() error {
			leafIdx, _, appendErr := outLog.Append(ctx, leaves[idx])
			if appendErr != nil {
				return fmt.Errorf("Append(%d) failed: %w", idx, appendErr)
			}
			indices[idx] = leafIdx
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("concurrent appends failed: %v", err)
	}

	size, err := outLog.Size(ctx)
	if err != nil {
		t.Fatalf("Size() failed: %v", err)
	}
	if size != uint64(numEntries) {
		t.Fatalf("Size() = %d, want %d", size, numEntries)
	}

	rawCP, err := outLog.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint() failed: %v", err)
	}
	parsedCP, err := tree.ParseCheckpointHeader(rawCP)
	if err != nil {
		t.Fatalf("ParseCheckpointHeader failed: %v", err)
	}

	// Map returned leafIdx back to original leaf payload
	idxToLeaf := make(map[uint64][]byte, numEntries)
	for i := 0; i < numEntries; i++ {
		idxToLeaf[indices[i]] = leaves[i]
	}

	// Spot check boundary indices across bundle 0 and bundle 1 (>256)
	testIndices := []uint64{0, 1, 127, 255, 256, 257, uint64(numEntries - 1)}
	for _, idx := range testIndices {
		wantLeaf := idxToLeaf[idx]
		gotLeaf, getErr := outLog.GetLeaf(ctx, idx)
		if getErr != nil {
			t.Fatalf("GetLeaf(%d) failed: %v", idx, getErr)
		}
		if !bytes.Equal(gotLeaf, wantLeaf) {
			t.Fatalf("GetLeaf(%d) = %q, want %q", idx, gotLeaf, wantLeaf)
		}

		proofHashes, proofErr := outLog.InclusionProof(ctx, idx, parsedCP.Size)
		if proofErr != nil {
			t.Fatalf("InclusionProof(%d, %d) failed: %v", idx, parsedCP.Size, proofErr)
		}
		rawProof := make([][]byte, len(proofHashes))
		for pIdx, h := range proofHashes {
			rawProof[pIdx] = h[:]
		}
		leafHash := rfc6962.DefaultHasher.HashLeaf(wantLeaf)
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, parsedCP.Size, leafHash, rawProof, parsedCP.Hash); err != nil {
			t.Fatalf("VerifyInclusion failed for leaf %d: %v", idx, err)
		}
	}
}

func TestPOSIXOutputLog_PersistenceReopen(t *testing.T) {
	ctx := context.Background()
	signer := newTestSigner(t)
	tmpDir := filepath.Join(t.TempDir(), "persistent_log")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	// Phase 1: Open, write 3 entries, close
	{
		log1, err := tree.NewPOSIXOutputLog(ctx, tmpDir, signer,
			tree.WithCheckpointInterval(100*time.Millisecond),
			tree.WithPollPeriod(5*time.Millisecond),
		)
		if err != nil {
			t.Fatalf("Phase 1 NewPOSIXOutputLog failed: %v", err)
		}

		for i := 0; i < 3; i++ {
			leaf := []byte(fmt.Sprintf("phase1-leaf-%d", i))
			idx, _, appendErr := log1.Append(ctx, leaf)
			if appendErr != nil {
				t.Fatalf("Phase 1 Append(%d) failed: %v", i, appendErr)
			}
			if idx != uint64(i) {
				t.Fatalf("Phase 1 Append(%d) idx = %d, want %d", i, idx, i)
			}
		}

		if err := log1.Close(); err != nil {
			t.Fatalf("Phase 1 Close failed: %v", err)
		}
	}

	// Phase 2: Reopen on same directory, verify existing entries, write 2 more entries
	{
		log2, err := tree.NewPOSIXOutputLog(ctx, tmpDir, signer,
			tree.WithCheckpointInterval(100*time.Millisecond),
			tree.WithPollPeriod(5*time.Millisecond),
		)
		if err != nil {
			t.Fatalf("Phase 2 NewPOSIXOutputLog failed: %v", err)
		}
		defer func() {
			_ = log2.Close()
		}()

		size, err := log2.Size(ctx)
		if err != nil {
			t.Fatalf("Phase 2 Size() failed: %v", err)
		}
		if size != 3 {
			t.Fatalf("Phase 2 Size() = %d, want 3", size)
		}

		for i := 0; i < 3; i++ {
			wantLeaf := []byte(fmt.Sprintf("phase1-leaf-%d", i))
			gotLeaf, getErr := log2.GetLeaf(ctx, uint64(i))
			if getErr != nil {
				t.Fatalf("Phase 2 GetLeaf(%d) failed: %v", i, getErr)
			}
			if !bytes.Equal(gotLeaf, wantLeaf) {
				t.Fatalf("Phase 2 GetLeaf(%d) = %q, want %q", i, gotLeaf, wantLeaf)
			}
		}

		// Append 2 more entries
		for i := 3; i < 5; i++ {
			leaf := []byte(fmt.Sprintf("phase2-leaf-%d", i))
			idx, _, appendErr := log2.Append(ctx, leaf)
			if appendErr != nil {
				t.Fatalf("Phase 2 Append(%d) failed: %v", i, appendErr)
			}
			if idx != uint64(i) {
				t.Fatalf("Phase 2 Append(%d) idx = %d, want %d", i, idx, i)
			}
		}

		size, err = log2.Size(ctx)
		if err != nil {
			t.Fatalf("Phase 2 Size() after append failed: %v", err)
		}
		if size != 5 {
			t.Fatalf("Phase 2 Size() after append = %d, want 5", size)
		}

		rawCP, err := log2.Checkpoint(ctx)
		if err != nil {
			t.Fatalf("Phase 2 Checkpoint() failed: %v", err)
		}
		parsedCP, err := tree.ParseCheckpointHeader(rawCP)
		if err != nil {
			t.Fatalf("Phase 2 ParseCheckpointHeader failed: %v", err)
		}

		// Verify inclusion proofs for all 5 leaves
		for i := 0; i < 5; i++ {
			var wantLeaf []byte
			if i < 3 {
				wantLeaf = []byte(fmt.Sprintf("phase1-leaf-%d", i))
			} else {
				wantLeaf = []byte(fmt.Sprintf("phase2-leaf-%d", i))
			}

			proofHashes, proofErr := log2.InclusionProof(ctx, uint64(i), parsedCP.Size)
			if proofErr != nil {
				t.Fatalf("InclusionProof(%d, %d) failed: %v", i, parsedCP.Size, proofErr)
			}
			rawProof := make([][]byte, len(proofHashes))
			for pIdx, h := range proofHashes {
				rawProof[pIdx] = h[:]
			}
			leafHash := rfc6962.DefaultHasher.HashLeaf(wantLeaf)
			if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(i), parsedCP.Size, leafHash, rawProof, parsedCP.Hash); err != nil {
				t.Fatalf("VerifyInclusion failed for leaf %d: %v", i, err)
			}
		}
	}
}
