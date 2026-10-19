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

package mpt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	torchmpt "filippo.io/torchwood/mpt"
)

func TestMPT_EmptyTree(t *testing.T) {
	mgr := NewMem()
	emptyRoot := sha256.Sum256(nil)
	if mgr.Root() != emptyRoot {
		t.Fatalf("Empty tree root = %x, want %x", mgr.Root(), emptyRoot)
	}

	key := sha256.Sum256([]byte("non-existent-key"))
	proof, val, exists, err := mgr.Prove(key)
	if err != nil {
		t.Fatalf("Prove on empty tree failed: %v", err)
	}
	if exists {
		t.Fatal("expected exists = false on empty tree")
	}
	if err := Verify(mgr.Root(), key, val, exists, proof); err != nil {
		t.Fatalf("Verify non-inclusion failed on empty tree: %v", err)
	}
}

func TestMPT_PredictMatchesCommit(t *testing.T) {
	mgr := NewMem()

	mutations := make(map[[sha256.Size]byte][sha256.Size]byte)
	for i := 0; i < 500; i++ {
		k := sha256.Sum256([]byte(fmt.Sprintf("key_%d", i)))
		v := sha256.Sum256([]byte(fmt.Sprintf("val_%d", i)))
		mutations[k] = v
	}

	predictedRoot, err := mgr.Predict(mutations)
	if err != nil {
		t.Fatalf("Predict failed: %v", err)
	}

	actualRoot, err := mgr.Commit(mutations)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if actualRoot != predictedRoot {
		t.Fatalf("Predict / Commit root mismatch: predicted %x, actual %x", predictedRoot, actualRoot)
	}
	if mgr.Root() != actualRoot {
		t.Fatalf("mgr.Root() = %x, want %x", mgr.Root(), actualRoot)
	}

	// Verify inclusion proof for all committed keys
	for k, wantVal := range mutations {
		proof, gotVal, exists, err := mgr.Prove(k)
		if err != nil {
			t.Fatalf("Prove(%x) failed: %v", k, err)
		}
		if !exists {
			t.Fatalf("Prove(%x) exists = false, want true", k)
		}
		if gotVal != wantVal {
			t.Fatalf("Prove(%x) val = %x, want %x", k, gotVal, wantVal)
		}
		if err := Verify(actualRoot, k, gotVal, true, proof); err != nil {
			t.Fatalf("Verify(%x) inclusion failed: %v", k, err)
		}
	}

	// Verify non-inclusion for missing key
	missingKey := sha256.Sum256([]byte("absent_key"))
	proof, val, exists, err := mgr.Prove(missingKey)
	if err != nil {
		t.Fatalf("Prove(missingKey) failed: %v", err)
	}
	if exists {
		t.Fatal("expected exists = false for absent key")
	}
	if err := Verify(actualRoot, missingKey, val, false, proof); err != nil {
		t.Fatalf("Verify non-inclusion failed: %v", err)
	}
}

func BenchmarkMPT_Prove_NoSync(b *testing.B) {
	dir := b.TempDir()
	mgr, err := Open(dir)
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	b.Cleanup(func() { _ = mgr.Close() })

	const numKeys = 2000
	keys := make([][sha256.Size]byte, numKeys)
	initialMutations := make(map[[sha256.Size]byte][sha256.Size]byte, numKeys)
	for i := 0; i < numKeys; i++ {
		k := sha256.Sum256([]byte(fmt.Sprintf("bench_key_%d", i)))
		v := sha256.Sum256([]byte(fmt.Sprintf("bench_val_%d", i)))
		keys[i] = k
		initialMutations[k] = v
	}
	if _, err := mgr.Commit(initialMutations); err != nil {
		b.Fatalf("initial Commit failed: %v", err)
	}
	if err := mgr.Persist(); err != nil {
		b.Fatalf("initial Persist failed: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			k := keys[i%numKeys]
			mgr.RLock()
			_, _, _, err := mgr.ProveLocked(k)
			mgr.RUnlock()
			if err != nil {
				b.Errorf("ProveLocked failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkMPT_ReadContentionDuringSync(b *testing.B) {
	dir := b.TempDir()
	mgr, err := Open(dir)
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	b.Cleanup(func() { _ = mgr.Close() })

	// Pre-populate with 2,000 keys
	const numKeys = 2000
	keys := make([][sha256.Size]byte, numKeys)
	initialMutations := make(map[[sha256.Size]byte][sha256.Size]byte, numKeys)
	for i := 0; i < numKeys; i++ {
		k := sha256.Sum256([]byte(fmt.Sprintf("bench_key_%d", i)))
		v := sha256.Sum256([]byte(fmt.Sprintf("bench_val_%d", i)))
		keys[i] = k
		initialMutations[k] = v
	}
	if _, err := mgr.Commit(initialMutations); err != nil {
		b.Fatalf("initial Commit failed: %v", err)
	}
	if err := mgr.Persist(); err != nil {
		b.Fatalf("initial Persist failed: %v", err)
	}

	// Background worker doing continuous mutations + Persist() disk syncs
	stopCh := make(chan struct{})
	go func() {
		counter := 0
		for {
			select {
			case <-stopCh:
				return
			default:
				counter++
				muts := make(map[[sha256.Size]byte][sha256.Size]byte, 10)
				for j := 0; j < 10; j++ {
					k := keys[(counter*10+j)%numKeys]
					v := sha256.Sum256([]byte(fmt.Sprintf("val_update_%d_%d", counter, j)))
					muts[k] = v
				}
				_, _ = mgr.Commit(muts)
				_ = mgr.Persist()
			}
		}
	}()
	b.Cleanup(func() { close(stopCh) })

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			k := keys[i%numKeys]
			mgr.RLock()
			_, _, _, err := mgr.ProveLocked(k)
			mgr.RUnlock()
			if err != nil {
				b.Errorf("ProveLocked failed: %v", err)
			}
			i++
		}
	})
}

func TestMPT_SetBatchAndSnap(t *testing.T) {
	mgr := NewMem()

	mutations := make(map[[sha256.Size]byte][sha256.Size]byte)
	for i := 0; i < 200; i++ {
		k := sha256.Sum256([]byte(fmt.Sprintf("genesis_key_%d", i)))
		v := sha256.Sum256([]byte(fmt.Sprintf("genesis_val_%d", i)))
		mutations[k] = v
	}

	// Compare SetBatch + Snap with Commit
	predictedRoot, err := mgr.Predict(mutations)
	if err != nil {
		t.Fatalf("Predict failed: %v", err)
	}

	if err := mgr.SetBatch(mutations); err != nil {
		t.Fatalf("SetBatch failed: %v", err)
	}

	snappedRoot, err := mgr.Snap(200)
	if err != nil {
		t.Fatalf("Snap failed: %v", err)
	}

	if snappedRoot != predictedRoot {
		t.Fatalf("snappedRoot %x != predictedRoot %x", snappedRoot, predictedRoot)
	}
	if mgr.PersistedVersion() != 200 {
		t.Fatalf("PersistedVersion = %d, want 200", mgr.PersistedVersion())
	}
	if mgr.PersistedSize() != 0 {
		t.Fatalf("PersistedSize before Persist() = %d, want 0", mgr.PersistedSize())
	}
	if err := mgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}
	if mgr.PersistedSize() != 200 {
		t.Fatalf("PersistedSize after Persist() = %d, want 200", mgr.PersistedSize())
	}
}

func TestMPT_DirtyCrashPreservesNonExactFlag(t *testing.T) {
	dir := t.TempDir()
	mgr, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !mgr.IsExact() {
		t.Fatal("freshly opened MPT should have IsExact() == true")
	}

	// Commit an initial clean version 10 and persist to disk
	k0 := sha256.Sum256([]byte("clean_key"))
	v0 := sha256.Sum256([]byte("clean_val"))
	if _, err := mgr.CommitWithVersion(map[[32]byte][32]byte{k0: v0}, 10); err != nil {
		t.Fatalf("CommitWithVersion failed: %v", err)
	}
	if err := mgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}
	if !mgr.IsExact() {
		t.Fatal("after CommitWithVersion + Persist, IsExact() should be true")
	}

	// Mutate via SetBatch without Snap to simulate dirty crash mid-write
	k := sha256.Sum256([]byte("dirty_key"))
	v := sha256.Sum256([]byte("dirty_val"))
	if err := mgr.SetBatch(map[[32]byte][32]byte{k: v}); err != nil {
		t.Fatalf("SetBatch failed: %v", err)
	}
	if mgr.IsExact() {
		t.Fatal("after SetBatch without Snap, IsExact() should be false")
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen: Open must inspect tree.Version() before calling Snap(-1) so IsExact() remains false!
	mgr2, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() { _ = mgr2.Close() }()
	if mgr2.IsExact() {
		t.Fatal("reopened dirty MPT must preserve IsExact() == false so Coordinator triggers replay")
	}
}

func TestMPT_DiskPersistence_Reopen(t *testing.T) {
	dir := t.TempDir()
	mgr, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	mutations := make(map[[sha256.Size]byte][sha256.Size]byte)
	for i := 0; i < 50; i++ {
		k := sha256.Sum256([]byte(fmt.Sprintf("persist_key_%d", i)))
		v := sha256.Sum256([]byte(fmt.Sprintf("persist_val_%d", i)))
		mutations[k] = v
	}

	actualRoot, err := mgr.CommitWithVersion(mutations, 50)
	if err != nil {
		t.Fatalf("CommitWithVersion failed: %v", err)
	}

	if err := mgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}
	if err := mgr.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if mgr.PersistedSize() != 50 {
		t.Fatalf("PersistedSize = %d, want 50", mgr.PersistedSize())
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen MPT on the same directory
	mgr2, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() { _ = mgr2.Close() }()

	if mgr2.Root() != actualRoot {
		t.Fatalf("Reopened root %x != original %x", mgr2.Root(), actualRoot)
	}
	if mgr2.PersistedVersion() != 50 {
		t.Fatalf("Reopened PersistedVersion = %d, want 50", mgr2.PersistedVersion())
	}
	if mgr2.PersistedSize() != 50 {
		t.Fatalf("Reopened PersistedSize = %d, want 50", mgr2.PersistedSize())
	}

	// Verify all keys prove and verify inclusion on reopened MPT
	for k, wantVal := range mutations {
		proof, gotVal, exists, err := mgr2.Prove(k)
		if err != nil {
			t.Fatalf("Prove(%x) failed on reopened MPT: %v", k, err)
		}
		if !exists || gotVal != wantVal {
			t.Fatalf("Prove(%x) exists=%v, val=%x, want %x", k, exists, gotVal, wantVal)
		}
		if err := Verify(actualRoot, k, gotVal, true, proof); err != nil {
			t.Fatalf("Verify(%x) failed on reopened MPT: %v", k, err)
		}
	}

	// Verify non-inclusion for missing key
	missingKey := sha256.Sum256([]byte("absent_key"))
	proof, val, exists, err := mgr2.Prove(missingKey)
	if err != nil || exists {
		t.Fatalf("Prove(missingKey) exists=%v, err=%v", exists, err)
	}
	if err := Verify(actualRoot, missingKey, val, false, proof); err != nil {
		t.Fatalf("Verify non-inclusion failed on reopened MPT: %v", err)
	}
}

func TestMPT_CorruptedFile_Open(t *testing.T) {
	dir := t.TempDir()
	// Write corrupted garbage to mpt.tree1
	if err := os.WriteFile(filepath.Join(dir, "mpt.tree1"), []byte("garbage_data_too_short"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := Open(dir); err == nil {
		t.Error("expected error opening corrupted mpt.tree1, got nil")
	}
}

func TestSortKeyVals(t *testing.T) {
	testSizes := []int{0, 1, 2, 8191, 8192, 8193, 20000}
	for _, sz := range testSizes {
		t.Run(fmt.Sprintf("size_%d", sz), func(t *testing.T) {
			input := make([]torchmpt.KeyVal, sz)
			for i := 0; i < sz; i++ {
				h := sha256.Sum256([]byte(fmt.Sprintf("key_%d", (i*31+17)%1000000)))
				input[i] = torchmpt.KeyVal{Key: torchmpt.Key(h[:])}
			}
			expected := make([]torchmpt.KeyVal, sz)
			copy(expected, input)
			slices.SortFunc(expected, func(a, b torchmpt.KeyVal) int {
				return a.Key.Compare(b.Key)
			})

			SortKeyVals(input)

			for i := 0; i < sz; i++ {
				if !bytes.Equal(input[i].Key, expected[i].Key) {
					t.Fatalf("mismatch at index %d: got %x, want %x", i, input[i].Key, expected[i].Key)
				}
			}
		})
	}

	t.Run("all_same_prefix", func(t *testing.T) {
		const sz = 10000
		input := make([]torchmpt.KeyVal, sz)
		for i := 0; i < sz; i++ {
			h := sha256.Sum256([]byte(fmt.Sprintf("prefix_key_%d", i)))
			h[0] = 0x42 // force all into single bucket
			input[i] = torchmpt.KeyVal{Key: torchmpt.Key(h[:])}
		}
		expected := make([]torchmpt.KeyVal, sz)
		copy(expected, input)
		slices.SortFunc(expected, func(a, b torchmpt.KeyVal) int {
			return a.Key.Compare(b.Key)
		})

		SortKeyVals(input)

		for i := 0; i < sz; i++ {
			if !bytes.Equal(input[i].Key, expected[i].Key) {
				t.Fatalf("mismatch at index %d: got %x, want %x", i, input[i].Key, expected[i].Key)
			}
		}
	})

	t.Run("duplicate_keys", func(t *testing.T) {
		const sz = 16000
		input := make([]torchmpt.KeyVal, sz)
		for i := 0; i < sz; i++ {
			h := sha256.Sum256([]byte(fmt.Sprintf("dup_key_%d", i%100)))
			input[i] = torchmpt.KeyVal{Key: torchmpt.Key(h[:])}
		}
		expected := make([]torchmpt.KeyVal, sz)
		copy(expected, input)
		slices.SortFunc(expected, func(a, b torchmpt.KeyVal) int {
			return a.Key.Compare(b.Key)
		})

		SortKeyVals(input)

		for i := 0; i < sz; i++ {
			if !bytes.Equal(input[i].Key, expected[i].Key) {
				t.Fatalf("mismatch at index %d: got %x, want %x", i, input[i].Key, expected[i].Key)
			}
		}
	})
}

func TestMPT_VariableLengthKeysAndPrefixProofs(t *testing.T) {
	mgr := NewMem()

	mutations := map[string][sha256.Size]byte{
		"com.google.":      sha256.Sum256([]byte("val_apex")),
		"com.google.*.":    sha256.Sum256([]byte("val_wildcard")),
		"com.google.docs.": sha256.Sum256([]byte("val_docs")),
		"com.google.mail.": sha256.Sum256([]byte("val_mail")),
		"com.googleapis.":  sha256.Sum256([]byte("val_apis")),
		"org.example.":     sha256.Sum256([]byte("val_example")),
	}

	for k := range mutations {
		if err := ValidateCanonicalKey([]byte(k)); err != nil {
			t.Fatalf("ValidateCanonicalKey(%q) failed: %v", k, err)
		}
	}

	if err := ValidateCanonicalKey(nil); err == nil {
		t.Fatal("expected error for empty canonical key")
	}
	if err := ValidateCanonicalKey([]byte("com.google.\x00")); err == nil {
		t.Fatal("expected error for canonical key with NUL")
	}
	if err := ValidateCanonicalKey([]byte("com.google. ")); err == nil {
		t.Fatal("expected error for canonical key with space")
	}

	predictedRoot, err := mgr.PredictKeys(mutations)
	if err != nil {
		t.Fatalf("PredictKeys failed: %v", err)
	}

	actualRoot, err := mgr.CommitKeys(mutations)
	if err != nil {
		t.Fatalf("CommitKeys failed: %v", err)
	}
	if actualRoot != predictedRoot {
		t.Fatalf("PredictKeys / CommitKeys mismatch: %x != %x", predictedRoot, actualRoot)
	}

	// Point lookup proofs (including coexisting "com.google." and "com.google.mail.")
	for k, wantVal := range mutations {
		proof, gotVal, exists, err := mgr.ProveKey([]byte(k))
		if err != nil {
			t.Fatalf("ProveKey(%q) failed: %v", k, err)
		}
		if !exists || gotVal != wantVal {
			t.Fatalf("ProveKey(%q) exists=%v, val=%x, want %x", k, exists, gotVal, wantVal)
		}
		if err := VerifyKey(actualRoot, []byte(k), gotVal, true, proof); err != nil {
			t.Fatalf("VerifyKey(%q) failed: %v", k, err)
		}
	}

	// Prefix proof for "com.google." (should match 4 keys in ascending order)
	prefix := []byte("com.google.")
	prefixProof, matches, err := mgr.ProvePrefix(prefix, 0)
	if err != nil {
		t.Fatalf("ProvePrefix failed: %v", err)
	}
	if len(matches) != 4 {
		t.Fatalf("len(matches) = %d, want 4", len(matches))
	}
	if err := VerifyPrefix(actualRoot, prefix, matches, prefixProof); err != nil {
		t.Fatalf("VerifyPrefix failed: %v", err)
	}

	// Adversarial check: omitting a key must fail VerifyPrefix
	if err := VerifyPrefix(actualRoot, prefix, matches[:3], prefixProof); err == nil {
		t.Fatal("expected VerifyPrefix to fail when omitting a matching key")
	}

	// MaxResults limit check
	if _, _, err := mgr.ProvePrefix(prefix, 3); err == nil {
		t.Fatal("expected ProvePrefix with maxResults=3 to fail with ErrPrefixTooManyKeys")
	}

	// Empty prefix match ("com.nonexistent.")
	emptyPrefix := []byte("com.nonexistent.")
	emptyProof, emptyMatches, err := mgr.ProvePrefix(emptyPrefix, 0)
	if err != nil {
		t.Fatalf("ProvePrefix(emptyPrefix) failed: %v", err)
	}
	if len(emptyMatches) != 0 {
		t.Fatalf("len(emptyMatches) = %d, want 0", len(emptyMatches))
	}
	if err := VerifyPrefix(actualRoot, emptyPrefix, emptyMatches, emptyProof); err != nil {
		t.Fatalf("VerifyPrefix(emptyPrefix) failed: %v", err)
	}
}

func BenchmarkMPT_ProvePrefix(b *testing.B) {
	mgr := NewMem()
	mutations := make(map[string][sha256.Size]byte, 2000)
	for i := 0; i < 2000; i++ {
		var k string
		if i < 50 {
			k = fmt.Sprintf("com.google.sub%04d.", i)
		} else {
			k = fmt.Sprintf("org.other%04d.sub.", i)
		}
		mutations[k] = sha256.Sum256([]byte(k))
	}
	root, err := mgr.CommitKeys(mutations)
	if err != nil {
		b.Fatalf("CommitKeys failed: %v", err)
	}
	prefix := []byte("com.google.")

	b.ResetTimer()
	for b.Loop() {
		proof, matches, err := mgr.ProvePrefix(prefix, 1000)
		if err != nil {
			b.Fatalf("ProvePrefix failed: %v", err)
		}
		if err := VerifyPrefix(root, prefix, matches, proof); err != nil {
			b.Fatalf("VerifyPrefix failed: %v", err)
		}
	}
}

func TestMPT_ConcurrentPersistAndReaders_Race(t *testing.T) {
	mgr, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	initial := make(map[string][sha256.Size]byte, 64)
	for i := 0; i < 64; i++ {
		k := fmt.Sprintf("com.example.k%03d.", i)
		initial[k] = sha256.Sum256([]byte(k))
	}
	if _, err := mgr.CommitKeysWithVersion(initial, 100); err != nil {
		t.Fatalf("initial CommitKeysWithVersion failed: %v", err)
	}
	if err := mgr.Persist(); err != nil {
		t.Fatalf("initial Persist failed: %v", err)
	}

	const rounds = 25
	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	reportErr := func(e error) {
		select {
		case errCh <- e:
		default:
		}
	}

	// Writer + Persist goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := 1; r <= rounds; r++ {
			batch := map[string][sha256.Size]byte{
				fmt.Sprintf("com.example.dyn%03d.", r): sha256.Sum256([]byte(fmt.Sprintf("v-%d", r))),
			}
			if _, err := mgr.CommitKeysWithVersion(batch, int64(100+r)); err != nil {
				reportErr(fmt.Errorf("CommitKeysWithVersion(%d): %w", r, err))
				return
			}
			if err := mgr.Persist(); err != nil {
				reportErr(fmt.Errorf("Persist(%d): %w", r, err))
				return
			}
		}
	}()

	// Concurrent ProveKey reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := 0; r < rounds*4; r++ {
			k := []byte(fmt.Sprintf("com.example.k%03d.", r%64))
			if _, _, exists, err := mgr.ProveKey(k); err != nil || !exists {
				reportErr(fmt.Errorf("ProveKey(%q): exists=%v err=%w", k, exists, err))
				return
			}
		}
	}()

	// Concurrent ProvePrefix reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		prefix := []byte("com.example.")
		for r := 0; r < rounds*2; r++ {
			if _, matches, err := mgr.ProvePrefix(prefix, 0); err != nil || len(matches) < 64 {
				reportErr(fmt.Errorf("ProvePrefix: len=%d err=%w", len(matches), err))
				return
			}
		}
	}()

	// Concurrent PredictRootFromKeyBatch reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		cand := map[string][sha256.Size]byte{
			"org.candidate.test.": sha256.Sum256([]byte("cand")),
		}
		for r := 0; r < rounds*2; r++ {
			if _, err := mgr.PredictRootFromKeyBatch(cand); err != nil {
				reportErr(fmt.Errorf("PredictRootFromKeyBatch: %w", err))
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatalf("concurrent MPT race/error: %v", e)
	}
	if got := mgr.PersistedSize(); got != uint64(100+rounds) {
		t.Fatalf("PersistedSize() = %d, want %d", got, 100+rounds)
	}
}

func testMPTLeafHash(key, val []byte) [sha256.Size]byte {
	var buf []byte
	buf = append(buf, 0x00)
	buf = binary.AppendUvarint(buf, uint64(len(key)))
	buf = append(buf, key...)
	buf = binary.AppendUvarint(buf, uint64(len(val)))
	buf = append(buf, val...)
	return sha256.Sum256(buf)
}

func testMPTInnerHash(bitPos uint64, left, right [sha256.Size]byte) [sha256.Size]byte {
	var buf []byte
	buf = append(buf, 0x01)
	buf = binary.AppendUvarint(buf, bitPos)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

func TestVerify_AdversarialWireBounds(t *testing.T) {
	val32 := sha256.Sum256([]byte("value-root"))
	sibHash := sha256.Sum256([]byte("sibling-node"))

	t.Run("reject_split_bit_8193", func(t *testing.T) {
		key := []byte("com.example.key")
		leafH := testMPTLeafHash(key, val32[:])
		// For bit 8193 (> len(key)*8), padded bit is 1 (0xFF padding), so node_hash is right child.
		forgedRoot := testMPTInnerHash(8193, sibHash, leafH)
		var proof []byte
		proof = binary.AppendUvarint(proof, 8193)
		proof = append(proof, sibHash[:]...)

		if err := VerifyKey(forgedRoot, key, val32, true, proof); err == nil {
			t.Fatal("expected VerifyKey to reject split bit 8193")
		}
	})

	t.Run("reject_non_canonical_path_key_in_non_inclusion_and_empty_prefix", func(t *testing.T) {
		badPathKeys := [][]byte{
			{},                              // empty
			[]byte("bad key"),               // contains space 0x20
			bytes.Repeat([]byte("a"), 1025), // 1025 bytes > 1024
		}
		targetKey := []byte("com.example.missing")
		targetPrefix := []byte("com.example.none.")

		for _, badPK := range badPathKeys {
			forgedRoot := testMPTLeafHash(badPK, val32[:])
			var proof []byte
			proof = binary.AppendUvarint(proof, uint64(len(badPK)))
			proof = append(proof, badPK...)
			proof = binary.AppendUvarint(proof, uint64(len(val32)))
			proof = append(proof, val32[:]...)

			if err := VerifyKey(forgedRoot, targetKey, [32]byte{}, false, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyKey(badPK len=%d) err = %v, want ErrInvalidProof", len(badPK), err)
			}
			if err := VerifyPrefix(forgedRoot, targetPrefix, nil, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyPrefix(badPK len=%d) err = %v, want ErrInvalidProof", len(badPK), err)
			}
		}
	})

	t.Run("reject_invalid_path_val_length", func(t *testing.T) {
		goodPK := []byte("com.example.present")
		shortVal := make([]byte, 16)
		forgedRoot := testMPTLeafHash(goodPK, shortVal)
		var proof []byte
		proof = binary.AppendUvarint(proof, uint64(len(goodPK)))
		proof = append(proof, goodPK...)
		proof = binary.AppendUvarint(proof, uint64(len(shortVal)))
		proof = append(proof, shortVal...)

		if err := VerifyKey(forgedRoot, []byte("com.example.absent"), [32]byte{}, false, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(len(path_val)=16) err = %v, want ErrInvalidProof", err)
		}
		if err := VerifyPrefix(forgedRoot, []byte("org.absent."), nil, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyPrefix(len(path_val)=16) err = %v, want ErrInvalidProof", err)
		}
	})

	t.Run("reject_overlong_uvarints_and_non_empty_proof_on_empty_mpt", func(t *testing.T) {
		key := []byte("a") // 'a' = 0x61 = 0b01100001 -> bit 0 is 0
		leafH := testMPTLeafHash(key, val32[:])
		root := testMPTInnerHash(0, leafH, sibHash)

		// Overlong uvarint for bit 0: [0x80, 0x00]
		var overlongStepProof []byte
		overlongStepProof = append(overlongStepProof, 0x80, 0x00)
		overlongStepProof = append(overlongStepProof, sibHash[:]...)

		if err := VerifyKey(root, key, val32, true, overlongStepProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(overlong step uvarint) err = %v, want ErrInvalidProof", err)
		}

		// Overlong uvarint for klen (1 encoded as [0x81, 0x00]) in non-inclusion proof
		singleLeafRoot := testMPTLeafHash(key, val32[:])
		var overlongKLenProof []byte
		overlongKLenProof = append(overlongKLenProof, 0x81, 0x00)
		overlongKLenProof = append(overlongKLenProof, key...)
		overlongKLenProof = binary.AppendUvarint(overlongKLenProof, 32)
		overlongKLenProof = append(overlongKLenProof, val32[:]...)

		if err := VerifyKey(singleLeafRoot, []byte("b"), [32]byte{}, false, overlongKLenProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(overlong klen) err = %v, want ErrInvalidProof", err)
		}

		// Non-empty proof for empty MPT root
		emptyRoot := sha256.Sum256(nil)
		if err := VerifyKey(emptyRoot, []byte("b"), [32]byte{}, false, []byte{0x00}); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(empty MPT with non-empty proof) err = %v, want ErrInvalidProof", err)
		}
		if err := VerifyPrefix(emptyRoot, []byte("b"), nil, []byte{0x00}); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyPrefix(empty MPT with non-empty proof) err = %v, want ErrInvalidProof", err)
		}
	})
}
