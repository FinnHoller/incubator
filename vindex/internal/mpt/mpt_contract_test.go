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
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	torchmpt "filippo.io/torchwood/mpt"
)

func testVal(seed string) torchmpt.Val {
	h := sha256.Sum256([]byte(seed))
	return torchmpt.Val(h[:])
}

// runBothTreeImpls runs fn against both the in-memory Tree and the disk-backed Tree.
// Note: Each diskTree reserves 16 TiB (1 << 44 bytes) of virtual address space via mmap(PROT_NONE).
// Under -race (TSAN shadow memory) on 48-bit Linux x86_64, opening >4 diskTree instances
// concurrently exhausts virtual address space ("span.Reserve 17592186044416: cannot allocate memory").
// Therefore tests that invoke runBothTreeImpls or torchmpt.Create/Open must run sequentially
// so each diskTree is unmapped via Close() before the next is created.
func runBothTreeImpls(t *testing.T, fn func(t *testing.T, tr torchmpt.Tree)) {
	t.Helper()
	t.Run("mem", func(t *testing.T) {
		tr := torchmpt.NewMemTree()
		defer func() { _ = tr.Close() }()
		fn(t, tr)
	})
	t.Run("disk", func(t *testing.T) {
		dir := t.TempDir()
		tr, err := torchmpt.Create(
			filepath.Join(dir, "mpt.tree1"),
			filepath.Join(dir, "mpt.tree2"),
			filepath.Join(dir, "mpt.disk"),
		)
		if err != nil {
			t.Fatalf("torchmpt.Create failed: %v", err)
		}
		defer func() { _ = tr.Close() }()
		fn(t, tr)
	})
}

func TestMPTContract_KeyOrderingAndBounds(t *testing.T) {
	t.Run("MaxKeyLen_and_MaxValLen_constants", func(t *testing.T) {
		if torchmpt.MaxKeyLen != 1024 {
			t.Fatalf("MaxKeyLen = %d, want 1024", torchmpt.MaxKeyLen)
		}
		if torchmpt.MaxValLen != 1024 {
			t.Fatalf("MaxValLen = %d, want 1024", torchmpt.MaxValLen)
		}
	})

	t.Run("key_length_bounds_0_1_1024_1025", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			k0 := torchmpt.Key("")
			k1 := torchmpt.Key("a")
			k1023 := torchmpt.Key(strings.Repeat("b", 1023))
			k1024 := torchmpt.Key(strings.Repeat("b", 1024))
			k1024B := torchmpt.Key(strings.Repeat("b", 1023) + "c")
			k1025 := torchmpt.Key(strings.Repeat("d", 1025))

			// Predict enforces MaxKeyLen (1024) and MaxValLen (1024) with ErrInvalidPredict.
			_, err := tr.Predict([]torchmpt.KeyVal{{Key: k1025, Val: testVal("v1025")}})
			if !errors.Is(err, torchmpt.ErrInvalidPredict) {
				t.Fatalf("Predict(len(key)=1025) err = %v, want ErrInvalidPredict", err)
			}
			oversizedVal := make(torchmpt.Val, torchmpt.MaxValLen+1)
			_, err = tr.Predict([]torchmpt.KeyVal{{Key: k1, Val: oversizedVal}})
			if !errors.Is(err, torchmpt.ErrInvalidPredict) {
				t.Fatalf("Predict(len(val)=1025) err = %v, want ErrInvalidPredict", err)
			}

			// Valid keys from 0..1024 bytes work in Predict, Set, Snap, Path, ProveLookup, and Scan.
			validKVs := []torchmpt.KeyVal{
				{Key: k0, Val: testVal("v0")},
				{Key: k1, Val: testVal("v1")},
				{Key: k1023, Val: testVal("v1023")},
				{Key: k1024, Val: testVal("v1024")},
				{Key: k1024B, Val: testVal("v1024B")},
			}
			slices.SortFunc(validKVs, torchmpt.KeyVal.CompareKey)

			predHash, err := tr.Predict(validKVs)
			if err != nil {
				t.Fatalf("Predict(0..1024B keys) failed: %v", err)
			}
			for _, kv := range validKVs {
				if err := tr.Set(kv.Key, kv.Val); err != nil {
					t.Fatalf("Set(len=%d) failed: %v", len(kv.Key), err)
				}
			}
			snap, err := tr.Snap(1)
			if err != nil {
				t.Fatalf("Snap(1) failed: %v", err)
			}
			if snap.Hash != predHash {
				t.Fatalf("Snap.Hash %x != Predict %x", snap.Hash, predHash)
			}

			for _, kv := range validKVs {
				path, err := tr.Path(kv.Key)
				if err != nil {
					t.Fatalf("Path(len=%d) failed: %v", len(kv.Key), err)
				}
				gotVal, ok, proof, err := torchmpt.ProveLookup(kv.Key, path)
				if err != nil {
					t.Fatalf("ProveLookup(len=%d) failed: %v", len(kv.Key), err)
				}
				if !ok || !bytes.Equal(gotVal, kv.Val) {
					t.Fatalf("ProveLookup(len=%d) = (%x, %v), want (%x, true)", len(kv.Key), gotVal, ok, kv.Val)
				}
				if err := torchmpt.VerifyLookup(snap, kv.Key, gotVal, true, proof); err != nil {
					t.Fatalf("VerifyLookup(len=%d) failed: %v", len(kv.Key), err)
				}
			}
		})
	})

	t.Run("Compare_matches_bytes_Compare_for_NUL_free_ASCII", func(t *testing.T) {
		t.Parallel()
		keys := []torchmpt.Key{
			torchmpt.Key("com."),
			torchmpt.Key("com.goog."),
			torchmpt.Key("com.google."),
			torchmpt.Key("com.google.*."),
			torchmpt.Key("com.google.accounts."),
			torchmpt.Key("com.google.docs."),
			torchmpt.Key("com.google.mail."),
			torchmpt.Key("com.google.mail.*."),
			torchmpt.Key("com.google.mail.sub."),
			torchmpt.Key("com.googleapis."),
			torchmpt.Key("com.googleusercontent."),
			torchmpt.Key("github.com/google/go-cmp"),
			torchmpt.Key("github.com/google/uuid"),
			torchmpt.Key("github.com/googleapis/gax-go"),
			torchmpt.Key("org.example."),
		}

		// Verify pairwise agreement between Key.Compare and bytes.Compare on all NUL-free keys.
		for i, a := range keys {
			for j, b := range keys {
				got := a.Compare(b)
				want := bytes.Compare(a, b)
				if got != want {
					t.Fatalf("Key(%q).Compare(%q) [idx %d,%d] = %d, bytes.Compare = %d", a, b, i, j, got, want)
				}
			}
		}

		// Verify the input list is already in strictly ascending order.
		for i := 0; i < len(keys)-1; i++ {
			if keys[i].Compare(keys[i+1]) >= 0 {
				t.Fatalf("expected %q < %q", keys[i], keys[i+1])
			}
		}
	})

	t.Run("NUL_byte_violates_bytes_Compare_equivalence", func(t *testing.T) {
		t.Parallel()
		// Because torchwood/mpt pads a key of length L with 0x00 at index L followed by
		// infinite 0xFF bytes ("00 FF FF..."), a longer key containing 0x00 at index L
		// followed by any byte < 0xFF (or ending after 0x00 so its own padding puts 0x00 at L+1)
		// sorts BEFORE the shorter prefix key in Key.Compare, opposite to bytes.Compare!
		shortKey := torchmpt.Key("com.google.")
		nulKey := torchmpt.Key("com.google.\x00")
		nulChildKey := torchmpt.Key("com.google.\x00a")

		if bytes.Compare(shortKey, nulKey) >= 0 {
			t.Fatalf("expected bytes.Compare(%q, %q) < 0", shortKey, nulKey)
		}
		if shortKey.Compare(nulKey) <= 0 {
			t.Fatalf("expected Key(%q).Compare(%q) > 0 due to 00 FF FF... padding, got %d",
				shortKey, nulKey, shortKey.Compare(nulKey))
		}
		if shortKey.Compare(nulChildKey) <= 0 {
			t.Fatalf("expected Key(%q).Compare(%q) > 0 due to 00 FF FF... padding, got %d",
				shortKey, nulChildKey, shortKey.Compare(nulChildKey))
		}
	})

	t.Run("HasPrefix_semantics", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name   string
			key    torchmpt.Key
			prefix []byte
			want   bool
		}{
			{
				name:   "exact match",
				key:    torchmpt.Key("com.google."),
				prefix: []byte("com.google."),
				want:   true,
			},
			{
				name:   "child subdomain match",
				key:    torchmpt.Key("com.google.mail."),
				prefix: []byte("com.google."),
				want:   true,
			},
			{
				name:   "wildcard child match",
				key:    torchmpt.Key("com.google.*."),
				prefix: []byte("com.google."),
				want:   true,
			},
			{
				name:   "sibling sharing character prefix without dot boundary",
				key:    torchmpt.Key("com.googleapis."),
				prefix: []byte("com.google."),
				want:   false,
			},
			{
				name:   "shorter sibling prefix",
				key:    torchmpt.Key("com.goog."),
				prefix: []byte("com.google."),
				want:   false,
			},
			{
				name:   "key shorter than NUL-free prefix",
				key:    torchmpt.Key("com."),
				prefix: []byte("com.google."),
				want:   false,
			},
			{
				name:   "empty prefix nil",
				key:    torchmpt.Key("com.google."),
				prefix: nil,
				want:   true,
			},
			{
				name:   "empty prefix slice",
				key:    torchmpt.Key("com.google."),
				prefix: []byte{},
				want:   true,
			},
			{
				name:   "NUL-padded prefix matches shorter key due to 00 FF padding",
				key:    torchmpt.Key("com.google."),
				prefix: []byte("com.google.\x00\xff"),
				want:   true,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if got := tc.key.HasPrefix(tc.prefix); got != tc.want {
					t.Fatalf("Key(%q).HasPrefix(%q) = %v, want %v", tc.key, tc.prefix, got, tc.want)
				}
			})
		}
	})
}

func TestMPTContract_PointLookups(t *testing.T) {
	t.Run("empty_tree_non_inclusion", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			snap, err := tr.Snap(0)
			if err != nil {
				t.Fatalf("Snap(0) failed: %v", err)
			}
			if snap.Hash != torchmpt.EmptyTreeHash() {
				t.Fatalf("empty tree hash = %x, want %x", snap.Hash, torchmpt.EmptyTreeHash())
			}

			key := torchmpt.Key("com.google.")
			path, err := tr.Path(key)
			if err != nil {
				t.Fatalf("Path on empty tree failed: %v", err)
			}
			if path == nil || len(path) != 0 {
				t.Fatalf("Path on empty tree = %v (len %d), want non-nil empty Proof{}", path, len(path))
			}

			val, ok, proof, err := torchmpt.ProveLookup(key, path)
			if err != nil {
				t.Fatalf("ProveLookup on empty tree failed: %v", err)
			}
			if ok || val != nil || len(proof) != 0 {
				t.Fatalf("ProveLookup on empty tree = (%v, %v, %x), want (nil, false, empty)", val, ok, proof)
			}
			if err := torchmpt.VerifyLookup(snap, key, nil, false, proof); err != nil {
				t.Fatalf("VerifyLookup on empty tree failed: %v", err)
			}
			if err := torchmpt.VerifyNotPresent(snap, key, proof); err != nil {
				t.Fatalf("VerifyNotPresent on empty tree failed: %v", err)
			}
		})
	})

	t.Run("single_key_tree_inclusion_and_non_inclusion", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			onlyKey := torchmpt.Key("com.google.mail.")
			onlyVal := testVal("mail-val")
			if err := tr.Set(onlyKey, onlyVal); err != nil {
				t.Fatalf("Set failed: %v", err)
			}
			snap, err := tr.Snap(1)
			if err != nil {
				t.Fatalf("Snap failed: %v", err)
			}

			// Inclusion of the single key.
			path, err := tr.Path(onlyKey)
			if err != nil {
				t.Fatalf("Path(onlyKey) failed: %v", err)
			}
			gotVal, ok, proof, err := torchmpt.ProveLookup(onlyKey, path)
			if err != nil || !ok || !bytes.Equal(gotVal, onlyVal) {
				t.Fatalf("ProveLookup(onlyKey) = (%x, %v, %v), want (%x, true, nil)", gotVal, ok, err, onlyVal)
			}
			if err := torchmpt.VerifyLookup(snap, onlyKey, gotVal, true, proof); err != nil {
				t.Fatalf("VerifyLookup(onlyKey) failed: %v", err)
			}

			// Non-inclusion of shorter parent prefix key ("com.google.") and sibling ("com.googleapis.").
			for _, missing := range []torchmpt.Key{
				torchmpt.Key("com."),
				torchmpt.Key("com.google."),
				torchmpt.Key("com.google.mail.sub."),
				torchmpt.Key("com.googleapis."),
			} {
				mPath, err := tr.Path(missing)
				if err != nil {
					t.Fatalf("Path(%q) failed: %v", missing, err)
				}
				mVal, mOK, mProof, err := torchmpt.ProveLookup(missing, mPath)
				if err != nil || mOK || mVal != nil {
					t.Fatalf("ProveLookup(%q) = (%x, %v, %v), want (nil, false, nil)", missing, mVal, mOK, err)
				}
				if err := torchmpt.VerifyLookup(snap, missing, nil, false, mProof); err != nil {
					t.Fatalf("VerifyLookup(%q, ok=false) failed: %v", missing, err)
				}
			}
		})
	})

	t.Run("coexisting_parent_prefix_and_child_keys_plus_adversarial_checks", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			entries := []struct {
				key string
				val torchmpt.Val
			}{
				{"com.goog.", testVal("goog")},
				{"com.google.", testVal("google-apex")},
				{"com.google.*.", testVal("google-wildcard")},
				{"com.google.docs.", testVal("google-docs")},
				{"com.google.mail.", testVal("google-mail")},
				{"com.google.mail.*.", testVal("google-mail-wildcard")},
				{"com.googleapis.", testVal("googleapis")},
				{"org.example.", testVal("example")},
			}

			for _, e := range entries {
				if err := tr.Set(torchmpt.Key(e.key), e.val); err != nil {
					t.Fatalf("Set(%q) failed: %v", e.key, err)
				}
			}

			// Calling Path before Snap on a modified tree must return ErrModifiedTree.
			if _, err := tr.Path(torchmpt.Key("com.google.")); !errors.Is(err, torchmpt.ErrModifiedTree) {
				t.Fatalf("Path before Snap err = %v, want ErrModifiedTree", err)
			}

			snap, err := tr.Snap(1)
			if err != nil {
				t.Fatalf("Snap(1) failed: %v", err)
			}

			// 1. Verify inclusion of all inserted keys (confirming parent "com.google." and children coexist).
			for _, e := range entries {
				k := torchmpt.Key(e.key)
				path, err := tr.Path(k)
				if err != nil {
					t.Fatalf("Path(%q) failed: %v", e.key, err)
				}
				gotVal, ok, proof, err := torchmpt.ProveLookup(k, path)
				if err != nil {
					t.Fatalf("ProveLookup(%q) failed: %v", e.key, err)
				}
				if !ok || !bytes.Equal(gotVal, e.val) {
					t.Fatalf("ProveLookup(%q) = (%x, %v), want (%x, true)", e.key, gotVal, ok, e.val)
				}
				if err := torchmpt.VerifyLookup(snap, k, gotVal, true, proof); err != nil {
					t.Fatalf("VerifyLookup(%q) inclusion failed: %v", e.key, err)
				}
				if err := torchmpt.VerifyPresent(snap, k, gotVal, proof); err != nil {
					t.Fatalf("VerifyPresent(%q) failed: %v", e.key, err)
				}

				// Adversarial inclusion checks:
				// a) Mutated value
				badVal := slices.Clone(gotVal)
				badVal[0] ^= 0xff
				if err := torchmpt.VerifyLookup(snap, k, badVal, true, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
					t.Fatalf("VerifyLookup(%q) with mutated val err = %v, want ErrInvalidProof", e.key, err)
				}
				// b) Flipped ok (true -> false) with nil val
				if err := torchmpt.VerifyLookup(snap, k, nil, false, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
					t.Fatalf("VerifyLookup(%q) with flipped ok=false err = %v, want ErrInvalidProof", e.key, err)
				}
				// c) Non-empty val with ok=false -> ErrInvalidLookup
				if err := torchmpt.VerifyLookup(snap, k, gotVal, false, proof); !errors.Is(err, torchmpt.ErrInvalidLookup) {
					t.Fatalf("VerifyLookup(%q) with ok=false and non-nil val err = %v, want ErrInvalidLookup", e.key, err)
				}
				// d) Wrong key
				if err := torchmpt.VerifyLookup(snap, torchmpt.Key(e.key+"x"), gotVal, true, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
					t.Fatalf("VerifyLookup(%q) with wrong key err = %v, want ErrInvalidProof", e.key, err)
				}
				// e) Corrupted proof bytes
				if len(proof) > 0 {
					badProof := slices.Clone(proof)
					badProof[len(badProof)-1] ^= 0x01
					if err := torchmpt.VerifyLookup(snap, k, gotVal, true, badProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
						t.Fatalf("VerifyLookup(%q) with corrupted proof err = %v, want ErrInvalidProof", e.key, err)
					}
				}
			}

			// 2. Verify non-inclusion of missing parent, missing child, and missing sibling keys.
			missingKeys := []string{
				"com.",
				"com.google", // without trailing dot
				"com.google.chat.",
				"com.google.mail.chat.",
				"com.googlea.",
				"net.example.",
			}
			for _, mk := range missingKeys {
				k := torchmpt.Key(mk)
				path, err := tr.Path(k)
				if err != nil {
					t.Fatalf("Path(%q) failed: %v", mk, err)
				}
				gotVal, ok, proof, err := torchmpt.ProveLookup(k, path)
				if err != nil {
					t.Fatalf("ProveLookup(%q) failed: %v", mk, err)
				}
				if ok || gotVal != nil {
					t.Fatalf("ProveLookup(%q) = (%x, %v), want (nil, false)", mk, gotVal, ok)
				}
				if err := torchmpt.VerifyLookup(snap, k, nil, false, proof); err != nil {
					t.Fatalf("VerifyLookup(%q) non-inclusion failed: %v", mk, err)
				}

				// Adversarial non-inclusion checks:
				// a) Claiming ok=true with non-inclusion proof
				if err := torchmpt.VerifyLookup(snap, k, testVal("fake"), true, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
					t.Fatalf("VerifyLookup(%q) with flipped ok=true err = %v, want ErrInvalidProof", mk, err)
				}
				// b) Empty proof on non-empty snapshot
				if err := torchmpt.VerifyLookup(snap, k, nil, false, torchmpt.Proof{}); !errors.Is(err, torchmpt.ErrInvalidProof) {
					t.Fatalf("VerifyLookup(%q) with empty proof on non-empty tree err = %v, want ErrInvalidProof", mk, err)
				}
			}
		})
	})
}

func TestMPTContract_PrefixLookups(t *testing.T) {
	t.Run("multi_key_prefix_subtree_and_soundness", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			allKVs := []torchmpt.KeyVal{
				{Key: torchmpt.Key("com.goog."), Val: testVal("goog")},
				{Key: torchmpt.Key("com.google."), Val: testVal("google-apex")},
				{Key: torchmpt.Key("com.google.*."), Val: testVal("google-wildcard")},
				{Key: torchmpt.Key("com.google.docs."), Val: testVal("google-docs")},
				{Key: torchmpt.Key("com.google.mail."), Val: testVal("google-mail")},
				{Key: torchmpt.Key("com.googleapis."), Val: testVal("googleapis")},
				{Key: torchmpt.Key("org.example."), Val: testVal("example")},
			}
			for _, kv := range allKVs {
				if err := tr.Set(kv.Key, kv.Val); err != nil {
					t.Fatalf("Set(%q) failed: %v", kv.Key, err)
				}
			}
			snap, err := tr.Snap(1)
			if err != nil {
				t.Fatalf("Snap(1) failed: %v", err)
			}

			prefix := []byte("com.google.")
			wantKeys := []string{
				"com.google.",
				"com.google.*.",
				"com.google.docs.",
				"com.google.mail.",
			}

			// 1. Scan(prefix) yields keys in strictly ascending Key.Compare order.
			var scanned []torchmpt.KeyVal
			for kv, err := range tr.Scan(prefix) {
				if err != nil {
					t.Fatalf("Scan(%q) error: %v", prefix, err)
				}
				scanned = append(scanned, torchmpt.KeyVal{
					Key: kv.Key.Clone(),
					Val: kv.Val.Clone(),
				})
			}
			if len(scanned) != len(wantKeys) {
				t.Fatalf("Scan(%q) returned %d keys, want %d", prefix, len(scanned), len(wantKeys))
			}
			for i, kv := range scanned {
				if string(kv.Key) != wantKeys[i] {
					t.Fatalf("Scan(%q)[%d].Key = %q, want %q", prefix, i, kv.Key, wantKeys[i])
				}
				if !kv.Key.HasPrefix(prefix) {
					t.Fatalf("Scan(%q) yielded key %q without prefix", prefix, kv.Key)
				}
				if i > 0 && scanned[i-1].Key.Compare(kv.Key) >= 0 {
					t.Fatalf("Scan(%q) keys not strictly increasing at %d: %q >= %q", prefix, i, scanned[i-1].Key, kv.Key)
				}
			}

			// 2. TreeHash over scanned slice and TreeHashErr over Scan iterator match ProvePrefix.
			clientSubtreeHash := torchmpt.TreeHash(slices.Values(scanned))
			iterSubtreeHash, err := torchmpt.TreeHashErr(tr.Scan(prefix))
			if err != nil {
				t.Fatalf("TreeHashErr(Scan(%q)) failed: %v", prefix, err)
			}
			if clientSubtreeHash != iterSubtreeHash {
				t.Fatalf("TreeHash(%x) != TreeHashErr(%x)", clientSubtreeHash, iterSubtreeHash)
			}

			path, err := tr.Path(prefix)
			if err != nil {
				t.Fatalf("Path(%q) failed: %v", prefix, err)
			}
			proverSubtreeHash, proof, err := torchmpt.ProvePrefix(prefix, path)
			if err != nil {
				t.Fatalf("ProvePrefix(%q) failed: %v", prefix, err)
			}
			if proverSubtreeHash != clientSubtreeHash {
				t.Fatalf("ProvePrefix hash %x != client TreeHash %x", proverSubtreeHash, clientSubtreeHash)
			}
			if err := torchmpt.VerifyPrefix(snap, prefix, clientSubtreeHash, proof); err != nil {
				t.Fatalf("VerifyPrefix(%q) failed: %v", prefix, err)
			}

			// 3. Soundness Check A: Omitting 1 matching key from the scanned set fed to TreeHash MUST fail VerifyPrefix.
			for omitIdx := range scanned {
				partial := make([]torchmpt.KeyVal, 0, len(scanned)-1)
				for i, kv := range scanned {
					if i != omitIdx {
						partial = append(partial, kv)
					}
				}
				partialHash := torchmpt.TreeHash(slices.Values(partial))
				if err := torchmpt.VerifyPrefix(snap, prefix, partialHash, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
					t.Fatalf("VerifyPrefix succeeded when omitting key %q (idx %d): err = %v", scanned[omitIdx].Key, omitIdx, err)
				}
			}

			// 4. Soundness Check B: Server proving a narrower sub-prefix ("com.google.mail.") cannot verify for "com.google.".
			narrowPrefix := []byte("com.google.mail.")
			narrowPath, err := tr.Path(narrowPrefix)
			if err != nil {
				t.Fatalf("Path(%q) failed: %v", narrowPrefix, err)
			}
			narrowHash, narrowProof, err := torchmpt.ProvePrefix(narrowPrefix, narrowPath)
			if err != nil {
				t.Fatalf("ProvePrefix(%q) failed: %v", narrowPrefix, err)
			}
			if err := torchmpt.VerifyPrefix(snap, prefix, narrowHash, narrowProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyPrefix(%q) with narrower subtree proof for %q err = %v, want ErrInvalidProof", prefix, narrowPrefix, err)
			}

			// 5. Soundness Check C: Adding an extra key or mutating a value in scanned set MUST fail VerifyPrefix.
			withExtra := slices.Clone(scanned)
			withExtra = append(withExtra, torchmpt.KeyVal{
				Key: torchmpt.Key("com.google.zzz."),
				Val: testVal("extra"),
			})
			slices.SortFunc(withExtra, torchmpt.KeyVal.CompareKey)
			extraHash := torchmpt.TreeHash(slices.Values(withExtra))
			if err := torchmpt.VerifyPrefix(snap, prefix, extraHash, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyPrefix with extra key err = %v, want ErrInvalidProof", err)
			}

			mutatedValSet := slices.Clone(scanned)
			mutatedValSet[0].Val = testVal("tampered-val")
			mutatedHash := torchmpt.TreeHash(slices.Values(mutatedValSet))
			if err := torchmpt.VerifyPrefix(snap, prefix, mutatedHash, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyPrefix with mutated value err = %v, want ErrInvalidProof", err)
			}

			// 6. Soundness Check D (One-Sided Ancestor Subtree Attack from PREFIX_LOOKUPS.md §2.4.2):
			// If a malicious server proves parent prefix "com." instead of "com.google." and returns all "com.*" keys:
			parentPrefix := []byte("com.")
			parentPath, err := tr.Path(parentPrefix)
			if err != nil {
				t.Fatalf("Path(%q) failed: %v", parentPrefix, err)
			}
			parentHash, parentProof, err := torchmpt.ProvePrefix(parentPrefix, parentPath)
			if err != nil {
				t.Fatalf("ProvePrefix(%q) failed: %v", parentPrefix, err)
			}

			// VerifyPrefix ALONE is one-sided: it accepts (parentHash, parentProof) as a valid proof for "com.google."!
			if err := torchmpt.VerifyPrefix(snap, prefix, parentHash, parentProof); err != nil {
				t.Fatalf("expected one-sided VerifyPrefix to accept ancestor 'com.' subtree for 'com.google.', got: %v", err)
			}

			// Confirm that the client-side HasPrefix check catches the out-of-prefix keys in the "com." scan:
			var parentScanned []torchmpt.KeyVal
			hasOutOfPrefixKey := false
			for kv, err := range tr.Scan(parentPrefix) {
				if err != nil {
					t.Fatalf("Scan(%q) failed: %v", parentPrefix, err)
				}
				if !kv.Key.HasPrefix(prefix) {
					hasOutOfPrefixKey = true
				}
				parentScanned = append(parentScanned, torchmpt.KeyVal{Key: kv.Key.Clone(), Val: kv.Val.Clone()})
			}
			if !hasOutOfPrefixKey {
				t.Fatal("expected parentScan('com.') to include keys failing HasPrefix('com.google.')")
			}

			// And if the server strips the out-of-prefix keys ("com.goog.", "com.googleapis.") to evade HasPrefix
			// while still sending parentProof, then TreeHash(scanned) != parentHash, so VerifyPrefix FAILS!
			if err := torchmpt.VerifyPrefix(snap, prefix, clientSubtreeHash, parentProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyPrefix with filtered keys and parentProof err = %v, want ErrInvalidProof", err)
			}
		})
	})

	t.Run("single_key_prefix_match_longer_and_exact", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			mailKey := torchmpt.Key("com.google.mail.")
			mailVal := testVal("mail")
			otherKey := torchmpt.Key("org.example.")
			otherVal := testVal("example")

			if err := tr.Set(mailKey, mailVal); err != nil {
				t.Fatalf("Set(mailKey) failed: %v", err)
			}
			if err := tr.Set(otherKey, otherVal); err != nil {
				t.Fatalf("Set(otherKey) failed: %v", err)
			}
			snap, err := tr.Snap(1)
			if err != nil {
				t.Fatalf("Snap(1) failed: %v", err)
			}

			// Case A: Single matching key ("com.google.mail.") is strictly longer than prefix ("com.google.").
			prefixA := []byte("com.google.")
			pathA, err := tr.Path(prefixA)
			if err != nil {
				t.Fatalf("Path(%q) failed: %v", prefixA, err)
			}
			hashA, proofA, err := torchmpt.ProvePrefix(prefixA, pathA)
			if err != nil {
				t.Fatalf("ProvePrefix(%q) failed: %v", prefixA, err)
			}
			scanHashA, err := torchmpt.TreeHashErr(tr.Scan(prefixA))
			if err != nil {
				t.Fatalf("TreeHashErr(Scan(%q)) failed: %v", prefixA, err)
			}
			if hashA != scanHashA {
				t.Fatalf("Case A: ProvePrefix hash %x != scan TreeHash %x", hashA, scanHashA)
			}
			if err := torchmpt.VerifyPrefix(snap, prefixA, scanHashA, proofA); err != nil {
				t.Fatalf("Case A: VerifyPrefix(%q) failed: %v", prefixA, err)
			}

			// Case B: Single matching key ("com.google.mail.") equals prefix ("com.google.mail.").
			prefixB := []byte("com.google.mail.")
			pathB, err := tr.Path(prefixB)
			if err != nil {
				t.Fatalf("Path(%q) failed: %v", prefixB, err)
			}
			hashB, proofB, err := torchmpt.ProvePrefix(prefixB, pathB)
			if err != nil {
				t.Fatalf("ProvePrefix(%q) failed: %v", prefixB, err)
			}
			scanHashB, err := torchmpt.TreeHashErr(tr.Scan(prefixB))
			if err != nil {
				t.Fatalf("TreeHashErr(Scan(%q)) failed: %v", prefixB, err)
			}
			if hashB != scanHashB || hashB != hashA {
				t.Fatalf("Case B: hashB %x != scanHashB %x or hashA %x", hashB, scanHashB, hashA)
			}
			if err := torchmpt.VerifyPrefix(snap, prefixB, scanHashB, proofB); err != nil {
				t.Fatalf("Case B: VerifyPrefix(%q) failed: %v", prefixB, err)
			}
		})
	})

	t.Run("zero_key_prefix_match_empty_and_populated_trees", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			// 1. Empty tree: prefix query returns 0 items, EmptyTreeHash(), empty proof, and verifies.
			emptySnap, err := tr.Snap(0)
			if err != nil {
				t.Fatalf("Snap(0) failed: %v", err)
			}
			prefix := []byte("com.google.")
			emptyPath, err := tr.Path(prefix)
			if err != nil {
				t.Fatalf("Path on empty tree failed: %v", err)
			}
			emptySubtreeHash, emptyProof, err := torchmpt.ProvePrefix(prefix, emptyPath)
			if err != nil {
				t.Fatalf("ProvePrefix on empty tree failed: %v", err)
			}
			if emptySubtreeHash != torchmpt.EmptyTreeHash() || len(emptyProof) != 0 {
				t.Fatalf("ProvePrefix on empty tree = (%x, %x), want (EmptyTreeHash, empty)", emptySubtreeHash, emptyProof)
			}
			scanHash, err := torchmpt.TreeHashErr(tr.Scan(prefix))
			if err != nil || scanHash != torchmpt.EmptyTreeHash() {
				t.Fatalf("TreeHashErr(Scan) on empty tree = (%x, %v), want (EmptyTreeHash, nil)", scanHash, err)
			}
			if err := torchmpt.VerifyPrefix(emptySnap, prefix, scanHash, emptyProof); err != nil {
				t.Fatalf("VerifyPrefix on empty tree failed: %v", err)
			}

			// 2. Populated tree: non-existent prefixes ("com.nonexistent." and "com.google.chat.").
			for _, k := range []string{"com.google.", "com.google.mail.", "org.example."} {
				if err := tr.Set(torchmpt.Key(k), testVal(k)); err != nil {
					t.Fatalf("Set(%q) failed: %v", k, err)
				}
			}
			snap, err := tr.Snap(1)
			if err != nil {
				t.Fatalf("Snap(1) failed: %v", err)
			}

			for _, missingPrefix := range [][]byte{
				[]byte("com.nonexistent."),
				[]byte("com.google.chat."),
				[]byte("net."),
			} {
				var count int
				for _, err := range tr.Scan(missingPrefix) {
					if err != nil {
						t.Fatalf("Scan(%q) failed: %v", missingPrefix, err)
					}
					count++
				}
				if count != 0 {
					t.Fatalf("Scan(%q) count = %d, want 0", missingPrefix, count)
				}

				mScanHash, err := torchmpt.TreeHashErr(tr.Scan(missingPrefix))
				if err != nil || mScanHash != torchmpt.EmptyTreeHash() {
					t.Fatalf("TreeHashErr(Scan(%q)) = (%x, %v), want EmptyTreeHash", missingPrefix, mScanHash, err)
				}

				mPath, err := tr.Path(missingPrefix)
				if err != nil {
					t.Fatalf("Path(%q) failed: %v", missingPrefix, err)
				}
				mHash, mProof, err := torchmpt.ProvePrefix(missingPrefix, mPath)
				if err != nil {
					t.Fatalf("ProvePrefix(%q) failed: %v", missingPrefix, err)
				}
				if mHash != torchmpt.EmptyTreeHash() {
					t.Fatalf("ProvePrefix(%q) hash = %x, want EmptyTreeHash", missingPrefix, mHash)
				}
				if err := torchmpt.VerifyPrefix(snap, missingPrefix, mScanHash, mProof); err != nil {
					t.Fatalf("VerifyPrefix(%q, EmptyTreeHash) failed: %v", missingPrefix, err)
				}

				// Confirm that when 0 keys match prefix in a non-empty tree, ProvePrefix and ProveLookup share the exact same proof.
				_, ok, lookupProof, err := torchmpt.ProveLookup(torchmpt.Key(missingPrefix), mPath)
				if err != nil || ok || !bytes.Equal(lookupProof, mProof) {
					t.Fatalf("ProveLookup(%q) = (ok=%v, proof=%x), want (false, %x)", missingPrefix, ok, lookupProof, mProof)
				}
			}
		})
	})
}

func TestMPTContract_PredictAndPersistence(t *testing.T) {
	t.Run("Predict_variable_length_keys_insert_and_update", func(t *testing.T) {
		runBothTreeImpls(t, func(t *testing.T, tr torchmpt.Tree) {
			batch1 := []torchmpt.KeyVal{
				{Key: torchmpt.Key("com.google."), Val: testVal("v1-google")},
				{Key: torchmpt.Key("com.google.*."), Val: testVal("v1-wildcard")},
				{Key: torchmpt.Key("com.google.mail."), Val: testVal("v1-mail")},
				{Key: torchmpt.Key("com.googleapis."), Val: testVal("v1-googleapis")},
			}
			slices.SortFunc(batch1, torchmpt.KeyVal.CompareKey)

			pred1, err := tr.Predict(batch1)
			if err != nil {
				t.Fatalf("Predict(batch1) failed: %v", err)
			}
			for _, kv := range batch1 {
				if err := tr.Set(kv.Key, kv.Val); err != nil {
					t.Fatalf("Set(%q) failed: %v", kv.Key, err)
				}
			}
			// Predict before Snap on dirty tree must return ErrModifiedTree.
			if _, err := tr.Predict(batch1); !errors.Is(err, torchmpt.ErrModifiedTree) {
				t.Fatalf("Predict on dirty tree err = %v, want ErrModifiedTree", err)
			}

			snap1, err := tr.Snap(10)
			if err != nil {
				t.Fatalf("Snap(10) failed: %v", err)
			}
			if snap1.Hash != pred1 {
				t.Fatalf("snap1.Hash %x != pred1 %x", snap1.Hash, pred1)
			}

			// Batch 2: update existing keys ("com.google.", "com.google.mail.") + insert shorter ("com.") and longer ("com.google.mail.smtp.").
			batch2 := []torchmpt.KeyVal{
				{Key: torchmpt.Key("com."), Val: testVal("v2-com")},
				{Key: torchmpt.Key("com.google."), Val: testVal("v2-google-updated")},
				{Key: torchmpt.Key("com.google.mail."), Val: testVal("v2-mail-updated")},
				{Key: torchmpt.Key("com.google.mail.smtp."), Val: testVal("v2-smtp")},
			}
			slices.SortFunc(batch2, torchmpt.KeyVal.CompareKey)

			pred2, err := tr.Predict(batch2)
			if err != nil {
				t.Fatalf("Predict(batch2) failed: %v", err)
			}
			for _, kv := range batch2 {
				if err := tr.Set(kv.Key, kv.Val); err != nil {
					t.Fatalf("Set(%q) failed: %v", kv.Key, err)
				}
			}
			snap2, err := tr.Snap(20)
			if err != nil {
				t.Fatalf("Snap(20) failed: %v", err)
			}
			if snap2.Hash != pred2 {
				t.Fatalf("snap2.Hash %x != pred2 %x", snap2.Hash, pred2)
			}
		})
	})

	t.Run("Disk_Create_Sync_Close_Open_preserves_keys_proofs_and_version", func(t *testing.T) {
		dir := t.TempDir()
		f1 := filepath.Join(dir, "mpt.tree1")
		f2 := filepath.Join(dir, "mpt.tree2")
		fDisk := filepath.Join(dir, "mpt.disk")

		tr1, err := torchmpt.Create(f1, f2, fDisk)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		kvs := []torchmpt.KeyVal{
			{Key: torchmpt.Key("com.google."), Val: testVal("google-apex")},
			{Key: torchmpt.Key("com.google.*."), Val: testVal("google-wildcard")},
			{Key: torchmpt.Key("com.google.docs."), Val: testVal("google-docs")},
			{Key: torchmpt.Key("com.google.mail."), Val: testVal("google-mail")},
			{Key: torchmpt.Key("com.googleapis."), Val: testVal("googleapis")},
			{Key: torchmpt.Key("github.com/google/uuid"), Val: testVal("uuid")},
		}
		for _, kv := range kvs {
			if err := tr1.Set(kv.Key, kv.Val); err != nil {
				t.Fatalf("Set(%q) failed: %v", kv.Key, err)
			}
		}

		// Update an existing key in-place before Snap.
		updatedApexVal := testVal("google-apex-v2")
		kvs[0].Val = updatedApexVal
		if err := tr1.Set(kvs[0].Key, updatedApexVal); err != nil {
			t.Fatalf("Set(update apex) failed: %v", err)
		}

		snap1, err := tr1.Snap(42)
		if err != nil {
			t.Fatalf("Snap(42) failed: %v", err)
		}
		if err := tr1.Sync(); err != nil {
			t.Fatalf("Sync failed: %v", err)
		}
		if v, exact := tr1.Version(); v != 42 || !exact {
			t.Fatalf("Version after Snap(42)+Sync = (%d, %v), want (42, true)", v, exact)
		}
		if err := tr1.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Reopen with torchmpt.Open.
		tr2, err := torchmpt.Open(f1, f2, fDisk)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer func() { _ = tr2.Close() }()

		if v, exact := tr2.Version(); v != 42 || !exact {
			t.Fatalf("Reopened Version = (%d, %v), want (42, true)", v, exact)
		}
		snap2, err := tr2.Snap(-1)
		if err != nil {
			t.Fatalf("Reopened Snap(-1) failed: %v", err)
		}
		if snap2 != snap1 {
			t.Fatalf("Reopened Snap(-1) = %+v, want %+v", snap2, snap1)
		}

		// Verify point lookups on reopened disk tree.
		for _, kv := range kvs {
			path, err := tr2.Path(kv.Key)
			if err != nil {
				t.Fatalf("Reopened Path(%q) failed: %v", kv.Key, err)
			}
			gotVal, ok, proof, err := torchmpt.ProveLookup(kv.Key, path)
			if err != nil || !ok || !bytes.Equal(gotVal, kv.Val) {
				t.Fatalf("Reopened ProveLookup(%q) = (%x, %v, %v), want (%x, true, nil)", kv.Key, gotVal, ok, err, kv.Val)
			}
			if err := torchmpt.VerifyLookup(snap2, kv.Key, gotVal, true, proof); err != nil {
				t.Fatalf("Reopened VerifyLookup(%q) failed: %v", kv.Key, err)
			}
		}

		// Verify prefix scan & prefix proof on reopened disk tree.
		prefix := []byte("com.google.")
		path, err := tr2.Path(prefix)
		if err != nil {
			t.Fatalf("Reopened Path(%q) failed: %v", prefix, err)
		}
		subHash, proof, err := torchmpt.ProvePrefix(prefix, path)
		if err != nil {
			t.Fatalf("Reopened ProvePrefix(%q) failed: %v", prefix, err)
		}
		scanHash, err := torchmpt.TreeHashErr(tr2.Scan(prefix))
		if err != nil {
			t.Fatalf("Reopened TreeHashErr(Scan(%q)) failed: %v", prefix, err)
		}
		if subHash != scanHash {
			t.Fatalf("Reopened ProvePrefix hash %x != scanHash %x", subHash, scanHash)
		}
		if err := torchmpt.VerifyPrefix(snap2, prefix, scanHash, proof); err != nil {
			t.Fatalf("Reopened VerifyPrefix(%q) failed: %v", prefix, err)
		}
	})
}

func BenchmarkMPTContract_ProveLookup_VarKeys(b *testing.B) {
	tr := torchmpt.NewMemTree()
	defer func() { _ = tr.Close() }()

	const numKeys = 10000
	keys := make([]torchmpt.Key, numKeys)
	for i := range numKeys {
		keys[i] = torchmpt.Key(fmt.Sprintf("com.example.org-%03d.sub-%04d.", i%100, i))
		if err := tr.Set(keys[i], testVal(string(keys[i]))); err != nil {
			b.Fatalf("Set failed: %v", err)
		}
	}
	snap, err := tr.Snap(1)
	if err != nil {
		b.Fatalf("Snap failed: %v", err)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		k := keys[i%numKeys]
		path, err := tr.Path(k)
		if err != nil {
			b.Fatal(err)
		}
		val, ok, proof, err := torchmpt.ProveLookup(k, path)
		if err != nil || !ok {
			b.Fatalf("ProveLookup failed: ok=%v err=%v", ok, err)
		}
		if err := torchmpt.VerifyLookup(snap, k, val, ok, proof); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkMPTContract_ProveAndVerifyPrefix_100Subdomains(b *testing.B) {
	tr := torchmpt.NewMemTree()
	defer func() { _ = tr.Close() }()

	const numOrgs = 100
	const subsPerOrg = 100
	for org := range numOrgs {
		for sub := range subsPerOrg {
			k := torchmpt.Key(fmt.Sprintf("com.example-%03d.sub-%03d.", org, sub))
			if err := tr.Set(k, testVal(string(k))); err != nil {
				b.Fatalf("Set failed: %v", err)
			}
		}
	}
	snap, err := tr.Snap(1)
	if err != nil {
		b.Fatalf("Snap failed: %v", err)
	}
	prefix := []byte("com.example-042.")

	b.ReportAllocs()
	for b.Loop() {
		path, err := tr.Path(prefix)
		if err != nil {
			b.Fatal(err)
		}
		_, proof, err := torchmpt.ProvePrefix(prefix, path)
		if err != nil {
			b.Fatal(err)
		}
		subHash, err := torchmpt.TreeHashErr(tr.Scan(prefix))
		if err != nil {
			b.Fatal(err)
		}
		if err := torchmpt.VerifyPrefix(snap, prefix, subHash, proof); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMPTContract_Predict_100VarKeysIn10K(b *testing.B) {
	tr := torchmpt.NewMemTree()
	defer func() { _ = tr.Close() }()

	const numKeys = 10000
	for i := range numKeys {
		k := torchmpt.Key(fmt.Sprintf("com.example.org-%03d.sub-%04d.", i%100, i))
		if err := tr.Set(k, testVal(string(k))); err != nil {
			b.Fatalf("Set failed: %v", err)
		}
	}
	if _, err := tr.Snap(1); err != nil {
		b.Fatalf("Snap failed: %v", err)
	}

	changes := make([]torchmpt.KeyVal, 100)
	for i := range 100 {
		k := torchmpt.Key(fmt.Sprintf("com.example.org-%03d.sub-%04d.", i, i*50))
		changes[i] = torchmpt.KeyVal{Key: k, Val: testVal(fmt.Sprintf("updated-%d", i))}
	}
	slices.SortFunc(changes, torchmpt.KeyVal.CompareKey)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := tr.Predict(changes); err != nil {
			b.Fatal(err)
		}
	}
}
