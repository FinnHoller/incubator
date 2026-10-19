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

package kvstore

import (
	"bytes"
	"crypto/sha256"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestChunkKey_InvertedOrdering(t *testing.T) {
	var keyHash [32]byte
	copy(keyHash[:], []byte("deterministic_test_key_hash_32B!"))

	chunk0Key := EncodeChunkKey(keyHash, 0)
	chunk1Key := EncodeChunkKey(keyHash, 1)
	chunk10Key := EncodeChunkKey(keyHash, 10)
	chunkMaxKey := EncodeChunkKey(keyHash, math.MaxUint64)

	// Due to bitwise inversion ^chunkNum, higher chunk numbers sort BEFORE lower chunk numbers.
	if bytes.Compare(chunk1Key, chunk0Key) >= 0 {
		t.Fatalf("expected chunk 1 to sort before chunk 0, got cmp = %d", bytes.Compare(chunk1Key, chunk0Key))
	}
	if bytes.Compare(chunk10Key, chunk1Key) >= 0 {
		t.Fatalf("expected chunk 10 to sort before chunk 1, got cmp = %d", bytes.Compare(chunk10Key, chunk1Key))
	}
	if bytes.Compare(chunkMaxKey, chunk10Key) >= 0 {
		t.Fatalf("expected chunk Max to sort before chunk 10, got cmp = %d", bytes.Compare(chunkMaxKey, chunk10Key))
	}
}

func TestChunkKey_EncodeDecodeRoundtrip(t *testing.T) {
	keyHash := sha256.Sum256([]byte("example_key_1"))

	testCases := []uint64{0, 1, 2, 42, 65535, 65536, 1 << 30, math.MaxUint64}
	for _, chunkNum := range testCases {
		enc := EncodeChunkKey(keyHash, chunkNum)
		if len(enc) != 41 {
			t.Fatalf("encoded key length = %d, want 41", len(enc))
		}
		decHash, decChunkNum, err := DecodeChunkKey(enc)
		if err != nil {
			t.Fatalf("DecodeChunkKey error for chunk %d: %v", chunkNum, err)
		}
		if decHash != keyHash {
			t.Fatalf("decoded keyHash mismatch: got %x, want %x", decHash, keyHash)
		}
		if decChunkNum != chunkNum {
			t.Fatalf("decoded chunkNum mismatch: got %d, want %d", decChunkNum, chunkNum)
		}
	}

	// Invalid keys
	if _, _, err := DecodeChunkKey([]byte("too_short")); err == nil {
		t.Fatal("expected error for short key")
	}
	invalidPrefixKey := EncodeChunkKey(keyHash, 0)
	invalidPrefixKey[0] = 'x'
	if _, _, err := DecodeChunkKey(invalidPrefixKey); err == nil {
		t.Fatal("expected error for non-'c' prefix key")
	}
}

func TestChunkValue_DelimitlessRoundtrip(t *testing.T) {
	testCases := []struct {
		name string
		rec  *ChunkRecord
	}{
		{
			name: "empty_record",
			rec: &ChunkRecord{
				Preceding:       0,
				CompactRange:    nil,
				RelativeIndices: nil,
			},
		},
		{
			name: "single_hash_and_indices",
			rec: &ChunkRecord{
				Preceding: 1, // 1 compact hash
				CompactRange: [][32]byte{
					sha256.Sum256([]byte("h0")),
				},
				RelativeIndices: []uint16{0, 5, 42, 65535},
			},
		},
		{
			name: "multi_hashes_and_indices",
			rec: &ChunkRecord{
				Preceding: 7, // 7 = 4 + 2 + 1 -> 3 compact hashes
				CompactRange: [][32]byte{
					sha256.Sum256([]byte("h0_3")),
					sha256.Sum256([]byte("h4_5")),
					sha256.Sum256([]byte("h6")),
				},
				RelativeIndices: []uint16{1, 2, 3, 100, 200, 300, 65534},
			},
		},
		{
			name: "max_chunk_size",
			rec: &ChunkRecord{
				Preceding: 65536, // 65536 = 1 hash (2^16)
				CompactRange: [][32]byte{
					sha256.Sum256([]byte("full_chunk_0")),
				},
				RelativeIndices: []uint16{0, 1, 2, 3, 65535},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := MarshalChunkValue(tc.rec)
			got, err := UnmarshalChunkValue(b)
			if err != nil {
				t.Fatalf("UnmarshalChunkValue failed: %v", err)
			}

			if diff := cmp.Diff(tc.rec, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("ChunkRecord mismatch (-want +got):\n%s", diff)
			}
		})
	}

	// Malformed value tests
	if _, err := UnmarshalChunkValue([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for data < 8 bytes")
	}

	// Preceding = 1 expects 8 + 32 = 40 bytes minimum
	badData := make([]byte, 20)
	badData[7] = 1 // Preceding = 1
	if _, err := UnmarshalChunkValue(badData); err == nil {
		t.Fatal("expected error for truncated compact range")
	}

	// Odd number of trailing bytes for relative indices
	oddData := make([]byte, 8+1)
	if _, err := UnmarshalChunkValue(oddData); err == nil {
		t.Fatal("expected error for odd relative indices bytes")
	}
}

func BenchmarkMarshalChunkValue(b *testing.B) {
	rec := &ChunkRecord{
		Preceding: 7,
		CompactRange: [][32]byte{
			sha256.Sum256([]byte("h0")),
			sha256.Sum256([]byte("h1")),
			sha256.Sum256([]byte("h2")),
		},
		RelativeIndices: make([]uint16, 256),
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = MarshalChunkValue(rec)
	}
}

func BenchmarkMarshalChunkValueInto(b *testing.B) {
	rec := &ChunkRecord{
		Preceding: 7,
		CompactRange: [][32]byte{
			sha256.Sum256([]byte("h0")),
			sha256.Sum256([]byte("h1")),
			sha256.Sum256([]byte("h2")),
		},
		RelativeIndices: make([]uint16, 256),
	}
	buf := make([]byte, 8+32*3+2*256)
	b.ReportAllocs()
	for b.Loop() {
		buf = MarshalChunkValueInto(buf, rec)
	}
}

func TestChunkKeyInto_And_ChunkValueInto(t *testing.T) {
	keyHash := sha256.Sum256([]byte("buffer_test_key"))
	var keyBuf [41]byte
	k := EncodeChunkKeyInto(&keyBuf, keyHash, 123)
	h, c, err := DecodeChunkKey(k)
	if err != nil || h != keyHash || c != 123 {
		t.Fatalf("DecodeChunkKey failed: %v, %x, %d", err, h, c)
	}

	var prefixBuf [33]byte
	p := EncodeChunkPrefixInto(&prefixBuf, keyHash)
	if len(p) != 33 || p[0] != PrefixChunkByte || !bytes.Equal(p[1:], keyHash[:]) {
		t.Fatalf("EncodeChunkPrefixInto mismatch: %x", p)
	}

	rec := &ChunkRecord{
		Preceding:       3,
		CompactRange:    [][32]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))},
		RelativeIndices: []uint16{1, 5, 9},
	}
	val := MarshalChunkValueInto(nil, rec)
	got, err := UnmarshalChunkValue(val)
	if err != nil {
		t.Fatalf("UnmarshalChunkValue failed: %v", err)
	}
	if diff := cmp.Diff(rec, got, cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
}

