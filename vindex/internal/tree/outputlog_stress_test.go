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

package tree

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	mathrand "math/rand"
	"strings"
	"testing"

	"github.com/transparency-dev/formats/log"
)

func TestParseOutputLogLeaf_StressEdgeCases(t *testing.T) {
	validMPTRoot := sha256.Sum256([]byte("stress_test_root"))
	validRootB64 := base64.StdEncoding.EncodeToString(validMPTRoot[:])
	lowerHexRoot := hex.EncodeToString(validMPTRoot[:])
	upperHexRoot := strings.ToUpper(lowerHexRoot)

	makeLeaf := func(origin string, from, inputSize uint64, inRootB64, mptRootB64 string) []byte {
		return []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin %s\nfrom %d\ninput-size %d\ninput-root %s\nmpt-root %s\n",
			origin, from, inputSize, inRootB64, mptRootB64))
	}

	validHashB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	validHashHex := hex.EncodeToString(make([]byte, 32))

	t.Run("nil_and_empty", func(t *testing.T) {
		inputs := [][]byte{
			nil,
			{},
			[]byte(""),
		}
		for i, in := range inputs {
			_, _, err := ParseOutputLogLeaf(in)
			if err == nil {
				t.Fatalf("[%d] expected error for nil/empty input, got nil", i)
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("[%d] expected ErrOutputLogCorrupted, got %v", i, err)
			}
		}
	})

	t.Run("whitespace_variations", func(t *testing.T) {
		corruptedWhitespace := [][]byte{
			[]byte(" "),
			[]byte("   "),
			[]byte("\t\t"),
			[]byte("\n"),
			[]byte("\r\n"),
			[]byte("\n\n\n"),
			[]byte("  \t \r\n \n \t  "),
			[]byte(lowerHexRoot + "   "),
			[]byte(lowerHexRoot + "\t"),
			[]byte(lowerHexRoot + "\n\n\n"),
			[]byte(lowerHexRoot + "\r\n"),
			[]byte(lowerHexRoot + "\n   \t  \n"),
		}
		for i, in := range corruptedWhitespace {
			_, _, err := ParseOutputLogLeaf(in)
			if err == nil {
				t.Fatalf("[%d] expected error for whitespace-only leaf %q, got nil", i, string(in))
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("[%d] expected ErrOutputLogCorrupted, got %v", i, err)
			}
		}
	})

	t.Run("single_line_malformed", func(t *testing.T) {
		singleLines := [][]byte{
			[]byte("not_even_hex"),
			[]byte("deadbeef"),
			[]byte(lowerHexRoot),
			[]byte(upperHexRoot),
			[]byte("a" + lowerHexRoot),
		}
		for i, in := range singleLines {
			_, _, err := ParseOutputLogLeaf(in)
			if err == nil {
				t.Fatalf("[%d] expected error for single line input %q, got nil", i, string(in))
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("[%d] expected ErrOutputLogCorrupted, got %v", i, err)
			}
		}
	})

	t.Run("canonical_base64_formatting", func(t *testing.T) {
		parsedLeaf, err := ParseOutputLogLeafFull(makeLeaf("example.com/log", 0, 12345, validRootB64, validRootB64))
		if err != nil {
			t.Fatalf("ParseOutputLogLeafFull failed: %v", err)
		}
		if parsedLeaf.MPTRoot != validMPTRoot {
			t.Fatalf("MPTRoot mismatch: got %x, want %x", parsedLeaf.MPTRoot, validMPTRoot)
		}
		if parsedLeaf.InputRoot != validMPTRoot {
			t.Fatalf("InputRoot mismatch: got %x, want %x", parsedLeaf.InputRoot, validMPTRoot)
		}
		if parsedLeaf.InCP.Size != 12345 {
			t.Fatalf("inCP.Size mismatch: got %d, want 12345", parsedLeaf.InCP.Size)
		}

		reformatted := FormatOutputLogLeafFull(parsedLeaf.MPTRoot, parsedLeaf.From, parsedLeaf.InCP)
		expected := fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size 12345\ninput-root %s\nmpt-root %s\n",
			validRootB64, validRootB64)
		if string(reformatted) != expected {
			t.Fatalf("reformatted leaf mismatch:\ngot:\n%q\nwant:\n%q", string(reformatted), expected)
		}
	})

	t.Run("embedded_nulls", func(t *testing.T) {
		nullInRoot := makeLeaf("example.com/log", 0, 1234, validHashB64, validRootB64[:10]+"\x00"+validRootB64[11:])
		if _, _, err := ParseOutputLogLeaf(nullInRoot); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for null in mpt-root line, got %v", err)
		}

		nullInOrigin := makeLeaf("example.com/\x00log", 0, 1234, validHashB64, validRootB64)
		if _, _, err := ParseOutputLogLeaf(nullInOrigin); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for null in input-origin, got %v", err)
		}

		nullInHash := makeLeaf("example.com/log", 0, 1234, validHashB64[:10]+"\x00"+validHashB64[11:], validRootB64)
		if _, _, err := ParseOutputLogLeaf(nullInHash); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for null in input-root, got %v", err)
		}
	})

	t.Run("input_size_boundaries", func(t *testing.T) {
		leafZero := makeLeaf("example.com/log", 0, 0, validHashB64, validRootB64)
		_, cpZero, err := ParseOutputLogLeaf(leafZero)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for size 0: %v", err)
		}
		if cpZero.Size != 0 {
			t.Fatalf("cpZero.Size = %d, want 0", cpZero.Size)
		}

		leafMax := makeLeaf("example.com/log", 0, math.MaxUint64, validHashB64, validRootB64)
		_, cpMax, err := ParseOutputLogLeaf(leafMax)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for size MaxUint64: %v", err)
		}
		if cpMax.Size != math.MaxUint64 {
			t.Fatalf("cpMax.Size = %d, want %d", cpMax.Size, uint64(math.MaxUint64))
		}

		leafOverflow := []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size 18446744073709551616\ninput-root %s\nmpt-root %s\n", validHashB64, validRootB64))
		if _, _, err := ParseOutputLogLeaf(leafOverflow); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for uint64 overflow, got %v", err)
		}

		leafNeg := []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size -1\ninput-root %s\nmpt-root %s\n", validHashB64, validRootB64))
		if _, _, err := ParseOutputLogLeaf(leafNeg); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for negative size, got %v", err)
		}
	})

	t.Run("hash_encodings", func(t *testing.T) {
		leafB64 := makeLeaf("example.com/log", 0, 100, validHashB64, validRootB64)
		_, cpB64, err := ParseOutputLogLeaf(leafB64)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for base64 hash: %v", err)
		}
		if len(cpB64.Hash) != 32 {
			t.Fatalf("cpB64.Hash len = %d, want 32", len(cpB64.Hash))
		}

		leafHex := makeLeaf("example.com/log", 0, 100, validHashHex, validRootB64)
		if _, _, err := ParseOutputLogLeaf(leafHex); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for hex input-root hash, got %v", err)
		}

		leafShortHash := makeLeaf("example.com/log", 0, 100, "aGFzaA==", validRootB64)
		if _, _, err := ParseOutputLogLeaf(leafShortHash); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for short base64 hash, got %v", err)
		}
	})
}

func TestDifferentialFuzzing_Roundtrip(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(133742))

	for i := 0; i < 2000; i++ {
		var mptRoot [sha256.Size]byte
		_, _ = rand.Read(mptRoot[:])

		origin := fmt.Sprintf("origin-%d.example.com", rng.Intn(10000))
		size := rng.Uint64()
		var hash [sha256.Size]byte
		_, _ = rand.Read(hash[:])

		inCP := &log.Checkpoint{
			Origin: origin,
			Size:   size,
			Hash:   hash[:],
		}
		formatted := FormatOutputLogLeaf(mptRoot, inCP)

		parsedRoot, parsedCP, err := ParseOutputLogLeaf(formatted)
		if err != nil {
			t.Fatalf("iteration %d: ParseOutputLogLeaf failed on valid generated leaf: %v", i, err)
		}
		if parsedRoot != mptRoot {
			t.Fatalf("iteration %d: mptRoot mismatch: got %x, want %x", i, parsedRoot, mptRoot)
		}
		if parsedCP.Origin != origin {
			t.Fatalf("iteration %d: origin mismatch: got %q, want %q", i, parsedCP.Origin, origin)
		}
		if parsedCP.Size != size {
			t.Fatalf("iteration %d: size mismatch: got %d, want %d", i, parsedCP.Size, size)
		}
		if !bytes.Equal(parsedCP.Hash, hash[:]) {
			t.Fatalf("iteration %d: hash mismatch: got %x, want %x", i, parsedCP.Hash, hash[:])
		}

		reformatted := FormatOutputLogLeaf(parsedRoot, parsedCP)
		if !bytes.Equal(reformatted, formatted) {
			t.Fatalf("iteration %d: roundtrip non-idempotent:\ngot:\n%s\nwant:\n%s", i, string(reformatted), string(formatted))
		}
	}
}

func TestDifferentialFuzzing_Mutations(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(987654))

	baseMPTRoot := sha256.Sum256([]byte("fuzz_base_root"))
	baseHash := sha256.Sum256([]byte("fuzz_base_hash"))
	baseCP := &log.Checkpoint{
		Origin: "example.com/log",
		Size:   500,
		Hash:   baseHash[:],
	}
	baseLeaf := FormatOutputLogLeaf(baseMPTRoot, baseCP)

	for i := 0; i < 3000; i++ {
		mutated := make([]byte, len(baseLeaf))
		copy(mutated, baseLeaf)

		mutationType := rng.Intn(4)
		switch mutationType {
		case 0:
			pos := rng.Intn(len(mutated))
			mutated[pos] ^= 1 << rng.Intn(8)
		case 1:
			pos := rng.Intn(len(mutated))
			mutated = append(mutated[:pos], append([]byte{byte(rng.Intn(256))}, mutated[pos:]...)...)
		case 2:
			if len(mutated) > 1 {
				pos := rng.Intn(len(mutated))
				mutated = append(mutated[:pos], mutated[pos+1:]...)
			}
		case 3:
			truncLen := rng.Intn(len(mutated))
			mutated = mutated[:truncLen]
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iteration %d: ParseOutputLogLeaf panicked on mutated input %q: %v", i, string(mutated), r)
				}
			}()

			_, _, err := ParseOutputLogLeaf(mutated)
			if err != nil {
				if !errors.Is(err, ErrOutputLogCorrupted) {
					t.Fatalf("iteration %d: error does not wrap ErrOutputLogCorrupted: %v", i, err)
				}
			}
		}()
	}
}
