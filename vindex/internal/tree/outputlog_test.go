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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/transparency-dev/formats/log"
)

func TestParseOutputLogLeaf_Valid(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("test_mpt_root_123"))
	cpHash := sha256.Sum256([]byte("checkpoint_hash_123"))

	inCP := &log.Checkpoint{
		Origin: "example.com/log",
		Size:   42,
		Hash:   cpHash[:],
	}
	leafData := FormatOutputLogLeafFull(mptRoot, 5, inCP)

	parsedRoot, parsedCP, err := ParseOutputLogLeaf(leafData)
	if err != nil {
		t.Fatalf("ParseOutputLogLeaf failed: %v", err)
	}

	if parsedRoot != mptRoot {
		t.Fatalf("parsedRoot = %x, want %x", parsedRoot, mptRoot)
	}
	if parsedCP == nil {
		t.Fatal("parsedCP is nil")
	}
	if parsedCP.Origin != "example.com/log" {
		t.Fatalf("parsedCP.Origin = %q, want %q", parsedCP.Origin, "example.com/log")
	}
	if parsedCP.Size != 42 {
		t.Fatalf("parsedCP.Size = %d, want 42", parsedCP.Size)
	}
	if !bytes.Equal(parsedCP.Hash, cpHash[:]) {
		t.Fatalf("parsedCP.Hash = %x, want %x", parsedCP.Hash, cpHash[:])
	}

	full, err := ParseOutputLogLeafFull(leafData)
	if err != nil {
		t.Fatalf("ParseOutputLogLeafFull failed: %v", err)
	}
	if full.MPTRoot != mptRoot || full.InputOrigin != "example.com/log" || full.InputSize != 42 || full.InputRoot != cpHash || full.From != 5 {
		t.Fatalf("full = %+v", full)
	}
}

func TestParseOutputLogLeaf_Errors(t *testing.T) {
	validHashB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name     string
		leafData []byte
	}{
		{
			name:     "empty_leaf",
			leafData: []byte(""),
		},
		{
			name:     "whitespace_only",
			leafData: []byte("   \n\t  \n"),
		},
		{
			name:     "single_line_no_newline",
			leafData: []byte("c2sp.org/tlog-vindex-state@v1"),
		},
		{
			name:     "five_lines_only",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size 100\ninput-root %s\n", validHashB64)),
		},
		{
			name:     "seven_lines_extra",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size 100\ninput-root %s\nmpt-root %s\nextra 1\n", validHashB64, validHashB64)),
		},
		{
			name:     "trailing_newline",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size 100\ninput-root %s\nmpt-root %s\n\n", validHashB64, validHashB64)),
		},
		{
			name:     "mpt_root_too_short",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size 100\ninput-root %s\nmpt-root abcd\n", validHashB64)),
		},
		{
			name:     "input_root_invalid_base64",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size 100\ninput-root %s\nmpt-root %s\n", strings.Repeat("!", 44), validHashB64)),
		},
		{
			name:     "from_leading_zero",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 01\ninput-size 100\ninput-root %s\nmpt-root %s\n", validHashB64, validHashB64)),
		},
		{
			name:     "from_exceeds_input_size",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 101\ninput-size 100\ninput-root %s\nmpt-root %s\n", validHashB64, validHashB64)),
		},
		{
			name:     "empty_input_origin",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin \nfrom 0\ninput-size 100\ninput-root %s\nmpt-root %s\n", validHashB64, validHashB64)),
		},
		{
			name:     "input_size_not_a_number",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin example.com/log\nfrom 0\ninput-size not_a_number\ninput-root %s\nmpt-root %s\n", validHashB64, validHashB64)),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseOutputLogLeaf(tc.leafData)
			if err == nil {
				t.Fatalf("ParseOutputLogLeaf(%q) succeeded, want error", string(tc.leafData))
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("ParseOutputLogLeaf error = %v, want errors.Is(err, ErrOutputLogCorrupted)", err)
			}
		})
	}
}

func TestFormatOutputLogLeaf_Roundtrip(t *testing.T) {
	for i := 0; i < 10; i++ {
		mptRoot := sha256.Sum256([]byte(fmt.Sprintf("mpt_root_iteration_%d", i)))
		cpHash := sha256.Sum256([]byte(fmt.Sprintf("cp_hash_iteration_%d", i)))
		inCP := &log.Checkpoint{
			Origin: "origin.example.com",
			Size:   uint64(i * 10),
			Hash:   cpHash[:],
		}

		leaf := FormatOutputLogLeaf(mptRoot, inCP)

		parsedRoot, parsedCP, err := ParseOutputLogLeaf(leaf)
		if err != nil {
			t.Fatalf("iteration %d: ParseOutputLogLeaf failed: %v", i, err)
		}
		if parsedRoot != mptRoot {
			t.Fatalf("iteration %d: parsedRoot = %x, want %x", i, parsedRoot, mptRoot)
		}
		if parsedCP.Size != uint64(i*10) {
			t.Fatalf("iteration %d: parsedCP.Size = %d, want %d", i, parsedCP.Size, i*10)
		}
		if parsedCP.Origin != "origin.example.com" {
			t.Fatalf("iteration %d: parsedCP.Origin = %q, want %q", i, parsedCP.Origin, "origin.example.com")
		}

		reformatted := FormatOutputLogLeaf(parsedRoot, parsedCP)
		if !bytes.Equal(reformatted, leaf) {
			t.Fatalf("iteration %d: roundtrip leaf mismatch:\ngot:\n%s\nwant:\n%s", i, string(reformatted), string(leaf))
		}
	}
}

func TestFormatOutputLogLeaf_ExactFormat(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("dummy"))
	inRoot := sha256.Sum256([]byte("in_dummy"))
	inCP := &log.Checkpoint{
		Origin: "origin",
		Size:   5,
		Hash:   inRoot[:],
	}

	leaf := FormatOutputLogLeaf(mptRoot, inCP)
	expected := fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\ninput-origin origin\nfrom 0\ninput-size 5\ninput-root %s\nmpt-root %s\n",
		base64.StdEncoding.EncodeToString(inRoot[:]),
		base64.StdEncoding.EncodeToString(mptRoot[:]))
	if string(leaf) != expected {
		t.Fatalf("unexpected formatted leaf:\ngot:\n%q\nwant:\n%q", string(leaf), expected)
	}
}
