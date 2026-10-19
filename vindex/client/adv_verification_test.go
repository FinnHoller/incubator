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

package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

func setupAdvTestServer(t *testing.T) (string, string, Config) {
	t.Helper()
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)

	keyStr := "adv_test_key.example.com"
	key := sha256.Sum256([]byte(keyStr))
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20, 30},
		},
		CanonicalKeys: map[[32]byte]string{
			key: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	inCP, rawInCP := keys.signInputCP(t, 100)
	_, err = pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys?key="+keyStr, nil)
	w := httptest.NewRecorder()
	srv.HandleKeys(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleKeys failed: %d", w.Code)
	}

	return keyStr, w.Body.String(), keys.clientConfig(t)
}

// TestAdv_VerifyKeysResponse_OutputLogLeafCorruption tests that any corruption of the
// OutputLog leaf within the response envelope is detected and properly wrapped with wire.ErrOutputLogCorrupted.
func TestAdv_VerifyKeysResponse_OutputLogLeafCorruption(t *testing.T) {
	keyStr, validBody, cfg := setupAdvTestServer(t)

	// Baseline check: valid body must verify cleanly
	if _, err := VerifyKeysResponse([]byte(validBody), keyStr, false, cfg); err != nil {
		t.Fatalf("Baseline valid body failed verification: %v", err)
	}

	// Extract current extra <base64> line from valid response
	var extraLine string
	for _, l := range strings.Split(validBody, "\n") {
		if strings.HasPrefix(l, "extra ") {
			extraLine = l
			break
		}
	}
	if extraLine == "" {
		t.Fatal("failed to extract extra line from valid body")
	}

	corruptionCases := []struct {
		name        string
		corruptLeaf string
	}{
		{
			name:        "truncated_single_line_no_newline",
			corruptLeaf: "abcd1234deadbeef",
		},
		{
			name:        "invalid_hex_root_length_short",
			corruptLeaf: "abcd1234\nexample.com/input\n100\nAAAA\n",
		},
		{
			name:        "invalid_hex_root_length_long",
			corruptLeaf: strings.Repeat("a", 66) + "\nexample.com/input\n100\nAAAA\n",
		},
		{
			name:        "invalid_hex_chars",
			corruptLeaf: strings.Repeat("z", 64) + "\nexample.com/input\n100\nAAAA\n",
		},
		{
			name:        "corrupted_checkpoint_missing_lines",
			corruptLeaf: strings.Repeat("0", 64) + "\nonly_one_line",
		},
		{
			name:        "corrupted_checkpoint_invalid_size",
			corruptLeaf: strings.Repeat("0", 64) + "\nexample.com/input\nnot_a_number\nAAAA\n",
		},
		{
			name:        "corrupted_checkpoint_invalid_hash_encoding",
			corruptLeaf: strings.Repeat("0", 64) + "\nexample.com/input\n100\n!@#$%^&*\n",
		},
	}

	for _, tc := range corruptionCases {
		t.Run(tc.name, func(t *testing.T) {
			corruptExtra := "extra " + base64.StdEncoding.EncodeToString([]byte(tc.corruptLeaf))
			tamperedBody := strings.Replace(validBody, extraLine, corruptExtra, 1)
			_, err := VerifyKeysResponse([]byte(tamperedBody), keyStr, false, cfg)
			if err == nil {
				t.Fatalf("expected error for corrupted leaf in %s, got nil", tc.name)
			}
			if !errors.Is(err, wire.ErrOutputLogCorrupted) {
				t.Fatalf("expected errors.Is(err, wire.ErrOutputLogCorrupted), got %v", err)
			}
			if !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("expected errors.Is(err, ErrVerificationFailed), got %v", err)
			}
		})
	}
}

// TestAdv_VerifyLookupResponse_OutputLogLeafErrorWrapping tests that ParseOutputLogLeaf
// properly wraps wire.ErrOutputLogCorrupted when output log leaf parsing fails.
func TestAdv_VerifyLookupResponse_OutputLogLeafErrorWrapping(t *testing.T) {
	testLeaves := []struct {
		name string
		leaf []byte
	}{
		{"empty", []byte("")},
		{"short_hex", []byte("1234\nexample.com/in\n1\nAAAA\n")},
		{"bad_hex_chars", []byte(strings.Repeat("q", 64) + "\nexample.com/in\n1\nAAAA\n")},
		{"bad_checkpoint", []byte(strings.Repeat("0", 64) + "\nexample.com/in\nnot_num\nAAAA\n")},
	}

	for _, tc := range testLeaves {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := wire.ParseOutputLogLeaf(tc.leaf)
			if err == nil {
				t.Fatalf("ParseOutputLogLeaf should fail for %s", tc.name)
			}
			if !errors.Is(err, wire.ErrOutputLogCorrupted) {
				t.Fatalf("ParseOutputLogLeaf error must wrap ErrOutputLogCorrupted: %v", err)
			}

			wrappedErr := fmt.Errorf("output log leaf malformed: %w", err)
			if !errors.Is(wrappedErr, wire.ErrOutputLogCorrupted) {
				t.Fatalf("wrappedErr must satisfy errors.Is(wrappedErr, wire.ErrOutputLogCorrupted)")
			}
		})
	}
}
