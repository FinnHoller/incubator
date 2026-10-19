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
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

func FuzzVerifyKeysResponse(f *testing.F) {
	_, outVKey, err := note.GenerateKey(rand.Reader, "example.com/output")
	if err != nil {
		f.Fatal(err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		f.Fatal(err)
	}

	outPolicy, err := SingleKeyPolicy("example.com/output", outVerifier)
	if err != nil {
		f.Fatal(err)
	}
	cfg := Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "example.com/input",
	}

	f.Add([]byte("c2sp.org/tlog-vindex-keys@v1\nproof\n\nc2sp.org/tlog-proof@v1\nextra AAAA\nindex 0\n\nexample.com/output\n1\nAAAA\n"), "com.example.", false)
	f.Add([]byte("c2sp.org/tlog-vindex-keys@v1\nproof\ncom.example. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\nc2sp.org/tlog-proof@v1\nextra AAAA\nindex 0\n\n"), "com.example.", true)
	f.Add([]byte(""), "", false)

	f.Fuzz(func(_ *testing.T, rawBody []byte, target string, isPrefix bool) {
		_, _ = VerifyKeysResponse(rawBody, target, isPrefix, cfg)
	})
}

func FuzzVerifyValuesResponse(f *testing.F) {
	vr, err := wire.ComputeValueLogRoot(nil, 0, []uint64{10, 20})
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n10\n20\n"), vr[:], uint64(0), uint64(100))
	f.Add([]byte("c2sp.org/tlog-vindex-values@v1\npreceding 1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n55\n"), vr[:], uint64(50), uint64(60))
	f.Add([]byte(""), make([]byte, 32), uint64(0), uint64(0))

	f.Fuzz(func(_ *testing.T, rawBody []byte, rootSlice []byte, from, before uint64) {
		var expectedRoot [sha256.Size]byte
		copy(expectedRoot[:], rootSlice)
		resp, err := VerifyValuesResponse(rawBody, expectedRoot, from, before)
		if err == nil && resp != nil {
			_, _, _ = resp.NextPage()
		}
	})
}
