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
	_ "embed"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, cn string, sans []string) []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:              sans,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	return der
}

func buildRFC6962Leaf(entryType uint16, payload []byte) []byte {
	var buf []byte
	buf = append(buf, 0x00) // version 0
	buf = append(buf, 0x00) // leaf_type = timestamped_entry
	var ts [8]byte
	buf = append(buf, ts[:]...)
	var et [2]byte
	binary.BigEndian.PutUint16(et[:], entryType)
	buf = append(buf, et[:]...)

	switch entryType {
	case 0: // x509_entry
		certLen := len(payload)
		buf = append(buf, byte(certLen>>16), byte(certLen>>8), byte(certLen))
		buf = append(buf, payload...)
		buf = append(buf, 0x00, 0x00) // extensions length
	case 1: // precert_entry
		var keyHash [32]byte
		buf = append(buf, keyHash[:]...)
		tbsLen := len(payload)
		buf = append(buf, byte(tbsLen>>16), byte(tbsLen>>8), byte(tbsLen))
		buf = append(buf, payload...)
		buf = append(buf, 0x00, 0x00) // extensions length
	}
	return buf
}

func TestMapCTLeaf_X509Certificate(t *testing.T) {
	certDer := generateTestCert(t, "example.com", []string{"foo.bar.example.com", "*.sub.example.org"})
	leaf := buildRFC6962Leaf(0, certDer)

	var domains []string
	MapCTLeaf(leaf, func(key []byte) {
		domains = append(domains, string(key))
	})
	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	expectedDomains := []string{
		"com.example.",
		"com.example.bar.foo.",
		"org.example.sub.*.",
	}

	if len(domains) != len(expectedDomains) {
		t.Errorf("got %d domains %v, want %d %v", len(domains), domains, len(expectedDomains), expectedDomains)
	}
	for _, d := range expectedDomains {
		if !domainMap[d] {
			t.Errorf("expected domain %q in mapped entries, got %v", d, domains)
		}
	}
}

func TestMapCTLeaf_MultiLabelTLD_And_IDNA(t *testing.T) {
	// Subject.CommonName is marshaled as UTF8String by x509.CreateCertificate, allowing IDN test input.
	certDer := generateTestCert(t, "*.münchen.de.", []string{"deep.sub.service.co.uk.", "MAPS.GOOGLE.COM"})
	var domains []string
	MapCTLeaf(certDer, func(key []byte) {
		domains = append(domains, string(key))
	})
	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	expectedDomains := []string{
		"de.xn--mnchen-3ya.*.",
		"uk.co.service.sub.deep.",
		"com.google.maps.",
	}

	if len(domains) != len(expectedDomains) {
		t.Errorf("got %d domains %v, want %d %v", len(domains), domains, len(expectedDomains), expectedDomains)
	}
	for _, d := range expectedDomains {
		if !domainMap[d] {
			t.Errorf("expected domain %q in mapped entries, got %v", d, domains)
		}
	}
}

func TestMapCTLeaf_NoPlaintextFallback(t *testing.T) {
	plain := []byte("alpha.example.com\n*.beta.example.com\n")
	var domains []string
	MapCTLeaf(plain, func(key []byte) {
		domains = append(domains, string(key))
	})
	if len(domains) != 0 {
		t.Errorf("expected 0 keys for non-ASN.1 plaintext input, got %v", domains)
	}
}

func TestMapCTLeaf_LargeSANOverflow(t *testing.T) {
	var sans []string
	for i := 0; i < 100; i++ {
		sans = append(sans, fmt.Sprintf("host-%03d.long-subdomain-segment.example.com", i))
	}
	certDer := generateTestCert(t, "", sans)
	leaf := buildRFC6962Leaf(0, certDer)

	var domains []string
	MapCTLeaf(leaf, func(key []byte) {
		domains = append(domains, string(key))
	})
	if len(domains) != 100 {
		t.Fatalf("expected 100 domains, got %d", len(domains))
	}
}

func TestMapCTLeaf_Empty(t *testing.T) {
	var count int
	emitCount := func(key []byte) { count++ }

	count = 0
	MapCTLeaf(nil, emitCount)
	if count != 0 {
		t.Fatalf("expected 0 results for nil input, got %d", count)
	}

	count = 0
	MapCTLeaf([]byte("   \n\t  "), emitCount)
	if count != 0 {
		t.Fatalf("expected 0 results for whitespace input, got %d", count)
	}
}

func TestCanonicalizeDomainBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{name: "IPv4 literal 192.0.2.1", in: "192.0.2.1", want: "", wantOK: false},
		{name: "IPv4 literal 127.0.0.1", in: "127.0.0.1", want: "", wantOK: false},
		{name: "IPv4 literal trailing dot", in: "192.0.2.1.", want: "", wantOK: false},
		{name: "IPv6 literal", in: "2001:db8::1", want: "", wantOK: false},
		{name: "IPv6 bracketed literal", in: "[2001:db8::1]", want: "", wantOK: false},
		{name: "leading hyphen label", in: "-bad.example.com", want: "", wantOK: false},
		{name: "trailing hyphen label", in: "bad-.example.com", want: "", wantOK: false},
		{name: "leading hyphen TLD", in: "example.-com", want: "", wantOK: false},
		{name: "trailing hyphen TLD", in: "example.com-", want: "", wantOK: false},
		{name: "numeric subdomains", in: "1.2.example.com", want: "com.example.2.1.", wantOK: true},
		{name: "wildcard subdomain", in: "*.mail.example.com", want: "com.example.mail.*.", wantOK: true},
		{name: "IDN domain", in: "bücher.example.com", want: "com.example.xn--bcher-kva.", wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf [256]byte
			got, ok := canonicalizeDomainBytes([]byte(tc.in), &buf)
			if ok != tc.wantOK || string(got) != tc.want {
				t.Errorf("canonicalizeDomainBytes(%q) = (%q, %v), want (%q, %v)", tc.in, string(got), ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestMapCTLeaf_SkipIPAndInvalidLabels(t *testing.T) {
	invalidCert := generateTestCert(t, "192.0.2.1", []string{
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
	})
	invalidLeaf := buildRFC6962Leaf(0, invalidCert)

	var gotInvalid []string
	MapCTLeaf(invalidLeaf, func(key []byte) {
		gotInvalid = append(gotInvalid, string(key))
	})
	if len(gotInvalid) != 0 {
		t.Errorf("MapCTLeaf(invalid IP/hyphen labels) emitted %v, want 0 keys", gotInvalid)
	}

	// Subject.CommonName is marshaled as UTF8String by x509.CreateCertificate, allowing IDN test input.
	mixedCert := generateTestCert(t, "bücher.example.com", []string{
		"192.0.2.1",
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
		"1.2.example.com",
		"*.mail.example.com",
	})
	mixedLeaf := buildRFC6962Leaf(0, mixedCert)

	var gotMixed []string
	MapCTLeaf(mixedLeaf, func(key []byte) {
		gotMixed = append(gotMixed, string(key))
	})
	slices.Sort(gotMixed)
	wantMixed := []string{
		"com.example.2.1.",
		"com.example.mail.*.",
		"com.example.xn--bcher-kva.",
	}
	if !slices.Equal(gotMixed, wantMixed) {
		t.Errorf("MapCTLeaf(mixed valid/invalid) = %v, want %v", gotMixed, wantMixed)
	}
}

func splitStaticCTTile(data []byte) ([][]byte, error) {
	var leaves [][]byte
	offset := 0
	for offset < len(data) {
		start := offset
		if offset+10 > len(data) {
			return nil, fmt.Errorf("truncated at offset %d", offset)
		}
		entryType := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		switch entryType {
		case 0: // x509_entry
			if offset+3 > len(data) {
				return nil, fmt.Errorf("truncated cert len at %d", offset)
			}
			certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3 + certLen
		case 1: // precert_entry
			if offset+32+3 > len(data) {
				return nil, fmt.Errorf("truncated precert header at %d", offset)
			}
			offset += 32
			tbsLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3 + tbsLen
		default:
			return nil, fmt.Errorf("unknown entry type %d at offset %d", entryType, offset-10)
		}


		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated ext len at %d", offset)
		}
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + extLen

		if entryType == 1 {
			if offset+3 > len(data) {
				return nil, fmt.Errorf("truncated precert len at %d", offset)
			}
			pLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3 + pLen
		}

		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated chain len at %d", offset)
		}
		chainLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + chainLen

		if offset > len(data) {
			return nil, fmt.Errorf("tile overflow: offset %d > len %d", offset, len(data))
		}
		leaves = append(leaves, data[start:offset])
	}
	return leaves, nil
}

func TestMapCTLeaf_RealStaticCTTile(t *testing.T) {
	data, err := os.ReadFile("/tmp/sycamore_tile_000.bin")
	if err != nil {
		t.Skipf("skipping: /tmp/sycamore_tile_000.bin not found: %v", err)
	}
	leaves, err := splitStaticCTTile(data)
	if err != nil {
		t.Fatalf("failed to split static-ct tile: %v", err)
	}
	if len(leaves) != 256 {
		t.Fatalf("expected 256 entries in tile, got %d", len(leaves))
	}

	totalKeys := 0
	for i, leaf := range leaves {
		emittedCount := 0
		MapCTLeaf(leaf, func(key []byte) {
			emittedCount++
			totalKeys++
		})
		if emittedCount == 0 {
			t.Errorf("leaf %d emitted 0 search keys", i)
		}
	}
	t.Logf("Successfully mapped 256 real static-CT leaves into %d search keys", totalKeys)
}

//go:embed testdata/golden_leaves.json
var goldenLeavesJSON []byte

type goldenCase struct {
	Index      int    `json:"index"`
	EntryType  string `json:"entry_type"`
	Category   string `json:"category"`
	LeafHex    string `json:"leaf_hex"`
	ByteLength int    `json:"byte_length"`
}

func TestMapCTLeaf_GoldenDataset(t *testing.T) {
	var cases []goldenCase
	if err := json.Unmarshal(goldenLeavesJSON, &cases); err != nil {
		t.Fatalf("failed to unmarshal golden_leaves.json: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty golden dataset")
	}

	for _, tc := range cases {
		leafBytes, err := hex.DecodeString(tc.LeafHex)
		if err != nil {
			t.Fatalf("case %d: failed to decode hex: %v", tc.Index, err)
		}
		if len(leafBytes) != tc.ByteLength {
			t.Fatalf("case %d: byte length mismatch: got %d, want %d", tc.Index, len(leafBytes), tc.ByteLength)
		}

		var domains []string
		MapCTLeaf(leafBytes, func(key []byte) {
			domains = append(domains, string(key))
		})

		if len(domains) == 0 {
			t.Errorf("case %d [%s/%s]: emitted 0 search keys", tc.Index, tc.EntryType, tc.Category)
		}
		t.Logf("Case %d [%s]: %d domains emitted: %v", tc.Index, tc.EntryType, len(domains), domains)
	}
}

func BenchmarkMapCTLeaf(b *testing.B) {
	var cases []goldenCase
	if err := json.Unmarshal(goldenLeavesJSON, &cases); err != nil {
		b.Fatalf("failed to unmarshal golden_leaves.json: %v", err)
	}
	if len(cases) == 0 {
		b.Fatal("empty golden dataset")
	}
	leaf, err := hex.DecodeString(cases[0].LeafHex)
	if err != nil {
		b.Fatalf("failed to decode hex: %v", err)
	}

	b.ReportAllocs()
	emitSink := func(key []byte) {}
	for b.Loop() {
		MapCTLeaf(leaf, emitSink)
	}
}



