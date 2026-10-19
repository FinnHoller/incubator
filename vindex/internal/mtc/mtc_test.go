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

package mtc

import (
	"encoding/asn1"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/incubator/vindex/internal/mtc/mtctest"
)

func TestParseAndExtract(t *testing.T) {

	// Fixed DER payload
	derHex := "30820146a003020102301c311a3018060a2b0601040182da4b2f010c0a34343336332e34382e38301e170d3235313131313230313732365a170d3235313131383230313732365a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311430120603550407130b4c6f7320416e67656c6573313c303a060355040a1333496e7465726e657420436f72706f726174696f6e20666f722041737369676e6564204e616d657320616e64204e756d626572733116301406035504030c0d2a2e6578616d706c652e636f6d042088c3292097527f95650a51dac5945eca168bc4bb2664c30d022036a4c47cfccea34e304c30250603551d11041e301c820d2a2e6578616d706c652e636f6d820b6578616d706c652e636f6d300e0603551d0f0101ff04040302078030130603551d25040c300a06082b0601050507030100"
	der, err := hex.DecodeString(derHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	entry, err := ParseTBSCertificateLogEntry(der)
	if err != nil {
		t.Fatalf("ParseTBSCertificateLogEntry failed: %v", err)
	}

	gotDNSNames := ExtractDNSNames(entry)
	wantDNSNames := []string{"*.example.com", "example.com"}

	if diff := cmp.Diff(wantDNSNames, gotDNSNames); diff != "" {
		t.Errorf("ExtractDNSNames mismatch (-want +got):\n%s", diff)
	}
}

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

	entry := TBSCertificateLogEntry{
		Extensions: []asn1.RawValue{{FullBytes: extBytes}},
	}

	entryBytes, err := asn1.Marshal(entry)
	if err != nil {
		return nil, err
	}

	return append([]byte{0, 1}, entryBytes...), nil
}

func TestExtractDomainNames(t *testing.T) {
	derHex := "30820146a003020102301c311a3018060a2b0601040182da4b2f010c0a34343336332e34382e38301e170d3235313131313230313732365a170d3235313131383230313732365a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311430120603550407130b4c6f7320416e67656c6573313c303a060355040a1333496e7465726e657420436f72706f726174696f6e20666f722041737369676e6564204e616d657320616e64204e756d626572733116301406035504030c0d2a2e6578616d706c652e636f6d042088c3292097527f95650a51dac5945eca168bc4bb2664c30d022036a4c47cfccea34e304c30250603551d11041e301c820d2a2e6578616d706c652e636f6d820b6578616d706c652e636f6d300e0603551d0f0101ff04040302078030130603551d25040c300a06082b0601050507030100"
	derBytes, err := hex.DecodeString(derHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	validType1 := append([]byte{0x00, 0x01}, derBytes...)
	validType0 := append([]byte{0x00, 0x00}, derBytes...)
	invalidType1 := append([]byte{0x00, 0x01}, []byte("invalid der")...)

	subdomainCert, err := marshalMTCEntry([]string{"deep.maps.google.co.uk"})
	if err != nil {
		t.Fatalf("failed to create subdomain cert: %v", err)
	}
	mixedCaseCert, err := marshalMTCEntry([]string{"MAPS.GOOGLE.COM"})
	if err != nil {
		t.Fatalf("failed to create mixed case cert: %v", err)
	}
	ipAndInvalidLabelsOnlyCert, err := marshalMTCEntry([]string{
		"192.0.2.1",
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
	})
	if err != nil {
		t.Fatalf("failed to create ip/invalid cert: %v", err)
	}
	mixedValidAndInvalidCert, err := marshalMTCEntry([]string{
		"192.0.2.1",
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
		"1.2.example.com",
		"*.mail.example.com",
		"bücher.example.com",
	})
	if err != nil {
		t.Fatalf("failed to create mixed valid/invalid cert: %v", err)
	}

	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{
			name: "Valid Type 1 (wildcard preserved, reversed-label with trailing dot)",
			data: validType1,
			want: []string{"com.example.*.", "com.example."},
		},
		{
			name: "Type 0 (ignored)",
			data: validType0,
			want: nil,
		},
		{
			name: "Invalid Type 1 (ignored)",
			data: invalidType1,
			want: nil,
		},
		{
			name: "Too short data",
			data: []byte{0x00},
			want: nil,
		},
		{
			name: "Subdomain indexing (reversed-label single key)",
			data: subdomainCert,
			want: []string{"uk.co.google.maps.deep."},
		},
		{
			name: "Mixed case normalization",
			data: mixedCaseCert,
			want: []string{"com.google.maps."},
		},
		{
			name: "IP literals and invalid hyphenated labels skipped (0 emitted keys)",
			data: ipAndInvalidLabelsOnlyCert,
			want: nil,
		},
		{
			name: "Numeric subdomains, wildcards, and IDN emitted while IP and invalid labels skipped",
			data: mixedValidAndInvalidCert,
			want: []string{"com.example.2.1.", "com.example.mail.*.", "com.example.xn--bcher-kva."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			ExtractDomainNames(tt.data, func(domain string) {
				got = append(got, domain)
			})
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("ExtractDomainNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractDomainNames_Golden(t *testing.T) {
	for _, tc := range mtctest.GoldenLeaves() {
		t.Run(tc.Category, func(t *testing.T) {
			raw := tc.MustLeafBytes()
			var got []string
			ExtractDomainNames(raw, func(domain string) {
				got = append(got, domain)
			})
			want := slices.Clone(tc.ExpectedDomains)
			slices.Sort(got)
			slices.Sort(want)

			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("ExtractDomainNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCanonicalizeDomain(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"example.com", "com.example.", true},
		{"mail.google.com", "com.google.mail.", true},
		{"*.google.com", "com.google.*.", true},
		{"*.mail.google.com.", "com.google.mail.*.", true},
		{"  MAPS.GOOGLE.COM. ", "com.google.maps.", true},
		{"münchen.de", "de.xn--mnchen-3ya.", true},
		{"*.münchen.de", "de.xn--mnchen-3ya.*.", true},
		{"_dmarc.example.com", "com.example._dmarc.", true},
		{"1.2.example.com", "com.example.2.1.", true},
		{"*.mail.example.com", "com.example.mail.*.", true},
		{"bücher.example.com", "com.example.xn--bcher-kva.", true},
		{"192.0.2.1", "", false},
		{"127.0.0.1", "", false},
		{"192.0.2.1.", "", false},
		{"2001:db8::1", "", false},
		{"[2001:db8::1]", "", false},
		{"-bad.example.com", "", false},
		{"bad-.example.com", "", false},
		{"example.-com", "", false},
		{"example.com-", "", false},
		{"", "", false},
		{"localhost", "", false},
		{"*.com", "", false},
		{"*foo.example.com", "", false},
		{"sub.*.example.com", "", false},
		{"My Root CA", "", false},
	}

	for _, tc := range tests {
		got, ok := CanonicalizeDomain(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("CanonicalizeDomain(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
