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

// Package mtc implements parsing, checkpoint verification, and leaf mapping for Merkle Tree Certificates.
package mtc

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// Validity represents the validity period of a certificate.
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// TBSCertificateLogEntry represents the ASN.1 structure inside a tile entry.
type TBSCertificateLogEntry struct {
	Version                  int `asn1:"optional,explicit,default:0,tag:0"`
	Issuer                   pkix.RDNSequence
	Validity                 Validity
	Subject                  pkix.RDNSequence
	SubjectPublicKeyInfoHash []byte
	IssuerUniqueID           asn1.BitString  `asn1:"optional,implicit,tag:1"`
	SubjectUniqueID          asn1.BitString  `asn1:"optional,implicit,tag:2"`
	Extensions               []asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

type extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional,default:false"`
	Value    []byte
}

// ParseTBSCertificateLogEntry parses the ASN.1 DER encoded TBSCertificateLogEntry.
func ParseTBSCertificateLogEntry(der []byte) (*TBSCertificateLogEntry, error) {
	var entry TBSCertificateLogEntry
	rest, err := asn1.Unmarshal(der, &entry)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TBSCertificateLogEntry: %w", err)
	}
	// We allow trailing data because some test cases might have it.
	_ = rest
	return &entry, nil
}

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ExtractDNSNames extracts DNS names from the Subject CommonName and SAN extension of the entry.
func ExtractDNSNames(entry *TBSCertificateLogEntry) []string {
	var dnsNames []string
	for _, rawExt := range entry.Extensions {
		var ext extension
		if _, err := asn1.Unmarshal(rawExt.FullBytes, &ext); err != nil {
			continue
		}
		if !ext.Id.Equal(oidExtensionSubjectAltName) {
			continue
		}
		var sequence []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &sequence); err != nil {
			continue
		}
		for _, raw := range sequence {
			if raw.Class == 2 && raw.Tag == 2 {
				dnsNames = append(dnsNames, string(raw.Bytes))
			}
		}
	}
	var subjName pkix.Name
	subjName.FillFromRDNSequence(&entry.Subject)
	if cn := subjName.CommonName; cn != "" {
		found := false
		for _, existing := range dnsNames {
			if strings.EqualFold(existing, cn) {
				found = true
				break
			}
		}
		if !found {
			dnsNames = append(dnsNames, cn)
		}
	}
	return dnsNames
}

var (
	sanOIDBytes = []byte{0x55, 0x1d, 0x11} // id-ce-subjectAltName (2.5.29.17)
	cnOIDBytes  = []byte{0x55, 0x04, 0x03} // id-at-commonName (2.5.4.3)
)

func readTagLen(b []byte) (tag byte, content []byte, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	if b[1] < 0x80 {
		l := int(b[1])
		if len(b) < 2+l {
			return 0, nil, nil, false
		}
		return tag, b[2 : 2+l], b[2+l:], true
	}
	numBytes := int(b[1] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(b) < 2+numBytes {
		return 0, nil, nil, false
	}
	var l int
	for i := 0; i < numBytes; i++ {
		l = (l << 8) | int(b[2+i])
	}
	if l < 0 || len(b) < 2+numBytes+l {
		return 0, nil, nil, false
	}
	return tag, b[2+numBytes : 2+numBytes+l], b[2+numBytes+l:], true
}

func extractDNSNamesFromDER(der []byte, emit func(dns []byte)) {
	tag, tbsContent, _, ok := readTagLen(der)
	if !ok || tag != 0x30 {
		return
	}

	seqCount := 0
	for len(tbsContent) > 0 {
		var field []byte
		tag, field, tbsContent, ok = readTagLen(tbsContent)
		if !ok {
			return
		}
		if tag == 0x30 {
			seqCount++
			if seqCount == 3 { // 3rd SEQUENCE in TBSCertificateLogEntry is Subject
				subjSeq := field
				for len(subjSeq) > 0 {
					var rdnSet []byte
					tag, rdnSet, subjSeq, ok = readTagLen(subjSeq)
					if !ok || tag != 0x31 {
						break
					}
					for len(rdnSet) > 0 {
						var attrSeq []byte
						tag, attrSeq, rdnSet, ok = readTagLen(rdnSet)
						if !ok || tag != 0x30 {
							break
						}
						oTag, oid, attrRest, ok := readTagLen(attrSeq)
						if ok && oTag == 0x06 && bytes.Equal(oid, cnOIDBytes) {
							_, val, _, ok := readTagLen(attrRest)
							if ok && len(val) > 0 {
								emit(val)
							}
						}
					}
				}
			}
			continue
		}
		if tag == 0xa3 { // [3] EXPLICIT Extensions
			tag, extSeq, _, ok := readTagLen(field)
			if !ok || tag != 0x30 {
				return
			}
			for len(extSeq) > 0 {
				var ext []byte
				tag, ext, extSeq, ok = readTagLen(extSeq)
				if !ok || tag != 0x30 {
					return
				}
				tag, oid, ext, ok := readTagLen(ext)
				if !ok || tag != 0x06 {
					continue
				}
				if !bytes.Equal(oid, sanOIDBytes) {
					continue
				}
				tag, val, ext, ok := readTagLen(ext)
				if !ok {
					return
				}
				if tag == 0x01 { // critical BOOLEAN
					tag, val, _, ok = readTagLen(ext)
					if !ok {
						return
					}
				}
				if tag != 0x04 { // extnValue OCTET STRING
					return
				}
				tag, sanSeq, _, ok := readTagLen(val)
				if !ok || tag != 0x30 {
					return
				}
				for len(sanSeq) > 0 {
					var item []byte
					tag, item, sanSeq, ok = readTagLen(sanSeq)
					if !ok {
						return
					}
					if tag == 0x82 { // [2] IMPLICIT dNSName
						emit(item)
					}
				}
				return
			}
		}
	}
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// canonicalizeDomainBytes normalizes a raw DNS name or Subject CN into a reversed-label
// canonical key with a mandatory trailing dot (e.g. "*.mail.google.com" -> "com.google.mail.*.").
func canonicalizeDomainBytes(raw []byte, outBuf *[256]byte) ([]byte, bool) {
	for len(raw) > 0 && isASCIIWhitespace(raw[0]) {
		raw = raw[1:]
	}
	for len(raw) > 0 && isASCIIWhitespace(raw[len(raw)-1]) {
		raw = raw[:len(raw)-1]
	}
	if len(raw) > 0 && raw[len(raw)-1] == '.' {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 {
		return nil, false
	}

	hasWildcard := false
	if len(raw) >= 2 && raw[0] == '*' && raw[1] == '.' {
		hasWildcard = true
		raw = raw[2:]
	} else if raw[0] == '*' {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, false
	}

	hasNonASCII := false
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			hasNonASCII = true
			break
		}
	}
	if hasNonASCII {
		ascii, err := idna.Lookup.ToASCII(string(raw))
		if err != nil || len(ascii) == 0 {
			return nil, false
		}
		if ascii[len(ascii)-1] == '.' {
			ascii = ascii[:len(ascii)-1]
		}
		if len(ascii) == 0 {
			return nil, false
		}
		raw = []byte(ascii)
	}

	needed := len(raw) + 1
	if hasWildcard {
		needed += 2
	}
	if len(raw) > 253 || needed > len(outBuf) {
		return nil, false
	}

	outLen := 0
	dotCount := 0
	labelEnd := len(raw)

	for i := len(raw) - 1; i >= -1; i-- {
		if i == -1 || raw[i] == '.' {
			if i >= 0 {
				dotCount++
			}
			labelStart := i + 1
			labelLen := labelEnd - labelStart
			if labelLen < 1 || labelLen > 63 {
				return nil, false
			}
			if raw[labelStart] == '-' || raw[labelEnd-1] == '-' {
				return nil, false
			}
			isTLD := labelEnd == len(raw)
			allDigits := true
			for j := labelStart; j < labelEnd; j++ {
				c := raw[j]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
					return nil, false
				}
				if c < '0' || c > '9' {
					allDigits = false
				}
				outBuf[outLen] = c
				outLen++
			}
			if isTLD && allDigits {
				return nil, false
			}
			outBuf[outLen] = '.'
			outLen++
			labelEnd = i
		}
	}

	if dotCount < 1 {
		return nil, false
	}
	if hasWildcard {
		outBuf[outLen] = '*'
		outLen++
		outBuf[outLen] = '.'
		outLen++
	}
	return outBuf[:outLen], true
}

// CanonicalizeDomain converts a domain string (e.g. "mail.google.com" or "*.google.com")
// into its reversed-label canonical key with a mandatory trailing dot ("com.google.mail."
// or "com.google.*."). Returns ("", false) if the input is not a valid domain.
func CanonicalizeDomain(raw string) (string, bool) {
	var buf [256]byte
	out, ok := canonicalizeDomainBytes([]byte(raw), &buf)
	if !ok {
		return "", false
	}
	return string(out), true
}

// ExtractDomainNames parses an MTC log leaf and invokes emit for each unique reversed-label
// canonical domain key with a trailing dot.
func ExtractDomainNames(leaf []byte, emit func(domain string)) {
	if len(leaf) < 2 {
		return
	}
	entryType := binary.BigEndian.Uint16(leaf[:2])
	if entryType != 1 {
		return
	}

	var namesBuf [64]string
	names := namesBuf[:0]
	var outBuf [256]byte

	extractDNSNamesFromDER(leaf[2:], func(raw []byte) {
		canonBytes, ok := canonicalizeDomainBytes(raw, &outBuf)
		if !ok {
			return
		}
		for _, existing := range names {
			if len(existing) == len(canonBytes) && existing == string(canonBytes) {
				return
			}
		}
		names = append(names, string(canonBytes))
	})

	for _, name := range names {
		emit(name)
	}
}
