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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o ct.wasm ."

// Package main implements an optimized, zero-alloc CT (Certificate Transparency) WASM MapFn plugin.
package main

import (
	"bytes"
	"encoding/binary"

	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
	"golang.org/x/net/idna"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapCTLeaf)
}

var (
	oidSANRaw = []byte{0x55, 0x1d, 0x11} // 2.5.29.17 (Subject Alternative Name)
	oidCNRaw  = []byte{0x55, 0x04, 0x03} // 2.5.4.3 (Common Name)
)

type domainSpan struct {
	start uint16
	end   uint16
}

var (
	leafStorage [2048]byte
	leafSpans   [64]domainSpan
)

// MapCTLeaf extracts all unique reversed-label canonical domain keys from a CT log leaf.
func MapCTLeaf(data []byte, emit func(key []byte)) {
	if len(data) == 0 {
		return
	}

	storageUsed := 0
	spanCount := 0
	var overflowDomains [][]byte
	var outBuf [256]byte

	extractRawDomainNames(data, func(rawName []byte) {
		canon, ok := canonicalizeDomainBytes(rawName, &outBuf)
		if !ok {
			return
		}

		for i := 0; i < spanCount; i++ {
			sp := leafSpans[i]
			if bytes.Equal(leafStorage[sp.start:sp.end], canon) {
				return
			}
		}
		for _, ov := range overflowDomains {
			if bytes.Equal(ov, canon) {
				return
			}
		}

		if storageUsed+len(canon) <= len(leafStorage) && spanCount < len(leafSpans) {
			baseStart := uint16(storageUsed)
			baseEnd := baseStart + uint16(len(canon))
			copy(leafStorage[baseStart:], canon)
			storageUsed = int(baseEnd)
			leafSpans[spanCount] = domainSpan{start: baseStart, end: baseEnd}
			spanCount++
		} else {
			overflowDomains = append(overflowDomains, append([]byte(nil), canon...))
		}
	})

	for i := 0; i < spanCount; i++ {
		sp := leafSpans[i]
		emit(leafStorage[sp.start:sp.end])
	}
	for _, ov := range overflowDomains {
		emit(ov)
	}
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

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

// readASN1Header parses tag and length at pos. Returns (tag, contentStart, contentEnd, nextElem, ok).
func readASN1Header(b []byte, pos int) (tag byte, start, end, next int, ok bool) {
	if pos >= len(b) {
		return 0, 0, 0, 0, false
	}
	tag = b[pos]
	pos++
	if pos >= len(b) {
		return 0, 0, 0, 0, false
	}
	lByte := b[pos]
	pos++
	var length int
	if lByte < 0x80 {
		length = int(lByte)
	} else {
		numBytes := int(lByte & 0x7f)
		if numBytes == 0 || numBytes > 4 || pos+numBytes > len(b) {
			return 0, 0, 0, 0, false
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(b[pos+i])
		}
		pos += numBytes
	}
	if pos+length > len(b) {
		return 0, 0, 0, 0, false
	}
	return tag, pos, pos + length, pos + length, true
}

// fastExtractDomainsFromTBS extracts CommonName and SAN DNSNames from raw TBSCertificate DER.
func fastExtractDomainsFromTBS(tbs []byte, emit func(raw []byte)) bool {
	tag, start, end, _, ok := readASN1Header(tbs, 0)
	if !ok || tag != 0x30 {
		return false
	}
	payload := tbs[start:end]

	pos := 0

	// 1. Optional version [0] EXPLICIT
	if pos < len(payload) && payload[pos] == 0xa0 {
		_, _, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return false
		}
		pos = next
	}

	// 2. serialNumber INTEGER (0x02)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x02 {
		pos = next
	} else {
		return false
	}

	// 3. signature AlgorithmIdentifier SEQUENCE (0x30)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// 4. issuer Name SEQUENCE (0x30)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// 5. validity Validity SEQUENCE (0x30)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// 6. subject Name SEQUENCE (0x30)
	var subjectBytes []byte
	if tag, sStart, sEnd, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
		subjectBytes = payload[sStart:sEnd]
	} else {
		return false
	}

	// 7. subjectPublicKeyInfo SEQUENCE (0x30) - SKIP without parsing keys!
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// Optional: issuerUniqueID [1]
	if pos < len(payload) && payload[pos] == 0x81 {
		_, _, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return false
		}
		pos = next
	}

	// Optional: subjectUniqueID [2]
	if pos < len(payload) && payload[pos] == 0x82 {
		_, _, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return false
		}
		pos = next
	}

	// Emit Subject CN if present
	sPos := 0
	for sPos < len(subjectBytes) {
		_, setStart, setEnd, setNext, ok := readASN1Header(subjectBytes, sPos)
		if !ok {
			break
		}
		setBytes := subjectBytes[setStart:setEnd]
		subPos := 0
		for subPos < len(setBytes) {
			_, seqStart, seqEnd, seqNext, ok := readASN1Header(setBytes, subPos)
			if !ok {
				break
			}
			seqBytes := setBytes[seqStart:seqEnd]
			oTag, oStart, oEnd, oNext, ok := readASN1Header(seqBytes, 0)
			if ok && oTag == 0x06 && bytes.Equal(seqBytes[oStart:oEnd], oidCNRaw) {
				_, vStart, vEnd, _, ok := readASN1Header(seqBytes, oNext)
				if ok && vEnd > vStart {
					emit(seqBytes[vStart:vEnd])
				}
			}
			subPos = seqNext
		}
		sPos = setNext
	}

	// Optional: extensions [3] EXPLICIT (0xa3)
	if pos < len(payload) && payload[pos] == 0xa3 {
		_, eStart, eEnd, _, ok := readASN1Header(payload, pos)
		if ok {
			extContainer := payload[eStart:eEnd]
			tag, sStart, sEnd, _, ok := readASN1Header(extContainer, 0)
			if ok && tag == 0x30 {
				extList := extContainer[sStart:sEnd]
				ePos := 0
				for ePos < len(extList) {
					_, itemStart, itemEnd, itemNext, ok := readASN1Header(extList, ePos)
					if !ok {
						break
					}
					itemBytes := extList[itemStart:itemEnd]
					iPos := 0
					tag, oStart, oEnd, next, ok := readASN1Header(itemBytes, iPos)
					if ok && tag == 0x06 {
						isSAN := bytes.Equal(itemBytes[oStart:oEnd], oidSANRaw)
						iPos = next
						if iPos < len(itemBytes) && itemBytes[iPos] == 0x01 { // critical BOOLEAN
							_, _, _, next, ok := readASN1Header(itemBytes, iPos)
							if ok {
								iPos = next
							}
						}
						tag, vStart, vEnd, _, ok := readASN1Header(itemBytes, iPos) // extnValue OCTET STRING
						if ok && tag == 0x04 && isSAN {
							sanVal := itemBytes[vStart:vEnd]
							tag, gnStart, gnEnd, _, ok := readASN1Header(sanVal, 0)
							if ok && tag == 0x30 {
								gnList := sanVal[gnStart:gnEnd]
								gnPos := 0
								for gnPos < len(gnList) {
									tag, dStart, dEnd, gnNext, ok := readASN1Header(gnList, gnPos)
									if !ok {
										break
									}
									if tag == 0x82 && dEnd > dStart { // dNSName [2]
										emit(gnList[dStart:dEnd])
									}
									gnPos = gnNext
								}
							}
						}
					}
					ePos = itemNext
				}
			}
		}
	}

	return true
}

// fastExtractDomainsFromCert unwraps the outer Certificate SEQUENCE and parses TBSCertificate.
func fastExtractDomainsFromCert(certDer []byte, emit func(raw []byte)) bool {
	tag, start, end, _, ok := readASN1Header(certDer, 0)
	if !ok || tag != 0x30 {
		return false
	}
	outer := certDer[start:end]
	tag, _, _, _, ok = readASN1Header(outer, 0)
	if !ok || tag != 0x30 {
		return false
	}
	return fastExtractDomainsFromTBS(outer, emit)
}

func extractRawDomainNames(data []byte, emit func(raw []byte)) {
	if len(data) == 0 {
		return
	}

	// 1. Try RFC 6962 MerkleTreeLeaf parsing (starts with 0x00, 0x00 version & leaf_type)
	if len(data) >= 12 && data[0] == 0 && data[1] == 0 {
		entryType := binary.BigEndian.Uint16(data[10:12])
		if entryType == 0 && len(data) >= 15 { // x509_entry
			certLen := int(data[12])<<16 | int(data[13])<<8 | int(data[14])
			if certLen > 0 && len(data) >= 15+certLen {
				if fastExtractDomainsFromCert(data[15:15+certLen], emit) {
					return
				}
			}
		} else if entryType == 1 && len(data) >= 47 { // precert_entry
			tbsLen := int(data[44])<<16 | int(data[45])<<8 | int(data[46])
			if tbsLen > 0 && len(data) >= 47+tbsLen {
				if fastExtractDomainsFromTBS(data[47:47+tbsLen], emit) {
					return
				}
			}
		}
	}

	// 2. Try C2SP Static-CT TileLeaf parsing (starts directly with 8-byte timestamp)
	if len(data) >= 13 {
		entryType := binary.BigEndian.Uint16(data[8:10])
		if entryType == 0 { // x509_entry
			certLen := int(data[10])<<16 | int(data[11])<<8 | int(data[12])
			if certLen > 0 && len(data) >= 13+certLen {
				if fastExtractDomainsFromCert(data[13:13+certLen], emit) {
					return
				}
			}
		} else if entryType == 1 && len(data) >= 45 { // precert_entry
			tbsLen := int(data[42])<<16 | int(data[43])<<8 | int(data[44])
			if tbsLen > 0 && len(data) >= 45+tbsLen {
				if fastExtractDomainsFromTBS(data[45:45+tbsLen], emit) {
					return
				}
			}
		}
	}

	// 3. Try raw X.509 Certificate DER
	if fastExtractDomainsFromCert(data, emit) {
		return
	}

	// 4. Try raw TBSCertificate DER
	_ = fastExtractDomainsFromTBS(data, emit)
}
