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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o sumdb.wasm ."

// Package main implements the SumDB WASM MapFn plugin.
package main

import (
	"bytes"
	"unsafe"

	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
	"golang.org/x/mod/module"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapSumDBLeaf)
}

var goModSuffix = []byte("/go.mod")

// MapSumDBLeaf parses a Go SumDB log leaf, filtering pseudo-versions and streaming canonical module path preimages.
func MapSumDBLeaf(data []byte, emit func(key []byte)) {
	var emitted [8][]byte
	n := 0
	var overflow [][]byte

	for len(data) > 0 {
		var line []byte
		idx := bytes.IndexByte(data, '\n')
		if idx >= 0 {
			line = data[:idx]
			data = data[idx+1:]
		} else {
			line = data
			data = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		modEnd := bytes.IndexByte(line, ' ')
		if modEnd <= 0 {
			continue
		}
		rawModPath := line[:modEnd]

		verStart := modEnd + 1
		if verStart >= len(line) {
			continue
		}
		verLen := bytes.IndexByte(line[verStart:], ' ')
		var verBytes []byte
		if verLen == -1 {
			verBytes = line[verStart:]
		} else {
			verBytes = line[verStart : verStart+verLen]
		}
		verBytes = bytes.TrimSuffix(verBytes, goModSuffix)

		// Fast zero-allocation pseudo-version filter
		if isPseudoVersion(verBytes) {
			continue
		}

		var modPath []byte
		if isSimpleLowercaseModulePath(rawModPath) {
			modPath = rawModPath
		} else {
			escaped, err := module.EscapePath(unsafe.String(unsafe.SliceData(rawModPath), len(rawModPath)))
			if err != nil || len(escaped) == 0 {
				continue
			}
			modPath = unsafe.Slice(unsafe.StringData(escaped), len(escaped))
		}
		if len(modPath) == 0 || len(modPath) > 1024 {
			continue
		}

		duplicate := false
		for i := 0; i < n; i++ {
			if bytes.Equal(emitted[i], modPath) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			for _, ov := range overflow {
				if bytes.Equal(ov, modPath) {
					duplicate = true
					break
				}
			}
		}
		if !duplicate {
			if n < len(emitted) {
				emitted[n] = modPath
				n++
			} else {
				overflow = append(overflow, modPath)
			}
			emit(modPath)
		}
	}
}

// isPseudoVersion reports whether v is a Go module pseudo-version without heap allocations.
// Pattern: ^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$
func isPseudoVersion(v []byte) bool {
	if len(v) < 30 || v[0] != 'v' {
		return false
	}

	// 1. Strip build metadata (+...)
	if idx := bytes.IndexByte(v, '+'); idx != -1 {
		build := v[idx+1:]
		if len(build) == 0 {
			return false
		}
		for _, b := range build {
			if !isIdentChar(b) && b != '.' {
				return false
			}
		}
		v = v[:idx]
	}

	// 2. Must contain at least two dashes: <base>-<timestamp>-<rev>
	lastDash := bytes.LastIndexByte(v, '-')
	if lastDash == -1 {
		return false
	}
	rev := v[lastDash+1:]
	if len(rev) == 0 {
		return false
	}
	for _, b := range rev {
		if !isAlnum(b) {
			return false
		}
	}

	rest := v[:lastDash]
	secondDash := bytes.LastIndexByte(rest, '-')
	if secondDash == -1 {
		return false
	}

	var timestamp []byte
	var prefix []byte

	dotAfterDash := bytes.LastIndexByte(rest[secondDash:], '.')
	if dotAfterDash != -1 {
		dotPos := secondDash + dotAfterDash
		timestamp = rest[dotPos+1:]
		prefix = rest[:dotPos]
	} else {
		timestamp = rest[secondDash+1:]
		prefix = rest[:secondDash]
	}

	if len(timestamp) != 14 {
		return false
	}
	for _, b := range timestamp {
		if b < '0' || b > '9' {
			return false
		}
	}

	// 3. Validate prefix
	if dotAfterDash == -1 {
		// Form 1: vX.0.0
		return isMajorDotZeroDotZero(prefix)
	}

	// Form 2-5: vX.Y.Z-0 or vX.Y.Z-pre.0
	if !bytes.HasSuffix(prefix, []byte(".0")) && !bytes.HasSuffix(prefix, []byte("-0")) {
		return false
	}

	dashIdx := bytes.IndexByte(prefix, '-')
	if dashIdx == -1 {
		return false
	}
	base := prefix[:dashIdx]
	return isBaseSemver(base)
}

func isMajorDotZeroDotZero(s []byte) bool {
	if len(s) < 6 || s[0] != 'v' || !bytes.HasSuffix(s, []byte(".0.0")) {
		return false
	}
	major := s[1 : len(s)-4]
	if len(major) == 0 {
		return false
	}
	if len(major) > 1 && major[0] == '0' {
		return false
	}
	for _, b := range major {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func isBaseSemver(s []byte) bool {
	if len(s) < 6 || s[0] != 'v' {
		return false
	}
	s = s[1:]
	dot1 := bytes.IndexByte(s, '.')
	if dot1 <= 0 {
		return false
	}
	major := s[:dot1]
	if len(major) > 1 && major[0] == '0' {
		return false
	}
	for _, b := range major {
		if b < '0' || b > '9' {
			return false
		}
	}

	s = s[dot1+1:]
	dot2 := bytes.IndexByte(s, '.')
	if dot2 <= 0 {
		return false
	}
	minor := s[:dot2]
	if len(minor) > 1 && minor[0] == '0' {
		return false
	}
	for _, b := range minor {
		if b < '0' || b > '9' {
			return false
		}
	}

	patch := s[dot2+1:]
	if len(patch) == 0 {
		return false
	}
	if len(patch) > 1 && patch[0] == '0' {
		return false
	}
	for _, b := range patch {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentChar(b byte) bool {
	return isAlnum(b) || b == '-'
}

func isSimpleLowercaseModulePath(p []byte) bool {
	if len(p) == 0 || p[0] == '/' || p[len(p)-1] == '/' || p[len(p)-1] == '.' {
		return false
	}
	hasDotInFirstElem := false
	inFirstElem := true
	segStart := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			if i == segStart || p[i-1] == '.' {
				return false
			}
			inFirstElem = false
			segStart = i + 1
			continue
		}
		if c == '.' {
			if i == segStart || (i+1 < len(p) && p[i+1] == '.') {
				return false
			}
			if inFirstElem {
				hasDotInFirstElem = true
			}
			continue
		}
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return hasDotInFirstElem
}
