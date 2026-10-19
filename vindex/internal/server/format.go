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

package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

// FormatKeysResponse builds the plain-text C2SP response for GET /keys?key=<key> or ?prefix=<prefix>.
func FormatKeysResponse(state *tree.ServingState, mode string, proof []byte, matches []mpt.PrefixKeyVal) []byte {
	return wire.FormatKeysResponseFull(state.RawCheckpoint, state.OutputLogIndex, state.MPTRoot, state.From, state.InputLogCP, state.OutputLogProof, mode, proof, matches)
}

// FormatValuesResponse builds the plain-text C2SP response for GET /values?key=<key>&before=<before>.
func FormatValuesResponse(matchedIndices []uint64, prefixCR *kvstore.CompactRange, _ *uint64) []byte {
	var preceding uint64
	var hashes [][sha256.Size]byte
	if prefixCR != nil {
		preceding = prefixCR.Preceding
		hashes = prefixCR.Hashes
	}
	return wire.FormatValuesResponse(preceding, hashes, matchedIndices)
}

// PrefixPolicy validates whether a prefix query (?prefix=<prefix>) is permitted.
type PrefixPolicy func(prefix string) error

// AllowAllPrefixPolicy permits any valid canonical key prefix.
func AllowAllPrefixPolicy(_ string) error {
	return nil
}

// DisallowPrefixPolicy rejects all prefix queries.
func DisallowPrefixPolicy(prefix string) error {
	return fmt.Errorf("prefix queries are disabled on this server (prefix %q)", prefix)
}

// parseRFC3986Query parses a raw URL query string using strict RFC 3986 percent-decoding.
// Unlike url.ParseQuery, it rejects malformed %-escapes with an error and preserves literal '+' (0x2B) bytes.
func parseRFC3986Query(rawQuery string) (map[string][]string, error) {
	q := make(map[string][]string)
	if rawQuery == "" {
		return q, nil
	}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			return nil, errors.New("empty query parameter segment")
		}
		rawName, rawVal, _ := strings.Cut(part, "=")
		if rawName == "" {
			return nil, errors.New("empty query parameter name")
		}
		name, err := url.PathUnescape(rawName)
		if err != nil {
			return nil, fmt.Errorf("invalid percent-encoding in query parameter name: %w", err)
		}
		val, err := url.PathUnescape(rawVal)
		if err != nil {
			return nil, fmt.Errorf("invalid percent-encoding in query parameter %q: %w", name, err)
		}
		q[name] = append(q[name], val)
	}
	return q, nil
}

func parseKeysQuery(r *http.Request) (string, bool, error) {
	q, err := parseRFC3986Query(r.URL.RawQuery)
	if err != nil {
		return "", false, err
	}
	for k := range q {
		if k != "key" && k != "prefix" {
			return "", false, fmt.Errorf("unknown query parameter %q", k)
		}
	}
	keys, hasKey := q["key"]
	prefixes, hasPrefix := q["prefix"]
	if hasKey && hasPrefix {
		return "", false, errors.New("cannot specify both key and prefix parameters")
	}
	if len(keys) > 1 || len(prefixes) > 1 {
		return "", false, errors.New("duplicate key or prefix parameter not allowed")
	}
	var keyStr string
	var isPrefix bool
	switch {
	case hasPrefix:
		keyStr = prefixes[0]
		isPrefix = true
	case hasKey:
		keyStr = keys[0]
		isPrefix = false
	default:
		return "", false, errors.New("missing key or prefix parameter")
	}
	if err := mpt.ValidateCanonicalKey([]byte(keyStr)); err != nil {
		return "", false, err
	}
	return keyStr, isPrefix, nil
}

func extractCanonicalKey(q map[string][]string) (string, error) {
	keys, hasKey := q["key"]
	if len(keys) > 1 {
		return "", errors.New("duplicate key parameter not allowed")
	}
	if !hasKey {
		return "", errors.New("missing key parameter")
	}
	keyStr := keys[0]
	if err := mpt.ValidateCanonicalKey([]byte(keyStr)); err != nil {
		return "", err
	}
	return keyStr, nil
}
