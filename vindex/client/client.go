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

// Package client provides a lightweight verification library and HTTP client for VIndex.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// CheckpointPolicy is an alias for wire.Policy.
type CheckpointPolicy = wire.Policy

// KeyValueRoot is an alias for wire.KeyValueRoot.
type KeyValueRoot = wire.KeyValueRoot

var (
	ErrVerificationFailed = errors.New("vindex: verification failed")
	ErrBadRequest         = errors.New("vindex: bad request")
	ErrTooManyKeys        = errors.New("vindex: prefix matched too many keys")
	ErrUnavailable        = errors.New("vindex: server unavailable")
)

const maxResponseBodyBytes = 32 << 20 // 32 MiB

// Config holds the Output Log verification policy and expected log origins for a VIndex Client.
type Config struct {
	ExpectedOutputLogOrigin string
	OutputLogPolicy         CheckpointPolicy
	ExpectedInputLogOrigin  string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient configures the underlying *http.Client used by the Client.
// The supplied *http.Client is shallow-copied so its CheckRedirect hook can reject 3xx redirects without mutating the caller's client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// SingleKeyPolicy constructs an origin-bound single-key CheckpointPolicy.
func SingleKeyPolicy(origin string, v note.Verifier) (CheckpointPolicy, error) {
	return wire.BuildPolicy(origin, v, nil, 0)
}

// WitnessPolicy constructs an origin-bound CheckpointPolicy requiring the primary log signature
// plus at least threshold distinct witness cosignatures.
func WitnessPolicy(origin string, v note.Verifier, witnesses []note.Verifier, threshold int) (CheckpointPolicy, error) {
	return wire.BuildPolicy(origin, v, witnesses, threshold)
}

// LookupResult represents a cryptographically verified snapshot-scoped response from LookupKey or LookupPrefix.
type LookupResult struct {
	OutputSize  uint64
	OutputRoot  [sha256.Size]byte
	InputOrigin string
	From        uint64
	InputSize   uint64
	InputRoot   [sha256.Size]byte
	MPTRoot     [sha256.Size]byte
	Keys        []MatchedKey // 0..1 for LookupKey; 0..N (lexicographically sorted) for LookupPrefix
}

// MatchedKey represents a single key and its authenticated Value Log Merkle root within a LookupResult snapshot.
type MatchedKey struct {
	Key       string
	ValueRoot [sha256.Size]byte

	client    *Client
	from      uint64
	inputSize uint64
}

// Values streams verified Input Log entry indices in [from, inputSize) for k in descending order (newest-first).
// Each /values page's RFC 6962 compact range root is verified against the expected ValueRoot before any entry index from that page is yielded.
func (k MatchedKey) Values(ctx context.Context) iter.Seq2[uint64, error] {
	return func(yield func(uint64, error) bool) {
		if k.client == nil || k.ValueRoot == ([sha256.Size]byte{}) || k.inputSize <= k.from {
			yield(0, fmt.Errorf("%w: uninitialized or invalid MatchedKey for %q", ErrVerificationFailed, k.Key))
			return
		}

		before := k.inputSize
		expectedValueRoot := k.ValueRoot

		for {
			page, err := k.client.fetchValuesPage(ctx, k.Key, expectedValueRoot, k.from, before)
			if err != nil {
				yield(0, err)
				return
			}

			for i := len(page.Indices) - 1; i >= 0; i-- {
				if !yield(page.Indices[i], nil) {
					return
				}
			}

			nextBefore, nextRoot, ok := page.NextPage()
			if !ok {
				return
			}
			before = nextBefore
			expectedValueRoot = nextRoot
		}
	}
}

// ValuesResponse represents a verified single page from GET <index-url>/values?key=<key>&before=<before>.
type ValuesResponse struct {
	Preceding    uint64
	CompactRange [][sha256.Size]byte
	Indices      []uint64
	ValueRoot    [sha256.Size]byte
}

// NextPage folds CompactRange right-to-left when Preceding > 0, returning the next exclusive
// upper bound (Indices[0]) and expected value log root for backward pagination.
func (r *ValuesResponse) NextPage() (before uint64, expectedValueRoot [sha256.Size]byte, ok bool) {
	if r == nil || r.Preceding == 0 || len(r.Indices) == 0 {
		return 0, [sha256.Size]byte{}, false
	}
	vr, err := wire.ComputeValueLogRoot(r.CompactRange, r.Preceding, nil)
	if err != nil {
		return 0, [sha256.Size]byte{}, false
	}
	return r.Indices[0], vr, true
}

// VerifyKeysResponse verifies a raw response body from GET <index-url>/keys?key=<target> or ?prefix=<target>.
// It is a pure, stateless function that performs zero network I/O or state mutations.
func VerifyKeysResponse(rawBody []byte, target string, isPrefix bool, cfg Config) (*LookupResult, error) {
	if err := mpt.ValidateCanonicalKey([]byte(target)); err != nil {
		if isPrefix {
			return nil, fmt.Errorf("%w: invalid query prefix %q: %w", ErrBadRequest, target, err)
		}
		return nil, fmt.Errorf("%w: invalid query key %q: %w", ErrBadRequest, target, err)
	}
	if cfg.ExpectedOutputLogOrigin == "" {
		return nil, fmt.Errorf("%w: expected output log origin is required", ErrVerificationFailed)
	}
	if cfg.OutputLogPolicy == nil {
		return nil, fmt.Errorf("%w: output log policy is required", ErrVerificationFailed)
	}
	if err := wire.ValidateInputOrigin(cfg.ExpectedInputLogOrigin); err != nil {
		return nil, fmt.Errorf("%w: invalid expected input log origin: %w", ErrVerificationFailed, err)
	}

	stanzas := bytes.SplitN(rawBody, []byte("\n\n"), 2)
	if len(stanzas) != 2 {
		return nil, fmt.Errorf("%w: keys response must contain keys block and proof block", ErrVerificationFailed)
	}

	keysSec, err := wire.ParseKeysSection(stanzas[0])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse keys section: %w", ErrVerificationFailed, err)
	}
	bindSec, err := wire.ParseBindingSection(stanzas[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse binding section: %w", ErrVerificationFailed, err)
	}

	outCP, err := cfg.OutputLogPolicy.Verify(bindSec.OutSignedCP)
	if err != nil {
		return nil, fmt.Errorf("%w: output log checkpoint verification failed: %w", ErrVerificationFailed, err)
	}
	if outCP.Origin != cfg.ExpectedOutputLogOrigin {
		return nil, fmt.Errorf("%w: output log origin %q != expected %q", ErrVerificationFailed, outCP.Origin, cfg.ExpectedOutputLogOrigin)
	}
	if outCP.Size < 1 {
		return nil, fmt.Errorf("%w: output log checkpoint size is %d, want >= 1", ErrVerificationFailed, outCP.Size)
	}
	outputSize := outCP.Size
	if bindSec.OutLeafIdx != outputSize-1 {
		return nil, fmt.Errorf("%w: output log leaf index %d != output_size - 1 (%d)", ErrVerificationFailed, bindSec.OutLeafIdx, outputSize-1)
	}

	leafHash := rfc6962.DefaultHasher.HashLeaf(bindSec.RawOutLeaf)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, bindSec.OutLeafIdx, outputSize, leafHash, bindSec.InclusionProof, outCP.Hash); err != nil {
		return nil, fmt.Errorf("%w: output log inclusion proof invalid: %w", ErrVerificationFailed, err)
	}

	if bindSec.InputOrigin != cfg.ExpectedInputLogOrigin {
		return nil, fmt.Errorf("%w: state commitment input-origin %q != expected %q", ErrVerificationFailed, bindSec.InputOrigin, cfg.ExpectedInputLogOrigin)
	}
	inputSize := bindSec.InputSize
	if bindSec.From > inputSize {
		return nil, fmt.Errorf("%w: state commitment from (%d) exceeds input_size (%d)", ErrVerificationFailed, bindSec.From, inputSize)
	}
	if inputSize == bindSec.From && len(keysSec.Matches) > 0 {
		return nil, fmt.Errorf("%w: matched keys returned when input_size (%d) == from (%d)", ErrVerificationFailed, inputSize, bindSec.From)
	}

	var outRoot [sha256.Size]byte
	copy(outRoot[:], outCP.Hash)
	inRoot := bindSec.InputRoot
	mptRoot := bindSec.MPTRoot
	mptProofBytes := keysSec.MPTProof
	keys := keysSec.Matches

	if !isPrefix {
		if len(keys) == 0 {
			if err := mpt.VerifyKey(mptRoot, []byte(target), [sha256.Size]byte{}, false, mptProofBytes); err != nil {
				return nil, fmt.Errorf("%w: non-inclusion proof verification failed: %w", ErrVerificationFailed, err)
			}
			return &LookupResult{
				OutputSize:  outputSize,
				OutputRoot:  outRoot,
				InputOrigin: bindSec.InputOrigin,
				From:        bindSec.From,
				InputSize:   inputSize,
				InputRoot:   inRoot,
				MPTRoot:     mptRoot,
				Keys:        nil,
			}, nil
		}
		if len(keys) > 1 {
			return nil, fmt.Errorf("%w: point lookup returned %d keys", ErrVerificationFailed, len(keys))
		}
		if keys[0].Key != target {
			return nil, fmt.Errorf("%w: inclusion response must contain matching key %q, got %q", ErrVerificationFailed, target, keys[0].Key)
		}
		if err := mpt.VerifyKey(mptRoot, []byte(target), keys[0].ValueRoot, true, mptProofBytes); err != nil {
			return nil, fmt.Errorf("%w: inclusion proof verification failed: %w", ErrVerificationFailed, err)
		}
		return &LookupResult{
			OutputSize:  outputSize,
			OutputRoot:  outRoot,
			InputOrigin: bindSec.InputOrigin,
			From:        bindSec.From,
			InputSize:   inputSize,
			InputRoot:   inRoot,
			MPTRoot:     mptRoot,
			Keys: []MatchedKey{{
				Key:       keys[0].Key,
				ValueRoot: keys[0].ValueRoot,
				from:      bindSec.From,
				inputSize: inputSize,
			}},
		}, nil
	}

	if err := mpt.VerifyPrefix(mptRoot, []byte(target), keys, mptProofBytes); err != nil {
		return nil, fmt.Errorf("%w: prefix proof verification failed: %w", ErrVerificationFailed, err)
	}
	var matched []MatchedKey
	if len(keys) > 0 {
		matched = make([]MatchedKey, len(keys))
		for i, kv := range keys {
			matched[i] = MatchedKey{
				Key:       kv.Key,
				ValueRoot: kv.ValueRoot,
				from:      bindSec.From,
				inputSize: inputSize,
			}
		}
	}
	return &LookupResult{
		OutputSize:  outputSize,
		OutputRoot:  outRoot,
		InputOrigin: bindSec.InputOrigin,
		From:        bindSec.From,
		InputSize:   inputSize,
		InputRoot:   inRoot,
		MPTRoot:     mptRoot,
		Keys:        matched,
	}, nil
}

// VerifyValuesResponse verifies a raw response body from GET <index-url>/values?key=<key>&before=<before>
// against expectedValueRoot and the range [from, before).
// It is a pure, stateless function that performs zero network I/O or state mutations.
func VerifyValuesResponse(rawBody []byte, expectedValueRoot [sha256.Size]byte, from, before uint64) (*ValuesResponse, error) {
	if expectedValueRoot == ([sha256.Size]byte{}) {
		return nil, fmt.Errorf("%w: VerifyValuesResponse requires a non-zero expectedValueRoot", ErrVerificationFailed)
	}
	if before == 0 || from > before {
		return nil, fmt.Errorf("%w: invalid range [%d, %d)", ErrVerificationFailed, from, before)
	}
	if from == before {
		return nil, fmt.Errorf("%w: empty range [%d, %d) cannot contain value entries", ErrVerificationFailed, from, before)
	}

	valSec, err := wire.ParseValuesResponse(rawBody)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse values response: %w", ErrVerificationFailed, err)
	}
	if len(valSec.Indices) == 0 {
		return nil, fmt.Errorf("%w: values response must contain at least one index", ErrVerificationFailed)
	}

	for i := 1; i < len(valSec.Indices); i++ {
		if valSec.Indices[i] <= valSec.Indices[i-1] {
			return nil, fmt.Errorf("%w: index[%d]=%d <= index[%d]=%d", ErrVerificationFailed, i, valSec.Indices[i], i-1, valSec.Indices[i-1])
		}
	}

	if valSec.Indices[0] < from {
		return nil, fmt.Errorf("%w: first index %d < from %d", ErrVerificationFailed, valSec.Indices[0], from)
	}
	if valSec.Indices[len(valSec.Indices)-1] >= before {
		return nil, fmt.Errorf("%w: index %d >= before %d", ErrVerificationFailed, valSec.Indices[len(valSec.Indices)-1], before)
	}
	if valSec.Preceding > valSec.Indices[0]-from {
		return nil, fmt.Errorf("%w: preceding count (%d) exceeds available range before first index (%d - %d); total entries exceed upperBound %d", ErrVerificationFailed, valSec.Preceding, valSec.Indices[0], from, before)
	}
	if uint64(len(valSec.Indices)) > before-from-valSec.Preceding {
		return nil, fmt.Errorf("%w: total entries (%d + %d) exceed available range [%d, %d)", ErrVerificationFailed, valSec.Preceding, len(valSec.Indices), from, before)
	}

	computedRoot, err := wire.ComputeValueLogRoot(valSec.CompactRange, valSec.Preceding, valSec.Indices)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to compute value log root: %w", ErrVerificationFailed, err)
	}
	if computedRoot != expectedValueRoot {
		return nil, fmt.Errorf("%w: value log root mismatch: got %x, want %x", ErrVerificationFailed, computedRoot, expectedValueRoot)
	}

	return &ValuesResponse{
		Preceding:    valSec.Preceding,
		CompactRange: valSec.CompactRange,
		Indices:      valSec.Indices,
		ValueRoot:    computedRoot,
	}, nil
}

const upperHex = "0123456789ABCDEF"

func isRFC3986Unreserved(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

func encodeRFC3986Unreserved(s string) string {
	var needsEncoding bool
	for i := 0; i < len(s); i++ {
		if !isRFC3986Unreserved(s[i]) {
			needsEncoding = true
			break
		}
	}
	if !needsEncoding {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isRFC3986Unreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0x0F])
		}
	}
	return b.String()
}

// Client performs cryptographically verified, stateless lookups against a VIndex HTTP endpoint.
type Client struct {
	baseURL    *url.URL
	cfg        Config
	httpClient *http.Client
}

// New creates a new VIndex Client targeting indexURL. HTTP redirects (3xx) are rejected per tlog-vindex.
func New(indexURL string, cfg Config, opts ...Option) (*Client, error) {
	u, err := url.Parse(indexURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid index URL %q: %w", ErrBadRequest, indexURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%w: index URL %q must use http or https with a non-empty host", ErrBadRequest, indexURL)
	}
	if cfg.ExpectedOutputLogOrigin == "" {
		return nil, fmt.Errorf("%w: ExpectedOutputLogOrigin is required", ErrBadRequest)
	}
	if cfg.OutputLogPolicy == nil {
		return nil, fmt.Errorf("%w: OutputLogPolicy is required", ErrBadRequest)
	}
	if err := wire.ValidateInputOrigin(cfg.ExpectedInputLogOrigin); err != nil {
		return nil, fmt.Errorf("%w: invalid ExpectedInputLogOrigin: %w", ErrBadRequest, err)
	}

	c := &Client{
		baseURL:    u,
		cfg:        cfg,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	clonedClient := *c.httpClient
	clonedClient.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("HTTP redirects (3xx) are forbidden by tlog-vindex spec (redirected to %q)", req.URL.String())
	}
	c.httpClient = &clonedClient
	return c, nil
}

func (c *Client) queryEndpointURL(routePath string) *url.URL {
	u := *c.baseURL
	basePath := strings.TrimSuffix(u.Path, "/")
	u.Path = basePath + routePath
	u.RawPath = ""
	return &u
}

func appendRawQuery(existing, param string) string {
	if existing == "" {
		return param
	}
	return existing + "&" + param
}

func mapKeysHTTPStatusError(statusCode int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	switch statusCode {
	case http.StatusBadRequest:
		return fmt.Errorf("%w: server returned status 400: %s", ErrBadRequest, msg)
	case http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w: server returned status 413: %s", ErrTooManyKeys, msg)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%w: server returned status 503: %s", ErrUnavailable, msg)
	default:
		return fmt.Errorf("server returned status %d: %s", statusCode, msg)
	}
}

func (c *Client) lookupKeys(ctx context.Context, target string, isPrefix bool) (*LookupResult, error) {
	if err := mpt.ValidateCanonicalKey([]byte(target)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	u := c.queryEndpointURL("/keys")
	if isPrefix {
		u.RawQuery = appendRawQuery(u.RawQuery, "prefix="+encodeRFC3986Unreserved(target))
	} else {
		u.RawQuery = appendRawQuery(u.RawQuery, "key="+encodeRFC3986Unreserved(target))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct keys request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read keys response body: %w", err)
	}
	if len(body) > maxResponseBodyBytes {
		return nil, fmt.Errorf("%w: keys response body exceeds %d bytes", ErrVerificationFailed, maxResponseBodyBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, mapKeysHTTPStatusError(resp.StatusCode, body)
	}

	res, err := VerifyKeysResponse(body, target, isPrefix, c.cfg)
	if err != nil {
		return nil, err
	}
	for i := range res.Keys {
		res.Keys[i].client = c
	}
	return res, nil
}

// LookupKey queries GET <index-url>/keys?key=<key> and verifies the state commitment and MPT proof.
func (c *Client) LookupKey(ctx context.Context, key string) (*LookupResult, error) {
	return c.lookupKeys(ctx, key, false)
}

// LookupPrefix queries GET <index-url>/keys?prefix=<prefix> and verifies the two-sided MPT prefix proof.
func (c *Client) LookupPrefix(ctx context.Context, prefix string) (*LookupResult, error) {
	return c.lookupKeys(ctx, prefix, true)
}

func (c *Client) fetchValuesPage(
	ctx context.Context,
	key string,
	expectedValueRoot [sha256.Size]byte,
	from, before uint64,
) (*ValuesResponse, error) {
	if err := mpt.ValidateCanonicalKey([]byte(key)); err != nil {
		return nil, fmt.Errorf("%w: invalid key %q: %w", ErrBadRequest, key, err)
	}
	if expectedValueRoot == ([sha256.Size]byte{}) {
		return nil, fmt.Errorf("%w: expectedValueRoot is required", ErrVerificationFailed)
	}
	if before == 0 || from >= before {
		return nil, fmt.Errorf("%w: invalid range [%d, %d)", ErrVerificationFailed, from, before)
	}

	u := c.queryEndpointURL("/values")
	rawQuery := "key=" + encodeRFC3986Unreserved(key) + "&before=" + strconv.FormatUint(before, 10)
	u.RawQuery = appendRawQuery(u.RawQuery, rawQuery)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct values request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read values response body: %w", err)
	}
	if len(body) > maxResponseBodyBytes {
		return nil, fmt.Errorf("%w: values response body exceeds %d bytes", ErrVerificationFailed, maxResponseBodyBytes)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: unexpected HTTP 404 on promised value log page for key %q (before=%d)", ErrVerificationFailed, key, before)
		}
		return nil, mapKeysHTTPStatusError(resp.StatusCode, body)
	}

	return VerifyValuesResponse(body, expectedValueRoot, from, before)
}
