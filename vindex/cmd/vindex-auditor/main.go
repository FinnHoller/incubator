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

// vindex-auditor is the dedicated standalone Verifiable Index auditor and verifier.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	outputLogURL      = flag.String("output_log_url", "", "Base URL of Output Log to verify (required).")
	outputLogPolicy   = flag.String("output_log_policy", "", "Path to C2SP tlog-policy file for Output Log checkpoint verification.")
	outputLogPubKey   = flag.String("output_log_pubkey", "", "Public key or key file for Output Log checkpoint verification.")
	outputLogOrigin   = flag.String("output_log_origin", "example.com/vindex/output", "Origin string for Output Log.")
	witnessPubKeys    = flag.String("witness_pubkeys", "", "Comma-separated list of witness verifier public keys for Output Log checkpoint verification.")
	witnessThreshold  = flag.Int("witness_threshold", 0, "Required witness signature quorum threshold for Output Log (0 = all --witness_pubkeys).")
	inputLogURL       = flag.String("input_log_url", "", "Base URL of the Input Log (required).")
	inputLogPolicy    = flag.String("input_log_policy", "", "Path to C2SP tlog-policy file for Input Log checkpoint verification.")
	inputLogPubKey    = flag.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification.")
	inputLogOrigin    = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	dbPath            = flag.String("db_path", "", "NVMe path for Pebble DB (Disk A) (required).")
	mptDir            = flag.String("mpt_dir", "", "Isolated NVMe path for MPT mmap files (Disk B) (required).")
	wasmPath          = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary.")
	mapper            = flag.String("mapper", "identity", "Leaf mapper implementation: identity, ct, or sumdb.")
	metricsAddr       = flag.String("metrics_addr", ":9090", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof.")
	chunkSize         = flag.Uint64("chunk_size", 65536, "Logical chunk size.")
	commitBatchSize   = flag.Uint64("commit_batch_size", 4096, "Number of leaves accumulated per batch commit.")
	tileCacheDir      = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval      = flag.Duration("poll_interval", 10*time.Second, "Polling interval for new Output Log checkpoints.")
	oneShot           = flag.Bool("oneshot", false, "Run verification once against log tip and exit.")
	fromFlag          = flag.Uint64("from", 0, "Expected starting Input Log leaf index (from) in Output Log leaves.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("vindex-auditor failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *outputLogURL == "" {
		return errors.New("--output_log_url is required")
	}
	if *inputLogURL == "" {
		return errors.New("--input_log_url is required")
	}
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}
	if *mptDir == "" {
		return errors.New("--mpt_dir flag is required")
	}

	resolvedInPubKey, err := resolveKey(*inputLogPubKey)
	if err != nil {
		return fmt.Errorf("failed to resolve input log pubkey: %w", err)
	}
	resolvedOutPubKey, err := resolveKey(*outputLogPubKey)
	if err != nil {
		return fmt.Errorf("failed to resolve output log pubkey: %w", err)
	}

	var witnessVerifiers []note.Verifier
	for _, wk := range splitNonEmptyCSV(*witnessPubKeys) {
		wv, err := wire.ParseWitnessVerifier(wk)
		if err != nil {
			return fmt.Errorf("failed to parse witness verifier %q: %w", wk, err)
		}
		witnessVerifiers = append(witnessVerifiers, wv)
	}
	threshold := *witnessThreshold
	if threshold == 0 {
		threshold = len(witnessVerifiers)
	}

	var inPolicy wire.Policy
	if strings.TrimSpace(*inputLogPolicy) != "" || resolvedInPubKey != "" {
		inOrigin := strings.TrimSpace(*inputLogOrigin)
		if inOrigin == "" && strings.TrimSpace(*inputLogPolicy) == "" {
			if v, err := wire.ParseVerifier(resolvedInPubKey); err == nil {
				inOrigin = v.Name()
			}
		}
		p, err := wire.ParsePolicyOrVerifier(*inputLogPolicy, resolvedInPubKey, inOrigin, nil, 0)
		if err != nil {
			return fmt.Errorf("failed to build input log policy: %w", err)
		}
		inPolicy = p
	}

	var outPolicy wire.Policy
	if strings.TrimSpace(*outputLogPolicy) != "" || resolvedOutPubKey != "" {
		outOrigin := strings.TrimSpace(*outputLogOrigin)
		if outOrigin == "" && strings.TrimSpace(*outputLogPolicy) == "" {
			if v, err := wire.ParseVerifier(resolvedOutPubKey); err == nil {
				outOrigin = v.Name()
			}
		}
		p, err := wire.ParsePolicyOrVerifier(*outputLogPolicy, resolvedOutPubKey, outOrigin, witnessVerifiers, threshold)
		if err != nil {
			return fmt.Errorf("failed to build output log policy: %w", err)
		}
		outPolicy = p
	}

	leafMapper, closeMapper, err := initMapper(ctx, *wasmPath, *mapper)
	if err != nil {
		return err
	}
	if closeMapper != nil {
		defer closeMapper()
	}

	cfg := auditor.Config{
		InputLogURL:     *inputLogURL,
		InputLogPubKey:  resolvedInPubKey,
		InputLogOrigin:  *inputLogOrigin,
		InputLogPolicy:  inPolicy,
		OutputLogURL:    *outputLogURL,
		OutputLogPubKey: resolvedOutPubKey,
		OutputLogOrigin: *outputLogOrigin,
		OutputLogPolicy: outPolicy,
		MapFn:           leafMapper,
		DBPath:          *dbPath,
		MPTDir:          *mptDir,
		TileCacheDir:    *tileCacheDir,
		MetricsAddr:     *metricsAddr,
		PollInterval:    *pollInterval,
		ChunkSize:       *chunkSize,
		CommitBatchSize: *commitBatchSize,
	}
	if isFlagPassed("from") {
		fromVal := *fromFlag
		cfg.ExpectedFrom = &fromVal
	}

	v, err := auditor.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize auditor engine: %w", err)
	}
	defer func() { _ = v.Close() }()

	if *oneShot {
		klog.Info("Running oneshot verification...")
		if err := v.VerifyOnce(ctx); err != nil {
			return fmt.Errorf("oneshot verification failed: %w", err)
		}
		klog.Info("Oneshot verification succeeded.")
		return nil
	}

	klog.Infof("Starting auditor daemon (poll interval: %v)...", *pollInterval)
	return v.Run(ctx)
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func splitNonEmptyCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func resolveKey(keyOrPath string) (string, error) {
	keyOrPath = strings.TrimSpace(keyOrPath)
	if keyOrPath == "" {
		return "", nil
	}
	if data, err := os.ReadFile(keyOrPath); err == nil {
		return string(bytes.TrimSpace(data)), nil
	}
	return keyOrPath, nil
}

func initMapper(ctx context.Context, wasm, mapperName string) (ingest.LeafMapper, func(), error) {
	if wasm != "" {
		wasmBytes, err := os.ReadFile(wasm)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read WASM binary %q: %w", wasm, err)
		}
		host, err := wasmhost.NewWASMHost(ctx, wasmBytes, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize WASM host: %w", err)
		}
		return host, func() { _ = host.Close(ctx) }, nil
	}

	switch strings.ToLower(mapperName) {
	case "sumdb":
		return &sumdbLeafMapper{}, nil, nil
	case "ct":
		return &ctLeafMapper{}, nil, nil
	case "identity", "":
		return &defaultIdentityMapper{}, nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown mapper %q (expected identity, ct, sumdb)", mapperName)
	}
}

type defaultIdentityMapper struct{}

func (m *defaultIdentityMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	trimmed := bytes.TrimSpace(leaf)
	var key string
	if mpt.ValidateCanonicalKey(trimmed) == nil {
		key = string(trimmed)
	}
	kh := sha256.Sum256(trimmed)
	return []ingest.MappedEntry{{Key: key, KeyHash: kh}}, nil
}

func (m *defaultIdentityMapper) Close(_ context.Context) error { return nil }

type ctLeafMapper struct{}

func (m *ctLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	seen := make(map[string]struct{})
	var entries []ingest.MappedEntry
	addDomain := func(d string) {
		key, ok := mtc.CanonicalizeDomain(d)
		if !ok {
			return
		}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			entries = append(entries, ingest.MappedEntry{
				Key:     key,
				KeyHash: sha256.Sum256([]byte(key)),
			})
		}
	}

	// RFC 6962 binary MerkleTreeLeaf (version == 0, leaf_type == 0)
	if len(leaf) >= 15 && leaf[0] == 0 && leaf[1] == 0 {
		entryType := uint16(leaf[10])<<8 | uint16(leaf[11])
		switch entryType {
		case 0: // X509Entry
			certLen := int(leaf[12])<<16 | int(leaf[13])<<8 | int(leaf[14])
			if certLen > 0 && 15+certLen <= len(leaf) {
				if cert, err := x509.ParseCertificate(leaf[15 : 15+certLen]); err == nil {
					if cert.Subject.CommonName != "" {
						addDomain(cert.Subject.CommonName)
					}
					for _, dns := range cert.DNSNames {
						addDomain(dns)
					}
				}
			}
		case 1: // PrecertEntry (32B issuer_key_hash + 3B length + TBSCertificate)
			if len(leaf) >= 12+32+3 {
				tbsOff := 12 + 32
				tbsLen := int(leaf[tbsOff])<<16 | int(leaf[tbsOff+1])<<8 | int(leaf[tbsOff+2])
				if tbsLen > 0 && tbsOff+3+tbsLen <= len(leaf) {
					extractPrecertTBSDomains(leaf[tbsOff+3:tbsOff+3+tbsLen], addDomain)
				}
			}
		}
		return entries, nil
	}

	// Plaintext domain lines (used by synthetic CLI/E2E tests)
	for _, b := range leaf {
		if b != '\n' && b != '\r' && (b < 0x20 || b > 0x7E) {
			return nil, nil
		}
	}
	lines := strings.Split(string(leaf), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		addDomain(line)
	}
	return entries, nil
}

func (m *ctLeafMapper) Close(_ context.Context) error { return nil }

type precertTBSCertificate struct {
	Version      int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber asn1.RawValue
	Signature    asn1.RawValue
	Issuer       asn1.RawValue
	Validity     asn1.RawValue
	Subject      pkix.RDNSequence
	PublicKey    asn1.RawValue
	UniqueId     asn1.BitString   `asn1:"optional,tag:1"`
	SubjectId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions   []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func extractPrecertTBSDomains(tbsBytes []byte, emit func(string)) {
	var tbs precertTBSCertificate
	if _, err := asn1.Unmarshal(tbsBytes, &tbs); err != nil {
		return
	}
	var subj pkix.Name
	subj.FillFromRDNSequence(&tbs.Subject)
	if subj.CommonName != "" {
		emit(subj.CommonName)
	}
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}
	for _, ext := range tbs.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		var seq []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			continue
		}
		for _, raw := range seq {
			if raw.Class == 2 && raw.Tag == 2 {
				emit(string(raw.Bytes))
			}
		}
	}
}

type sumdbLeafMapper struct{}

func (m *sumdbLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	return mapSumDBLeaf(leaf), nil
}

func (m *sumdbLeafMapper) MapBundle(_ context.Context, leaves [][]byte) ([][]ingest.MappedEntry, error) {
	results := make([][]ingest.MappedEntry, len(leaves))
	for i, leaf := range leaves {
		results[i] = mapSumDBLeaf(leaf)
	}
	return results, nil
}

func (m *sumdbLeafMapper) Close(_ context.Context) error { return nil }

func mapSumDBLeaf(data []byte) []ingest.MappedEntry {
	var results []ingest.MappedEntry

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
		verBytes = bytes.TrimSuffix(verBytes, []byte("/go.mod"))
		if isPseudoVersion(verBytes) {
			continue
		}

		escaped, err := module.EscapePath(string(rawModPath))
		if err != nil || escaped == "" || len(escaped) > 1024 {
			continue
		}

		h := sha256.Sum256([]byte(escaped))
		duplicate := false
		for i := range results {
			if results[i].KeyHash == h {
				duplicate = true
				break
			}
		}
		if !duplicate {
			results = append(results, ingest.MappedEntry{
				Key:     escaped,
				KeyHash: h,
			})
		}
	}

	return results
}

func isPseudoVersion(v []byte) bool {
	if len(v) < 30 || v[0] != 'v' {
		return false
	}
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
	dashIdx := bytes.LastIndexByte(v, '-')
	if dashIdx == -1 || dashIdx < 16 {
		return false
	}
	rev := v[dashIdx+1:]
	if len(rev) == 0 {
		return false
	}
	for _, b := range rev {
		if !isIdentChar(b) {
			return false
		}
	}
	tsStart := dashIdx - 14
	ts := v[tsStart:dashIdx]
	for _, b := range ts {
		if b < '0' || b > '9' {
			return false
		}
	}
	prefix := v[:tsStart]
	i := 1
	for i < len(prefix) && prefix[i] >= '0' && prefix[i] <= '9' {
		i++
	}
	if i == 1 || i >= len(prefix) || prefix[i] != '.' {
		return false
	}
	rest := prefix[i+1:]
	if bytes.Equal(rest, []byte("0.0-")) {
		return true
	}
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 || j >= len(rest) || rest[j] != '.' {
		return false
	}
	k := j + 1
	for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
		k++
	}
	if k == j+1 || k >= len(rest) || rest[k] != '-' {
		return false
	}
	afterPatchDash := rest[k+1:]
	if bytes.Equal(afterPatchDash, []byte("0.")) {
		return true
	}
	if !bytes.HasSuffix(afterPatchDash, []byte(".0.")) {
		return false
	}
	pre := afterPatchDash[:len(afterPatchDash)-3]
	if len(pre) == 0 {
		return false
	}
	for _, b := range pre {
		if b == '+' {
			return false
		}
	}
	return true
}

func isIdentChar(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '-'
}
