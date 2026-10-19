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

// mtcverify queries and cryptographically verifies domain lookups in an MTC verifiable index.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"k8s.io/klog/v2"
)

var (
	vindexURL    = flag.String("vindex_url", "http://localhost:8088", "Base URL of the VIndex server")
	outLogPolicy = flag.String("out_log_policy", "", "Path to C2SP tlog-policy file for Output Log")
	outLogOrigin = flag.String("out_log_origin", "MTCIndex", "Expected origin for Output Log")
	outLogPubKey = flag.String("out_log_pubkey", "", "Public key note verifier string for Output Log")
	inLogOrigin  = flag.String("in_log_origin", "bootstrap-mtca.cloudflareresearch.com/logs/shard3", "Expected origin for Input Log")
	domain       = flag.String("domain", "", "Domain name to search and verify")
	prefixQuery  = flag.Bool("prefix", false, "Perform a prefix subtree lookup (?prefix=<domain>) for all subdomains under --domain")
	inLogURL     = flag.String("in_log_url", "", "Base URL of Input Log for dereferencing pointers (optional)")
	dereference  = flag.Bool("dereference", false, "Dereference and print original leaves from Input Log")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if *domain == "" {
		return errors.New("--domain must be specified")
	}
	if *vindexURL == "" {
		return errors.New("--vindex_url must be specified")
	}

	searchKey, ok := mtc.CanonicalizeDomain(*domain)
	if !ok {
		return fmt.Errorf("invalid domain %q", *domain)
	}

	var outPolicy client.CheckpointPolicy
	outOrigin := strings.TrimSpace(*outLogOrigin)
	if strings.TrimSpace(*outLogPolicy) != "" {
		var err error
		outPolicy, err = wire.ParsePolicyOrVerifier(*outLogPolicy, "", "", nil, 0)
		if err != nil {
			return fmt.Errorf("failed to parse output log policy: %w", err)
		}
	} else {
		if *outLogPubKey == "" {
			return errors.New("--out_log_policy or --out_log_pubkey must be specified")
		}
		outVerifier, err := wire.ParseVerifier(*outLogPubKey)
		if err != nil {
			return fmt.Errorf("failed to create output log verifier: %w", err)
		}
		if outOrigin == "" {
			outOrigin = outVerifier.Name()
		}
		outPolicy, err = client.SingleKeyPolicy(outOrigin, outVerifier)
		if err != nil {
			return fmt.Errorf("failed to create output log policy: %w", err)
		}
	}

	cfg := client.Config{
		ExpectedOutputLogOrigin: outOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  strings.TrimSpace(*inLogOrigin),
	}

	cli, err := client.New(*vindexURL, cfg, client.WithHTTPClient(http.DefaultClient))
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	if *prefixQuery {
		pResp, err := cli.LookupPrefix(ctx, searchKey)
		if err != nil {
			return fmt.Errorf("prefix lookup verification failed: %w", err)
		}
		fmt.Printf("Domain Prefix:  %s\n", *domain)
		fmt.Printf("Canonical Key:  %s\n", searchKey)
		fmt.Printf("Matched Keys:   %d\n", len(pResp.Keys))
		fmt.Printf("MPT Root:       %x\n", pResp.MPTRoot)
		fmt.Printf("Output Log Size:%d\n", pResp.OutputSize)
		fmt.Printf("Input Log Size: %d\n", pResp.InputSize)
		for _, kr := range pResp.Keys {
			var rev []uint64
			for idx, err := range kr.Values(ctx) {
				if err != nil {
					return fmt.Errorf("values lookup verification failed for key %q: %w", kr.Key, err)
				}
				rev = append(rev, idx)
			}
			indices := make([]uint64, len(rev))
			for i, v := range rev {
				indices[len(rev)-1-i] = v
			}
			fmt.Printf("  Key %s (%x): %v\n", kr.Key, kr.ValueRoot, indices)
		}
		return nil
	}

	keysResp, err := cli.LookupKey(ctx, searchKey)
	if err != nil {
		return fmt.Errorf("lookup verification failed: %w", err)
	}

	exists := len(keysResp.Keys) > 0
	fmt.Printf("Domain:         %s\n", *domain)
	fmt.Printf("Canonical Key:  %s\n", searchKey)
	fmt.Printf("Key Hash:       %x\n", sha256.Sum256([]byte(searchKey)))
	fmt.Printf("Exists:         %v\n", exists)
	fmt.Printf("MPT Root:       %x\n", keysResp.MPTRoot)
	fmt.Printf("Output Log Size:%d\n", keysResp.OutputSize)
	fmt.Printf("Input Log Size: %d\n", keysResp.InputSize)

	if !exists {
		fmt.Println("Domain not found in verifiable index (cryptographically verified non-inclusion).")
		return nil
	}

	var rev []uint64
	for idx, err := range keysResp.Keys[0].Values(ctx) {
		if err != nil {
			return fmt.Errorf("values lookup verification failed: %w", err)
		}
		rev = append(rev, idx)
	}
	indices := make([]uint64, len(rev))
	for i, v := range rev {
		indices[len(rev)-1-i] = v
	}

	fmt.Printf("Value Root:     %x\n", keysResp.Keys[0].ValueRoot)
	fmt.Printf("Verified leaf indices (%d):\n", len(indices))
	for _, idx := range indices {
		fmt.Printf("  - %d\n", idx)
	}

	if *dereference && *inLogURL != "" {
		fmt.Println("\nDereferencing verified leaves from Input Log:")
		for _, idx := range indices {
			leafData, err := ingest.FetchEntryByIndex(ctx, http.DefaultClient, *inLogURL, idx, keysResp.InputSize)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error fetching leaf at index %d: %v\n", idx, err)
				continue
			}
			if len(leafData) >= 2 && binary.BigEndian.Uint16(leafData[:2]) == 1 {
				entry, pErr := mtc.ParseTBSCertificateLogEntry(leafData[2:])
				if pErr == nil {
					dnsNames := mtc.ExtractDNSNames(entry)
					fmt.Printf("  [%d]: SANs: %v\n", idx, dnsNames)
					continue
				}
			}
			fmt.Printf("  [%d]: (raw leaf length: %d bytes)\n", idx, len(leafData))
		}
	}

	return nil
}
