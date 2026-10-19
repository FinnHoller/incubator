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

// vindex-client is a CLI client for looking up keys in a Verifiable Index with full cryptographic verification.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"k8s.io/klog/v2"
)

// prefixFlag supports both boolean mode (--prefix --key="foo") and string value mode (--prefix="foo").
type prefixFlag struct {
	enabled bool
	value   string
}

func (p *prefixFlag) IsBoolFlag() bool { return true }

func (p *prefixFlag) String() string {
	if p.value != "" {
		return p.value
	}
	if p.enabled {
		return "true"
	}
	return "false"
}

func (p *prefixFlag) Set(s string) error {
	switch strings.ToLower(s) {
	case "true":
		p.enabled = true
	case "false":
		p.enabled = false
		p.value = ""
	default:
		p.enabled = true
		p.value = s
	}
	return nil
}

var (
	vindexURL    = flag.String("vindex_url", "http://localhost:8080", "Base URL of the VIndex server.")
	key          = flag.String("key", "", "Canonical key (or prefix when --prefix is set) to search.")
	prefix       prefixFlag
	outLogPolicy = flag.String("out_log_policy", "", "Path to C2SP tlog-policy file for Output Log checkpoint verification.")
	outLogOrigin = flag.String("out_log_origin", "", "Expected origin for Output Log.")
	outLogPubKey = flag.String("out_log_pubkey", "", "Public key or key file for Output Log checkpoint verification.")
	inLogOrigin  = flag.String("in_log_origin", "", "Optional expected origin for Input Log.")
	fetchAll     = flag.Bool("all", false, "Fetch all matching indices across pages.")
	inLogURL     = flag.String("in_log_url", "", "Base URL of Input Log for dereferencing pointers.")
	dereference  = flag.Bool("dereference", false, "Dereference and print original leaves from Input Log.")
)

func init() {
	flag.Var(&prefix, "prefix", "Perform a prefix query (?prefix=<prefix>); accepts boolean (--prefix --key=...) or prefix string (--prefix=...).")
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	target := *key
	isPrefix := prefix.enabled
	if prefix.value != "" {
		if target != "" && target != prefix.value {
			return errors.New("cannot specify different values for --key and --prefix=<str>")
		}
		target = prefix.value
	} else if isPrefix && target == "" && flag.NArg() == 1 {
		target = flag.Arg(0)
	}
	if target == "" {
		return errors.New("must specify --key (or --prefix=<prefix>)")
	}

	if strings.TrimSpace(*outLogPolicy) == "" && strings.TrimSpace(*outLogPubKey) == "" {
		return errors.New("must specify --out_log_policy or --out_log_pubkey")
	}
	outOrigin := *outLogOrigin
	if outOrigin == "" && strings.TrimSpace(*outLogPolicy) == "" {
		if v, err := wire.ParseVerifier(*outLogPubKey); err == nil {
			outOrigin = v.Name()
		}
	}
	outPolicy, err := wire.ParsePolicyOrVerifier(*outLogPolicy, *outLogPubKey, outOrigin, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to build output log policy: %w", err)
	}

	cfg := client.Config{
		ExpectedOutputLogOrigin: outOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  *inLogOrigin,
	}

	cli, err := client.New(*vindexURL, cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	if isPrefix {
		keysResp, err := cli.LookupPrefix(ctx, target)
		if err != nil {
			return fmt.Errorf("prefix keys verification failed: %w", err)
		}
		fmt.Printf("Prefix:          %s\n", target)
		fmt.Printf("Matching Keys:   %d\n", len(keysResp.Keys))
		fmt.Printf("MPT Root:        %x\n", keysResp.MPTRoot)
		fmt.Printf("Output Log Size: %d\n", keysResp.OutputSize)
		fmt.Printf("Input Log Size:  %d\n", keysResp.InputSize)
		for _, kv := range keysResp.Keys {
			if *fetchAll {
				var indices []uint64
				for idx, vErr := range kv.Values(ctx) {
					if vErr != nil {
						return fmt.Errorf("prefix values verification failed for key %q: %w", kv.Key, vErr)
					}
					indices = append(indices, idx)
				}
				slices.Reverse(indices)
				fmt.Printf("  Key %s (%x): %d occurrences %v\n", kv.Key, kv.ValueRoot, len(indices), indices)
				if *dereference && *inLogURL != "" {
					dereferenceIndices(ctx, *inLogURL, indices, keysResp.InputSize)
				}
			} else {
				fmt.Printf("  Key: %s ValueRoot: %x\n", kv.Key, kv.ValueRoot)
			}
		}
		return nil
	}

	keysResp, err := cli.LookupKey(ctx, target)
	if err != nil {
		return fmt.Errorf("key lookup verification failed: %w", err)
	}

	exists := len(keysResp.Keys) > 0
	fmt.Printf("Key:             %s\n", target)
	fmt.Printf("Exists:          %v\n", exists)
	fmt.Printf("MPT Root:        %x\n", keysResp.MPTRoot)
	fmt.Printf("Output Log Size: %d\n", keysResp.OutputSize)
	fmt.Printf("Input Log Size:  %d\n", keysResp.InputSize)

	if !exists {
		fmt.Println("No occurrences found in Input Log (cryptographically verified non-inclusion).")
		return nil
	}

	mk := keysResp.Keys[0]
	fmt.Printf("Value Root:      %x\n", mk.ValueRoot)

	var indices []uint64
	for idx, vErr := range mk.Values(ctx) {
		if vErr != nil {
			return fmt.Errorf("values lookup verification failed: %w", vErr)
		}
		indices = append(indices, idx)
	}
	slices.Reverse(indices)

	fmt.Printf("Found %d verified occurrences:\n", len(indices))
	for _, idx := range indices {
		fmt.Printf("  Index: %d\n", idx)
	}

	if *dereference && *inLogURL != "" {
		dereferenceIndices(ctx, *inLogURL, indices, keysResp.InputSize)
	}

	return nil
}

func dereferenceIndices(ctx context.Context, baseURL string, indices []uint64, treeSize uint64) {
	fmt.Println("\nDereferencing leaves from Input Log:")
	for _, idx := range indices {
		data, err := ingest.FetchEntryByIndex(ctx, http.DefaultClient, baseURL, idx, treeSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error fetching leaf at index %d: %v\n", idx, err)
			continue
		}
		fmt.Printf("  [%d]: %s\n", idx, string(data))
	}
}
