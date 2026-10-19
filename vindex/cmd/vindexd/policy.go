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
	"fmt"
	"strings"

	"github.com/transparency-dev/incubator/vindex/internal/server"
	"golang.org/x/net/publicsuffix"
)

// parsePrefixPolicy resolves a CLI policy name into a server.PrefixPolicy.
func parsePrefixPolicy(name string) (server.PrefixPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "allow":
		return server.AllowAllPrefixPolicy, nil
	case "none", "disallow":
		return server.DisallowPrefixPolicy, nil
	case "reversed-dns", "domain":
		return reversedDNSPrefixPolicy, nil
	default:
		return nil, fmt.Errorf("unknown prefix_policy %q: expected 'allow', 'reversed-dns', or 'none'", name)
	}
}

// reversedDNSPrefixPolicy enforces that prefix queries use reversed-DNS label
// notation with a trailing '.' and cover at least an eTLD+1 registrable domain
// according to the Public Suffix List (e.g. "com.example." or "uk.co.google.").
func reversedDNSPrefixPolicy(prefix string) error {
	if prefix == "" || !strings.HasSuffix(prefix, ".") {
		return fmt.Errorf("prefix %q must end with a trailing '.' on a label boundary", prefix)
	}
	trimmed := strings.TrimSuffix(prefix, ".")
	if trimmed == "" {
		return fmt.Errorf("prefix %q must contain at least an eTLD+1 domain", prefix)
	}

	revLabels := strings.Split(trimmed, ".")
	for _, lbl := range revLabels {
		if lbl == "" {
			return fmt.Errorf("prefix %q contains an empty DNS label", prefix)
		}
	}

	// If the most-specific reversed label is a wildcard ("*"), validate the parent domain.
	if revLabels[len(revLabels)-1] == "*" {
		revLabels = revLabels[:len(revLabels)-1]
		if len(revLabels) == 0 {
			return fmt.Errorf("prefix %q must contain at least an eTLD+1 domain", prefix)
		}
	}

	fwdLabels := make([]string, len(revLabels))
	for i, lbl := range revLabels {
		fwdLabels[len(revLabels)-1-i] = strings.ToLower(lbl)
	}
	forwardDomain := strings.Join(fwdLabels, ".")

	if _, err := publicsuffix.EffectiveTLDPlusOne(forwardDomain); err != nil {
		return fmt.Errorf("prefix %q (%s) must specify at least an eTLD+1 domain: %w", prefix, forwardDomain, err)
	}
	return nil
}
