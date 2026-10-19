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
	"context"
	"flag"
	"strings"
	"testing"
)

func TestRemovedLegacyFlags(t *testing.T) {
	for _, removed := range []string{
		"key_hash",
		"sub_root",
		"expected_map_fn",
		"before",
		"value_root",
		"limit",
		"in_log_policy",
		"in_log_pubkey",
	} {
		if f := flag.CommandLine.Lookup(removed); f != nil {
			t.Errorf("removed legacy flag --%s must not be registered", removed)
		}
	}
}

func TestPrefixFlagModes(t *testing.T) {
	var pf prefixFlag
	if err := pf.Set("true"); err != nil || !pf.enabled || pf.value != "" {
		t.Fatalf("Set(true) failed: %+v, err=%v", pf, err)
	}
	if err := pf.Set("com.example."); err != nil || !pf.enabled || pf.value != "com.example." {
		t.Fatalf("Set(com.example.) failed: %+v, err=%v", pf, err)
	}
	if err := pf.Set("false"); err != nil || pf.enabled || pf.value != "" {
		t.Fatalf("Set(false) failed: %+v, err=%v", pf, err)
	}
}

func TestRunFlagValidation(t *testing.T) {
	ctx := context.Background()
	*key = ""
	prefix = prefixFlag{}
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "must specify --key") {
		t.Fatalf("expected missing --key error, got: %v", err)
	}

	*key = "example"
	*outLogPolicy = ""
	*outLogPubKey = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--out_log_policy or --out_log_pubkey") {
		t.Fatalf("expected missing output policy/pubkey error, got: %v", err)
	}
}
