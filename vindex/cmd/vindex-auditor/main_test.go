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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVindexAuditor_NoSignerKeyFlag(t *testing.T) {
	// Verify that the dedicated auditor binary does NOT define --output_log_signer_key
	f := flag.CommandLine.Lookup("output_log_signer_key")
	if f != nil {
		t.Fatalf("security invariant violation: --output_log_signer_key must not exist in vindex-auditor, but found: %v", f)
	}

	fDir := flag.CommandLine.Lookup("output_log_dir")
	if fDir != nil {
		t.Fatalf("output_log_dir must not exist in vindex-auditor, but found: %v", fDir)
	}

	fMode := flag.CommandLine.Lookup("mode")
	if fMode != nil {
		t.Fatalf("mode flag should not exist in dedicated vindex-auditor, but found: %v", fMode)
	}
}

func TestVindexAuditor_FlagValidation(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// 1. Missing output_log_url
	*outputLogURL = ""
	*inputLogURL = "http://localhost:8080/in"
	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = filepath.Join(tmpDir, "mpt")
	err := run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--output_log_url is required") {
		t.Fatalf("expected missing output_log_url error, got: %v", err)
	}

	// 2. Missing input_log_url
	*outputLogURL = "http://localhost:8080/out"
	*inputLogURL = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--input_log_url is required") {
		t.Fatalf("expected missing input_log_url error, got: %v", err)
	}

	// 3. Missing db_path
	*inputLogURL = "http://localhost:8080/in"
	*dbPath = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--db_path flag is required") {
		t.Fatalf("expected missing db_path error, got: %v", err)
	}

	// 4. Missing mpt_dir
	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--mpt_dir flag is required") {
		t.Fatalf("expected missing mpt_dir error, got: %v", err)
	}
	*mptDir = filepath.Join(tmpDir, "mpt")

	// 5. Unknown mapper
	*mapper = "unknown_mapper_type"
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "unknown mapper \"unknown_mapper_type\"") {
		t.Fatalf("expected unknown mapper error, got: %v", err)
	}
	*mapper = "identity"
}

func TestVindexAuditor_ResolveKey(t *testing.T) {
	// Literal key
	k, err := resolveKey("literal_key_val")
	if err != nil || k != "literal_key_val" {
		t.Fatalf("resolveKey literal failed: got (%q, %v)", k, err)
	}

	// Empty key
	k, err = resolveKey("")
	if err != nil || k != "" {
		t.Fatalf("resolveKey empty failed: got (%q, %v)", k, err)
	}

	// File key
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")
	if err := os.WriteFile(keyFile, []byte("key_from_file\n"), 0o644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	k, err = resolveKey(keyFile)
	if err != nil || k != "key_from_file" {
		t.Fatalf("resolveKey file failed: got (%q, %v)", k, err)
	}
}

func TestVindexAuditor_CLIHelp(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "-output_log_url") {
		t.Fatalf("vindex-auditor --help failed: %v\nOutput: %s", err, string(out))
	}
	helpText := string(out)
	if !strings.Contains(helpText, "-output_log_url") {
		t.Errorf("expected -output_log_url in help output, got: %s", helpText)
	}
	if !strings.Contains(helpText, "-oneshot") {
		t.Errorf("expected -oneshot in help output, got: %s", helpText)
	}
	if strings.Contains(helpText, "-output_log_signer_key") {
		t.Errorf("found forbidden -output_log_signer_key in help output: %s", helpText)
	}
	if strings.Contains(helpText, "/syncz") {
		t.Errorf("found deleted /syncz in help output: %s", helpText)
	}
}

func TestVindexAuditor_PolicyFlagsExist(t *testing.T) {
	for _, name := range []string{"output_log_policy", "input_log_policy", "witness_pubkeys", "witness_threshold"} {
		if flag.CommandLine.Lookup(name) == nil {
			t.Errorf("expected --%s flag to be registered", name)
		}
	}
}
