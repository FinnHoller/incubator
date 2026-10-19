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

package auditor_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

// TestAdv_M3_ColdRestart_OutputLogTreeSizeRegressed verifies that if the OutputLog
// tree size regressed across a cold restart (outCP.Size < verifiedOutputSize),
// VerifyOnce returns ErrOutputLogRegressed and halts.
func TestAdv_M3_ColdRestart_OutputLogTreeSizeRegressed(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	mptDir := filepath.Join(tmpDir, "mpt")

	// Verify 2 leaves in run 1
	h.inLog.AppendLeaf([]byte("leaf-0"))
	root0 := computeExpectedMPTRoot(t, h.inLog.leaves[:1], h.mapper)
	cp0, _ := h.inLog.SignCheckpoint(1)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp0))

	h.inLog.AppendLeaf([]byte("leaf-1"))
	root1 := computeExpectedMPTRoot(t, h.inLog.leaves[:2], h.mapper)
	cp1, _ := h.inLog.SignCheckpoint(2)
	_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root1, cp1))

	cfg1 := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
	}
	v1, err := auditor.New(cfg1)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	_ = v1.Close()

	// Truncate outLog leaves to 1 (regressing tree size from 2 to 1)
	h.outLog.mu.Lock()
	h.outLog.leaves = h.outLog.leaves[:1]
	h.outLog.mu.Unlock()

	// Run 2: Restart with regressed log
	cfg2 := cfg1
	v2, err := auditor.New(cfg2)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	err = v2.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrOutputLogRegressed) {
		t.Fatalf("expected ErrOutputLogRegressed, got: %v", err)
	}
	if !v2.Status().IsHalted {
		t.Fatal("expected verifier to be halted after regression")
	}
}
