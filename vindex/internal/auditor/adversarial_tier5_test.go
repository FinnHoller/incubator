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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

// -----------------------------------------------------------------------------
// Vector 6: Malformed/Corrupted OutputLog Leaf Payloads (ErrOutputLogCorrupted)
// -----------------------------------------------------------------------------

// TestAdv_Tier5_MalformedOutputLogLeaf_CorruptedPayloadMatrix tests Vector 6:
// Verifier engine halts, freezes watermarks, and returns ErrOutputLogCorrupted
// across an exhaustive matrix of malformed OutputLog leaf payloads.
func TestAdv_Tier5_MalformedOutputLogLeaf_CorruptedPayloadMatrix(t *testing.T) {
	ctx := context.Background()

	validRoot := sha256.Sum256([]byte("dummy_root"))
	validHex := hex.EncodeToString(validRoot[:])

	tests := []struct {
		name    string
		payload []byte
	}{
		{"EmptyPayload", []byte{}},
		{"WhitespaceOnly", []byte("   \n\n  \t ")},
		{"MissingNewlineDelimiter", []byte(validHex)},
		{"ShortHexRoot_63Chars", []byte(validHex[:63] + "\nexample.com/origin\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")},
		{"LongHexRoot_65Chars", []byte(validHex + "a\nexample.com/origin\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")},
		{"InvalidHexCharacters", []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\nexample.com/origin\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")},
		{"NullBytesInHex", []byte(validHex[:32] + "\x00" + validHex[33:] + "\nexample.com/origin\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")},
		{"CorruptedCheckpointHeader", []byte(validHex + "\nINVALID_HEADER_GARBAGE\n")},
		{"NegativeCheckpointSize", []byte(validHex + "\nexample.com/origin\n-5\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")},
		{"OverflowCheckpointSize", []byte(validHex + "\nexample.com/origin\n99999999999999999999999999999\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			h.inLog.AppendLeaf([]byte("entry-0"))

			// Append corrupted leaf to OutputLog
			if _, _, err := h.outLog.Append(ctx, tc.payload); err != nil {
				t.Fatalf("outLog.Append failed: %v", err)
			}

			cfg := auditor.Config{
				InputLogVerifier:  h.inVerifier,
				OutputLogVerifier: h.outVerifier,
				OutputLogOrigin:   h.outLog.origin,
				InputLogOrigin:    h.inLog.origin,
				OutputLog:         h.outLog,
				InputLogFetcher:   h.inLog,
				MapFn:             h.mapper,
				DBPath:            ":memory:",
				MPTDir:            ":memory:",
			}
			v, err := auditor.New(cfg)
			if err != nil {
				t.Fatalf("auditor.New failed: %v", err)
			}
			defer func() { _ = v.Close() }()

			err = v.VerifyOnce(ctx)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !errors.Is(err, wire.ErrOutputLogCorrupted) {
				t.Fatalf("expected errors.Is(err, wire.ErrOutputLogCorrupted), got: %v", err)
			}
			if !errors.Is(err, auditor.ErrOutputLogCorrupted) {
				t.Fatalf("expected errors.Is(err, auditor.ErrOutputLogCorrupted), got: %v", err)
			}

			st := v.Status()
			if !st.IsHalted {
				t.Fatalf("verifier should be permanently halted for %s", tc.name)
			}
			if st.VerifiedOutputSize != 0 {
				t.Fatalf("verified output watermark should be 0, got %d", st.VerifiedOutputSize)
			}
			if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrOutputLogCorrupted) {
				t.Fatalf("HealthCheck() = %v, want auditor.ErrOutputLogCorrupted", hErr)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Vector 1: Forged Output Root (ErrRootMismatch)
// -----------------------------------------------------------------------------

// TestAdv_Tier5_ForgedOutputRoot_Containment tests Vector 1:
// Verifier discovers committed root divergence, sets metrics, halts,
// and preserves watermarks.
func TestAdv_Tier5_ForgedOutputRoot_Containment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	// Seed 5 input leaves
	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("doc-%d", i)))
	}
	leaves5 := h.inLog.leaves[:5]
	expectedRoot0 := computeExpectedMPTRoot(t, leaves5, h.mapper)
	cp5, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint 5 failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(expectedRoot0, cp5)); err != nil {
		t.Fatalf("outLog.Append honest leaf 0 failed: %v", err)
	}

	// Append 5 more input leaves (total 10)
	for i := 5; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("doc-%d", i)))
	}
	cp10, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint 10 failed: %v", err)
	}

	// Leaf 1: Tampered Root
	forgedRoot := sha256.Sum256([]byte("forged_mpt_root_tier5"))
	if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(forgedRoot, cp10)); err != nil {
		t.Fatalf("outLog.Append tampered leaf 1 failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// Execution: processes leaf 0 (honest) then leaf 1 (tampered root)
	err = v.VerifyOnce(ctx)
	if err == nil {
		t.Fatal("expected VerifyOnce to fail on tampered root, got nil")
	}
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}

	var mismatchErr *auditor.RootMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("expected *auditor.RootMismatchError, got %T", err)
	}
	if mismatchErr.OutputIndex != 1 {
		t.Errorf("mismatchErr.OutputIndex = %d, want 1", mismatchErr.OutputIndex)
	}
	if mismatchErr.InputSize != 10 {
		t.Errorf("mismatchErr.InputSize = %d, want 10", mismatchErr.InputSize)
	}
	if mismatchErr.CommittedMPTRoot != forgedRoot {
		t.Errorf("mismatchErr.CommittedMPTRoot = %x, want %x", mismatchErr.CommittedMPTRoot, forgedRoot)
	}

	// Status and Watermarks
	st := v.Status()
	if !st.IsHalted {
		t.Error("v.Status().IsHalted = false, want true")
	}
	if st.VerifiedOutputSize != 1 {
		t.Errorf("VerifiedOutputSize = %d, want 1 (frozen at honest leaf 0)", st.VerifiedOutputSize)
	}
	if st.VerifiedInputSize != 5 {
		t.Errorf("VerifiedInputSize = %d, want 5 (frozen at honest size 5)", st.VerifiedInputSize)
	}

	// Metrics
	if m := testutil.ToFloat64(metrics.AuditorRootMismatch); m != 1.0 {
		t.Errorf("vindex_auditor_root_mismatch = %v, want 1.0", m)
	}
	if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal); c < 1.0 {
		t.Errorf("vindex_auditor_root_mismatches_total = %v, want >= 1.0", c)
	}

	// Health check
	if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrRootMismatch) {
		t.Errorf("HealthCheck() = %v, want ErrRootMismatch", hErr)
	}

	// Idempotency: subsequent calls immediately return ErrRootMismatch
	if err := v.VerifyOnce(ctx); !errors.Is(err, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", err)
	}
}

// -----------------------------------------------------------------------------
// Vector 2: Corrupted Input Leaf Bytes
// -----------------------------------------------------------------------------

// TestAdv_Tier5_CorruptedInputLeaves_DivergentRootDetection tests Vector 2:
// Tampering in input log leaves causes local MPT root to diverge from committed root.
func TestAdv_Tier5_CorruptedInputLeaves_DivergentRootDetection(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		corrupt func([][]byte)
	}{
		{
			name: "BitFlipFirstLeaf",
			corrupt: func(leaves [][]byte) {
				leaves[0][0] ^= 0x01
			},
		},
		{
			name: "BitFlipMiddleLeaf",
			corrupt: func(leaves [][]byte) {
				leaves[2][0] ^= 0x02
			},
		},
		{
			name: "TruncatedPayload",
			corrupt: func(leaves [][]byte) {
				leaves[1] = leaves[1][:len(leaves[1])/2]
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			metrics.ResetAuditorRootMismatch()

			var originalLeaves [][]byte
			for i := 0; i < 5; i++ {
				entry := []byte(fmt.Sprintf("genuine-record-%d", i))
				originalLeaves = append(originalLeaves, entry)
				h.inLog.AppendLeaf(entry)
			}

			// Genuine root calculated from uncorrupted leaves
			genuineRoot := computeExpectedMPTRoot(t, originalLeaves, h.mapper)
			cp, err := h.inLog.SignCheckpoint(5)
			if err != nil {
				t.Fatalf("SignCheckpoint failed: %v", err)
			}
			if _, _, err := h.outLog.Append(ctx, wire.FormatOutputLogLeaf(genuineRoot, cp)); err != nil {
				t.Fatalf("outLog.Append failed: %v", err)
			}

			// Corrupt input log leaves
			tc.corrupt(h.inLog.leaves)

			cfg := auditor.Config{
				InputLogVerifier:  h.inVerifier,
				OutputLogVerifier: h.outVerifier,
				OutputLogOrigin:   h.outLog.origin,
				InputLogOrigin:    h.inLog.origin,
				OutputLog:         h.outLog,
				InputLogFetcher:   h.inLog,
				MapFn:             h.mapper,
				DBPath:            ":memory:",
				MPTDir:            ":memory:",
			}
			v, err := auditor.New(cfg)
			if err != nil {
				t.Fatalf("auditor.New failed: %v", err)
			}
			defer func() { _ = v.Close() }()

			err = v.VerifyOnce(ctx)
			if err == nil {
				t.Fatal("expected VerifyOnce to fail with root mismatch due to corrupted input leaf, got nil")
			}
			if !errors.Is(err, auditor.ErrRootMismatch) {
				t.Fatalf("expected ErrRootMismatch, got %v", err)
			}

			var mismatchErr *auditor.RootMismatchError
			if !errors.As(err, &mismatchErr) {
				t.Fatalf("expected *auditor.RootMismatchError, got %T", err)
			}
			if mismatchErr.LocalMPTRoot == mismatchErr.CommittedMPTRoot {
				t.Error("LocalMPTRoot should not equal CommittedMPTRoot")
			}
			if mismatchErr.CommittedMPTRoot != genuineRoot {
				t.Errorf("CommittedMPTRoot = %x, want %x", mismatchErr.CommittedMPTRoot, genuineRoot)
			}
			if v.Status().VerifiedOutputSize != 0 {
				t.Errorf("VerifiedOutputSize = %d, want 0", v.Status().VerifiedOutputSize)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Vector 3: Non-Monotonic Input Tree Sizes (ErrMonotonicityBroken)
// -----------------------------------------------------------------------------

// TestAdv_Tier5_Monotonicity_InputSizeRegressionMatrix tests Vector 3:
// Severe regression, off-by-one regression, stuttering (zero-delta), and mid-batch regression.
func TestAdv_Tier5_Monotonicity_InputSizeRegressionMatrix(t *testing.T) {
	ctx := context.Background()

	// Subtest 1: SevereRegression (size 10 -> size 0)
	t.Run("SevereRegression", func(t *testing.T) {
		h := newTestHarness(t)
		for i := 0; i < 10; i++ {
			h.inLog.AppendLeaf([]byte(fmt.Sprintf("rec-%d", i)))
		}
		root0 := computeExpectedMPTRoot(t, h.inLog.leaves[:10], h.mapper)
		cp10, _ := h.inLog.SignCheckpoint(10)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp10))

		cp0, _ := h.inLog.SignCheckpoint(0)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp0))

		cfg := auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   h.outLog.origin,
			InputLogOrigin:    h.inLog.origin,
			OutputLog:         h.outLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		}
		v, err := auditor.New(cfg)
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		err = v.VerifyOnce(ctx)
		if !errors.Is(err, auditor.ErrMonotonicityBroken) {
			t.Fatalf("expected ErrMonotonicityBroken, got %v", err)
		}
		st := v.Status()
		if st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 10 {
			t.Errorf("watermarks advanced unexpectedly: output=%d, input=%d", st.VerifiedOutputSize, st.VerifiedInputSize)
		}
	})

	// Subtest 2: OffByOneRegression (verified 10 -> published 9)
	t.Run("OffByOneRegression", func(t *testing.T) {
		h := newTestHarness(t)
		for i := 0; i < 10; i++ {
			h.inLog.AppendLeaf([]byte(fmt.Sprintf("rec-%d", i)))
		}
		root0 := computeExpectedMPTRoot(t, h.inLog.leaves[:10], h.mapper)
		cp10, _ := h.inLog.SignCheckpoint(10)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp10))

		cp9, _ := h.inLog.SignCheckpoint(9)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp9))

		cfg := auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   h.outLog.origin,
			InputLogOrigin:    h.inLog.origin,
			OutputLog:         h.outLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		}
		v, err := auditor.New(cfg)
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		err = v.VerifyOnce(ctx)
		if !errors.Is(err, auditor.ErrMonotonicityBroken) {
			t.Fatalf("expected ErrMonotonicityBroken, got %v", err)
		}
		st := v.Status()
		if st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 10 {
			t.Errorf("watermarks advanced unexpectedly: output=%d, input=%d", st.VerifiedOutputSize, st.VerifiedInputSize)
		}
	})

	// Subtest 3: StutteringZeroDelta (verified 10 -> published 10 MUST SUCCEED)
	t.Run("StutteringZeroDelta", func(t *testing.T) {
		h := newTestHarness(t)
		for i := 0; i < 10; i++ {
			h.inLog.AppendLeaf([]byte(fmt.Sprintf("rec-%d", i)))
		}
		root0 := computeExpectedMPTRoot(t, h.inLog.leaves[:10], h.mapper)
		cp10, _ := h.inLog.SignCheckpoint(10)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp10))
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root0, cp10))

		cfg := auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   h.outLog.origin,
			InputLogOrigin:    h.inLog.origin,
			OutputLog:         h.outLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		}
		v, err := auditor.New(cfg)
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		if err := v.VerifyOnce(ctx); err != nil {
			t.Fatalf("stuttering zero-delta sync failed: %v", err)
		}
		st := v.Status()
		if st.VerifiedOutputSize != 2 || st.VerifiedInputSize != 10 {
			t.Errorf("stuttering status mismatch: output=%d, input=%d", st.VerifiedOutputSize, st.VerifiedInputSize)
		}
	})

	// Subtest 4: MidBatchRegression (sizes 10, 20, 15)
	t.Run("MidBatchRegression", func(t *testing.T) {
		h := newTestHarness(t)
		for i := 0; i < 20; i++ {
			h.inLog.AppendLeaf([]byte(fmt.Sprintf("rec-%d", i)))
		}
		root10 := computeExpectedMPTRoot(t, h.inLog.leaves[:10], h.mapper)
		cp10, _ := h.inLog.SignCheckpoint(10)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root10, cp10))

		root20 := computeExpectedMPTRoot(t, h.inLog.leaves[:20], h.mapper)
		cp20, _ := h.inLog.SignCheckpoint(20)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root20, cp20))

		cp15, _ := h.inLog.SignCheckpoint(15)
		_, _, _ = h.outLog.Append(ctx, wire.FormatOutputLogLeaf(root20, cp15))

		cfg := auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   h.outLog.origin,
			InputLogOrigin:    h.inLog.origin,
			OutputLog:         h.outLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		}
		v, err := auditor.New(cfg)
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		err = v.VerifyOnce(ctx)
		if !errors.Is(err, auditor.ErrMonotonicityBroken) {
			t.Fatalf("expected ErrMonotonicityBroken, got %v", err)
		}
		st := v.Status()
		if st.VerifiedOutputSize != 2 || st.VerifiedInputSize != 20 {
			t.Errorf("mid-batch watermarks mismatch: output=%d (want 2), input=%d (want 20)", st.VerifiedOutputSize, st.VerifiedInputSize)
		}
	})
}

// -----------------------------------------------------------------------------
// Vector 4: Regressed OutputLog Checkpoint Size (ErrOutputLogRegressed)
// -----------------------------------------------------------------------------

// dynamicCheckpointOutputLog wraps memoryOutputLog and allows overriding published checkpoints.
type dynamicCheckpointOutputLog struct {
	*memoryOutputLog
	overrideCP atomic.Pointer[[]byte]
}

func (l *dynamicCheckpointOutputLog) Checkpoint(ctx context.Context) ([]byte, error) {
	if o := l.overrideCP.Load(); o != nil {
		return *o, nil
	}
	return l.memoryOutputLog.Checkpoint(ctx)
}

func TestAdv_Tier5_OutputLog_RollbackRegression(t *testing.T) {
	ctx := context.Background()

	h := newTestHarness(t)
	dynLog := &dynamicCheckpointOutputLog{memoryOutputLog: h.outLog}

	for i := 0; i < 3; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("item-%d", i)))
		root := computeExpectedMPTRoot(t, h.inLog.leaves[:i+1], h.mapper)
		cp, _ := h.inLog.SignCheckpoint(uint64(i + 1))
		_, _, _ = dynLog.Append(ctx, wire.FormatOutputLogLeaf(root, cp))
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         dynLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// Sync 3 honest leaves
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}
	if v.Status().VerifiedOutputSize != 3 {
		t.Fatalf("VerifiedOutputSize = %d, want 3", v.Status().VerifiedOutputSize)
	}

	// Regress published checkpoint to size 1
	root1 := kvstore.BatchRoot(dynLog.leaves[:1])
	text := fmt.Sprintf("%s\n%d\n%s\n", dynLog.origin, 1, base64.StdEncoding.EncodeToString(root1[:]))
	regressedCP, err := note.Sign(&note.Note{Text: text}, dynLog.signer)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}
	dynLog.overrideCP.Store(&regressedCP)

	// Trigger VerifyOnce with regressed size
	err = v.VerifyOnce(ctx)
	if err == nil {
		t.Fatal("expected ErrOutputLogRegressed, got nil")
	}
	if !errors.Is(err, auditor.ErrOutputLogRegressed) {
		t.Fatalf("expected ErrOutputLogRegressed, got %v", err)
	}

	st := v.Status()
	if !st.IsHalted {
		t.Error("v.Status().IsHalted = false, want true")
	}
	if st.VerifiedOutputSize != 3 {
		t.Errorf("VerifiedOutputSize regressed to %d, want 3", st.VerifiedOutputSize)
	}
	if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrOutputLogRegressed) {
		t.Errorf("HealthCheck() = %v, want ErrOutputLogRegressed", hErr)
	}
}

// -----------------------------------------------------------------------------
// Vector 5: Forged/Corrupted Inclusion Proofs (ErrInclusionFailed)
// -----------------------------------------------------------------------------

type tamperedProofOutputLog struct {
	*memoryOutputLog
	tamperProof func([][sha256.Size]byte) [][sha256.Size]byte
}

func (l *tamperedProofOutputLog) InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	proof, err := l.memoryOutputLog.InclusionProof(ctx, leafIdx, treeSize)
	if err != nil {
		return nil, err
	}
	if l.tamperProof != nil {
		return l.tamperProof(proof), nil
	}
	return proof, nil
}

func TestAdv_Tier5_InclusionProof_TamperingMatrix(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name        string
		tamperProof func([][sha256.Size]byte) [][sha256.Size]byte
	}{
		{
			name: "BitFlipInProof",
			tamperProof: func(p [][sha256.Size]byte) [][sha256.Size]byte {
				if len(p) > 0 {
					p[0][0] ^= 0xaa
				}
				return p
			},
		},
		{
			name: "TruncatedProofPath",
			tamperProof: func(p [][sha256.Size]byte) [][sha256.Size]byte {
				if len(p) > 1 {
					return p[:len(p)-1]
				}
				return nil
			},
		},
		{
			name: "ExtraneousProofPath",
			tamperProof: func(p [][sha256.Size]byte) [][sha256.Size]byte {
				return append(p, sha256.Sum256([]byte("extra_bogus_node")))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			tamperedLog := &tamperedProofOutputLog{
				memoryOutputLog: h.outLog,
				tamperProof:     tc.tamperProof,
			}

			for i := 0; i < 4; i++ {
				h.inLog.AppendLeaf([]byte(fmt.Sprintf("doc-%d", i)))
				root := computeExpectedMPTRoot(t, h.inLog.leaves[:i+1], h.mapper)
				cp, _ := h.inLog.SignCheckpoint(uint64(i + 1))
				_, _, _ = tamperedLog.Append(ctx, wire.FormatOutputLogLeaf(root, cp))
			}

			cfg := auditor.Config{
				InputLogVerifier:  h.inVerifier,
				OutputLogVerifier: h.outVerifier,
				OutputLogOrigin:   h.outLog.origin,
				InputLogOrigin:    h.inLog.origin,
				OutputLog:         tamperedLog,
				InputLogFetcher:   h.inLog,
				MapFn:             h.mapper,
				DBPath:            ":memory:",
				MPTDir:            ":memory:",
			}
			v, err := auditor.New(cfg)
			if err != nil {
				t.Fatalf("auditor.New failed: %v", err)
			}
			defer func() { _ = v.Close() }()

			err = v.VerifyOnce(ctx)
			if err == nil {
				t.Fatal("expected ErrInclusionFailed, got nil")
			}
			if !errors.Is(err, auditor.ErrInclusionFailed) {
				t.Fatalf("expected ErrInclusionFailed, got %v", err)
			}
			st := v.Status()
			if !st.IsHalted {
				t.Error("v.Status().IsHalted = false, want true")
			}
			if st.VerifiedOutputSize != 0 {
				t.Errorf("VerifiedOutputSize = %d, want 0", st.VerifiedOutputSize)
			}
		})
	}
}
