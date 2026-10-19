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

package tree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	torchmpt "filippo.io/torchwood/mpt"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"k8s.io/klog/v2"
)

// OutputPublisher orchestrates root prediction, Output Log append, witness collection, and atomic state ratcheting.
type OutputPublisher struct {
	mu              sync.RWMutex
	db              *kvstore.DB
	mptMgr          *mpt.Manager
	outputLog       OutputLogClient
	witness         WitnessClient
	outputLogPolicy wire.Policy
	inputOrigin     string
	from            uint64
	servingState    atomic.Pointer[ServingState]
}

// NewOutputPublisher creates a new OutputPublisher.
func NewOutputPublisher(db *kvstore.DB, mptMgr *mpt.Manager, outputLog OutputLogClient, witness WitnessClient) *OutputPublisher {
	return &OutputPublisher{
		db:        db,
		mptMgr:    mptMgr,
		outputLog: outputLog,
		witness:   witness,
	}
}

// SetOutputLogPolicy configures an optional wire.Policy used to verify Output Log checkpoints
// (including witness cosignatures) prior to promoting ServingState.
func (p *OutputPublisher) SetOutputLogPolicy(policy wire.Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outputLogPolicy = policy
}

// SetInputOrigin sets the Input Log origin string committed in Output Log leaves.
func (p *OutputPublisher) SetInputOrigin(origin string) {
	p.inputOrigin = origin
}

// InputOrigin returns the Input Log origin string committed in Output Log leaves.
func (p *OutputPublisher) InputOrigin() string {
	return p.inputOrigin
}

// SetFrom sets the inclusive starting Input Log index committed in Output Log leaves.
func (p *OutputPublisher) SetFrom(from uint64) {
	p.from = from
}

// From returns the inclusive starting Input Log index committed in Output Log leaves.
func (p *OutputPublisher) From() uint64 {
	return p.from
}

// GetServingState returns the currently active ServingState.
func (p *OutputPublisher) GetServingState() *ServingState {
	return p.servingState.Load()
}

// SetServingState explicitly sets the active serving state (e.g. during recovery/startup).
func (p *OutputPublisher) SetServingState(state *ServingState) {
	p.servingState.Store(state)
	if state != nil {
		metrics.ServingTreeSize.Set(float64(state.InputLogSize))
		metrics.WitnessSignaturesCount.Set(float64(countWitnessSignatures(state.RawCheckpoint)))
	}
}

// PublishBatch publishes a batch of 32-byte keyHash value root modifications (encoded as 64-byte lowercase hex keys) to the Output Log and promotes the serving state.
func (p *OutputPublisher) PublishBatch(ctx context.Context, modifiedValueRoots map[[sha256.Size]byte][sha256.Size]byte, inputLogCP *log.Checkpoint, rawInputLogCP []byte) (*ServingState, error) {
	keys := make([]byte, len(modifiedValueRoots)*sha256.Size*2)
	vals := make([]byte, len(modifiedValueRoots)*sha256.Size)
	changes := make([]torchmpt.KeyVal, 0, len(modifiedValueRoots))
	i := 0
	for k, v := range modifiedValueRoots {
		kb := keys[i*sha256.Size*2 : (i+1)*sha256.Size*2 : (i+1)*sha256.Size*2]
		vb := vals[i*sha256.Size : (i+1)*sha256.Size : (i+1)*sha256.Size]
		hex.Encode(kb, k[:])
		copy(vb, v[:])
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(kb),
			Val: torchmpt.Val(vb),
		})
		i++
	}
	return p.publishKeyVals(ctx, changes, inputLogCP, rawInputLogCP)
}

// PublishKeyBatch publishes a batch of variable-length canonical key value root modifications to the Output Log and promotes the serving state.
func (p *OutputPublisher) PublishKeyBatch(ctx context.Context, modifiedValueRoots map[string][sha256.Size]byte, inputLogCP *log.Checkpoint, rawInputLogCP []byte) (*ServingState, error) {
	vals := make([]byte, len(modifiedValueRoots)*sha256.Size)
	changes := make([]torchmpt.KeyVal, 0, len(modifiedValueRoots))
	i := 0
	for k, v := range modifiedValueRoots {
		if err := mpt.ValidateCanonicalKey([]byte(k)); err != nil {
			return nil, err
		}
		vb := vals[i*sha256.Size : (i+1)*sha256.Size : (i+1)*sha256.Size]
		copy(vb, v[:])
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key([]byte(k)),
			Val: torchmpt.Val(vb),
		})
		i++
	}
	return p.publishKeyVals(ctx, changes, inputLogCP, rawInputLogCP)
}

func (p *OutputPublisher) publishKeyVals(ctx context.Context, changes []torchmpt.KeyVal, inputLogCP *log.Checkpoint, rawInputLogCP []byte) (*ServingState, error) {
	if (inputLogCP == nil || inputLogCP.Origin == "" || len(inputLogCP.Hash) == 0) && len(rawInputLogCP) > 0 {
		parsed, err := ParseCheckpointHeader(rawInputLogCP)
		if err == nil {
			if inputLogCP == nil {
				inputLogCP = parsed
			} else {
				if inputLogCP.Origin == "" {
					inputLogCP.Origin = parsed.Origin
				}
				if len(inputLogCP.Hash) == 0 {
					inputLogCP.Hash = parsed.Hash
				}
				if inputLogCP.Size == 0 {
					inputLogCP.Size = parsed.Size
				}
			}
		}
	}
	if inputLogCP != nil && inputLogCP.Origin == "" && p.inputOrigin != "" {
		inputLogCP.Origin = p.inputOrigin
	}
	var inputLogSize uint64
	if inputLogCP != nil {
		inputLogSize = inputLogCP.Size
	}

	mpt.SortKeyVals(changes)

	// 1. Lock-Free Phase: Predict MPT root
	predictStart := time.Now()
	predictedMPTRoot, err := p.mptMgr.PredictKeyVals(changes)
	metrics.MPTPredictDurationSeconds.Observe(time.Since(predictStart).Seconds())
	if err != nil {
		return nil, fmt.Errorf("mptMgr.Predict failed: %w", err)
	}
	klog.V(2).Infof("Milestone M3: MPT root predicted: %x for %d keys in %v", predictedMPTRoot, len(changes), time.Since(predictStart))

	// 2. Format StateCommitment: c2sp.org/tlog-vindex-state@v1
	leafData := FormatOutputLogLeafFull(predictedMPTRoot, p.from, inputLogCP)

	// 3. Append to Output Log
	appendStart := time.Now()
	leafIdx, rawCP, err := p.outputLog.Append(ctx, leafData)
	if err != nil {
		return nil, fmt.Errorf("outputLog.Append failed: %w", err)
	}
	metrics.OutputTreeSize.Set(float64(leafIdx + 1))

	// 4. Submit to remote witnesses if configured
	if p.witness != nil {
		witStart := time.Now()
		witnessedCP, err := p.witness.Witness(ctx, rawCP)
		metrics.WitnessWaitSeconds.Observe(time.Since(witStart).Seconds())
		if err != nil {
			metrics.WitnessErrorsTotal.Inc()
			return nil, fmt.Errorf("witness failed: %w", err)
		}
		if len(witnessedCP) > 0 {
			rawCP = witnessedCP
		}
	}

	// 5. Verify/parse Output Log checkpoint
	p.mu.RLock()
	outPolicy := p.outputLogPolicy
	p.mu.RUnlock()

	var outCP *log.Checkpoint
	if outPolicy != nil {
		outCP, err = outPolicy.Verify(rawCP)
		if err != nil {
			if p.witness != nil {
				metrics.WitnessErrorsTotal.Inc()
			}
			return nil, fmt.Errorf("failed to verify output log checkpoint against policy: %w", err)
		}
	} else {
		outCP, err = ParseCheckpointHeader(rawCP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse output log checkpoint: %w", err)
		}
	}

	// 6. Fetch inclusion proof for Output Log leaf
	proof, err := p.outputLog.InclusionProof(ctx, leafIdx, outCP.Size)
	if err != nil {
		return nil, fmt.Errorf("outputLog.InclusionProof failed: %w", err)
	}
	metrics.OutputLogAppendDurationSeconds.Observe(time.Since(appendStart).Seconds())
	klog.V(2).Infof("Milestone M4: Output Log updated: index %d size %d in %v", leafIdx, outCP.Size, time.Since(appendStart))

	// 7. Critical Section: Commit to MPT under lock, assert root matches prediction, and ratchet serving state
	lockWaitStart := time.Now()
	p.mptMgr.Lock()
	metrics.MPTLockWaitSeconds.Observe(time.Since(lockWaitStart).Seconds())
	writeStart := time.Now()
	actualRoot, err := p.mptMgr.CommitKeyValsLocked(changes, int64(inputLogSize))
	metrics.MPTWriteDurationSeconds.Observe(time.Since(writeStart).Seconds())
	if err != nil {
		p.mptMgr.Unlock()
		return nil, fmt.Errorf("mptMgr.CommitKeyValsLocked failed: %w", err)
	}
	if actualRoot != predictedMPTRoot {
		p.mptMgr.Unlock()
		panic(fmt.Sprintf("FATAL: MPT root prediction mismatch after output log append: actual root %x != predicted root %x", actualRoot, predictedMPTRoot))
	}
	klog.Infof("Milestone M5: Committed MPTRoot: %x for InputLog size %d in %v (time-to-serve reached)", actualRoot, inputLogSize, time.Since(writeStart))

	// 8. Construct and store new ServingState
	newState := &ServingState{
		OutputLogIndex: leafIdx,
		OutputLogSize:  outCP.Size,
		OutputLogCP:    outCP,
		RawCheckpoint:  rawCP,
		OutputLogProof: proof,
		InputLogCP:     inputLogCP,
		RawInputLogCP:  rawInputLogCP,
		InputLogSize:   inputLogSize,
		MPTRoot:        actualRoot,
		From:           p.from,
	}
	p.SetServingState(newState)
	p.mptMgr.Unlock()
	if err := p.mptMgr.Persist(); err != nil {
		return nil, fmt.Errorf("mptMgr.Persist failed: %w", err)
	}
	return newState, nil
}

func countWitnessSignatures(rawCP []byte) int {
	if len(rawCP) == 0 {
		return 0
	}
	lines := bytes.Split(rawCP, []byte("\n"))
	count := 0
	for _, l := range lines {
		trimmed := bytes.TrimSpace(l)
		if bytes.HasPrefix(trimmed, []byte("— ")) || bytes.HasPrefix(trimmed, []byte("-- ")) || bytes.HasPrefix(trimmed, []byte("\xe2\x80\x94 ")) {
			count++
		}
	}
	return count
}

// Publish provides a simplified signature taking raw checkpoint bytes and input log size.
func (p *OutputPublisher) Publish(ctx context.Context, rawInputLogCP []byte, inputLogSize uint64, valueRoots map[[sha256.Size]byte][sha256.Size]byte) (*ServingState, error) {
	cp := &log.Checkpoint{
		Size: inputLogSize,
	}
	return p.PublishBatch(ctx, valueRoots, cp, rawInputLogCP)
}

// ParseCheckpointHeader parses a raw signed-note / tlog-checkpoint header extracting Origin, Size, and Hash.
func ParseCheckpointHeader(rawCP []byte) (*log.Checkpoint, error) {
	return wire.ParseCheckpointHeader(rawCP)
}
