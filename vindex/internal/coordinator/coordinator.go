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

package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

type consistencyProver interface {
	ConsistencyProof(ctx context.Context, smaller, larger uint64) ([][]byte, error)
}

const (
	// DefaultCommitBatchSize is the default number of leaves aggregated before committing to the KV store (16 tiles).
	DefaultCommitBatchSize uint64 = 4096 // 16 tiles (256 * 16)

	// DefaultCoarseCheckpointInterval is the default leaf interval between coarse checkpoints during Genesis Backfill.
	DefaultCoarseCheckpointInterval uint64 = 50000000

	// DefaultBackfillMaxPendingKeys is the default maximum number of deduplicated modified keys
	// buffered in memory before flushing to the MPT during Genesis Backfill (~5.5 GB RAM).
	DefaultBackfillMaxPendingKeys uint64 = 50000000
)

// Coordinator manages the 3-phase startup and crash recovery workflow.
type Coordinator struct {
	db                       *kvstore.DB
	mptMgr                   *mpt.Manager
	outputLog                OutputLogReader
	pub                      *tree.OutputPublisher
	indexer                  *kvstore.KVIndexer
	fetcher                  ingest.TileFetcher
	cache                    ingest.TileCache
	mapper                   ingest.LeafMapper
	pipeline                 *ingest.IngestionPipeline
	commitBatchSize          uint64
	coarseCheckpointInterval uint64
	backfillMaxPendingKeys   uint64
	workers                  int
	fetchWorkers             int
	fetchBatchBundles        int
	pipelineChanCap          int
	replayActive             atomic.Bool
	replayCurrent            atomic.Uint64
}

// SetWorkers configures the number of WASM / mapping workers for the coordinator's pipeline.
func (c *Coordinator) SetWorkers(n int) {
	if n < 0 {
		n = 0
	}
	c.workers = n
	if c.fetcher != nil && c.mapper != nil {
		c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, c.workers)
		if c.fetchWorkers > 0 {
			c.pipeline.SetFetchWorkers(c.fetchWorkers)
		}
		if c.fetchBatchBundles > 0 {
			c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
		}
		if c.pipelineChanCap > 0 {
			c.pipeline.SetChannelCapacity(c.pipelineChanCap)
		}
	}
}

// SetPipeline explicitly sets the IngestionPipeline instance used by the coordinator.
func (c *Coordinator) SetPipeline(p *ingest.IngestionPipeline) {
	c.pipeline = p
}

// NewCoordinator creates a new recovery Coordinator.
func NewCoordinator(
	db *kvstore.DB,
	mptMgr *mpt.Manager,
	outputLog OutputLogReader,
	pub *tree.OutputPublisher,
	indexer *kvstore.KVIndexer,
	fetcher ingest.TileFetcher,
	cache ingest.TileCache,
	mapper ingest.LeafMapper,
) *Coordinator {
	var pipeline *ingest.IngestionPipeline
	if fetcher != nil && mapper != nil {
		pipeline = ingest.NewPipeline(fetcher, cache, mapper, 0)
	}
	return &Coordinator{
		db:                       db,
		mptMgr:                   mptMgr,
		outputLog:                outputLog,
		pub:                      pub,
		indexer:                  indexer,
		fetcher:                  fetcher,
		cache:                    cache,
		mapper:                   mapper,
		pipeline:                 pipeline,
		commitBatchSize:          DefaultCommitBatchSize,
		coarseCheckpointInterval: DefaultCoarseCheckpointInterval,
	}
}

// SetCommitBatchSize sets the commit batch size for leaf aggregation.
func (c *Coordinator) SetCommitBatchSize(size uint64) {
	if size == 0 {
		size = DefaultCommitBatchSize
	}
	c.commitBatchSize = size
}

// CommitBatchSize returns the configured commit batch size.
func (c *Coordinator) CommitBatchSize() uint64 {
	if c.commitBatchSize == 0 {
		return DefaultCommitBatchSize
	}
	return c.commitBatchSize
}

// SetCoarseCheckpointInterval sets the coarse checkpoint interval for Genesis Backfill.
func (c *Coordinator) SetCoarseCheckpointInterval(interval uint64) {
	if interval == 0 {
		interval = DefaultCoarseCheckpointInterval
	}
	c.coarseCheckpointInterval = interval
}

// CoarseCheckpointInterval returns the configured coarse checkpoint interval.
func (c *Coordinator) CoarseCheckpointInterval() uint64 {
	if c.coarseCheckpointInterval == 0 {
		return DefaultCoarseCheckpointInterval
	}
	return c.coarseCheckpointInterval
}

// SetBackfillMaxPendingKeys sets the maximum number of deduplicated keys buffered during Genesis Backfill.
func (c *Coordinator) SetBackfillMaxPendingKeys(maxKeys uint64) {
	if maxKeys == 0 {
		maxKeys = DefaultBackfillMaxPendingKeys
	}
	c.backfillMaxPendingKeys = maxKeys
}

// BackfillMaxPendingKeys returns the configured maximum number of deduplicated keys buffered during Genesis Backfill.
func (c *Coordinator) BackfillMaxPendingKeys() uint64 {
	if c.backfillMaxPendingKeys == 0 {
		return DefaultBackfillMaxPendingKeys
	}
	return c.backfillMaxPendingKeys
}

// SafeWatermark returns max(min(m_kv_size, MPT.PersistedSize()), from).
func (c *Coordinator) SafeWatermark(_ context.Context) (uint64, error) {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	mptPersistedSize := c.mptMgr.PersistedSize()
	w := min(kvSize, mptPersistedSize)
	if c.pub != nil && w < c.pub.From() {
		w = c.pub.From()
	}
	return w, nil
}

type readinessStatusError struct {
	Status          string `json:"status"`
	GenesisBackfill bool   `json:"genesis_backfill"`
	LeavesIndexed   uint64 `json:"leaves_indexed"`
	TargetLeaves    uint64 `json:"target_leaves"`
}

func (e *readinessStatusError) Error() string {
	return fmt.Sprintf("status=%s genesis_backfill=%v leaves_indexed=%d target_leaves=%d",
		e.Status, e.GenesisBackfill, e.LeavesIndexed, e.TargetLeaves)
}

func (e *readinessStatusError) JSONDiagnostics() []byte {
	b, _ := json.Marshal(e)
	return append(b, '\n')
}

// ReadinessCheck evaluates whether the coordinator has promoted a valid ServingState.
// While in Genesis Backfill or startup recovery, it returns a structured JSON diagnostic error.
func (c *Coordinator) ReadinessCheck() error {
	if c.pub != nil {
		if state := c.pub.GetServingState(); state != nil && len(state.RawCheckpoint) > 0 {
			return nil
		}
	}

	var kvSize uint64
	var targetLeaves uint64
	if c.db != nil {
		kvSize, _ = c.db.GetUint64(kvstore.KeyMetaKVSize)
		for _, metaKey := range [][]byte{kvstore.KeyMetaTargetCheckpoint, kvstore.KeyMetaKVCheckpoint} {
			if rawCP, err := c.db.GetMetadata(metaKey); err == nil && len(rawCP) > 0 {
				if cp, pErr := wire.ParseCheckpointHeader(rawCP); pErr == nil && cp.Size > 0 {
					targetLeaves = cp.Size
					break
				}
			}
		}
	}
	leavesIndexed := kvSize
	if c.replayActive.Load() {
		leavesIndexed = c.replayCurrent.Load()
	}
	if targetLeaves == 0 {
		targetLeaves = kvSize
	}

	outSize := uint64(0)
	if c.outputLog != nil {
		outSize, _ = c.outputLog.Size(context.Background())
	}

	if outSize == 0 {
		return &readinessStatusError{
			Status:          "genesis_backfill",
			GenesisBackfill: true,
			LeavesIndexed:   leavesIndexed,
			TargetLeaves:    targetLeaves,
		}
	}
	return &readinessStatusError{
		Status:          "recovering",
		GenesisBackfill: false,
		LeavesIndexed:   leavesIndexed,
		TargetLeaves:    targetLeaves,
	}
}

// SetFetchWorkers sets the number of concurrent tile fetch workers for the pipeline.
func (c *Coordinator) SetFetchWorkers(n int) {
	if n < 1 {
		n = 1
	}
	c.fetchWorkers = n
	if c.pipeline != nil {
		c.pipeline.SetFetchWorkers(n)
	}
}

// FetchWorkers returns the configured number of tile fetch workers.
func (c *Coordinator) FetchWorkers() int {
	if c.fetchWorkers <= 0 {
		return ingest.DefaultFetchWorkers()
	}
	return c.fetchWorkers
}

// SetFetchBatchBundles sets the number of bundles fetched per worker batch in Stage 1.
func (c *Coordinator) SetFetchBatchBundles(n int) {
	if n < 1 {
		n = 1
	}
	c.fetchBatchBundles = n
	if c.pipeline != nil {
		c.pipeline.SetFetchBatchBundles(n)
	}
}

// FetchBatchBundles returns the configured number of bundles fetched per worker batch.
func (c *Coordinator) FetchBatchBundles() int {
	if c.fetchBatchBundles <= 0 {
		return ingest.DefaultFetchBatchBundles()
	}
	return c.fetchBatchBundles
}

// SetPipelineChannelCapacity sets the buffer capacity of internal pipeline channels.
func (c *Coordinator) SetPipelineChannelCapacity(n int) {
	if n < 1 {
		n = 1
	}
	c.pipelineChanCap = n
	if c.pipeline != nil {
		c.pipeline.SetChannelCapacity(n)
	}
}

// PipelineChannelCapacity returns the configured pipeline channel capacity.
func (c *Coordinator) PipelineChannelCapacity() int {
	if c.pipelineChanCap <= 0 {
		return ingest.DefaultPipelineChannelCapacity()
	}
	return c.pipelineChanCap
}

// Recover runs the recovery sequence:
// 1. If output log has size 0, executes Genesis Backfill dirty crash recovery if needed.
// 2. Phase 1: Tip match check (< 5ms fast serve on clean shutdown).
// 3. Phase 2: If tip did not match, replay missing tiles up to Output Log tip, verify, and promote serving state.
func (c *Coordinator) Recover(ctx context.Context) error {
	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return fmt.Errorf("failed to get output log size: %w", err)
	}

	if outSize == 0 {
		return c.recoverGenesisBackfill(ctx)
	}

	matched, err := c.Phase1(ctx)
	if err != nil {
		return fmt.Errorf("phase 1 recovery failed: %w", err)
	}

	if !matched {
		if err := c.Phase2(ctx, outSize); err != nil {
			return fmt.Errorf("phase 2 recovery failed: %w", err)
		}
	}

	return nil
}

func (c *Coordinator) setFetcherTreeState(size uint64, hash [sha256.Size]byte) {
	if c.fetcher == nil {
		return
	}
	if hash != ([sha256.Size]byte{}) {
		if stater, ok := c.fetcher.(interface{ SetTreeState(uint64, [32]byte) }); ok {
			stater.SetTreeState(size, hash)
			return
		}
	}
	if sizer, ok := c.fetcher.(interface{ SetTreeSize(uint64) }); ok {
		sizer.SetTreeSize(size)
	}
}

// recoverGenesisBackfill handles crash recovery when outputLog.Size() == 0.
// If mptPersistedSize < kvSize (or MPT is dirty), leaves in [replayStart .. kvSize) are replayed
// with zero storage writes and value roots extracted via indexer.GetValueRoot, then coarse-checkpointed.
func (c *Coordinator) recoverGenesisBackfill(ctx context.Context) error {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	mptPersistedSize := c.mptMgr.PersistedSize()

	if mptPersistedSize > kvSize {
		klog.Errorf("Invariant violation: MPT durable size (%d) > m_kv_size (%d)", mptPersistedSize, kvSize)
		return fmt.Errorf("%w: MPT durable size (%d) > m_kv_size (%d)", ErrInvariantViolation, mptPersistedSize, kvSize)
	}

	if mptPersistedSize < kvSize || (!c.mptMgr.IsExact() && kvSize > 0) {
		replayStart := mptPersistedSize
		if replayStart == kvSize {
			replayStart = 0
		}
		if c.pub != nil && replayStart < c.pub.From() {
			replayStart = c.pub.From()
		}
		klog.Infof("Genesis dirty crash detected: MPT size (%d, exact=%v) vs KV size (%d). Replaying leaves [%d..%d) from WASM with zero Pebble writes...",
			mptPersistedSize, c.mptMgr.IsExact(), kvSize, replayStart, kvSize)

		cpSize := kvSize
		var cpHash [sha256.Size]byte
		for _, metaKey := range [][]byte{kvstore.KeyMetaKVCheckpoint, kvstore.KeyMetaTargetCheckpoint} {
			if rawCP, err := c.db.GetMetadata(metaKey); err == nil && len(rawCP) > 0 {
				if cp, pErr := wire.ParseCheckpointHeader(rawCP); pErr == nil && cp.Size >= kvSize && len(cp.Hash) == sha256.Size {
					cpSize = cp.Size
					cpHash = [sha256.Size]byte(cp.Hash)
					break
				}
			}
		}
		if cpHash == ([sha256.Size]byte{}) && c.fetcher != nil {
			if cp, err := c.fetcher.Checkpoint(ctx); err == nil && cp != nil && cp.Size >= kvSize {
				cpSize = cp.Size
				cpHash = cp.Hash
			}
		}
		c.setFetcherTreeState(cpSize, cpHash)

		if c.pipeline == nil && c.fetcher != nil && c.mapper != nil {
			c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
			if c.fetchWorkers > 0 {
				c.pipeline.SetFetchWorkers(c.fetchWorkers)
			}
			if c.fetchBatchBundles > 0 {
				c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
			}
		}
		if c.pipeline == nil {
			return errors.New("cannot replay genesis backfill: pipeline not initialized")
		}

		c.replayCurrent.Store(replayStart)
		c.replayActive.Store(true)
		defer c.replayActive.Store(false)

		batchChan, errChan := c.pipeline.StreamBatches(ctx, replayStart, kvSize)
		modifiedKeys := make(map[[sha256.Size]byte]string)
		replayedLeaves := replayStart
		lastReplayLog := replayStart
		for batch := range batchChan {
			for k := range batch.KeyMap {
				ck := hex.EncodeToString(k[:])
				if batch.CanonicalKeys != nil {
					if name, ok := batch.CanonicalKeys[k]; ok && name != "" {
						ck = name
					}
				}
				modifiedKeys[k] = ck
			}
			replayedLeaves += uint64(batch.Count)
			c.replayCurrent.Store(replayedLeaves)
			if replayedLeaves-lastReplayLog >= 500000 || replayedLeaves == kvSize {
				klog.Infof("Genesis replay progress: %d / %d leaves replayed (%d unique keys)",
					replayedLeaves, kvSize, len(modifiedKeys))
				lastReplayLog = replayedLeaves
			}
		}
		if err := <-errChan; err != nil {
			return fmt.Errorf("stream batches failed during genesis recovery: %w", err)
		}

		klog.Infof("Genesis replay extracting value roots for %d unique modified keys from Pebble (zero storage writes)...", len(modifiedKeys))
		mutations, err := c.indexer.GetKeyValueRoots(ctx, modifiedKeys, kvSize)
		if err != nil {
			return fmt.Errorf("failed to extract value roots during genesis replay: %w", err)
		}

		klog.Infof("Genesis replay applying %d value-root mutations to MPT...", len(mutations))
		if err := c.mptMgr.SetKeyBatch(mutations); err != nil {
			return fmt.Errorf("failed to set batch in MPT during genesis replay: %w", err)
		}

		if _, err := c.mptMgr.Snap(int64(kvSize)); err != nil {
			return fmt.Errorf("genesis recovery mpt.Snap error: %w", err)
		}
		if err := c.mptMgr.Sync(); err != nil {
			return fmt.Errorf("genesis recovery mpt.Sync error: %w", err)
		}
		klog.Infof("Genesis dirty crash recovery completed: MPT snapped at %d", kvSize)
	}
	return nil
}

// Phase1 inspects the Output Log tip (leaf N-1) for a clean shutdown match where
// tip.InputLogSize == MPT_Persisted_Size and tip.MPTRoot == MPT.Root().
//
// Performance fast-path (NOT a functional correctness requirement):
// On a clean shutdown, the tip Output Log commitment matches the persisted MPT state.
// Phase1 verifies tip equality directly (< 5ms) and promotes serving state immediately, completely
// bypassing Phase 2 replay. If this check fails or is omitted, Phase 2 executes full replay
// and arrives at the exact same state.
func (c *Coordinator) Phase1(ctx context.Context) (matched bool, err error) {
	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return false, fmt.Errorf("outputLog.Size failed: %w", err)
	}
	if outSize == 0 {
		return false, nil
	}

	tipIdx := outSize - 1
	leafData, err := c.outputLog.GetLeaf(ctx, tipIdx)
	if err != nil {
		return false, fmt.Errorf("failed to get tip leaf %d: %w", tipIdx, err)
	}

	tipLeaf, err := parseOutputLogLeafFull(leafData)
	if err != nil {
		return false, fmt.Errorf("failed to parse tip leaf %d: %w", tipIdx, err)
	}
	mptRoot, inCP := tipLeaf.MPTRoot, tipLeaf.InCP
	var rawInCP []byte
	if c.db != nil {
		if savedRaw, mErr := c.db.GetMetadata(kvstore.KeyMetaKVCheckpoint); mErr == nil && len(savedRaw) > 0 {
			rawInCP = savedRaw
		}
	}

	mptPersistedSize := c.mptMgr.PersistedSize()
	if inCP.Size == mptPersistedSize && c.mptMgr.IsExact() && c.mptMgr.Root() == mptRoot {
		// Clean match at tip! Generate inclusion proof and promote serving state
		proof, err := c.outputLog.InclusionProof(ctx, tipIdx, outSize)
		if err != nil {
			return false, fmt.Errorf("failed to generate inclusion proof for tip leaf %d: %w", tipIdx, err)
		}

		rawOutCP, err := c.outputLog.Checkpoint(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to fetch output log checkpoint: %w", err)
		}
		outCP, err := wire.ParseCheckpointHeader(rawOutCP)
		if err != nil {
			return false, fmt.Errorf("failed to parse output log checkpoint: %w", err)
		}

		state := &tree.ServingState{
			OutputLogIndex: tipIdx,
			OutputLogSize:  outSize,
			OutputLogCP:    outCP,
			RawCheckpoint:  rawOutCP,
			OutputLogProof: proof,
			InputLogCP:     inCP,
			RawInputLogCP:  rawInCP,
			InputLogSize:   inCP.Size,
			MPTRoot:        mptRoot,
			From:           tipLeaf.From,
		}
		if c.pub != nil {
			if c.pub.InputOrigin() == "" && inCP.Origin != "" {
				c.pub.SetInputOrigin(inCP.Origin)
			}
			if c.pub.From() == 0 && tipLeaf.From != 0 {
				c.pub.SetFrom(tipLeaf.From)
			}
		}
		c.pub.SetServingState(state)
		return true, nil
	}

	return false, nil
}

// Phase2 replays missing leaf delta up to OutputLog[N-1].InputLogSize from tile cache / fetcher into MPT and ratchets serving state.
func (c *Coordinator) Phase2(ctx context.Context, outSize uint64) error {
	if outSize == 0 {
		return nil
	}
	tipIdx := outSize - 1
	tipLeafData, err := c.outputLog.GetLeaf(ctx, tipIdx)
	if err != nil {
		return fmt.Errorf("failed to get tip leaf %d: %w", tipIdx, err)
	}

	tipLeaf, err := parseOutputLogLeafFull(tipLeafData)
	if err != nil {
		return fmt.Errorf("failed to parse tip leaf: %w", err)
	}
	tipMPTRoot, tipInCP := tipLeaf.MPTRoot, tipLeaf.InCP
	var tipRawInCP []byte
	if c.db != nil {
		if savedRaw, mErr := c.db.GetMetadata(kvstore.KeyMetaKVCheckpoint); mErr == nil && len(savedRaw) > 0 {
			tipRawInCP = savedRaw
		}
	}

	mptPersistedSize := c.mptMgr.PersistedSize()
	targetInputSize := tipInCP.Size

	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to get m_kv_size: %w", err)
	}

	// Grouped Invariant Checks: Target CP >= Cached Tiles >= m_kv_size >= Output Size >= MPT_Durable_Size
	if kvSize < targetInputSize {
		klog.Errorf("Invariant violation: m_kv_size (%d) < OutputLog tip size (%d)", kvSize, targetInputSize)
		return fmt.Errorf("%w: m_kv_size (%d) < OutputLog tip size (%d)", ErrInvariantViolation, kvSize, targetInputSize)
	}
	if kvSize < mptPersistedSize {
		klog.Errorf("Invariant violation: m_kv_size (%d) < MPT durable size (%d)", kvSize, mptPersistedSize)
		return fmt.Errorf("%w: m_kv_size (%d) < MPT durable size (%d)", ErrInvariantViolation, kvSize, mptPersistedSize)
	}
	if mptPersistedSize > targetInputSize {
		klog.Errorf("Invariant violation: MPT durable size (%d) > OutputLog tip size (%d)", mptPersistedSize, targetInputSize)
		return fmt.Errorf("%w: MPT durable size (%d) > OutputLog tip size (%d)", ErrInvariantViolation, mptPersistedSize, targetInputSize)
	}
	if mptPersistedSize == targetInputSize && c.mptMgr.IsExact() && c.mptMgr.Root() != tipMPTRoot {
		klog.Errorf("Invariant violation: MPT root mismatch at equal size %d (MPT root %x != tip root %x)", targetInputSize, c.mptMgr.Root(), tipMPTRoot)
		return fmt.Errorf("%w: MPT root mismatch at size %d: MPT %x, want tip %x", ErrRootMismatch, targetInputSize, c.mptMgr.Root(), tipMPTRoot)
	}

	if mptPersistedSize < targetInputSize || !c.mptMgr.IsExact() {
		replayStart := mptPersistedSize
		if replayStart == targetInputSize {
			replayStart = 0
		}
		if c.pub != nil && replayStart < c.pub.From() {
			replayStart = c.pub.From()
		}
		if replayStart < tipLeaf.From {
			replayStart = tipLeaf.From
		}
		var tipHash [sha256.Size]byte
		if len(tipInCP.Hash) == sha256.Size {
			tipHash = [sha256.Size]byte(tipInCP.Hash)
		}
		c.setFetcherTreeState(targetInputSize, tipHash)
		if c.pipeline == nil && c.fetcher != nil && c.mapper != nil {
			c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
			if c.fetchWorkers > 0 {
				c.pipeline.SetFetchWorkers(c.fetchWorkers)
			}
			if c.fetchBatchBundles > 0 {
				c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
			}
		}

		modifiedKeys := make(map[[sha256.Size]byte]string)

		if c.pipeline != nil {
			batchChan, errChan := c.pipeline.StreamBatches(ctx, replayStart, targetInputSize)
			for batch := range batchChan {
				for k := range batch.KeyMap {
					ck := hex.EncodeToString(k[:])
					if batch.CanonicalKeys != nil {
						if name, ok := batch.CanonicalKeys[k]; ok && name != "" {
							ck = name
						}
					}
					modifiedKeys[k] = ck
				}
			}
			if err := <-errChan; err != nil {
				return fmt.Errorf("stream batches failed during recovery: %w", err)
			}
		}

		mutations, err := c.indexer.GetKeyValueRoots(ctx, modifiedKeys, targetInputSize)
		if err != nil {
			return fmt.Errorf("failed to get value roots during Phase 2 replay: %w", err)
		}

		// Commit mutations to MPT
		actualRoot, err := c.mptMgr.CommitKeysWithVersion(mutations, int64(targetInputSize))
		if err != nil {
			return fmt.Errorf("mptMgr.CommitWithVersion failed during replay: %w", err)
		}
		if actualRoot != tipMPTRoot {
			klog.Errorf("Invariant violation: replayed MPT root %x != tip root %x at size %d", actualRoot, tipMPTRoot, targetInputSize)
			return fmt.Errorf("%w: replay reached root %x, want tip leaf root %x", ErrRootMismatch, actualRoot, tipMPTRoot)
		}
		if err := c.mptMgr.Persist(); err != nil {
			return fmt.Errorf("mptMgr.Persist failed during replay: %w", err)
		}
	}

	// Generate proof for tip leaf
	proof, err := c.outputLog.InclusionProof(ctx, tipIdx, outSize)
	if err != nil {
		return fmt.Errorf("failed to generate inclusion proof for tip leaf %d: %w", tipIdx, err)
	}

	rawOutCP, err := c.outputLog.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch output log checkpoint: %w", err)
	}
	outCP, err := wire.ParseCheckpointHeader(rawOutCP)
	if err != nil {
		return fmt.Errorf("failed to parse output log checkpoint: %w", err)
	}

	state := &tree.ServingState{
		OutputLogIndex: tipIdx,
		OutputLogSize:  outSize,
		OutputLogCP:    outCP,
		RawCheckpoint:  rawOutCP,
		OutputLogProof: proof,
		InputLogCP:     tipInCP,
		RawInputLogCP:  tipRawInCP,
		InputLogSize:   tipInCP.Size,
		MPTRoot:        tipMPTRoot,
		From:           tipLeaf.From,
	}
	if c.pub != nil {
		if c.pub.InputOrigin() == "" && tipInCP.Origin != "" {
			c.pub.SetInputOrigin(tipInCP.Origin)
		}
		if c.pub.From() == 0 && tipLeaf.From != 0 {
			c.pub.SetFrom(tipLeaf.From)
		}
	}
	c.pub.SetServingState(state)
	return nil
}

// SyncOnce fetches the latest checkpoint from the input log, streams and indexes missing batches.
// When outputLog.Size == 0 (unserved bootstrap), it executes Genesis Backfill.
// Once Leaf 0 is committed, it operates in Normal Serving Mode.
func (c *Coordinator) SyncOnce(ctx context.Context) error {
	if c.fetcher == nil {
		return nil
	}

	targetCP, err := c.fetcher.Checkpoint(ctx)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return fmt.Errorf("ingestion fetch checkpoint error: %w", err)
	}
	if targetCP == nil {
		return nil
	}

	if c.pub != nil && targetCP.Size < c.pub.From() {
		return fmt.Errorf("input log checkpoint size (%d) is below configured start index from (%d)", targetCP.Size, c.pub.From())
	}
	if c.pub != nil && c.pub.InputOrigin() == "" && targetCP.Origin != "" {
		c.pub.SetInputOrigin(targetCP.Origin)
	}

	var prevCP *log.Checkpoint
	if c.pub != nil {
		if state := c.pub.GetServingState(); state != nil && state.InputLogCP != nil {
			prevCP = state.InputLogCP
		}
	}
	if prevCP == nil && c.db != nil {
		for _, metaKey := range [][]byte{kvstore.KeyMetaKVCheckpoint, kvstore.KeyMetaTargetCheckpoint} {
			if rawCP, err := c.db.GetMetadata(metaKey); err == nil && len(rawCP) > 0 {
				if cp, pErr := wire.ParseCheckpointHeader(rawCP); pErr == nil {
					prevCP = cp
					break
				}
			}
		}
	}

	if prevCP != nil {
		if targetCP.Size < prevCP.Size {
			return fmt.Errorf("%w: input log checkpoint regressed from %d to %d", ErrInvariantViolation, prevCP.Size, targetCP.Size)
		}
		if targetCP.Size == prevCP.Size {
			if len(prevCP.Hash) == sha256.Size && !bytes.Equal(targetCP.Hash[:], prevCP.Hash) {
				return fmt.Errorf("%w: input log split-view at size %d: got %x, want %x", ErrInvariantViolation, targetCP.Size, targetCP.Hash, prevCP.Hash)
			}
		}
		if targetCP.Size > prevCP.Size && prevCP.Size > 0 && len(prevCP.Hash) == sha256.Size {
			if prover, ok := c.fetcher.(consistencyProver); ok {
				cProof, err := prover.ConsistencyProof(ctx, prevCP.Size, targetCP.Size)
				if err != nil {
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("failed to fetch input log consistency proof (%d -> %d): %w", prevCP.Size, targetCP.Size, err)
				}
				if err := proof.VerifyConsistency(rfc6962.DefaultHasher, prevCP.Size, targetCP.Size, cProof, prevCP.Hash, targetCP.Hash[:]); err != nil {
					metrics.InputFetchErrorsTotal.Inc()
					return fmt.Errorf("input log consistency verification failed (%d -> %d): %w", prevCP.Size, targetCP.Size, err)
				}
			}
		}
	}

	metrics.InputTreeSize.Set(float64(targetCP.Size))

	if err := c.db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw); err != nil {
		return fmt.Errorf("failed to persist target checkpoint: %w", err)
	}

	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return fmt.Errorf("failed to get output log size: %w", err)
	}

	if outSize == 0 {
		return c.syncGenesisBackfill(ctx, targetCP)
	}

	var startLogSize uint64
	if state := c.pub.GetServingState(); state != nil {
		startLogSize = state.InputLogSize
	}
	if c.pub != nil && startLogSize < c.pub.From() {
		startLogSize = c.pub.From()
	}

	if startLogSize >= targetCP.Size {
		return nil
	}

	if c.pipeline == nil {
		if c.mapper == nil {
			return errors.New("cannot initialize pipeline without leaf mapper")
		}
		c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
		if c.fetchWorkers > 0 {
			c.pipeline.SetFetchWorkers(c.fetchWorkers)
		}
		if c.fetchBatchBundles > 0 {
			c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
		}
	}

	allModifiedValueRoots := make(map[string][sha256.Size]byte)
	startTime := time.Now()
	startProgressSize := startLogSize
	lastLogSize := startLogSize
	const logInterval = uint64(100000)

	batchSize := c.commitBatchSize
	if batchSize == 0 {
		batchSize = DefaultCommitBatchSize
	}

	err = c.streamAndIndex(ctx, startLogSize, targetCP.Size, batchSize, func(drainCtx context.Context, batch *ingest.MappedBatch) error {
		res, err := c.indexer.IndexBatch(drainCtx, batch, targetCP)
		if err != nil {
			return fmt.Errorf("indexing error: %w", err)
		}
		metrics.KVCommittedSize.Set(float64(res.NewKVSize))
		metrics.LeavesIndexedTotal.Add(float64(batch.Count))
		for k, v := range res.ModifiedKeyValueRoots {
			allModifiedValueRoots[k] = v
		}
		metrics.IndexingLag.Set(float64(targetCP.Size - res.NewKVSize))
		if res.NewKVSize-lastLogSize >= logInterval || res.NewKVSize == targetCP.Size {
			elapsed := time.Since(startTime).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(res.NewKVSize-startProgressSize) / elapsed
			}
			klog.Infof("Indexing progress: %d / %d leaves (%.1f leaves/sec)", res.NewKVSize, targetCP.Size, rate)
			lastLogSize = res.NewKVSize
		}
		return nil
	})
	if err != nil {
		return err
	}
	klog.Infof("Milestone M2: Ingestion and KV store 100%% synced: %d leaves in %v", targetCP.Size, time.Since(startTime))

	logCP := &log.Checkpoint{
		Origin: targetCP.Origin,
		Size:   targetCP.Size,
		Hash:   targetCP.Hash[:],
	}
	if _, err := c.pub.PublishKeyBatch(ctx, allModifiedValueRoots, logCP, targetCP.Raw); err != nil {
		return fmt.Errorf("publish error: %w", err)
	}
	metrics.IndexingLag.Set(0)
	return nil
}

// syncGenesisBackfill executes the Genesis Backfill lifecycle for unserved bootstrap indexing (outputLog.Size() == 0).
func (c *Coordinator) syncGenesisBackfill(ctx context.Context, targetCP *ingest.Checkpoint) error {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	mptPersistedSize := c.mptMgr.PersistedSize()

	if mptPersistedSize > kvSize {
		klog.Errorf("Invariant violation: MPT durable size (%d) > m_kv_size (%d) during genesis backfill", mptPersistedSize, kvSize)
		return fmt.Errorf("%w: MPT durable size (%d) > m_kv_size (%d)", ErrInvariantViolation, mptPersistedSize, kvSize)
	}

	if mptPersistedSize < kvSize || (!c.mptMgr.IsExact() && kvSize > 0) {
		if err := c.recoverGenesisBackfill(ctx); err != nil {
			return fmt.Errorf("genesis dirty crash recovery failed: %w", err)
		}
		mptPersistedSize = c.mptMgr.PersistedSize()
	}

	startLogSize := min(kvSize, mptPersistedSize)
	if c.pub != nil && startLogSize < c.pub.From() {
		startLogSize = c.pub.From()
	}
	if startLogSize >= targetCP.Size {
		return c.finalizeGenesisBackfill(ctx, targetCP, nil)
	}

	if c.pipeline == nil {
		if c.mapper == nil {
			return errors.New("cannot initialize pipeline without leaf mapper")
		}
		c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
		if c.fetchWorkers > 0 {
			c.pipeline.SetFetchWorkers(c.fetchWorkers)
		}
		if c.fetchBatchBundles > 0 {
			c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
		}
	}
	c.setFetcherTreeState(targetCP.Size, targetCP.Hash)

	batchSize := c.CommitBatchSize()
	coarseInterval := c.CoarseCheckpointInterval()
	maxPendingKeys := c.BackfillMaxPendingKeys()
	lastCheckpointLeaf := mptPersistedSize
	lastIndexedSize := startLogSize

	startTime := time.Now()
	startProgressSize := startLogSize
	lastLogSize := startLogSize
	const logInterval = uint64(100000)

	activeBuffer := make(map[string][sha256.Size]byte)
	leavesSinceCheckpoint := uint64(0)

	flushCoarseCheckpoint := func(checkpointSize uint64) error {
		if len(activeBuffer) == 0 && checkpointSize <= lastCheckpointLeaf {
			return nil
		}
		flushStart := time.Now()
		klog.Infof("Genesis backfill: flushing %d deduplicated keys to MPT at leaf %d...", len(activeBuffer), checkpointSize)
		if err := c.db.Sync(); err != nil {
			return fmt.Errorf("genesis flush db.Sync error: %w", err)
		}
		if len(activeBuffer) > 0 {
			if err := c.mptMgr.SetKeyBatch(activeBuffer); err != nil {
				return fmt.Errorf("genesis mpt.SetKeyBatch error: %w", err)
			}
		}
		if _, err := c.mptMgr.Snap(int64(checkpointSize)); err != nil {
			return fmt.Errorf("genesis mpt.Snap error: %w", err)
		}
		if err := c.mptMgr.Sync(); err != nil {
			return fmt.Errorf("genesis mpt.Sync error: %w", err)
		}
		clear(activeBuffer)
		leavesSinceCheckpoint = 0
		lastCheckpointLeaf = checkpointSize
		klog.Infof("Genesis backfill coarse checkpoint completed at leaf %d in %v", checkpointSize, time.Since(flushStart))
		return nil
	}

	streamErr := c.streamAndIndex(ctx, startLogSize, targetCP.Size, batchSize, func(drainCtx context.Context, batch *ingest.MappedBatch) error {
		res, err := c.indexer.IndexBatch(drainCtx, batch, targetCP)
		if err != nil {
			return fmt.Errorf("genesis indexing error: %w", err)
		}
		lastIndexedSize = res.NewKVSize
		leavesSinceCheckpoint += uint64(batch.Count)
		metrics.KVCommittedSize.Set(float64(res.NewKVSize))
		metrics.LeavesIndexedTotal.Add(float64(batch.Count))
		metrics.IndexingLag.Set(float64(targetCP.Size - res.NewKVSize))

		for k, v := range res.ModifiedKeyValueRoots {
			activeBuffer[k] = v
		}
		res.ModifiedValueRoots = nil
		res.ModifiedKeyValueRoots = nil

		flushNeeded := (maxPendingKeys > 0 && uint64(len(activeBuffer)) >= maxPendingKeys) ||
			(coarseInterval > 0 && res.NewKVSize < targetCP.Size && leavesSinceCheckpoint >= coarseInterval)

		if res.NewKVSize < targetCP.Size && flushNeeded {
			if err := flushCoarseCheckpoint(res.NewKVSize); err != nil {
				return err
			}
		}

		if res.NewKVSize-lastLogSize >= logInterval || res.NewKVSize == targetCP.Size {
			elapsed := time.Since(startTime).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(res.NewKVSize-startProgressSize) / elapsed
			}
			klog.Infof("Genesis backfill progress: %d / %d leaves (%.1f leaves/sec, %d pending keys in active buffer)", res.NewKVSize, targetCP.Size, rate, len(activeBuffer))
			lastLogSize = res.NewKVSize
		}
		return nil
	})

	if streamErr != nil {
		// On graceful context shutdown / cancellation, execute coarse checkpoint if progress was made
		if lastIndexedSize > lastCheckpointLeaf {
			if err := flushCoarseCheckpoint(lastIndexedSize); err == nil {
				klog.Infof("Genesis backfill shutdown checkpoint saved at leaf %d", lastIndexedSize)
			}
		}
		return streamErr
	}

	return c.finalizeGenesisBackfill(ctx, targetCP, activeBuffer)
}

func (c *Coordinator) finalizeGenesisBackfill(ctx context.Context, targetCP *ingest.Checkpoint, pendingValueRoots map[string][sha256.Size]byte) error {
	if err := c.db.Sync(); err != nil {
		return fmt.Errorf("genesis final db.Sync error: %w", err)
	}
	if len(pendingValueRoots) > 0 {
		klog.Infof("Genesis backfill: applying final %d deduplicated keys to MPT at leaf %d...", len(pendingValueRoots), targetCP.Size)
		if err := c.mptMgr.SetKeyBatch(pendingValueRoots); err != nil {
			return fmt.Errorf("genesis final mpt.SetKeyBatch error: %w", err)
		}
	}
	finalRoot, err := c.mptMgr.Snap(int64(targetCP.Size))
	if err != nil {
		return fmt.Errorf("genesis final mpt.Snap error: %w", err)
	}
	if err := c.mptMgr.Sync(); err != nil {
		return fmt.Errorf("genesis final mpt.Sync error: %w", err)
	}

	var logCP *log.Checkpoint
	var rawCP []byte
	if targetCP != nil {
		logCP = &log.Checkpoint{
			Origin: targetCP.Origin,
			Size:   targetCP.Size,
			Hash:   targetCP.Hash[:],
		}
		rawCP = targetCP.Raw
	}
	if _, err := c.pub.PublishKeyBatch(ctx, nil, logCP, rawCP); err != nil {
		return fmt.Errorf("genesis Leaf 0 publish error: %w", err)
	}
	metrics.IndexingLag.Set(0)
	klog.Infof("STATE TRANSITION: Genesis Backfill -> Normal Serving Mode. Leaf 0 committed to Output Log (root: %x, input size: %d). HTTP read endpoints (/keys, /values, /checkpoint) are now ACTIVE.", finalRoot, targetCP.Size)
	return nil
}

// streamAndIndex coordinates pipelined double-buffered batch consumption and indexing.
// The reader goroutine streams and aggregates bundles into MappedBatch slabs of batchSize.
// Slabs are dispatched via a bounded channel (capacity 32) to a dedicated committer goroutine,
// overlapping WASM mapping and fetch I/O with Pebble KV indexing and disk commits.
func (c *Coordinator) streamAndIndex(
	ctx context.Context,
	fromLeaf, toLeaf uint64,
	batchSize uint64,
	indexFn func(ctx context.Context, batch *ingest.MappedBatch) error,
) error {
	if fromLeaf >= toLeaf {
		return nil
	}
	if c.pipeline == nil {
		return errors.New("cannot stream and index: pipeline not initialized")
	}
	if batchSize == 0 {
		batchSize = DefaultCommitBatchSize
	}

	g, gCtx := errgroup.WithContext(ctx)
	// Multi-slab buffering: up to 32 slabs draining/pending in committer while reader actively accumulates.
	slabChan := make(chan *ingest.MappedBatch, 32)

	// Committer goroutine: drains slabs sequentially in strict monotonic order.
	g.Go(func() error {
		for slab := range slabChan {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}
			if err := indexFn(gCtx, slab); err != nil {
				return err
			}
		}
		return nil
	})

	// Reader goroutine: streams bundles and aggregates into slabs.
	g.Go(func() error {
		defer close(slabChan)
		batchChan, errChan := c.pipeline.StreamBatches(gCtx, fromLeaf, toLeaf)
		var pendingBatch *ingest.MappedBatch

		for batch := range batchChan {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}

			if batch.EndLeafIdx == 0 && batch.Count > 0 {
				batch.EndLeafIdx = batch.StartLeafIdx + uint64(batch.Count)
			}
			if pendingBatch == nil {
				pendingBatch = batch
			} else {
				pendingBatch.Merge(batch)
			}

			if pendingBatch.EndLeafIdx-pendingBatch.StartLeafIdx >= batchSize {
				select {
				case slabChan <- pendingBatch:
					pendingBatch = nil
				case <-gCtx.Done():
					return gCtx.Err()
				}
			}
		}

		if err, ok := <-errChan; ok && err != nil {
			return fmt.Errorf("stream batches failed: %w", err)
		}

		if pendingBatch != nil && pendingBatch.EndLeafIdx > pendingBatch.StartLeafIdx {
			select {
			case slabChan <- pendingBatch:
			case <-gCtx.Done():
				return gCtx.Err()
			}
		}
		return nil
	})

	return g.Wait()
}

func isFatalSyncError(err error) bool {
	return errors.Is(err, ingest.ErrWasmHalt) ||
		errors.Is(err, ingest.ErrInvalidMemory) ||
		errors.Is(err, ingest.ErrMalformedOutput) ||
		errors.Is(err, ingest.ErrUnalignedOutput) ||
		errors.Is(err, ErrInvariantViolation) ||
		errors.Is(err, ErrRootMismatch)
}

// Run executes startup recovery and enters the periodic ingestion polling loop until ctx is canceled.
func (c *Coordinator) Run(ctx context.Context, pollInterval time.Duration) error {
	if err := c.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	if err := c.SyncOnce(ctx); err != nil {
		if isFatalSyncError(err) {
			return fmt.Errorf("fatal initial sync error: %w", err)
		}
		klog.Warningf("Initial sync error: %v", err)
	}

	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.SyncOnce(ctx); err != nil {
				if isFatalSyncError(err) {
					return fmt.Errorf("fatal sync error: %w", err)
				}
				klog.Warningf("Sync error: %v", err)
			}
		}
	}
}
