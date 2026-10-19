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

package hammer

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// CheckpointQueue holds signed checkpoints produced by the sequencer awaiting drip-feed release.
type CheckpointQueue struct {
	mu    sync.Mutex
	items [][]byte
}

// NewCheckpointQueue creates an empty CheckpointQueue.
func NewCheckpointQueue() *CheckpointQueue {
	return &CheckpointQueue{}
}

// Enqueue adds a checkpoint to the queue.
func (q *CheckpointQueue) Enqueue(cp []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, cp)
}

// Dequeue removes and returns the oldest checkpoint from the queue.
func (q *CheckpointQueue) Dequeue() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, false
	}
	cp := q.items[0]
	q.items = q.items[1:]
	return cp, true
}

// DequeueBurst removes and returns up to maxCount checkpoints.
func (q *CheckpointQueue) DequeueBurst(maxCount int) [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	if maxCount <= 0 || maxCount >= len(q.items) {
		res := q.items
		q.items = nil
		return res
	}
	res := q.items[:maxCount]
	q.items = q.items[maxCount:]
	return res
}

// Len returns the current count of queued checkpoints.
func (q *CheckpointQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// PeekLatest returns the most recent checkpoint in the queue without removing it.
func (q *CheckpointQueue) PeekLatest() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, false
	}
	return q.items[len(q.items)-1], true
}

// SequencerConfig configures the Tessera input log sequencer.
type SequencerConfig struct {
	StorageDir         string
	Origin             string
	SignerKey          string
	WriteRate          float64 // Leaves per second (0 = unconstrained)
	WriteGoal          uint64  // Total leaves to write before stopping (0 = continuous)
	BatchSize          uint
	BatchTimeout       time.Duration
	CheckpointInterval time.Duration
	AwaitPollPeriod    time.Duration
}

// DefaultSequencerConfig returns sensible defaults for the sequencer.
func DefaultSequencerConfig(storageDir string) SequencerConfig {
	return SequencerConfig{
		StorageDir:         storageDir,
		Origin:             "example.com/hammer/inputlog",
		WriteRate:          500,
		BatchSize:          4096,
		BatchTimeout:       10 * time.Millisecond,
		CheckpointInterval: 100 * time.Millisecond,
		AwaitPollPeriod:    10 * time.Millisecond,
	}
}

// SequencerStats holds atomic telemetry counters.
type SequencerStats struct {
	LeavesWritten      uint64
	CheckpointsCreated uint64
	LatestTreeSize     uint64
}

// Sequencer writes generated leaves to a local Tessera POSIX log and enqueues newly signed checkpoints.
type Sequencer struct {
	cfg          SequencerConfig
	generator    *Generator
	queue        *CheckpointQueue
	driver       tessera.Driver
	appender     *tessera.Appender
	shutdownFn   func(context.Context) error
	reader       tessera.LogReader
	awaiter      *tessera.PublicationAwaiter
	signer       note.Signer
	verifier     note.Verifier
	signerKey    string
	verifierKey  string
	stats        SequencerStats
	lastSeenSize uint64
	mu           sync.Mutex
}

// NewSequencer initializes a new Tessera POSIX sequencer.
func NewSequencer(ctx context.Context, cfg SequencerConfig, gen *Generator, queue *CheckpointQueue) (*Sequencer, error) {
	if cfg.Origin == "" {
		cfg.Origin = "example.com/hammer/inputlog"
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 4096
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 10 * time.Millisecond
	}
	if cfg.CheckpointInterval < 100*time.Millisecond {
		cfg.CheckpointInterval = 100 * time.Millisecond
	}
	if cfg.AwaitPollPeriod == 0 {
		cfg.AwaitPollPeriod = 10 * time.Millisecond
	}
	if queue == nil {
		queue = NewCheckpointQueue()
	}

	var signer note.Signer
	var verifier note.Verifier
	var skey, vkey string
	var err error

	if cfg.SignerKey != "" {
		skey = cfg.SignerKey
		signer, verifier, err = fnote.NewEd25519SignerVerifier(skey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse signer key: %w", err)
		}
	} else {
		skey, vkey, err = note.GenerateKey(rand.Reader, cfg.Origin)
		if err != nil {
			return nil, fmt.Errorf("failed to generate note key: %w", err)
		}
		signer, verifier, err = fnote.NewEd25519SignerVerifier(skey)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer/verifier: %w", err)
		}
	}

	driver, err := posix.New(ctx, posix.Config{Path: cfg.StorageDir})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize POSIX log at %q: %w", cfg.StorageDir, err)
	}

	appendOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCheckpointInterval(cfg.CheckpointInterval).
		WithBatching(cfg.BatchSize, cfg.BatchTimeout)

	appender, shutdownFn, reader, err := tessera.NewAppender(ctx, driver, appendOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Tessera appender: %w", err)
	}

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, cfg.AwaitPollPeriod)

	return &Sequencer{
		cfg:         cfg,
		generator:   gen,
		queue:       queue,
		driver:      driver,
		appender:    appender,
		shutdownFn:  shutdownFn,
		reader:      reader,
		awaiter:     awaiter,
		signer:      signer,
		verifier:    verifier,
		signerKey:   skey,
		verifierKey: vkey,
	}, nil
}

// Verifier returns the note verifier for the Input Log checkpoints.
func (s *Sequencer) Verifier() note.Verifier {
	return s.verifier
}

// VerifierKey returns the verifier string.
func (s *Sequencer) VerifierKey() string {
	return s.verifierKey
}

// Origin returns the origin string for the Input Log.
func (s *Sequencer) Origin() string {
	return s.cfg.Origin
}

// Queue returns the CheckpointQueue.
func (s *Sequencer) Queue() *CheckpointQueue {
	return s.queue
}

// Stats returns a snapshot of current sequencer stats.
func (s *Sequencer) Stats() SequencerStats {
	return SequencerStats{
		LeavesWritten:      atomic.LoadUint64(&s.stats.LeavesWritten),
		CheckpointsCreated: atomic.LoadUint64(&s.stats.CheckpointsCreated),
		LatestTreeSize:     atomic.LoadUint64(&s.stats.LatestTreeSize),
	}
}

// WriteLeaf appends a single leaf to the log and waits for it to be integrated and published.
func (s *Sequencer) WriteLeaf(ctx context.Context, leafData []byte) (uint64, []byte, error) {
	fut := s.appender.Add(ctx, tessera.NewEntry(leafData))
	idx, cpBytes, err := s.awaiter.Await(ctx, fut)
	if err != nil {
		return 0, nil, err
	}

	atomic.AddUint64(&s.stats.LeavesWritten, 1)
	s.observeCheckpoint(cpBytes)

	return idx.Index, cpBytes, nil
}

// RunLoop continuously writes generated leaves to the log at cfg.WriteRate until ctx is cancelled or WriteGoal is reached.
func (s *Sequencer) RunLoop(ctx context.Context) error {
	var ticker *time.Ticker
	if s.cfg.WriteRate > 0 {
		interval := time.Duration(float64(time.Second) / s.cfg.WriteRate)
		if interval < time.Microsecond {
			interval = time.Microsecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	// Background awaiter loop: periodically tracks latest published checkpoint
	go s.checkpointPoller(ctx)

	var lastFut tessera.IndexFuture
	for {
		if s.cfg.WriteGoal > 0 && atomic.LoadUint64(&s.stats.LeavesWritten) >= s.cfg.WriteGoal {
			if lastFut != nil {
				_, cpBytes, err := s.awaiter.Await(ctx, lastFut)
				if err == nil && len(cpBytes) > 0 {
					s.observeCheckpoint(cpBytes)
				}
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if ticker != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}

		leaf := s.generator.NextLeaf()
		fut := s.appender.Add(ctx, tessera.NewEntry(leaf.LeafData))
		lastFut = fut
		atomic.AddUint64(&s.stats.LeavesWritten, 1)

		// Every batch of leaves, await to capture checkpoint updates
		if atomic.LoadUint64(&s.stats.LeavesWritten)%uint64(s.cfg.BatchSize) == 0 {
			go func(f tessera.IndexFuture) {
				_, cpBytes, err := s.awaiter.Await(ctx, f)
				if err == nil && len(cpBytes) > 0 {
					s.observeCheckpoint(cpBytes)
				}
			}(fut)
		}
	}
}

func (s *Sequencer) checkpointPoller(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.CheckpointInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rawCP, err := s.reader.ReadCheckpoint(ctx)
			if err != nil || len(rawCP) == 0 {
				continue
			}
			s.observeCheckpoint(rawCP)
		}
	}
}

func (s *Sequencer) observeCheckpoint(rawCP []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parsed, _, _, err := log.ParseCheckpoint(rawCP, s.cfg.Origin, s.verifier)
	if err != nil {
		return
	}

	if parsed.Size > s.lastSeenSize {
		s.lastSeenSize = parsed.Size
		atomic.StoreUint64(&s.stats.LatestTreeSize, parsed.Size)
		atomic.AddUint64(&s.stats.CheckpointsCreated, 1)
		s.queue.Enqueue(rawCP)
		klog.V(2).Infof("Sequencer published checkpoint size %d (queued count: %d)", parsed.Size, s.queue.Len())
	}
}

// Close shuts down the Tessera appender gracefully.
func (s *Sequencer) Close(ctx context.Context) error {
	if s.shutdownFn != nil {
		return s.shutdownFn(ctx)
	}
	return nil
}
