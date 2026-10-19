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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

type posixConfig struct {
	origin             string
	batchMaxSize       uint16
	batchMaxAge        time.Duration
	checkpointInterval time.Duration
	pollPeriod         time.Duration
	witnessGroup       *tessera.WitnessGroup
	witnessOpts        *tessera.WitnessOptions
}

// POSIXOption configures a POSIXOutputLog instance.
type POSIXOption func(*posixConfig)

// WithOrigin sets the origin string for the log.
func WithOrigin(origin string) POSIXOption {
	return func(c *posixConfig) {
		c.origin = origin
	}
}

// WithBatchMaxSize sets the maximum batch size for entry integration.
func WithBatchMaxSize(size uint16) POSIXOption {
	return func(c *posixConfig) {
		c.batchMaxSize = size
	}
}

// WithBatchMaxAge sets the maximum duration to wait before committing a batch.
func WithBatchMaxAge(d time.Duration) POSIXOption {
	return func(c *posixConfig) {
		c.batchMaxAge = d
	}
}

// WithCheckpointInterval sets the interval for issuing checkpoints.
func WithCheckpointInterval(d time.Duration) POSIXOption {
	return func(c *posixConfig) {
		c.checkpointInterval = d
	}
}

// WithPollPeriod sets the polling interval for checkpoint publication awaiting.
func WithPollPeriod(d time.Duration) POSIXOption {
	return func(c *posixConfig) {
		c.pollPeriod = d
	}
}

// WithWitnessGroup configures witness cosigning for published checkpoints.
func WithWitnessGroup(wg tessera.WitnessGroup, opts *tessera.WitnessOptions) POSIXOption {
	return func(c *posixConfig) {
		c.witnessGroup = &wg
		c.witnessOpts = opts
	}
}

// WithDefaultWitnessGroup configures mandatory (fail-closed) witness cosigning for published checkpoints.
func WithDefaultWitnessGroup(wg tessera.WitnessGroup) POSIXOption {
	return WithWitnessGroup(wg, &tessera.WitnessOptions{FailOpen: false})
}

// BuildWitnessGroup constructs a tessera.WitnessGroup requiring cosignatures from all configured witnesses.
func BuildWitnessGroup(urls, pubKeys []string) (tessera.WitnessGroup, error) {
	if len(urls) != len(pubKeys) {
		return tessera.WitnessGroup{}, fmt.Errorf("witness URLs count (%d) does not match witness pubkeys count (%d)", len(urls), len(pubKeys))
	}
	if len(urls) == 0 {
		return tessera.WitnessGroup{}, nil
	}
	var wg tessera.WitnessGroup
	for i := range urls {
		rawURL := strings.TrimSpace(urls[i])
		pubKey := strings.TrimSpace(pubKeys[i])
		if rawURL == "" || pubKey == "" {
			return tessera.WitnessGroup{}, fmt.Errorf("witness URL and pubkey at index %d must not be empty", i)
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return tessera.WitnessGroup{}, fmt.Errorf("invalid witness URL %q at index %d: %w", rawURL, i, err)
		}
		w, err := tessera.NewWitness(pubKey, u)
		if err != nil {
			return tessera.WitnessGroup{}, fmt.Errorf("invalid witness at index %d: %w", i, err)
		}
		if i == 0 {
			wg = tessera.NewWitnessGroup(1, w)
		} else {
			wg = tessera.NewWitnessGroup(2, wg, w)
		}
	}
	return wg, nil
}

// POSIXOutputLog wraps a Tessera POSIX-backed tile log for appending and serving output log commitments.
type POSIXOutputLog struct {
	appender  *tessera.Appender
	awaiter   *tessera.PublicationAwaiter
	logReader tessera.LogReader
	shutdown  func(context.Context) error
	cancel    context.CancelFunc
	origin    string
	closeOnce sync.Once
	closeErr  error
}

var _ OutputLogClient = (*POSIXOutputLog)(nil)

// NewPOSIXOutputLog initializes and returns a new POSIXOutputLog.
func NewPOSIXOutputLog(ctx context.Context, storageDir string, signer note.Signer, opts ...POSIXOption) (*POSIXOutputLog, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}
	if storageDir == "" {
		return nil, errors.New("storageDir must not be empty")
	}

	cfg := posixConfig{
		batchMaxSize:       1,
		batchMaxAge:        time.Millisecond,
		checkpointInterval: 100 * time.Millisecond,
		pollPeriod:         10 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.origin == "" {
		cfg.origin = signer.Name()
	} else if cfg.origin != signer.Name() {
		return nil, fmt.Errorf("configured origin %q does not match signer name %q", cfg.origin, signer.Name())
	}

	driver, err := posix.New(ctx, posix.Config{Path: storageDir})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize posix storage: %w", err)
	}

	cpInterval := cfg.checkpointInterval
	if cpInterval < 100*time.Millisecond {
		cpInterval = 100 * time.Millisecond
	}

	appendOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(uint(cfg.batchMaxSize), cfg.batchMaxAge).
		WithCheckpointInterval(cpInterval)

	if cfg.witnessGroup != nil {
		appendOpts.WithWitnesses(*cfg.witnessGroup, cfg.witnessOpts)
	}

	appCtx, cancel := context.WithCancel(context.Background())
	appender, shutdown, logReader, err := tessera.NewAppender(appCtx, driver, appendOpts)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create appender: %w", err)
	}

	awaiter := tessera.NewPublicationAwaiter(appCtx, logReader.ReadCheckpoint, cfg.pollPeriod)

	return &POSIXOutputLog{
		appender:  appender,
		awaiter:   awaiter,
		logReader: logReader,
		shutdown:  shutdown,
		cancel:    cancel,
		origin:    cfg.origin,
	}, nil
}

// Origin returns the configured origin for the output log.
func (l *POSIXOutputLog) Origin() string {
	return l.origin
}

// Append appends a leaf to the log and awaits publication in a signed checkpoint.
func (l *POSIXOutputLog) Append(ctx context.Context, leafData []byte) (leafIdx uint64, cp []byte, err error) {
	index, rawCP, err := l.awaiter.Await(ctx, l.appender.Add(ctx, tessera.NewEntry(leafData)))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to append leaf: %w", err)
	}
	return index.Index, rawCP, nil
}

// InclusionProof builds an inclusion proof for the leaf at leafIdx in a tree of size treeSize.
func (l *POSIXOutputLog) InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	pb, err := client.NewProofBuilder(ctx, treeSize, l.logReader.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder: %w", err)
	}
	proof, err := pb.InclusionProof(ctx, leafIdx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate inclusion proof: %w", err)
	}
	proofRes := make([][sha256.Size]byte, len(proof))
	for i, p := range proof {
		if len(p) != sha256.Size {
			return nil, fmt.Errorf("invalid proof element size %d at %d, want %d", len(p), i, sha256.Size)
		}
		copy(proofRes[i][:], p)
	}
	return proofRes, nil
}

// Size returns the size of the latest published checkpoint, or 0 if no checkpoint exists yet.
func (l *POSIXOutputLog) Size(ctx context.Context) (uint64, error) {
	rawCP, err := l.logReader.ReadCheckpoint(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read checkpoint: %w", err)
	}
	cp, err := ParseCheckpointHeader(rawCP)
	if err != nil {
		return 0, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	return cp.Size, nil
}

// Checkpoint returns the raw bytes of the latest published checkpoint, or nil if none exists yet.
func (l *POSIXOutputLog) Checkpoint(ctx context.Context) ([]byte, error) {
	rawCP, err := l.logReader.ReadCheckpoint(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}
	return rawCP, nil
}

// GetLeaf retrieves the leaf payload at idx from the appropriate entry bundle.
func (l *POSIXOutputLog) GetLeaf(ctx context.Context, idx uint64) ([]byte, error) {
	size, err := l.Size(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tree size: %w", err)
	}
	if idx >= size {
		return nil, fmt.Errorf("leaf index %d out of range for tree size %d", idx, size)
	}
	bundleIndex := idx / layout.EntryBundleWidth
	offset := idx % layout.EntryBundleWidth

	bundle, err := client.GetEntryBundle(ctx, l.logReader.ReadEntryBundle, bundleIndex, size)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry bundle: %w", err)
	}
	if int(offset) >= len(bundle.Entries) {
		return nil, fmt.Errorf("leaf index %d offset %d out of range in bundle (len %d)", idx, offset, len(bundle.Entries))
	}
	return bundle.Entries[offset], nil
}

// Close gracefully terminates the log appender and publication awaiter.
func (l *POSIXOutputLog) Close() error {
	l.closeOnce.Do(func() {
		if l.shutdown != nil {
			l.closeErr = l.shutdown(context.Background())
		}
		if l.cancel != nil {
			l.cancel()
		}
	})
	return l.closeErr
}
