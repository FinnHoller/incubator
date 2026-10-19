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

// Package ingest coordinates fetching leaves from the Input Log, mapping them via WASM/MapFn, and streaming ordered batches.
package ingest

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
)

const (
	// DefaultBundleSize is the default number of leaves per LeafBundle.
	DefaultBundleSize uint64 = wasmhost.DefaultBundleSize
)

var (
	ErrFetcherClosed    = errors.New("tile fetcher is closed")
	ErrPipelineHalt     = errors.New("ingestion pipeline halted")
	ErrBundleNotFound   = errors.New("bundle not found in cache")
	ErrInvalidWatermark = errors.New("invalid watermark")
)

// Checkpoint represents an Input Log checkpoint note preserving raw bit-for-bit bytes.
type Checkpoint struct {
	Raw        []byte
	Origin     string
	Size       uint64
	Hash       [sha256.Size]byte
	Extension  []byte
	Signatures []string
}

// LeafBundle contains a chunk of contiguous raw leaves from the Input Log.
type LeafBundle struct {
	BundleIdx    uint64
	StartLeafIdx uint64
	Leaves       [][]byte
	PooledBuf    *PooledBuffer
}

// Retain increments the reference count of the underlying pooled buffer, if any.
func (b *LeafBundle) Retain() {
	if b != nil && b.PooledBuf != nil {
		b.PooledBuf.Retain()
	}
}

// Release decrements the reference count of the underlying pooled buffer, returning it to pool on zero.
func (b *LeafBundle) Release() {
	if b != nil && b.PooledBuf != nil {
		b.PooledBuf.Release()
	}
}

// MappedBatch contains the extracted key-to-indices mapping for a LeafBundle.
type MappedBatch struct {
	BundleIdx     uint64
	StartLeafIdx  uint64
	EndLeafIdx    uint64
	Count         uint32
	KeyMap        map[[32]byte][]uint64
	CanonicalKeys map[[32]byte]string
}

// BundleMapper is an optional optimization interface for LeafMappers supporting batched execution.
type BundleMapper = wasmhost.BundleMapper

// RunnerProvider is an optional optimization interface for LeafMappers that can furnish dedicated runners per worker.
type RunnerProvider = wasmhost.RunnerProvider


// Merge combines another MappedBatch into this one.
func (b *MappedBatch) Merge(other *MappedBatch) {
	if other == nil {
		return
	}
	if b.EndLeafIdx == 0 && b.Count > 0 {
		b.EndLeafIdx = b.StartLeafIdx + uint64(b.Count)
	}
	otherEnd := other.EndLeafIdx
	if otherEnd == 0 && other.Count > 0 {
		otherEnd = other.StartLeafIdx + uint64(other.Count)
	}
	if b.KeyMap == nil {
		b.KeyMap = make(map[[32]byte][]uint64)
	}
	for k, indices := range other.KeyMap {
		b.KeyMap[k] = append(b.KeyMap[k], indices...)
	}
	if len(other.CanonicalKeys) > 0 {
		if b.CanonicalKeys == nil {
			b.CanonicalKeys = make(map[[32]byte]string, len(other.CanonicalKeys))
		}
		for kh, ck := range other.CanonicalKeys {
			if ck != "" {
				b.CanonicalKeys[kh] = ck
			}
		}
	}
	if otherEnd > b.EndLeafIdx {
		b.EndLeafIdx = otherEnd
	}
	b.Count = uint32(b.EndLeafIdx - b.StartLeafIdx)
}

// TileFetcher defines methods needed to fetch checkpoints and leaf bundles from an Input Log.
type TileFetcher interface {
	Checkpoint(ctx context.Context) (*Checkpoint, error)
	FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error)
	Leaf(ctx context.Context, idx uint64) ([]byte, error)
}

// TileCache defines local caching and garbage collection of raw tile bundles.
type TileCache interface {
	GetBundle(bundleIdx uint64) (*LeafBundle, error)
	PutBundle(bundle *LeafBundle) error
	PruneBefore(watermark uint64) (int, error)
}

// TilePruner defines an interface for components that can prune cached tiles below a watermark.
type TilePruner interface {
	PruneBefore(watermark uint64) (int, error)
}

// DirSizer defines an optional interface for caches that can compute disk space usage.
type DirSizer interface {
	DirSize() (int64, error)
}
