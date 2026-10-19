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

package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"k8s.io/klog/v2"
)

var keyMetaKVSize = []byte("m_kv_size")

// KVSizeReader reads the latest indexed KV watermark.
type KVSizeReader interface {
	GetUint64(key []byte) (uint64, error)
}

// TreeSizeReader reads the persisted tree version watermark.
type TreeSizeReader interface {
	PersistedSize() uint64
}

// TileReaper periodically deletes pruned cached tile files below the SafeWatermark.
// SafeWatermark = min(m_kv_size, MPT.PersistedSize()).
type TileReaper struct {
	kvReader    KVSizeReader
	treeReader  TreeSizeReader
	cache       TilePruner
	watermarkFn func(context.Context) (uint64, error)
}

// NewTileReaper creates a new TileReaper instance.
func NewTileReaper(kvReader KVSizeReader, treeReader TreeSizeReader, cache TilePruner) *TileReaper {
	return &TileReaper{
		kvReader:   kvReader,
		treeReader: treeReader,
		cache:      cache,
	}
}

// SetWatermarkFunc configures a coordinator-governed watermark provider (e.g. Coordinator.SafeWatermark).
func (r *TileReaper) SetWatermarkFunc(fn func(context.Context) (uint64, error)) {
	r.watermarkFn = fn
}

// New creates a new TileReaper instance (alias for NewTileReaper).
func New(kvReader KVSizeReader, treeReader TreeSizeReader, cache TilePruner) *TileReaper {
	return NewTileReaper(kvReader, treeReader, cache)
}

// SafeWatermark returns min(m_kv_size, MPT.PersistedSize()).
func (r *TileReaper) SafeWatermark(ctx context.Context) (uint64, error) {
	if r.watermarkFn != nil {
		return r.watermarkFn(ctx)
	}
	if r.kvReader == nil {
		return 0, nil
	}
	kvSize, err := r.kvReader.GetUint64(keyMetaKVSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read m_kv_size: %w", err)
	}

	watermark := kvSize
	if r.treeReader != nil {
		treeSize := r.treeReader.PersistedSize()
		if treeSize < watermark {
			watermark = treeSize
		}
	}
	return watermark, nil
}

func (r *TileReaper) updateDirSizeMetric() {
	if sizer, ok := r.cache.(DirSizer); ok {
		if size, err := sizer.DirSize(); err == nil {
			metrics.TileCacheBytes.Set(float64(size))
		}
	}
}

// PruneOnce executes a single tile garbage collection pass.
// It prunes cached tiles strictly below SafeWatermark.
func (r *TileReaper) PruneOnce(ctx context.Context) (uint64, int, error) {
	defer r.updateDirSizeMetric()

	watermark, err := r.SafeWatermark(ctx)
	if err != nil {
		return 0, 0, err
	}

	if watermark == 0 || r.cache == nil {
		return watermark, 0, nil
	}

	n, err := r.cache.PruneBefore(watermark)
	if err != nil {
		return watermark, n, fmt.Errorf("failed to prune tiles before watermark %d: %w", watermark, err)
	}

	if n > 0 {
		klog.V(1).Infof("TileReaper: pruned %d cached tiles below watermark %d", n, watermark)
	}

	return watermark, n, nil
}

// Run runs the reaper loop at the given interval until ctx is cancelled.
func (r *TileReaper) Run(ctx context.Context, interval time.Duration) error {
	r.updateDirSizeMetric()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, _, err := r.PruneOnce(ctx); err != nil {
				klog.Warningf("TileReaper pass failed: %v", err)
			}
		}
	}
}
