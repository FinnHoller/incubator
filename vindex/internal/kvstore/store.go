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

package kvstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
)

// DB wraps a Pebble database with VIndex conventions.
type DB struct {
	db               *pebble.DB
	cache            *pebble.Cache
	chunkSize        uint64
	maxChunksPerReq  int
	hasCanonicalKeys atomic.Bool
	closeMu          sync.Mutex
	closed           bool
}

// MarkHasCanonicalKeys records that preimage canonical keys have been indexed in this DB.
func (d *DB) MarkHasCanonicalKeys() {
	d.hasCanonicalKeys.Store(true)
}

// HasCanonicalKeys reports whether preimage canonical keys have been indexed in this DB.
func (d *DB) HasCanonicalKeys() bool {
	return d.hasCanonicalKeys.Load()
}

// SetChunkSize configures the chunk size for DB operations.
func (d *DB) SetChunkSize(chunkSize uint64) {
	if chunkSize == 0 {
		chunkSize = ChunkSize
	}
	d.chunkSize = chunkSize
}

// ChunkSize returns the configured chunk size, or the default ChunkSize if not set.
func (d *DB) ChunkSize() uint64 {
	if d.chunkSize == 0 {
		return ChunkSize
	}
	return d.chunkSize
}

// SetMaxChunksPerRequest configures the maximum number of non-empty chunks visited per Lookup request.
func (d *DB) SetMaxChunksPerRequest(maxChunks int) {
	if maxChunks <= 0 {
		maxChunks = DefaultMaxChunksPerRequest
	}
	d.maxChunksPerReq = maxChunks
}

// MaxChunksPerRequest returns the maximum number of non-empty chunks visited per Lookup request.
func (d *DB) MaxChunksPerRequest() int {
	if d.maxChunksPerReq <= 0 {
		return DefaultMaxChunksPerRequest
	}
	return d.maxChunksPerReq
}

var _ IndexStore = (*DB)(nil)

// InvertedPrefixChunkComparer returns a pebble.Comparer that splits keys at 33 bytes
// for 'c' prefix keys ('c' + 32-byte KeyHash).
//
// Performance optimization (NOT a functional sorting requirement):
// Splitting keys at 33 bytes allows Pebble's full-table 10-bit Bloom filters to index only
// the ('c' + KeyHash) prefix across all SSTable levels.
// Without this split, Bloom filters would hash the full 41-byte key including the inverted
// chunk number, preventing prefix-based Bloom filtering. With this split, iter.SeekPrefixGE
// prunes non-existent keys with zero disk I/O.
func InvertedPrefixChunkComparer() *pebble.Comparer {
	return &pebble.Comparer{
		Name:           "vindex.inverted_prefix_chunk_comparer",
		Compare:        bytes.Compare,
		Equal:          bytes.Equal,
		FormatKey:      pebble.DefaultComparer.FormatKey,
		FormatValue:    pebble.DefaultComparer.FormatValue,
		Separator:      pebble.DefaultComparer.Separator,
		Successor:      pebble.DefaultComparer.Successor,
		AbbreviatedKey: pebble.DefaultComparer.AbbreviatedKey,
		Split: func(key []byte) int {
			if len(key) >= 33 && key[0] == PrefixChunkByte {
				return 33
			}
			return len(key)
		},
	}
}

// Open opens a Pebble DB configured for VIndex.
func Open(dir string, opts *pebble.Options) (*DB, error) {
	if opts == nil {
		opts = &pebble.Options{}
	}
	if opts.Comparer == nil {
		opts.Comparer = InvertedPrefixChunkComparer()
	}
	if opts.Filters == nil {
		opts.Filters = map[string]pebble.FilterPolicy{
			bloom.FilterPolicy(10).Name(): bloom.FilterPolicy(10),
		}
	}
	var allocatedCache *pebble.Cache
	if opts.Cache == nil {
		allocatedCache = pebble.NewCache(512 << 20)
		opts.Cache = allocatedCache
	}
	if opts.MemTableSize == 0 {
		opts.MemTableSize = 128 << 20 // 128 MB write buffer
	}
	if opts.MemTableStopWritesThreshold == 0 {
		opts.MemTableStopWritesThreshold = 8
	}
	if opts.L0CompactionThreshold == 0 {
		opts.L0CompactionThreshold = 8
	}
	if opts.L0StopWritesThreshold == 0 {
		opts.L0StopWritesThreshold = 32
	}
	if opts.MaxConcurrentCompactions == nil {
		opts.MaxConcurrentCompactions = func() int { return 8 }
	}
	if opts.MaxOpenFiles <= 0 {
		opts.MaxOpenFiles = autoTuneMaxOpenFiles()
	}
	if len(opts.Levels) == 0 {
		opts.Levels = make([]pebble.LevelOptions, 7)
		for i := range opts.Levels {
			opts.Levels[i].FilterPolicy = bloom.FilterPolicy(10)
			if i >= 2 {
				// Scale SSTable sizes from 8MB in L2 up to 64MB in L5/L6
				opts.Levels[i].TargetFileSize = int64((8 << 20) * (1 << min(i-2, 3)))
			}
		}
	}

	pDb, err := pebble.Open(dir, opts)
	if err != nil {
		if allocatedCache != nil {
			allocatedCache.Unref()
		}
		return nil, err
	}
	d := &DB{db: pDb, cache: allocatedCache, chunkSize: ChunkSize}
	if val, closer, err := pDb.Get(KeyMetaHasCanonicalKeys); err == nil {
		hasCanon := len(val) > 0 && val[0] != 0
		_ = closer.Close()
		if hasCanon {
			d.hasCanonicalKeys.Store(true)
		}
	}
	return d, nil
}

// Close closes the underlying database.
func (d *DB) Close() (retErr error) {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if d.closed {
		return pebble.ErrClosed
	}
	d.closed = true

	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && errors.Is(err, pebble.ErrClosed) {
				retErr = pebble.ErrClosed
				return
			}
			panic(r)
		}
	}()

	err := d.db.Close()
	if d.cache != nil {
		d.cache.Unref()
		d.cache = nil
	}
	return err
}

// Sync flushes the memtable to stable storage, ensuring durability of all uncommitted writes.
func (d *DB) Sync() (retErr error) {
	if d == nil {
		return nil
	}
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if d.closed {
		return pebble.ErrClosed
	}
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && errors.Is(err, pebble.ErrClosed) {
				retErr = pebble.ErrClosed
				return
			}
			panic(r)
		}
	}()
	return d.db.Flush()
}

// Pebble returns the underlying *pebble.DB.
func (d *DB) Pebble() *pebble.DB {
	return d.db
}

// NewBatch creates a new Pebble batch.
func (d *DB) NewBatch() *pebble.Batch {
	return d.db.NewBatch()
}

// NewIter creates a new Pebble iterator.
func (d *DB) NewIter(opts *pebble.IterOptions) (iter *pebble.Iterator, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && errors.Is(err, pebble.ErrClosed) {
				retErr = pebble.ErrClosed
				return
			}
			panic(r)
		}
	}()
	return d.db.NewIter(opts)
}

// DeleteRange deletes keys in [start, end).
func (d *DB) DeleteRange(start, end []byte, opts *pebble.WriteOptions) error {
	return d.db.DeleteRange(start, end, opts)
}

// GetMetadata retrieves a metadata key value. Returns nil, nil if key does not exist.
func (d *DB) GetMetadata(key []byte) (res []byte, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && errors.Is(err, pebble.ErrClosed) {
				retErr = pebble.ErrClosed
				return
			}
			panic(r)
		}
	}()
	val, closer, err := d.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = closer.Close() }()
	res = make([]byte, len(val))
	copy(res, val)
	return res, nil
}

// SetMetadata sets a metadata key-value pair synchronously.
func (d *DB) SetMetadata(key, value []byte) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && errors.Is(err, pebble.ErrClosed) {
				retErr = pebble.ErrClosed
				return
			}
			panic(r)
		}
	}()
	return d.db.Set(key, value, pebble.Sync)
}

// GetUint64 reads a big-endian uint64 metadata value. Returns 0, nil if not found.
func (d *DB) GetUint64(key []byte) (uint64, error) {
	val, err := d.GetMetadata(key)
	if err != nil {
		return 0, err
	}
	if val == nil {
		return 0, nil
	}
	if len(val) != 8 {
		return 0, fmt.Errorf("%w: expected 8 bytes for uint64 at %q, got %d", ErrInvalidMetadata, string(key), len(val))
	}
	return binary.BigEndian.Uint64(val), nil
}

// SetUint64 writes a big-endian uint64 metadata value synchronously.
func (d *DB) SetUint64(key []byte, val uint64) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	return d.SetMetadata(key, buf)
}

// WriteBatch commits an ordered batch of mapped key entries and updates kv_size atomically.
func (d *DB) WriteBatch(entries map[[sha256.Size]byte][]uint64, targetSize uint64) error {
	idx := NewKVIndexer(d, d.ChunkSize())
	batch := &ingest.MappedBatch{
		EndLeafIdx: targetSize,
		Count:      uint32(targetSize),
		KeyMap:     entries,
	}
	_, err := idx.IndexMappedBatch(context.Background(), batch, nil, targetSize)
	return err
}
