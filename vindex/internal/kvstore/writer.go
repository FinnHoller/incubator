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
	"encoding/hex"
	"fmt"
	"runtime"
	"slices"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"golang.org/x/sync/errgroup"
)

// activeChunkEntry caches the in-memory descriptor of the active (unsealed) chunk for a key.
type activeChunkEntry struct {
	chunkNum uint64
	record   *ChunkRecord

	// runningRange is a purely in-memory performance optimization (NOT a functional requirement).
	// It maintains the cumulative compact Merkle range across batches for the active chunk.
	//
	// Without runningRange, computing the modified value root on every batch requires cloning
	// record.CompactRange and re-hashing all historical relative indices in the active chunk
	// from index 0, leading to O(N^2) leaf hashing over the life of a chunk.
	//
	// In benchmarks (BenchmarkKVIndexer_IncrementalIndex), maintaining runningRange in RAM
	// improves incremental indexing throughput by ~71% (3.5x speedup: 640.9ms down to 185.1ms
	// for 200 keys x 50 batches) and eliminates ~85% of transient heap allocations on hot keys.
	//
	// It has NO effect on the persisted storage layout: Pebble DB rows continue to store only
	// the compact hashes of prior sealed chunks. On cache eviction or node restart, runningRange
	// is lazily reconstructed once from the persisted record upon first load.
	runningRange *CompactRange
}

// maxGenChunkCacheSize bounds the in-memory active chunk cache.
// Performance optimization (NOT a functional requirement): a bounded two-generational
// cache (currentCache + previousCache) absorbs repeated writes to hot keys across consecutive
// batches, eliminating >90% of Pebble block cache read I/O without the mutex or pointer overhead of an LRU.
const maxGenChunkCacheSize = 131072

// KVIndexer indexes mapped batches into Pebble inverted chunks ('c') and maintains Merkle compact ranges.
type KVIndexer struct {
	// Required for correctness: database instance, chunk capacity, and root state.
	db                    *DB
	chunkSize             uint64
	lastModifiedValueRoots map[[sha256.Size]byte][sha256.Size]byte

	// Performance optimizations (NOT functional requirements):
	// Generational in-memory active chunk cache to avoid Pebble block cache read I/O on hot keys.
	currentCache  map[[sha256.Size]byte]activeChunkEntry
	previousCache map[[sha256.Size]byte]activeChunkEntry
	marshalBuf    []byte          // Reusable serialization buffer to eliminate heap churn during chunk writes.
	writesBuf     []chunkMutation // Reusable chunk mutation buffer for sequential batch path.
	numWorkers    int             // Number of worker goroutines for parallel key indexing (defaults to min(8, max(1, GOMAXPROCS/2))).
}

// DefaultKVIndexerWorkers calculates the recommended worker count for parallel key indexing.
// Performance optimization: caps workers to min(8, max(1, GOMAXPROCS/2)) to capture >80% of
// parallel Merkle speedup while preserving cores for WASM mapping, Pebble compactions, and read RPCs.
func DefaultKVIndexerWorkers() int {
	w := runtime.GOMAXPROCS(0) / 2
	if w > 8 {
		w = 8
	}
	if w < 1 {
		w = 1
	}
	return w
}

// NewKVIndexer creates a new KVIndexer with the given DB and chunk size.
// If chunkSize is 0, ChunkSize (65536) is used.
func NewKVIndexer(db *DB, chunkSize uint64) *KVIndexer {
	if chunkSize == 0 {
		chunkSize = ChunkSize
	}
	return &KVIndexer{
		db:           db,
		chunkSize:    chunkSize,
		currentCache: make(map[[sha256.Size]byte]activeChunkEntry, 1024),
		numWorkers:   DefaultKVIndexerWorkers(),
	}
}

// SetNumWorkers sets the number of worker goroutines for parallel key indexing.
// Performance optimization: setting n <= 1 enforces sequential single-threaded execution.
func (idx *KVIndexer) SetNumWorkers(n int) {
	if n < 1 {
		n = 1
	}
	idx.numWorkers = n
}

// NumWorkers returns the configured number of worker goroutines.
func (idx *KVIndexer) NumWorkers() int {
	return idx.numWorkers
}

// ClearCache evicts all cached active chunk descriptors.
func (idx *KVIndexer) ClearCache() {
	idx.currentCache = make(map[[sha256.Size]byte]activeChunkEntry, 1024)
	idx.previousCache = nil
}

// ChunkSize returns the configured chunk capacity.
func (idx *KVIndexer) ChunkSize() uint64 {
	return idx.chunkSize
}

// ModifiedValueRoots returns the value roots modified in the last indexing batch.
func (idx *KVIndexer) ModifiedValueRoots() map[[sha256.Size]byte][sha256.Size]byte {
	return idx.lastModifiedValueRoots
}

func canonicalKeyForHash(batch *ingest.MappedBatch, keyHash [sha256.Size]byte) string {
	if batch != nil && batch.CanonicalKeys != nil {
		if k, ok := batch.CanonicalKeys[keyHash]; ok && k != "" {
			return k
		}
	}
	return hex.EncodeToString(keyHash[:])
}

func buildModifiedKeyValueRoots(batch *ingest.MappedBatch, modifiedValueRoots map[[sha256.Size]byte][sha256.Size]byte) map[string][sha256.Size]byte {
	out := make(map[string][sha256.Size]byte, len(modifiedValueRoots))
	for kh, vr := range modifiedValueRoots {
		out[canonicalKeyForHash(batch, kh)] = vr
	}
	return out
}

// IndexBatch indexes a MappedBatch into Pebble inverted chunks and updates metadata in the same atomic Pebble batch.
func (idx *KVIndexer) IndexBatch(ctx context.Context, batch *ingest.MappedBatch, targetCP *ingest.Checkpoint) (*IndexResult, error) {
	if batch == nil {
		kvSize, _ := idx.db.GetUint64(KeyMetaKVSize)
		return &IndexResult{
			NewKVSize:             kvSize,
			ModifiedValueRoots:    make(map[[32]byte][32]byte),
			ModifiedKeyValueRoots: make(map[string][32]byte),
		}, nil
	}

	var rawCP []byte
	var targetSize uint64
	if targetCP != nil {
		rawCP = targetCP.Raw
		targetSize = targetCP.Size
	}
	return idx.IndexMappedBatch(ctx, batch, rawCP, targetSize)
}

// IndexMappedBatch indexes a MappedBatch with optional raw target checkpoint bytes and target size.
func (idx *KVIndexer) IndexMappedBatch(ctx context.Context, batch *ingest.MappedBatch, rawTargetCP []byte, targetSize uint64) (res *IndexResult, retErr error) {
	if batch == nil {
		kvSize, _ := idx.db.GetUint64(KeyMetaKVSize)
		return &IndexResult{
			NewKVSize:             kvSize,
			ModifiedValueRoots:    make(map[[32]byte][32]byte),
			ModifiedKeyValueRoots: make(map[string][32]byte),
		}, nil
	}

	persistedKVSize, err := idx.db.GetUint64(KeyMetaKVSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read persisted kv_size: %w", err)
	}

	pBatch := idx.db.NewBatch()
	defer func() {
		_ = pBatch.Close()
		if retErr != nil {
			idx.ClearCache()
		}
	}()

	modifiedValueRoots, newCachedEntries, newKVSize, err := idx.buildBatchMutations(ctx, pBatch, persistedKVSize, batch, targetSize)
	if err != nil {
		return nil, err
	}

	if newKVSize > persistedKVSize {
		var szBuf [8]byte
		binary.BigEndian.PutUint64(szBuf[:], newKVSize)
		if err := pBatch.Set(KeyMetaKVSize, szBuf[:], nil); err != nil {
			return nil, fmt.Errorf("failed to set metadata kv_size: %w", err)
		}

		// Performance optimization: use pebble.NoSync for intermediate catch-up batches
		// to avoid blocking on synchronous disk fsync() every 256 leaves. Durability is enforced
		// via pebble.Sync on the final catch-up boundary (newKVSize == targetSize) and steady-state commits.
		syncOption := pebble.Sync
		if targetSize > 0 && newKVSize < targetSize {
			syncOption = pebble.NoSync
		} else if len(rawTargetCP) > 0 {
			if err := pBatch.Set(KeyMetaKVCheckpoint, rawTargetCP, nil); err != nil {
				return nil, fmt.Errorf("failed to set metadata kv_checkpoint: %w", err)
			}
		}

		applyStart := time.Now()
		if err := idx.db.Pebble().Apply(pBatch, syncOption); err != nil {
			return nil, fmt.Errorf("failed to commit indexing batch: %w", err)
		}
		metrics.PebbleApplyDurationSeconds.Observe(time.Since(applyStart).Seconds())

		if len(idx.currentCache)+len(newCachedEntries) > maxGenChunkCacheSize {
			idx.previousCache = idx.currentCache
			idx.currentCache = make(map[[sha256.Size]byte]activeChunkEntry, maxGenChunkCacheSize)
		}
		for k, v := range newCachedEntries {
			idx.currentCache[k] = v
		}
	} else if len(rawTargetCP) > 0 && targetSize > 0 && newKVSize == targetSize {
		if err := idx.db.SetMetadata(KeyMetaKVCheckpoint, rawTargetCP); err != nil {
			return nil, fmt.Errorf("failed to set metadata kv_checkpoint: %w", err)
		}
	}

	idx.lastModifiedValueRoots = modifiedValueRoots
	return &IndexResult{
		NewKVSize:             newKVSize,
		ModifiedValueRoots:    modifiedValueRoots,
		ModifiedKeyValueRoots: buildModifiedKeyValueRoots(batch, modifiedValueRoots),
	}, nil
}

// StageMappedBatch stages chunk mutations for batch into stagedBatch without applying them to the underlying DB.
// This allows callers (such as the auditor) to predict and verify the resulting MPT root hash before committing
// any chunk or watermark mutations to Pebble. If verification subsequently fails, the caller must discard
// stagedBatch and call ClearCache().
func (idx *KVIndexer) StageMappedBatch(ctx context.Context, stagedBatch *pebble.Batch, persistedKVSize uint64, batch *ingest.MappedBatch, targetSize uint64) (res *IndexResult, retErr error) {
	if batch == nil {
		return &IndexResult{
			NewKVSize:             persistedKVSize,
			ModifiedValueRoots:    make(map[[32]byte][32]byte),
			ModifiedKeyValueRoots: make(map[string][32]byte),
		}, nil
	}
	defer func() {
		if retErr != nil {
			idx.ClearCache()
		}
	}()

	modifiedValueRoots, newCachedEntries, newKVSize, err := idx.buildBatchMutations(ctx, stagedBatch, persistedKVSize, batch, targetSize)
	if err != nil {
		return nil, err
	}

	if newKVSize > persistedKVSize {
		if stagedBatch != nil && stagedBatch.Indexed() && len(idx.currentCache)+len(newCachedEntries) > maxGenChunkCacheSize {
			idx.previousCache = idx.currentCache
			idx.currentCache = make(map[[sha256.Size]byte]activeChunkEntry, maxGenChunkCacheSize)
		}
		for k, v := range newCachedEntries {
			idx.currentCache[k] = v
		}
	}

	idx.lastModifiedValueRoots = modifiedValueRoots
	return &IndexResult{
		NewKVSize:             newKVSize,
		ModifiedValueRoots:    modifiedValueRoots,
		ModifiedKeyValueRoots: buildModifiedKeyValueRoots(batch, modifiedValueRoots),
	}, nil
}

func (idx *KVIndexer) newBatchOrDBIter(pBatch *pebble.Batch) (*pebble.Iterator, error) {
	if pBatch != nil && pBatch.Indexed() {
		return pBatch.NewIter(nil)
	}
	return idx.db.NewIter(nil)
}

func (idx *KVIndexer) buildBatchMutations(
	ctx context.Context,
	pBatch *pebble.Batch,
	persistedKVSize uint64,
	batch *ingest.MappedBatch,
	targetSize uint64,
) (map[[sha256.Size]byte][sha256.Size]byte, map[[sha256.Size]byte]activeChunkEntry, uint64, error) {
	keys := make([][sha256.Size]byte, 0, len(batch.KeyMap))
	if len(batch.CanonicalKeys) > 0 && idx.db != nil {
		if !idx.db.HasCanonicalKeys() && pBatch != nil {
			_ = pBatch.Set(KeyMetaHasCanonicalKeys, []byte{1}, nil)
		}
		idx.db.MarkHasCanonicalKeys()
	}
	for k := range batch.KeyMap {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [sha256.Size]byte) int {
		return bytes.Compare(a[:], b[:])
	})

	for _, k := range keys {
		indices := batch.KeyMap[k]
		if len(indices) > 1 {
			if !slices.IsSorted(indices) {
				slices.Sort(indices)
			}
			batch.KeyMap[k] = slices.Compact(indices)
		}
	}

	modifiedValueRoots := make(map[[sha256.Size]byte][sha256.Size]byte, len(keys))
	newCachedEntries := make(map[[sha256.Size]byte]activeChunkEntry, len(keys))

	newKVSize := batch.EndLeafIdx
	if newKVSize == 0 && batch.Count > 0 {
		newKVSize = batch.StartLeafIdx + uint64(batch.Count)
	} else if newKVSize == 0 && targetSize > 0 {
		newKVSize = targetSize
	}

	const parallelThreshold = 32
	const minKeysPerWorker = 16
	if idx.numWorkers <= 1 || len(keys) < parallelThreshold || (pBatch != nil && pBatch.Indexed()) {
		iter, err := idx.newBatchOrDBIter(pBatch)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to create iterator: %w", err)
		}
		getIter := func() (*pebble.Iterator, error) { return iter, nil }

		var prefixBuf [33]byte
		idx.marshalBuf = idx.marshalBuf[:0]
		idx.writesBuf = idx.writesBuf[:0]

		for _, keyHash := range keys {
			select {
			case <-ctx.Done():
				_ = iter.Close()
				return nil, nil, 0, ctx.Err()
			default:
			}

			res, newBuf, err := idx.processKey(
				keyHash, batch.KeyMap[keyHash], persistedKVSize, newKVSize, targetSize,
				batch.StartLeafIdx, idx.marshalBuf, &idx.writesBuf, &prefixBuf, getIter,
			)
			if err != nil {
				_ = iter.Close()
				return nil, nil, 0, err
			}
			idx.marshalBuf = newBuf
			modifiedValueRoots[keyHash] = res.valueRoot
			if res.hasCache {
				newCachedEntries[keyHash] = res.cached
			}
		}
		_ = iter.Close()
		for j := range idx.writesBuf {
			w := &idx.writesBuf[j]
			if err := pBatch.Set(w.key[:], w.val, nil); err != nil {
				return nil, nil, 0, fmt.Errorf("failed to set chunk: %w", err)
			}
		}
	} else {
		// Performance optimization: partition keys across worker goroutines to compute
		// CompactRange.Append, runningRange.Root(), and chunk serialization in parallel.
		workers := idx.numWorkers
		if maxW := len(keys) / minKeysPerWorker; workers > maxW {
			workers = maxW
		}
		if workers < 1 {
			workers = 1
		}

		chunkSize := (len(keys) + workers - 1) / workers
		results := make([]keyProcessResult, len(keys))
		workerWrites := make([][]chunkMutation, workers)
		g, gCtx := errgroup.WithContext(ctx)

		for w := 0; w < workers; w++ {
			w := w
			start := w * chunkSize
			if start >= len(keys) {
				continue
			}
			end := min(start+chunkSize, len(keys))
			workerWrites[w] = make([]chunkMutation, 0, end-start)

			g.Go(func() error {
				var wIter *pebble.Iterator
				defer func() {
					if wIter != nil {
						_ = wIter.Close()
					}
				}()
				getIter := func() (*pebble.Iterator, error) {
					if wIter == nil {
						var err error
						wIter, err = idx.db.NewIter(nil)
						if err != nil {
							return nil, fmt.Errorf("failed to create worker iterator: %w", err)
						}
					}
					return wIter, nil
				}

				var wPrefixBuf [33]byte
				wMarshalBuf := make([]byte, 0, (end-start)*64)
				wWrites := workerWrites[w]

				for i := start; i < end; i++ {
					select {
					case <-gCtx.Done():
						return gCtx.Err()
					default:
					}

					keyHash := keys[i]
					res, newBuf, err := idx.processKey(
						keyHash, batch.KeyMap[keyHash], persistedKVSize, newKVSize, targetSize,
						batch.StartLeafIdx, wMarshalBuf, &wWrites, &wPrefixBuf, getIter,
					)
					if err != nil {
						return err
					}
					wMarshalBuf = newBuf
					results[i] = res
				}
				workerWrites[w] = wWrites
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return nil, nil, 0, err
		}

		for i := range results {
			r := &results[i]
			modifiedValueRoots[r.keyHash] = r.valueRoot
			if r.hasCache {
				newCachedEntries[r.keyHash] = r.cached
			}
		}
		for _, wWrites := range workerWrites {
			for j := range wWrites {
				w := &wWrites[j]
				if err := pBatch.Set(w.key[:], w.val, nil); err != nil {
					return nil, nil, 0, fmt.Errorf("failed to set chunk: %w", err)
				}
			}
		}
	}

	return modifiedValueRoots, newCachedEntries, newKVSize, nil
}

type chunkMutation struct {
	key [41]byte
	val []byte
}

type keyProcessResult struct {
	keyHash   [sha256.Size]byte
	valueRoot [sha256.Size]byte
	cached    activeChunkEntry
	hasCache  bool
}

func (idx *KVIndexer) processKey(
	keyHash [sha256.Size]byte,
	indices []uint64,
	persistedKVSize uint64,
	newKVSize uint64,
	targetSize uint64,
	batchStartLeafIdx uint64,
	marshalBuf []byte,
	writes *[]chunkMutation,
	prefixBuf *[33]byte,
	getIter func() (*pebble.Iterator, error),
) (res keyProcessResult, outBuf []byte, err error) {
	res.keyHash = keyHash

	// Filter unpersisted indices (indices >= persistedKVSize).
	var unpersisted []uint64
	if batchStartLeafIdx >= persistedKVSize {
		unpersisted = indices
	} else {
		hasPersisted := false
		for _, leafIdx := range indices {
			if leafIdx < persistedKVSize {
				hasPersisted = true
				break
			}
		}
		if !hasPersisted {
			unpersisted = indices
		} else {
			for _, leafIdx := range indices {
				if leafIdx >= persistedKVSize {
					unpersisted = append(unpersisted, leafIdx)
				}
			}
		}
	}

	if len(unpersisted) == 0 {
		limit := newKVSize
		if limit == 0 {
			limit = targetSize
		}
		if limit == 0 {
			limit = persistedKVSize
		}
		vr, err := idx.GetValueRoot(keyHash, limit)
		if err != nil {
			return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to get value root for key %x: %w", keyHash, err)
		}
		res.valueRoot = vr
		return res, marshalBuf, nil
	}

	var currChunkNum uint64
	var rec *ChunkRecord
	var runningRange *CompactRange

	if cached, ok := idx.currentCache[keyHash]; ok {
		currChunkNum = cached.chunkNum
		rec = cached.record
		runningRange = cached.runningRange
	} else if cached, ok := idx.previousCache[keyHash]; ok {
		currChunkNum = cached.chunkNum
		rec = &ChunkRecord{
			Preceding:       cached.record.Preceding,
			CompactRange:    cached.record.CompactRange,
			RelativeIndices: append([]uint16(nil), cached.record.RelativeIndices...),
		}
		runningRange = cached.runningRange.Clone()
	} else {
		prefix := EncodeChunkPrefixInto(prefixBuf, keyHash)
		iter, err := getIter()
		if err != nil {
			return keyProcessResult{}, marshalBuf, err
		}
		if iter.SeekPrefixGE(prefix) && bytes.HasPrefix(iter.Key(), prefix) {
			_, cNum, err := DecodeChunkKey(iter.Key())
			if err != nil {
				return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to decode chunk key: %w", err)
			}
			currChunkNum = cNum
			rec, err = UnmarshalChunkValue(iter.Value())
			if err != nil {
				return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to unmarshal chunk value: %w", err)
			}
			runningHashes := make([][sha256.Size]byte, len(rec.CompactRange), 64)
			copy(runningHashes, rec.CompactRange)
			runningRange = &CompactRange{
				Preceding: rec.Preceding,
				Hashes:    runningHashes,
			}
			for _, rel := range rec.RelativeIndices {
				absIdx := currChunkNum*idx.chunkSize + uint64(rel)
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], absIdx)
				runningRange.Append(LeafHash(b[:]))
			}
		} else {
			currChunkNum = unpersisted[0] / idx.chunkSize
			rec = &ChunkRecord{
				Preceding:       0,
				CompactRange:    nil,
				RelativeIndices: nil,
			}
			runningRange = NewCompactRange()
		}
	}

	for _, leafIdx := range unpersisted {
		targetChunkNum := leafIdx / idx.chunkSize
		rel := uint16(leafIdx % idx.chunkSize)
		if targetChunkNum < currChunkNum || (targetChunkNum == currChunkNum && len(rec.RelativeIndices) > 0 && rel <= rec.RelativeIndices[len(rec.RelativeIndices)-1]) {
			continue
		}
		if targetChunkNum > currChunkNum {
			if len(rec.RelativeIndices) > 0 {
				start := len(marshalBuf)
				marshalBuf = AppendChunkValue(marshalBuf, rec)
				sealedVal := marshalBuf[start:]
				var sealedKey [41]byte
				EncodeChunkKeyInto(&sealedKey, keyHash, currChunkNum)
				*writes = append(*writes, chunkMutation{key: sealedKey, val: sealedVal})
			}

			currChunkNum = targetChunkNum
			rec = &ChunkRecord{
				Preceding:       runningRange.Preceding,
				CompactRange:    slices.Clone(runningRange.Hashes),
				RelativeIndices: nil,
			}
		}
		rec.RelativeIndices = append(rec.RelativeIndices, rel)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], leafIdx)
		runningRange.Append(LeafHash(b[:]))
	}

	start := len(marshalBuf)
	marshalBuf = AppendChunkValue(marshalBuf, rec)
	activeVal := marshalBuf[start:]
	var activeKey [41]byte
	EncodeChunkKeyInto(&activeKey, keyHash, currChunkNum)
	*writes = append(*writes, chunkMutation{key: activeKey, val: activeVal})

	res.valueRoot = runningRange.Root()
	res.cached = activeChunkEntry{
		chunkNum:     currChunkNum,
		record:       rec,
		runningRange: runningRange,
	}
	res.hasCache = true
	return res, marshalBuf, nil
}

// GetValueRoot calculates the value log root for the given keyHash up to maxInputLogSize.
func (idx *KVIndexer) GetValueRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error) {
	iter, err := idx.db.NewIter(nil)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer func() { _ = iter.Close() }()
	return idx.getValueRootWithIter(iter, keyHash, maxInputLogSize)
}

func (idx *KVIndexer) getValueRootWithIter(iter *pebble.Iterator, keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error) {
	if maxInputLogSize == 0 {
		return EmptyRoot(), nil
	}

	maxChunkNum := (maxInputLogSize - 1) / idx.chunkSize
	var seekKey [41]byte
	EncodeChunkKeyInto(&seekKey, keyHash, maxChunkNum)
	prefix := seekKey[:33]

	if !iter.SeekPrefixGE(seekKey[:]) || !bytes.HasPrefix(iter.Key(), prefix) {
		return EmptyRoot(), nil
	}

	for ; iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		_, cNum, err := DecodeChunkKey(iter.Key())
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		if cNum*idx.chunkSize >= maxInputLogSize {
			continue
		}

		rec, err := UnmarshalChunkValue(iter.Value())
		if err != nil {
			return [sha256.Size]byte{}, err
		}

		cr := &CompactRange{
			Preceding: rec.Preceding,
			Hashes:    slices.Clone(rec.CompactRange),
		}
		chunkBase := cNum * idx.chunkSize
		for _, rel := range rec.RelativeIndices {
			absIdx := chunkBase + uint64(rel)
			if absIdx >= maxInputLogSize {
				break
			}
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], absIdx)
			cr.Append(LeafHash(b[:]))
		}

		if cr.Preceding == 0 {
			return EmptyRoot(), nil
		}
		return cr.Root(), nil
	}

	return EmptyRoot(), nil
}

// GetValueRoots computes the value log roots for a set of keys up to maxInputLogSize in parallel,
// reusing Pebble iterators across worker goroutines and performing zero storage writes.
func (idx *KVIndexer) GetValueRoots(ctx context.Context, keys [][sha256.Size]byte, maxInputLogSize uint64) (map[[sha256.Size]byte][sha256.Size]byte, error) {
	if len(keys) == 0 {
		return make(map[[sha256.Size]byte][sha256.Size]byte), nil
	}

	workers := idx.numWorkers
	if workers < 1 {
		workers = 1
	}
	if workers > len(keys) {
		workers = len(keys)
	}

	results := make([]struct {
		key  [sha256.Size]byte
		root [sha256.Size]byte
	}, len(keys))

	chunkSize := (len(keys) + workers - 1) / workers
	g, gCtx := errgroup.WithContext(ctx)

	for w := 0; w < workers; w++ {
		w := w
		start := w * chunkSize
		if start >= len(keys) {
			continue
		}
		end := min(start+chunkSize, len(keys))

		g.Go(func() error {
			iter, err := idx.db.NewIter(nil)
			if err != nil {
				return fmt.Errorf("failed to create iterator: %w", err)
			}
			defer func() { _ = iter.Close() }()

			for i := start; i < end; i++ {
				select {
				case <-gCtx.Done():
					return gCtx.Err()
				default:
				}
				k := keys[i]
				vr, err := idx.getValueRootWithIter(iter, k, maxInputLogSize)
				if err != nil {
					return err
				}
				results[i].key = k
				results[i].root = vr
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := make(map[[sha256.Size]byte][sha256.Size]byte, len(keys))
	for _, r := range results {
		res[r.key] = r.root
	}
	return res, nil
}

// GetKeyValueRoots computes the value log roots for a set of canonical keys (keyed by their SHA-256 keyHash)
// up to maxInputLogSize in parallel, reusing Pebble iterators and performing zero storage writes.
func (idx *KVIndexer) GetKeyValueRoots(ctx context.Context, keys map[[sha256.Size]byte]string, maxInputLogSize uint64) (map[string][sha256.Size]byte, error) {
	if len(keys) == 0 {
		return make(map[string][sha256.Size]byte), nil
	}
	hashes := make([][sha256.Size]byte, 0, len(keys))
	for kh := range keys {
		hashes = append(hashes, kh)
	}
	hashValueRoots, err := idx.GetValueRoots(ctx, hashes, maxInputLogSize)
	if err != nil {
		return nil, err
	}
	res := make(map[string][sha256.Size]byte, len(hashValueRoots))
	for kh, vr := range hashValueRoots {
		ck := keys[kh]
		if ck == "" {
			ck = hex.EncodeToString(kh[:])
		}
		res[ck] = vr
	}
	return res, nil
}
