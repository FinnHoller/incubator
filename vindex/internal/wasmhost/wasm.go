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

// Package wasmhost provides a pure Wazero WebAssembly host runtime and ABI decoder
// for VIndex MapFn guest modules without HTTP or log-fetching dependencies.
package wasmhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

const (
	// DefaultBundleSize is the default number of leaves per bundle execution.
	DefaultBundleSize uint64 = 256
)

var (
	ErrWasmHalt        = errors.New("wasm execution halted due to violation or trap")
	ErrInvalidMemory   = errors.New("wasm returned memory pointer out of bounds")
	ErrUnalignedOutput = errors.New("wasm output length not a multiple of 32 bytes")
	ErrMalformedOutput = errors.New("wasm output format is malformed")
	ErrHostClosed      = errors.New("wasm host is closed")
)

// MappedEntry represents a single search key and optional value produced by a LeafMapper.
type MappedEntry struct {
	Key     string
	KeyHash [sha256.Size]byte
	Value   []byte
}

// ValidatePreimageKey validates that a WASM-emitted preimage key satisfies the canonical
// key invariants: 1 <= len <= 1024 and printable ASCII (0x21..0x7E, no NUL or whitespace).
func ValidatePreimageKey(keyBytes []byte) error {
	if len(keyBytes) == 0 || len(keyBytes) > 1024 {
		return fmt.Errorf("%w: canonical key length %d out of range [1, 1024]", ErrMalformedOutput, len(keyBytes))
	}
	for i, b := range keyBytes {
		if b < 0x21 || b > 0x7E {
			return fmt.Errorf("%w: canonical key contains invalid byte 0x%02x at offset %d", ErrMalformedOutput, b, i)
		}
	}
	return nil
}

// LeafMapper maps a raw Input Log leaf payload to a set of searchable MappedEntry records.
type LeafMapper interface {
	MapLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error)
	Close(ctx context.Context) error
}

// BundleMapper is an optional optimization interface for LeafMappers supporting batched execution.
type BundleMapper interface {
	LeafMapper
	MapBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error)
}

// RunnerProvider is an optional optimization interface for LeafMappers that can furnish dedicated runners per worker.
type RunnerProvider interface {
	LeafMapper
	NewRunner(ctx context.Context) (LeafMapper, error)
}

// MapFnHashProvider is an optional interface for LeafMappers that expose a 32-byte SHA-256 commitment
// to their mapping function implementation (e.g. SHA-256 of the compiled WASM module).
type MapFnHashProvider interface {
	MapFnHash() [sha256.Size]byte
}

// WASMHost manages the lifecycle and execution of a compiled Wazero WebAssembly module.
type WASMHost struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	hash     [sha256.Size]byte
	pool     chan *wasmInstance
	mu       sync.Mutex
	closed   bool
	haltErr  error
	poolSize int
}

type wasmInstance struct {
	// Required for correctness: module instance and exported guest bindings.
	mod         api.Module
	mapBundleFn api.Function
	mapLeafFn   api.Function
	allocFn     api.Function
	resetFn     api.Function
	mem         api.Memory

	// Performance optimizations (NOT functional requirements):
	// Reusable per-instance buffers to eliminate heap allocation churn during bundle processing.
	packedBuf  []byte          // Reusable input buffer for packing bundle leaves into guest memory.
	resultsBuf [][]MappedEntry // Reusable outer slice buffer for decoded leaf entries.
	entriesBuf []MappedEntry   // Reusable contiguous backing array for all mapped entries in a bundle.

	// staticInPtr is a performance optimization (NOT a functional requirement).
	// Bypasses invoking allocate() across the WASM boundary when a static arena or input buffer is exported.
	staticInPtr uint32
}

// Engine is an alias for WASMHost.
type Engine = WASMHost

// NewEngine compiles the guest bytecode and initializes a pool of instantiated WASM modules.
func NewEngine(ctx context.Context, wasmBytes []byte, poolSize int) (*Engine, error) {
	return NewWASMHost(ctx, wasmBytes, poolSize)
}

// NewWASMHost compiles the guest bytecode and initializes a pool of instantiated WASM modules.
// If poolSize <= 0, it defaults to runtime.GOMAXPROCS(0) - 1 (minimum 1).
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	if poolSize <= 0 {
		poolSize = runtime.GOMAXPROCS(0) - 1
		if poolSize < 1 {
			poolSize = 1
		}
	}

	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(1024).WithCloseOnContextDone(true))
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}

	h := &WASMHost{
		runtime:  r,
		compiled: compiled,
		hash:     sha256.Sum256(wasmBytes),
		pool:     make(chan *wasmInstance, poolSize),
		poolSize: poolSize,
	}

	for i := 0; i < poolSize; i++ {
		inst, err := h.instantiateInstance(ctx)
		if err != nil {
			_ = h.Close(ctx)
			return nil, fmt.Errorf("failed to instantiate initial wasm module %d: %w", i, err)
		}
		h.pool <- inst
	}

	return h, nil
}

// Hash returns the SHA-256 digest of the compiled WASM module bytes.
func (h *WASMHost) Hash() [sha256.Size]byte {
	return h.hash
}

// MapFnHash returns the SHA-256 digest of the compiled WASM module bytes (implementing MapFnHashProvider).
func (h *WASMHost) MapFnHash() [sha256.Size]byte {
	return h.hash
}

func (h *WASMHost) instantiateInstance(ctx context.Context) (*wasmInstance, error) {
	var id [8]byte
	_, _ = rand.Read(id[:])
	modName := fmt.Sprintf("vindex_mod_%x", id)

	wasiConfig := wazero.NewModuleConfig().
		WithName(modName).
		WithStartFunctions("_initialize").
		WithStdout(io.Discard).
		WithStderr(io.Discard).
		WithStdin(bytes.NewReader(nil)).
		WithArgs().
		WithWalltime(func() (sec int64, nsec int32) { return 1, 0 }, sys.ClockResolution(1)).
		WithNanotime(func() int64 { return 1_000_000 }, sys.ClockResolution(1)).
		WithNanosleep(func(int64) {}).
		WithRandSource(bytes.NewReader(make([]byte, 1024)))

	mod, err := h.runtime.InstantiateModule(ctx, h.compiled, wasiConfig)
	if err != nil {
		return nil, err
	}

	mapBundleFn := mod.ExportedFunction("map_bundle")
	mapLeafFn := mod.ExportedFunction("map_leaf")
	if mapBundleFn == nil && mapLeafFn == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: neither 'map_bundle' nor 'map_leaf' exported", ErrWasmHalt)
	}

	mem := mod.Memory()
	if mem == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: module memory not found", ErrWasmHalt)
	}

	allocFn := mod.ExportedFunction("allocate")
	if allocFn == nil {
		allocFn = mod.ExportedFunction("malloc")
	}

	resetFn := mod.ExportedFunction("reset")

	var staticInPtr uint32
	if inBufFn := mod.ExportedFunction("input_buffer"); inBufFn != nil {
		if res, err := inBufFn.Call(ctx); err == nil && len(res) > 0 && res[0] != 0 {
			staticInPtr = uint32(res[0])
		}
	}

	return &wasmInstance{
		mod:         mod,
		mapBundleFn: mapBundleFn,
		mapLeafFn:   mapLeafFn,
		allocFn:     allocFn,
		resetFn:     resetFn,
		mem:         mem,
		staticInPtr: staticInPtr,
	}, nil
}

func (inst *wasmInstance) packBundle(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 || n > 256 {
		return nil
	}

	headerLen := 4 + (n+1)*4
	var payloadLen int
	for _, l := range leaves {
		payloadLen += len(l)
	}

	totalLen := headerLen + payloadLen
	if cap(inst.packedBuf) < totalLen {
		inst.packedBuf = make([]byte, totalLen)
	} else {
		inst.packedBuf = inst.packedBuf[:totalLen]
	}
	buf := inst.packedBuf

	binary.LittleEndian.PutUint32(buf[0:4], uint32(n))

	var currentOffset uint32
	binary.LittleEndian.PutUint32(buf[4:8], 0)
	payloadDst := buf[headerLen:]
	var writePos int

	for i, l := range leaves {
		copy(payloadDst[writePos:], l)
		writePos += len(l)
		currentOffset += uint32(len(l))
		binary.LittleEndian.PutUint32(buf[4+(i+1)*4:4+(i+2)*4], currentOffset)
	}

	return buf
}

func (inst *wasmInstance) executeBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	if inst.mapBundleFn != nil {
		n := len(leaves)
		if n == 0 {
			return nil, nil
		}
		if n > 256 {
			return nil, fmt.Errorf("%w: bundle size %d exceeds 256", ErrMalformedOutput, n)
		}

		var inPtr uint32
		var inputLen uint32
		if inst.staticInPtr != 0 {
			headerLen := 4 + (n+1)*4
			var payloadLen int
			for _, l := range leaves {
				payloadLen += len(l)
			}
			totalLen := headerLen + payloadLen
			if totalLen > 4*1024*1024 {
				return nil, fmt.Errorf("%w: bundle input size %d exceeds 4 MB static slab capacity", ErrWasmHalt, totalLen)
			}
			inPtr = inst.staticInPtr
			inputLen = uint32(totalLen)
			destSlice, ok := inst.mem.Read(inPtr, inputLen)
			if !ok {
				return nil, fmt.Errorf("%w: failed to read guest buffer at ptr %d len %d", ErrInvalidMemory, inPtr, totalLen)
			}
			binary.LittleEndian.PutUint32(destSlice[0:4], uint32(n))
			var currentOffset uint32
			binary.LittleEndian.PutUint32(destSlice[4:8], 0)
			payloadDst := destSlice[headerLen:]
			var writePos int
			for i, l := range leaves {
				copy(payloadDst[writePos:], l)
				writePos += len(l)
				currentOffset += uint32(len(l))
				binary.LittleEndian.PutUint32(destSlice[4+(i+1)*4:4+(i+2)*4], currentOffset)
			}
		}

		if inputLen == 0 {
			packedInput := inst.packBundle(leaves)
			if inst.allocFn == nil {
				return nil, fmt.Errorf("%w: guest module must export 'allocate' or 'malloc'", ErrWasmHalt)
			}
			res, err := inst.allocFn.Call(ctx, uint64(len(packedInput)))
			if err != nil {
				return nil, fmt.Errorf("%w: allocate failed: %v", ErrWasmHalt, err)
			}
			inPtr = uint32(res[0])
			if inPtr == 0 {
				return nil, fmt.Errorf("%w: guest allocator returned null pointer (0)", ErrInvalidMemory)
			}

			if !inst.mem.Write(inPtr, packedInput) {
				return nil, fmt.Errorf("%w: failed to write bundle input to memory at ptr %d len %d",
					ErrInvalidMemory, inPtr, len(packedInput))
			}
			inputLen = uint32(len(packedInput))
		}

		callRes, err := inst.mapBundleFn.Call(ctx, uint64(inPtr), uint64(inputLen))
		if err != nil {
			return nil, fmt.Errorf("%w: map_bundle execution failed: %v", ErrWasmHalt, err)
		}
		if len(callRes) == 0 {
			return nil, fmt.Errorf("%w: map_bundle returned no result", ErrMalformedOutput)
		}

		packed := callRes[0]
		outPtr := uint32(packed >> 32)
		outLen := uint32(packed & 0xFFFFFFFF)
		if outPtr == 0 || outLen == 0 {
			return nil, fmt.Errorf("%w: map_bundle returned (ptr=%d, len=%d): output slab overflow or invalid input", ErrWasmHalt, outPtr, outLen)
		}

		outBuf, ok := inst.mem.Read(outPtr, outLen)
		if !ok {
			return nil, fmt.Errorf("%w: out_ptr=%d out_len=%d exceeds guest memory %d",
				ErrInvalidMemory, outPtr, outLen, inst.mem.Size())
		}

		return inst.decodeBundleOutput(outBuf, n)
	}

	// Fallback to legacy single-leaf map_leaf
	if cap(inst.resultsBuf) < len(leaves) {
		inst.resultsBuf = make([][]MappedEntry, len(leaves))
	} else {
		inst.resultsBuf = inst.resultsBuf[:len(leaves)]
		clear(inst.resultsBuf)
	}
	results := inst.resultsBuf
	for i, leaf := range leaves {
		entries, err := inst.executeLeaf(ctx, leaf)
		if err != nil {
			return nil, fmt.Errorf("leaf %d in bundle: %w", i, err)
		}
		results[i] = entries

		if inst.resetFn != nil && i+1 < len(leaves) {
			if _, err := inst.resetFn.Call(ctx); err != nil {
				return nil, fmt.Errorf("%w: reset failed on leaf %d: %v", ErrWasmHalt, i, err)
			}
		}
	}
	return results, nil
}

func decodeBundleOutputInto(resultsBuf [][]MappedEntry, entriesBuf []MappedEntry, outBuf []byte, expectedCount int) ([][]MappedEntry, []MappedEntry, error) {
	if len(outBuf) < 4+expectedCount*4 {
		return nil, nil, fmt.Errorf("%w: bundle output length %d is too short for %d leaves", ErrMalformedOutput, len(outBuf), expectedCount)
	}

	leafCount := binary.LittleEndian.Uint32(outBuf[0:4])
	if int(leafCount) != expectedCount {
		return nil, nil, fmt.Errorf("%w: bundle output leaf_count %d != expected %d", ErrMalformedOutput, leafCount, expectedCount)
	}

	keyCountsOffset := 4
	preimagesOffset := 4 + expectedCount*4

	var totalKeysU64 uint64
	for i := 0; i < expectedCount; i++ {
		totalKeysU64 += uint64(binary.LittleEndian.Uint32(outBuf[keyCountsOffset+i*4 : keyCountsOffset+(i+1)*4]))
	}

	maxPossibleKeys := uint64(len(outBuf)-preimagesOffset) / 4
	if totalKeysU64 > maxPossibleKeys {
		return nil, nil, fmt.Errorf("%w: total keys %d exceeds maximum possible %d for buffer length %d", ErrMalformedOutput, totalKeysU64, maxPossibleKeys, len(outBuf))
	}
	totalKeys := int(totalKeysU64)

	if cap(resultsBuf) < expectedCount {
		resultsBuf = make([][]MappedEntry, expectedCount)
	} else {
		resultsBuf = resultsBuf[:expectedCount]
		clear(resultsBuf)
	}
	if totalKeys == 0 {
		return resultsBuf, entriesBuf[:0], nil
	}

	if cap(entriesBuf) < totalKeys {
		entriesBuf = make([]MappedEntry, totalKeys)
	} else {
		entriesBuf = entriesBuf[:totalKeys]
	}
	allEntries := entriesBuf
	var curEntryIdx int

	for i := 0; i < expectedCount; i++ {
		kCount := int(binary.LittleEndian.Uint32(outBuf[keyCountsOffset+i*4 : keyCountsOffset+(i+1)*4]))
		if kCount == 0 {
			continue
		}

		startEntryIdx := curEntryIdx
		for j := 0; j < kCount; j++ {
			if preimagesOffset+4 > len(outBuf) {
				return nil, nil, fmt.Errorf("%w: truncated key length header", ErrMalformedOutput)
			}
			keyLen := binary.LittleEndian.Uint32(outBuf[preimagesOffset : preimagesOffset+4])
			preimagesOffset += 4

			if uint64(preimagesOffset)+uint64(keyLen) > uint64(len(outBuf)) {
				return nil, nil, fmt.Errorf("%w: truncated key bytes", ErrMalformedOutput)
			}
			keyBytes := outBuf[preimagesOffset : preimagesOffset+int(keyLen)]
			preimagesOffset += int(keyLen)
			if err := ValidatePreimageKey(keyBytes); err != nil {
				return nil, nil, err
			}

			allEntries[curEntryIdx] = MappedEntry{
				Key:     string(keyBytes),
				KeyHash: sha256.Sum256(keyBytes),
			}
			curEntryIdx++
		}

		entries := allEntries[startEntryIdx:curEntryIdx]
		if len(entries) > 1 {
			slices.SortFunc(entries, func(a, b MappedEntry) int {
				return bytes.Compare(a.KeyHash[:], b.KeyHash[:])
			})
			entries = slices.CompactFunc(entries, func(a, b MappedEntry) bool {
				return a.KeyHash == b.KeyHash
			})
		}
		curEntryIdx = startEntryIdx + len(entries)
		resultsBuf[i] = entries[:len(entries):len(entries)]
	}

	return resultsBuf, allEntries[:curEntryIdx], nil
}

func (inst *wasmInstance) decodeBundleOutput(outBuf []byte, expectedCount int) ([][]MappedEntry, error) {
	results, entries, err := decodeBundleOutputInto(inst.resultsBuf, inst.entriesBuf, outBuf, expectedCount)
	if err != nil {
		return nil, err
	}
	inst.resultsBuf = results
	inst.entriesBuf = entries
	return results, nil
}

func decodeBundleOutput(outBuf []byte, expectedCount int) ([][]MappedEntry, error) {
	results, _, err := decodeBundleOutputInto(nil, nil, outBuf, expectedCount)
	return results, err
}

func (inst *wasmInstance) executeLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	if inst.mapBundleFn != nil {
		res, err := inst.executeBundle(ctx, [][]byte{leaf})
		if err != nil {
			return nil, err
		}
		if len(res) == 0 {
			return nil, nil
		}
		return res[0], nil
	}

	var inputPtr uint32
	leafLen := uint32(len(leaf))
	if leafLen > 0 {
		if inst.staticInPtr != 0 && leafLen <= 4*1024*1024 {
			inputPtr = inst.staticInPtr
		} else {
			if inst.allocFn == nil {
				return nil, fmt.Errorf("%w: guest module must export 'allocate' or 'malloc'", ErrWasmHalt)
			}
			res, err := inst.allocFn.Call(ctx, uint64(leafLen))
			if err != nil {
				return nil, fmt.Errorf("%w: allocate failed: %v", ErrWasmHalt, err)
			}
			inputPtr = uint32(res[0])
			if inputPtr == 0 {
				return nil, fmt.Errorf("%w: guest allocator returned null pointer (0)", ErrInvalidMemory)
			}
		}
		if !inst.mem.Write(inputPtr, leaf) {
			return nil, fmt.Errorf("%w: failed to write leaf to guest memory at ptr %d len %d (mem size %d)",
				ErrInvalidMemory, inputPtr, leafLen, inst.mem.Size())
		}
	}

	results, err := inst.mapLeafFn.Call(ctx, uint64(inputPtr), uint64(leafLen))
	if err != nil {
		return nil, fmt.Errorf("%w: map_leaf execution failed: %v", ErrWasmHalt, err)
	}
	if len(results) == 0 {
		return nil, nil
	}

	packed := results[0]
	outPtr := uint32(packed >> 32)
	outLen := uint32(packed & 0xFFFFFFFF)
	if outLen == 0 {
		return nil, nil
	}

	outBuf, ok := inst.mem.Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("%w: out_ptr=%d out_len=%d exceeds guest memory %d",
			ErrInvalidMemory, outPtr, outLen, inst.mem.Size())
	}

	entries, err := decodeMappedEntries(outBuf)
	if err != nil {
		return nil, err
	}

	// Post-processing: Sort by KeyHash and deduplicate
	if len(entries) > 1 {
		slices.SortFunc(entries, func(a, b MappedEntry) int {
			if cmp := bytes.Compare(a.KeyHash[:], b.KeyHash[:]); cmp != 0 {
				return cmp
			}
			return bytes.Compare(a.Value, b.Value)
		})

		entries = slices.CompactFunc(entries, func(a, b MappedEntry) bool {
			return a.KeyHash == b.KeyHash && bytes.Equal(a.Value, b.Value)
		})
	}

	return entries, nil
}

func (h *WASMHost) replenishInstance(oldInst *wasmInstance, reason string) {
	if oldInst != nil && oldInst.mod != nil {
		_ = oldInst.mod.Close(context.Background())
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.mu.Unlock()

	newInst, instErr := h.instantiateInstance(context.Background())

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		if newInst != nil && newInst.mod != nil {
			_ = newInst.mod.Close(context.Background())
		}
		return
	}
	if instErr != nil {
		h.closed = true
		h.haltErr = fmt.Errorf("%w: %s: %v", ErrWasmHalt, reason, instErr)
		return
	}
	select {
	case h.pool <- newInst:
	default:
		if newInst.mod != nil {
			_ = newInst.mod.Close(context.Background())
		}
	}
}

// MapLeaf executes the WASM map_leaf/map_bundle export against leaf payload and returns sorted, deduplicated entries.
func (h *WASMHost) MapLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	h.mu.Lock()
	if h.closed {
		err := h.haltErr
		if err == nil {
			err = ErrHostClosed
		}
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()

	var inst *wasmInstance
	var ok bool
	select {
	case inst, ok = <-h.pool:
		if !ok || inst == nil {
			return nil, ErrHostClosed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var modErr error
	defer func() {
		if modErr != nil {
			h.replenishInstance(inst, "failed to replenish worker instance")
			return
		}

		if inst.resetFn != nil && inst.staticInPtr == 0 {
			if _, resetErr := inst.resetFn.Call(context.Background()); resetErr != nil {
				h.replenishInstance(inst, "failed to replenish worker instance after reset failure")
				return
			}
		}

		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closed {
			_ = inst.mod.Close(context.Background())
			return
		}
		h.pool <- inst
	}()

	entries, err := inst.executeLeaf(ctx, leaf)
	if err != nil {
		modErr = err
		return nil, modErr
	}
	return cloneMappedEntries(entries), nil
}

// MapBundle executes WASM mapping across a contiguous bundle of leaves using a single checked-out instance.
func (h *WASMHost) MapBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	h.mu.Lock()
	if h.closed {
		err := h.haltErr
		if err == nil {
			err = ErrHostClosed
		}
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()

	var inst *wasmInstance
	var ok bool
	select {
	case inst, ok = <-h.pool:
		if !ok || inst == nil {
			return nil, ErrHostClosed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var modErr error
	defer func() {
		if modErr != nil {
			h.replenishInstance(inst, "failed to replenish worker instance")
			return
		}

		if inst.resetFn != nil && inst.staticInPtr == 0 {
			if _, resetErr := inst.resetFn.Call(context.Background()); resetErr != nil {
				h.replenishInstance(inst, "failed to replenish worker instance after reset failure")
				return
			}
		}

		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closed {
			_ = inst.mod.Close(context.Background())
			return
		}
		h.pool <- inst
	}()

	results, err := inst.executeBundle(ctx, leaves)
	if err != nil {
		modErr = err
		return nil, modErr
	}

	return cloneBundleResults(results), nil
}

func cloneBundleResults(results [][]MappedEntry) [][]MappedEntry {
	if results == nil {
		return nil
	}
	cloned := make([][]MappedEntry, len(results))
	for i, r := range results {
		if len(r) > 0 {
			cloned[i] = append([]MappedEntry(nil), r...)
		}
	}
	return cloned
}

func cloneMappedEntries(entries []MappedEntry) []MappedEntry {
	if entries == nil {
		return nil
	}
	cloned := make([]MappedEntry, len(entries))
	for i, e := range entries {
		cloned[i] = MappedEntry{
			Key:     e.Key,
			KeyHash: e.KeyHash,
			Value:   append([]byte(nil), e.Value...),
		}
	}
	return cloned
}

func decodeMappedEntries(data []byte) ([]MappedEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// Schema 1: Structured entries: [Count(4B)][Entry: KeyHash(32B) + ValLen(2B) + Val]...
	if len(data) >= 4 {
		count := binary.BigEndian.Uint32(data[0:4])
		maxPossible := uint32(len(data)-4) / 34
		if count <= maxPossible {
			offset := 4
			entries := make([]MappedEntry, 0, count)
			valid := true
			for i := uint32(0); i < count; i++ {
				if offset+34 > len(data) {
					valid = false
					break
				}
				var entry MappedEntry
				copy(entry.KeyHash[:], data[offset:offset+32])
				offset += 32
				valLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
				offset += 2
				if offset+valLen > len(data) {
					valid = false
					break
				}
				if valLen > 0 {
					entry.Value = make([]byte, valLen)
					copy(entry.Value, data[offset:offset+valLen])
					offset += valLen
				}
				entries = append(entries, entry)
			}
			if valid && offset == len(data) {
				return entries, nil
			}
		}
	}

	// Schema 2: Raw concatenated 32-byte hashes: [Hash(32B)]...
	if len(data)%sha256.Size == 0 {
		count := len(data) / sha256.Size
		entries := make([]MappedEntry, count)
		for i := 0; i < count; i++ {
			copy(entries[i].KeyHash[:], data[i*sha256.Size:(i+1)*sha256.Size])
		}
		return entries, nil
	}

	return nil, fmt.Errorf("%w: length %d is neither structured nor a multiple of 32", ErrMalformedOutput, len(data))
}

// Close closes all module instances and releases the Wazero runtime.
func (h *WASMHost) Close(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true

	close(h.pool)
	for inst := range h.pool {
		_ = inst.mod.Close(ctx)
	}
	if h.compiled != nil {
		_ = h.compiled.Close(ctx)
	}
	if h.runtime != nil {
		return h.runtime.Close(ctx)
	}
	return nil
}

// WASMRunner is a dedicated, unshared WASM execution environment bound to a single worker.
// It executes mapping calls lock-free without instance pool or mutex contention.
type WASMRunner struct {
	host     *WASMHost
	inst     *wasmInstance
	fromPool bool
	closed   bool
	hadErr   bool
}

// NewRunner creates a dedicated WASMRunner from the host.
// The runner has exclusive access to its WASM module instance, eliminating pool and mutex overhead.
func (h *WASMHost) NewRunner(ctx context.Context) (*WASMRunner, error) {
	h.mu.Lock()
	if h.closed {
		err := h.haltErr
		if err == nil {
			err = ErrHostClosed
		}
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()

	var inst *wasmInstance
	var fromPool bool
	select {
	case inst = <-h.pool:
		fromPool = true
	default:
		var err error
		inst, err = h.instantiateInstance(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate wasm runner: %w", err)
		}
	}

	return &WASMRunner{
		host:     h,
		inst:     inst,
		fromPool: fromPool,
	}, nil
}

// NewRunnerMapper creates a dedicated runner satisfying the RunnerProvider interface.
func (h *WASMHost) NewRunnerMapper(ctx context.Context) (LeafMapper, error) {
	return h.NewRunner(ctx)
}

// MapBundle executes WASM mapping across a contiguous bundle of leaves on this dedicated runner.
// The returned slice and sub-slices reference internal runner buffers and remain valid until
// the next invocation of MapBundle or MapLeaf on this runner.
func (r *WASMRunner) MapBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	if r.closed {
		return nil, ErrHostClosed
	}

	results, err := r.inst.executeBundle(ctx, leaves)
	if err != nil {
		r.hadErr = true
		return nil, err
	}

	if r.inst.resetFn != nil && r.inst.staticInPtr == 0 {
		if _, err := r.inst.resetFn.Call(context.Background()); err != nil {
			r.hadErr = true
			return nil, fmt.Errorf("%w: reset failed: %v", ErrWasmHalt, err)
		}
	}

	return results, nil
}

// MapLeaf executes WASM mapping for a single leaf on this dedicated runner.
func (r *WASMRunner) MapLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	if r.closed {
		return nil, ErrHostClosed
	}

	entries, err := r.inst.executeLeaf(ctx, leaf)
	if err != nil {
		r.hadErr = true
		return nil, err
	}

	if r.inst.resetFn != nil && r.inst.staticInPtr == 0 {
		if _, err := r.inst.resetFn.Call(context.Background()); err != nil {
			r.hadErr = true
			return nil, fmt.Errorf("%w: reset failed: %v", ErrWasmHalt, err)
		}
	}

	return entries, nil
}

// Close releases this runner's WASM module instance, returning it to the host pool if healthy.
func (r *WASMRunner) Close(ctx context.Context) error {
	if r.closed {
		return nil
	}
	r.closed = true

	if r.inst == nil {
		return nil
	}

	if r.hadErr {
		var closeErr error
		if r.inst.mod != nil {
			closeErr = r.inst.mod.Close(ctx)
			r.inst.mod = nil
		}
		if r.fromPool {
			r.host.replenishInstance(nil, "failed to replenish runner instance")
		}
		return closeErr
	}

	r.host.mu.Lock()
	defer r.host.mu.Unlock()

	if r.host.closed {
		if r.inst.mod != nil {
			return r.inst.mod.Close(ctx)
		}
		return nil
	}

	select {
	case r.host.pool <- r.inst:
		return nil
	default:
		if r.inst.mod != nil {
			return r.inst.mod.Close(ctx)
		}
		return nil
	}
}
