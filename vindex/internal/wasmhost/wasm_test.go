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

package wasmhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func writeSection(buf *bytes.Buffer, secID byte, secPayload []byte) {
	buf.WriteByte(secID)
	buf.Write(leb128U32(uint32(len(secPayload))))
	buf.Write(secPayload)
}

func assembleWasm(funcBody []byte, dataBytes []byte, dataOffset uint32) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x02,                   // 2 types
		0x60, 0x02, 0x7f, 0x7f, // type 0: func(i32, i32) -> i64
		0x01, 0x7e,
		0x60, 0x01, 0x7f, // type 1: func(i32) -> i32
		0x01, 0x7f,
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x02, 0x00, 0x01} // 2 funcs
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(3) // 3 exports
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(2)) // 2 function bodies

	var body bytes.Buffer
	body.Write(leb128U32(0)) // 0 local declarations
	body.Write(funcBody)
	body.WriteByte(0x0b) // end opcode

	codeSec.Write(leb128U32(uint32(body.Len())))
	codeSec.Write(body.Bytes())

	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0)) // 0 local declarations
	allocBody.WriteByte(0x41)     // i32.const
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b) // end opcode

	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())

	if len(dataBytes) > 0 {
		var dataSec bytes.Buffer
		dataSec.Write(leb128U32(1)) // 1 data segment
		dataSec.WriteByte(0x00)     // active segment, memory 0
		dataSec.WriteByte(0x41)
		dataSec.Write(leb128U32(dataOffset))
		dataSec.WriteByte(0x0b)
		dataSec.Write(leb128U32(uint32(len(dataBytes))))
		dataSec.Write(dataBytes)
		writeSection(&buf, 11, dataSec.Bytes())
	}

	return buf.Bytes()
}

func encodeStructuredEntries(entries []MappedEntry) []byte {
	var buf bytes.Buffer
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(entries)))
	buf.Write(count[:])
	for _, e := range entries {
		buf.Write(e.KeyHash[:])
		var vlen [2]byte
		binary.BigEndian.PutUint16(vlen[:], uint16(len(e.Value)))
		buf.Write(vlen[:])
		buf.Write(e.Value)
	}
	return buf.Bytes()
}

func buildStaticOutputWasm(staticBytes []byte) []byte {
	var body bytes.Buffer
	packed := (uint64(1024) << 32) | uint64(len(staticBytes))
	body.WriteByte(0x42) // i64.const
	body.Write(leb128I64(int64(packed)))

	return assembleWasm(body.Bytes(), staticBytes, 1024)
}

func leb128U32(val uint32) []byte {
	var res []byte
	for {
		b := byte(val & 0x7f)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		res = append(res, b)
		if val == 0 {
			break
		}
	}
	return res
}

func leb128I64(val int64) []byte {
	var res []byte
	for {
		b := byte(val & 0x7f)
		val >>= 7
		sign := (b & 0x40) != 0
		if (val == 0 && !sign) || (val == -1 && sign) {
			res = append(res, b)
			break
		}
		b |= 0x80
		res = append(res, b)
	}
	return res
}

func TestWASMHost_StructuredEntries(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("key_beta"))
	h2 := sha256.Sum256([]byte("key_alpha"))
	h3 := sha256.Sum256([]byte("key_alpha")) // duplicate to test sorting & deduplication

	inputEntries := []MappedEntry{
		{KeyHash: h1, Value: []byte("val_beta")},
		{KeyHash: h2, Value: []byte("val_alpha")},
		{KeyHash: h3, Value: []byte("val_alpha")},
	}
	encoded := encodeStructuredEntries(inputEntries)
	wasmBytes := buildStaticOutputWasm(encoded)

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapLeaf(ctx, []byte("test_leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}

	expected := []MappedEntry{
		{KeyHash: h1, Value: []byte("val_beta")},
		{KeyHash: h2, Value: []byte("val_alpha")},
	}

	if diff := cmp.Diff(expected, results); diff != "" {
		t.Fatalf("MapLeaf diff (-want +got):\n%s", diff)
	}
}

func TestWASMHost_RawHashes(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("z_key"))
	h2 := sha256.Sum256([]byte("a_key"))

	raw := append(h1[:], h2[:]...)
	wasmBytes := buildStaticOutputWasm(raw)

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapLeaf(ctx, []byte("leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}

	expected := []MappedEntry{
		{KeyHash: h1},
		{KeyHash: h2},
	}

	if diff := cmp.Diff(expected, results); diff != "" {
		t.Fatalf("MapLeaf diff (-want +got):\n%s", diff)
	}
}

func TestWASMHost_EmptyOutput(t *testing.T) {
	ctx := context.Background()

	var body bytes.Buffer
	packed := uint64(1024) << 32
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasm(body.Bytes(), nil, 0)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapLeaf(ctx, []byte("leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected empty results, got %v", results)
	}
}

func TestWASMHost_UnreachableTrap(t *testing.T) {
	ctx := context.Background()

	funcBody := []byte{0x00}
	wasmBytes := assembleWasm(funcBody, nil, 0)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("trap_leaf"))
	if err == nil {
		t.Fatal("expected error on unreachable instruction, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func TestWASMHost_OutOfBoundsMemory(t *testing.T) {
	ctx := context.Background()

	var body bytes.Buffer
	packed := (uint64(500000) << 32) | uint64(32)
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasm(body.Bytes(), nil, 0)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("oob_leaf"))
	if err == nil {
		t.Fatal("expected out of bounds error, got nil")
	}
	if !errors.Is(err, ErrInvalidMemory) {
		t.Fatalf("expected ErrInvalidMemory, got: %v", err)
	}
}

func TestWASMHost_MalformedOutput(t *testing.T) {
	ctx := context.Background()

	junkData := bytes.Repeat([]byte{0xFF}, 17)
	wasmBytes := buildStaticOutputWasm(junkData)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("malformed"))
	if err == nil {
		t.Fatal("expected malformed output error, got nil")
	}
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput, got: %v", err)
	}
}

func TestWASMHost_ConcurrentExecution(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("concurrent_key"))
	wasmBytes := buildStaticOutputWasm(h1[:])

	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				res, err := host.MapLeaf(ctx, []byte("concurrent_leaf"))
				if err != nil {
					t.Errorf("concurrent MapLeaf failed: %v", err)
					return
				}
				if len(res) != 1 || res[0].KeyHash != h1 {
					t.Errorf("unexpected MapLeaf result: %v", res)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestWASMHost_ClosedHost(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("closed_key"))
	wasmBytes := buildStaticOutputWasm(h1[:])

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}

	if err := host.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err = host.MapLeaf(ctx, []byte("leaf"))
	if !errors.Is(err, ErrHostClosed) {
		t.Fatalf("expected ErrHostClosed after Close(), got: %v", err)
	}
}

func assembleWasmWithoutAllocate(funcBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x01,
		0x60, 0x02, 0x7f, 0x7f,
		0x01, 0x7e,
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x01, 0x00}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(2)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(1))
	var body bytes.Buffer
	body.Write(leb128U32(0))
	body.Write(funcBody)
	body.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(body.Len())))
	codeSec.Write(body.Bytes())
	writeSection(&buf, 10, codeSec.Bytes())

	return buf.Bytes()
}

func TestWASMHost_MissingAllocateExport(t *testing.T) {
	ctx := context.Background()

	var body bytes.Buffer
	packed := uint64(1024) << 32
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasmWithoutAllocate(body.Bytes())

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("non_empty_leaf"))
	if err == nil {
		t.Fatal("expected error on missing allocate export, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func assembleWasmWithNullAllocate(funcBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x02,
		0x60, 0x02, 0x7f, 0x7f,
		0x01, 0x7e,
		0x60, 0x01, 0x7f,
		0x01, 0x7f,
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x02, 0x00, 0x01}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(3)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(2))

	var body bytes.Buffer
	body.Write(leb128U32(0))
	body.Write(funcBody)
	body.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(body.Len())))
	codeSec.Write(body.Bytes())

	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.Write([]byte{0x41, 0x00}) // i32.const 0 (NULL)
	allocBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())
	return buf.Bytes()
}

func TestWASMHost_NullPointerAllocation(t *testing.T) {
	ctx := context.Background()

	var body bytes.Buffer
	packed := uint64(1024) << 32
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasmWithNullAllocate(body.Bytes())

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("non_empty_leaf"))
	if err == nil {
		t.Fatal("expected error on null pointer allocation, got nil")
	}
	if !errors.Is(err, ErrInvalidMemory) {
		t.Fatalf("expected ErrInvalidMemory, got: %v", err)
	}
}

func assembleWasmWithInfiniteLoop() []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x40, 0x0c, 0x00, 0x0b})
	body.WriteByte(0x42)
	body.Write(leb128I64(0))
	return assembleWasm(body.Bytes(), nil, 0)
}

func TestWASMHost_Timeout(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithInfiniteLoop()

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leafCtx, leafCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer leafCancel()

	start := time.Now()
	_, err = host.MapLeaf(leafCtx, []byte("infinite_loop"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error for infinite loop, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
	if elapsed < 80*time.Millisecond || elapsed > 2000*time.Millisecond {
		t.Logf("execution elapsed: %v (expected ~100ms timeout)", elapsed)
	}
}

func assembleWasmWithReset(resetBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x03,                   // 3 types
		0x60, 0x02, 0x7f, 0x7f, // type 0: func(i32, i32) -> i64 (map_leaf)
		0x01, 0x7e,
		0x60, 0x01, 0x7f, // type 1: func(i32) -> i32 (allocate)
		0x01, 0x7f,
		0x60, 0x00, 0x00, // type 2: func() -> () (reset)
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x03, 0x00, 0x01, 0x02}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(4)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)
	expSec.WriteByte(5)
	expSec.WriteString("reset")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x02)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(3))

	var mapBody bytes.Buffer
	mapBody.Write(leb128U32(0))
	mapBody.WriteByte(0x42)
	packed := (uint64(1024) << 32) | uint64(32)
	mapBody.Write(leb128I64(int64(packed)))
	mapBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(mapBody.Len())))
	codeSec.Write(mapBody.Bytes())

	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.WriteByte(0x41)
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	var rBody bytes.Buffer
	rBody.Write(leb128U32(0))
	rBody.Write(resetBody)
	rBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(rBody.Len())))
	codeSec.Write(rBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())

	var dataSec bytes.Buffer
	dataSec.Write(leb128U32(1))
	dataSec.WriteByte(0x00)
	dataSec.WriteByte(0x41)
	dataSec.Write(leb128U32(1024))
	dataSec.WriteByte(0x0b)
	dataSec.Write(leb128U32(32))
	dataSec.Write(bytes.Repeat([]byte{0x42}, 32))
	writeSection(&buf, 11, dataSec.Bytes())

	return buf.Bytes()
}

func TestWASMHost_ResetExport(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	for i := 0; i < 2; i++ {
		res, err := host.MapLeaf(ctx, []byte("leaf"))
		if err != nil {
			t.Fatalf("run %d failed: %v", i, err)
		}
		if len(res) != 1 {
			t.Fatalf("run %d expected 1 entry, got %d", i, len(res))
		}
	}
}

func TestWASMHost_ResetFailureReplenishesPool(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset([]byte{0x00})

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	res, err := host.MapLeaf(ctx, []byte("leaf"))
	if err != nil {
		t.Fatalf("first MapLeaf failed: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res))
	}

	res, err = host.MapLeaf(ctx, []byte("leaf2"))
	if err != nil {
		t.Fatalf("second MapLeaf failed: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res))
	}
}

func assembleWasmWASIImport() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x03,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e,
		0x60, 0x01, 0x7f, 0x01, 0x7f,
	}
	writeSection(&buf, 1, typeSec)

	var impSec bytes.Buffer
	impSec.WriteByte(1)
	impSec.WriteByte(22)
	impSec.WriteString("wasi_snapshot_preview1")
	impSec.WriteByte(10)
	impSec.WriteString("random_get")
	impSec.WriteByte(0x00)
	impSec.WriteByte(0x00)
	writeSection(&buf, 2, impSec.Bytes())

	funcSec := []byte{0x02, 0x01, 0x02}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(3)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x02)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(2))

	var mapBody bytes.Buffer
	mapBody.Write(leb128U32(0))
	mapBody.Write([]byte{
		0x41, 0x80, 0x08,
		0x41, 0x20,
		0x10, 0x00,
		0x1a,
		0x42,
	})
	packed := (uint64(1024) << 32) | uint64(32)
	mapBody.Write(leb128I64(int64(packed)))
	mapBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(mapBody.Len())))
	codeSec.Write(mapBody.Bytes())

	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.WriteByte(0x41)
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())
	return buf.Bytes()
}

func TestWASMHost_WASIInstantiation(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWASIImport()

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed for WASI module: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	res, err := host.MapLeaf(ctx, []byte("wasi_leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res))
	}
}

func TestWASMHost_MapBundle(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaves := [][]byte{
		[]byte("leaf0"),
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
	}

	results, err := host.MapBundle(ctx, leaves)
	if err != nil {
		t.Fatalf("MapBundle failed: %v", err)
	}
	if len(results) != len(leaves) {
		t.Fatalf("expected %d bundle results, got %d", len(leaves), len(results))
	}
	for i, r := range results {
		if len(r) != 1 {
			t.Fatalf("leaf %d expected 1 entry, got %d", i, len(r))
		}
	}
}

func assembleMapBundleWasm(outputData []byte, outOffset uint32) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x03,
		0x60, 0x02, 0x7f, 0x7f,
		0x01, 0x7e,
		0x60, 0x01, 0x7f,
		0x01, 0x7f,
		0x60, 0x00, 0x00,
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x03, 0x00, 0x01, 0x02}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(4)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)

	expSec.WriteByte(10)
	expSec.WriteString("map_bundle")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)

	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)

	expSec.WriteByte(5)
	expSec.WriteString("reset")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x02)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(3))

	var mapBody bytes.Buffer
	mapBody.Write(leb128U32(0))
	packed := (uint64(outOffset) << 32) | uint64(len(outputData))
	mapBody.WriteByte(0x42)
	mapBody.Write(leb128I64(int64(packed)))
	mapBody.WriteByte(0x0b)

	codeSec.Write(leb128U32(uint32(mapBody.Len())))
	codeSec.Write(mapBody.Bytes())

	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.WriteByte(0x41)
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b)

	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	var resetBody bytes.Buffer
	resetBody.Write(leb128U32(0))
	resetBody.WriteByte(0x0b)

	codeSec.Write(leb128U32(uint32(resetBody.Len())))
	codeSec.Write(resetBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())

	if len(outputData) > 0 {
		var dataSec bytes.Buffer
		dataSec.Write(leb128U32(1))
		dataSec.WriteByte(0x00)
		dataSec.WriteByte(0x41)
		dataSec.Write(leb128U32(outOffset))
		dataSec.WriteByte(0x0b)
		dataSec.Write(leb128U32(uint32(len(outputData))))
		dataSec.Write(outputData)
		writeSection(&buf, 11, dataSec.Bytes())
	}

	return buf.Bytes()
}

func TestWASMHost_MapBundle_PreimagesAndHardwareHashing(t *testing.T) {
	ctx := context.Background()

	var outBuf bytes.Buffer
	var leafCount [4]byte
	binary.LittleEndian.PutUint32(leafCount[:], 3)
	outBuf.Write(leafCount[:])

	var kc [12]byte
	binary.LittleEndian.PutUint32(kc[0:4], 2)
	binary.LittleEndian.PutUint32(kc[4:8], 0)
	binary.LittleEndian.PutUint32(kc[8:12], 1)
	outBuf.Write(kc[:])

	k0 := []byte("golang.org/x/mod")
	var k0Len [4]byte
	binary.LittleEndian.PutUint32(k0Len[:], uint32(len(k0)))
	outBuf.Write(k0Len[:])
	outBuf.Write(k0)

	k1 := []byte("example.com")
	var k1Len [4]byte
	binary.LittleEndian.PutUint32(k1Len[:], uint32(len(k1)))
	outBuf.Write(k1Len[:])
	outBuf.Write(k1)

	k2 := []byte("my-package")
	var k2Len [4]byte
	binary.LittleEndian.PutUint32(k2Len[:], uint32(len(k2)))
	outBuf.Write(k2Len[:])
	outBuf.Write(k2)

	wasmBytes := assembleMapBundleWasm(outBuf.Bytes(), 2048)
	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaves := [][]byte{
		[]byte("leaf0_payload"),
		[]byte("leaf1_payload"),
		[]byte("leaf2_payload"),
	}

	results, err := host.MapBundle(ctx, leaves)
	if err != nil {
		t.Fatalf("MapBundle failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	h0 := sha256.Sum256(k0)
	h1 := sha256.Sum256(k1)
	if len(results[0]) != 2 {
		t.Fatalf("leaf 0 expected 2 entries, got %d", len(results[0]))
	}
	var expected0, expected1 [32]byte
	if bytes.Compare(h0[:], h1[:]) < 0 {
		expected0, expected1 = h0, h1
	} else {
		expected0, expected1 = h1, h0
	}
	if results[0][0].KeyHash != expected0 || results[0][1].KeyHash != expected1 {
		t.Fatalf("leaf 0 key hashes mismatch")
	}

	if len(results[1]) != 0 {
		t.Fatalf("leaf 1 expected 0 entries, got %d", len(results[1]))
	}

	h2 := sha256.Sum256(k2)
	if len(results[2]) != 1 {
		t.Fatalf("leaf 2 expected 1 entry, got %d", len(results[2]))
	}
	if results[2][0].KeyHash != h2 {
		t.Fatalf("leaf 2 hash mismatch: got %x, want %x", results[2][0].KeyHash, h2)
	}
}

func BenchmarkWASMHost_MapLeaf(b *testing.B) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)
	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaf := []byte("benchmark_leaf_payload")
	b.ReportAllocs()

	for b.Loop() {
		_, err := host.MapLeaf(ctx, leaf)
		if err != nil {
			b.Fatalf("MapLeaf failed: %v", err)
		}
	}
}

func BenchmarkWASMHost_MapBundle(b *testing.B) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)
	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaves := make([][]byte, 256)
	for i := range leaves {
		leaves[i] = []byte("benchmark_leaf_payload")
	}

	b.ReportAllocs()

	for b.Loop() {
		_, err := host.MapBundle(ctx, leaves)
		if err != nil {
			b.Fatalf("MapBundle failed: %v", err)
		}
	}
}

func BenchmarkWASMRunner_MapBundle(b *testing.B) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)
	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		b.Fatalf("NewRunner failed: %v", err)
	}
	defer func() { _ = runner.Close(ctx) }()

	leaves := make([][]byte, 256)
	for i := range leaves {
		leaves[i] = []byte("benchmark_leaf_payload")
	}

	b.ReportAllocs()

	for b.Loop() {
		_, err := runner.MapBundle(ctx, leaves)
		if err != nil {
			b.Fatalf("runner.MapBundle failed: %v", err)
		}
	}
}

func BenchmarkDecodeBundleOutput(b *testing.B) {
	const leavesCount = 256
	const keysPerLeaf = 2
	var outBuf bytes.Buffer
	var countBuf [4]byte
	binary.LittleEndian.PutUint32(countBuf[:], leavesCount)
	outBuf.Write(countBuf[:])

	for i := 0; i < leavesCount; i++ {
		var kc [4]byte
		binary.LittleEndian.PutUint32(kc[:], keysPerLeaf)
		outBuf.Write(kc[:])
	}

	domain1 := []byte("example.com")
	domain2 := []byte("sub.example.org")
	for i := 0; i < leavesCount; i++ {
		var k1Len, k2Len [4]byte
		binary.LittleEndian.PutUint32(k1Len[:], uint32(len(domain1)))
		outBuf.Write(k1Len[:])
		outBuf.Write(domain1)

		binary.LittleEndian.PutUint32(k2Len[:], uint32(len(domain2)))
		outBuf.Write(k2Len[:])
		outBuf.Write(domain2)
	}

	rawOutput := outBuf.Bytes()
	b.ReportAllocs()

	for b.Loop() {
		res, err := decodeBundleOutput(rawOutput, leavesCount)
		if err != nil || len(res) != leavesCount {
			b.Fatalf("decodeBundleOutput failed: %v", err)
		}
	}
}

func BenchmarkDecodeBundleOutputInto(b *testing.B) {
	const leavesCount = 256
	const keysPerLeaf = 2
	var outBuf bytes.Buffer
	var countBuf [4]byte
	binary.LittleEndian.PutUint32(countBuf[:], leavesCount)
	outBuf.Write(countBuf[:])

	for i := 0; i < leavesCount; i++ {
		var kc [4]byte
		binary.LittleEndian.PutUint32(kc[:], keysPerLeaf)
		outBuf.Write(kc[:])
	}

	domain1 := []byte("example.com")
	domain2 := []byte("sub.example.org")
	for i := 0; i < leavesCount; i++ {
		var k1Len, k2Len [4]byte
		binary.LittleEndian.PutUint32(k1Len[:], uint32(len(domain1)))
		outBuf.Write(k1Len[:])
		outBuf.Write(domain1)

		binary.LittleEndian.PutUint32(k2Len[:], uint32(len(domain2)))
		outBuf.Write(k2Len[:])
		outBuf.Write(domain2)
	}

	rawOutput := outBuf.Bytes()
	var resultsBuf [][]MappedEntry
	var entriesBuf []MappedEntry

	b.ReportAllocs()

	for b.Loop() {
		var err error
		resultsBuf, entriesBuf, err = decodeBundleOutputInto(resultsBuf, entriesBuf, rawOutput, leavesCount)
		if err != nil || len(resultsBuf) != leavesCount {
			b.Fatalf("decodeBundleOutputInto failed: %v", err)
		}
	}
}

func BenchmarkWASMRunner_MapBundleRealWasm(b *testing.B) {
	ctx := context.Background()
	const leavesCount = 256
	const keysPerLeaf = 2
	var outBuf bytes.Buffer
	var countBuf [4]byte
	binary.LittleEndian.PutUint32(countBuf[:], leavesCount)
	outBuf.Write(countBuf[:])

	for i := 0; i < leavesCount; i++ {
		var kc [4]byte
		binary.LittleEndian.PutUint32(kc[:], keysPerLeaf)
		outBuf.Write(kc[:])
	}

	domain1 := []byte("example.com")
	domain2 := []byte("sub.example.org")
	for i := 0; i < leavesCount; i++ {
		var k1Len, k2Len [4]byte
		binary.LittleEndian.PutUint32(k1Len[:], uint32(len(domain1)))
		outBuf.Write(k1Len[:])
		outBuf.Write(domain1)

		binary.LittleEndian.PutUint32(k2Len[:], uint32(len(domain2)))
		outBuf.Write(k2Len[:])
		outBuf.Write(domain2)
	}

	rawOutput := outBuf.Bytes()
	wasmBytes := assembleMapBundleWasm(rawOutput, 32768)
	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		b.Fatalf("NewRunner failed: %v", err)
	}
	defer func() { _ = runner.Close(ctx) }()

	leaves := make([][]byte, leavesCount)
	for i := range leaves {
		leaves[i] = []byte("benchmark_leaf_payload")
	}

	b.ReportAllocs()

	for b.Loop() {
		res, err := runner.MapBundle(ctx, leaves)
		if err != nil || len(res) != leavesCount {
			b.Fatalf("runner.MapBundle failed: %v", err)
		}
	}
}

func TestWASMRunner_DedicatedExecution(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer func() { _ = runner.Close(ctx) }()

	res, err := runner.MapLeaf(ctx, []byte("test_leaf"))
	if err != nil {
		t.Fatalf("runner.MapLeaf failed: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected non-empty entries")
	}

	leaves := [][]byte{[]byte("bundle_leaf_0"), []byte("bundle_leaf_1")}
	bundleRes, err := runner.MapBundle(ctx, leaves)
	if err != nil {
		t.Fatalf("runner.MapBundle failed: %v", err)
	}
	if len(bundleRes) != 2 {
		t.Fatalf("expected 2 bundle results, got %d", len(bundleRes))
	}
}

func TestWASMRunner_ConcurrentDedicatedRunners(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)

	concurrency := 8
	host, err := NewWASMHost(ctx, wasmBytes, concurrency)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			runner, err := host.NewRunner(ctx)
			if err != nil {
				errCh <- fmt.Errorf("worker %d: NewRunner failed: %w", workerID, err)
				return
			}
			defer func() { _ = runner.Close(ctx) }()

			for j := 0; j < 50; j++ {
				leaves := [][]byte{
					[]byte(fmt.Sprintf("worker_%d_bundle_%d_leaf_0", workerID, j)),
					[]byte(fmt.Sprintf("worker_%d_bundle_%d_leaf_1", workerID, j)),
				}
				res, err := runner.MapBundle(ctx, leaves)
				if err != nil {
					errCh <- fmt.Errorf("worker %d: MapBundle failed on iter %d: %w", workerID, j, err)
					return
				}
				if len(res) != 2 {
					errCh <- fmt.Errorf("worker %d: expected 2 results, got %d", workerID, len(res))
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func TestDecodeBundleOutput_BoundsCheck(t *testing.T) {
	outBuf := make([]byte, 20)
	binary.LittleEndian.PutUint32(outBuf[0:4], 1)
	binary.LittleEndian.PutUint32(outBuf[4:8], 1_000_000)

	_, err := decodeBundleOutput(outBuf, 1)
	if err == nil {
		t.Fatal("expected error for totalKeys exceeding buffer capacity, got nil")
	}
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput, got: %v", err)
	}
}

func TestDecodeBundleOutputInto_CapacityProtection(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(5))
	buf.WriteString("key_a")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(5))
	buf.WriteString("key_a")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(5))
	buf.WriteString("key_b")

	results, entries, err := decodeBundleOutputInto(nil, nil, buf.Bytes(), 2)
	if err != nil {
		t.Fatalf("decodeBundleOutputInto failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 leaf results, got %d", len(results))
	}
	if len(results[0]) != 1 {
		t.Fatalf("expected 1 compacted key in leaf 0, got %d", len(results[0]))
	}
	if cap(results[0]) != len(results[0]) {
		t.Errorf("expected cap(results[0]) == len(results[0]) (%d), got cap %d", len(results[0]), cap(results[0]))
	}
	if len(results[1]) != 1 {
		t.Fatalf("expected 1 key in leaf 1, got %d", len(results[1]))
	}
	if cap(results[1]) != len(results[1]) {
		t.Errorf("expected cap(results[1]) == len(results[1]) (%d), got cap %d", len(results[1]), cap(results[1]))
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 total compacted entries, got %d", len(entries))
	}
	expectedHashA := sha256.Sum256([]byte("key_a"))
	expectedHashB := sha256.Sum256([]byte("key_b"))
	if results[0][0].KeyHash != expectedHashA {
		t.Errorf("leaf 0 hash mismatch: got %x, want %x", results[0][0].KeyHash, expectedHashA)
	}
	if results[1][0].KeyHash != expectedHashB {
		t.Errorf("leaf 1 hash mismatch: got %x, want %x", results[1][0].KeyHash, expectedHashB)
	}
}

func TestDecodeBundleOutputInto_KeyLenOverflow(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	buf.WriteString("short_data")

	_, _, err := decodeBundleOutputInto(nil, nil, buf.Bytes(), 1)
	if err == nil {
		t.Fatal("expected ErrMalformedOutput for overflowing keyLen, got nil")
	}
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput, got: %v", err)
	}
}

func TestWASMHost_MapBundle_ZeroLenSlabOverflowFailsFast(t *testing.T) {
	ctx := context.Background()

	wasmBytes := assembleMapBundleWasm(nil, 0)
	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapBundle(ctx, [][]byte{[]byte("leaf0")})
	if err == nil {
		t.Fatal("expected ErrWasmHalt when map_bundle returns (0, 0), got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func TestWASMRunner_TrapReplenishesPoolSlot(t *testing.T) {
	ctx := context.Background()

	wasmBytes := assembleWasm([]byte{0x00}, nil, 0)
	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	if _, err := runner.MapLeaf(ctx, []byte("trap")); !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt on trap, got: %v", err)
	}
	if err := runner.Close(ctx); err != nil {
		t.Fatalf("runner.Close failed: %v", err)
	}

	if got := len(host.pool); got != 1 {
		t.Fatalf("expected host.pool len = 1 after runner trap Close(), got %d", got)
	}
}

func TestDecodeBundleOutputInto_NonCanonicalKeys(t *testing.T) {
	badKeys := [][]byte{
		{},
		bytes.Repeat([]byte("a"), 1025),
		[]byte("has space"),
		[]byte("has\x00nul"),
		[]byte("has\x7fdel"),
		[]byte{0x20},
		[]byte{0xff},
	}
	for i, badKey := range badKeys {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(badKey)))
		buf.Write(badKey)

		_, _, err := decodeBundleOutputInto(nil, nil, buf.Bytes(), 1)
		if !errors.Is(err, ErrMalformedOutput) {
			t.Fatalf("case %d (%q): expected ErrMalformedOutput, got %v", i, badKey, err)
		}
	}
}
