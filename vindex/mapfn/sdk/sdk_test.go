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

package sdk

import (
	"encoding/binary"
	"testing"
)

func TestArena_AllocateAndReset(t *testing.T) {
	Reset()

	ptr1 := Allocate(100)
	if ptr1 == 0 {
		t.Fatal("expected non-zero pointer for 100 bytes allocation")
	}

	ptr2 := Allocate(200)
	if ptr2 == 0 {
		t.Fatal("expected non-zero pointer for 200 bytes allocation")
	}
	if ptr2 != ptr1+100 {
		t.Fatalf("expected bump allocation: ptr2=%d, want %d", ptr2, ptr1+100)
	}

	// Test writing and reading via GetInputSlice
	slice := GetInputSlice(ptr1, 100)
	for i := range slice {
		slice[i] = byte(i)
	}
	readSlice := GetInputSlice(ptr1, 100)
	for i := range readSlice {
		if readSlice[i] != byte(i) {
			t.Fatalf("mismatch at byte %d: got %d, want %d", i, readSlice[i], byte(i))
		}
	}

	Reset()
	ptrAfterReset := Allocate(50)
	if ptrAfterReset != ptr1 {
		t.Fatalf("expected reset to return to base ptr %d, got %d", ptr1, ptrAfterReset)
	}
}

func TestArena_AllocateOverflow(t *testing.T) {
	Reset()

	ptr := Allocate(MaxBufferSize + 1)
	if ptr != 0 {
		t.Fatalf("expected 0 for oversized allocation, got %d", ptr)
	}

	// Allocate entire buffer
	ptr = Allocate(MaxBufferSize)
	if ptr == 0 {
		t.Fatal("expected successful full buffer allocation")
	}

	// Subsequent allocation must fail
	ptrExtra := Allocate(1)
	if ptrExtra != 0 {
		t.Fatalf("expected 0 after full buffer allocated, got %d", ptrExtra)
	}
	Reset()
}

func TestPackBundleInput_And_ExecuteBundle_Emit(t *testing.T) {
	Reset()

	RegisterEmit(func(leaf []byte, emit func(key []byte)) {
		if string(leaf) == "skip" {
			return
		}
		emit([]byte("key_" + string(leaf)))
		emit([]byte("extra_" + string(leaf)))
	})

	leaves := [][]byte{
		[]byte("leaf0"),
		[]byte("leaf1"),
		[]byte("skip"),
		[]byte("leaf3"),
	}

	packedInput := PackBundleInput(leaves)
	if len(packedInput) == 0 {
		t.Fatal("PackBundleInput returned empty buffer")
	}

	ptr := Allocate(uint32(len(packedInput)))
	if ptr == 0 {
		t.Fatal("Allocate failed")
	}
	copy(GetInputSlice(ptr, uint32(len(packedInput))), packedInput)

	outPtr, outLen := ExecuteBundle(ptr, uint32(len(packedInput)))
	if outPtr == 0 || outLen == 0 {
		t.Fatalf("ExecuteBundle failed: outPtr=%d outLen=%d", outPtr, outLen)
	}

	outBuf := outputBuf[:outLen]
	leafCount := binary.LittleEndian.Uint32(outBuf[0:4])
	if leafCount != 4 {
		t.Fatalf("leafCount = %d, want 4", leafCount)
	}

	k0 := binary.LittleEndian.Uint32(outBuf[4:8])
	k1 := binary.LittleEndian.Uint32(outBuf[8:12])
	k2 := binary.LittleEndian.Uint32(outBuf[12:16])
	k3 := binary.LittleEndian.Uint32(outBuf[16:20])

	if k0 != 2 || k1 != 2 || k2 != 0 || k3 != 2 {
		t.Fatalf("key counts mismatch: [%d, %d, %d, %d], want [2, 2, 0, 2]", k0, k1, k2, k3)
	}

	// Verify mapBundle wasm export
	ret := mapBundle(ptr, uint32(len(packedInput)))
	if ret == 0 {
		t.Fatal("mapBundle returned 0")
	}

	reset()
	if allocOffset != 0 {
		t.Fatalf("reset failed, allocOffset is %d", allocOffset)
	}
}

func TestExecuteBundle_EmitSingle(t *testing.T) {
	Reset()

	RegisterEmit(func(leaf []byte, emit func(key []byte)) {
		emit([]byte("domain_" + string(leaf)))
	})

	leaves := [][]byte{[]byte("example.com")}
	packedInput := PackBundleInput(leaves)

	ptr := Allocate(uint32(len(packedInput)))
	copy(GetInputSlice(ptr, uint32(len(packedInput))), packedInput)

	outPtr, outLen := ExecuteBundle(ptr, uint32(len(packedInput)))
	if outPtr == 0 || outLen == 0 {
		t.Fatalf("ExecuteBundle failed: outPtr=%d outLen=%d", outPtr, outLen)
	}

	outBuf := outputBuf[:outLen]
	leafCount := binary.LittleEndian.Uint32(outBuf[0:4])
	if leafCount != 1 {
		t.Fatalf("leafCount = %d, want 1", leafCount)
	}
	kCount := binary.LittleEndian.Uint32(outBuf[4:8])
	if kCount != 1 {
		t.Fatalf("kCount = %d, want 1", kCount)
	}

	keyLen := binary.LittleEndian.Uint32(outBuf[8:12])
	keyBytes := string(outBuf[12 : 12+keyLen])
	if keyBytes != "domain_example.com" {
		t.Fatalf("key = %q, want %q", keyBytes, "domain_example.com")
	}
}

func TestExecuteBundle_EmitOverflow(t *testing.T) {
	Reset()

	RegisterEmit(func(leaf []byte, emit func(key []byte)) {
		bigKey := make([]byte, MaxBufferSize)
		emit(bigKey)
	})

	leaves := [][]byte{[]byte("leaf")}
	packedInput := PackBundleInput(leaves)

	ptr := Allocate(uint32(len(packedInput)))
	copy(GetInputSlice(ptr, uint32(len(packedInput))), packedInput)

	outPtr, outLen := ExecuteBundle(ptr, uint32(len(packedInput)))
	if outPtr != 0 || outLen != 0 {
		t.Fatalf("expected (0, 0) on overflow, got (%d, %d)", outPtr, outLen)
	}
}


