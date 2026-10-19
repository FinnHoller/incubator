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
	"unsafe"
)

const (
	// MaxBufferSize is the static arena buffer size (4MB to accommodate 256-leaf bundles).
	MaxBufferSize = 4 * 1024 * 1024
)

var (
	inputBuf      [MaxBufferSize]byte
	outputBuf     [MaxBufferSize]byte
	allocOffset   uint32
	emitOutOffset int
	emitKeyCount  int
	emitOverflow  bool
)

func emitKey(k []byte) {
	kLen := len(k)
	if emitOverflow || emitOutOffset+4+kLen > MaxBufferSize {
		emitOverflow = true
		return
	}
	binary.LittleEndian.PutUint32(outputBuf[emitOutOffset:emitOutOffset+4], uint32(kLen))
	copy(outputBuf[emitOutOffset+4:emitOutOffset+4+kLen], k)
	emitOutOffset += 4 + kLen
	emitKeyCount++
}

// Allocate allocates a slice of size bytes from the static input arena.
// Returns a 32-bit WASM memory address, or 0 if allocation exceeds capacity.
func Allocate(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	if allocOffset+size > MaxBufferSize {
		return 0
	}
	ptr := uint32(uintptr(unsafe.Pointer(&inputBuf[allocOffset])))
	allocOffset += size
	return ptr
}

// GetInputSlice returns a byte slice corresponding to the allocated memory region.
func GetInputSlice(ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	base := uint32(uintptr(unsafe.Pointer(&inputBuf[0])))
	if ptr >= base && ptr+length <= base+MaxBufferSize {
		offset := ptr - base
		return inputBuf[offset : offset+length]
	}
	if ptr < MaxBufferSize && ptr+length <= MaxBufferSize {
		return inputBuf[ptr : ptr+length]
	}
	return nil
}

// Reset clears the bump allocator offset for the next execution.
func Reset() {
	allocOffset = 0
}

// InputBuffer returns the fixed WASM memory address of the static input arena buffer.
func InputBuffer() uint32 {
	return uint32(uintptr(unsafe.Pointer(&inputBuf[0])))
}

// PackBundleInput serializes a slice of up to 256 leaves into the standard input buffer layout.
// Framing: [leaf_count (4B uint32 LE)][offsets ([N+1]uint32 LE)][contiguous payload bytes]
func PackBundleInput(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 || n > 256 {
		return nil
	}

	headerLen := 4 + (n+1)*4
	var payloadLen int
	for _, l := range leaves {
		payloadLen += len(l)
	}

	buf := make([]byte, headerLen+payloadLen)
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

// ExecuteBundle processes a framed bundle of leaves in inputBuf and writes framed preimages to outputBuf.
func ExecuteBundle(inPtr, inLen uint32) (uint32, uint32) {
	allocOffset = 0
	emitOverflow = false
	if inLen < 8 {
		return 0, 0
	}

	inSlice := GetInputSlice(inPtr, inLen)
	if len(inSlice) < 8 {
		return 0, 0
	}

	leafCount := binary.LittleEndian.Uint32(inSlice[0:4])
	if leafCount == 0 || leafCount > 256 {
		return 0, 0
	}

	headerLen := 4 + (leafCount+1)*4
	if uint32(len(inSlice)) < headerLen {
		return 0, 0
	}

	offsetTable := inSlice[4:headerLen]
	payload := inSlice[headerLen:]

	outBase := uint32(uintptr(unsafe.Pointer(&outputBuf[0])))
	binary.LittleEndian.PutUint32(outputBuf[0:4], leafCount)

	keyCountsOffset := 4
	outOffset := 4 + int(leafCount)*4

	for i := uint32(0); i < leafCount; i++ {
		start := binary.LittleEndian.Uint32(offsetTable[i*4 : (i+1)*4])
		end := binary.LittleEndian.Uint32(offsetTable[(i+1)*4 : (i+2)*4])

		if end < start || end > uint32(len(payload)) {
			return 0, 0
		}
		leafBytes := payload[start:end]

		if registeredEmitMapFunc != nil {
			emitOutOffset = outOffset
			emitKeyCount = 0
			registeredEmitMapFunc(leafBytes, emitKey)
			if emitOverflow {
				return 0, 0
			}
			binary.LittleEndian.PutUint32(outputBuf[keyCountsOffset+int(i)*4:], uint32(emitKeyCount))
			outOffset = emitOutOffset
		} else {
			binary.LittleEndian.PutUint32(outputBuf[keyCountsOffset+int(i)*4:], 0)
		}
	}

	return outBase, uint32(outOffset)
}
