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
	"bytes"
	"context"
	"fmt"
	"testing"
)

func writeSection(buf *bytes.Buffer, secID byte, secPayload []byte) {
	buf.WriteByte(secID)
	buf.Write(leb128U32(uint32(len(secPayload))))
	buf.Write(secPayload)
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

func assembleWasmWithReset(resetBody []byte) []byte {
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

func TestIngestionPipeline_WithWASMRunner(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)

	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaves := make([][]byte, 256)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf_%d", i))
	}
	fetcher := &mockTileFetcher{
		leaves:     leaves,
		origin:     "test",
		bundleSize: 64,
	}

	pipeline := NewPipeline(fetcher, nil, host, 4)
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 256)

	var totalLeaves uint64
	for batch := range batchChan {
		totalLeaves += uint64(batch.Count)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("StreamBatches failed: %v", err)
	}
	if totalLeaves != 256 {
		t.Fatalf("expected 256 total leaves processed, got %d", totalLeaves)
	}
}
