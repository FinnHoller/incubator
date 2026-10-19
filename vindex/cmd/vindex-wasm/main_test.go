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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func buildTestWasm() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x02,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e, // map_leaf: (i32, i32) -> i64
		0x60, 0x01, 0x7f, 0x01, 0x7f, // allocate: (i32) -> i32
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

	// map_leaf body
	var mapBody bytes.Buffer
	mapBody.Write(leb128U32(0))
	mapBody.WriteByte(0x42)
	packed := (uint64(1024) << 32) | uint64(32)
	mapBody.Write(leb128I64(int64(packed)))
	mapBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(mapBody.Len())))
	codeSec.Write(mapBody.Bytes())

	// allocate body
	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.WriteByte(0x41)
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())

	// Data segment: 32 bytes at 1024
	var dataSec bytes.Buffer
	dataSec.Write(leb128U32(1))
	dataSec.WriteByte(0x00)
	dataSec.WriteByte(0x41)
	dataSec.Write(leb128U32(1024))
	dataSec.WriteByte(0x0b)
	dataSec.Write(leb128U32(32))
	dataSec.Write(bytes.Repeat([]byte{0x77}, 32))
	writeSection(&buf, 11, dataSec.Bytes())

	return buf.Bytes()
}

func TestCLI_TestCmd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmPath, buildTestWasm(), 0o644); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}

	// 1. Plain output
	err := run(ctx, []string{"test", "--wasm=" + wasmPath, "--input=hello"})
	if err != nil {
		t.Fatalf("test command failed: %v", err)
	}

	// 2. JSON output
	err = run(ctx, []string{"test", "--wasm=" + wasmPath, "--input=hello", "--format=json"})
	if err != nil {
		t.Fatalf("test json command failed: %v", err)
	}

	// 3. Hex input
	err = run(ctx, []string{"test", "--wasm=" + wasmPath, "--hex=68656c6c6f"})
	if err != nil {
		t.Fatalf("test hex command failed: %v", err)
	}

	// 4. Input file
	inFile := filepath.Join(tmpDir, "input.txt")
	if err := os.WriteFile(inFile, []byte("file_input"), 0o644); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}
	// 5. Positional input
	err = run(ctx, []string{"test", "--wasm=" + wasmPath, "positional_arg_leaf"})
	if err != nil {
		t.Fatalf("test positional command failed: %v", err)
	}
}

func TestCLI_InspectCmd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmBytes := buildTestWasm()
	wasmPath := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0o644); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stdout = w
	runErr := run(ctx, []string{"inspect", "--wasm=" + wasmPath})
	_ = w.Close()
	os.Stdout = origStdout
	outBytes, _ := io.ReadAll(r)
	_ = r.Close()
	if runErr != nil {
		t.Fatalf("inspect command failed: %v", runErr)
	}

	digest := sha256.Sum256(wasmBytes)
	wantB64 := fmt.Sprintf("MapFn (base64): %s", base64.StdEncoding.EncodeToString(digest[:]))
	wantHex := fmt.Sprintf("SHA-256 (hex): %x", digest)
	outStr := string(outBytes)
	if !strings.Contains(outStr, wantB64) {
		t.Errorf("inspect output missing %q:\n%s", wantB64, outStr)
	}
	if !strings.Contains(outStr, wantHex) {
		t.Errorf("inspect output missing %q:\n%s", wantHex, outStr)
	}

	// Positional syntax
	err = run(ctx, []string{"inspect", wasmPath})
	if err != nil {
		t.Fatalf("inspect positional failed: %v", err)
	}
}

func buildStaticSlabWasm() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x02,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e, // map_bundle: (i32, i32) -> i64
		0x60, 0x00, 0x01, 0x7f, // input_buffer: () -> i32
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
	expSec.WriteByte(10)
	expSec.WriteString("map_bundle")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	expSec.WriteByte(12)
	expSec.WriteString("input_buffer")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(2))

	var mapBody bytes.Buffer
	mapBody.Write(leb128U32(0))
	mapBody.WriteByte(0x42)
	packed := (uint64(1024) << 32) | uint64(8)
	mapBody.Write(leb128I64(int64(packed)))
	mapBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(mapBody.Len())))
	codeSec.Write(mapBody.Bytes())

	var inBufBody bytes.Buffer
	inBufBody.Write(leb128U32(0))
	inBufBody.WriteByte(0x41)
	inBufBody.Write(leb128I64(64))
	inBufBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(inBufBody.Len())))
	codeSec.Write(inBufBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())
	return buf.Bytes()
}

func TestCLI_InspectCmd_InputBufferWithoutAllocate(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "slab.wasm")
	if err := os.WriteFile(wasmPath, buildStaticSlabWasm(), 0o644); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}
	if err := run(ctx, []string{"inspect", "--wasm=" + wasmPath}); err != nil {
		t.Fatalf("inspect failed on input_buffer + map_bundle module: %v", err)
	}
}

func TestCLI_BenchCmd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmPath, buildTestWasm(), 0o644); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}

	err := run(ctx, []string{"bench", "--wasm=" + wasmPath, "--iterations=50", "--workers=2"})
	if err != nil {
		t.Fatalf("bench command failed: %v", err)
	}
}

func TestCLI_ErrorsAndHelp(t *testing.T) {
	ctx := context.Background()

	// Empty args
	if err := run(ctx, []string{}); err == nil {
		t.Fatal("expected error on empty args, got nil")
	}

	// Help flag
	if err := run(ctx, []string{"--help"}); err != nil {
		t.Fatalf("expected nil for help, got %v", err)
	}

	// Unknown subcommand
	if err := run(ctx, []string{"unknown-cmd"}); err == nil {
		t.Fatal("expected error on unknown subcommand, got nil")
	}

	// Missing wasm flag
	if err := run(ctx, []string{"test"}); err == nil {
		t.Fatal("expected error on missing --wasm, got nil")
	}
}

func TestCLI_WithCompiledPlugins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow wasm compilation test in short mode")
	}
	ctx := context.Background()
	tmpDir := t.TempDir()

	sumdbWasm := filepath.Join(tmpDir, "sumdb.wasm")
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", sumdbWasm, "github.com/transparency-dev/incubator/vindex/mapfn/examples/sumdb")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build sumdb wasm: %v\nOutput: %s", err, string(out))
	}

	ctWasm := filepath.Join(tmpDir, "ct.wasm")
	cmd = exec.Command("go", "build", "-buildmode=c-shared", "-o", ctWasm, "github.com/transparency-dev/incubator/vindex/mapfn/examples/ct")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build ct wasm: %v\nOutput: %s", err, string(out))
	}

	// 1. Test sumdb plugin via CLI
	err := run(ctx, []string{"test", "--wasm=" + sumdbWasm, "--input=golang.org/x/mod v0.40.0 h1:abc="})
	if err != nil {
		t.Fatalf("sumdb test failed: %v", err)
	}

	// 2. Test CT plugin via CLI
	err = run(ctx, []string{"test", "--wasm=" + ctWasm, "--input=foo.bar.example.com", "--format=json"})
	if err != nil {
		t.Fatalf("ct test failed: %v", err)
	}

	// 4. Bench CT plugin
	err = run(ctx, []string{"bench", "--wasm=" + ctWasm, "--input=foo.bar.example.com", "--iterations=50", "--workers=2"})
	if err != nil {
		t.Fatalf("ct bench failed: %v", err)
	}
}
