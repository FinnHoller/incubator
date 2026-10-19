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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func runInspectCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	wasmPath := fs.String("wasm", "", "Path to compiled WASM plugin file (required).")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *wasmPath == "" {
		if fs.NArg() > 0 {
			*wasmPath = fs.Arg(0)
		} else {
			return errors.New("--wasm flag is required")
		}
	}

	wasmBytes, err := os.ReadFile(*wasmPath)
	if err != nil {
		return fmt.Errorf("failed to read WASM file %q: %w", *wasmPath, err)
	}

	r := wazero.NewRuntime(ctx)
	defer func() { _ = r.Close(ctx) }()

	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("failed to compile WASM module: %w", err)
	}
	defer func() { _ = compiled.Close(ctx) }()

	exports := compiled.ExportedFunctions()
	imports := compiled.ImportedFunctions()

	hasInputBuf := exports["input_buffer"] != nil
	hasAlloc := hasInputBuf || exports["allocate"] != nil || exports["malloc"] != nil
	hasMapBundle := exports["map_bundle"] != nil
	hasMapLeaf := exports["map_leaf"] != nil
	hasMap := hasMapBundle || hasMapLeaf
	hasReset := exports["reset"] != nil

	digest := sha256.Sum256(wasmBytes)
	fmt.Printf("=== VIndex WASM MapFn Inspection: %s ===\n", *wasmPath)
	fmt.Printf("Module Size: %d bytes (%.2f KB)\n", len(wasmBytes), float64(len(wasmBytes))/1024.0)
	fmt.Printf("MapFn (base64): %s\n", base64.StdEncoding.EncodeToString(digest[:]))
	fmt.Printf("SHA-256 (hex): %x\n\n", digest)

	fmt.Println("Required ABI Exports:")
	if hasInputBuf {
		fmt.Println("  [✓] input_buffer () -> i32 (static 4 MB input slab)")
	} else if exports["allocate"] != nil {
		fmt.Println("  [✓] allocate (i32) -> i32")
	} else if exports["malloc"] != nil {
		fmt.Println("  [✓] malloc (i32) -> i32 (fallback)")
	} else {
		fmt.Println("  [✗] input_buffer, allocate, or malloc: MISSING")
	}

	if hasMapBundle {
		fmt.Println("  [✓] map_bundle (i32, i32) -> i64 (batch tile ABI)")
	} else if hasMapLeaf {
		fmt.Println("  [✓] map_leaf (i32, i32) -> i64 (legacy single-leaf ABI)")
	} else {
		fmt.Println("  [✗] map_bundle or map_leaf: MISSING")
	}

	fmt.Println("\nOptional ABI Exports:")
	if hasReset {
		fmt.Println("  [✓] reset () -> ()")
	} else {
		fmt.Println("  [-] reset: not exported (host will allocate fresh instances on reuse)")
	}

	fmt.Printf("\nImports (%d):\n", len(imports))
	for _, imp := range imports {
		mod, name, _ := imp.Import()
		fmt.Printf("  - %s.%s\n", mod, name)
	}

	fmt.Println("\nABI Compatibility Status:")
	if hasAlloc && hasMap {
		fmt.Println("  >>> PASSED: Compatible with VIndex host runtime (vindexd).")
		return nil
	}

	return errors.New("module failed VIndex MapFn ABI requirements")
}
