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

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
)

var (
	ErrWasmHalt        = wasmhost.ErrWasmHalt
	ErrInvalidMemory   = wasmhost.ErrInvalidMemory
	ErrUnalignedOutput = wasmhost.ErrUnalignedOutput
	ErrMalformedOutput = wasmhost.ErrMalformedOutput
	ErrHostClosed      = wasmhost.ErrHostClosed
)

// MappedEntry represents a single search key and optional value produced by a LeafMapper.
type MappedEntry = wasmhost.MappedEntry

// ValidatePreimageKey validates that a WASM-emitted preimage key satisfies the canonical
// key invariants: 1 <= len <= 1024 and printable ASCII (0x21..0x7E, no NUL or whitespace).
func ValidatePreimageKey(keyBytes []byte) error {
	return wasmhost.ValidatePreimageKey(keyBytes)
}

// LeafMapper maps a raw Input Log leaf payload to a set of searchable MappedEntry records.
type LeafMapper = wasmhost.LeafMapper

// MapFnHashProvider is an optional interface for LeafMappers that expose a 32-byte SHA-256 commitment
// to their mapping function implementation (e.g. SHA-256 of the compiled WASM module).
type MapFnHashProvider = wasmhost.MapFnHashProvider

// WASMHost manages the lifecycle and execution of a compiled Wazero WebAssembly module.
type WASMHost = wasmhost.WASMHost

// Engine is an alias for WASMHost.
type Engine = wasmhost.Engine

// WASMRunner is a dedicated, unshared WASM execution environment bound to a single worker.
type WASMRunner = wasmhost.WASMRunner

// NewWASMHost compiles the guest bytecode and initializes a pool of instantiated WASM modules.
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	return wasmhost.NewWASMHost(ctx, wasmBytes, poolSize)
}

// NewEngine compiles the guest bytecode and initializes a pool of instantiated WASM modules.
func NewEngine(ctx context.Context, wasmBytes []byte, poolSize int) (*Engine, error) {
	return wasmhost.NewEngine(ctx, wasmBytes, poolSize)
}
