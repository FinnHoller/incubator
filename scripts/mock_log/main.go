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
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: go run mock_log.go <dir> [origin]\n")
		os.Exit(1)
	}

	dir := os.Args[1]
	origin := "mock.log.local"
	if len(os.Args) > 2 && os.Args[2] != "" {
		origin = os.Args[2]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GenerateKey failed: %v\n", err)
		os.Exit(1)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewSigner failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "MkdirAll failed: %v\n", err)
		os.Exit(1)
	}

	driver, err := posix.New(ctx, posix.Config{Path: dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "posix.New failed: %v\n", err)
		os.Exit(1)
	}

	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewAppender failed: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = shutdown(context.Background()) }()

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 10*time.Millisecond)

	entries := []string{
		"apple",
		"banana",
		"cherry",
		"apple",
	}

	for _, e := range entries {
		_, _, err := awaiter.Await(ctx, appender.Add(ctx, tessera.NewEntry([]byte(e))))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Await(Add) failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Write keys to files for convenience
	_ = os.WriteFile(filepath.Join(dir, "signer.key"), []byte(skey), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "verifier.vkey"), []byte(vkey), 0o644)

	fmt.Printf("INPUT_LOG_ORIGIN=%s\n", origin)
	fmt.Printf("INPUT_LOG_PUBKEY=%s\n", vkey)
	fmt.Printf("INPUT_LOG_DIR=%s\n", dir)
	fmt.Printf("ENTRIES_COUNT=%d\n", len(entries))
}
