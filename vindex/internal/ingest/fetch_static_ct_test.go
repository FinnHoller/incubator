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
	"net/url"
	"os"
	"testing"
	"time"
)

func TestStaticCTLiveFetch(t *testing.T) {
	u, err := url.Parse("https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}

	tf, err := NewTiledFetcher(u, nil, "parcelyard2027h1.prod.certificate.transparency.goog", nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}
	tf.SetAllowUnverifiedCheckpoints(true)
	if !tf.IsStaticCT() {
		t.Fatalf("expected IsStaticCT() = true for ParcelYard")
	}

	if testing.Short() || os.Getenv("VINDEX_LIVE_TESTS") == "" {
		t.Skip("skipping live external Static-CT network fetch; set VINDEX_LIVE_TESTS=1 to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cp, err := tf.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	if cp.Size == 0 {
		t.Fatalf("expected non-zero tree size, got %d", cp.Size)
	}
	t.Logf("Fetched checkpoint: size = %d", cp.Size)

	// Fetch bundle 0 (leaves 0..255)
	bundles, err := tf.FetchTiles(ctx, 0, 256)
	if err != nil {
		t.Fatalf("FetchTiles failed: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(bundles))
	}
	if len(bundles[0].Leaves) != 256 {
		t.Fatalf("expected 256 leaves in bundle 0, got %d", len(bundles[0].Leaves))
	}

	// Fetch single leaf via Leaf()
	leaf0, err := tf.Leaf(ctx, 0)
	if err != nil {
		t.Fatalf("Leaf(0) failed: %v", err)
	}
	if len(leaf0) == 0 {
		t.Fatalf("Leaf(0) returned empty bytes")
	}
	t.Logf("Leaf(0) len = %d bytes", len(leaf0))
}
