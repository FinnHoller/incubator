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

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReadServer_HealthCheck_StateTransitions tests fine-grained state transitions
// across nil, healthy, multiple distinct errors, and back to nil.
func TestReadServer_HealthCheck_StateTransitions(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)

	assertStatus := func(expectedCode int, expectedBodySubstring string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()
		srv.HandleHealthz(w, req)
		if w.Code != expectedCode {
			t.Fatalf("HandleHealthz status = %d, want %d", w.Code, expectedCode)
		}
		if !strings.Contains(w.Body.String(), expectedBodySubstring) {
			t.Fatalf("HandleHealthz body = %q, want substring %q", w.Body.String(), expectedBodySubstring)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("Content-Type = %q, want text/plain", ct)
		}
	}

	// 1. Initial state (nil) -> 200 "ok\n"
	assertStatus(http.StatusOK, "ok\n")

	// 2. Healthy callback -> 200 "ok\n"
	srv.SetHealthChecker(func() error { return nil })
	assertStatus(http.StatusOK, "ok\n")

	// 3. Unhealthy callback 1 -> 503 "database closed"
	srv.SetHealthChecker(func() error { return errors.New("database closed") })
	assertStatus(http.StatusServiceUnavailable, "unhealthy: database closed")

	// 4. Unhealthy callback 2 (mismatch error) -> 503 "root mismatch"
	srv.SetHealthChecker(func() error { return errors.New("root mismatch at leaf 999") })
	assertStatus(http.StatusServiceUnavailable, "unhealthy: root mismatch at leaf 999")

	// 5. Recovery -> 200 "ok\n"
	srv.SetHealthChecker(func() error { return nil })
	assertStatus(http.StatusOK, "ok\n")

	// 6. Reset to nil -> 200 "ok\n"
	srv.SetHealthChecker(nil)
	assertStatus(http.StatusOK, "ok\n")
}

// TestReadServer_HealthCheck_HighConcurrencyStress executes 100 concurrent HTTP readers
// alongside 10 concurrent health-state mutators under -race for 2.5 seconds.
func TestReadServer_HealthCheck_HighConcurrencyStress(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	var (
		totalReads   atomic.Uint64
		totalWrites  atomic.Uint64
		healthyReads atomic.Uint64
		errorReads   atomic.Uint64
	)

	var wg sync.WaitGroup

	// 10 concurrent mutators rapidly setting health check states
	for m := 0; m < 10; m++ {
		wg.Add(1)
		go func(mutatorID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					switch i % 3 {
					case 0:
						srv.SetHealthChecker(nil)
					case 1:
						srv.SetHealthChecker(func() error { return nil })
					case 2:
						errMsg := fmt.Sprintf("fault-%d-%d", mutatorID, i)
						srv.SetHealthChecker(func() error { return errors.New(errMsg) })
					}
					totalWrites.Add(1)
					i++
					// Micro-yield to allow readers to interleave
					if i%10 == 0 {
						time.Sleep(50 * time.Microsecond)
					}
				}
			}
		}(m)
	}

	// 100 concurrent reader goroutines issuing /healthz requests
	for r := 0; r < 100; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
					w := httptest.NewRecorder()
					srv.HandleHealthz(w, req)

					totalReads.Add(1)
					switch w.Code {
					case http.StatusOK:
						healthyReads.Add(1)
						if body := w.Body.String(); body != "ok\n" {
							t.Errorf("expected body 'ok\\n' for status 200, got %q", body)
						}
					case http.StatusServiceUnavailable:
						errorReads.Add(1)
						if body := w.Body.String(); !strings.HasPrefix(body, "unhealthy:") {
							t.Errorf("expected body prefix 'unhealthy:' for status 503, got %q", body)
						}
					default:
						t.Errorf("unexpected HTTP status code %d", w.Code)
					}
				}
			}
		}()
	}

	wg.Wait()

	t.Logf("Concurrency stress completed: %d total reads (%d ok, %d unhealthy), %d total writes",
		totalReads.Load(), healthyReads.Load(), errorReads.Load(), totalWrites.Load())

	if totalReads.Load() < 1000 {
		t.Fatalf("Insufficient throughput during concurrency stress: %d reads", totalReads.Load())
	}
	if totalWrites.Load() < 500 {
		t.Fatalf("Insufficient writes during concurrency stress: %d writes", totalWrites.Load())
	}
}

// TestReadServer_HealthCheck_SelfUnregisteringCallback tests that a HealthChecker
// callback can safely call srv.SetHealthChecker from within itself without deadlocking.
func TestReadServer_HealthCheck_SelfUnregisteringCallback(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Self-unregistering callback
		srv.SetHealthChecker(func() error {
			srv.SetHealthChecker(nil)
			return errors.New("self-resetting error")
		})

		// First call invokes callback, which self-unregisters to nil
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w1 := httptest.NewRecorder()
		srv.HandleHealthz(w1, req)
		if w1.Code != http.StatusServiceUnavailable {
			t.Errorf("call 1: got code %d, want 503", w1.Code)
		}

		// Second call should now observe nil healthChecker -> 200 OK
		w2 := httptest.NewRecorder()
		srv.HandleHealthz(w2, req)
		if w2.Code != http.StatusOK {
			t.Errorf("call 2: got code %d, want 200", w2.Code)
		}
		if got := w2.Body.String(); got != "ok\n" {
			t.Errorf("call 2: body = %q, want 'ok\\n'", got)
		}
	}()

	select {
	case <-done:
		// Succeeded without deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK detected: HealthChecker calling SetHealthChecker deadlocked")
	}
}

// TestReadServer_HealthCheck_PanickingCallback tests that if a HealthChecker panics,
// the server's internal mutex is not left held or permanently corrupted.
func TestReadServer_HealthCheck_PanickingCallback(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)

	srv.SetHealthChecker(func() error {
		panic("simulated panic inside health checker")
	})

	// Invoke HandleHealthz and recover panic
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	func() {
		defer func() {
			_ = recover()
		}()
		w := httptest.NewRecorder()
		srv.HandleHealthz(w, req)
	}()

	// Verify server can still update healthChecker and serve requests without hanging
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.SetHealthChecker(func() error { return nil })
		w2 := httptest.NewRecorder()
		srv.HandleHealthz(w2, req)
		if w2.Code != http.StatusOK {
			t.Errorf("subsequent call: code = %d, want 200", w2.Code)
		}
	}()

	select {
	case <-done:
		// Lock was released cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK: healthMu was left locked after HealthChecker panic")
	}
}
