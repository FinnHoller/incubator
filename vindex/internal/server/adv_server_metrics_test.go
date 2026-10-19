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
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/transparency-dev/incubator/vindex/internal/metrics"
)

// TestReadServer_AuditorMetrics_PrometheusTextFormat verifies that the auditor
// Prometheus metrics are correctly emitted in standard Prometheus text format via GET /metrics.
func TestReadServer_AuditorMetrics_PrometheusTextFormat(t *testing.T) {
	mux := http.NewServeMux()
	srv := NewReadServer(nil, nil, nil, 64)
	srv.RegisterAdminRoutes(mux)

	// Subtest 1: Check initial presence and Prometheus text format annotations
	t.Run("prometheus_text_format_headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("/metrics status = %d, want 200", w.Code)
		}
		body := w.Body.String()

		expectedSubstrings := []string{
			"# HELP vindex_auditor_root_mismatches_total ",
			"# TYPE vindex_auditor_root_mismatches_total counter",
			"# HELP vindex_auditor_root_mismatch ",
			"# TYPE vindex_auditor_root_mismatch gauge",
		}

		for _, sub := range expectedSubstrings {
			if !strings.Contains(body, sub) {
				t.Errorf("/metrics missing expected prometheus text format line: %q", sub)
			}
		}
	})

	// Subtest 2: Mutation and Dynamic Scraping
	t.Run("mutation_and_scraping", func(t *testing.T) {
		// Reset gauge to 0 initially
		metrics.ResetAuditorRootMismatch()

		// Scrape baseline
		req1 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w1 := httptest.NewRecorder()
		mux.ServeHTTP(w1, req1)
		body1 := w1.Body.String()

		totalBefore := extractMetricValue(t, body1, "vindex_auditor_root_mismatches_total")
		gaugeBefore := extractMetricValue(t, body1, "vindex_auditor_root_mismatch")

		if gaugeBefore != 0 {
			t.Fatalf("vindex_auditor_root_mismatch before Record = %f, want 0", gaugeBefore)
		}

		// Trigger mismatch event
		metrics.RecordAuditorRootMismatch()

		// Scrape after record
		req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w2 := httptest.NewRecorder()
		mux.ServeHTTP(w2, req2)
		body2 := w2.Body.String()

		totalAfter := extractMetricValue(t, body2, "vindex_auditor_root_mismatches_total")
		gaugeAfter := extractMetricValue(t, body2, "vindex_auditor_root_mismatch")

		if totalAfter != totalBefore+1 {
			t.Fatalf("vindex_auditor_root_mismatches_total after Record = %f, want %f", totalAfter, totalBefore+1)
		}
		if gaugeAfter != 1 {
			t.Fatalf("vindex_auditor_root_mismatch after Record = %f, want 1", gaugeAfter)
		}

		// Reset gauge
		metrics.ResetAuditorRootMismatch()

		// Scrape after reset
		req3 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w3 := httptest.NewRecorder()
		mux.ServeHTTP(w3, req3)
		body3 := w3.Body.String()

		gaugeReset := extractMetricValue(t, body3, "vindex_auditor_root_mismatch")
		if gaugeReset != 0 {
			t.Fatalf("vindex_auditor_root_mismatch after Reset = %f, want 0", gaugeReset)
		}

		// Explicit gauge value toggle test
		metrics.SetAuditorRootMismatch(1)
		w4 := httptest.NewRecorder()
		mux.ServeHTTP(w4, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if v := extractMetricValue(t, w4.Body.String(), "vindex_auditor_root_mismatch"); v != 1 {
			t.Fatalf("vindex_auditor_root_mismatch after Set(1) = %f, want 1", v)
		}

		metrics.SetAuditorRootMismatch(0)
		w5 := httptest.NewRecorder()
		mux.ServeHTTP(w5, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if v := extractMetricValue(t, w5.Body.String(), "vindex_auditor_root_mismatch"); v != 0 {
			t.Fatalf("vindex_auditor_root_mismatch after Set(0) = %f, want 0", v)
		}
	})
}

func extractMetricValue(t *testing.T, body, metricName string) float64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metricName) + `(?:\s+([0-9.eE+-]+)|\{[^}]*\}\s+([0-9.eE+-]+))`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		t.Fatalf("could not find metric %q in body:\n%s", metricName, body)
	}
	valStr := matches[1]
	if valStr == "" && len(matches) > 2 {
		valStr = matches[2]
	}
	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		t.Fatalf("failed to parse metric %q value %q: %v", metricName, valStr, err)
	}
	return val
}
