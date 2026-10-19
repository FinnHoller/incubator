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

package dashboards

import (
	"encoding/json"
	"testing"

	"github.com/grafana/grafana-foundation-sdk/go/dashboard"
)

func TestNewVIndexOverview(t *testing.T) {
	opts := Options{
		Title: "Test Dashboard",
		UID:   "test-dash",
		Tags:  []string{"test"},
	}
	data, err := RenderJSON(opts)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var d dashboard.Dashboard //nolint:staticcheck
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("Unmarshal generated JSON failed: %v", err)
	}

	if d.Title == nil || *d.Title != "Test Dashboard" {
		t.Errorf("expected title 'Test Dashboard', got %v", d.Title)
	}
	if d.Uid == nil || *d.Uid != "test-dash" {
		t.Errorf("expected uid 'test-dash', got %v", d.Uid)
	}
	if len(d.Panels) != 25 {
		t.Errorf("expected 25 panels/rows, got %d", len(d.Panels))
	}
}

func TestSumDBOverviewOptions(t *testing.T) {
	opts := SumDBOverviewOptions()
	data, err := RenderJSON(opts)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var d dashboard.Dashboard //nolint:staticcheck
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("Unmarshal generated JSON failed: %v", err)
	}

	if d.Title == nil || *d.Title != "VIndex - SumDB Personality Overview" {
		t.Errorf("expected title 'VIndex - SumDB Personality Overview', got %v", d.Title)
	}
	if d.Uid == nil || *d.Uid != "vindex-sumdb-overview" {
		t.Errorf("expected uid 'vindex-sumdb-overview', got %v", d.Uid)
	}
	if len(d.Panels) != 25 {
		t.Errorf("expected 25 panels/rows, got %d", len(d.Panels))
	}
}
