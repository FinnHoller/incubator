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

package sumdb_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/incubator/vindex/dashboards"
)

func TestCheckedInDashboardMatchesGenerator(t *testing.T) {
	opts := dashboards.SumDBOverviewOptions()
	generated, err := dashboards.RenderJSON(opts)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	checkedInPath := filepath.Join("grafana", "dashboards", "sumdb_overview.json")
	checkedIn, err := os.ReadFile(checkedInPath)
	if err != nil {
		t.Fatalf("failed to read checked-in dashboard: %v", err)
	}

	if !bytes.Equal(generated, checkedIn) {
		t.Errorf("checked-in dashboard %s differs from generated:\n%s", checkedInPath, cmp.Diff(string(checkedIn), string(generated)))
	}
}
