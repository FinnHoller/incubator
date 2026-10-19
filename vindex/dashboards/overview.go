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

// Package dashboards provides programmatic Grafana dashboard builders for VIndex components.
package dashboards

import (
	"encoding/json"
	"fmt"

	"github.com/grafana/grafana-foundation-sdk/go/cog"
	"github.com/grafana/grafana-foundation-sdk/go/common"
	"github.com/grafana/grafana-foundation-sdk/go/dashboard" //nolint:staticcheck // dashboardv1 is the standard Grafana dashboard schema for file provisioning
	"github.com/grafana/grafana-foundation-sdk/go/prometheus"
	"github.com/grafana/grafana-foundation-sdk/go/stat"
	"github.com/grafana/grafana-foundation-sdk/go/timeseries"
)

// Options configures the generated VIndex overview dashboard.
type Options struct {
	Title       string
	UID         string
	Tags        []string
	Datasource  string // Prometheus datasource UID (default: "prometheus")
	Refresh     string // Refresh interval (default: "5s")
	ExtraPanels []cog.Builder[dashboard.Panel]
}

// SumDBOverviewOptions returns default configuration for the Go Checksum DB personality.
func SumDBOverviewOptions() Options {
	return Options{
		Title:      "VIndex - SumDB Personality Overview",
		UID:        "vindex-sumdb-overview",
		Tags:       []string{"vindex", "sumdb"},
		Datasource: "prometheus",
		Refresh:    "5s",
	}
}

// NewVIndexOverview constructs a Grafana DashboardBuilder containing the complete
// VIndex operational sections: Overview Ratchets, Ingestion & MapFn, Storage & Pebble,
// Output & Witnessing, and Query Serving.
//
//nolint:staticcheck // dashboardv1 is standard schema for file provisioning
func NewVIndexOverview(opts Options) (*dashboard.DashboardBuilder, error) {
	if opts.Title == "" {
		opts.Title = "VIndex - System Overview"
	}
	if opts.UID == "" {
		opts.UID = "vindex-overview"
	}
	if opts.Datasource == "" {
		opts.Datasource = "prometheus"
	}
	if opts.Refresh == "" {
		opts.Refresh = "5s"
	}

	dsRef := common.DataSourceRef{
		Type: cog.ToPtr("prometheus"),
		Uid:  cog.ToPtr(opts.Datasource),
	}

	b := dashboard.NewDashboardBuilder(opts.Title). //nolint:staticcheck
							Uid(opts.UID).
							Tags(opts.Tags).
							Editable().
							LiveNow(true).
							Refresh(opts.Refresh).
							Time("now-15m", "now").
							Timezone("browser").
							Tooltip(dashboard.DashboardCursorSyncCrosshair).
							FiscalYearStartMonth(0)

	// =========================================================================
	// ROW 1: Pipeline Overview & Checkpoint Ratchets
	// =========================================================================
	b.WithRow(
		dashboard.NewRowBuilder("Pipeline Overview & Checkpoint Ratchets").
			Id(100).
			GridPos(dashboard.GridPos{H: 1, W: 24, X: 0, Y: 0}),
	)

	// Stat cards: The 4 checkpoint sizes ratcheted at critical stages
	b.WithPanel(
		stat.NewPanelBuilder().
			Id(1).
			Title("Input Log Tip Size").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 4, W: 6, X: 0, Y: 1}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_input_tree_size").
					RefId("A"),
			),
	)

	b.WithPanel(
		stat.NewPanelBuilder().
			Id(2).
			Title("KV Committed Size").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 4, W: 6, X: 6, Y: 1}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_kv_committed_size").
					RefId("A"),
			),
	)

	b.WithPanel(
		stat.NewPanelBuilder().
			Id(3).
			Title("Output Tree Size").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 4, W: 6, X: 12, Y: 1}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_output_tree_size").
					RefId("A"),
			),
	)

	b.WithPanel(
		stat.NewPanelBuilder().
			Id(4).
			Title("Serving Tree Size").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 4, W: 6, X: 18, Y: 1}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_serving_tree_size").
					RefId("A"),
			),
	)

	// Progression graph showing all 4 ratchets together to immediately spot stalls
	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(5).
			Title("Checkpoint Progression (All Ratchets)").
			Datasource(dsRef).
			DrawStyle(common.GraphDrawStyleLine).
			LineInterpolation(common.LineInterpolationLinear).
			LineWidth(2).
			ShowPoints(common.VisibilityModeNever).
			Unit("short").
			GridPos(dashboard.GridPos{H: 8, W: 12, X: 0, Y: 5}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_input_tree_size").
					LegendFormat("1. Input Log Tip").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_kv_committed_size").
					LegendFormat("2. KV Committed (m_kv_size)").
					RefId("B"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_output_tree_size").
					LegendFormat("3. Output Log Committed").
					RefId("C"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_serving_tree_size").
					LegendFormat("4. Serving Output Tree").
					RefId("D"),
			),
	)

	// Inter-stage lags identifying the bottleneck boundary
	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(6).
			Title("Pipeline Inter-stage Lags (Leaves)").
			Datasource(dsRef).
			DrawStyle(common.GraphDrawStyleLine).
			LineInterpolation(common.LineInterpolationLinear).
			LineWidth(2).
			ShowPoints(common.VisibilityModeNever).
			Unit("short").
			GridPos(dashboard.GridPos{H: 8, W: 12, X: 12, Y: 5}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_input_tree_size - vindex_kv_committed_size").
					LegendFormat("Catch-up Lag (Input - KV)").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_kv_committed_size - vindex_output_tree_size").
					LegendFormat("Indexing Lag (KV - Output)").
					RefId("B"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_output_tree_size - vindex_serving_tree_size").
					LegendFormat("Witness Lag (Output - Serving)").
					RefId("C"),
			),
	)

	// =========================================================================
	// ROW 2: Stage 1: Ingestion & WASM Mapping
	// =========================================================================
	b.WithRow(
		dashboard.NewRowBuilder("Stage 1: Ingestion & WASM Mapping").
			Id(200).
			GridPos(dashboard.GridPos{H: 1, W: 24, X: 0, Y: 13}),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(7).
			Title("Throughput by Stage (leaves/sec)").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 8, X: 0, Y: 14}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(vindex_leaves_downloaded_total[1m])").
					LegendFormat("Downloaded (leaves/s)").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(vindex_leaves_mapped_total[1m])").
					LegendFormat("Mapped (leaves/s)").
					RefId("B"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(vindex_leaves_indexed_total[1m])").
					LegendFormat("Indexed (leaves/s)").
					RefId("C"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(8).
			Title("WASM Map Duration (per 256-leaf Bundle)").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 8, X: 8, Y: 14}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.99, sum(rate(vindex_map_duration_seconds_bucket[1m])) by (le))").
					LegendFormat("MapFn p99 (s)").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.90, sum(rate(vindex_map_duration_seconds_bucket[1m])) by (le))").
					LegendFormat("MapFn p90 (s)").
					RefId("B"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.50, sum(rate(vindex_map_duration_seconds_bucket[1m])) by (le))").
					LegendFormat("MapFn p50 (s)").
					RefId("C"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(9).
			Title("Ingestion Fetch & Map Errors (/sec)").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 8, X: 16, Y: 14}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(vindex_input_fetch_errors_total[1m])").
					LegendFormat("Input Fetch Errors /s").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("sum by (policy) (rate(vindex_map_errors_total[1m]))").
					LegendFormat("Map Errors (policy={{policy}}) /s").
					RefId("B"),
			),
	)

	b.WithPanel(
		stat.NewPanelBuilder().
			Id(10).
			Title("Tile Cache Disk Usage").
			Datasource(dsRef).
			Unit("bytes").
			GridPos(dashboard.GridPos{H: 4, W: 8, X: 0, Y: 22}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_tile_cache_bytes").
					RefId("A"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(11).
			Title("WASM Keys Mapped Rate (/sec)").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 4, W: 8, X: 8, Y: 22}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(vindex_keys_mapped_total[1m])").
					LegendFormat("Search Keys Emitted /s").
					RefId("A"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(12).
			Title("Process Memory (RSS)").
			Datasource(dsRef).
			Unit("bytes").
			GridPos(dashboard.GridPos{H: 4, W: 8, X: 16, Y: 22}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("process_resident_memory_bytes").
					LegendFormat("Resident Memory (RSS)").
					RefId("A"),
			),
	)

	// =========================================================================
	// ROW 3: Stage 2: Storage & Pebble Commit
	// =========================================================================
	b.WithRow(
		dashboard.NewRowBuilder("Stage 2: Storage & Pebble Commit").
			Id(300).
			GridPos(dashboard.GridPos{H: 1, W: 24, X: 0, Y: 26}),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(13).
			Title("Pebble Batch Apply Duration").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 12, X: 0, Y: 27}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.99, sum(rate(vindex_pebble_apply_duration_seconds_bucket[1m])) by (le))").
					LegendFormat("Pebble Apply p99 (s)").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.90, sum(rate(vindex_pebble_apply_duration_seconds_bucket[1m])) by (le))").
					LegendFormat("Pebble Apply p90 (s)").
					RefId("B"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.50, sum(rate(vindex_pebble_apply_duration_seconds_bucket[1m])) by (le))").
					LegendFormat("Pebble Apply p50 (s)").
					RefId("C"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(14).
			Title("Process CPU & Goroutines").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 12, X: 12, Y: 27}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(process_cpu_seconds_total[1m])").
					LegendFormat("CPU Cores Used").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("go_goroutines").
					LegendFormat("Active Goroutines").
					RefId("B"),
			),
	)

	// =========================================================================
	// ROW 4: Stage 3: Output Log, MPT & Witnessing
	// =========================================================================
	b.WithRow(
		dashboard.NewRowBuilder("Stage 3: Output Log, MPT & Witnessing").
			Id(400).
			GridPos(dashboard.GridPos{H: 1, W: 24, X: 0, Y: 35}),
	)

	b.WithPanel(
		stat.NewPanelBuilder().
			Id(15).
			Title("Witness Signatures").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 4, X: 0, Y: 36}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("vindex_witness_signatures_count").
					RefId("A"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(16).
			Title("Witness Latency & Signing Errors").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 10, X: 4, Y: 36}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.99, sum(rate(vindex_witness_wait_seconds_bucket[1m])) by (le))").
					LegendFormat("Witness Wait p99 (s)").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.50, sum(rate(vindex_witness_wait_seconds_bucket[1m])) by (le))").
					LegendFormat("Witness Wait p50 (s)").
					RefId("B"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(vindex_witness_errors_total[1m])").
					LegendFormat("Witness Errors /s").
					RefId("C"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(17).
			Title("MPT Mutation Duration & Lock Wait").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 10, X: 14, Y: 36}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.99, sum(rate(vindex_mpt_write_duration_seconds_bucket[1m])) by (le))").
					LegendFormat("MPT Write p99 (s)").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.99, sum(rate(vindex_mpt_lock_wait_seconds_bucket[1m])) by (le))").
					LegendFormat("MPT Lock Wait p99 (s)").
					RefId("B"),
			),
	)

	// =========================================================================
	// ROW 5: Query Serving & Lookup API
	// =========================================================================
	b.WithRow(
		dashboard.NewRowBuilder("Query Serving & Lookup API").
			Id(500).
			GridPos(dashboard.GridPos{H: 1, W: 24, X: 0, Y: 44}),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(18).
			Title("Lookup Request Rate (QPS)").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 8, X: 0, Y: 45}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("rate(vindex_lookup_latency_seconds_count[1m])").
					LegendFormat("Lookup QPS").
					RefId("A"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(19).
			Title("Lookup Response Latency").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 8, X: 8, Y: 45}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.99, sum(rate(vindex_lookup_latency_seconds_bucket[1m])) by (le))").
					LegendFormat("p99 (s)").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.95, sum(rate(vindex_lookup_latency_seconds_bucket[1m])) by (le))").
					LegendFormat("p95 (s)").
					RefId("B"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.50, sum(rate(vindex_lookup_latency_seconds_bucket[1m])) by (le))").
					LegendFormat("p50 (s)").
					RefId("C"),
			),
	)

	b.WithPanel(
		timeseries.NewPanelBuilder().
			Id(20).
			Title("Matched Leaves Distribution (Per Query)").
			Datasource(dsRef).
			GridPos(dashboard.GridPos{H: 8, W: 8, X: 16, Y: 45}).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.99, sum(rate(vindex_lookup_results_returned_bucket[1m])) by (le))").
					LegendFormat("Matched Leaves p99").
					RefId("A"),
			).
			WithTarget(
				prometheus.NewDataqueryBuilder().
					Expr("histogram_quantile(0.50, sum(rate(vindex_lookup_results_returned_bucket[1m])) by (le))").
					LegendFormat("Matched Leaves p50").
					RefId("B"),
			),
	)

	// Append any personality-specific panels
	for _, p := range opts.ExtraPanels {
		b.WithPanel(p)
	}

	return b, nil
}

// RenderJSON builds the dashboard and marshals it into indented JSON.
func RenderJSON(opts Options) ([]byte, error) {
	b, err := NewVIndexOverview(opts)
	if err != nil {
		return nil, err
	}
	d, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("building dashboard: %w", err)
	}
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling dashboard JSON: %w", err)
	}
	return append(out, '\n'), nil
}
