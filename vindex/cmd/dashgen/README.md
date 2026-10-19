# VIndex Grafana Dashboard Generator (`dashgen`)

`dashgen` is a CLI tool that compiles Grafana dashboards from the typed Go Foundation SDK (`vindex/dashboards`) into standardized JSON schemas (version 42) for Grafana file provisioning and Docker Compose/Kubernetes deployments.

## Usage

Generate the Go Checksum DB (SumDB) personality dashboard:
```bash
go run ./vindex/cmd/dashgen -personality sumdb -out deploy/sumdb/grafana/dashboards/sumdb_overview.json
```

Generate the generic VIndex system overview dashboard:
```bash
go run ./vindex/cmd/dashgen -personality generic -out vindex_overview.json
```

Output directly to stdout:
```bash
go run ./vindex/cmd/dashgen -personality sumdb
```

---

## Dashboard Architecture

The generated dashboard organizes VIndex observability into 5 functional sections (Grafana Rows) on a single timeline to enable root-cause bottleneck isolation:

### Row 1: Pipeline Overview & Checkpoint Ratchets
Provides an instant bird's-eye view of pipeline health and identifies which stage is lagging:
- **Stat Panels (4 Ratchet Points)**:
  - `Input Log Tip Size`: Discovered upstream Input Log checkpoint size (`vindex_input_tree_size`).
  - `KV Committed Size`: Highest leaf index committed to the Pebble KV store (`vindex_kv_committed_size`).
  - `Output Tree Size`: Output Log committed size (`vindex_output_tree_size`).
  - `Serving Tree Size`: Covered log size exposed to client lookup queries (`vindex_serving_tree_size`).
- **Checkpoint Progression Graph**: Plots all 4 ratchet sizes on one graph. Flatlines or diverging slopes instantly localize where the pipeline has stopped.
- **Pipeline Inter-Stage Lags**:
  - `Catch-up Lag` (`Input - KV`): Measures ingestion and mapping backlog.
  - `Indexing Lag` (`KV - Output`): Measures MPT calculation and output log batching delay.
  - `Witness Lag` (`Output - Serving`): Measures delay in collecting remote witness co-signatures.

### Row 2: Stage 1: Ingestion & WASM Mapping
- **Throughput by Stage**: Rates for leaves downloaded, leaves mapped, and leaves indexed per second.
- **WASM Map Duration**: p50, p90, and p99 execution duration per 256-leaf bundle (`vindex_map_duration_seconds`).
- **Ingestion Errors & Retries**: Upstream fetch failures (`vindex_input_fetch_errors_total`) and MapFn execution failures labeled by policy (`vindex_map_errors_total`).
- **Tile Cache Disk Usage**: Total bytes stored in managed local tile cache (`vindex_tile_cache_bytes`).
- **Search Keys Mapped Rate**: Key emission rate (`vindex_keys_mapped_total`), measuring fanout expansion ratio into the inverted index.
- **Process Memory (RSS)**: Resident memory tracking (`process_resident_memory_bytes`).

### Row 3: Stage 2: Storage & Pebble Commit
- **Pebble Batch Apply Duration**: p50, p90, and p99 latency committing atomic inverted chunk batches to NVMe (`vindex_pebble_apply_duration_seconds`).
- **Process CPU & Goroutines**: CPU core utilization (`process_cpu_seconds_total`) and active goroutine counts (`go_goroutines`).

### Row 4: Stage 3: Output Log, MPT & Witnessing
- **Witness Signatures**: Number of valid witness signatures attached to the current active checkpoint (`vindex_witness_signatures_count`).
- **Witness Latency & Signing Errors**: Round-trip co-signing latency (`vindex_witness_wait_seconds`) and failure rate (`vindex_witness_errors_total`).
- **MPT Mutation Duration & Lock Wait**: Time spent acquiring the tree lock (`vindex_mpt_lock_wait_seconds`) and critical section write duration (`vindex_mpt_write_duration_seconds`).

### Row 5: Query Serving & Lookup API
- **Lookup Request Rate (QPS)**: Incoming query traffic rate (`vindex_lookup_latency_seconds_count`).
- **Lookup Response Latency**: End-user query latency percentiles: p50, p95, p99 (`vindex_lookup_latency_seconds`).
- **Matched Leaves Distribution**: Percentiles of leaf pointers returned per query (`vindex_lookup_results_returned`).

---

## Future Metrics Roadmap

To achieve complete end-to-end visibility, the following metrics should be instrumented in `vindex/internal/metrics`:

### High Priority (Bottleneck & Failure Detection)
1. **`vindex_lookup_requests_total{code}`** (CounterVec):
   - Currently, `LookupLatencySeconds` only counts total requests. HTTP status codes (`200`, `400`, `500`, `503`) are missing, hiding server-side errors and client malformed request spikes.
2. **`vindex_witness_required_count`** (Gauge):
   - Tracks the configured witness quorum threshold (e.g. `N=2`). Enables Grafana alerting when `witness_signatures_count < witness_required_count`.
3. **`vindex_input_checkpoint_timestamp_seconds`** (Gauge):
   - Records the timestamp of the discovered upstream checkpoint. Enables time-based lag alerting (`time() - vindex_input_checkpoint_timestamp_seconds`) to detect upstream log stalls even when tree size remains unchanged.
4. **`vindex_pebble_compaction_debt_bytes`** (Gauge):
   - Extracted from Pebble's `db.Metrics().Compact.EstimatedCompactionDebt`. Compaction debt is the primary indicator of write stalls and NVMe saturation in LSM storage engines.

### Medium Priority (Subsystem Profiling)
1. **`vindex_tile_cache_hits_total` / `misses_total`** (Counter):
   - Measures cache hit ratio when fetching tiles, ensuring daemon restarts don't re-download duplicate data.
2. **`vindex_pebble_block_cache_hit_ratio`** (Gauge / Counters):
   - Tracks Pebble block cache hits vs misses (`BlockCache.Hits` / `Misses`) to diagnose lookup latency spikes caused by disk reads.
3. **`vindex_mpt_nodes_total`** (Gauge):
   - Total number of allocated nodes in the Merkle Patricia Trie, helping track trie memory growth over time.

---

## Future Planned Dashboards

1. **Storage & Engine Deep Dive (`vindex_storage_deepdive`)**:
   - Focused on storage internals: Pebble level-by-level SST sizes, memtable flush rates, WAL sync duration, and MPT mmap memory usage.
2. **Multi-Personality Cluster View (`vindex_cluster_overview`)**:
   - Fleet overview aggregating multiple personalities (SumDB, MTC, CT) running across instances, with cross-personality comparison of lag and throughput.
3. **SLO & Reliability Dashboard (`vindex_slo`)**:
   - Focused on service-level objectives: Query latency budget burn rates, lookup availability (99.9%), and witness quorum continuity.
