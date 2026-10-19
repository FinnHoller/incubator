# VIndex v1 Quickstart & Developer Guide

This guide walks you through running a Verifiable Index, querying it with full cryptographic proofs, authoring a custom WebAssembly mapping function, and indexing your own transparency log.

---

## Tooling & Prerequisites

Before starting, ensure you have the following installed:

* **[Go](https://go.dev/dl/)** (>= 1.22 required; 1.24+ recommended for `wasip1` builds)
* **[just](https://github.com/casey/just#installation)** (Command runner for repository automation)
* **[Docker](https://docs.docker.com/get-docker/)** (Optional; required for multi-container SumDB stack)

Verify your environment:
```bash
go version
just --version
docker --version # optional
```

---

## 1. 30-Second Local Demo

To see VIndex in action with zero manual configuration:

```bash
just demo-local
```

What this does automatically:
1. Compiles the [`starter`](./mapfn/examples/starter) WASM mapping function targeting `wasip1/wasm`.
2. Creates an ephemeral local [Tessera](https://github.com/transparency-dev/tessera) input log with sample leaves (`apple`, `banana`, `cherry`, `apple`).
3. Generates cryptographic Ed25519 Note keys.
4. Starts `vindexd` to ingest, extract keys in WASM, update the Sparse Merkle Patricia Trie, and commit checkpoints.
5. Runs `vindex-client` queries verifying multi-index occurrences (`apple` -> indices `[0, 3]`) and cryptographically proving non-inclusion (`nonexistent`).
6. Shuts down cleanly with zero orphaned processes or leftover temp files.

---

## 2. Building Core Binaries

To build all VIndex command-line tools into `bin/`:

```bash
just build
```

Or manually with standard `go build`:
```bash
mkdir -p bin
go build -o bin/vindexd ./vindex/cmd/vindexd
go build -o bin/vindex-client ./vindex/cmd/vindex-client
go build -o bin/vindex-wasm ./vindex/cmd/vindex-wasm
go build -o bin/vindex-auditor ./vindex/cmd/vindex-auditor
go build -o bin/clonelog ./vindex/cmd/clonelog
```

| Binary | Purpose |
| :--- | :--- |
| `bin/vindexd` | VIndex indexing and serving daemon (with built-in auditor and oneshot modes) |
| `bin/vindex-client` | End-user CLI for cryptographically verified key lookups |
| `bin/vindex-wasm` | Tooling for inspecting, testing, and benchmarking WASM mapping plugins |
| `bin/vindex-auditor` | Independent full-log auditor |
| `bin/clonelog` | High-speed local log cloning utility |

---

## 3. Authoring a Custom WASM MapFn

VIndex parses log leaves inside an isolated, sandboxed WebAssembly runtime. Mapping functions are written using the high-performance [`vindex/mapfn/sdk`](./mapfn/sdk).

### The MapFn Contract

A minimal mapping plugin needs only one file (`main.go`):

```go
package main

import (
	"bytes"
	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
)

func main() {}

func init() {
	// Register zero-allocation streaming callback
	sdk.RegisterEmit(MapLeaf)
}

// MapLeaf inspects each raw log leaf and emits zero or more search key preimages.
func MapLeaf(leaf []byte, emit func(key []byte)) {
	leaf = bytes.TrimSpace(leaf)
	if len(leaf) == 0 {
		return
	}
	// Example: emit the leaf payload itself as the search key.
	// For structured data, parse JSON/proto/text and emit identifiers (e.g. domain, package name).
	emit(leaf)
}
```

### Compiling Your Plugin

Compile to `wasip1` WebAssembly:

```bash
just build-wasm vindex/mapfn/examples/starter bin/starter.wasm
```

Or manually:
```bash
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -buildmode=c-shared \
  -o bin/starter.wasm ./vindex/mapfn/examples/starter
```

### Validating Your Plugin

Before deploying your WASM binary to `vindexd`, qualify it using `vindex-wasm`:

```bash
# 1. Inspect ABI exports and imported symbols
go run ./vindex/cmd/vindex-wasm inspect --wasm=bin/starter.wasm

# 2. Test key extraction on a sample leaf payload
go run ./vindex/cmd/vindex-wasm test --wasm=bin/starter.wasm --input="my-sample-payload"

# 3. Benchmark throughput
go run ./vindex/cmd/vindex-wasm bench --wasm=bin/starter.wasm --input="my-sample-payload" --iterations=1000
```

Or run all qualification checks with one command:
```bash
just verify-wasm bin/starter.wasm "my-sample-payload"
```

---

## 4. Pointing VIndex to Your Own Log

### Requirements for the Input Log
VIndex connects to any log conforming to the [tlog-tiles (C2SP)](https://c2sp.org/tlog-tiles) specification (or local filesystem layout via `file://`). It requires:
1. A readable `checkpoint` file signed with an RFC 6962 / Note key.
2. Standard entry bundles (`tile/entries/x...`) and hash tiles (`tile/0/x...`).

> **Tip:** You can generate a local mock log for testing using `just mock-log /tmp/inlog demo.mock.log`.

### Step A: Generate Note Keypair for the Output Log
VIndex signs its state trie commitments to an append-only Output Log. Generate an Ed25519 Note keypair:

```bash
just keygen my.vindex.org
```

Output:
```
Origin:       my.vindex.org
Signer Key:   PRIVATE+KEY+my.vindex.org+904c615e+...
Verifier Key: my.vindex.org+904c615e+...
```

### Step B: Run `vindexd`
Start the daemon in publisher mode pointing to your input log:

```bash
go run ./vindex/cmd/vindexd \
  --mode=publisher \
  --input_log_url="https://your-log-endpoint.org" \
  --input_log_origin="your-log.org" \
  --input_log_pubkey="your-log.org+a1b2c3d4+..." \
  --output_log_dir="/data/vindex/outlog" \
  --output_log_origin="my.vindex.org" \
  --output_log_signer_key="PRIVATE+KEY+my.vindex.org+..." \
  --wasm_path="/path/to/compiled_plugin.wasm" \
  --db_path="/data/vindex/pebble" \
  --mpt_dir="/data/vindex/mpt" \
  --tile_cache_dir="/data/vindex/tiles" \
  --listen_addr=":8080" \
  --metrics_addr=":9090" \
  --enable_ui=true
```

> **Note on Tile Serving:** `vindexd` serves the `tlog-vindex` Read API (`/keys?key=<key>` or `/keys?prefix=<key-prefix>` and `/values?key=<key>&before=<B>`), `/checkpoint`, and Output Log tiles (`/tile/*`) directly. The tile files written to `--output_log_dir` can also be served statically over HTTP (e.g. via Caddy or Nginx) to support external witnesses and full log auditors.

For large initial historical catch-ups, run with `--oneshot` to index the log up to tip and terminate.

#### Input & Output Log Verification Policies
When configuring `vindexd` (`--input_log_policy` / `--input_log_pubkey`) or `vindex-client` (`--out_log_policy` / `--out_log_pubkey`), you can supply either a [C2SP `tlog-cosignature` policy file](https://c2sp.org/tlog-cosignature) (`--*_policy`) for witness quorum verification or a single-key verifier string/file (`--*_pubkey`) supporting two formats (`internal/wire`):
1. **Standard RFC 6962 / SumDB Note format**: `<name>+<hash>+<base64Key>`
2. **Merkle Tree Certificates (MTC) format**: `mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>`

---

## 5. Querying the VIndex

### Interactive Web UI
When `vindexd` is running with `--enable_ui=true` (enabled by default), navigate your browser to:
```
http://localhost:8080/
```
This provides an interactive search interface to look up keys, view cryptographic proofs, inspect raw leaf indices, and explore checkpoint commitments.

### Using the CLI Client (`vindex-client`)
The client verifies the cryptographic Sparse Merkle Trie proof and Output Log commitment before displaying results:

```bash
go run ./vindex/cmd/vindex-client \
  --vindex_url="http://localhost:8080" \
  --out_log_origin="my.vindex.org" \
  --out_log_pubkey="my.vindex.org+904c615e+..." \
  --in_log_origin="your-log.org" \
  --key="my-search-key"
```

#### Dereferencing Original Leaf Payloads (`--dereference`)
By default, the client returns verified leaf sequence indices in the Input Log. Pass `--dereference` and `--in_log_url` to fetch and print the raw leaf contents:

```bash
go run ./vindex/cmd/vindex-client \
  --vindex_url="http://localhost:8080" \
  --out_log_origin="my.vindex.org" \
  --out_log_pubkey="my.vindex.org+904c615e+..." \
  --in_log_origin="your-log.org" \
  --in_log_url="https://your-log-endpoint.org" \
  --dereference \
  --all \
  --key="my-search-key"
```

- `--dereference`: Fetches the corresponding leaf bundle from `--in_log_url` and prints the payload.
- `--all`: Automatically paginates through all historical occurrences of the key (and values for prefix matches).

### Using HTTP Directly
VIndex separates public `tlog-vindex` query endpoints from internal operational endpoints:

**Public Read API (`--listen_addr`, default `:8080`):**
- `GET /keys?key=<key>` and `GET /keys?prefix=<key-prefix>`: Authenticated key/prefix value root lookup with MPT and Output Log proofs.
- `GET /values?key=<key>&before=<B>`: Lock-free paginated value log occurrence indices and compact range prefixes.
- `GET /checkpoint`: Latest signed Output Log checkpoint.
- `GET /tile/*`: Output Log hash and entry tiles (`tlog-tiles`).

**Internal Operational Listener (`--metrics_addr`, default `:9090`, non-public):**
- `GET /healthz`: Process liveness probe.
- `GET /readyz`: Sync readiness probe (`200 OK` when ready, `503 Service Unavailable` while catching up or halted).
- `GET /metrics`: Prometheus metrics scrape endpoint.
- `GET /debug/pprof/*`: Go runtime profiling handlers.

---

## 6. Real-World Personality: Go Checksum Database (SumDB)

The repository includes a production-grade personality for indexing the [Go Checksum Database](https://sum.golang.org).

### Launching the SumDB Stack
Run the multi-container Docker Compose stack:

```bash
just run-sumdb
```

*(Or `cd deploy/sumdb && docker compose up --build`)*

This starts:
1. `sumdbproxy`: Translates upstream `sum.golang.org` into standard `tlog-tiles` at `http://localhost:8080/sumdb/`.
2. `vindexd`: Ingests tiles, runs `sumdb.wasm` to index module paths, commits to Pebble/MPT, and serves C2SP queries.
3. `caddy`: Reverse proxy at `http://localhost:8080`.
4. `prometheus` & `grafana`: Pre-provisioned metrics and dashboards at `http://localhost:8080/grafana/`.

### Querying the Deployed SumDB Index

#### Option 1: Via `just` Task Runner
Query any Go module path with full cryptographic verification and leaf dereferencing:

```bash
just query-sumdb golang.org/x/mod
just query-sumdb github.com/transparency-dev/tessera
```

#### Option 2: Via `vindex-client` Directly
```bash
go run ./vindex/cmd/vindex-client \
  --vindex_url="http://localhost:8080" \
  --out_log_origin="sumdb.vindex.local" \
  --out_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  --in_log_origin="go.sum database tree" \
  --in_log_url="http://localhost:8080/sumdb/" \
  --dereference \
  --key="golang.org/x/mod"
```

Example output:
```text
37258761)
golang.org/x/mod v0.14.0 h1:abc...
golang.org/x/mod v0.14.0/go.mod h1:def...
```

#### Option 3: Prefix Discovery with `vindex-client`
The [`vindex-client`](./cmd/vindex-client) utility also supports verified prefix discovery (`--prefix`) across module families:

```bash
go run ./vindex/cmd/vindex-client \
  --vindex_url="http://localhost:8080" \
  --out_log_origin="sumdb.vindex.local" \
  --out_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  --in_log_origin="go.sum database tree" \
  --prefix \
  --key="golang.org/x/"
```

#### Option 4: Interactive Web UI
Open your browser to:
```
http://localhost:8080/
```
Type any module path (e.g. `golang.org/x/crypto` or `github.com/google/trillian`) into the search bar to see verified inclusion proofs and version history.

### Teardown
```bash
cd deploy/sumdb && docker compose down -v
```
