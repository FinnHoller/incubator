# VIndex SumDB Personality Docker Compose Bundle

This deployment bundle runs a fully functional, self-contained **Verifiable Index (VIndex) personality for the Go Checksum Database (SumDB)**, complete with upstream proxying, WASM MapFn execution, Caddy gateway routing, Prometheus metrics, and a pre-provisioned Grafana dashboard.

## Architecture

```
                                      +---------------------------------------------+
                                      |                Caddy Gateway                |
                                      |             (http://localhost:8080)          |
                                      +---------------------------------------------+
                                            /                  |               \
                       /checkpoint, /tile/* |                  | /sumdb/*       \ /grafana/*
                       /keys, /values, /    |                  |                 \
                                            v                  v                  v
                             +-------------------+    +-----------------+    +-----------------+
                             |      vindexd      |    |    sumdbproxy   |    |     Grafana     |
                             |   (WASM: sumdb)   |    |    (:8089)      |    |     (:3000)     |
                             +-------------------+    +-----------------+    +-----------------+
                                      |    ^                   |                      ^
                         fetches tiles|    |                   | fetches upstream     | queries
                                      +----+                   v                      v
                                                        sum.golang.org       +-----------------+
                                                                             |    Prometheus   |
                                                                             |     (:9090)     |
                                                                             +-----------------+
```

## Quickstart

### 1. Launch the Stack
```bash
cd deploy/sumdb
docker compose up -d --build
```

### 2. Service Endpoints (via Gateway Port `8080`)

| Service / Path | URL | Description |
| :--- | :--- | :--- |
| **VIndex Web UI** | `http://localhost:8080/` | Interactive single-page UI for searching modules and exploring log tree state. |
| **Output Log Checkpoint** | `http://localhost:8080/checkpoint` | Current signed tree head for `sumdb.vindex.local`. |
| **Output Log Tiles** | `http://localhost:8080/tile/*` | `tlog-tiles` hash and entry bundles for `sumdb.vindex.local`. |
| **Index Key & Prefix Lookup** | `http://localhost:8080/keys?key=<key>` or `?prefix=<key-prefix>` | Verifiable inclusion / non-inclusion / prefix proofs for module search keys. |
| **Index Value Pagination** | `http://localhost:8080/values?key=<key>&before=<B>` | Verifiable value log entry indices and compact range prefixes. |
| **SumDB Proxy** | `http://localhost:8080/sumdb/` | Proxied `sum.golang.org` tiles and checkpoints. |
| **Grafana Dashboards** | `http://localhost:8080/grafana/` | Pre-built dashboard (Login: `admin` / `admin`). |

---

## Verifying & Querying the Deployed Index

Use [`vindex-client`](../../vindex/cmd/vindex-client) to cryptographically verify queries against the running index:

```bash
# Query a canonical Go module path through the Caddy gateway
go run ./vindex/cmd/vindex-client \
  --vindex_url="http://localhost:8080" \
  --out_log_origin="sumdb.vindex.local" \
  --out_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  --in_log_origin="go.sum database tree" \
  --in_log_url="http://localhost:8080/sumdb/" \
  --dereference \
  --key="golang.org/x/mod"
```

---

## Teardown

To stop all containers and remove persistent volumes:
```bash
docker compose down -v
```
