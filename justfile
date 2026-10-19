# Verifiable Index (VIndex) Task Runner
# https://github.com/casey/just

set shell := ["bash", "-uc"]

# List available recipes
default:
    @just --list

# Build all core VIndex binaries into bin/
build:
    @mkdir -p bin
    go build -o bin/vindexd ./vindex/cmd/vindexd
    go build -o bin/vindex-client ./vindex/cmd/vindex-client
    go build -o bin/vindex-wasm ./vindex/cmd/vindex-wasm
    if [ -d ./vindex/cmd/vindex-auditor ]; then go build -o bin/vindex-auditor ./vindex/cmd/vindex-auditor; fi
    if [ -d ./vindex/cmd/clonelog ]; then go build -o bin/clonelog ./vindex/cmd/clonelog; fi
    @echo "Built binaries in bin/"

# Run full repository test suite
test:
    go test ./vindex/...

# Generate an Ed25519 Note signing and verification keypair
keygen origin="vindex.local":
    @go run ./scripts/keygen "{{origin}}"

# Generate a local mock Input Log with signed checkpoint and test entries
mock-log dir="/tmp/mock-inlog" origin="demo.mock.log":
    @go run ./scripts/mock_log "{{dir}}" "{{origin}}"

# Compile a WASM MapFn plugin for wasip1
build-wasm dir="vindex/mapfn/examples/starter" out="bin/starter.wasm":
    @mkdir -p $(dirname "{{out}}")
    GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -buildmode=c-shared -o "{{out}}" "./{{dir}}"
    @echo "Compiled: {{out}}"

# Test a WASM MapFn plugin against a sample leaf string
test-wasm wasm="bin/starter.wasm" input="package:github.com/foo/bar@v1.0.0":
    @go run ./vindex/cmd/vindex-wasm test --wasm="{{wasm}}" --input="{{input}}"

# Run full qualification on a WASM plugin (inspect, test, benchmark)
verify-wasm wasm="bin/starter.wasm" input="package:github.com/foo/bar@v1.0.0":
    @echo "=== Inspect ABI Exports ==="
    @go run ./vindex/cmd/vindex-wasm inspect --wasm="{{wasm}}"
    @echo "\n=== Test Mapping Function ==="
    @go run ./vindex/cmd/vindex-wasm test --wasm="{{wasm}}" --input="{{input}}"
    @echo "\n=== Benchmark Throughput ==="
    @go run ./vindex/cmd/vindex-wasm bench --wasm="{{wasm}}" --input="{{input}}" --iterations=500

# Run local zero-configuration end-to-end demo (mock log + starter.wasm + vindexd + query)
demo-local:
    @./scripts/demo-local.sh

# Run complete Go SumDB stack via Docker Compose
run-sumdb:
    cd deploy/sumdb && docker compose up --build

# Query local SumDB Docker stack for a Go module path
query-sumdb module="golang.org/x/mod":
    @go run ./vindex/cmd/vindex-client \
        --vindex_url="http://localhost:8080" \
        --out_log_origin="sumdb.vindex.local" \
        --out_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
        --in_log_origin="go.sum database tree" \
        --in_log_url="http://localhost:8080/sumdb/" \
        --dereference \
        --key="{{module}}"

# Query a running VIndex instance via vindex-client
query url="http://localhost:8080" key="" out_key="" out_origin="" in_origin="":
    @go run ./vindex/cmd/vindex-client \
        --vindex_url="{{url}}" \
        --key="{{key}}" \
        {{ if out_key != "" { "--out_log_pubkey=" + out_key } else { "" } }} \
        {{ if out_origin != "" { "--out_log_origin=" + out_origin } else { "" } }} \
        {{ if in_origin != "" { "--in_log_origin=" + in_origin } else { "" } }}

# Remove build artifacts and temporary files
clean:
    rm -rf bin/ /tmp/vindex-demo-*
