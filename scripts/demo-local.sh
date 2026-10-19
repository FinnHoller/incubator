#!/usr/bin/env bash
# Copyright 2026 The Transparency Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

DEMO_DIR=$(mktemp -d -t vindex-demo-XXXXXX)
VINDEXD_PID=""

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$VINDEXD_PID" ]]; then
    kill -TERM "$VINDEXD_PID" 2>/dev/null || true
    for _ in {1..20}; do
      if ! kill -0 "$VINDEXD_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    kill -KILL "$VINDEXD_PID" 2>/dev/null || true
  fi
  if [[ $exit_code -ne 0 && -f "$DEMO_DIR/vindexd.log" ]]; then
    echo -e "\n=== vindexd.log (Last 25 Lines) ==="
    tail -n 25 "$DEMO_DIR/vindexd.log" || true
  fi
  rm -rf "$DEMO_DIR"
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

# Localhost ports (configurable via DEMO_PORT and DEMO_METRICS_PORT)
PORT=${DEMO_PORT:-8999}
METRICS_PORT=${DEMO_METRICS_PORT:-$((PORT + 1))}

echo "=== 1. Compiling Binaries & Starter WASM ==="
mkdir -p "$DEMO_DIR/bin"
go build -o "$DEMO_DIR/bin/vindexd" ./vindex/cmd/vindexd
go build -o "$DEMO_DIR/bin/vindex-client" ./vindex/cmd/vindex-client
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -buildmode=c-shared \
  -o "$DEMO_DIR/starter.wasm" ./vindex/mapfn/examples/starter
echo "Compiled: vindexd, vindex-client, starter.wasm"

echo -e "\n=== 2. Creating Local Input Log ==="
eval $(go run ./scripts/mock_log "$DEMO_DIR/inlog" "demo.mock.log")
echo "Created mock input log with $ENTRIES_COUNT entries ('apple', 'banana', 'cherry', 'apple')"

echo -e "\n=== 3. Generating VIndex Output Log Keypair ==="
KEYGEN_OUT=$(go run ./scripts/keygen "demo.vindex.log")
OUT_SKEY=$(echo "$KEYGEN_OUT" | grep "Signer Key:" | awk '{print $3}')
OUT_VKEY=$(echo "$KEYGEN_OUT" | grep "Verifier Key:" | awk '{print $3}')
echo "Origin: demo.vindex.log"
echo "Public Verifier: $OUT_VKEY"

echo -e "\n=== 4. Launching vindexd Server (Port: $PORT, Metrics Port: $METRICS_PORT) ==="
mkdir -p "$DEMO_DIR/db" "$DEMO_DIR/mpt" "$DEMO_DIR/outlog" "$DEMO_DIR/tiles"

"$DEMO_DIR/bin/vindexd" \
  --mode=publisher \
  --input_log_url="file://$INPUT_LOG_DIR" \
  --input_log_origin="$INPUT_LOG_ORIGIN" \
  --input_log_pubkey="$INPUT_LOG_PUBKEY" \
  --output_log_dir="$DEMO_DIR/outlog" \
  --output_log_origin="demo.vindex.log" \
  --output_log_signer_key="$OUT_SKEY" \
  --wasm_path="$DEMO_DIR/starter.wasm" \
  --db_path="$DEMO_DIR/db" \
  --mpt_dir="$DEMO_DIR/mpt" \
  --tile_cache_dir="$DEMO_DIR/tiles" \
  --listen_addr="127.0.0.1:$PORT" \
  --metrics_addr="127.0.0.1:$METRICS_PORT" \
  --poll_interval=100ms >"$DEMO_DIR/vindexd.log" 2>&1 &
VINDEXD_PID=$!

# Health probe (served on internal --metrics_addr)
for i in {1..50}; do
  if curl -sf "http://127.0.0.1:$METRICS_PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$VINDEXD_PID" 2>/dev/null; then
    echo "vindexd failed to start"
    exit 1
  fi
  sleep 0.1
done

# Wait for initial checkpoint commit
for i in {1..50}; do
  if curl -s "http://127.0.0.1:$PORT/checkpoint" 2>/dev/null | grep -q "demo.vindex.log"; then
    break
  fi
  sleep 0.1
done

echo -e "\n=== 5. Running Verified Client Queries ==="

echo -e "\n[Query 1/3] Key 'apple' -> Expecting occurrences at leaf 0 and leaf 3:"
"$DEMO_DIR/bin/vindex-client" \
  --vindex_url="http://127.0.0.1:$PORT" \
  --out_log_pubkey="$OUT_VKEY" \
  --out_log_origin="demo.vindex.log" \
  --in_log_origin="$INPUT_LOG_ORIGIN" \
  --key="apple"

echo -e "\n[Query 2/3] Key 'cherry' -> Expecting occurrence at leaf 2:"
"$DEMO_DIR/bin/vindex-client" \
  --vindex_url="http://127.0.0.1:$PORT" \
  --out_log_pubkey="$OUT_VKEY" \
  --out_log_origin="demo.vindex.log" \
  --in_log_origin="$INPUT_LOG_ORIGIN" \
  --key="cherry"

echo -e "\n[Query 3/3] Key 'nonexistent' -> Expecting verified non-inclusion:"
"$DEMO_DIR/bin/vindex-client" \
  --vindex_url="http://127.0.0.1:$PORT" \
  --out_log_pubkey="$OUT_VKEY" \
  --out_log_origin="demo.vindex.log" \
  --in_log_origin="$INPUT_LOG_ORIGIN" \
  --key="nonexistent" || true

echo -e "\nDemo completed successfully. Shutting down cleanly."
