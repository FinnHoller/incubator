# MTC Verifiable Index Verifier (`mtcverify`)

`mtcverify` queries and cryptographically verifies domain lookups in an MTC verifiable index.

## Usage

```bash
go run ./vindex/cmd/mtcverify/ \
  --vindex_url=http://localhost:8088 \
  --out_log_pubkey=MTCIndex+07392c46+... \
  --domain=example.com
```
