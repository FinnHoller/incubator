# MTC Verifiable Indexer (`mtcindex`)

`mtcindex` brings up a verifiable index for Merkle Tree Certificates (MTC) logs. It ingests leaf entries from an MTC log, parses certificates via ASN.1, extracts reversed-label SAN/CN domain keys (`com.example.`), and maintains an authenticated state trie (MPT) and inverted chunk index.

## Usage

```bash
OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+MTCIndex+07392c46+ATPJ4crkyUbPeaRffN/4NUof3KV0pQznVIPGOQm3SDEJ \
go run ./vindex/cmd/mtcindex/ \
  --storage_dir=/path/to/storage \
  --listen_addr=:8088
```

## Verification

Query and verify certificates for a domain using `mtcverify`:

```bash
go run ./vindex/cmd/mtcverify/ \
  --vindex_url=http://localhost:8088 \
  --out_log_pubkey=MTCIndex+07392c46+... \
  --domain=example.com
```
