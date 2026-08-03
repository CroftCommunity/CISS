# CISS — Croft Item Storage Server

A PDS-like **cooperative metered-storage server** in Rust: a network-accessible,
custom storage server that exposes an **S3-compatible object interface** (and,
in progress, an **atproto PDS blob API**) where the network boundary *is* the
metering boundary. Every byte that crosses the boundary is metered with a signed
receipt (postage), and rent derives from the customer's own signed manifest.

CISS is destined for VPS deployment via **croft-stack** and doubles as the
substrate for the MLS history-convergence server (one store, two consumers).

## Design: meter the boundary, not the machine

CISS is two layers that compose but never conflate:

```
   HTTP boundary  ── Layer 2: metering / crypto provenance ──┐
   (S3 / atproto)     signed receipts (postage) + the         │  the ledger
                      customer's signed manifest (rent)        │  (E0–E9)
        │             + statements / audit / seal              │
        ▼                                                       ▼
   BlobStore trait ── Layer 1: dumb bytes-under-a-key backend ─┘
   (memory · FS · …)   never meters, never verifies, never trusted
```

- **Layer 1 (`blobstore.rs`)** is a deliberately dumb, pluggable byte store
  keyed by `(DID, CID)`. FS-first; Garage/SeaweedFS/R2 are later backends behind
  the same `BlobStore` trait. It never meters and never content-checks.
- **Layer 2 (`server.rs`)** is the boundary: it content-addresses (SHA-256),
  re-verifies bytes on the way out (tamper-at-rest is caught here), meters each
  transfer with a provider-signed receipt in the customer's per-DID SQLite
  ledger, and derives rent from the customer's signed manifest.

The provenance comes from the two parties' keys plus the customer's manifest —
never from the backend. That is why a blind, untrusted backend still bills
correctly.

## Status

- **E0–E9 metering ledger core: complete, mutation-gated.** Identity/crypto,
  content-addressed items + a customer-signed Merkle manifest, two-mode transfer
  receipts over an append-only signed ledger, balance-forward statements with
  byte-day rent + rollup/purge + per-user SQLite, k-sample spot-check audit with
  the assurance dial, and the seal/tombstone/grace tiers.
- **S3-compatible metered boundary (Phase 7): shipped.** A real axum HTTP server
  where PUT/GET are metered end-to-end; a pluggable `BlobStore` (memory + FS);
  the customer-signed manifest surface; a graceful-shutdown + socket-activation
  seam; forward-compat seams for per-DID compute observability (E83) and
  kernel-perf backends (E84).
- **Pending:** the atproto PDS blob API (`uploadBlob`/`getBlob`/`listBlobs`)
  over the same metered path, then croft-stack VPS deploy.

## The v0 metered boundary

| Method | Path | Meaning |
|---|---|---|
| `PUT` | `/{did}/objects/{key}` | Store bytes; content-addressed by SHA-256; metered (a provider-signed upload receipt). Returns `{cid, bytes, receipt_mode}` + `ETag`. |
| `GET` | `/{did}/objects/{cid}` | Return the exact bytes (re-verified); metered (a download receipt). |
| `PUT` | `/{did}/manifest` | Store the customer's signed manifest (header `x-croft-pubkey`; the DID must be the key's fingerprint). Rent base. |
| `GET` | `/{did}/manifest` | The stored signed manifest. |
| `GET` | `/{did}/meter` | Metering summary: `{receipt_count, upload_bytes, download_bytes, running_total_bytes, postage_cents}`. |

Everything else on the S3 verb surface (DELETE, LIST, HEAD, multipart) is a
`SEAM:` behind the fallback — not yet in v0.

## Run it

```sh
cargo run
# configuration (env, dev defaults shown):
#   CISS_SEED=ciss-dev              provider key seed (SEAM: real key from a KMS)
#   CISS_BLOB_ROOT=./data/blocks    filesystem blob backend root
#   CISS_DB=./data/meter.sqlite     per-DID metering SQLite
#   CISS_ADDR=127.0.0.1:8080        bind address (or systemd socket-activated)
```

A metered round-trip:

```sh
CID=$(printf 'hello' | shasum -a 256 | cut -d' ' -f1)
curl -X PUT --data-binary 'hello' http://127.0.0.1:8080/id:me/objects/greeting
curl http://127.0.0.1:8080/id:me/objects/$CID      # -> hello
curl http://127.0.0.1:8080/id:me/meter             # -> receipt tally
```

## Develop

Standalone crate. From the repo root:

```sh
cargo test                              # full suite (unit + wiring + abuse)
cargo test --test wiring_s3_metered     # the Phase-7 anti-dead-code wiring gate
cargo test --test e86_abuse             # the end-to-end abuse suite
cargo clippy --all-targets -- -W clippy::pedantic -D warnings
cargo fmt --check
cargo mutants --file src/server.rs --file src/blobstore.rs   # mutation gate
```

## Provenance

CISS is the productionization of the `item-storage-protocol` experiment. The
full build plan (problem, reasoning, phase-by-phase design, decisions) lives in
the `discovery` repo:
`discovery/alpha/plans/2026-07-31-1-plan-coop-metered-storage-service.md`.
