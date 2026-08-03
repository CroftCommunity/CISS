# CISS — Croft Item Storage Server

A PDS-like **cooperative metered-storage server** in Rust: a network-accessible,
custom storage server that exposes an **S3-compatible object interface** and an
**atproto PDS blob API** over one metered byte-path, where the network boundary
*is* the metering boundary. Every byte that crosses the boundary is metered with
a signed receipt (postage), and rent derives from the customer's own signed
manifest.

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
- **atproto PDS blob API (Phase 8): shipped.** `uploadBlob`/`getBlob`/`listBlobs`
  as a thin layer over the *same* metered byte-path — an atproto transfer meters
  identically to an S3 one. Real CIDv1 (`raw` + sha-256) blob references close
  the hex-SHA-256 CID `SEAM:`; a mock-bearer auth `SEAM:` stands in for the real
  atproto OAuth/DPoP session on `uploadBlob`.
- **croft-stack deploy contract (Phase 9): ready.** The binary honours the
  croft-stack tenant contract — `--data-dir <path>` + `--listen <host:port>`,
  all state under the data dir (`meter.sqlite` canonical, `blocks/` blobs),
  `GET /healthz` → `ok`, unprivileged, port ≥ 1024. The provider key seed is
  persisted in the canonical SQLite (generated on first start), so the signing
  identity survives a Litestream backup/restore with no external secret wiring.
  Deployed as a governed, hardened tenant via `CroftCommunity/croft-stack`.

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

## The atproto PDS blob surface

The Bluesky-facing blob endpoints (canonical lexicon shapes), a thin layer over
the same metered byte-path — so an atproto transfer produces the same signed
receipts as the S3 plane. The network speaks CIDv1 (`ref.$link`); the backend is
keyed by the same digest in hex, and `cidv1.rs` bridges the two losslessly.

| Method | Path | Meaning |
|---|---|---|
| `POST` | `/xrpc/com.atproto.repo.uploadBlob` | **Auth required.** Store the raw-body blob in the authed repo; metered. Returns `{"blob":{"$type":"blob","ref":{"$link":"<CIDv1>"},"mimeType":"<ct>","size":<int>}}`. |
| `GET` | `/xrpc/com.atproto.sync.getBlob?did=&cid=` | **Public.** Return the raw bytes addressed by the CIDv1; metered. |
| `GET` | `/xrpc/com.atproto.sync.listBlobs?did=` | **Public.** The CIDv1 addresses the DID has uploaded: `{"cids":[...]}`. |

`SEAM:`s: `uploadBlob` auth is a mock bearer check (the token stands in for the
DID; real atproto OAuth/DPoP is a later spike); `getBlob`'s Content-Type echo and
`listBlobs` pagination (`cursor`/`since`/`limit`) are deferred. The rest of the
PDS surface (`getRepo`/`getRecord`/`subscribeRepos`/…) is out of v0.

## Run it

```sh
cargo run -- --data-dir ./data --listen 127.0.0.1:8080
# Two flags, nothing else (croft-stack contract §1). Dev defaults match the
# above, so a bare `cargo run` also works. The binary self-manages its layout:
#   <data-dir>/meter.sqlite   per-DID metering ledger (canonical; Litestream)
#                             — also holds the persisted provider key seed
#   <data-dir>/blocks/        content-addressed blob bytes (rclone --immutable)
# Both are created on start. A systemd socket-activation fd is inherited when
# offered (LISTEN_FDS/LISTEN_PID); SIGTERM drains + checkpoints the WAL.
```

`GET /healthz` returns `200 ok` once serving. A metered round-trip:

```sh
CID=$(printf 'hello' | shasum -a 256 | cut -d' ' -f1)
curl -X PUT --data-binary 'hello' http://127.0.0.1:8080/id:me/objects/greeting
curl http://127.0.0.1:8080/id:me/objects/$CID      # -> hello
curl http://127.0.0.1:8080/id:me/meter             # -> receipt tally
```

The same round-trip over the atproto surface (a real CIDv1 comes back):

```sh
LINK=$(curl -s -X POST -H 'Authorization: Bearer did:plc:me' \
  --data-binary 'hello' \
  http://127.0.0.1:8080/xrpc/com.atproto.repo.uploadBlob \
  | sed -E 's/.*"\$link":"([^"]+)".*/\1/')
curl "http://127.0.0.1:8080/xrpc/com.atproto.sync.getBlob?did=did:plc:me&cid=$LINK"   # -> hello
curl "http://127.0.0.1:8080/xrpc/com.atproto.sync.listBlobs?did=did:plc:me"           # -> {"cids":[...]}
```

## Develop

Standalone crate. From the repo root:

```sh
cargo test                              # full suite (unit + wiring + abuse)
cargo test --test wiring_s3_metered     # the Phase-7 anti-dead-code wiring gate
cargo test --test wiring_pds_blob       # the Phase-8 atproto wiring gate
cargo test --test e86_abuse             # the end-to-end abuse suite
cargo clippy --all-targets -- -W clippy::pedantic -D warnings
cargo fmt --check
cargo mutants --file src/server.rs --file src/blobstore.rs   # mutation gate
cargo mutants --file src/cidv1.rs --file src/pds_api.rs       # Phase-8 mutation gate
```

## Provenance

CISS is the productionization of the `item-storage-protocol` experiment. The
full build plan (problem, reasoning, phase-by-phase design, decisions) lives in
the `discovery` repo:
`discovery/alpha/plans/2026-07-31-1-plan-coop-metered-storage-service.md`.
