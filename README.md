# CISS — Croft Item Storage Server

A PDS-like **cooperative metered-storage server** in Rust. CISS exposes an
**S3-compatible object interface** and an **atproto PDS blob API**
(`uploadBlob`/`getBlob`/`listBlobs`) over **one metered byte-path**, where the
network boundary *is* the metering boundary: every byte that crosses it is
metered with a provider-signed receipt (postage), and rent is derived from the
customer's own signed manifest — never from the storage backend.

CISS is the productionization of the proven `item-storage-protocol` experiment.
It runs live as a governed [croft-stack](https://github.com/CroftCommunity/croft-stack)
tenant, and is designed to also serve as the substrate for a *planned* content-blind
history-convergence server (one store, two consumers — the second consumer is not
built yet).

- **Live:** `https://ciss.croft.ing`
- **Design docs:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
- **Full build plan / provenance** (reasoning, per-phase design, decisions): the
  `discovery` repo, `alpha/plans/2026-07-31-1-plan-coop-metered-storage-service.md`.

---

## Why CISS exists (the use case)

A cooperative that hosts storage for its members needs a way to charge honestly
for what it actually costs to store and move bytes — **without** trusting the
operator's word for the bill, and **without** the operator having to trust the
member's word either. CISS makes the meter itself verifiable:

- **The member** keeps a signed **manifest** of what they asked to store (CIDs +
  sizes). Rent (bytes-at-rest × days) is a pure function of *their own* signed
  document, so they can recompute the bill independently.
- **The provider** signs a **receipt** for every transfer (bytes in/out). The
  receipts form an append-only, hash-linked ledger; a monthly balance-forward
  **statement** nets opening state + receipts + byte-days into a closing state
  both parties can check.
- **Neither side can quietly cheat:** content is addressed by its own hash
  (tamper-at-rest is caught on read), receipts and statements are signed, and
  the arithmetic is exact integer cents.

Because it speaks the **atproto blob API**, CISS is also a PDS-shaped node on the
Bluesky network — it can host blobs for a repo without owning the identity — and
because it speaks a plain **S3 PUT/GET** interface, it is usable as ordinary
metered object storage. The two surfaces share one metering plane.

## The core idea: meter the boundary, not the machine

CISS is two layers that compose but never conflate:

```
   HTTP boundary  ── Layer 2: metering / crypto provenance ────────────┐
   S3  ·  atproto    content-address (SHA-256) + re-verify on read;     │  the ledger
   ·  manifest       provider-signed receipt per transfer (postage);    │  (E0–E9),
   ·  meter          rent from the customer's signed manifest;          │  per-DID
        │            statements · audit · seal · grace                   │  SQLite
        ▼                                                                ▼
   BlobStore trait ── Layer 1: dumb bytes-under-a-key backend ──────────┘
   (memory · FS · …)   never meters, never verifies, never trusted
```

- **Layer 1 (`blobstore.rs`)** is a deliberately dumb, pluggable byte store keyed
  by `(DID, CID)`. It never meters, never content-checks, holds no provenance —
  so any S3-compatible store (FS today; Garage/SeaweedFS/R2 later) can stand in,
  and a compromised backend still cannot forge a bill or slip a bad blob past
  Layer 2.
- **Layer 2 (`server.rs` + `pds_api.rs` + `cidv1.rs`)** is the boundary. It content-addresses
  (SHA-256), re-verifies bytes on the way out (tamper-at-rest is caught here),
  meters each transfer with a provider-signed receipt in the customer's per-DID
  SQLite ledger, and derives rent from the customer's signed manifest.

Provenance comes from the two parties' keys plus the customer's manifest — never
from the backend. That is *why* a blind, untrusted backend still bills correctly.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full model.

## Quickstart

```sh
cargo run -- --data-dir ./data --listen 127.0.0.1:8080
# Two flags, nothing else (croft-stack contract). Dev defaults match the above,
# so a bare `cargo run` also works. The binary self-manages its layout:
#   <data-dir>/meter.sqlite   per-DID metering ledger (+ the provider PUBLIC key)
#   <data-dir>/blocks/        content-addressed blob bytes ({did}/{cid})
#   <data-dir>/tmp/           write staging (temp→rename), outside blocks/
# The provider signing seed comes from a unit-supplied secret (systemd credential
# or CISS_PROVIDER_SEED), never the database. See docs/SECURITY-POSTURE.md §9.
```

A metered round-trip over the S3 surface. **Reads are world-readable by default;
an owner can gate a namespace or a single object with a read policy (a denied read
404s, `listBlobs` omits it); writes and the billing meter are authenticated
(owner-only, ADR 0001)** — see `docs/spec/gated-reads.md`. The write and meter
calls need `$AUTH`: either an `id:` signed session
(`x-croft-pubkey` + `x-croft-session` over the session challenge) or a `did:`
service-auth JWT bearer. Anonymous writes/meter are `401` by design.

```sh
CID=$(printf 'hello' | shasum -a 256 | cut -d' ' -f1)
curl -X PUT $AUTH --data-binary 'hello' http://127.0.0.1:8080/id:me/objects/greeting  # owner-only
curl http://127.0.0.1:8080/id:me/objects/$CID      # -> hello  (public read)
curl $AUTH http://127.0.0.1:8080/id:me/meter       # -> receipt tally (owner-only)
```

Operator storage usage (a read-only report over the `did_usage` surface — store
ceiling as a % of the partition, per-DID on-disk + cumulative-transferred bytes):

```sh
cargo run -- usage --data-dir ./data            # all DIDs
cargo run -- usage --data-dir ./data --did id:me # one DID
```

The same over the atproto surface. `uploadBlob` is authenticated: the bearer is a
**service-auth JWT** (Model R — `iss`=caller DID, `aud`=`did:web:ciss.croft.ing`,
`lxm`=`com.atproto.repo.uploadBlob`, signed by the caller's repo key), verified
against the DID-resolved key. A bare `Bearer did:plc:me` authenticates as nobody
(`401`). `getBlob`/`listBlobs` are public reads.

```sh
# uploadBlob (authenticated) — $JWT is a service-auth JWT for aud=did:web:ciss.croft.ing:
LINK=$(curl -s -X POST -H "Authorization: Bearer $JWT" \
  --data-binary 'hello' \
  http://127.0.0.1:8080/xrpc/com.atproto.repo.uploadBlob \
  | sed -E 's/.*"\$link":"([^"]+)".*/\1/')
# public reads (no auth):
curl "http://127.0.0.1:8080/xrpc/com.atproto.sync.getBlob?did=did:plc:me&cid=$LINK"  # -> hello
curl "http://127.0.0.1:8080/xrpc/com.atproto.sync.listBlobs?did=did:plc:me"          # -> {"cids":[...]}
```

## API surface

### S3-compatible metering plane

| Method | Path | Meaning |
|---|---|---|
| `PUT` | `/{did}/objects/{key}` | Store bytes; content-addressed by SHA-256; metered (provider-signed **upload** receipt). Returns `{cid, bytes, receipt_mode}` + `ETag`. |
| `GET` | `/{did}/objects/{cid}` | **Public by default; gateable** (a denied read 404s; authenticates an `id:` session). Return the exact bytes (re-verified against the CID); metered (**download** receipt). |
| `PUT` | `/{did}/manifest` | Store the customer's signed manifest (header `x-croft-pubkey`; the DID must be the key's fingerprint). The rent base. |
| `GET` | `/{did}/manifest` | The stored signed manifest. |
| `GET` | `/{did}/meter` | Metering summary: `{receipt_count, upload_bytes, download_bytes, running_total_bytes, postage_cents}`. |

DELETE / LIST / HEAD / multipart are a `SEAM:` behind the fallback (`501`), not in v0.

### atproto PDS blob surface

Canonical lexicon shapes, a thin layer over the *same* metered byte-path — an
atproto transfer produces the same signed receipts as an S3 one. The network
speaks CIDv1 (`ref.$link`); the backend is keyed by the same digest in hex, and
`cidv1.rs` bridges the two losslessly.

| Method | Path | Meaning |
|---|---|---|
| `POST` | `/xrpc/com.atproto.repo.uploadBlob` | **Auth required.** Store the raw-body blob in the authed repo; metered. Returns `{"blob":{"$type":"blob","ref":{"$link":"<CIDv1>"},"mimeType":"<ct>","size":<int>}}`. |
| `GET` | `/xrpc/com.atproto.sync.getBlob?did=&cid=` | **Public by default; gateable.** Return the raw bytes addressed by the CIDv1; metered. A gated blob 404s an unauthorized caller (authenticates an `id:` session or `did:` JWT reader). |
| `GET` | `/xrpc/com.atproto.sync.listBlobs?did=` | **Public by default; gateable.** The CIDv1 addresses a DID has uploaded: `{"cids":[...]}` — omits any the caller may not read. |
| `PUT`/`GET` | `/{did}/policy`, `/{did}/objects/{cid}/policy` | Set/read the read policy for a namespace or object (gated reads). `id:` owner submits a signed record; `did:` owner authorizes via a `Bearer` service-auth JWT. See `docs/spec/gated-reads.md`. |

### Operational endpoints

| Method | Path | Meaning |
|---|---|---|
| `GET` | `/healthz` | `200 ok` once serving. Fast, side-effect-free (croft-stack readiness probe). |

## Client (`ciss-ctl`)

`ciss-ctl` is the reference client (`crates/ciss-cli`), homebrew-installable. It
links the server's own crates, so its crypto matches the wire byte-for-byte. It
owns a client identity (native ed25519, or imported from `ssh-keygen`), uploads
and fetches over **either** plane interchangeably (one digest), manages gated-read
ACLs (Model A `id:` / Model C `did:`), and shows the bytes transferred.

```bash
ciss-ctl key gen                                  # or: key import ~/.ssh/id_ed25519
ciss-ctl put note.txt                             # atproto uploadBlob (default) → {cid, cidv1, bytes}
ciss-ctl put note.txt --via s3                    # S3-compat plane → same cid
ciss-ctl get <cid> --via s3 -o out.txt            # cross-plane fetch (same bytes)
ciss-ctl meter                                    # receipts + bytes + postage
ciss-ctl acl set <cid> --class grantees --readers id:<did>   # gate a private object
```

Denial is oracle-free (`404`, never `403`; `ls` omits hidden objects). The `did:`
path relays a PDS-minted service-auth JWT (Model R) — the client holds a
credential, never a key. Full walkthrough: **`docs/CLIENT.md`**.

## Configuration

The binary takes exactly two flags (the croft-stack tenant contract) and manages
everything else itself:

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir <path>` | `./data` | Root of all state. `meter.sqlite`, `blocks/`, `tmp/` live here. Created on start. |
| `--listen <host:port>` | `127.0.0.1:8080` | Bind address. Always a port ≥ 1024 (TLS is Caddy's job). |

- The **provider signing seed** is supplied by the unit as a secret — a systemd
  credential (`$CREDENTIALS_DIRECTORY/provider-seed`) or `CISS_PROVIDER_SEED` — and
  is **never stored in the database** (finding I8); under systemd the service
  **fails closed** if neither is present. Only the **public** key is persisted to
  `meter.sqlite`, as a durable verification anchor. See `docs/SECURITY-POSTURE.md`
  §9 and `docs/DEPLOYMENT.md` §3.
- Atproto-identity config (Model R) is env-driven with safe defaults:
  `CISS_SERVICE_DID` (default `did:web:ciss.croft.ing`), `CISS_PLC_DIRECTORY_URL`,
  `CISS_DID_RESOLVE_TIMEOUT_MS`, `CISS_DID_CACHE_TTL_S`, and the pinned-admin
  break-glass file `CISS_ADMIN_PINS_FILE`. See `docs/DEPLOYMENT.md`.
- A systemd **socket-activation** fd is inherited when offered
  (`LISTEN_FDS`/`LISTEN_PID`); **SIGTERM** triggers a graceful drain + a WAL
  checkpoint before exit.

## Repository layout

```
src/
  # Layer 2 — the metered boundary
  server.rs        the S3 boundary + Op-dispatch + metering hook + HTTP mapping
  pds_api.rs       the atproto blob surface (uploadBlob/getBlob/listBlobs)
  cidv1.rs         real CIDv1 (raw+sha-256) <-> hex-digest bridge for blob refs
  main.rs          the runnable binary (flags, layout, graceful shutdown)
  # Layer 1 — the dumb backend
  blobstore.rs     BlobStore trait + MemoryBlobStore + FsBlobStore ({did}/{cid})
  # The E0–E9 ledger core (proven; ported from the item-storage-protocol)
  crypto.rs        SHA-256 fingerprints + Ed25519 sign/verify (zeroized keys)
  identity.rs      an actor is a keypair; its id is derived from its public key
  item.rs          content-addressed items + the in-memory content store
  manifest.rs      the customer's signed Merkle manifest (what to store; rent base)
  receipts.rs      signed transfer receipts (Bilateral | Unilateral postage)
  ledger.rs        append-only, hash-linked, signed per-actor ledgers
  statements.rs    balance-forward statements + byte-day rent + rollup/purge
  audit.rs         k-sample spot-check audit (detection math over a seeded RNG)
  dial.rs          the assurance dial — priced, signed assurance setting
  seal.rs          seal / tombstone tiers (pin-a-root, fail-closed ceremonies)
  grace.rs         the grace ledger — co-signed mercy events that net to zero
  pricing.rs       the price list (integer cents; postage + rent)
  canonical.rs     the one canonical byte-string every signature/hash is taken over
  clock.rs         a deterministic day clock (time advances only when told)
  rng.rs           a seeded deterministic PRNG (mulberry32; bit-exact parity)
  persist.rs       per-DID SQLite (manifests, receipts, statements, meta kv)
  did_resolver.rs  production DID-resolver composition (reqwest fetcher + wiring)
crates/            # the authentication surface, split from the metering core
  ciss-auth/       pure crypto: id: session + did: service-auth JWT verify, replay
  ciss-resolve/    DID resolution (did:plc/did:web) behind a fail-closed DidResolver
tests/
  e0..e9_*.rs      per-tier behavioral suites (the E0–E9 oracle parity)
  e86_abuse.rs     end-to-end abuse suite (forge/replay/tamper/walkaway/…)
  wiring_*.rs      anti-dead-code gates: s3_metered, pds_blob, contract, persist, checkpoint
  flow_*.rs        the workflow tier (World/Actor personas; incl. flow_atproto_identity)
docs/              ARCHITECTURE.md, DEPLOYMENT.md, SECURITY-POSTURE.md,
                   TESTING-STRATEGY.md, adr/, notes/
```

## Testing & quality gates

```sh
cargo test                              # full suite (unit + wiring + abuse)
cargo test --test wiring_s3_metered     # Phase-7 S3 anti-dead-code gate
cargo test --test wiring_pds_blob       # Phase-8 atproto gate
cargo test --test wiring_contract       # Phase-9 croft-stack contract gate
cargo test --test e86_abuse             # the end-to-end abuse suite
cargo clippy --all-targets -- -W clippy::pedantic -D warnings
cargo fmt --check
cargo mutants --file src/server.rs --file src/blobstore.rs   # mutation gate
cargo mutants --file src/cidv1.rs  --file src/pds_api.rs     # (Phase-8)
```

Discipline: TDD (every wiring test is RED→GREEN), `clippy::pedantic` clean, no
`unwrap`/`expect` on production paths, `Zeroize` on key material, and a
mutation-testing gate (kill real survivors; exclude only genuinely-equivalent
mutants with a rationale in `.cargo/mutants.toml`).

## Deployment

CISS runs as a governed, hardened [croft-stack](https://github.com/CroftCommunity/croft-stack)
tenant behind Caddy TLS. It is fronted on `443` (name-routed by hostname) and
binds loopback-only (`127.0.0.1:8301` in production); the firewall never exposes
its port. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the release model,
the systemd unit + hardening + cgroup governance, the data profile + backup, and
the incident runbook (list / disable / enable a fronted backend).

## Security posture (summary)

- **Verified identity, not asserted.** A caller acts only as a DID it can prove:
  an `id:` signed session, or a `did:plc`/`did:web` **service-auth JWT** (Model R)
  verified against the caller's DID-resolved key. CISS is an atproto resource
  server (it serves its own `did:web:ciss.croft.ing`) — it issues nothing. Writes
  and the meter are owner-only; public reads stay public (PDS-compat). See
  `docs/SECURITY-POSTURE.md` §4 (A1–A7).
- **Untrusted backend.** Layer 1 is never trusted; Layer 2 re-verifies content
  addresses on read, so tamper-at-rest is caught and named.
- **No key leakage.** Signing keys are `Zeroize`d and never `Debug`-printed or
  logged; journald carries only the *public* provider id.
- **Fail loud.** No silent fallbacks — a bilateral receipt at the raw S3 boundary,
  a byte-count mismatch, a bad manifest signature, or a DID/key mismatch are all
  hard errors, not degraded modes.
- **Hardened unit.** In production: unprivileged user, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, full cgroup
  accounting + limits (`systemd-analyze security` ≈ 1.5).

## Provenance & license

CISS graduated from the `discovery` corpus's `item-storage-protocol` experiment
after its network boundary was built (Phases 7–8) and now deploys via croft-stack
(Phase 9). The design record — problem, reasoning, per-phase design, decisions,
and the E0–E9 provenance — lives in `discovery`
(`alpha/plans/2026-07-31-1-plan-coop-metered-storage-service.md`).

See [`LICENSE`](LICENSE).
