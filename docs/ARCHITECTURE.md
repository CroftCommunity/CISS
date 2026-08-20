# CISS architecture

How CISS is put together, why the pieces are shaped the way they are, and where
the deliberate seams for future work sit. For the operational/deploy view see
[`DEPLOYMENT.md`](DEPLOYMENT.md); for the API surface see the [README](../README.md).

## 1. The two-layer split

The whole design turns on one principle — **meter the boundary, not the machine** —
which forces a strict separation:

```
   ┌─ Layer 2: the metered boundary (server.rs, pds_api.rs, cidv1.rs) ─────────┐
   │  · authenticates the caller to a verified Principal (ciss-auth,           │
   │    ciss-resolve) before it acts — see §4a                                 │
   │  · content-addresses bytes (SHA-256) and RE-VERIFIES them on read         │
   │  · signs a receipt for every transfer (postage)                           │
   │  · derives rent from the customer's OWN signed manifest                    │
   │  · owns all provenance: the two parties' keys + the manifest              │
   └───────────────────────────────┬───────────────────────────────────────────┘
                                    │ BlobStore trait (put/get/has by (DID,CID))
   ┌────────────────────────────────▼──────────────────────────────────────────┐
   │  Layer 1: the dumb backend (blobstore.rs)                                   │
   │  · holds bytes under a key; that is ALL                                     │
   │  · never meters, never content-checks, never trusted                       │
   │  · MemoryBlobStore (tests) · FsBlobStore ({root}/blocks/{did}/{cid})        │
   └─────────────────────────────────────────────────────────────────────────────┘
```

**Why the backend is dumb on purpose.** If the backend could meter or vouch for
content, then trusting the bill would mean trusting the storage — exactly the
thing a non-extractive co-op can't ask its members to do. By keeping Layer 1
incapable of provenance, a compromised, buggy, or third-party backend (R2, a
community Garage node) still cannot forge a receipt, inflate rent, or serve a
tampered blob past the Layer-2 re-verify. The backend is swappable precisely
because nothing depends on it being honest.

## 2. The metered byte-path

Every request enters through an `Op`-dispatch boundary (`server::dispatch`) so a
future per-DID compute-observability wrapper (see §7, E83) has one attach point.
Both the S3 plane and the atproto plane route through the *same* dispatch, so
they meter identically.

**PUT / uploadBlob (upload):**
0. **Authenticate + authorize.** `uploadBlob` resolves the caller to a verified
   `Principal` — a `did:` service-auth JWT (Model R) or an `id:` signed session —
   and acts only as that DID; an unverified caller is `401`. See
   `SECURITY-POSTURE.md` §4 (A1–A7).
1. `cid = sha256_hex(bytes)` — the boundary computes the content address.
2. `blobs.put(did, cid, bytes)` — Layer 1 writes and reports the byte count.
3. **Byte-count integrity check:** the boundary byte count must equal what the
   backend persisted, or it is a loud `500` (never a silent tally).
4. A provider-signed **Unilateral** receipt (`Direction::Upload`) is appended to
   the DID's ledger, carrying the running total.

**GET / getBlob (download):**
0. **Authorize the read (gated reads).** `dispatch` resolves the target's read
   policy and checks membership: `world` (the default) allows anyone; a gated
   target admits only the owner or a listed grantee, and a denied read is a **404**
   (oracle-free), never the bytes. Reads authenticate the caller so a grantee is
   recognized: the atproto `getBlob` accepts an `id:` session **or** a `did:`
   service-auth JWT (bound to the read method); the S3 `GET /{did}/objects/{cid}`
   authenticates an `id:` session only (a `did:` grantee reads via `getBlob`). See
   `SECURITY-POSTURE.md` §5 (Z4–Z8) and `docs/spec/gated-reads.md`.
1. `blobs.get(did, cid)` returns the raw stored bytes (unverified — dumb backend).
2. Layer 2 **re-fingerprints** them: if `sha256(stored) != cid`, that is
   tamper-at-rest → a loud `500` naming the object, *not* a served bad blob.
3. A provider-signed **Download** receipt is appended.

Policy is set on a dedicated surface (`PUT/GET /{did}/policy` and
`/{did}/assertion/policy/{cid}`) by submitting an owner-authorized policy assertion (the `policy` kind on the self-assertion substrate, `src/assertion.rs`)
(`id:` owner self-signs; `did:` owner authorizes via a service-auth JWT that CISS
provider-attests). `listBlobs` filters the same way — hidden cids are omitted.

`GET /{did}/meter` reports the ledger totals (upload/download bytes, running
total, postage cents, and `drawdown_download_bytes` — the separable "drain"
line: bytes downloaded while the account was in drawdown, fully counted in
`download_bytes` too, surfaced so statement-time billing judgment has a
figure to act on). Totals are served from an O(1) per-DID cache maintained
atomically with each receipt (invariant B5); the receipt ledger stays the
source of truth — the cache backfills from it and must always equal a full
scan.

Every receipt core also carries the **account mode in effect at transfer
time** (`account_mode`, signed into the content hash), so a transfer's
accounting class — today `active`/`drawdown`, the seam for future classes
like service/bot/staff — is an attested fact, not a mutable server-side
annotation.

### Receipt modes (Unilateral vs Bilateral)

A receipt is two-mode: **Unilateral** (provider-signed, our-side measurement) or
**Bilateral** (co-signed by both parties). Unilateral is the default; the
customer opts into Bilateral with the `dial.receipt-mode` assertion (D4), after
which every metered transfer yields a provider-signed **partial** awaiting the
customer's countersignature — `POST /{did}/receipt/{hash}/countersign` completes
it into a doubly-signed fact verifiable offline under the two keys published in
the well-known `did.json` (`#receipts` + the customer's own). The walkaway case
is tolerated by design: an uncountersigned partial stays a valid our-side
measurement. Bilateral is the co-attested form the deferred capital layer will
require. (Historical: Bilateral was a hard `BilateralUnsupported` 501 until the
D4 dial unstubbed it — a loud seam, never a silent downgrade.)

## 3. Content addressing and the CIDv1 bridge

Internally CISS addresses content by a bare hex SHA-256 (the backend key). The
atproto network, however, expects a real **CIDv1** in `blob.ref.$link` — `raw`
codec (`0x55`) over a sha-256 multihash. `cidv1.rs` bridges the two losslessly:
the 32-byte digest lives inside the multihash, so

```
blob_cid_string(bytes)  ==  from_sha256_hex(sha256_hex(bytes))
to_sha256_hex(cidv1)    ==  the backend hex key
```

`to_sha256_hex` rejects anything that is not a CIDv1 `raw` + sha-256 CID (wrong
version, codec, or hash algorithm) rather than coercing it — a bad `cid=` query
is a `400`, never a mis-keyed lookup. This closes the one deliberate simplification
the original experiment carried (`SEAM:` hex-for-CID), using the in-corpus
`ipld-core` path that is byte-identical to real PDS records.

`listBlobs` needs no backend enumeration primitive: it derives a DID's uploaded
CIDs from that DID's **upload receipts** in the ledger, then maps each hex key to
its CIDv1.

## 4. The E0–E9 ledger model

The metering machinery is the proven `item-storage-protocol` core, ported
module-by-module under TDD. In dependency order:

- **crypto / identity (E0).** An actor *is* an Ed25519 keypair; its identifier is
  derived from its public key (`derive_id`), so identity and key are one fact and
  no external key registry is needed — a manifest PUT verifies
  `derive_id(presented_key) == claimed_did`. Signing keys are `Zeroize`d.
- **item + manifest (E1–E2).** An **item**'s name is the fingerprint of its bytes
  (content-addressed; change a byte, change the name). A **manifest** is the
  customer's signed Merkle list of `(cid, size)` leaves — the authoritative
  statement of *what the provider is supposed to be holding*, and the rent base.
  Rent is a pure function of this customer-authored document.
- **receipts + ledger (E3).** Each transfer yields a signed **receipt**; receipts
  append to a hash-linked, per-actor **ledger**. Nothing is edited in place — a
  forged or replayed receipt breaks the chain and is caught.
- **statements (E4).** A monthly balance-forward **statement** nets `opening root
  + Σ receipts + byte-days = closing root`; a **rollup/purge** compacts settled
  history. Rent is the **byte-day** integral (bytes-at-rest × days) over the
  manifest.
- **audit + dial (E5–E6).** A **spot-check audit** samples `k` items uniformly at
  random (seeded, deterministic RNG) and applies the detection math
  `1 − (1 − f)^k`; the **dial** turns assurance into a *priced, signed* setting —
  more assurance costs linearly more, and the choice is on the record.
- **seal + tombstone (E7–E8).** **Sealing** pins a root for cold storage where the
  plan is "no movement, verification proves it"; the **tombstone** ceremony is the
  fail-closed key-destruction path. Both are pin-a-root, fail-closed ceremonies.
- **grace (E9).** Mercy is *in the books, not off-book*: a co-signed **grace**
  event that nets to zero, so a waived charge is auditable rather than a silent
  adjustment.

`canonical.rs` defines the single canonical byte-string every signature and hash
is taken over (so two peers hash the same bytes); `pricing.rs` keeps every figure
in integer cents; `clock.rs` and `rng.rs` are deterministic so every assertion is
exact.

## 4a. Identity & authentication

Layer 2 authenticates the caller to a verified `Principal` before it acts. There
are two identity spaces, kept distinct by type, and two crates that keep the
crypto isolated from the network:

- **`id:<64-hex>`** — this codebase's native space (`"id:" ++ SHA-256(pubkey)`).
  A caller proves possession by signing a session challenge; no external
  resolution. Verified by `ciss-auth::verify_session`.
- **`did:plc` / `did:web`** — atproto identities (Model R). A caller presents a
  **service-auth JWT** (a short-lived compact JWS minted by
  `com.atproto.server.getServiceAuth`, `iss`=caller DID, `aud`=CISS's
  `did:web:ciss.croft.ing`, `lxm`=method, ~60s `exp`) signed by the caller's repo
  key. CISS **resolves** the `iss` DID to its signing key and **verifies** the JWT
  against it — it issues nothing (resource-server, not an issuer).

The split by crate is deliberate: **`ciss-auth`** is pure crypto (no network) — it
verifies a signature against a key it is handed; **`ciss-resolve`** owns all
network/cache/timeout (did:plc via `plc.directory`, did:web via `.well-known`)
behind a `DidResolver` trait, resolving fail-closed with a TTL cache and a pinned
admin-DID break-glass set. On the client side, **`ciss-cli`** is the reference
client (`ciss-ctl`), and **`ciss-sync`** is the file-sync engine (content-defined
chunking, dual sha-256/blake3 chunk refs, the canonical DAG-CBOR fs-manifest) —
pure core, no network; the sync transport rides `ciss-cli`'s `Client`
(plan: `docs/plans/2026-08-07-file-sync-m1-chunk-and-backup.md`). CISS serves its own did:web document at
`GET /.well-known/did.json`, and OAuth resource-server discovery (RFC 9728) at
`GET /.well-known/oauth-protected-resource` — the pointer half only: it names
bsky as the AS, but CISS does not yet accept OAuth tokens (the verification
half is parked; `docs/notes/pds-capability-gap.md`, ROADMAP_TODO E101). Full
trust model + invariants: `SECURITY-POSTURE.md`
§4 (A1–A7); design: `docs/notes/atproto-integration-model.md`; decision: ADR 0001.

## 5. Persistence

Per Phase-0 discovery, storage mirrors the official-PDS **per-actor SQLite**
layout:

- `meter.sqlite` (**canonical**, WAL) co-locates each DID's `manifest`,
  `receipt`, and `statement` rows, keyed by the `did` column, plus a small `meta`
  key/value table.
- The **provider signing seed is never stored in the database** (finding I8). It
  is supplied by the unit as a secret — a systemd credential
  (`$CREDENTIALS_DIRECTORY/provider-seed`) or `CISS_PROVIDER_SEED` — and under
  systemd the service **fails closed** if neither is present. Only the provider's
  **public** key is persisted to the `meta` table, as a durable verification
  anchor so historical receipts stay verifiable across a key rotation or loss. See
  `SECURITY-POSTURE.md` §9 (S1/S2).
- A `rusqlite::Connection` is `!Sync`; v0 resolves this with a single-writer
  `Arc<Mutex<Store>>`. `SEAM:` a real deployment shards a `Store` per DID behind a
  small pool.
- On graceful shutdown, `wal_checkpoint(TRUNCATE)` flushes the WAL so a restart
  opens a clean database (E87).

Blob *bytes* never enter SQLite — they stay in the Layer-1 backend, keyed
`(DID, CID)`.

### 5.1 Comparison: the reference-PDS storage split

The official atproto reference PDS (TypeScript `@atproto/pds`) in SQLite mode
makes the same database/blob split CISS makes, and the correspondence is worth
stating precisely because the dividing line is **records vs blobs, not
structured vs content-addressed**: the reference PDS stores repo *record blocks*
(MST nodes, commits, records — CBOR bytes, themselves CID-addressed) as rows
*inside* the per-actor SQLite, while blob (media) bytes never enter any
database. Content addressing alone does not decide where bytes live.

| | Reference PDS (SQLite mode) | rsky-pds | CISS |
|---|---|---|---|
| Structured / canonical state | per-actor `actors/{sha256(did)[0..2]}/{did}/store.sqlite` + service DBs (`account.sqlite`, `sequencer.sqlite`, `did_cache.sqlite`) | per-actor SQLite | `meter.sqlite` (per-DID rows, one file — v0 single-writer, §5) |
| Repo record blocks (CID-addressed CBOR) | rows **in** the actor SQLite (`repo_block`, `record`, `repo_root` tables) | in SQLite | n/a — CISS has no repos/records |
| Blob bytes | `DiskBlobStore` `{location}/{did}/{cid}` with tmp staging (random-keyed) + a quarantine tree; or `S3BlobStore` (`@atproto/aws`) | filesystem `blocks/{did}/{cid}` | `FsBlobStore` `{root}/blocks/{did}/{cid}` + `{root}/tmp/{did}/{cid}` (mirrors rsky-pds) |
| Blob metadata | `blob` table (cid, mimeType, size, tempKey, createdAt, takedownRef) + `record_blob` for record↔blob refs | in SQLite | derived from upload **receipts** in the ledger (`listBlobs`, §3) |
| Blob-store abstraction | `BlobStore` interface (disk / S3) | — | `BlobStore` trait (`Fs` / `Memory`), dumb Layer 1, re-verified by Layer 2 |

Reference-PDS specifics verified against `bluesky-social/atproto` `main`
(2026-08-11): `packages/pds/src/actor-store/actor-store.ts` (`getLocation`:
actor dir sharded by the first two hex chars of `sha256(did)`, db file
`store.sqlite`), `packages/pds/src/config/config.ts` (service-DB filenames
under `dataDirectory`), `packages/pds/src/disk-blobstore.ts` (blob/tmp/
quarantine path construction), `packages/pds/src/actor-store/db/schema/`
(the seven actor tables incl. `repo_block`, `blob`, `record_blob`), and
`packages/aws/src/s3.ts` (`S3BlobStore`).

Two deliberate divergences, both simplifications CISS's scope permits:

- **No records means a cleaner line.** With no repo layer, CISS's split
  degenerates to "everything structured in `meter.sqlite`, all content bytes
  under `blocks/`" — the reference PDS's subtlety (CID-addressed bytes on both
  sides of the line) does not arise here.
- **Blob metadata is not a table.** Where the reference PDS maintains a `blob`
  table as its blob index, CISS derives the blob index from the signed upload
  receipts already in the ledger (§3, `listBlobs`). The metering ledger *is*
  the blob metadata — one authoritative surface instead of a table that could
  drift from it.

What is mirrored on purpose: the per-actor SQLite orientation (Phase-0
discovery, above), the `blocks/{did}/{cid}` on-disk layout (byte-compatible
with rsky-pds's), and the swappable blob-store seam (the reference PDS's
disk/S3 choice is the same seam as `Blobs::Fs`/`Memory`; an S3-shaped backend
would attach at the `BlobStore` trait, §7 E84).

## 5a. The storage model: six declared axes

Everything CISS stores is one record family sitting at a declared point in a
small semantic space. This framing (ADR 0005, owner-directed 2026-08-11)
replaces the earlier build-by-use-case accretion: a new stored thing picks a
point on six axes instead of hand-rolling behaviour, and the cross-inspection
below shows every existing surface already fits.

| Axis | Values | The question it answers |
|---|---|---|
| **Retention** | `setting` · `immutable` · `log` · `chain` | Does history exist, and how? `setting`: latest wins, old value replaced. `immutable`: write-once per key, never updated (content-addressed bytes). `log`: append-only rows, integrity via periodic roots rather than per-entry links. `chain`: append-only + each entry binds its predecessor's hash. |
| **Authorship** | `derived` · `owner-signed` · `provider-signed` · `co-signed` | Whose statement is this? `derived` records are unsigned, rebuildable caches of signed data — never authoritative. |
| **Erasure** | `erasable` · `permanent` | Is true removal offered? `chain` implies `permanent` (until a checkpoint); the seal **tombstone** tier is `permanent` enforced by *destroying the unseal capability* — the axis's extreme point, already shipped. |
| **Enumeration** | `listable` · `point-only` | Can the owner list their keys, or is knowing the key the price of asking? `point-only` is a privacy stance, chosen on purpose. |
| **Hashing** | `fold-bound` · `chain-linked` · `merkle-rooted` · `content-addressed`, × algorithm | What does the hash commit to — a canonical serialization, the predecessor, a set, or the identity itself? The **algorithm is declared**: SHA-256 throughout CISS; BLAKE3 where content interoperates with iroh file transfer. The split is deliberate ecosystem alignment. |
| **Sizing** | body ceiling, growth: `bounded` · `rolling` · `unbounded` | Nothing is assumed infinite. `rolling` = compaction behind **acknowledged** checkpoints (the statements rollup/purge boundary, generalized). `unbounded` exists only as a visible choice. |

The whole store, classified:

| Surface | Retention | Authorship | Erasure | Enumeration | Hashing | Sizing |
|---|---|---|---|---|---|---|
| blobs (`blocks/{did}/{cid}`) | immutable | owner-submitted, boundary-verified | erasable | listable (manifest/`du`) | content-addressed / SHA-256 | store + per-DID ceilings |
| `manifest` | setting | owner-signed | erasable | n/a (one per DID) | **merkle-rooted** / SHA-256 (root over `(cid,size)` leaves) | grows with item count — ceiling applies |
| `receipt` | **log** | provider- or co-signed | permanent **until settled** | listable (self-only) | fold-bound / SHA-256 | **rolling** — `purge_receipts_settled_through` drops rows behind a settled statement |
| `statement` | **chain** | co-signed | permanent | listable (self-only) | chain-linked + merkle-rooted / SHA-256 | rolling (it *is* the checkpoint layer) |
| ledger entries (incl. grace) | chain | co-signed | permanent | listable per actor | chain-linked / SHA-256 | rolling via statements |
| `did_total` | setting | **derived** (rebuildable from receipts) | erasable | n/a | none | bounded |
| `meta` | setting | derived / provider-internal | erasable | n/a | none | bounded |
| assertions (`policy`, `dial.*`, `kv.flag`) | setting | owner-signed or provider-attested, provider-acked | per kind (ADR 0005) | per kind | fold-bound / SHA-256 | small ceiling, bounded |
| seal declarations | setting | owner-signed | tombstone tier: **capability destroyed** | point-only | fold-bound over a pinned root | bounded |
| `chain.counter` (ADR 0005, A3–A4) | chain | owner-signed, provider-acked | permanent | listable | chain-linked / SHA-256 | rolling — checkpoints compact behind an acked checkpoint; policy `on_ack` (default) or `deferred` to a billing-marker call |

What the cross-inspection taught (and fed back into ADR 0005): retention needed
four values, not two (blobs are `immutable`, receipts are a `log`); authorship
was a latent sixth axis the substrate's Model A/C already half-encoded; the
manifest's Merkle root is a fourth hashing posture; and the checkpoint/
compaction design for chains is a **port of shipped practice** (the statements
rollup/purge boundary), not an invention. The queue work layering on CISS
(meer, custodian chains) slots in as future `log`/`chain` rows — the axes are
the vocabulary for that conversation too.

## 6. Trust boundaries / threat model

| Actor / surface | Trusted for | NOT trusted for | Caught by |
|---|---|---|---|
| Layer-1 backend | holding bytes | content, provenance, integrity | Layer-2 re-verify on read |
| The customer | signing their manifest | the byte counts (provider measures) | provider-signed receipts |
| The provider | signing receipts | rent (customer's manifest is the base) | customer recomputes rent independently |
| The network | delivering requests | anything | signatures + content addressing |

The abuse suite (`tests/e86_abuse.rs`) actively drives the live engine to break
it: forge/replay receipts, inflate the manifest, tamper at rest across the
boundary, walk away mid-transfer, double-count an audit, feed malformed input.

## 7. Deliberate seams (deferred, not stubbed)

Marked `SEAM:` in code and tracked in `discovery/ROADMAP_TODO`:

- **E83 — per-DID compute observability.** All requests route through
  `server::dispatch`; `Op::is_heavy()` classifies each op. **Stage 1 shipped
  2026-08-19** (`docs/notes/rate-limiting-design.md` §5): every dispatch is
  timed and attributed per caller × op class into a bounded in-memory ledger
  (`src/compute.rs`), flushed to the derived `compute_usage` table
  (periodically + at checkpoint) and surfaced by `ciss usage`. Remaining
  stage-1 increments: component timers, mutex-hold, poll-time, an auth-fail
  class. The cgroup-scoping half of the seam is unchanged: v0 ops are all
  cheap (never cgroup-scoped), and the attach point still awaits a *heavy* op
  (CAR export, MST rebuild, audit sampling).
- **E84 — kernel-perf backend.** `FsBlobStore` uses `write` + atomic
  same-filesystem `rename` (temp→permanent). The `BlobStore` trait is the attach
  point for an `io_uring`/`copy_file_range`/reflink backend. **On the production
  box this is N/A:** the filesystem is ext4 (no CoW/reflink), so temp→rename is
  the whole story there.
- **E85 — object index structure.** v0 uses a flat keyspace; MST/RBSR grouping is
  tracked.
- **E87 — zero-downtime upgrade.** The binary can inherit a systemd
  socket-activation fd and drains on SIGTERM. v0 ships the *lean* strategy
  (graceful drain + Caddy request-retry, see DEPLOYMENT.md); socket-activation /
  `SO_REUSEPORT` blue-green is the stretch.
- **getBlob Content-Type echo.** UNCONFIRMED in the lexicon; v0 returns
  `application/octet-stream` rather than guess the echo behavior.

Each seam is a real, load-bearing classification point — not a placeholder that
silently does nothing.
