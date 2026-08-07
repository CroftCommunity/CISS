# CISS file-sync — M1 execution plan (chunk core + one-device backup/restore)

date: 2026-08-07
status: **Pass 1 + Pass 2 complete; Pass 3 (quality gates) pending in a fresh context, then execute.**
parent: `docs/plans/2026-08-07-file-sync-client.md` (milestone ladder; this doc executes **M1**).
skill: authored under the `phase-plan` three-pass workflow (`coding-agents/skills/phase-plan.md`).

## Problem Statement

Deliver **M1** of the file-sync client: *"back up a directory to CISS and restore it byte-identical,"*
one device + the helper server, judicious with bandwidth (upload only chunks the server lacks). This is the
end-to-end spine that every later milestone builds on — chunking, the filesystem manifest, the have/want
skip, and the keep-set commit. No multi-writer frontier yet (that is M3); M1's frontier is trivial (one
device, tracked client-local). Constraint: CISS v0.5.6 caps objects at 2 MiB, has no Range/multipart/HEAD/304,
and exposes `du`/`listBlobs` as the only body-free "have" set.

## Reasoning

Chunking is mandatory (the 2 MiB cap forces it), and content-defined chunking (FastCDC) makes dedup and
delta the *same* mechanism: "upload the chunks you don't have." We hash each chunk **both** ways in one pass
— sha-256 (CISS's native address) and blake3 (iroh's, for M4) — so the store is transport-ready without a
re-hash later. The filesystem manifest (`path → {mode, mtime, [ChunkRef], size}`) is our one invented
artifact (CISS stores no paths; the S3 `key` is narration). The CISS `Manifest` keep-set (billing) is the
union of chunk cids + the fs-manifest blob cid, committed under the existing monotonic-seq CAS (I5).

**Why a separate `ciss-sync` crate:** keep the sync engine (chunking, manifest, transport, fold later)
separable from the thin `ciss-ctl` CLI and reusable by a future GUI or the meer. The engine core (Phase 1)
is pure/sync; only the transport (Phase 2) is async.

**Alternatives rejected:** fixed-size blocks (shift-sensitive — a 1-byte insert rewrites everything);
rsync rolling-hash delta as the primary (needs a shared base + server-side per-file state — deferred to a
possible large-mutable-file optimization); a bespoke manifest endpoint (the existing `Manifest` slot already
carries a signed, seq-CAS'd keep-set — reuse it).

## Verified Assumptions

- **CISS client API** (`crates/ciss-cli/src/client.rs`): `Client::new(base)`; `put_s3(&session, key, body) ->
  PutResult{cid,bytes,receipt_mode,etag}` (:166); `get_s3(...) -> GetResult{bytes,etag}` verifying the cid
  (:198); `du(Option<&session>, did) -> Usage{objects:[UsageObject{cid,bytes}], total_bytes}` (:509);
  `verify_cid(expected, bytes)` (:615); `session_for(&keypair) -> Session` over `ciss-session/v1/<did>` (:46).
  Auth is the `id:` session where `derive_id(key)==DID` — **one keypair == the namespace**, which *is* the
  shared-account-key model M1 uses. All calls are `async` (reqwest/tokio).
- **Manifest builder** (`src/manifest.rs`): `build_manifest(&[ManifestLeaf], customer_id, customer_key, seq)
  -> Manifest` (:190), `ManifestLeaf::new(cid, size)`; leaves sorted by cid; `size <= MAX_OBJECT_BYTES`
  enforced by `ManifestLeaf::is_valid`. Signing preimage binds `(signer_id, seq, leaf_count, total_bytes,
  root)`; I5 monotonic-seq CAS in `op_put_manifest`.
- **Workspace deps** (`Cargo.toml`): `sha2 = "0.10"`, `rusqlite = "0.32" (bundled)`, `reqwest = "0.13.4"
  (rustls,http2)` present and reusable. **`blake3` and `fastcdc` are NOT present** — new deps (Phase 0 pins them).
- **Server API map** (v0.5.6): 2 MiB `MAX_OBJECT_BYTES`; `PUT/GET /{did}/objects/{key}` addressed by content
  (key is narration, response carries the server-assigned sha256 cid); `du` self-only per-object sizes; no
  Range/multipart/HEAD/304; a signed receipt per transfer.
- **GAP (found in Pass 2): the client has no manifest-PUT method.** `Client` exposes no `put_manifest`; the
  `man` CLI subcommand is `clap_mangen` (man page). Phase 2 must add `Client::put_manifest(&session, &Manifest)`
  → `PUT /{did}/manifest` with `x-croft-pubkey` + JSON body, plus a `get_manifest`.

## Documentation Impact

- `Cargo.toml` (workspace) — add `crates/ciss-sync` to `members`; add `fastcdc`, `blake3` deps. **Phase 1.**
- `crates/ciss-sync/` — new crate; its own `README`/module docs (`#![warn(missing_docs)]`). **Phase 1.**
- `crates/ciss-cli/src/main.rs` + help — new `sync backup|restore` subcommand. **Phases 2–3.**
- `docs/plans/2026-08-07-file-sync-client.md` — link this M1 execution plan under M1. **Phase 1 (cheap).**
- `docs/ARCHITECTURE.md` — if it enumerates crates, add `ciss-sync`. **Phase 1** (grepped: confirm at exec).
- `README.md` — if it lists crates/commands, note the `sync` command. **Phase 3.**
- (If OQ1 → lib extraction) `crates/ciss-cli/src/lib.rs` — expose `client`/`identity` as a lib target. **Phase 2.**

## Concurrency Map

**All phases sequential.** Phase 0 (discovery) → Phase 1 (pure core) → Phase 2 (transport+backup, depends on
core) → Phase 3 (restore, depends on backup). Each phase reads what the prior wrote; no parallelizable subgraph
worth isolating, and the phases share the `ciss-sync` crate write-set. No worktrees.

## Phases

### Phase 0: Discovery
**Goal:** pin the two external deps and confirm the `ciss` crate re-exports, before building on them.
- [ ] **D1: FastCDC crate + params.** Probe: add `fastcdc` (latest 3.x), read its chunker API; confirm
  min/avg/max are configurable and `max < 2 MiB` is settable; confirm pure-Rust, maintained, deterministic
  boundaries. **Success:** a version pinned + the exact constructor/iterator call recorded here. **Disposition:**
  throwaway. *(If sandbox egress blocks the fetch, escalate — user runs `! cargo add fastcdc -p ciss-sync`.)*
- [ ] **D2: blake3 crate.** Probe: add `blake3`; confirm `blake3::hash(&[u8]) -> Hash` + hex/`[u8;32]` access
  and streaming hasher. **Success:** version pinned + API recorded. **Disposition:** throwaway.
- [ ] **D3: `ciss` crate re-exports.** Probe: read `src/lib.rs`; confirm `crypto::{sha256_hex, Keypair}`,
  `identity::derive_id`, `manifest::{build_manifest, ManifestLeaf, Manifest}` are `pub` and reachable from an
  external workspace crate. **Success:** the import paths ciss-sync will use, recorded. **Disposition:** throwaway.
- [ ] **D4: manifest wire contract.** Probe: read `src/pds_api.rs`/`server.rs` `put_manifest_handler` +
  `Manifest` serde; confirm the exact JSON shape and the `x-croft-pubkey` header. **Success:** the request
  shape for the new `Client::put_manifest`, recorded. **Disposition:** throwaway.
- [ ] **D5: DAG-CBOR codec (canonical, deterministic).** Probe: confirm `ipld-core` (already a CISS dep) +
  add a DAG-CBOR codec (`serde_ipld_dagcbor` or equivalent); verify it produces **deterministic** bytes
  (sorted keys, definite lengths) so `content_id` over an `FsManifest` is stable across runs. **Success:**
  crate/version pinned + a round-trip + a byte-determinism check recorded. **Disposition:** throwaway.
**Done when:** D1–D5 recorded in Verified Assumptions with concrete evidence; no BLOCKING unknown remains.

### Phase 1: chunk + content-address core (`ciss-sync` crate, pure, no network)
**Goal:** deterministic chunking + dual-hash + a canonical filesystem manifest, fully unit-tested offline.
**Changes:**
- [ ] new `crates/ciss-sync` (lib); workspace member; deps `fastcdc`, `blake3`, `ciss`, `serde`, `rusqlite`,
  `ipld-core` + a DAG-CBOR codec (`serde_ipld_dagcbor`, pinned in D5).
- [ ] `ChunkRef { sha256:[u8;32], blake3:[u8;32], len:u32 }` (len < 2 MiB, asserted).
- [ ] `chunk_file(bytes) -> Vec<(ChunkRef, Range)>` via FastCDC (**avg 256 KiB, min 64 KiB, max 1 MiB** — see
  Tuning rationale below); single pass computes both sha-256 and blake3.
- [ ] `FsManifest { entries: BTreeMap<Path, FileEntry{mode,mtime,size,[ChunkRef]}> }`.
- [ ] `trait ManifestCodec { encode(&FsManifest)->Vec<u8>; decode(&[u8])->Result<FsManifest> }` with
  **`DagCbor` as the canonical, deterministic encoding** (OQ3). `content_id()` = sha-256 over the **DAG-CBOR**
  bytes — the single addressed identity. A `PrettyJson` **decode-only view** (`inspect`) is non-authoritative
  (never stored, never addressed). Plain JSON is *not* deterministic and is never the addressed form.

**Tuning rationale (FastCDC params — documented per user request 2026-08-07, revisit hooks):** avg 256 KiB
balances **dedup granularity** (smaller = better delta on edits) against **per-chunk overhead** — and on CISS
that overhead is *economic*: each chunk transfer emits a metered receipt, so tiny chunks inflate postage/receipt
count. Max 1 MiB keeps headroom under the hard 2 MiB `MAX_OBJECT_BYTES`. Min 64 KiB avoids pathological tiny
chunks. **Revisit when:** we can measure real dedup ratio on a corpus; if receipt-overhead dominates cost
(raise avg); if large-mutable-file delta is poor (consider an rsync-delta layer, out of M1); if the tariff
changes the postage-per-chunk economics. These are tuning constants behind one config, not a structural choice.
- [ ] minimal local index (rusqlite): `path -> (mtime, size, fs-entry hash)` — the mtime "probably-unchanged"
  fast-path only (correctness never rides on it). Thin; heavier use is M2/M3.
**Call chain:** (engine API) `ciss_sync::scan_tree(dir) -> FsManifest` → `chunk_file` per file. No entry point
yet — Phase 2 wires the CLI. (This phase is a library core; its wiring is Phase 2's `sync backup`.)
**Wiring test:** N/A at CLI level this phase; the integration proof is Phase 2. Phase-1 gate is unit-level.
**Depends on:** Phase 0.
**Read-set:** `Cargo.toml`, `src/lib.rs` (for imports). **Write-set:** `Cargo.toml`, `crates/ciss-sync/**`.
**Shared-state contract:** none beyond the file write-set (pure lib; tests use `tempfile`, no network/ports).
**Risks:** FastCDC param choice affects dedup/receipt-overhead — OQ2; a bad canonical serialization would make
`content_id` unstable — pin it with a golden test.
**Done when:**
1. **Behavioral:** `scan_tree` over a fixture dir yields a stable `FsManifest.content_id`; re-running on
   unchanged bytes yields identical chunk boundaries/hashes; a 1-byte insert changes only local chunks.
2. **Verification:** `cargo test -p ciss-sync` (determinism, 1-byte-insert-locality, `len<2MiB`, manifest
   round-trip + golden content_id).
**Validation:** Narrow → wiring (Phase 2) + unit tests sufficient here. Mutation-test the chunker + serializer
once green (encoder shape — per `CLAUDE.md`).

### Phase 2: transport + backup (`sync backup <dir>`)
**Goal:** push a directory to CISS — upload only missing chunks + the fs-manifest, commit the keep-set Manifest.
**Changes:**
- [ ] `trait BlobTransport { async have(&[sha256])->HaveSet; async put(&ChunkRef,&[u8]); async get(&ChunkRef)->Bytes }`.
- [ ] `HttpCiss` impl: `have` via `Client::du` (the DID's cid set); `put` via `put_s3`; assert the server-returned
  cid == our local sha256 hex (G3). *(OQ1: reuse `ciss-cli`'s `Client` via a lib target, or a thin own client.)*
- [ ] `Client::put_manifest(&session, &Manifest)` + `get_manifest` (the Pass-2 GAP) — `PUT/GET /{did}/manifest`,
  `x-croft-pubkey`, JSON body.
- [ ] backup flow: scan → diff vs `have` → upload missing chunks + fs-manifest blob → `build_manifest(keep-set,
  seq)` → `put_manifest`. seq starts at 1 (or last+1 from `get_manifest`).
- [ ] CLI: `ciss-ctl sync backup <dir>` wired to the flow (entry point).
**Call chain:** `ciss-ctl sync backup <dir>` → `ciss_sync::backup(dir, transport, session)` → `scan_tree` →
`transport.have` → `transport.put`(missing) → `put_manifest`.
**Wiring test (RED→GREEN):** a workflow-tier test (`tests/flow_sync_backup.rs`, World + one Actor against an
in-process CISS) that runs `backup(tmpdir)` and asserts: the fs-manifest cid is stored, the keep-set Manifest
seq advanced, and a *second* backup of the unchanged tree uploads **zero** chunks (have/want skip). This proves
the CLI/engine reaches the server, not just that the chunker works.
**Depends on:** Phase 1.
**Read-set:** `crates/ciss-sync/**`, `crates/ciss-cli/src/client.rs`, `src/manifest.rs`, `src/server.rs`
(manifest handler), test harness `tests/common/**`. **Write-set:** `crates/ciss-sync/**`,
`crates/ciss-cli/src/{client.rs,main.rs}` (+ `lib.rs` if OQ1→extract), `tests/flow_sync_backup.rs`.
**Shared-state contract:** tests bind an ephemeral in-process server port (via the existing harness); no other
ambient state; no git operations.
**Risks:** the manifest-PUT contract (D4) must match exactly or every commit 400s; `du` returns the whole
namespace (fine — have/want only needs "does this cid exist"); async/sync boundary between the pure core and
the transport.
**Done when:**
1. **Behavioral:** `ciss-ctl sync backup <dir>` uploads the tree once; a re-run transfers zero chunks; the
   namespace's keep-set Manifest reflects the tree.
2. **Verification:** `cargo test -p ciss --test flow_sync_backup` (the wiring test above) + a live smoke:
   `sync backup` against the in-process server, then `du` shows the chunks.
**Validation:** Moderate → wiring + unit + exercise the CLI against the in-process server; confirm zero-chunk
re-backup outside the harness.

### Phase 3: restore + verify (`sync restore <dir>`)
**Goal:** reconstruct a backed-up tree byte-identically from the server, verifying every chunk.
**Changes:**
- [ ] restore flow: locate the fs-manifest (cold-restore discovery, OQ5) → fetch its chunks via `transport.get`
  (each `verify_cid`'d) → rebuild files with `{mode, mtime}` → write atomically.
- [ ] CLI: `ciss-ctl sync restore <dir>`.
- [ ] cold-restore fs_root discovery: from the keep-set Manifest, scan small leaves for the self-tagged
  fs-manifest (M1's rare path; the discoverable `heads` field is M3).
**Call chain:** `ciss-ctl sync restore <dir>` → `ciss_sync::restore(dir, transport, session)` → find fs-manifest
→ `transport.get`(chunks, verify) → materialize tree.
**Wiring test (RED→GREEN):** `tests/flow_sync_roundtrip.rs` — World/Actor: `backup(src)` then wipe then
`restore(dst)` → `dst` is **byte-identical** to `src` (content + mode; mtime within tolerance). The end-to-end
capability gate for M1.
**Depends on:** Phase 2.
**Read-set:** `crates/ciss-sync/**`, `crates/ciss-cli/src/client.rs`. **Write-set:** `crates/ciss-sync/**`,
`crates/ciss-cli/src/main.rs`, `tests/flow_sync_roundtrip.rs`.
**Shared-state contract:** as Phase 2 (ephemeral in-process server; tempdirs).
**Risks:** a corrupted/substituted chunk must fail closed (`verify_cid`); cold-restore scan cost if the
namespace is large (acceptable for M1; the M3 `heads` field removes it).
**Done when:**
1. **Behavioral:** back up a tree, wipe local, `sync restore` reproduces it byte-identically; a tampered chunk
   is rejected, not written.
2. **Verification:** `cargo test -p ciss --test flow_sync_roundtrip` + a manual `backup`→wipe→`restore` diff.
**Validation:** Moderate → wiring + unit + a real backup→restore diff outside the harness.

## Open Questions — all RESOLVED 2026-08-07 (user)

- **Crate topology** — **RESOLVED: reuse `ciss-cli`'s `Client` via a lib target.** Avoids duplicating the
  metered-call + `verify_cid` path (the repo already links `ciss` into the client to stop crypto drift).
  Phase 2 gives `ciss-cli` a `lib.rs` exposing `client`/`identity`; `ciss-sync` depends on it.
- **FastCDC params** — **RESOLVED: avg 256 KiB / min 64 KiB / max 1 MiB to start, with the What/Why documented**
  (see Phase 1 "Tuning rationale" + revisit hooks) so future tuning is a reflected decision, not a silent constant.
- **fs-manifest serialization** — **RESOLVED (corrected): DAG-CBOR is the canonical, deterministic addressed
  encoding** (determinism is *required* for content-addressing; plain/pretty JSON is not deterministic).
  Serialization is **pluggable** behind a `ManifestCodec` trait, but the addressed identity (`content_id`) is
  defined over the DAG-CBOR bytes; a pretty-JSON `inspect` view is a non-authoritative decode-only render.
  (Supersedes the Pass-1 "JSON for M1" recommendation.)
- **Cold-restore discovery** — **RESOLVED: small-blob scan for M1.** Cold restore is disaster-recovery-only (a
  live device knows its `fs_root` locally); no server change is justified for M1 when the explicit `heads` field
  at M3 removes the discovery step structurally.

## Review Log

- **2026-08-07 Pass 1** — Base plan authored from the M1 slice of the milestone plan. Phases 0–3, reasoning,
  concurrency map (all-sequential), documentation impact.
- **2026-08-07 Pass 2 (same context)** — Gap analysis against the codebase. Findings folded in:
  (G1) **client has no manifest-PUT** — `man` is clap_mangen, not manifest; added `Client::put_manifest`/`get_manifest`
  to Phase 2 + to Verified Assumptions as the load-bearing gap. (G2) crate topology → OQ1. (G3) `put_s3`
  returns a server-assigned cid — Phase 2 asserts it equals the local sha256 (guards a silent addressing drift).
  (G4) `du` is whole-namespace — fine for have/want (existence check only); noted. (G5) async transport vs pure
  sync core — boundary drawn at Phase 1/2. (G6) local index not required for M1 correctness (full scan +
  have/want already prevents re-upload) — scoped to a *minimal* mtime fast-path in Phase 1, heavier use deferred
  to M2/M3. Documentation Impact expanded (Cargo workspace member, ARCHITECTURE, possible lib extraction).
- **2026-08-07 Open-question resolution (user)** — OQ1 reuse `Client` via a `ciss-cli` lib target. OQ2 params
  avg 256 KiB/min 64/max 1 MiB, with the What/Why + revisit hooks documented in Phase 1. **OQ3 corrected:
  DAG-CBOR is the canonical deterministic encoding** (user flagged that determinism is required and DAG-CBOR
  is the deterministic option) — serialization pluggable via a `ManifestCodec` trait, `content_id` over the
  DAG-CBOR bytes, pretty-JSON only as a decode-only `inspect` view; added **D5** (pin the DAG-CBOR codec) and a
  DAG-CBOR dep to Phase 1. OQ4 scan-for-M1 (cold restore is disaster-recovery-only; the `heads` field at M3
  removes the step). No phase reordering; changes are additive.
- **Pass 3 — PENDING (fresh context):** TDD ordering (RED-first for each wiring test), observability/diagnostic
  logging in the backup/restore flow, validation calibration, Documentation-Impact coverage check. Then execute.
