# CISS file-sync — M1 execution plan (chunk core + one-device backup/restore)

date: 2026-08-07
status: **EXECUTING (2026-08-07).** Passes 1–3 + foundations review done; OQ1–OQ6 resolved.

## Outcome Summary

| Phase | Outcome | Commit | Note |
|---|---|---|---|
| 0 discovery | ✅ | `6515155` | fastcdc 4.0.1 / blake3 1.8.6 / serde_ipld_dagcbor 0.7.0 pinned; probes green |
| 1 core | ✅ | `410fd9b` | `ciss-sync` crate; 17 tests RED→GREEN; mutants 34/0 missed (chunk+manifest) |
| 2 backup | ✅ | `8348a58` | `sync backup` end-to-end; flow tests + I5/G3/resume guards; live smoke green |
| 3 restore | ⏳ | — | |
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

## Foundations & corpus tie-in (deep review 2026-08-07, post-Pass-3)

A dedicated review pass verified this plan against the Croft/Drystone corpus (`discovery/`:
`beta/drystone-spec/`, `beta/impl/drystone-design/`, `alpha/thinking/`, COHESION §67, ROADMAP E90/E89/E82/E85)
and the CISS posture doc. Summary: **the foundations hold** — the design M1 executes is the one registered in
the seam-tracker, and the CISS substrate is the one the corpus specified. Where M1 deviates from the corpus,
the deviations are now *owned* below (each with its bridge back), rather than silently inherited. Three
concrete plan changes fell out (self-tag field, interrupted-resume test, pre-transfer pricing log — see the
Review Log entry).

### The CISS substrate is the one the corpus specified

CISS is not an incidental backend. The 2026-07-31 coop-metered-storage plan specified it as "one metered,
content-blind, network-accessible store under **two** consumers — PDS blob hosting and history convergence"
(`discovery/alpha/plans/2026-07-31-1-…:43`), with the client-side obligations M1 now inherits: the client
holds the keys, signs its own manifest (the rent basis), and the boundary emits signed receipts per transfer.
E82 (the CISS lane) is **shipped and live** — M1 is its first real dogfooding client.

The plan's guards map one-to-one onto posture invariants (`docs/SECURITY-POSTURE.md`):

| CISS invariant | M1 counterpart |
|---|---|
| **C1** server names content by hash | G3 guard: server-returned cid must equal local sha-256 (`server_cid_matches_local`) |
| **C2** tamper-at-rest caught on read | client-side twin: `verify_cid` on every receipt; `tampered_chunk_rejected` fails closed |
| **B1/B2** manifest binds claims; unambiguous Merkle | the keep-set rides `build_manifest` unchanged — nothing re-derived client-side |
| **B3 (= I5)** strictly-newer seq | the commit spine (`keep_set_advances_under_i5`) — and the only ordering the frontier will ever get from the server |
| **B4** per-transfer signed receipts | why chunk size is an *economic* parameter (see Economics below) |

### The seam is registered (COHESION §67 / E90 / E85)

COHESION §67 carries this exact design as the "CISS file-sync client lane": chunking mandatory under the
2 MiB cap, `du`/`listBlobs` as the free have/want set, the I5 seq-CAS as the safe multi-device commit, the
sha256/blake3 dual-name bridge, HEAD = per-device signed Frontier folded locally (never asserted), one
additive server change at M3, the M1→M5 ladder verbatim. M1 advances **E90** directly and dogfoods **E82**;
**E89** (cost twin) stays at M5 by design. **E85** ("keep manifest/index addressing pluggable") is the reason
the `ManifestCodec` trait exists — it is the registered seam, not engineering taste. Two wording
reconciliations against E90:

- **E90 says "authing via a bsky app-token."** M1 uses the `id:` session instead — this is structural, not
  drift: the keep-set Manifest must be *signed by the namespace key* (`derive_id(key)==DID`), so
  key-possession is required on the write path regardless. The app-token/`did:`-JWT path is the read-side /
  service-auth surface; it becomes relevant for gated reads, not the backup spine.
- **DAG-CBOR appears nowhere in E90/§67** (E90 says only "serialized as its own content-addressed blob") —
  the canonical codec is *this plan's own pin* (OQ3), made safely behind the E85 seam (below).

E90's decision "timestamps are an assertion, never authoritative between nodes" is honored structurally:
`mtime` is a fast-path hint (correctness never rides on it), restored as metadata, and never enters
ordering or conflict resolution (the fold tiebreak at M3 is content-address).

### What M1 instantiates from Drystone — and what it defers

The milestone plan calls this client "the first concrete instance of the corpus's parked frontier
machinery." Precisely scoped, that means:

- **The dial is right.** File sync sits at the *dataplane* strictness dial — recoverable, reads-never-gated
  (`liveness-freshness.md:168`) — which the corpus marks as the looser case. That is exactly why the file
  surface is the right first instance.
- **The frontier shape is faithful.** The corpus dataplane frontier is `{device-subspace → (head digest,
  high-water counter)}` over single-writer subspaces (`history-durability.md §I`); the milestone plan's
  `Frontier{heads: device_id → cid(DeviceHead)}` is that structure. Two devices of one persona are two
  subspaces — which is what makes the M3 commit non-lossy by construction.
- **The HEAD doctrine is the corpus's, verbatim.** "No point at which a participant accepts another's
  declared state without local validation" (part-2 §7.3.3); the substrate "never renders a verdict." The
  seq-CAS'd manifest slot orders writes; it never *decides* the tree. M1's trivial single-device frontier
  changes nothing about this — it just makes the fold a no-op.
- **Conflict handling at M3 matches fork-is-escalation.** The corpus treats equal-position divergence as a
  contradiction to surface (both branches preserved, attributed), never something a fold silently resolves.
  Conflict-copy *is* that: both contents kept, tiebreak by content-address, no clock ever consulted.
- **What M1 does not earn — said plainly.** `completeness-ahead` is the corpus's named "load-bearing,
  unearned" beam and `LocateLatest` is an explicitly non-normative proposal. M1 claims neither: it builds
  the chunk/manifest/keep-set substrate a frontier instance needs; M3 exercises the trivial-made-real
  version; the beam itself stays open in the corpus. Backfill admission (contiguity + standing, not
  signature alone) and freshness honesty ("a behind device looks behind") become live obligations at M3,
  not M1.

### Deliberate deviations from the corpus (owned, with bridges)

1. **Hash-suite inversion.** Drystone commits to **BLAKE3** as the single suite, with SHA-256 "the legacy
   side, retired at the wire-freeze." M1 inverts: sha-256 is the native address (because CISS C1 addresses
   by sha-256, and the corpus's own §4 proofs currently stand on SHA-256), blake3 computed alongside. The
   dual-hash `ChunkRef` **is the migration bridge**: every stored byte is already blake3-named, so when the
   corpus's wire-freeze lands, the store is transport-ready without a re-hash. This is the plan's central
   dual-name bet, and it is the corpus-aligned direction of travel, not a divergence from it.
2. **Domain separation in the content_id pre-image.** Corpus §4.2 requires tagged, domain-separated hash
   pre-images (untagged is a named disqualifier). The *address* of the fs-manifest blob must remain the
   server-computed CISS cid (C1 — the server names content), so the tag moves inside the bytes: `FsManifest`
   leads with a `kind: "croft.fs-manifest/v1"` self-tag field, making the hashed pre-image domain-separated
   and versioned. (Phase 3's cold-restore "self-tagged" scan already assumed this; the field is now
   specified in Phase 1 where it belongs.)
3. **`mtime` inside a hashed artifact.** The corpus bars wall-clock from identity/ordering/authority
   computations, while allowing asserted time as payload. The fs-manifest is *payload* — a backup artifact
   whose identity legitimately covers the metadata it restores. Consequence accepted: identical content
   with different mtimes yields different content_ids (an address change, never an ordering input).
4. **Content-indifferent is not content-blind.** In the corpus, "content-blind" is a *cryptographic*
   property (key-withholding, sealed blobs, envelope minimality). M1 is **plaintext v1** (E90 decision:
   encryption is a pure client layer, zero server impact, deferrable). So CISS in M1 is content-
   *indifferent* — it never parses, folds, or decides — but not corpus-content-blind. The blind-store
   discipline becomes binding if/when client-side E2EE lands (out of M1–M5).
5. **Byte-layout pinning vs the corpus's wire-freeze discipline.** Drystone deliberately keeps its
   canonical byte layouts unfrozen (`[gates-release]`). The DAG-CBOR golden test pins bytes for *our own
   client artifact*, not a Drystone wire format — and the `ManifestCodec` trait + the versioned self-tag
   are the unpinning path (the E85 seam again). Any future format is a new `kind` version behind the same
   trait.

### Economics: the meter shapes the dataplane

Per-transfer signed receipts (B4) make chunk granularity an economic choice, not just an engineering one —
the Phase 1 tuning rationale's "postage/receipt overhead" is grounded in the cost-ceilings thesis: the
synchronous meter is what makes a hard spending cap "a ledger comparison," postage is the volatile axis a
ceiling governs, and the corpus expects the **client** to price operations pre-flight from `du` × tariff
(there is deliberately no server estimate endpoint) and refuse/defer before sending. M5's cost twin is that
expectation made whole; **M1 plants its embryo for free**: the have/want diff computes the exact upload
byte count *before any byte moves*, and Phase 2 now logs it as a pre-transfer INFO line — the very number a
ceiling will later compare against. Two standing notes from the same thesis: restore today is a metered,
gated read (the "exit is unconditionally cap-exempt" rule is a *candidate* CISS invariant, not yet built —
E89's ADR lane), and M1's backup→wipe→restore drill exercises exactly the self-egress path that invariant
will one day have to exempt. Bilateral (co-signed) receipts remain `501` (E82 seam) — the revisit hooks on
chunk tuning should watch that seam too, since a co-signed tariff could change the postage economics.

### Known tension, carried consciously: the shared account key

The multi-device corpus names key-sharing across devices "the SSB/fusion-identity trap" and decided
(2026-06-16) on independent per-device keys under a lineage. The milestone plan *knows this* and takes the
shared account key anyway as a scoping decision (decided 2026-08-07): it removes the only server write-auth
change from the critical path, and the frontier model is forward-compatible (the `heads` map keys become
real device identities; fold and commit logic unchanged). M1 inherits that decision consciously: blast
radius is one person's own pool, and per-device lineage keys (with real revocation) remain the recorded
graduation path, out of M1–M5. What the shared key *forecloses meanwhile* — per-device revocation — is a
known cost, not an oversight.

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
- **(Pass 3) `ciss` re-exports — D3 resolved at planning.** `src/lib.rs` declares `pub mod crypto` (:31),
  `identity` (:36), `manifest` (:39); `sha256_hex` (crypto.rs:38), `Keypair` (crypto.rs:49), `derive_id`
  (identity.rs:25), `ManifestLeaf` (manifest.rs:37), `Manifest` (manifest.rs:122), `build_manifest`
  (manifest.rs:192) are all `pub`. External-crate reachability is already proven by `ciss-cli` itself
  (`ciss = { path = "../.." }`; `session_for` calls `ciss::identity::derive_id`, client.rs).
- **(Pass 3) manifest wire contract — D4 resolved at planning.** Route `PUT|GET /{did}/manifest`
  (server.rs:367). PUT reads the `x-croft-pubkey` header (hex pubkey) + a raw JSON body = serde of
  `Manifest{leaves,root,total_bytes,signer_id,seq,signature}` (`deny_unknown_fields`, manifest.rs:120).
  **Self-authorizing — no session header:** the handler requires `derive_id(key)==did`, `signer_id==did`,
  and a valid signature (server.rs:1153–:1169); I5 strictly-newer `seq` is enforced under one store lock
  (server.rs:1171–:1182). GET is anonymous and returns the manifest JSON (server.rs:1509).
- **(Pass 3) `crates/ciss-cli/src/lib.rs` already exists**, exposing `client`, `identity` (+ `atproto`,
  `commands`, `config`). The OQ1 "give ciss-cli a lib target" step is already done — Phase 2 only adds the
  dependency edge `ciss-sync → ciss-cli`.
- **(Pass 3) `ipld-core = "0.4"` confirmed** in the workspace `Cargo.toml` (:24) — D5's premise holds; only
  the DAG-CBOR codec crate pin remains for Phase 0.
- **(Pass 3) logging conventions:** the server uses structured `tracing` + `EnvFilter` (`init_tracing`,
  src/main.rs:368; e.g. server.rs:1183 logs each manifest store). **`ciss-cli` has no `tracing` dep today**
  (plain `println!`/`eprintln!`) — the Phase 1/2 observability items add `tracing` to `ciss-sync` and an
  `EnvFilter` subscriber to `ciss-ctl`.
- **(Pass 3) mutation tooling:** `.cargo/mutants.toml` exists (accessor exclusions with per-entry
  justification comments) — `cargo mutants` is the configured tool for the Phase 1 mutation audit.
- **(Phase 0, 2026-08-07) D1 — `fastcdc` pinned at 4.0.1** (plan guessed 3.x; 4.x is current). API:
  `fastcdc::v2020::FastCDC::new(&[u8], min: usize, avg: usize, max: usize)` (params are `usize` in 4.x),
  iterator of `Chunk{offset, length}`. Probe evidence (8 MiB LCG corpus, 64K/256K/1M): deterministic across
  runs; max chunk 1,048,576 (cap respected); full coverage; 20/21 chunks byte-identical after a 1-byte
  insert at 4 MiB (locality).
- **(Phase 0) D2 — `blake3` pinned at 1.8.6.** `blake3::hash(&[u8]) -> Hash`; `.as_bytes() -> &[u8; 32]`;
  `.to_hex()` (64 chars); streaming `Hasher::new/update/finalize` equals one-shot (probe-verified).
- **(Phase 0) D5 — `serde_ipld_dagcbor` pinned at 0.7.0** (pulls `ipld-core` 0.4.3, compatible with the
  workspace's `0.4`). `to_vec`/`from_slice`; probe evidence: repeat-stable bytes, insertion-order-stable,
  round-trip exact. Bonus: the encoder emits **canonical DAG-CBOR key order on the wire** (length-first —
  observed `"b"` before `"aa"` against BTreeMap iteration order), so wire determinism does not depend on
  the map type; BTreeMap kept for deterministic in-memory iteration.

## Documentation Impact

- `Cargo.toml` (workspace) — add `crates/ciss-sync` to `members`; add `fastcdc`, `blake3` deps. **Phase 1.**
- `crates/ciss-sync/` — new crate; its own `README`/module docs (`#![warn(missing_docs)]`). **Phase 1.**
- `crates/ciss-cli/src/main.rs` + help — new `sync backup|restore` subcommand. **Phases 2–3.**
- `docs/plans/2026-08-07-file-sync-client.md` — link this M1 execution plan under M1. **Phase 1 (cheap).**
- `docs/ARCHITECTURE.md` — if it enumerates crates, add `ciss-sync`. **Phase 1** (grepped: confirm at exec).
- `README.md` — if it lists crates/commands, note the `sync` command. **Phase 3.**
- ~~(If OQ1 → lib extraction) `crates/ciss-cli/src/lib.rs`~~ — **(Pass 3) the lib target already exists**,
  exposing `client`/`identity`; no extraction step. Phase 2 only adds the `ciss-sync → ciss-cli` dep edge.
- `Cargo.toml` (root `[dev-dependencies]`) — add `ciss-sync` so the repo-root `tests/flow_sync_*.rs` can
  drive the engine against the in-process server. **Phase 2.**

## Concurrency Map

**All phases sequential.** Phase 0 (discovery) → Phase 1 (pure core) → Phase 2 (transport+backup, depends on
core) → Phase 3 (restore, depends on backup). Each phase reads what the prior wrote; no parallelizable subgraph
worth isolating, and the phases share the `ciss-sync` crate write-set. No worktrees.

## Phases

### Phase 0: Discovery — ✅ SHIPPED (probes run 2026-08-07; findings in Verified Assumptions)
**Goal:** pin the two external deps and confirm the `ciss` crate re-exports, before building on them.
- [x] **D1: FastCDC crate + params.** **DONE — pinned 4.0.1** (usize params; deterministic; cap + locality
  probe-verified; see VA). Probe project deleted per throwaway disposition.
- [x] **D2: blake3 crate.** **DONE — pinned 1.8.6** (API verified; see VA). Throwaway honored.
- [x] **D3: `ciss` crate re-exports.** ~~Probe: read `src/lib.rs`~~ **RESOLVED at Pass 3 (planning-time
  read)** — all imports `pub` and reachable; evidence in Verified Assumptions. No execution-time work.
- [x] **D4: manifest wire contract.** ~~Probe: read `put_manifest_handler`~~ **RESOLVED at Pass 3
  (planning-time read)** — `x-croft-pubkey` header only (self-authorizing, no session header), JSON body =
  `Manifest` serde; evidence in Verified Assumptions. No execution-time work.
- [x] **D5: DAG-CBOR codec (canonical, deterministic).** **DONE — pinned `serde_ipld_dagcbor` 0.7.0**
  (deterministic canonical key order on the wire, round-trip exact; see VA). Throwaway honored.
**Done when:** D1, D2, D5 recorded in Verified Assumptions with concrete evidence (D3/D4 already resolved
at Pass 3); no BLOCKING unknown remains. **Met 2026-08-07 — no material plan change (version bump 3.x→4.0.1
and `usize` params only).**

### Phase 1: chunk + content-address core (`ciss-sync` crate, pure, no network) — ✅ SHIPPED (`410fd9b`)

**Delivered notes (2026-08-07):** as specced, plus: the golden test also pins a boundary+parameter digest
(mutation audit found the tuning constants otherwise unpinned — a min-size drift is invisible in any one
corpus's cuts, so the params are folded into the digest); `ipld-core` is not a direct dep (nothing uses its
types — `serde_ipld_dagcbor` pulls it transitively); the index API is `scan_tree_indexed(dir, &mut Index)`
with hit/miss counters, and the index file must live *outside* the scanned tree (scanning your own mutating
sqlite poisons the manifest — learned from a RED test). Mutation audit: 39 mutants → 34 caught, 5 unviable,
0 missed after closing the survivors (boundary/param pin + Debug/expecting diagnostic-contract asserts).
**Goal:** deterministic chunking + dual-hash + a canonical filesystem manifest, fully unit-tested offline.
**Changes:**
- [ ] new `crates/ciss-sync` (lib); workspace member; deps `fastcdc`, `blake3`, `ciss`, `serde`, `rusqlite`,
  `ipld-core` + a DAG-CBOR codec (`serde_ipld_dagcbor`, pinned in D5), `tracing` (Phase 2's flow
  observability instruments engine code — the dep lands with the crate).
- [ ] `ChunkRef { sha256:[u8;32], blake3:[u8;32], len:u32 }` (len < 2 MiB, asserted).
- [ ] `chunk_file(bytes) -> Vec<(ChunkRef, Range)>` via FastCDC (**avg 256 KiB, min 64 KiB, max 1 MiB** — see
  Tuning rationale below); single pass computes both sha-256 and blake3.
- [ ] `FsManifest { kind, entries: BTreeMap<Path, FileEntry{mode,mtime,size,[ChunkRef]}> }` — `kind` is a
  leading `"croft.fs-manifest/v1"` self-tag (foundations review): domain-separates the hashed pre-image
  (Drystone §4.2 spirit — the *address* stays the server-computed CISS cid per C1), versions the format
  behind the `ManifestCodec` seam, and is what Phase 3's cold-restore scan matches on.
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
**Test-first order (Pass 3 — write each test, watch it fail RED, then implement):**
1. `chunk_boundaries_deterministic` — same bytes → identical `(ChunkRef, Range)` list across two runs.
2. `chunk_len_caps` (**integrity guard, RED-first**) — every emitted chunk has `len ≤` the 1 MiB max param
   and `< MAX_OBJECT_BYTES` (2 MiB). Edges named, not just a happy point: empty file (0 chunks), 1-byte
   file, file exactly == max chunk size, file one byte over max (forces a cut), file < min chunk size.
3. `one_byte_insert_locality` — a 1-byte insert changes only chunks in the edit window; distant chunk
   refs are byte-identical.
4. `dual_hash_consistency` — `ChunkRef.sha256` equals `ciss::crypto::sha256_hex` over the same bytes (the
   local truth Phase 2's server-cid assert (G3) rides on).
5. `dagcbor_roundtrip_and_golden_content_id` (**integrity guard, RED-first**) — `decode(encode(m)) == m`;
   two encodes are byte-identical; entry-insertion order does not change the bytes; the encoding leads
   with the `kind` self-tag (assert it is present and first — the domain separation in the pre-image); a
   **golden** `content_id` hex is pinned in the test so any silent codec/schema change breaks loudly.
6. `pretty_json_is_not_addressed` — the `inspect` render decodes to an equal `FsManifest`, but
   `content_id` is defined over the DAG-CBOR bytes only (JSON bytes never hashed).
7. `scan_tree_roundtrip` — crate-level integration test (`crates/ciss-sync/tests/scan_roundtrip.rs`)
   driving the **public API only**: fixture dir → `scan_tree` → stable `content_id` across two runs.
**Call chain:** (engine API) `ciss_sync::scan_tree(dir) -> FsManifest` → `chunk_file` per file. No entry point
yet — Phase 2 wires the CLI. (This phase is a library core; its wiring is Phase 2's `sync backup`.)
**Wiring test:** N/A at the CLI level (pure lib — acknowledged plan-level exception, not an oversight). The
phase's wiring-equivalent is test 7 above: a crate-level integration test through the public API, proving
the pieces compose outside their own modules. The CLI-level wiring proof is Phase 2's `flow_sync_backup`.
**Depends on:** Phase 0.
**Read-set:** `Cargo.toml`, `src/lib.rs` (for imports). **Write-set:** `Cargo.toml`, `crates/ciss-sync/**`.
**Shared-state contract:** none beyond the file write-set (pure lib; tests use `tempfile`, no network/ports).
**Risks:** FastCDC param choice affects dedup/receipt-overhead — OQ2; a bad canonical serialization would make
`content_id` unstable — pin it with a golden test.
**Done when:**
1. **Behavioral:** `scan_tree` over a fixture dir yields a stable `FsManifest.content_id`; re-running on
   unchanged bytes yields identical chunk boundaries/hashes; a 1-byte insert changes only local chunks.
2. **Verification:** `cargo test -p ciss-sync` (runs tests 1–7 above, including the crate-level
   `scan_roundtrip` integration test — the public-API path, not only inner `#[cfg(test)]` modules).
**Validation:** Narrow → wiring (Phase 2) + unit tests sufficient here. **Mutation audit (Pass 3):** once
green, run `cargo mutants -p ciss-sync` scoped to the chunker + DAG-CBOR encoder (branch/boundary-heavy —
exactly where a green suite hides holes, per `CLAUDE.md`). Triage every survivor as equivalent-vs-real-gap
in the phase write-up; extend `.cargo/mutants.toml` `exclude_re` only with a per-entry justification
comment, matching the repo's existing convention.

### Phase 2: transport + backup (`sync backup <dir>`) — ✅ SHIPPED (`8348a58`)

**Delivered notes (2026-08-07):** three deviations from the spec, all recorded here. (1) **`HttpCiss`
lives in `ciss-cli`, not `ciss-sync`** — the CLI must depend on the engine to wire `sync backup`, so the
engine depending back on `ciss-cli` (the OQ1 reading) would be a package cycle; the dependency points
`ciss-cli → ciss-sync`, the Client stays single-sourced, and `HttpCiss` is glue beside it. (2) The
transport addresses blobs by **expected sha-256 hex** rather than `&ChunkRef`, so the fs-manifest blob
rides the same `put`/`get` path as chunks; `have()` takes no argument (du is whole-namespace, G4).
(3) The backup **re-reads and re-chunks** each file that owns a wanted chunk (scan keeps refs, not
ranges) and fails loud (`ChangedDuringBackup`) if the re-chunk no longer matches the scanned manifest —
the TOCTOU seam made explicit. Also: an interrupted backup provably never commits a keep-set (asserted
in the resume test). Live smoke against a real server binary: 10 chunks up, `skipped=10` on the re-run,
seq 1→2, du shows all 11 objects, pricing line present.
**Goal:** push a directory to CISS — upload only missing chunks + the fs-manifest, commit the keep-set Manifest.
**Changes:**
- [ ] `trait BlobTransport { async have(&[sha256])->HaveSet; async put(&ChunkRef,&[u8]); async get(&ChunkRef)->Bytes }`.
- [ ] `HttpCiss` impl: `have` via `Client::du` (the DID's cid set); `put` via `put_s3`; assert the server-returned
  cid == our local sha256 hex (G3). *(OQ1 resolved; Pass 3: `ciss-cli`'s lib target already exists — just
  add the `ciss-sync → ciss-cli` dep, no extraction.)*
- [ ] `Client::put_manifest(&session, &Manifest)` + `get_manifest` (the Pass-2 GAP) — `PUT/GET /{did}/manifest`.
  *(D4 resolved at Pass 3: PUT sends the `x-croft-pubkey` header + `Manifest` serde-JSON body only — the
  manifest is self-authorizing, no session header; GET is anonymous.)*
- [ ] root `Cargo.toml` `[dev-dependencies]`: add `ciss-sync` so `tests/flow_sync_backup.rs` can drive the
  engine against the in-process server.
- [ ] **observability (tracing, Pass 3):** the backup flow emits — DEBUG per chunk (cid prefix, `len`,
  `decision = skip|upload` from have/want), DEBUG per file (path, size, chunk count), INFO run summary
  (files scanned, chunks total/uploaded, bytes transferred, committed manifest `seq`, server-echoed root),
  ERROR on any cid mismatch or non-2xx **including the server response body**. Never log key material
  (Zeroize discipline) — DIDs and cids only. `ciss-ctl` gains a `tracing_subscriber` `EnvFilter` init
  (`RUST_LOG`, default `warn`) mirroring the server's `init_tracing` (src/main.rs:368) so default CLI
  output stays clean (OQ6). A failed backup is attributable from logs alone: which file, which chunk cid,
  what the server said. **Pre-transfer pricing line (foundations review):** before any byte moves, INFO
  `will upload <n> chunks / <b> bytes` from the have/want diff — the M5 cost-twin embryo (the corpus
  expects the client to price pre-flight from `du` × tariff; this is that number, logged today, compared
  to a ceiling later).
- [ ] backup flow: scan → diff vs `have` → upload missing chunks + fs-manifest blob → `build_manifest(keep-set,
  seq)` → `put_manifest`. seq starts at 1 (or last+1 from `get_manifest`).
- [ ] CLI: `ciss-ctl sync backup <dir>` wired to the flow (entry point).
**Call chain:** `ciss-ctl sync backup <dir>` → `ciss_sync::backup(dir, transport, session)` → `scan_tree` →
`transport.have` → `transport.put`(missing) → `put_manifest`.
**Wiring test (RED→GREEN):** a workflow-tier test (`tests/flow_sync_backup.rs`, World + one Actor against an
in-process CISS) that runs `backup(tmpdir)` and asserts: the fs-manifest cid is stored, the keep-set Manifest
seq advanced, and a *second* backup of the unchanged tree uploads **zero** chunks (have/want skip). This proves
the CLI/engine reaches the server, not just that the chunker works.
**Test-first order (Pass 3 — RED before impl):**
1. `tests/flow_sync_backup.rs` **first** — RED because `ciss_sync::backup` / `sync backup` don't exist yet.
   Watch it fail before writing transport code.
2. `keep_set_advances_under_i5` (**integrity guard, RED-first**, same flow file) — backup #2 commits `seq`
   strictly greater than backup #1's; a stale/equal-`seq` PUT is rejected by the server (I5) and surfaced
   as an actionable client error, never swallowed (OQ5 default: read `get_manifest`, commit `last+1`,
   fail closed on rejection — no retry loop in M1's one-device world).
3. `server_cid_matches_local` (**integrity guard, RED-first**, unit w/ mocked transport) — a server-returned
   cid ≠ our local sha256 is a hard error before the chunk is treated as stored (G3).
4. `have_want_diff` (unit) — the upload set is exactly `local_chunks − have`; edges: empty have-set (all
   uploaded), full have-set (zero uploaded), partial overlap.
5. `interrupted_backup_resumes` (foundations review — a parent-milestone commitment this plan had
   dropped: "interrupted push resumes by skipping stored chunks") — inject a transport failure after k of
   n chunks upload; re-run backup; assert only the missing chunks transfer and the flow completes with the
   keep-set committed. This is "chunk-level resume replaces byte-range resume" made concrete.
**Depends on:** Phase 1.
**Read-set:** `crates/ciss-sync/**`, `crates/ciss-cli/src/client.rs`, `src/manifest.rs`, `src/server.rs`
(manifest handler), test harness `tests/common/**`. **Write-set:** `crates/ciss-sync/**`,
`crates/ciss-cli/src/{client.rs,main.rs}`, root `Cargo.toml` (dev-deps), `tests/flow_sync_backup.rs`.
(Pass 3: dropped "+ lib.rs if OQ1→extract" — the lib target already exists.)
**Shared-state contract (Pass 3, as invariants):** tests bind only ephemeral loopback ports via the
harness's `TestServer` (`127.0.0.1:0`, tests/common/mod.rs:52) and assert clean shutdown; no fixed port
numbers anywhere; all filesystem writes land under `tempfile` dirs or the declared write-set; no `git`
commands invoked; no env-var mutation; no external network egress (in-process server only).
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
  fs-manifest — the match target is Phase 1's leading `kind: "croft.fs-manifest/v1"` field (M1's rare
  path; the discoverable `heads` field is M3).
- [ ] **observability (tracing, Pass 3):** restore emits — DEBUG per chunk fetch+verify (cid prefix, `len`,
  destination path), ERROR on a verify failure naming the cid and the target path (then fails closed),
  INFO run summary (files restored, chunks fetched, bytes, the manifest `seq`/root restored from, and —
  cold path — how many leaves the discovery scan touched). Same subscriber as Phase 2; no key material.
**Call chain:** `ciss-ctl sync restore <dir>` → `ciss_sync::restore(dir, transport, session)` → find fs-manifest
→ `transport.get`(chunks, verify) → materialize tree.
**Wiring test (RED→GREEN):** `tests/flow_sync_roundtrip.rs` — World/Actor: `backup(src)` then wipe then
`restore(dst)` → `dst` is **byte-identical** to `src` (content + mode; mtime within tolerance). The end-to-end
capability gate for M1.
**Test-first order (Pass 3 — RED before impl):**
1. `tests/flow_sync_roundtrip.rs` **first** — RED because `restore` doesn't exist yet.
2. `tampered_chunk_rejected` (**integrity guard, RED-first**, same flow file) — the World corrupts one
   stored chunk's bytes server-side (or the transport substitutes bytes); restore **fails closed**: the
   `verify_cid` error names the cid and the target path, and the destination file is **not written** (no
   partial/poisoned output left on disk — atomic write means verify-before-rename).
3. `cold_restore_discovery` — a restore with zero local state locates the fs-manifest via the keep-set
   scan and completes; edges: keep-set with exactly one leaf, and with many non-manifest small leaves.
**Depends on:** Phase 2.
**Read-set:** `crates/ciss-sync/**`, `crates/ciss-cli/src/client.rs`. **Write-set:** `crates/ciss-sync/**`,
`crates/ciss-cli/src/main.rs`, `tests/flow_sync_roundtrip.rs`.
**Shared-state contract (Pass 3, as invariants):** same invariants as Phase 2 — ephemeral loopback only,
`tempfile`-scoped writes, no git commands, no env mutation, no external egress.
**Risks:** a corrupted/substituted chunk must fail closed (`verify_cid`); cold-restore scan cost if the
namespace is large (acceptable for M1; the M3 `heads` field removes it).
**Done when:**
1. **Behavioral:** back up a tree, wipe local, `sync restore` reproduces it byte-identically; a tampered chunk
   is rejected, not written.
2. **Verification:** `cargo test -p ciss --test flow_sync_roundtrip` + a manual `backup`→wipe→`restore` diff.
**Validation:** Moderate → wiring + unit + a real backup→restore diff outside the harness, **plus a manual
tamper drill (Pass 3):** flip one byte of a stored chunk in the server's store, run `sync restore`, confirm
it refuses, names the cid in the ERROR log, and leaves no partial file. Restore is the integrity-critical
path — the drill proves the fail-closed behavior outside the test harness too.

## Open Questions

### OQ1–OQ4 — RESOLVED 2026-08-07 (user)

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

### OQ5–OQ6 — RESOLVED 2026-08-07 (user confirmed the Pass 3 defaults)

- **OQ5 — `put_manifest` seq-conflict behavior. RESOLVED: the proposed default.** Backup reads
  `get_manifest`, commits `last+1`, and on an I5 rejection fails closed with an actionable error (no retry
  loop — a concurrent writer cannot exist in M1's one-device world; retries would mask a real anomaly).
- **OQ6 — how the CLI surfaces tracing. RESOLVED: the proposed default.** `RUST_LOG` `EnvFilter` only
  (the server's convention), default level `warn`, so plain `sync backup` output stays clean; no `-v`
  flag in M1 (purely additive later).

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
### Pass 3: Quality Gates — 2026-08-07 (fresh context)
**TDD ordering:**
- Added a named **Test-first order** block to each implementation phase; every integrity guard is a named
  RED-first test in the phase that owns it: 2 MiB chunk cap (`chunk_len_caps`, P1), DAG-CBOR determinism +
  golden `content_id` (`dagcbor_roundtrip_and_golden_content_id`, P1), dual-hash local truth
  (`dual_hash_consistency`, P1), keep-set Manifest under I5 (`keep_set_advances_under_i5`, P2), server-cid
  == local sha256 (`server_cid_matches_local`, P2), tamper-rejected chunk (`tampered_chunk_rejected`, P3).
- Mutation-resistance edges named (empty/1-byte/==max/over-max/under-min files; have-set empty/full/partial;
  keep-set one-leaf/many-leaves) rather than single happy-path points.
- Phase 1's wiring-equivalent made explicit: `crates/ciss-sync/tests/scan_roundtrip.rs` through the public
  API only; CLI wiring proof remains Phase 2's `flow_sync_backup` (acknowledged pure-lib exception).
**Observability:**
- Backup (P2) and restore (P3) gained concrete `tracing` specs: DEBUG per chunk (cid, len, have/want
  decision), DEBUG per file, INFO run summary (incl. manifest seq/root), ERROR with server response body /
  failing cid + path. `ciss-sync` gets a `tracing` dep (P1); `ciss-ctl` gets an `EnvFilter` subscriber
  (P2) — spot-check found `ciss-cli` has **no** tracing today while the server is fully instrumented.
  Never log key material (Zeroize discipline).
**Debugging readiness:**
- Commit-per-phase checkpoints already present; each phase gates on its own flow test; the INFO/ERROR spec
  makes a failed run attributable from logs alone (file → chunk cid → server response).
**Validation calibration:**
- P1 narrow / P2 moderate confirmed as-is; P3 stays moderate but gains a **manual tamper drill** (flip a
  stored byte, confirm fail-closed outside the harness) — restore is the integrity-critical path.
- P1 mutation audit made concrete: `cargo mutants -p ciss-sync` (chunker + DAG-CBOR encoder) under the
  repo's `.cargo/mutants.toml` conventions; survivors triaged equivalent-vs-gap in the phase write-up.
**Concurrency honesty:**
- Map confirmed: all-sequential with reason, every phase accounted for. P2/P3 shared-state contracts
  rewritten from mechanisms to **invariants** (ephemeral `127.0.0.1:0` only, `tempfile`-scoped writes, no
  git commands, no env mutation, no external egress). No re-entry fields needed (no parallel sets); no
  missed parallelism worth extracting (phases share the `ciss-sync` write-set).
**Discovery:**
- **D3 + D4 resolved at planning** by reading the code (per the "resolve now if resolvable" gate) —
  evidence moved into Verified Assumptions; Phase 0 shrinks to D1/D2/D5 (the cargo-add probes). All
  remaining tasks have concrete probes, success criteria, and `throwaway` dispositions.
- Spot-check findings: `crates/ciss-cli/src/lib.rs` **already exists** (OQ1's extraction step removed from
  P2's write-set and Documentation Impact); `ipld-core 0.4` confirmed in the workspace; root `Cargo.toml`
  needs `ciss-sync` as a dev-dependency for the flow tests (added to P2).
- D4 detail that refines P2's spec: `put_manifest` is **self-authorizing** — `x-croft-pubkey` header +
  signed JSON body, no session header; `get_manifest` is anonymous.
**Coherence:**
- The plan still solves the stated M1 problem; no scope creep; no restructuring — all Pass 3 changes are
  insertions into the Pass 1+2 shape.
**Documentation impact:**
- Every listed doc has an owning phase; the stale lib-extraction item corrected; the root dev-dep item
  added (P2). No end-of-plan docs phase exists — updates stay in the phases that make them stale.
**Confirmed ready:** yes, pending user confirmation of the two new ADVISORY questions (OQ5 seq-conflict
default, OQ6 `RUST_LOG`-only tracing surface). OQ1–OQ4 were user-confirmed in the prior pass. Then execute:
Phase 0 (D1/D2/D5 under the Discovery Exemption) → Phases 1–3, commit per phase.

### Foundations & corpus review — 2026-08-07 (unstructured, post-Pass-3; user-requested)
**Scope:** OQ5/OQ6 confirmed by the user (defaults accepted; marked RESOLVED). Then a deep verification of
the plan's claimed foundations against the discovery corpus — three parallel research passes over (a)
`beta/drystone-spec/` + `beta/impl/drystone-design/` (history-durability, liveness-freshness, fold-semantics,
rbsr-construction, redb-storage-contract), (b) `alpha/thinking/` (cost-ceilings, multi-device,
meer-superpeer, thesis-lineage-groups), (c) COHESION §67 + ROADMAP E90/E89/E82/E85 + the 2026-07-31
coop-metered-storage plan + ECOSYSTEM — plus a direct read of `docs/SECURITY-POSTURE.md` and the milestone
plan. Findings written up as the new **"Foundations & corpus tie-in"** section (after Reasoning).
**Confirmed:** the substrate story holds (E82 live; one-store-two-consumers per the 2026-07-31 plan:43;
guard↔invariant map C1/C2/B1–B4/I5); COHESION §67 registers this exact design including the M1→M5 ladder;
the frontier/HEAD doctrine (never asserted, client-fold, per-subspace heads) is faithfully the corpus's;
the dataplane dial (recoverable, reads-never-gated) is the right first instance; conflict-copy matches
fork-is-escalation; `completeness-ahead`/`LocateLatest` statuses stated honestly (unearned / non-normative
— M1 claims neither).
**Deviations now owned in-plan (each with its bridge):** sha-256-native vs the corpus's committed BLAKE3
(the dual-hash ChunkRef is the migration bridge); untagged content_id pre-image vs §4.2 (fixed — leading
`kind` self-tag); mtime inside a hashed artifact (payload-not-protocol-fact framing; address-only effect);
content-*indifferent* ≠ corpus content-*blind* (plaintext v1 per E90; blind-store discipline binds when
E2EE lands); DAG-CBOR byte pin is our own, behind the E85 `ManifestCodec` seam. Shared-account-key tension
(the corpus's named trap) documented as the milestone plan's conscious scoping decision with the per-device
graduation path. E90 wording reconciliations recorded (bsky app-token = read-side; DAG-CBOR = this plan's
pin; timestamps-as-assertion honored structurally).
**Plan changes (additive):** (1) Phase 1 — `FsManifest` gains the leading `kind: "croft.fs-manifest/v1"`
self-tag (domain separation + versioning + the cold-restore match target); golden test asserts it. (2)
Phase 2 — new `interrupted_backup_resumes` test, restoring a parent-milestone commitment this plan had
dropped. (3) Phase 2 — pre-transfer INFO pricing line (`will upload n chunks / b bytes`), the M5 cost-twin
embryo. Phase 3's cold-restore bullet cross-references the `kind` field.
**Standing notes (context, no M1 action):** restore is today a metered, gated read — the exit-exempt
invariant is an unbuilt E89 candidate, and M1's roundtrip drill exercises the exact path it must one day
exempt; bilateral receipts remain `501` (E82 seam) and join the chunk-tuning revisit hooks; at M3 the
corpus's backfill-admission (contiguity + standing) and freshness-honesty rules become live obligations.
**Confirmed ready:** yes — all six open questions resolved; execute next (Phase 0: D1/D2/D5, then
Phases 1–3, commit per phase).
