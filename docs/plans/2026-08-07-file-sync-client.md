# CISS file-sync client — milestone plan (own-device file sync over CISS, then iroh)

date: 2026-08-07
status: design settled (frontier model + identity decision locked 2026-08-07); implementation not started
scope: the **own-device** file-sync surface — one device + helper, then a second device that may use the
helper or sync directly. Cross-lineage Croft-group sync is explicitly out of scope here (see §Future).
target server: CISS v0.5.6 (live at `https://ciss.croft.ing`).

Provenance: live design session 2026-08-07 + a distilled dialogue
(`discovery/alpha/seeds/transcripts/raw/ciss-cost-ceilings-and-prepaid-meter-equity-2026-08-07.md`).
Backlog: `discovery/alpha/ROADMAP_TODO.md` **E90** (this) + **E89** (cost twin). Seam map: COHESION §67.
Grounded against a session research pass over the Croft/Drystone corpus (own-device pool, the Drystone
governance frontier, the content-blind meer, RBSR, serverless iroh sync) — cited inline.

---

## Problem statement

Build a cloud-storage sync client that treats every file as CISS items, is **judicious with bandwidth**
(transmit deltas and metadata-only wherever possible), authenticates with a **bsky app-token**, and can
**optimize the client host's storage footprint**. CISS is the server side; later the data plane can also
run over **iroh** (resume/range/peer-fetch). The client starts as **one device + a helper server** (de-facto
backup and robustness), then grows a **second device** that syncs via the helper **or directly**, per need.

The hard part is not the byte-moving — CISS already gives us a content-addressed, metered, integrity-checked
store. The hard part is the **frontier**: with more than one writer, "what is the current tree, and how does
a device learn it, without trusting anyone's word or any clock?" The Croft corpus has this as **theory only**
(`Design / load-bearing / unearned`; drystone `open-threads.md:50` calls completeness-ahead "the single
load-bearing property," and `LocateLatest` is "still a proposal to talk through"). This plan is the **first
concrete, tractable instance** of that machinery — deliberately at the *dataplane* dial, which the spec marks
as the looser, recoverable, reads-never-gated case (`liveness-freshness.md:168`).

## Approach

Two planes over one content-addressed store, files modeled as manifests of content-defined chunks:

- **Metadata plane** (small, frequent, cheap): a filesystem manifest `path → {mode, mtime, chunk cids, size}`,
  and a **Frontier** naming each device's latest commit. Diffed to compute work.
- **Data plane** (large, dedup'd, resumable): only the chunks the server does not already hold.

Chunking is **mandatory**, not an optimization: CISS caps objects at 2 MiB (`MAX_OBJECT_BYTES`). Use
**FastCDC** (avg ~256 KB–1 MB, hard cap < 2 MiB), hashing each chunk **both** ways in one pass —
**sha-256** (CISS's native content address) and **blake3** (iroh's) — recorded in the manifest so either
transport can address the same bytes. Chunk-level resume replaces byte-range resume (CISS has no
Range/multipart/HEAD/304).

The multi-writer model is a **per-device signed frontier folded locally** — never an asserted HEAD:

- **DeviceHead** (content-addressed blob, signed): `{device_id, counter, fs_root, parent, base, sig}`.
- **Frontier** (the shared mutable pointer, in the CISS manifest slot, seq-CAS'd):
  `{heads: {device_id → cid(DeviceHead)}, keep_set_root, total_bytes, seq, writer_id, sig}`.
- **Current tree = a client-side fold**: each device's `fs_root`, three-way merged per path against the
  greatest common `base`; same-path divergence → **conflict-copy** (both preserved); tiebreak by
  content-address, never time.

**Concurrency is non-lossy** because each device writes only its **own** slot in `heads`: a stale seq (409)
forces a reload + re-apply-my-slot + retry, and the other device's head is untouched. The CISS `Manifest`
monotonic-seq CAS (invariant **I5**, `src/manifest.rs`) is exactly this "minimal, blind, not-a-rights-authority"
sequencer (meer design, `discovery/alpha/thinking/meer-superpeer-design.md`).

**Identity (decided 2026-08-07): shared account key now, MLS/lineage per-device keys later as an option.**
All devices hold the same keypair (`key == DID`), so `device_id` is a stable self-asserted install label
and **no server write-auth change is needed anywhere in this plan**. Graduating to per-device
lineage-derived keys (for clean per-device revocation, corpus-aligned — `discovery/alpha/thinking/multi-device.md:69`)
is deferred; it is the *only* thing that would add a server write-auth change, and it is out of these milestones.

**The server stays a content-blind helper**, never an authority: it validates signatures + seq-monotonicity,
stores bytes, and (later) reconciles sets — it never reads fs content, never computes the fold, never decides
"current." Losing it costs availability, never data or authority. Serverless (device↔device over iroh, gossip
topic derived from the lineage root) exchanges the same records and folds identically — helper-or-not is a
**transport** choice, not a trust choice.

## Reasoning

Why this shape, and why it is aligned rather than invented:

1. **HEAD is a self-verified fold, not an accepted assertion — even among your own devices.** The corpus is
   emphatic: a record is "rejected even from a trusted sibling device" unless it verifies on its own
   signature and folds into the hash structure (`discovery/alpha/thinking/multi-device.md`;
   `.../beta/impl/delivery-layer/01-delivery-architecture.md:296`). High trust only lowers the *freshness
   floor* (how readily you believe there might be something newer — k=1 within your own lineage), never the
   verification. So a "server-minted HEAD" is both wrong-in-principle and unnecessary; the owner-signed
   Frontier + local fold is the aligned mechanism, and the seq is the fold's minimal ordering.

2. **Set-reconciliation is the shared primitive across chat / governance / files — but not one canonical
   merge.** `thesis-lineage-groups.md:25` warns history reconciliation and key convergence "must not be
   conflated… message history is just data and never needs to merge into one canonical transcript." Files
   converge by set-union over content-addressed chains and get the *dataplane* strictness dial (recoverable,
   reads-never-gated) — which is why the file surface is the right place to make the frontier concrete first.

3. **CISS is already specified as the backend for the history-convergence server** — "one metered,
   content-blind store under two consumers: PDS blob hosting and history convergence"
   (`discovery/alpha/plans/2026-07-31-1-plan-coop-metered-storage-service.md:43`;
   `discovery/alpha/plans/croft-stack/10-drystone-layer.md`). This client and the future meer share the
   substrate; keeping the server blind here keeps that door open.

4. **Milestones, not phases.** Each milestone below is an *observable capability* — a thing you can do when
   it's done. "Phases" exist only as implementation sequencing beneath a milestone. (User framing, 2026-08-07.)

5. **Shared key first is a scoping decision, not a design compromise.** It removes the one server write-auth
   change from the critical path and lets M1 ship against today's server untouched; the frontier model is
   already forward-compatible with per-device keys (the `heads` map keys become real device identities, the
   fold and non-lossy-commit logic are unchanged).

---

## The frontier design (settled — the core artifact)

```
DeviceHead  (content-addressed blob, signed by the account key)
  { device_id,            // stable per-install label (shared-key era); a real device pubkey later
    counter: u64,         // this device's OWN monotonic high-water
    fs_root: cid,         // root of its path→chunks filesystem manifest
    parent: cid | null,   // previous DeviceHead from THIS device (per-device hash chain)
    base:   frontier_hash,// the frontier this commit was folded against (causal ref; happens-before, no clocks)
    sig }

Frontier    (the shared mutable pointer — CISS manifest slot, seq-CAS'd)
  { heads: { device_id → cid(DeviceHead) },
    keep_set_root, total_bytes,   // billing keep-set = ∪ all chunks + fs-manifests + DeviceHeads
    seq: u64,                     // monotonic CAS — the ONLY thing the server orders (I5)
    writer_id, sig }

fs-manifest (content-addressed blob)   path → { mode, mtime, [ChunkRef], size }
ChunkRef                               { sha256, blake3, len<2MiB }
```

**Commit (non-lossy under concurrency):**
```
write new chunks (skip those du/have already lists) + new fs-manifest + DeviceHead
GET Frontier (seq N) → set heads[my_device_id] = my new DeviceHead → PUT Frontier seq N+1
  on 409 stale: GET (seq N+k) → re-apply heads[my_device_id] only → retry     (peer heads untouched)
```

**Fold (current tree, deterministic, clock-free):** read `heads` → each `fs_root` → per-path three-way merge
vs greatest-common `base`; one-sided change → take it; same content → converged; divergent same path →
**conflict-copy** (both kept). Tiebreak = content-address.

**Have/want (no new endpoint):** `du` / `listBlobs` over the DID is the "have" set; upload only the missing
chunks. (RBSR is a later efficiency upgrade with the same contract — §Future.)

---

## Milestone ladder

Each milestone lists the capability, the implementation phases (RED→GREEN, unit + workflow-tier), and the
CISS server change (if any). TDD is non-negotiable per `CLAUDE.md`: every integrity/security-relevant guard
lands as a test that was RED against the absent behavior and stays as a regression wall.

### M1 — "Back up a directory to CISS and restore it byte-identical." (one device + helper)
Server change: **none** (runs against v0.5.6 as-is). Frontier is trivial (one head, tracked client-local).
**Execution plan: `docs/plans/2026-08-07-file-sync-m1-chunk-and-backup.md`** — **✅ M1 SHIPPED
2026-08-07** (all phases; `ciss-ctl sync backup|restore` live; see the plan's Outcome Summary).

- **P1.1 chunk + content-address core** (new `ciss-sync` crate, no network): FastCDC boundaries; `ChunkRef`
  dual sha256/blake3; a local sqlite index (`path → mtime,mode → [ChunkRef]`); the fs-manifest format +
  canonical serialization. Tests: deterministic chunking (same bytes → same boundaries/hashes); a 1-byte
  insert re-chunks only locally; manifest round-trips; every chunk `len < MAX_OBJECT_BYTES`.
- **P1.2 push/backup over HTTP**: `BlobTransport` (trait, HTTP/CISS impl by sha256); have/want via `du`;
  upload missing chunks + fs-manifest; record the keep-set in the CISS `Manifest` (existing schema).
  Tests: re-push of unchanged tree transfers zero chunks; interrupted push resumes by skipping stored chunks.
- **P1.3 restore/pull + verify**: reconstruct the tree from a manifest; verify every chunk's cid on receipt
  (client already does this). Cold-restore (fresh install) discovers `fs_root` by a bounded small-blob scan.
  Tests (**workflow-tier**, `tests/flow_*`): World with one Actor — back up a tree, wipe local, restore →
  byte-identical.

### M2 — "Local footprint is bounded regardless of logical tree size." (storage optimizer)
Server change: **none.** — **✅ M2 SHIPPED 2026-08-07** (`ciss-ctl sync evict|hydrate|status`; execution
plan `docs/plans/2026-08-07-file-sync-m2-bounded-footprint.md`).

- **P2.1 content-addressed local cache** with a size budget; a chunk is always safe to evict (re-fetchable
  by hash). LRU + pin policy (recent / starred / working-set).
- **P2.2 online-only placeholders**: keep the manifest entry, drop the bytes for cold files; **hydrate on
  access**. Tests: local bytes stay ≤ budget while the logical tree grows; hydrate-on-open reproduces content;
  eviction never loses data (re-fetch succeeds).

### M3 — "A second device converges, and a real conflict is preserved, not lost." (multi-writer frontier)
Server change: **one, additive** — the `Frontier.heads` map (below). Shared account key ⇒ **no write-auth change.**
— **✅ M3 SHIPPED 2026-08-07** (`ciss-ctl sync converge`; the heads field live under I5; execution plan
`docs/plans/2026-08-07-file-sync-m3-two-device-converge.md`).

- **P3.1 `DeviceHead` + `Frontier` records** and the non-lossy seq-CAS commit loop (retry re-applies only the
  local `heads` slot). Tests: two Actors committing concurrently both land (≤1 retry), both heads present.
- **P3.2 the fold** (per-path 3-way merge vs greatest-common `base`) + **conflict-copy** materialization +
  exact-set **rename detection** (optional polish; a `deleted` path whose chunk-set equals an `added` path's
  = a move — zero-byte either way). Tests (**workflow-tier**): disjoint-path edits merge cleanly; same-path
  divergent edits produce a conflict-copy with both contents; a rename transfers no chunks.
- **P3.3 CISS: additive `heads` on `Manifest`** — an optional owner-signed `heads: map<string,cid>` field
  folded into the manifest **signing preimage** and checked by `verify()`; still governed by the existing
  **I5** monotonic-seq CAS (a stale seq cannot un-add or roll back a head). This is **owner-signed,
  server-blind, server-validated** — explicitly *not* a server-minted HEAD. Tests (CISS side, RED-first):
  a manifest with a tampered/added `heads` entry fails `verify`; a lower-seq write with a different `heads`
  is refused (`409`, I5 holds); a valid `heads` update round-trips and a second device reads both heads.

### M4 — "The same sync runs over iroh, and blobs can come from a peer." (peer-fetch = less metered egress)
Server change: **none** (CISS remains one blob source among peers). — **✅ M4 SHIPPED 2026-08-07**
(`ciss-ctl sync p2p share|converge` + `PeerFirst` peer-preferred reads; execution plan
`docs/plans/2026-08-07-file-sync-m4-iroh-peer-fetch.md`)

- **P4.1 iroh `BlobTransport` impl** (addresses by `blake3`; Bao verified streaming — resume/range free).
- **P4.2 serverless path**: device↔device over iroh-gossip, `topic = derive(lineage_root)`, IP-free bootstrap
  (`discovery/alpha/thinking/multi-device.md:127`); the Frontier + DeviceHeads + chunks exchange directly;
  same fold. Helper optional. Tests: same tree converges over iroh with the server offline; a blob served from
  a peer is byte/hash-identical; transport is selectable/fallback per blob.

### M5 — "I know the cost before I sync, and it stops at my ceiling instead of surprising me." (cost twin)
Ties `discovery` **E89**. Server change: none for the client twin (a *co-signed* ceiling later wants the
bilateral-receipt seam — out of scope here, E82). — **✅ M5 SHIPPED 2026-08-07 — LADDER COMPLETE**
(`ciss-ctl sync price|ceiling` + POSTURE invariant **B6** (exit-exempt); execution plan
`docs/plans/2026-08-07-file-sync-m5-cost-twin.md`)

- **P5.1 pre-flight pricing**: from `du` sizes × the tariff (postage = `floor(bytes/1000)`¢ today), the client
  prices any sync **before** sending.
- **P5.2 ceiling**: a client-side "spend stops at X this period" that **throttles/defers, never bills**;
  ledger the throttle. Honor the **exit-exempt** rule — self-directed egress of one's own manifest+blobs to
  leave must run regardless of the ceiling (candidate new CISS invariant; `docs/SECURITY-POSTURE.md`).
  Tests: a sync whose priced bytes exceed the ceiling is deferred, not partially charged; egress-to-leave is
  never blocked by the ceiling.

---

## Server changes (consolidated)

The whole ladder needs **exactly one** CISS change, and it is small and additive:

- **M3 — `Manifest.heads` (additive, owner-signed).** Add an optional `heads: map<device_id → cid>` to the
  `Manifest` struct, fold it into `signing_preimage` and `verify`, keep it under the I5 seq-CAS. The server
  gains no new authority: it still only checks the owner signature + seq monotonicity and stores bytes; the
  fold stays entirely client-side. This replaces the earlier (rejected) "server-minted HEAD pointer" idea.

**Deferred (NOT in these milestones — the MLS graduation, an option):** per-device lineage keys +
multi-key namespace write-auth + `LineageClaim` verification, enabling clean per-device revocation. This is
the only change that would touch CISS auth; it waits until we graduate off the shared account key.

## Crate structure

New **`ciss-sync`** crate (the engine: chunking, manifest, frontier, fold, transports, local cache), consumed
by a thin integration in `ciss-cli` (the existing client; identity/auth/`du`/blob plumbing already there).
Keeps the sync engine separable from the CLI and reusable by a future GUI or the meer.

## Future / explicitly out of scope

- **Cross-lineage Croft-group sync** — the parked "resolution-ACL / croft-group L3" frontier
  (k-distinct-lineage freshness, standing+contiguity admission, R6 attributable acceptance). This plan is
  own-device only; the frontier model here is the tractable precursor.
- **RBSR upgrade** — replace have/want-via-`du` with range-based set reconciliation (Willow/Negentropy) when
  the O(n) `du` diff hurts at scale; same `H(chunk)` set contract, an efficiency change (E85 keeps addressing
  pluggable).
- **Bilateral (co-signed) receipts** for a genuinely co-signed ceiling (today `Bilateral` → `501`; E82 seam).
- **Client-side E2EE** — CISS is indifferent to plaintext vs ciphertext, so this is a pure client module with
  zero server impact; deferrable indefinitely.

## Definition of done (whole plan) & TDD posture

- Each milestone's capability is provable end-to-end, with a **workflow-tier** (`tests/flow_*`, the
  `World`/`Actor` harness — `docs/TESTING-STRATEGY.md`) test for the multi-actor stories (restore; two-device
  converge; conflict-copy; iroh-offline converge).
- Every integrity/security-relevant guard (chunk cap, cid verify-on-receipt, manifest `heads` under I5,
  exit-exempt egress) lands **RED-first** and stays as a regression wall.
- `cargo test --workspace` and `cargo clippy --all-targets --workspace` clean before each commit.
  **Do not run `cargo fmt`** (local rustfmt disagrees with committed style — hand-format; gate on clippy+test).
- Mutation-test the frontier fold and the chunker once green (they are exactly the "state machine / encoder"
  shape the `CLAUDE.md` mutation guidance calls out).

## References

- discovery: `COHESION.md` §67 · `ROADMAP_TODO.md` E90/E89/E82/E85 · `thinking/cost-ceilings-and-the-prepaid-meter.md`
  · `thinking/multi-device.md` (frontier exchange, same/cross-lineage tiers) · `thinking/meer-superpeer-design.md`
  (content-blind helper) · `beta/drystone-spec/` (`LocateLatest`, completeness-ahead, causal fold) ·
  `thinking/thesis-lineage-groups.md:25` (no canonical merge) · `plans/2026-07-31-1-…:43` (one-store-two-consumers).
- CISS: `src/manifest.rs` (I5 seq-CAS, the frontier's ordering primitive) · `docs/SECURITY-POSTURE.md`
  (billing invariants; the exit-exempt candidate invariant) · `docs/TESTING-STRATEGY.md` (World/Actor) ·
  the API map (v0.5.6): 2 MiB cap, `du`/`listBlobs` have-set, no Range/multipart/HEAD/304, unilateral receipts.
