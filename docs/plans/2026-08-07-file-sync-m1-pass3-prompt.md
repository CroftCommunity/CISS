# Handoff prompt — Pass 3 (quality gates) for the CISS file-sync M1 plan

Copy everything below the line into a fresh session (run it with the working directory at
`/Users/cpettet/git/chasemp/CroftC/CISS`, branch `ciss-sync`). It is self-contained: it carries the
problem space, prior art, approach, hard constraints, and every source reference Pass 3 needs.

---

You are running **Pass 3 (quality gates)** of the `phase-plan` three-pass workflow on an existing,
already-reviewed plan. **This is analysis only — do not write production code.** Passes are *additive*:
extend Pass 1+2, do not rewrite or reorganize what they produced unless something is concretely wrong.

## Your task

1. Load the skill: `/Users/cpettet/git/chasemp/coding-agents/skills/phase-plan.md` and its
   `skills/phase-plan/pass3.md` (and `execute.md` for the guardrails it references).
2. Apply Pass 3 to the **target plan doc**:
   `/Users/cpettet/git/chasemp/CroftC/CISS/docs/plans/2026-08-07-file-sync-m1-chunk-and-backup.md`
   (its parent/milestone context is `docs/plans/2026-08-07-file-sync-client.md`).
3. Layer these quality gates onto the plan (add/insert, don't rewrite):
   - **TDD ordering** — each phase's **wiring test** is named and written **RED first**; make the RED→GREEN
     sequence explicit per phase. Every integrity/security-relevant guard (2 MiB chunk cap, `verify_cid` on
     receipt, DAG-CBOR determinism / stable `content_id`, keep-set Manifest under I5, tamper-rejected chunk)
     lands RED-first and stays as a regression wall. This is a security-relevant crate — treat it that way.
   - **Observability / diagnostic logging** — the backup/restore flow must emit enough (via `tracing`, the
     repo's logging crate) to debug a failed sync in the field: which file, which chunk cid, have/want
     decision, what the server returned. Add a per-phase "diagnostics" note.
   - **Validation calibration** — confirm each phase's Validation matches its risk (narrow/moderate/broad);
     upgrade any that are under-specified. Wiring tests are the floor, not the ceiling.
   - **Documentation-Impact coverage** — verify every doc the plan touches is scheduled *in the phase that
     makes it stale* (Cargo workspace member, ARCHITECTURE, README, the milestone-plan link, a possible
     `ciss-cli` lib.rs). No end-of-plan "docs phase."
   - **Isolation honesty** — the Concurrency Map is "all sequential"; confirm that's right and the
     shared-state contracts (ephemeral in-process server port in tests, tempdirs, no git ops) are accurate.
   - **Mutation-testing note** — the chunker + the DAG-CBOR serializer + the fold-adjacent code are the
     "encoder / state-machine" shape the repo's `CLAUDE.md` flags for `cargo mutants` after green.
4. Add a **Review Log** entry recording what Pass 3 found/changed. Then present any open questions as a
   one-at-a-time severity walk-through (BLOCKING / PHASE-GATED / ADVISORY) and **stop before execution** —
   do not start Phase 0 until the user says "execute."

## Problem space (broad overview)

We are building a **cloud-storage file-sync client** with **CISS** (Croft Item Storage Server — a Rust,
S3-compatible + atproto-blob, *metered, content-addressed* object store) as the server side. Files are
modeled as **manifests of content-defined chunks**, so the metadata plane (small, frequent) is separated
from the data plane (large, dedup'd): you sync a tiny table-of-contents and transfer only the chunks the
server doesn't already hold. The long arc is a **milestone ladder** M1→M5: backup/restore → bounded local
footprint → two-device convergence → iroh peer-fetch → cost twin. The design's hard problem is the
**frontier** (multi-writer "what is current, learned without trusting anyone's word or any clock"), which is
a known *open, unearned* frontier in the Croft/Drystone corpus — this client is its first concrete, tractable
(dataplane) instance. **M1 (this plan) does not build the frontier** — a single device's frontier is trivial
and tracked client-local. M1 proves the spine everything else stands on.

## M1 scope (this plan)

"Back up a directory to CISS and restore it byte-identical," one device + the helper server. Three phases
under a Phase 0 discovery: **P0** pin external deps (`fastcdc`, `blake3`, a DAG-CBOR codec) + confirm `ciss`
re-exports + the manifest wire contract; **P1** the pure `ciss-sync` crate (FastCDC chunking, dual
sha-256/blake3 `ChunkRef`, `FsManifest`, a `ManifestCodec` trait with DAG-CBOR canonical, a minimal local
index); **P2** transport + `sync backup` (a `BlobTransport` trait, have/want via `du`, upload missing chunks
+ fs-manifest, a **new** `Client::put_manifest`, commit the keep-set Manifest); **P3** `sync restore` +
verify (fetch+`verify_cid` chunks, rebuild the tree, cold-restore fs-root discovery by small-blob scan).

## Prior art (real-world file sync — what informs the approach)

- **rsync** — rolling-checksum delta against a shared base. We use its *idea* (send only differences) but not
  its mechanism; kept as an optional large-mutable-file optimization, not the foundation.
- **Content-defined chunking (FastCDC/Rabin)** — restic, borg, casync/desync, Dropbox's modern stack. A
  content-defined boundary means a 1-byte insert re-chunks only locally; dedup and delta become the *same*
  mechanism ("upload the chunks you don't have"), with no server-side per-file state. This is our default.
- **git** — content-addressed objects, a Merkle tree, "have/want" negotiation, packfiles to amortize
  per-object overhead. We mirror content-addressing + have/want (via CISS `du`), and pack-thinking matters
  because CISS meters *per receipt*, so chunk size is an economic parameter.
- **Dropbox Smart Sync / OneDrive Files-On-Demand** — online-only placeholders + hydrate-on-access; the basis
  for M2's bounded local footprint (a content-addressed chunk is always safe to evict — it's re-fetchable by
  hash). Also the "conflicted copy" model for M3.
- **Syncthing (Block Exchange Protocol)** — block-level have/want between peers; the serverless analog for M4.
- **iroh-blobs (BLAKE3 + Bao verified streaming)** — resumable, range, verify-while-downloading, peer-fetch.
  Why we hash blake3 *now* even though M1 uses CISS's sha-256: the store becomes iroh-ready with no re-hash.
- **Willow / range-based set reconciliation (RBSR, Negentropy)** — the corpus's convergence primitive; a later
  efficiency upgrade over have/want-via-`du`, same set contract.
- **Unison** — bidirectional three-way reconciliation with conflict handling; the shape M3 adopts.
- **DAG-CBOR / IPLD (atproto)** — deterministic canonical encoding for content-addressed structured data; why
  the fs-manifest is DAG-CBOR (plain JSON is not deterministic, which would make the same tree get two cids).

## Approach (the design, for context)

- **Chunk + dual-hash:** FastCDC (avg 256 KiB, min 64 KiB, max 1 MiB — hard headroom under CISS's 2 MiB cap),
  each chunk hashed **sha-256** (CISS's address) and **blake3** (iroh's) in one pass, recorded in `ChunkRef`.
- **Filesystem manifest:** `path → {mode, mtime, size, [ChunkRef]}`, encoded **DAG-CBOR (canonical,
  deterministic)** — `content_id` = sha-256 over the DAG-CBOR bytes. Serialization is pluggable behind a
  `ManifestCodec` trait, but the *addressed* form must be deterministic; pretty-JSON is a decode-only
  `inspect` view, never stored/addressed.
- **Keep-set + commit:** the CISS `Manifest` (a signed Merkle over `(cid,size)` leaves with a monotonic-seq
  CAS, invariant **I5**) is the billing keep-set = ∪ all chunk cids + the fs-manifest blob cid. `build_manifest`
  already exists server-side.
- **Have/want:** `du` / `listBlobs` over the DID is the "have" set; upload only missing chunks. No new endpoint.
- **Identity:** **shared account key** for now (all devices hold the one keypair == DID, so no server
  write-auth change anywhere in M1–M5); graduating to MLS/lineage per-device keys is a later option.
- **Frontier (M3+, context only):** per-device signed `DeviceHead` records + a `Frontier{heads}` in the
  seq-CAS'd manifest slot; current tree = a client-side deterministic fold (per-path 3-way merge,
  conflict-copy, content-address tiebreak). The server stays a **content-blind helper**; serverless (iroh) is
  the same machinery. HEAD is a *self-verified fold*, never an asserted or server-minted pointer. **None of
  this is in M1.**

## Hard constraints (verified against CISS v0.5.6 — do not re-derive, honor these)

- 2 MiB `MAX_OBJECT_BYTES` per object → chunking mandatory; chunk-level resume replaces byte-range resume.
- **No** HTTP Range, multipart, resumable upload, HEAD, or conditional-GET/304. `du`/`listBlobs` are the only
  body-free "have" set (`du` returns `[{cid,bytes}]` + total, self-only).
- A signed **receipt per transfer**; receipts are **Unilateral only** (`Bilateral` → 501); **no pre-flight
  cost endpoint** (client prices `du`-sizes × tariff).
- Auth for M1 = the `id:` session (`session_for(keypair)`, `derive_id(key)==DID`) — the shared-account-key model.
- **The client has no manifest-PUT yet** (the `man` subcommand is the clap man-page generator) — Phase 2 adds
  `Client::put_manifest`/`get_manifest`.
- CISS is **indifferent** to plaintext vs ciphertext (a dumb content-addressed byte store) — encryption is a
  future client-only layer, out of M1.

## Source references

**CISS plan docs (this repo):**
- `docs/plans/2026-08-07-file-sync-m1-chunk-and-backup.md` — the Pass 3 **target**.
- `docs/plans/2026-08-07-file-sync-client.md` — milestone ladder + the full frontier design & reasoning.

**CISS code (this repo — read to keep the plan grounded):**
- `src/manifest.rs` — `Manifest`, `ManifestLeaf::new`, `build_manifest(&[leaf], id, key, seq)`, I5 seq-CAS,
  `MAX_OBJECT_BYTES` leaf bound.
- `crates/ciss-cli/src/client.rs` — `Client::{put_s3,get_s3,du,upload_blob}`, `verify_cid`, `session_for`,
  `Session`, `Usage/UsageObject`, `PutResult` (the transport surface P2 builds on; add `put_manifest` here).
- `src/server.rs` — `put_manifest_handler`/`op_put_manifest` (the wire contract + I5), `dispatch`, route table,
  `MAX_OBJECT_BYTES`, receipts.
- `src/pds_api.rs` — the atproto blob plane (`uploadBlob`/`getBlob`/`listBlobs`).
- `Cargo.toml` — workspace deps (`sha2`, `rusqlite` bundled, `reqwest`, `ipld-core`; add `fastcdc`, `blake3`,
  `serde_ipld_dagcbor`).
- `docs/SECURITY-POSTURE.md` — billing/integrity invariants (and the exit-exempt candidate invariant for M5).
- `docs/TESTING-STRATEGY.md` + `tests/common/**` + `tests/e*.rs` + any `tests/flow_*.rs` — the two test tiers;
  M1's wiring tests are workflow-tier (`World`/`Actor`) `flow_sync_backup` / `flow_sync_roundtrip`.
- `CLAUDE.md` (repo root) — CISS orientation + the bug-vs-design-gap discipline + posture-doc-first rule.

**discovery corpus (`/Users/cpettet/git/chasemp/CroftC/discovery`) — grounding, cite don't re-derive:**
- `alpha/COHESION.md` §67 · `alpha/ROADMAP_TODO.md` E90 (this work) / E89 (cost twin) / E82 (metered-storage
  lane) / E85 (flat manifest vs MST).
- `alpha/thinking/cost-ceilings-and-the-prepaid-meter.md` · `alpha/thinking/multi-device.md` (frontier
  exchange + same/cross-lineage tiers) · `alpha/thinking/meer-superpeer-design.md` (content-blind helper).
- `beta/drystone-spec/` (`part-1-reasoning-underpinnings.md`, `part-2-certifiable-design.md`,
  `open-threads.md`) + `beta/impl/drystone-design/{history-durability,liveness-freshness}.md`
  (`LocateLatest`, completeness-ahead, the causal fold — the frontier theory this dataplane instance realizes).
- `alpha/thinking/thesis-lineage-groups.md:25` (set-reconciliation shared, but NOT canonical merge).
- `alpha/plans/2026-07-31-1-plan-coop-metered-storage-service.md:43` (CISS = one store, two consumers).
- `alpha/seeds/transcripts/raw/ciss-cost-ceilings-and-prepaid-meter-equity-2026-08-07.md` (the source dialogue).

**Skill:** `/Users/cpettet/git/chasemp/coding-agents/skills/phase-plan.md` + `skills/phase-plan/pass3.md`.

## Conventions to honor

- **TDD is non-negotiable** (repo + global `CLAUDE.md`): no production code without a RED test first; Pass 3
  sets the ordering, `tdd-guardian` enforces it at execution.
- **Do NOT run `cargo fmt`** on CISS (local rustfmt disagrees with committed style — hand-format; gate on
  `cargo clippy --all-targets --workspace` + `cargo test --workspace`, both clean, clippy-pedantic).
- Rust discipline: `Result<T,E>` (thiserror), no `unwrap()`/`expect()` in production paths, doc comments on
  public items, newtypes at boundaries, `Zeroize` for any secret material.
- If you spawn subagents, pass `model` explicitly to match the session model (global `CLAUDE.md`).
- Git identity for this repo: `Chase Pettet <chase@owasp.org>`, host `github-personal`, account `chasemp`.
  Work is on branch `ciss-sync`; commit only when the user asks; end commit messages with
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## State at handoff

Plan committed on branch `ciss-sync` at `f6dea72` (Pass 1+2, all four open questions resolved). Nothing pushed.
After Pass 3 lands its Review Log entry and the user resolves any new open questions, the next step is
"execute" → Phase 0 discovery (Discovery Exemption applies) → Phases 1–3 with commit-per-phase.
