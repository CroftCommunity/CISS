# CISS file-sync — M3 execution plan (two-device converge, the frontier made real)

date: 2026-08-07
status: **Planned (condensed passes; the server phase is security-relevant and reasoned in full). EXECUTING.**
parent: `docs/plans/2026-08-07-file-sync-client.md` (milestone ladder; this doc executes **M3**).

## Problem Statement

Deliver **M3**: *"a second device converges, and a real conflict is preserved, not lost."* The
multi-writer frontier — per-device signed `DeviceHead`s named in a `Frontier.heads` map, folded
client-side — becomes real. This is the ladder's **only server change**: one additive, owner-signed
`heads` field on the CISS `Manifest`, bound into the signing preimage, still governed by I5. The server
gains no authority: it validates the signature and seq-monotonicity and stores bytes; the fold stays
entirely client-side; HEAD is never asserted or server-minted.

## Reasoning

**Why the server change is safe and small.** `heads: Option<BTreeMap<device_id, cid>>` on `Manifest`,
absent for every existing manifest. The signing preimage stays byte-identical when `heads` is `None`
(legacy manifests keep verifying — the back-compat guard is a RED-first test) and appends a canonical
heads digest when present, so a tampered or injected `heads` entry fails `verify()` exactly like a
tampered root (B1 extended, SECURITY-POSTURE updated in the same phase). I5 is untouched: a stale-seq
write is refused regardless of what its `heads` says, so a lagging device can never roll back another
device's head.

**The M3 no-data-loss invariant: the keep-set covers every head, not just mine.** A device committing
the Frontier commits the keep-set too — if it listed only its own tree, its commit would GC the *other*
device's chunks. So the commit computes keep-set = ∪ over **all** heads in the frontier being written:
each head's DeviceHead blob + fs-manifest + all its chunks + its base fs-manifest (manifest blob only —
the fold compares chunk *refs* against the base, never fetches base bytes). This lands RED-first, like
M2's placeholder-merge guard.

**Non-lossy concurrency by slot discipline.** Each device writes only `heads[its own device_id]`; a
stale-seq refusal (I5) triggers re-GET → re-apply own slot onto the fresh heads → retry (bounded).
Two devices committing concurrently both land; neither's head is ever overwritten by the other's retry.

**The fold is deterministic and clock-free.** Per-path 3-way merge against the last converged base
(client-local; each device records the folded tree's manifest cid as `base` after converging):
one-sided change → take it; identical → converged; divergent → **conflict-copy** (winner of the path by
content-address order — the smaller entry digest keeps the path, the loser materializes at
`<path>.conflict-<device_id>`; both contents preserved, both committed); modify-vs-delete → keep the
modification (non-lossy default, recorded here). mtime never participates (E90: timestamps are an
assertion). `DeviceHead` is a signed DAG-CBOR blob with a `croft.device-head/v1` kind self-tag (the
fs-manifest pattern), verified client-side on every fold — a head that fails its signature or tag is
rejected even from "yourself" (the corpus's HEAD doctrine).

**Rename detection: deliberately skipped (⏭️).** Dedup already gives the prize — a rename is
delete+add whose chunks the server has, so **zero chunks transfer** without any detection (tested as
such). Exact-chunk-set detection remains the recorded optional polish.

**Device identity (shared-key era):** `device_id` = a stable self-asserted install label, generated
once per profile (random 8-hex, stored in the profile config dir); `counter`/`parent` (the per-device
chain) live in the per-tree SyncState.

## Verified Assumptions

- `signing_preimage` = `ciss/v1/manifest:signer:seq:leaf_count:total_bytes:root` (src/manifest.rs:115);
  `Manifest` + `ManifestLeaf` are `deny_unknown_fields` (so `heads` needs `#[serde(default)]` +
  skip-if-none to keep old-wire compatibility); `verify()` checks leaves/root/total then the signature
  (src/manifest.rs:168). `build_manifest` is pre-1.0 — signature change, call sites updated, no compat
  shims (CLAUDE.md).
- Server manifest tests live in `tests/e2_manifest.rs` (+ `wiring_*`/flow guards); the M1/M2 client
  stack (`HttpCiss`, `SyncState`, materializer, flow harness) is on main.

## Documentation Impact

- `docs/SECURITY-POSTURE.md` — B1 wording: the manifest signature also binds `heads` when present. **Phase 1.**
- `README.md` — `sync converge` line. **Phase 3.**
- `docs/plans/2026-08-07-file-sync-client.md` — M3 stamp + the one-server-change note marked done. **Phase 3.**

## Concurrency Map

**All phases sequential** (Phase 2 needs Phase 1's wire field; Phase 3 needs Phase 2's commit loop).

## Phases

### Phase 1: CISS server — additive owner-signed `Manifest.heads` under I5
**Changes:** `heads: Option<BTreeMap<String, String>>` on `Manifest` (`default` + skip-if-none);
preimage appends `:heads=<sha256 over "id=cid;"… sorted>` **only when present**; `build_manifest` gains
the heads param (call sites updated); `verify()` covers it via the preimage; server handlers unchanged
(self-authorizing PUT already verifies). POSTURE B1 note.
**Test-first (RED):** `legacy_manifest_without_heads_still_verifies` (byte-identical preimage — the
back-compat guard); `tampered_heads_fails_verify` (add/remove/alter an entry after signing);
`heads_round_trips_over_the_wire` (PUT with heads → GET returns them, second session reads them);
`stale_seq_with_different_heads_refused` (I5 holds; the stored heads unchanged).
**Validation:** server-side unit + wiring; this is a signing-surface change → mutation audit on
`src/manifest.rs` after green.

### Phase 2: engine — `DeviceHead` + the non-lossy frontier commit
**Changes:** `device_head.rs` (record + kind tag + sign/verify over a domain-tagged preimage);
`SyncState` gains `device_id()` (profile-level, generated once), `counter`/`last_head`/`base` columns;
`backup` becomes frontier-aware behind the same API: upload DeviceHead blob, keep-set = ∪ all heads'
closures (the invariant above), commit `heads[my_id]` with bounded stale-seq retry re-applying only the
own slot.
**Test-first (RED):** flow `tests/flow_sync_frontier.rs` — `two_devices_both_land` (B commits between
A's read and write; A's retry lands; both heads present; **neither device's chunks left the keep-set**);
`keep_set_covers_other_head` (the no-data-loss guard, distinct assert); `device_head_chain`
(counter/parent advance; a bad signature or wrong kind is rejected on read).

### Phase 3: engine + CLI — the fold, conflict-copy, `sync converge`
**Changes:** `fold.rs` (3-way per-path vs base; the decision table above; deterministic conflict
naming); `converge` flow (fetch heads' manifests → fold → materialize deltas via the shared
materializer → commit folded tree as own head → record new base); CLI `sync converge <dir>`; docs.
**Test-first (RED):** `disjoint_edits_merge` (A adds x, B edits y → both trees identical afterward,
content_ids equal); `same_path_divergence_preserved` (both edit p → winner at p by content-address,
loser at `p.conflict-<id>`, both byte-contents present on **both** devices after each converges);
`rename_transfers_zero_chunks` (mv a→b on A; B converges; report shows 0 uploaded/0 fetched-from-server
for content, dedup carries it); `modify_beats_delete` (recorded default).
**Validation:** moderate+ — flow suite + a live two-device drill against a real server (two state
roots/profiles, real conflict, verify both converge byte-identically).

## Open Questions — resolved by default (execution delegated; overrides welcome)

- Conflict naming `<path>.conflict-<device_id>` with content-address winner-keeps-path. *ADVISORY.*
- Modify-vs-delete → modification wins (non-lossy). *ADVISORY.*
- Rename detection skipped (dedup already zero-transfer). *ADVISORY, recorded ⏭️.*
- Frontier `base` = client-local last-converged manifest cid (not a server object). *ADVISORY.*

## Review Log

- **2026-08-07 (condensed passes)** — plan authored from the milestone M3 slice + the settled frontier
  design. Pass-2/3 checks folded in: preimage back-compat guard named RED-first; keep-set-covers-all-heads
  as the phase-2 centerpiece; fold decision table written down before code; server phase carries the
  POSTURE doc update in-phase; mutation audit scoped to `manifest.rs` (signing surface) + `fold.rs`.
