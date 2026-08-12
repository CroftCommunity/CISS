# Kind semantics + the accounting chain: implementation plan

- **Status: IMPLEMENTED ✅ (2026-08-12).** All six phases landed, each RED-first,
  green + clippy-clean; the two money-shaped phases are mutation-clean (A3 16/16,
  A4 35/35). **Milestone A** merged to `main` as **release 0.8.0 (PR #37,
  `2d1e685`)**: A1 `KindSpec` + body ceilings · A2 generic DELETE/LIST · A3
  `chain.counter` · A4 checkpoints + compaction (configurable `on_ack`/`deferred`)
  · A5 `kv.counter` removed. **Milestone B / B1** merged to `croft-stack` (**PR
  #7, `b882d8f`**): pin bump to `2d1e685`, usage → `chain.counter`, `remove()` →
  DELETE, `keys()` → LIST. Execution notes per phase are in the commit history
  and the tiered-admission plan's execution log (discovery repo). ADR 0005 is the
  reasoning record; `ARCHITECTURE.md` §5a the stated model.
- **Original framing (retained):** ADR 0005 **Accepted** 2026-08-11; the design
  conversation (owner walk-through of every axis, the checkpoint model, and both
  classification calls) and the full-store cross-inspection served as this plan's
  design and verification passes. Six phases in **two milestones across two
  surfaces, strictly sequential** (owner: "implement one, then the other so that
  it's all in line — that's the advantage of it all being ours").
- **Surfaces:** Milestone A is this repo; Milestone B is
  `croft-stack/relay/source` (the pinned consumer). Milestone B starts only
  after A's release commit exists — the pin bump *is* the interface.
- **Discipline:** CISS house rules throughout (TDD RED-first, workflow-tier
  tests over `World`, clippy-pedantic clean, no `cargo fmt` runs).

## Problem Statement

ADR 0005 is accepted but unimplemented: kind semantics live as implicit code
behaviour, accounting sits in a latest-wins slot (`kv.counter`) where a
compromised writer can silently rewrite history, member removal cannot erase
its row, and nothing enforces body ceilings. The consumer
(croft-relay-admit) carries three recorded workarounds waiting on this work:
`keys()`/`remove()` returning `Unavailable`, and usage on the wrong kind.

## Approach

Build the declaration machinery first (no behaviour change beyond ceilings),
then the two generic endpoints, then the chain kind, then its checkpoint
story — each step leaving the workspace green — and only then bump the
consumer, migrating usage and retiring all three workarounds in one PR.

## Reasoning

Order follows dependency and blast radius: `KindSpec` is load-bearing for
everything after it; endpoints before the chain so the chain lands with its
enumeration story already generic; checkpoints after the plain chain so
set-time verification is proven before compaction complicates it; the
consumer last because the pin means A's mistakes are invisible downstream
until B chooses to see them — sequencing IS the isolation. `kv.counter` is
removed in A's release (not deprecated — owner: no 2am traps); the pinned
consumer keeps working on its old pin until B, so removal-before-migration
breaks nobody. **No data migration exists anywhere:** the private admit
instance is not yet deployed; only test data has ever been written under
`kv.counter`.

---

## Milestone A — CISS: the substrate learns its semantics

### Phase A1: `KindSpec` + reclassification + body ceilings

The declaration struct: retention (`Setting|Immutable|Log|Chain`), authorship,
erasure, enumeration, hashing (posture × algorithm), sizing (body ceiling +
growth). `kind_fold` becomes one accessor on the spec; every existing kind
gets its ARCHITECTURE §5a row as code. **Only new behaviour: body ceilings
enforce at the boundary** (over-ceiling assertion refused with the limit
quoted — the ceiling-dial refusal pattern).
**RED first:** spec-table unit rows (each kind's declaration pinned, the
chain⇒permanent invariant a `const` assertion or constructor refusal);
workflow: an over-ceiling body refused quoting the ceiling, an at-ceiling
body accepted.
**Write-set:** `src/kind_spec.rs` (new), `src/server.rs` (registry),
`src/kv.rs`, `src/dials.rs`, `src/policy.rs` (spec entries), tests.
**Done when:** every registered kind carries a spec; ceilings live; workspace
green, clippy-pedantic clean.

### Phase A2: the generic endpoints — DELETE (erasable) and LIST (listable)

`DELETE /{did}/assertion/{kind}/{subkey}` — owner-authorized (same auth as
writes), allowed only for kinds declaring `erasable`; refusal quotes the
declared reason for `permanent` kinds. `GET /{did}/assertions/{kind}` —
owner-only (the `du` discipline: self-only, no existence oracle), allowed
only for `listable` kinds.
**RED first, refusals as controls:** erase a `kv.flag` → row gone (a
subsequent GET 404s, a re-write starts at seq 1 — decide and pin the
post-erase seq semantics here); DELETE on `policy` → refused with reason;
LIST on `kv.flag` returns subkeys self-only, non-owner refused without an
existence oracle; LIST on `dial.*` (point-only) → refused.
**Write-set:** `src/server.rs` (routes + ops), `src/persist.rs`
(delete/list), tests.
**Done when:** both endpoints live and refuse by declaration; the security
posture note (no existence oracle, self-only) asserted by test.

### Phase A3: `chain.counter`

The chain kind per the ADR: entries `{delta: i64, total: u64,
prev_entry_hash}` in a new append table (the assertion table's PRIMARY KEY
enforces latest-wins — chains get `chain_entry (did, kind, subkey, seq)`
history); set-time verification (`total == prev.total + delta`,
`prev_entry_hash == hash(prev)`) refusing with real values quoted; reads
return latest, `?chain=1` returns entries to the nearest checkpoint;
`verify_entries`-style recomputation exposed for tests and `ciss usage`.
**RED first:** append/verify happy path; wrong-total refused quoting the real
total; wrong-prev-hash refused; signed-delta correction (negative delta, total
invariant holds); recompute-from-chain equals asserted total; a fork attempt
(second entry at an existing seq) refused.
**Write-set:** `src/kv.rs` or `src/chain_kind.rs`, `src/persist.rs`
(chain_entry table), `src/server.rs`, tests.
**Done when:** the chain kind is mutation-clean on the verification path
(no-unexplained-survivors policy — this is money-shaped code).

### Phase A4: checkpoints + compaction (ack-before-shred)

A checkpoint entry (`closing_total`, `chain_head_hash`, `prev_checkpoint`)
verified at write like any entry; **compaction permitted only behind an
acknowledged checkpoint** (the substrate's provider ack is the agreement —
the `purge_receipts_settled_through` pattern, generalized); after compaction
verification walks to the nearest checkpoint; the roll trigger is the spec's
`rolling` parameter.
**RED first:** checkpoint with wrong closing_total refused; compaction before
ack refused; after ack, entries behind C1 gone, chain verifies from C1, total
continuity holds across the boundary; a tampered pre-checkpoint copy fails
verification against C1's head hash.
**Write-set:** chain kind module, `src/persist.rs`, tests.
**Done when:** a long chain stays bounded (storage + verification walk) with
integrity asserted across a compaction.

### Phase A5: remove `kv.counter`; release

Delete the kind (registry, module entry, its flow tests move to
`chain.counter` shapes); CHANGELOG entry written for the consumer's bump PR
to read (what moved, what was removed, the post-erase seq semantics from A2);
version bump per house release flow.
**Done when:** workspace green with `kv.counter` gone; the release commit
exists — its hash is Milestone B's pin.

## Milestone B — croft-relay-admit: the consumer bump

### Phase B1: pin bump + migration of the three workarounds

One PR in `croft-stack/relay/source`, reading A5's CHANGELOG: bump both git
pins (`ciss`, `ciss-cli`) to the release commit; **usage → `chain.counter`**
(CissStore appends `{delta, total, prev_hash}` — read-modify-write becomes
read-append; the once-retry survives); **`remove()` → the real DELETE**
(member removal with no residue — the tombstone caveat retires);
**`keys()` → the real LIST** (the migration/enumeration gap retires;
`ciss_store.rs`'s "deliberate gap" doc comment comes out). Persistence
wiring test extended: usage survives restart *as a verifiable chain*
(recompute equals total); erased member leaves no row.
**RED first** against the old behaviour where possible (the erase test is
RED by definition — the old backend refuses).
**Done when:** relay workspace green; the tiered-admission plan's Phase 6
execution notes gain the retirement record; both gates green.

---

## Concurrency Map

Strictly sequential: A1 → A2 → A3 → A4 → A5 → B1 (owner's ordering; the pin
is the isolation boundary between A and B). No parallel sets.

## Documentation impact

- ADR 0005: status Accepted (done); implementation-order section becomes a
  pointer here. A-phase supersessions none — this *implements*, not revises.
- `ARCHITECTURE.md` §5a: `chain.counter` row flips from "pending" at A3;
  `kv.counter` row drops at A5.
- CISS `CHANGELOG.md`: A5's entry (the bump PR's reading material).
- CISS `docs/TODO.md` item 0: points here; closes at B1.
- Relay side at B1: `ciss_store.rs` doc comments, `GUIDE.md` §7,
  tiered-admission plan execution note.
