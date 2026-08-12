# ADR 0005 — Kind semantics classes, and the accounting chain

- Status: **Proposed** — owner-initiated 2026-08-11; axes, checkpoint design,
  and classifications **walked through and agreed with the owner 2026-08-11**
  (hashing + sizing axes added at the owner's direction). Implementation
  gated on final acceptance.
- Context: the assertion substrate (D1) + the first external-consumer kinds
  (`kv.flag`/`kv.counter`, PR #35) + the deletion-semantics question the
  croft-relay-admit integration surfaced

## Problem

The self-assertion substrate is proving to be the right primitive: a
crypto-signed KV store where writes are owner-signed (or provider-attested),
`seq` is strictly monotonic, reads are acked, and persistence is one story.
Consumers keep wanting it — and **each kind use case is similar, with a few
mutually exclusive needs** (owner's framing, verbatim). Today those needs are
implicit in each kind's implementation rather than declared, which produced
concrete gaps in the first external integration:

1. **Accounting in a latest-wins slot.** `kv.counter` overwrites: the current
   total is whatever the last write said. For a usage/accounting value that is
   the wrong shape — the writer (or anyone who compromises it) can silently
   assert a lower total, and there is no audit trail to notice. CISS's own
   money-path already knows the right shape: receipts → ledger → statements
   are **append-only, hash-linked, co-signed** — an edit breaks the chain at
   exactly that link. That integrity never reached the assertion substrate.
2. **Deletion semantics are unstated.** Removing a member is a `flag=false`
   overwrite (works; the old value is genuinely gone — `ON CONFLICT DO
   UPDATE` replaces the row) — but **erasing the row** has no endpoint. For
   some kinds erasure is a legitimate need (data-deletion regimes); for
   chained kinds it must be *refused by design*. Neither stance is currently
   declarable.
3. **Enumeration is unstated.** No "list my subkeys of kind K" endpoint.
   Sometimes a virtue (no readable roster), sometimes a gap (migration,
   audit). A property, not a policy.
4. **Hashing is unstated.** Three postures already live in the ecosystem —
   fold-bound signatures, chain-linked entries, content-addressed objects —
   and two algorithms, deliberately split (BLAKE3 for file transfer on the
   iroh side; SHA-256 in CISS's chains and content addresses). Nothing
   declares which posture/algorithm a kind uses, so the alignment is
   assumed, not stated — and vulnerable to a well-meaning "harmonizing"
   refactor that crosses an ecosystem boundary without noticing.
5. **Sizing is unstated.** No per-kind body ceiling, and — the sharp case —
   an append-only kind with no growth story quietly means "monotonically
   growing SQLite forever." Nothing may be assumed infinite (owner's
   ruling).

## Proposal: each kind declares its semantics

Kinds stay **code, not data** (the registry stays closed). What changes: the
registry entry for a kind declares its semantics on **five axes**, and the
generic machinery enforces them — a new use case picks a point in a small,
named space instead of hand-rolling behaviour.

| Axis | Values | Meaning |
|---|---|---|
| **Retention** | `setting` \| `chain` | `setting`: latest-wins; the old value is replaced and gone. `chain`: append-only; each entry binds the previous entry's hash; history is the value. |
| **Erasure** | `erasable` \| `permanent` | `erasable`: an owner-authorized `DELETE /{did}/assertion/{kind}/{subkey}` removes the subkey entirely. `permanent`: delete is refused with the declared reason. **`chain` implies `permanent`** — an erasable chain is a contradiction. |
| **Enumeration** | `listable` \| `point-only` | `listable`: owner-only `GET /{did}/assertions/{kind}` returns the subkeys (the `du` discipline). `point-only`: lookups require knowing the key — the no-readable-roster stance, chosen on purpose. |
| **Hashing** | `fold-bound` \| `chain-linked` \| `content-addressed`, **× algorithm** | `fold-bound`: the signature covers a canonical fold; no standalone content hash. `chain-linked`: additionally binds the previous entry's hash (implies fold-bound). `content-addressed`: the hash is the identity. The **algorithm is part of the declaration** — SHA-256 for CISS chains/content addresses, BLAKE3 where a kind's content interoperates with iroh file transfer. The split is deliberate ecosystem alignment; declaring it per kind is what stops a refactor from "harmonizing" across the boundary. |
| **Sizing** | body ceiling (bytes), **growth**: `bounded` \| `rolling` \| `unbounded` | Every kind declares a max body size. `bounded`: at most one row per subkey (settings). `rolling`: entries compact behind acknowledged checkpoints (chains — see below), parameterized by a roll trigger (every N entries or S bytes). `unbounded`: eternal fine-grained history as a **visible, conscious choice** — never a default. |

Classification of what exists (owner-agreed):

| Kind | Retention | Erasure | Enumeration | Hashing | Sizing |
|---|---|---|---|---|---|
| `policy` (+ per-object) | setting | erasable | point-only | fold-bound / SHA-256 | small ceiling, bounded |
| `dial.*` | setting | erasable | point-only | fold-bound / SHA-256 | small ceiling, bounded |
| `kv.flag` | setting | **erasable** | **listable** | fold-bound / SHA-256 | small ceiling, bounded |
| `kv.counter` | setting | erasable | listable | fold-bound / SHA-256 | **REMOVED once `chain.counter` lands** — a deprecated-but-present kind is a 2am trap (owner's call); no latest-wins counter use case currently exists to justify keeping it |
| **`chain.counter` (new)** | **chain** | **permanent** | listable | **chain-linked / SHA-256** | small ceiling, **rolling** |

Notes on the agreed calls:

- **`kv.flag` listable**: yes — the admit tenant may enumerate its own
  digests (migration, audit). The digests are peppered, so the enumeration
  is unreadable without a secret held outside the store.
- **`kv.flag` erasable**: this is the correct member-removal story — true
  row erasure, retiring the tombstone residue from the Phase-6 integration.

## The accounting chain kind (`chain.counter`)

A per-subkey append-only counter with the ledger's integrity, on the
assertion substrate's envelope:

- Entry body: `{ delta: i64, total: u64, prev_entry_hash: hex }` (first
  entry: `prev_entry_hash = GENESIS`). **`delta` is signed**: corrections are
  new entries with the history showing them (the ledger's principle — nothing
  edited in place), while `total` remains the checked invariant.
- Server-side set-time enforcement (the ceiling dial's refuse-at-set
  pattern): `total == prev.total + delta` and `prev_entry_hash ==
  hash(prev entry)`; a mismatch is refused quoting the real values. The
  server is thereby a chain *participant*, not a dumb store — it loads the
  previous entry on every append. Named as a cost; acceptable at target
  scale.
- Reads return the latest entry; `?chain=1` returns the entries back to the
  nearest checkpoint — "the books balance" is **recomputable, not asserted**
  (`verify_entries` discipline, ported to the substrate).

### Checkpoints and compaction (the `rolling` growth story)

Without this, `permanent` + append-only = unbounded storage and
ever-growing verification walks. The fix is the balance-forward statement
pattern CISS's money path already uses, applied per chain:

```
e1 → e2 → … → e100 → [CHECKPOINT C1] → e101 → …
                      { closing_total,
                        chain_head_hash = hash(e100),   ← commits transitively
                        prev_checkpoint = GENESIS }        to ALL of e1..e100
```

- A **checkpoint is itself a chain entry** — signed, hash-linked, verified
  at write time (its `closing_total` must equal the running total). Its
  `chain_head_hash` transitively commits to every entry behind it.
- **Compaction is permitted only behind an *acknowledged* checkpoint** —
  the no-shredding-before-agreement rule. The substrate already acks every
  accepted assertion; the checkpoint's provider ack is the agreement (writer
  asserted the close, store attested it; both signatures exist). Then
  `e1..e100` may be deleted; `C1` is the chain's new genesis, carrying the
  old world's conclusion. A future money-grade chain upgrades the ack to
  ADR-0004's bilateral co-signing — same shape, stronger second signature.
- After compaction, verification walks only back to the nearest checkpoint;
  storage per chain is (entries since last checkpoint + one checkpoint per
  period). Both costs bounded.
- **What is given up, stated plainly (owner-acknowledged):** fine-grained
  history behind the checkpoint is gone — the aggregate survives, the
  per-event breakdown does not. For accounting this is correct, and it is
  *less* retained data, which the privacy posture favours. A use case
  needing eternal detail declares `unbounded` and consciously eats the
  cost.
- The roll trigger (every N entries / S bytes) is the `rolling`
  declaration's parameter.

**First consumer:** croft-relay-admit's usage accounting moves from
`kv.counter` to `chain.counter` on a pin bump — its relay-usage totals become
tamper-evident, and a compromised admission service can no longer silently
shrink a member's usage history. (Its *membership* stays `kv.flag`: a roster
wants erasure, not permanence — the axes really are mutually exclusive per
use case.) `kv.counter` is removed in the same release; the consumer bump PR
handles both, reading this CHANGELOG entry.

## What acceptance unlocks, in one line each

- **Correct deletion** where deletion is right (`kv.flag` erasure — member
  removal with no residue, by declaration rather than workaround).
- **Correct permanence** where permanence is right (accounting that cannot
  be quietly rewritten; refusal-to-delete as a feature with a reason).
- **Enumeration as a choice** (migration/audit for kinds that opt in; the
  no-roster stance preserved for kinds that don't).
- **Hashing alignment declared** (posture + algorithm per kind; the
  BLAKE3/SHA-256 ecosystem split stated, not assumed).
- **Nothing assumed infinite** (body ceilings everywhere; growth posture
  everywhere; `unbounded` exists only as a visible choice).
- New use cases become a **table row + a typed body**, not a bespoke design
  conversation.

## Out of scope (named)

- Rewriting existing kinds' behaviour before this classification lands.
- The co-signed (bilateral) chain variant — money-grade; needs ADR-0004's
  machinery; the checkpoint-ack design above is its forward-compatible
  seat.
- Cross-kind or cross-subkey transactions.
- Consumer-defined kinds (the registry stays closed; this ADR makes closed
  *cheap*, not open).
- Re-hashing or re-addressing existing stores; declarations describe what
  is, then constrain what changes.

## Consequences if accepted

- The kind registry grows a declaration struct (`KindSpec`: fold + validate
  + the five-axis semantics); `kind_fold` becomes one branch of it.
- Two new generic endpoints (owner-only): DELETE for erasable kinds, LIST
  for listable kinds — each refusing, with the declared reason, for kinds
  that opted out.
- `chain.counter` lands with set-time chain verification, recomputable
  reads, and checkpoint/compaction under the ack rule; `kv.counter` is
  removed in the same release.
- Body-size ceilings are enforced at the boundary for every kind.
- Downstream pins (README "Downstream consumers") bump deliberately;
  croft-relay-admit's move is its own PR against this CHANGELOG entry.


## Cross-inspection: the whole store, against the axes (2026-08-11)

At the owner's direction, every storage surface in CISS — not only assertion
kinds — was swept against the model to see whether the framing bears out.
**It does, and the sweep refined it**; the full classification table now lives
in `ARCHITECTURE.md` §5a as the repo's stated storage model, replacing the
build-by-use-case framing. What the inspection changed:

1. **Retention has four values, not two.** Content-addressed blobs are
   `immutable` (write-once per key, deletable, never updated — neither a
   setting nor a chain). Receipts are a **`log`**: append-only rows whose
   integrity comes from periodic roots (statements) rather than per-entry
   links. So: `setting | immutable | log | chain`.
2. **Authorship is a sixth axis**, latent everywhere: `derived` (unsigned,
   rebuildable caches — `did_total`, `meta`; never authoritative) |
   `owner-signed` | `provider-signed` | `co-signed`. The substrate's Model
   A/C is this axis's assertion-shaped corner.
3. **Hashing gains a fourth posture: `merkle-rooted`** — the manifest's root
   over `(cid, size)` leaves, and the roots statements bind. Commitment over
   a *set*, distinct from fold, link, and identity.
4. **The checkpoint design is a port of shipped practice, not an
   invention:** `purge_receipts_settled_through` already drops receipts
   behind a *settled* (co-signed) statement — compaction behind an
   acknowledged checkpoint, live in the money path today. `chain.counter`
   generalizes it to the substrate. The seal **tombstone** tier likewise
   corroborates the erasure axis at its extreme: `permanent` enforced by
   destroying the unseal capability.

Nothing in the store resisted classification; the two `derived` tables were
the only surfaces needing a value the assertion-shaped draft lacked, and the
authorship axis absorbs them cleanly.

## Implementation order (when accepted)

1. `KindSpec` + reclassification of existing kinds (no behaviour change yet;
   body ceilings begin enforcing).
2. The two generic endpoints (DELETE / LIST), each RED-first with the
   refusal cases as controls.
3. `chain.counter` (entries + set-time verification + recomputable reads).
4. Checkpoints + compaction under the ack rule.
5. The consumer bump (croft-relay-admit usage → `chain.counter`;
   `kv.counter` removed).
