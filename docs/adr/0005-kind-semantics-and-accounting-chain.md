# ADR 0005 — Kind semantics classes, and the accounting chain

- Status: **Proposed (scoping)** — owner-initiated 2026-08-11; design first,
  implementation gated on acceptance
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
three concrete gaps in the first external integration:

1. **Accounting in a latest-wins slot.** `kv.counter` overwrites: the current
   total is whatever the last write said. For a *usage/accounting* value that
   is the wrong shape — the writer (or anyone who compromises it) can silently
   assert a lower total, and there is no audit trail to notice. CISS's own
   money-path already knows the right shape: receipts → ledger → statements
   are **append-only, hash-linked, co-signed** — an edit breaks the chain at
   exactly that link. That integrity never reached the assertion substrate.
2. **Deletion semantics are unstated.** Removing a member is a `flag=false`
   overwrite (works; the old value is genuinely gone because
   `ON CONFLICT DO UPDATE` replaces the row) — but **erasing the row** (no
   trace the subkey ever existed) has no endpoint. For some kinds erasure is
   a legitimate need (data-deletion regimes); for chained kinds it must be
   *refused by design* (erasure breaks the chain — that is the feature).
   Neither stance is currently declarable; both are just "whatever the code
   does".
3. **Enumeration is unstated.** There is no "list my subkeys of kind K"
   endpoint. Sometimes that is a virtue (no readable roster); sometimes it is
   a gap (migration, audit tooling). Again: a property, not a policy.

## Proposal: each kind declares its semantics class

Kinds stay **code, not data** (the registry stays closed). What changes: the
registry entry for a kind declares its semantics on three axes, and the
generic machinery enforces them — so a new use case picks a point in a small,
named space instead of hand-rolling behaviour.

| Axis | Values | Meaning |
|---|---|---|
| **Retention** | `setting` \| `chain` | `setting`: latest-wins, the old value is replaced and gone. `chain`: append-only; each entry binds the previous entry's hash; history is the value. |
| **Erasure** | `erasable` \| `permanent` | `erasable`: a row-delete endpoint (`DELETE /{did}/assertion/{kind}/{subkey}`, owner-authorized) removes the subkey entirely. `permanent`: delete is refused with the reason. **`chain` implies `permanent`** — an erasable chain is a contradiction. |
| **Enumeration** | `listable` \| `point-only` | `listable`: `GET /{did}/assertions/{kind}` returns the owner's subkeys (owner-only, like `du`). `point-only`: lookups require knowing the key — the no-readable-roster stance, chosen on purpose. |

Classification of what exists:

| Kind | Retention | Erasure | Enumeration | Notes |
|---|---|---|---|---|
| `policy` (+ per-object) | setting | erasable | point-only | clear-to-default already exists in spirit |
| `dial.*` | setting | erasable | point-only | clearing a dial restores provider defaults |
| `kv.flag` | setting | **erasable** | **listable** | erasure = the true-removal story the integration wanted; listable = the migration/audit story |
| `kv.counter` | setting | erasable | listable | **deprecated for accounting** once the chain kind lands; stays for genuinely latest-wins totals |
| **`chain.counter` (new)** | **chain** | **permanent** | listable | the accounting kind — below |

## The accounting chain kind (`chain.counter`)

A per-subkey append-only counter with the ledger's integrity, on the
assertion substrate's envelope:

- Entry body: `{ delta: u64-as-signed?, total: u64, prev_entry_hash: hex }`
  (first entry: `prev_entry_hash = GENESIS`). The fold binds all three.
- Server-side set-time enforcement (like the ceiling dial's bound check):
  `total == prev.total + delta` and `prev_entry_hash == hash(prev entry)`;
  a mismatch is refused at set with the real values quoted.
- Reads return the latest entry; `?chain=1` returns the full chain for
  verification — "the books balance" is **recomputable, not asserted**
  (`verify_entries` discipline, ported to the substrate).
- Storage: unlike `setting` kinds, entries append (a `chain_entry` table or
  an `(did,kind,subkey,seq)`-keyed history — implementation's choice; the
  declared semantics are the contract).
- Signing: Model A/C as today. A future co-signed variant (provider
  countersigns each entry, ADR-0004's bilateral pattern) is the natural
  extension when a chain's total carries money; not in the first cut.

**First consumer:** croft-relay-admit's usage accounting moves from
`kv.counter` to `chain.counter` on a pin bump — its relay-usage totals become
tamper-evident, and a compromised admission service can no longer silently
shrink a member's usage history. (Its *membership* stays `kv.flag`: a
membership roster wants erasure, not permanence — the axes really are
mutually exclusive per use case.)

## What acceptance would unlock, in one line each

- **Correct deletion** where deletion is right (`kv.flag` erasure — the
  member-tombstone question, solved by declaration rather than workaround).
- **Correct permanence** where permanence is right (accounting that cannot be
  quietly rewritten, refusal-to-delete as a feature with a reason string).
- **Enumeration as a choice** (migration/audit for kinds that opt in; the
  no-roster stance preserved for kinds that don't).
- New use cases become a **table row + a typed body**, not a bespoke design
  conversation.

## Out of scope (named)

- Rewriting existing kinds' behaviour before classification is agreed.
- The co-signed chain variant (money-grade; needs ADR-0004's machinery).
- Cross-kind or cross-subkey transactions.
- Consumer-defined kinds (the registry stays closed; this ADR makes closed
  cheap, not open).

## Consequences if accepted

- The kind registry grows a declaration struct; `kind_fold` becomes one
  branch of a `KindSpec` (fold + validate + semantics).
- Two new generic endpoints (owner-only): DELETE for erasable kinds, LIST for
  listable kinds — each refusing, with the declared reason, for kinds that
  opted out.
- `chain.counter` lands with set-time chain verification and recomputable
  reads.
- Downstream pins (README "Downstream consumers") bump deliberately;
  croft-relay-admit's move off `kv.counter` is its own PR against this
  CHANGELOG entry.
