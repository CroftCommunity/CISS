# Plan: the meer as a custodian-queue mode of CISS

**Status:** DRAFT — design record of an owner decision (2026-08-07, in conversation);
no implementation scheduled by this document. This is the committed home the workspace
decision registry marks as owed (`CroftC/.claude/DECISIONS.md`, row `CISS/meer-queue`).
Design-stage: nothing below is implemented; measurements cited are real, the mechanism
is `[UNVERIFIED]` until built.

## Problem statement

Drystone needs a **meer**: a blind MLS store-and-forward service (Part 2 §6.6.2,
D-meer) that holds ciphertext for offline members. Building it as its own service means
inventing a second store with its own identity, quotas, billing, and retention — beside
CISS, which already is the metered, owner-manifested store with proofs about who may
write what. The question this plan answers: what is the smallest meer that does not
duplicate CISS?

The decision (owner, 2026-08-07): **the meer is a thin pub/sub-in, mailbox-out shim
over CISS custodian chains — not a service with its own storage.**

## Approach

- **CISS gains a custodian chain mode.** A chain's **kind** (queue / file-sync /
  history-convergence) is declared in the **owner's manifest slot declaration** — never
  in the head blob — fixed at genesis, bound into the signed preimage the same way
  `heads` already is.
- **Queue is the only custodially-writable kind.** A mis-scoped custodial write fails
  one cheap enum check and cannot bleed into other chains.
- **The slot declaration carries kind + custodian + an owner-declared ceiling.**
  Custodial writes go to a **separate custodian-signed record**; the custodian never
  writes the owner's manifest, so CISS invariants B1/B3 keep their existing proofs
  unchanged.
- **Per-DID queues are the default** — "the mail is literally the recipient's the whole
  time." This *retires* the state-portability anti-entrenchment guard rather than
  satisfying it. Meer-owned **pooled queues stay a supported custody dial** (sibling to
  the confidentiality dial) for bootstrap, idle-heavy scale, and members who want the
  meer to know less about them.
- **Drain authorizes on CISS account identity, never MLS identity** — presenting group
  credentials to a blind store would leak group membership. Entitlement is enforced by
  the seal, not the drain gate.
- **Meter both transit and at-rest; billing is a separate decision from metering.** The
  transit meter is the corpus's unmeasured offline-data fraction (it sizes the meer
  fleet). **Meter retention must be bounded** — otherwise mail purges at 14 days while
  the profile about the recipient never expires.

## Reasoning

No MLS delivery service exists to copy, because everyone else's DS *is* their product
(ordering + group state + identity + policy). Croft declines ordering and group-state
validation, which leaves only a mailbox — and that is why the shim is genuinely small.
Riding CISS reuses the manifest/proof machinery instead of re-deriving it: the kind
enum, the custodian-signed side record, and the ceiling are the entire delta, and each
is placed where an existing invariant already guards it (genesis-fixed preimage; B1/B3
untouched; owner-declared limits).

Related settled context: kind semantics and the accounting chain are ADR 0005
(`docs/adr/0005-kind-semantics-and-accounting-chain.md` — the kind axis this plan
extends); compaction policy is registry row `CISS/compaction-policy`. Queue-shape
measurements: `discovery/alpha/experiments/meer-queue/PHASE-0-FINDINGS.md` (D7: the
ratchet-tree extension roughly doubles per-member Welcome cost — the offline-payload
scale input).

## Open questions (owner's, unresolved here)

1. **Who mints the custodian grant** — per-persona, or Group-collective?
2. **Meter retention policy** — the bound, and where it is enforced.

## Review Log

- 2026-08-24 — Drafted from the 2026-08-07 conversation record (previously held only in
  session memory) so the design has a committed, reviewable home. No review yet; on a
  `claude/` branch pending owner review.
