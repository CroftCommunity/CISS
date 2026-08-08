# Self-assertion dials: one substrate for every customer-signed setting

**Status:** PROPOSED — awaiting review (this document is the design + milestone
ladder; nothing is built)
**Grounds:** ADR 0004 (co-signed ceiling, Proposed — amended to build on this),
ADR 0001 (policy records), discovery E89.
**Server change:** yes — the first shared-substrate refactor since gated reads,
plus new enforcement surfaces. Phased so every step ships alone.

## Problem Statement

CISS has built the same mechanism three times, and is about to build it a
fourth:

| Instance | Where | What the customer asserts |
|---|---|---|
| **Manifest** (I5) | `src/manifest.rs`, `op_put_manifest` | *what is stored* — the billing base (+ M3 `heads`) |
| **Policy record** (Z6, ADR 0001) | `src/policy.rs`, the set-policy op | *who may read* — the access base |
| **DeviceHead** (M3, client-side) | `ciss-sync/src/device_head.rs` | *this device's tree tip* — the sync base |
| **Ceiling dial** (ADR 0004, proposed) | — | *how much I will spend / store* — the spend base |

Each one is: an owner-signed record over a **domain-separated structured
preimage** binding every field, a **monotonic `seq`** enforced
strictly-greater under one lock, **key↔DID self-authorization**
(`derive_id(key) == did` — no key registry, no operator), durable storage,
and a pure verify function as the single choke point.

The user's observation that motivates this plan: **self-assertion is the
pattern**. Nobody types customer settings into a database; the customer signs
their own requirement and the server verifies and obeys it. That deserves to
be one substrate, not four hand-rolled copies — because the copies have
already drifted:

- **Staleness is typed in one and text in another.** Policy refusal is a
  distinct `PolicyStale` status; the manifest path says
  `"manifest seq is not newer…"` in a string — which forced the M3 client to
  *text-match* the error to detect a stale frontier commit (a recorded wart).
- **Model C exists in one and not the other.** Policy records accept
  `ProviderAttested` (a `did:` owner authorizes via service-auth JWT and CISS
  counter-signs with a dedicated attestation key); the manifest is Model A
  only — which is *why* file-sync is `id:`-plane-only today.
- **Check order and refusal shapes differ** (policy: seq-then-signature with
  named reasons; manifest: signature-then-seq), storage is bespoke per kind,
  and read-back visibility rules are ad hoc per kind.

## Approach

### The substrate: `Assertion<K>`

One server module (`src/assertion.rs`) defining the envelope every
customer-signed setting shares:

```
Assertion {
  did,                  // whose assertion
  kind,                 // "policy" | "dial/ceiling" | … (domain tag ciss/v1/<kind>)
  subkey: Option<…>,    // e.g. the object cid for per-object policy
  seq,                  // strictly monotonic per (did, kind, subkey)
  body,                 // kind-specific fields, ALL bound into the preimage
  authorization,        // OwnerSigned (Model A) | ProviderAttested (Model C)
}
```

with shared machinery for: preimage construction discipline (domain tag +
canonical field folding — kinds supply a fold, the substrate guarantees
domain separation and seq/did/subkey binding), the **uniform write path**
(route-target match → seq-CAS under the store lock → verify → store → typed
outcome), a **uniform typed `Stale` refusal** for every kind, one storage
table keyed `(did, kind, subkey)`, and per-kind read-back visibility policy
(policy keeps its Q4 owner-only-readers rule; dials are owner-only).

Model A/C authorization is substrate-level: every kind gets `did:` support
for free — including, eventually, the manifest, which would un-restrict
file-sync from the `id:` plane (explicitly *not* in this plan's milestones;
noted as the option it unlocks).

**What conforms vs. what migrates:**

- **Policy records migrate onto the substrate** (behavior-preserving; the
  existing endpoint, wire records, and stored rows keep verifying — the
  substrate wraps the existing preimages as the `policy` kind's fold).
- **The manifest conforms but does not move**: it is large, hot, and its
  table is fine. It adopts the shared write discipline — most visibly the
  **typed staleness error**, which lets the client finally delete the
  text-match.
- **DeviceHead conforms conceptually** (already does: domain tag, signed,
  per-writer counter) and stays client-side; no change.

### The dials this plan actually ships

The first new kind is the **ceiling dial** (ADR 0004), split per the
mechanism-reuse insight:

1. **At-rest cap** — the customer's assertion of their own storage limit.
   Enforcement is the **existing `did_cap` gate verbatim** with a second
   limit source: `effective = min(provider_cap, customer_assertion)`. The
   provider's number protects the box; the customer's protects themselves.
   No receipts involved — the manifest already *is* the customer's signed
   at-rest assertion, so there is nothing to co-sign beyond the dial.
2. **Spend-period ceiling** — the flow quantity. Same gate shape, meter
   accounting (existing, O(1)), period boundary = a signed `new_period`
   dial (mirroring the client ledger's monotonic `period_seq`; calendar
   auto-close slots in when the statement-close scheduler SEAM lands).
   Refuse-with-quote carries the `{needed, spent, ceiling}` triple.
3. **Receipt-mode dial** — `ReceiptMode::Bilateral` stops being a stubbed
   `501` and becomes *opt-in by customer assertion*: exactly E89's
   "mode-change-only-with-customer-signature", expressed as a dial like any
   other. Bilateral receipts are then scoped to what needs them:
   non-repudiation of the spend total.

Rent-reservation, the B6 owner-egress carve-out, and the client soft-warn
attach where ADR 0004 put them (spend enforcement and client UX).

## Reasoning

- **Why extract now, not after the fourth copy:** the third consumer is the
  moment the pattern is proven and the divergence is still cheap to heal
  (two server instances, one migration). The M3 text-matching wart is the
  concrete evidence that divergence already cost something.
- **Why the customer's signature is the write path:** it removes the
  operator from the loop *structurally* — there is no "support sets your
  limit" surface to secure, audit, or abuse. Every setting is in the
  customer's handwriting, durable, and verifiable later without trusting
  the server (the same property that makes the manifest a billing base).
- **Why min() composition for caps:** provider and customer limits answer
  different questions (fairness vs. self-protection); neither may loosen
  the other, and one checkpoint serves both.
- **Why the manifest only conforms:** migrating a hot, large, heavily-read
  record for uniformity's sake is churn without a defect; adopting the
  write discipline (typed staleness) captures the actual value.
- **Why receipt-mode is a dial:** it *is* a customer-asserted setting with
  rollback stakes (a provider silently flipping a customer to unilateral
  would gut non-repudiation) — precisely the threat the seq-CAS'd signed
  record exists to kill.

## Milestones

Each milestone ships alone (plan → RED phases → gates → PR), the M1–M5
sync-ladder rhythm. Server work happens against the live box's data — every
migration is in-place and backward-verifying.

- **D1 — the substrate + policy migration + typed staleness.**
  `src/assertion.rs` (envelope, Model A/C, uniform write path, storage,
  typed `Stale`), policy records re-homed onto it behavior-preserving
  (existing stored rows and wire records keep verifying; the flow/e-suite
  ACL tests are the regression wall), and the manifest path adopting the
  typed staleness error — client deletes the M3 text-match in the same PR.
  *Server change, no new capability; ends with byte-for-byte-equivalent
  behavior except the typed error.*
- **D2 — the ceiling dial, at-rest half.** New `dial/ceiling` kind
  (customer-signed, countersigned on read-back); `min()` composition into
  the existing `did_cap` gate; `ciss-ctl dial ceiling --at-rest-bytes N`
  (+ show). Tests: assertion below current usage refuses new puts but never
  reads (B6); provider cap still binds independently; rollback refused.
- **D3 — the spend-period ceiling.** Enforcement before serving billable
  transfers (server twin of the client's `metered()` split);
  refuse-with-quote (typed, carrying the triple); signed `new_period`
  dial; rent reservation in the arithmetic (`budget = ceiling −
  projected_rent_to_period_end`); **B6 carve-out in code** (owner-egress
  never checks the ceiling) + POSTURE checklist row. Client: the same
  reservation term in `sync price`, the 90% soft-warn.
- **D4 — receipt-mode dial + bilateral receipts.** `dial/receipt-mode`
  (opt-in Bilateral, seq-CAS'd so it cannot be silently reverted); unstub
  the `501`: client co-signs the receipt core, server countersigns, both
  store; the period total becomes a doubly-signed fact; `sync ceiling
  --reconcile` upgraded to reconcile against countersigned totals where
  available. In-flight-sliver policy per ADR 0004 (provider absorbs,
  bounded ≤ ~2¢).
- **D5 — POSTURE + close-out.** New invariant family (the D-series:
  every assertion domain-separated and fully bound · strictly-monotonic
  per (did, kind, subkey) · Model A/C authorization only · typed staleness
  · per-kind read-back visibility), checklist rows, `SYNC-MODEL.md`/CLIENT
  doc touches, ADR 0004 flipped Accepted-as-amended, E89 stamps in
  discovery.

**Out of scope, unlocked but deferred:** manifest-on-substrate (would give
`did:`-plane file-sync via Model C — its own decision); tariff-parity
attestation and throttle-count governance (E89 bylaw lanes); calendar
period auto-close (statement-scheduler SEAM); groups as policy reader sets.

## Open questions (for review)

1. **D1 wire compat**: the set-policy endpoint keeps its current wire shape
   (substrate hidden behind it), or moves to a generic
   `PUT /{did}/assertion/{kind}` with the old route as an alias? Default if
   unstated: keep the current route in D1, introduce the generic route in
   D2 for dials only.
2. **Countersigning scope in D2/D3**: countersign every dial on write (the
   ADR's shape), or defer countersignatures to D4 where bilateral receipts
   land anyway? Default: countersign from D2 — it is cheap and makes every
   dial a two-party fact from day one.

## Definition of done (whole plan)

Every milestone: RED-first guards (workflow-tier for the multi-actor
stories: two devices vs one dial; deferral under a spend ceiling with
egress exempt; mode-rollback refused), `cargo test --workspace` +
clippy-pedantic clean, mutants on the new verify/CAS/composition logic, no
`cargo fmt`. The live box migrates in place at each step — no stored
record ever stops verifying.
