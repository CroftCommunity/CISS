# Self-assertion dials: one substrate for every customer-signed setting

**Status:** PLANNED — Pass 1 (reasoning/grounding) + Pass 2 (gap analysis)
applied 2026-08-07; open questions below awaiting confirmation; nothing is built
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
(route-target match → seq-CAS under the store lock → verify → store →
**countersign** → typed outcome), a **uniform typed `Stale` refusal** for
every kind, one storage table keyed `(did, kind, subkey)`, and per-kind
read-back visibility policy (policy keeps its Q4 owner-only-readers rule;
dials are owner-only).

**Countersignature is substrate-level, from the first assertion ever**
(user decision 2026-08-07): the server signs an acknowledgment over
`ciss/v1/assertion-ack:<kind>` with its existing dedicated attestation key
(`provider.attest_keypair` — the Model-C key, new domain) and returns it in
the write response and on read-back. The rationale is not ceremony: **the
ack is what distinguishes success from failure** — without it a customer
cannot prove, or even discern, that their assertion was accepted, which
makes the dial useless. Every stored assertion is a two-party fact from
day one.

Model A/C authorization is substrate-level: every kind gets `did:` support
for free — including, eventually, the manifest, which would un-restrict
file-sync from the `id:` plane (explicitly *not* in this plan's milestones;
noted as the option it unlocks).

**What conforms vs. what migrates:**

- **Policy records move onto the substrate with NO compatibility burden**
  (user decision 2026-08-07: pre-1.0 beta — "we can just nuke everything";
  the live box holds at most test-data ACLs). D1 restructures the wire
  shape and storage freely, ships the generic route immediately, and the
  deploy **purges stored policy records** via a destructive schema
  migration (documented in the CHANGELOG; the deployed box re-creates the
  table on startup). The *behavioral* contract of gated reads — Z4–Z8,
  oracle-free 404, Q4 visibility — is unchanged and re-guarded by the
  existing flow/e-suite tests; only the record plumbing and wire shape
  change.
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
   limit source, and the provider's limits **supersede** (user decision
   2026-08-07): a dial asserting more than the current effective provider
   bound — `min(store_ceiling, did_cap-if-set)` — is **refused at set
   time** with the real bound in the quote (no point storing an
   unreachable number), and enforcement is *always*
   `min(provider bounds, dial)` regardless (defense in depth: provider
   caps can change after a dial was accepted). The provider's number
   protects the box; the customer's protects themselves; neither can
   loosen the other. No receipts involved — the manifest already *is* the
   customer's signed at-rest assertion, so there is nothing to co-sign
   beyond the dial.
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

- **D1 — the substrate + policy re-home + typed staleness.** Phases:
  - **D1.1** `src/assertion.rs`: envelope (`did, kind, subkey, seq, body,
    authorization`), Model A/C verification (generalizing
    `policy.rs:395 verify_policy`'s shape), the ack countersignature
    (`ciss/v1/assertion-ack:<kind>` under `provider.attest_keypair`), and
    the uniform typed `Stale{kind, attempted, prior}` error. Pure module +
    unit tests; nothing wired.
  - **D1.2** storage (`persist.rs`: one `assertions (did, kind, subkey,
    seq, record, ack)` table; destructive migration drops the old policy
    table) + the generic write/read routes
    (`PUT/GET /{did}/assertion/{kind}[/{subkey}]`), seq-CAS under the
    store lock (the `op_put_manifest` server.rs:1170 pattern).
  - **D1.3** policy re-homed as the `policy` kind: `op_set_policy`/
    `op_get_policy` re-route onto the substrate; old route deleted;
    `ciss-ctl acl` updated in lockstep; gated-reads flow/e-suite green.
  - **D1.4** the manifest **conforms**: `op_put_manifest`'s stale refusal
    becomes the typed `Stale`; `ciss-cli/src/sync.rs` deletes the
    `"seq is not newer"` text-match (the M3 wart); `ManifestSlot` error
    mapping updated.
  *Done when:* every prior ACL/gated-reads/sync test passes on the new
  plumbing (`cargo test --workspace`), a stale policy write and a stale
  manifest commit both surface the same typed error, and the write
  response carries a verifiable ack.
- **D2 — the ceiling dial, at-rest half.** New `dial/ceiling` kind on the
  substrate; **refuse-at-set** above the effective provider bound
  (`Limits` at server.rs:164 — `min(store_ceiling, did_cap-if-set)`) with
  the bound in the quote; enforcement joins the existing quota gate in
  `op_put_object` as `min(provider bounds, dial)`; the attest pubkey is
  published in `/.well-known/did.json` (server.rs:396 — a did:web
  verification method) so clients verify acks offline;
  `ciss-ctl dial ceiling --at-rest-bytes N | --show`. Tests: over-bound
  dial refused-with-quote; dial below current usage refuses new puts but
  never reads (B6); provider cap binds independently even with a larger
  stored dial (cap lowered after acceptance); rollback (lower seq)
  refused; ack verifies against the well-known key.
- **D3 — the spend-period ceiling.** The server needs **period-scoped
  totals** — a Pass-2 finding: `running_totals` (persist.rs, read at
  server.rs:1200) is cumulative-forever, so the period boundary works by
  **baseline snapshot**: the signed `new_period` dial stores the meter
  total at acceptance, `period_spend = running_total − baseline` (O(1),
  no receipt rescan — the same arithmetic the client's `--reconcile`
  already uses, deliberately). Enforcement before serving billable
  transfers; refuse-with-quote (typed, carrying the triple); rent
  reservation (`budget = ceiling − projected_rent_to_period_end`, from
  the stored manifest total × `rent_cents`); **B6 carve-out in code**:
  owner-egress is *served* past the ceiling and still *billed* — the
  ceiling governs refusable operations, never data availability, and
  exempt egress may therefore carry the period past X (that is the
  furniture rule working as intended). Client: the reservation term in
  `sync price`, the 90% soft-warn.
- **D4 — receipt-mode dial + bilateral receipts.** `dial/receipt-mode`
  (opt-in `ReceiptMode::Bilateral` — receipts.rs:42; seq-CAS'd so it
  cannot be silently reverted); unstub the `501`: client co-signs the
  receipt core, server countersigns, both store; the period total becomes
  a doubly-signed fact; `sync ceiling --reconcile` upgraded to reconcile
  against countersigned totals where available. In-flight-sliver policy
  per ADR 0004 (provider absorbs, bounded ≤ ~2¢). Mechanically
  independent of D3 (a parallel candidate — see Concurrency Map); kept
  sequential by default so the receipt work lands on a settled dial
  substrate.
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

## Verified Assumptions

Confirmed by reading source this session (2026-08-07):

- `verify_policy` is a pure choke point taking `prior_seq` +
  the provider attest key — `src/policy.rs:395`; Model A requires
  `derive_id(signer) == did` (`policy.rs:427-437`); Model C verifies under
  the dedicated attestation key over `ciss/v1/policy-attest`
  (`policy.rs:44`). The two authorization forms are exactly the substrate's
  needed shapes.
- The manifest write path checks signature then seq under one store lock
  and refuses staleness with a **text** error
  (`src/server.rs:1170-1181` — `"manifest seq is not newer…"`); the M3
  client text-matches it (`crates/ciss-cli/src/sync.rs`, `commit_frontier`).
- The policy write path checks seq **before** signature with distinct
  typed statuses (`PolicyStale`/`PolicyUnauthorized`, `server.rs:1358-1383`)
  — the drift D1 heals.
- Provider limits: `Limits { store_ceiling, did_cap: Option }`
  (`server.rs:164-169`); `did_cap` unset by default (opportunistic);
  enforcement in the put path (V4/V5).
- The meter's totals are cumulative-forever (`op_get_meter`,
  `server.rs:1198-1208`, O(1) `running_totals` cache) — hence D3's
  baseline-snapshot design; there is no per-period accounting today.
- `ReceiptMode::Bilateral` exists in the wire enum and returns `501`
  (`src/receipts.rs:42-46`) — the D4 seam is real, not hypothetical.
- The attestation keypair (`state.provider.attest_keypair`) and
  `/.well-known/did.json` (`server.rs:396`) both exist — the ack key and
  its publication surface need no new infrastructure, only a new domain
  tag and a verification-method entry.
- No new external dependencies anywhere in D1–D5 — **no Phase 0 needed**:
  every assumption is about code read firsthand above.

## Documentation Impact

(grep: `policy record|verify_policy|ciss/v1/policy` over `docs/`)

- `docs/spec/gated-reads.md` — names the policy preimage domains and wire
  shape; **D1.3** updates it in the same phase that changes them.
- `docs/adr/0001-auth-and-access-control-model.md` — gains an amendment
  note ("record plumbing re-homed onto the assertion substrate, D1;
  semantics unchanged") in **D1.3**.
- `docs/ARCHITECTURE.md` — policy/record internals paragraph; **D1.3**.
- `docs/SECURITY-POSTURE.md` — the D-series invariant family + checklist
  rows (**D5**), the B6 row's enforcement point (**D3**), standing-gap #5
  closure (**D5**).
- `CHANGELOG.md` + `crates/ciss-cli/CHANGELOG.md` — the destructive policy
  migration (D1) and each milestone's surface, written at release time per
  practice.
- `docs/CLIENT.md` — `ciss-ctl dial` commands (**D2**), reconcile upgrade
  (**D4**).
- `docs/adr/0004-co-signed-spending-ceiling.md` — flipped
  Accepted-as-amended at **D5**.

## Concurrency Map

Sequential by default: D1 → D2 → D3 → D4 → D5. Every milestone's
write-set includes `src/server.rs` + `src/persist.rs` (routes, ops,
storage), so no two server milestones are parallel-safe. One candidate:
**D4 ∥ D3** — receipt-mode + bilateral receipts touch `receipts.rs` and
do not need D3's period machinery; their write-sets still overlap on
`server.rs` (routes) and the client's `sync.rs`, so parallelism would
need worktree isolation with a merge step. Recommendation: keep
sequential; the milestones are small enough that the coordination cost
exceeds the saving. Within each milestone, phases are sequential
(each builds on the previous phase's types).

## Open Questions

Resolved in review (2026-08-07), recorded here:

1. **[CONFIRMED: RESOLVED] D1 wire compat** — none needed. Pre-1.0 beta:
   restructure freely, ship the generic route in D1, **purge stored policy
   records on the live box** (destructive migration; test data at most).
2. **[CONFIRMED: RESOLVED] Countersigning** — from the first assertion
   ever, substrate-level. The ack is what distinguishes success from
   failure; without it the customer cannot discern that their assertion
   took effect, which would make the mechanism useless.
3. **[CONFIRMED: RESOLVED] Cap precedence** — provider limits supersede:
   a dial above the effective provider bound is refused at set time with
   the bound quoted, and enforcement is always `min(provider, dial)`.

New from Pass 2, awaiting confirmation:

4. **[RECOMMENDED: ADVISORY] Ack-key publication mechanism.** D2 publishes
   the attest pubkey as a did:web verification method in the existing
   `/.well-known/did.json`. Alternative: a dedicated endpoint. The
   well-known document is the idiomatic place and already served;
   recommend confirming the default.
5. **[RECOMMENDED: ADVISORY] Exempt egress is served AND billed.** The B6
   carve-out means owner-egress past the ceiling is never refused — but
   its postage still accrues, so exempt egress can carry a period past X.
   The ceiling governs *refusable* operations, never availability. This
   is the furniture rule working as intended, but it is a visible
   behavior (a statement can exceed the ceiling) worth explicit sign-off.
6. **[RECOMMENDED: ADVISORY] Purge mechanics.** The D1 destructive
   migration runs automatically at server startup (drop/recreate the
   policy table on schema-version bump), documented in the CHANGELOG —
   versus a manual on-box step in croft-stack. Automatic is recommended:
   pre-1.0, nothing to preserve, no operator choreography.

## Review Log

### Pass 1: Reasoning + grounding — 2026-08-07
- Grounded every milestone in named files/functions (see Verified
  Assumptions); confirmed no Phase 0 is needed (no unverified external
  behavior; all assumptions are firsthand source reads).
- Folded in the three user decisions from review: cap precedence
  (refuse-at-set + min() enforcement), pre-1.0 purge (no compat burden,
  generic route from D1), countersign-from-day-one (with the
  success-vs-failure rationale).
- Split D1 into four ≤3-file phases (D1.1 pure module → D1.2
  storage+routes → D1.3 policy re-home + spec docs → D1.4 manifest
  conformance + client text-match deletion).

### Pass 2: Gap Analysis — 2026-08-07
**Found:**
- The meter has no per-period accounting (cumulative `running_totals`
  only) — D3 as previously written assumed "existing accounting"
  sufficed. Fixed with the baseline-snapshot design (dial stores the
  meter total at period start; `period_spend = total − baseline`).
- Clients had no way to verify acks offline — the attest pubkey is not
  published anywhere. Added its publication (well-known doc) to D2 (OQ4).
- The B6 carve-out had an unstated consequence: exempt egress is billed
  while never refused, so a period can exceed the ceiling. Made explicit
  in D3 (OQ5).
- The purge decision needed a mechanic: automatic destructive migration
  proposed (OQ6).
- `docs/spec/gated-reads.md` + ADR 0001 + ARCHITECTURE.md reference the
  policy wire/preimage details D1 changes — scheduled in D1.3, not a
  trailing docs phase.
**Concurrency:**
- Map added: all sequential; D4∥D3 identified as the only candidate and
  rejected (write-set overlap on server.rs + client sync.rs; coordination
  cost exceeds saving).
**Changed:**
- D1 split into phases; D2 gained refuse-at-set + ack publication; D3
  gained the baseline-snapshot period design + the billed-not-refused
  egress statement; D4 marked mechanically independent of D3.
**Confirmed:**
- The substrate envelope matches both existing verify shapes (Model A/C
  generalize cleanly from `verify_policy`); the ack key and its
  publication surface already exist; `Bilateral` is a real enum variant
  behind `501`, not a hypothetical.

## Definition of done (whole plan)

Every milestone: RED-first guards (workflow-tier for the multi-actor
stories: two devices vs one dial; deferral under a spend ceiling with
egress exempt; mode-rollback refused), `cargo test --workspace` +
clippy-pedantic clean, mutants on the new verify/CAS/composition logic, no
`cargo fmt`. The live box migrates in place at each step — no stored
record ever stops verifying.
