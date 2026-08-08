# ADR 0004 — The co-signed spending ceiling (bilateral receipts + the customer's dial)

- **Status:** Proposed (amended 2026-08-07 — mechanism unification)
- **Date:** 2026-08-07
- **Amendment:** review discussion identified that the dial is the **third
  instance of an existing pattern** — the owner-signed monotonic record
  (manifest/I5, policy record/Z6; DeviceHead is a client-side fourth) — and
  that enforcement/accounting reuse the existing `did_cap` gate and meter
  caches. The build is therefore re-planned as a shared **self-assertion
  substrate** plus dials on top, with bilateral receipts scoped to the one
  thing that needs them (spend non-repudiation; the at-rest cap needs none —
  the manifest already is the customer's signed at-rest assertion). The
  milestone ladder superseding this ADR's "Build shape" lives in
  `docs/plans/2026-08-07-self-assertion-dials.md` (D1–D5). The decisions in
  this ADR (dial semantics, refuse-with-quote, rent reservation, B6
  carve-out, sliver policy, soft-warn) stand unchanged.
- **Context:** the M5 cost twin gave the customer a **unilateral** ceiling —
  the client refuses to send past X (`docs/plans/2026-08-07-file-sync-m5-cost-twin.md`,
  hardened by the metered-transport and meter-reconciliation follow-ons). That
  protects against surprise only as far as the client's own discipline: a
  buggy client, a second tool, or another device can spend past it, and the
  server neither knows the ceiling exists nor could honor it. Discovery
  **E89** names the complete instrument: a *co-signed* "spend stops at X",
  enforced server-side against *bilateral* receipts — the seam the receipt
  protocol already carries (`ReceiptMode::Bilateral` → `501` today, E82).
  This ADR fixes the design so the build can be phased; it changes server
  trust machinery, which is why it gets a decision record rather than riding
  a sync milestone.

---

## Problem statement

Three instruments coexist and must not be conflated:

| Instrument | Whose number | Bounds | Enforced by | Exists |
|---|---|---|---|---|
| `store_ceiling` / `did_cap` | provider's | bytes **at rest** (resource/fairness) | server, unilaterally | yes (V5) |
| M5 client ceiling | customer's | billed **spend** (postage) | client, unilaterally | yes |
| **Co-signed ceiling (this ADR)** | customer's, countersigned | billed **spend** | **both, bindingly** | no |

The gap the co-signed ceiling closes: today the customer's spend limit is
advisory to everyone but their own client. The E89 dial-pattern rules it must
satisfy, each a ledger fact rather than provider policy: *throttle/defer past
X, never mint debt* · *mode/ceiling changes only with the customer's
signature* · *exit unconditionally exempt* (POSTURE **B6**) · *tariff parity*
and *throttle-count-to-governance* (co-op bylaw territory, out of scope here).

## Decision (proposed)

### 1. The dial record: customer-signed, I5-governed, countersigned

A **CeilingDial** is a customer-signed record
`{did, ceiling_cents, period_policy, dial_seq}` submitted to a new owner-only
endpoint. The server verifies the owner signature, requires `dial_seq`
strictly greater than the stored dial's (the I5 pattern — a replayed or
stale dial is refused, so the provider cannot roll a customer back to a
higher ceiling), **countersigns**, stores, and returns the countersigned
record. Clearing the ceiling is itself a signed dial (`ceiling_cents: null`)
— absence of enforcement is also only ever customer-authorized. This is the
E89 "mode-change-only-with-customer-signature" rule made structural.

`period_policy` in v1 is the simplest thing that is not a clock promise: a
customer-initiated period boundary (a signed `new_period` dial), mirroring
the client ledger's monotonic `period_seq`. Calendar auto-close arrives with
the statement-close scheduler SEAM and slots in as a policy value.

### 2. Enforcement: comparison-before-serving

On every **billable** transfer (metered path only — the client's
`metered()` distinction has a server twin for free): the server computes
`postage_cents(period_bytes + this_transfer) > ceiling_cents` **before**
serving. Over means refuse-with-quote: a structured `402`-shaped error
carrying `{needed_cents, spent_cents, ceiling_cents}` — the same triple the
client twin computes, from the same integer arithmetic over the same
receipts, so the two sides cannot disagree about where the line is. The
client's pre-flight (`sync price` + local check) remains the first line;
the server check is the binding backstop.

**Exactness, not tolerance.** There is no ±: rent is priced from the
customer's own signed manifest (logical bytes — block sizes and fs overhead
are the provider's cost, never billed), postage from synchronous
integer-cent receipts. Both parties compute identical totals. The only
boundary case is a transfer already streaming when it would cross the line;
"never mint debt" fixes the policy: the provider either aborts it or
absorbs the sliver, which is bounded by one object — ≤ 2 MiB ≈ **2¢**. The
provider absorbs (simplest, cheapest, and the failure mode favors the
customer).

### 3. Rent: reserved, not gated

Rent accrues continuously on bytes at rest and **cannot be refused** without
deleting data — which must never be automatic (B6's spirit applied at rest:
a ceiling stops new spending; it never makes stored data the collateral).
The rule that keeps "never mint debt" intact:

```
transfer_budget = ceiling − projected_rent_to_period_end(keep-set)
```

Rent is exactly predictable from the signed manifest (`total_bytes ×
tariff × days-remaining`), so reserving it is exact, not a guess. Transfers
check against the remainder; the deferral quote itemizes the reservation
("ceiling 500¢: 180¢ reserved for rent, 240¢ postage spent, this sync needs
130¢ — deferred"). If the keep-set grows, the reservation grows at the next
commit — the customer sees it in `sync price` before agreeing to it.

### 4. Bilateral receipts (the E82 seam, unstubbed)

With a ceiling in force, transfer receipts upgrade to **bilateral**: the
client signs the receipt core the server proposes, the server countersigns,
both store. The period total is then a sum of doubly-signed facts — neither
side can dispute where the spend stood, which is what makes the ceiling's
`402` unarguable rather than a provider claim. Unilateral receipts remain
the mode for ceiling-less accounts (no forced migration).

### 5. Exit stays exempt — B6, now with a server-side enforcement point

Self-directed egress of the customer's own manifest + blobs is **never**
gated by the ceiling, the balance, or the dial mode. B6 today is a design
rule with no billing-conditioned read path to violate it; this ADR creates
the first such path, so the exemption becomes code: the ceiling check
applies to writes and third-party-billable reads, never to owner-egress.
The B6 checklist row gains this enforcement point when the build lands.

### 6. Soft warning (client UX, not protocol)

At a configurable fraction of the ceiling (default 90%), the client warns on
`sync price`/`backup` so users do not slam into the hard wall mid-tree. Pure
client policy; no server involvement; no accuracy semantics.

## Alternatives considered

- **Repurpose `did_cap` as the customer ceiling** — rejected: it is the
  provider's number about bytes-at-rest (resource fairness), a different
  question with a legitimately different value; conflating them makes one
  party's instrument disappear.
- **Client-only enforcement forever** — rejected by E89's own analysis: a
  unilateral cap is self-discipline, not a guarantee; the scandal history
  the checklist encodes is precisely about limits the counterparty could
  ignore or alter.
- **Server-trusted (not co-signed) ceiling** — rejected: a server-stored,
  unsigned setting could be altered or denied by either side; the whole
  value is that the dial and the running total are bilateral facts.
- **Tolerance band ("hold at 95%")** — rejected as an accuracy mechanism:
  there is no measurement error to absorb (logical bytes, integer cents).
  Survives only as the soft-warn UX threshold (§6).

## Consequences

- **Server**: a dial store + endpoint (owner-signed, seq-CAS'd,
  countersigned), the pre-serve ceiling comparison on billable transfers, a
  structured refuse-with-quote error, bilateral receipt
  countersign/verify/store, and the B6 owner-egress carve-out in the check.
  First server auth-adjacent surface since gated reads — POSTURE gains a
  billing invariant ("a stored dial reflects the newest customer-signed
  ceiling; no billable transfer serves past it; owner-egress never checks
  it") and the checklist a row.
- **Client**: `ciss-ctl ceiling --co-sign` (submit/rotate the dial), receipt
  co-signing in the transfer path, the rent-reservation term in `sync
  price`'s arithmetic and the local check (shared with the server by
  construction — both derive from the manifest and the tariff), the 90%
  soft-warn.
- **Deferred with it**: tariff parity attestation and throttle-count
  reporting (governance/bylaw, E89 lanes (c)); calendar period auto-close
  (statement-close scheduler SEAM).

## Build shape (when accepted)

Phased like the sync ladder, RED-first: P1 dial record + endpoint + refusal
arithmetic (no bilateral receipts yet — server-signed refusal quotes are
already binding on the server side); P2 bilateral receipts (unstub `501`);
P3 rent reservation + client wiring + soft-warn. Each phase lands with
workflow-tier guards (defer-whole, exit-exempt under an enforced ceiling,
dial rollback refused, receipt co-sign round-trip).
