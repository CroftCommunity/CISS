# Request-path burden management — design record (E102)

- **Date:** 2026-08-19 (owner-walked design discussion; supersedes the
  earlier token-bucket-first sketch)
- **Status:** design settled in shape; **stage 1 is buildable**; stages 2–3
  get plans of their own when their stage-1 data exists. The Caddy question
  (§6) is an explicitly **open decision**, recorded not taken.
- **Backlog:** ROADMAP_TODO **E102** (this doc is its design record); seam
  **E83** (per-DID compute observability) is stage 1 of this design.

## 1. Problem

The byte-path is metered; the request path is not. CISS's only request-path
protections are a global in-flight cap and a request timeout (V1/V4/V5) plus
storage ceilings. A hostile-but-authenticated client can burn compute
(signature verification, DID resolution, canonicalization, sqlite work) at
line rate inside the global cap without moving a metered byte — and one noisy
DID can starve the cooperative's other members within the shared budget.

**The NFS lesson (owner, from operating NFS at ~400 clients):** some queries
are cheap on disk and brutal on CPU; scalar load metrics don't attribute
that; and the mechanism that actually tamed uncooperative clients was
**traffic shaping, not refusal** — delay propagates backpressure through the
transport and clients self-throttle without being asked. Refusal (429)
depends on client cooperation; shaping does not.

## 2. Why one number cannot work

Wall-time per request conflates four different burdens:

| Burden | Looks like | Truth |
|---|---|---|
| CPU burn (sig verify, resolution, canonicalization, sqlite CPU) | *cheap* — each request fails/returns fast | the NFS "hard on CPU" query; the thing V-series findings don't cover |
| Disk wait (blob I/O) | expensive | mostly harmless to neighbors |
| **Lock wait** — the single-writer store mutex | invisible in per-request CPU | the actual scarce resource for every metadata op; one DID's heavy sqlite work starves everyone *at the lock* |
| Network drain (slow reader on a big blob) | very expensive | near-zero cost |

A slow reader looks expensive and isn't; a garbage-JWT hammer looks cheap
and is pure CPU. So measurement is **multi-dimensional per DID per operation
class**: request count · CPU proxy · store-mutex hold time · blob I/O ·
bytes in/out (the last already signed and metered — the byte meter).

**CPU attribution under tokio (the honest wrinkle):** requests hop worker
threads, so per-thread CPU clocks don't attribute. Two proxies, used
together: task **poll time** (time actually executing, never blocked — a
sound CPU approximation), and **component timers** around the known-expensive
synchronous sections (verify, resolve, canonicalize, sqlite). Instrument the
components, not just the request — the cpu-ish/io-ish cost vector per op
class then comes from data, not guesses.

## 3. Mechanisms, in the order we'd reach for them

**Shaping first, refusal as backstop** — "slow is the new refused."

1. **Per-DID concurrency caps.** At most K in flight per DID; the K+1th
   *waits briefly* (bounded, per-DID, tiny) rather than being refused.
   Backpressure propagates through the client's own stalled connections; no
   retry storm; memory bounded. The cheap 80% of shaping — and the same
   survival mechanism a finite nfsd thread pool provides.
2. **Egress byte shaping.** Throttle download streams per DID. True
   tc-style shaping of the one resource already metered and billed, so the
   drain rate can tie to the billing tier. B6 fully satisfied: data is never
   unreachable, it drains at the rate your standing entitles you to.
3. **Weighted fair queueing across DIDs** at the dispatch boundary — each
   DID a virtual queue, drained by weight. Held in reserve until stage-1
   data proves the first two insufficient. **Deliberately *unfair* by
   design:** weights are a policy surface, so system lanes (backup,
   maintenance, service accounts) can be prioritized. The hook already
   exists — the `AccountMode` seam anticipates `Service`/`Bot`/`Staff`
   accounting classes, and its authorization rule transfers verbatim: a
   self-asserted class may only restrict the asserter; **any favorable
   weight must be provider-attested (Model C)** — nobody signs themselves
   into the priority lane, and the grant is itself a seq'd, acked record.
4. **Token-bucket 429 + `Retry-After`** — the backstop for outright abusive
   request rates, keyed by **claimed** identity before expensive
   verification (a forger can drain a victim's bucket; the alternative
   donates our CPU to the forger, which is worse). Never queue on refusal.

Exempt: `/healthz` (already outside the data plane), the well-known
discovery documents (rate-limiting discovery breaks polite strangers).

## 4. Declared, not hidden

House limits, weights, and shaping rates are published in the E103
self-description document. An owner dial *below* the house limit follows the
ceiling-dial pattern (`min(house, dial)`). Compute may later graduate from
telemetry to a metered line (visible in `/{did}/meter`, eventually priced) —
a product decision stages 1–2 do not foreclose.

## 5. Staging

- **Stage 1 — observe (E83, buildable now).** Multi-dimensional counters at
  the single dispatch boundary: per DID per op class — count, poll-time,
  component timers, mutex hold, bytes. In memory, bounded map with
  least-recently-seen eviction (derived/rebuildable data — not ledger
  material; the per-DID key space is bounded by real authenticated
  identities, anonymous traffic is one shared row). Monotonic clock only.
  Surfaced on-box via `ciss usage` (cross-DID views stay off the wire);
  later a self-only meter line. **Then run it live and let the data pick
  the units and weights.**
- **Stage 2 — shape.** Per-DID concurrency caps, then egress shaping tied
  to the meter; house numbers from stage-1 data, published via E103.
- **Backstop.** 429 bucket for abusive request rates.
- **Reserve.** WFQ/priority lanes when data demands them, weights riding
  the accounting-class seam.

TDD anchors: stage 1 begins RED with "after N requests by a DID the usage
report shows N with durations"; stage 2 begins RED with a workflow story —
a hot-loop actor is shaped **while a quiet second actor's requests proceed
unaffected** (the quiet actor *is* the feature).

## 6. The Caddy question (open decision, recorded not taken)

What CISS cannot do from behind Caddy: see client IPs (pre-auth flood
defense), or shape at the connection/packet level (real tc). Getting out —
CISS terminating its own TLS — is **not out of bounds** (owner, 2026-08-19):
the project already runs services that read certs from tmpfs, the domain is
owned, and rustls-in-process is unexciting at this scale. But it is a big
decision with real reshaping costs (ADR 0002's healthz edge-gating and the
croft-stack deploy contract both assume Caddy), so it is parked as an open
decision to be taken deliberately — likely only if pre-auth floods become
real. Until then: per-IP and connection-level defense stay at the edge
(Caddy/kernel, croft-stack), per the ADR 0002 precedent.

## 7. Scale honesty

This is a large implementation across several releases (owner-acknowledged).
Stage 1 is small and pays for itself immediately (observability). Everything
after it is gated on evidence stage 1 produces, so the large stages are
built only if the data says they're needed.
