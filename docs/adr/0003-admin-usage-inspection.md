# ADR 0003 — Usage inspection (`du`): self-only over the wire, optionally admin-locked

- **Status:** Accepted
- **Date:** 2026-08-06
- **Context:** the `ciss-ctl` client wanted a `du` — "how big are the objects I
  stored?" — and, separately, an operator view of usage across DIDs. Sizes are
  already maintained in the ledger (`receipt.bytes`, `did_total.stored_bytes`), so
  the cost is not the question; the **authorization surface** is.

---

## Problem statement

Two capabilities hid under "du":

1. **Self usage** — a caller sees the per-object sizes (and total) of **its own**
   namespace.
2. **Cross-DID / store-wide usage** — someone sees usage for **another** DID (or
   the whole store). This exposes the sizes of objects the viewer does not own,
   including **gated** ones.

The design question is what to put **on the wire**. Exposing (2) over HTTP — even
to admins — means a network-reachable endpoint that reads *other users'* storage:
a standing privacy surface and a target. The alternative is to keep cross-DID
inspection **on the box**, where an operator already has `ciss usage` (a
read-only, per-DID/store-wide report) under normal host access controls.

## Decision

### 1. Remote `du` is **self-only**

`GET /{did}/du` returns `{"objects":[{"cid":"<hex>","bytes":N},…],
"total_bytes":T}` — but **only** when the authenticated caller **owns** `{did}`. A
cross-DID query is refused `403`, **for everyone, including admins**. No one reads
another user's storage over the wire. Sizes come from the maintained receipt
ledger (no filesystem walk). The `403` does not vary by whether `{did}` exists (no
existence oracle).

### 2. Cross-DID / store-wide inspection stays on the box

An operator uses the existing on-box **`ciss usage --data-dir <dir> [--did <did>]`**
report for cross-DID and whole-store usage. It is not exposed over HTTP; access is
governed by who can run a command on the host.

### 3. `CISS_ADMIN_ONLY_DU` — an optional lockdown of remote `du` to admins

`du` may be something an operator does not want self-serve (a nonzero read an
attacker could hammer, or simply a capability to gate). The flag lets an operator
**restrict who may run `du` at all**:

- **unset (default):** any authenticated caller may `du` **its own** namespace.
- **set (`1`/`true`):** only a DID in the break-glass admin-pin set (ADR 0001 §5)
  may run `du` — **still only for its own namespace** (cross-DID stays `403`).

The flag never *expands* access — it only narrows it. It reuses the admin-pin set
as the "who may run `du`" list; a deployment that never sets it is unaffected.

## Consequences

- **Posture (invariant Z9).** Remote `du` is a self-only read; cross-DID is never
  served over the wire. The gated-read visibility invariants (Z5) are **not**
  weakened — there is no admin-sees-others'-sizes exception.
  `CISS_ADMIN_ONLY_DU` can only *restrict* `du` further (to admins), never broaden
  it.
- **No new authz role over the wire.** The admin-pin set gains at most a
  *restrict-to* use (the lockdown); it never authorizes reading another DID's data
  remotely. Cross-DID inspection is an on-box operator action.
- **Rejected alternatives.** (a) An admin-gated *cross-DID* HTTP endpoint (an
  earlier draft of this ADR) — rejected: it puts other users' storage on the
  network even if admin-only; `ciss usage` on the box is the right place. (b)
  Extending the atproto `listBlobs` lexicon with sizes — rejected; keep the
  standard method standard and put the CISS-specific view on a CISS endpoint. (c) A
  separate admin-authz list distinct from the break-glass pins — unnecessary once
  cross-DID is off the wire; the flag only needs a "who may self-`du`" set.
