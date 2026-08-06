# ADR 0003 — Usage inspection (`du`): self by default, admin store-wide behind a flag

- **Status:** Accepted
- **Date:** 2026-08-06
- **Context:** the `ciss-ctl` client wanted a `du` — "how big are the objects I
  stored?" — and, optionally, an operator view of usage across DIDs. Sizes are
  already maintained in the ledger (`receipt.bytes`, `did_total.stored_bytes`), so
  the cost is not the question; the **authorization** is.

---

## Problem statement

Two distinct capabilities hide under "du":

1. **Self usage** — a caller sees the per-object sizes (and total) of **its own**
   namespace. This is just the caller's own data; the existing owner authorization
   already covers it. No new trust decision.
2. **Store-wide / cross-DID usage** — an operator sees usage for **another** DID
   (or the whole store). This reveals the **sizes** (not the content) of objects
   the operator does not own — including **gated** objects. That is a new
   authorization role and a deliberate exception to the gated-read visibility
   invariants (Z-series, `docs/SECURITY-POSTURE.md` §5), so it must be a design
   decision, not an incidental feature.

The admin **pin set** (`CISS_ADMIN_PINS_FILE`, ADR 0001 §5) exists today only for
**break-glass DID resolution** — it is not an authorization role. Reusing it to
authorize usage inspection overloads it, but is pragmatic (the set already names
the operators) and is what the operator chose.

## Decision

### 1. `GET /{did}/du` — per-object sizes + total

A new read endpoint returns `{"objects":[{"cid":"<hex>","bytes":N},…],
"total_bytes":T}` for `{did}`. Sizes come from the maintained receipt ledger (the
same receipts `listBlobs` already scans); **no filesystem walk**.

### 2. Self usage is always allowed; cross-DID is off by default

Authorization for `du` on `{did}`:

- **caller == `{did}`** → allowed (self usage; the caller owns the namespace).
- **caller ∈ admin pin set AND `CISS_ADMIN_USAGE` is enabled** → allowed for any
  `{did}` (mode-2, store-wide/audit).
- **otherwise** → `403 Forbidden`, with a response that does **not** vary by
  whether `{did}` exists (no existence oracle).

`CISS_ADMIN_USAGE` is a server-side flag, **off by default**. With it off, `du` is
purely self-scoped and introduces **no** change to the authorization or
gated-read invariants — the endpoint behaves like any other owner-only read.

### 3. Mode-2 is a documented admin/break-glass exception

When the flag is on, an admin sees the **sizes** of a target DID's objects,
including gated ones. This is a deliberate, narrow exception:

- **Sizes, never content.** `du` returns byte counts and cids, never object bytes.
- **Admins only, flag-gated.** Two independent conditions (admin membership *and*
  the operator having enabled the flag) must both hold.
- **Break-glass-aligned.** The admins already hold break-glass powers (local key
  pinning, ADR 0001 §5); adding "inspect store usage" to that operator role is
  consistent with their purpose.

## Consequences

- **Posture update.** `docs/SECURITY-POSTURE.md` §5 gains an invariant: `du` is
  self-only unless `CISS_ADMIN_USAGE` is set, in which case an admin-pin DID may
  read cross-DID **sizes** (not content). The default deployment (flag unset)
  keeps the gated-read visibility invariants intact.
- **Admin set becomes (optionally) an authz role.** The pin set is still primarily
  a resolution concept; the flag is what activates its authorization use, so a
  deployment that never sets the flag is unaffected.
- **Rejected alternatives.** (a) A separate admin-authz list distinct from the
  break-glass pins — cleaner separation, but more config for a capability the same
  operators need; deferred, can be added later without a wire change. (b) Making
  cross-DID usage always-on for admins — rejected; an operator must opt in, so the
  gated-size exception is never silently active. (c) Extending the atproto
  `listBlobs` lexicon with sizes — rejected; keep the standard method standard and
  put the CISS-specific view on a CISS endpoint.
