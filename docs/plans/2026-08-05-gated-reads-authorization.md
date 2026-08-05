# Plan — gated reads (the authorization layer)

- **Date:** 2026-08-05
- **Status:** Proposed (TDD-first)
- **Owns:** ADR 0001 §2 (namespace mode bits) + its deferred **grain** reopening;
  closes the standing design gap in `docs/SECURITY-POSTURE.md` §14.1 (gated-read
  namespaces).
- **Decisions (2026-08-05):** design **both grains together** — namespace mode
  bits with per-object reader overrides — set by an **owner-signed policy record**.

---

## Problem statement

Authentication is complete: a caller is proven to be a DID (`id:` session or
`did:` service-auth JWT). But **authorization for reads is still flat**: every
object/blob read and `listBlobs` is world-readable (invariant Z1). That is exact
PDS-compatibility and correct for public repos — but CISS has two use cases that
need *private* reads and have no enforcement today (posture §14.1):

- **history-convergence backend** — a "range-based crypto-chain query server"
  whose ranges/repos must be readable only by grantees;
- **private-PDS per-object sharing** — an object shared with a specific list of
  reader DIDs ("share this blob with alice + bob").

These pull toward two grains (a *namespace/range* and a *single object*), so the
model must serve both. ADR 0001 §2 chose namespace-grain and explicitly deferred
per-object ACLs ("the complexity and leakage surface"); this plan reopens that as
decided — **both**, composed — and builds it.

The load-bearing risk is **leakage**: a gate that leaks what it hides is no gate.
A denied read must not become an existence oracle, and `listBlobs` must not
enumerate objects the caller may not read.

## Approach

Authorization is a **lookup against an owner-signed policy**, evaluated at the
single `dispatch` choke point after authentication. Two composing grains:

```
  read(did, object)  ─▶  resolve policy:
      1. per-object ACL for `object`?      → use it            (finest grain wins)
      2. else namespace mode bits for `did`→ use read_class
      3. else default                      → world  (PDS-compat, unchanged)
  ─▶  authorize(principal, policy):
        world            → allow
        grantees/owner   → allow iff principal.did ∈ {owner} ∪ readers
      deny → 404 (no existence oracle);  listBlobs omits denied objects
```

**Policy is an owner-signed record** (self-authorizing, exactly like the manifest,
invariant Z3): the owner signs `{namespace|object, read_class, readers[], seq}`
with the key that derives its DID (`derive_id(key) == did`), so CISS trusts the
policy without a session — and a stale/forged policy fails the signature check.
`seq` is monotonic (replay/rollback defense, like the manifest `seq`).

- **Namespace mode bits** `{read_class ∈ {world, grantees, owner}, write_class}`
  set the default for a DID's whole namespace/range.
- **Per-object override** — an object may carry its own `{read_class, readers[]}`
  that wins over the namespace default (finest grain wins). Absent → inherit the
  namespace.
- **Write** stays owner-only (invariant Z2, unchanged) — this increment is about
  *reads*. `write_class` is stored for completeness but v1 enforces owner-only
  writes as today; delegated writes are a tracked follow-on.

**Denial semantics (the leakage rules), from ADR 0001 §2:**

- a gated read to an unauthorized/anonymous caller → **404**, never 403 (no
  existence oracle);
- `listBlobs` **omits** objects the caller may not read (never leaks a hidden CID);
- gated namespaces are **off the public-replication surface** (not on
  `subscribeRepos`/relay) — a SEAM to enforce when that surface exists.

## Reasoning

- **Why both grains, composed.** The two use cases genuinely differ in grain;
  forcing one would either bloat namespace policy with per-object exceptions or
  bloat every object with a full ACL. Namespace default + per-object override is
  the standard, minimal composition (like Unix dir mode + per-file ACL).
- **Why an owner-signed policy record, not a session-set flag.** CISS already
  trusts owner-signed artifacts (the manifest, Z3) and nothing else for durable
  authority. A signed record means policy provenance is a durable, verifiable
  artifact — not "whoever held a session at write time" — and it is checkable
  offline, survives backup/restore, and carries its own anti-rollback `seq`.
- **Why 404 + omit.** A gate that returns 403 or lists hidden CIDs leaks the very
  thing it protects. 404-on-deny and list-omission are the atproto-shaped,
  oracle-free denial (ADR 0001 §2).
- **Why reads only in v1.** Writes are already owner-only and safe; read-gating is
  the missing capability. Delegated writes (write_class: grantees) add a consent
  model and are deferred to keep this increment focused.

## Phases (TDD-first — every phase RED before GREEN)

### Phase 1 — The signed policy record (pure, `ciss-auth`/core)

- **RED:** a policy record verifies iff signed by the owner key that derives the
  namespace/object's DID (`derive_id == did`) with a monotonic `seq`; a forged
  signer, a wrong-DID signer, or a replayed lower `seq` is refused. `read_class`
  parses to `{world, grantees, owner}`; `readers[]` are validated `Did`s.
- **GREEN:** `PolicyRecord` + `verify_policy` (a signed preimage
  `ciss/v1/policy:did:seq:read_class:readers…`, mirroring the manifest preimage).

### Phase 2 — Policy storage + resolution (`persist`/`Store`)

- **RED:** store a namespace policy and an object policy; `resolve_policy(did,
  object)` returns the per-object policy if present, else the namespace policy,
  else `world`; a newer `seq` supersedes; malformed rows never widen access
  (fail-closed to the tighter of stored/default).
- **GREEN:** policy tables keyed by `did` (namespace) and `(did, cid)` (object);
  `put_policy` (owner-signed, verified) / `resolve_policy`.

### Phase 3 — Authorize reads at `dispatch` (the choke point)

- **RED (unit + wiring):** `authorize` for `GetObject`/`ListBlobs` consults
  `resolve_policy`:
  - `world` → allow (PDS-compat unchanged);
  - `grantees`/`owner` → allow iff `principal.did ∈ {owner} ∪ readers`;
  - denied `GetObject` → **404** (not 403, not 401-with-hint);
  - anonymous caller to a gated object → 404.
- **GREEN:** extend `authorize` with the policy lookup; map deny → `NotFound`.

### Phase 4 — `listBlobs` omission (no CID leak)

- **RED:** `listBlobs` for a DID with mixed public/gated objects returns only the
  objects the caller may read; an anonymous caller sees only `world` objects; the
  owner sees all; a grantee sees world + granted.
- **GREEN:** filter the `listBlobs` result through `resolve_policy` + `authorize`
  per object.

### Phase 5 — Set/change policy over HTTP (owner-signed)

- **RED (flow):** an owner sets a namespace to `grantees:[alice]`; alice reads,
  bob 404s, anon 404s; the owner grants bob (new `seq`), bob now reads; the owner
  revokes (new `seq`), bob 404s again; a per-object `world` override on one blob in
  a gated namespace makes just that blob public.
- **GREEN:** a `PUT …/policy` (namespace) and per-object policy endpoint that
  verify the owner signature and persist; `listBlobs`/`getBlob` honor it live.

### Phase 6 — Flow corpus + posture

- **`tests/flow_gated_reads.rs`** (World/Actor + AtprotoActor): grant→read,
  revoke→404, per-object override, `listBlobs` omission, anon→404, owner-always,
  cross-DID denial, forged/replayed policy refused.
- **`SECURITY-POSTURE.md`:** new invariants — signed policy (Z-tier), 404-on-deny
  (no existence oracle), listBlobs omission; close the §14.1 gated-read gap.
- **ADR 0001 §2:** record the grain decision (both, composed) + the policy-record
  shape.

## Design questions — resolved (2026-08-05)

All settled; the integrator contract is `docs/spec/gated-reads.md`.

- **Read model (Q1):** three explicit classes `{world, grantees, owner}` +
  `readers[]` of **explicit DIDs** (no groups/handles/nesting in v1). Owner always
  allowed; authorization is a pure set-membership check.
- **Policy transport (Q2):** a **dedicated owner-signed policy record**, separate
  from the manifest (keeps the billing signature and the authz signature distinct;
  makes per-object policy first-class). Submitted on its own endpoint.
- **Range grain (Q3):** **deferred.** v1 covers namespace + object; range-scoped
  policy is a tracked extension for when the history-convergence query surface is
  concrete. The `target` is an opaque extensible string so a `<did>/range/<lo>-<hi>`
  target slots in later without reshaping the record.
- **Group model:** deferred; the static-DID-list (v1) vs dynamic-group-pointer
  tension is recorded in the spec §8.1 so a later design starts from the tradeoff.

## Non-goals (tracked, not this increment)

- Delegated **writes** (`write_class: grantees` enforcement) — a consent model.
- Group/handle-based grants (vs explicit DID lists).
- Gated namespaces on the public-replication surface (there is no
  `subscribeRepos`/relay surface yet — SEAM).
- `did:plc` signed-oplog verification (separate atproto follow-on).
