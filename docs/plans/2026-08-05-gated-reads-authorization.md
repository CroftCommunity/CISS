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

Each phase is independently green, leaves the tree working, and is the smallest
increment that carries value. Sequencing: **1 → 2 → 3 → 4 → 5 → 6**; the pure core
(1) grounds storage (2), which grounds enforcement (3, 4), which the wire (5)
exercises, which the corpus (6) proves end-to-end. The whole increment is
**reads-only and additive** — no existing behavior changes until an owner writes a
non-`world` policy, so it can land dark and be exercised before any namespace is
gated.

### Phase 1 — The signed policy record (pure)

**Problem.** There is no representation of "who may read this," and no way to trust
one without a session. We need a self-authorizing artifact (like the manifest, Z3)
so policy provenance is a durable signature, not a session side-effect.

**Done means (RED).** Unit tests over a new `policy` module (core/`ciss-auth`-side,
pure — no I/O):
- a record signed by the key that derives the target's DID, with a `read_class ∈
  {world, grantees, owner}` and DID-validated `readers[]`, **verifies**;
- a record signed by a **different key** (forged), or one whose signer derives a
  **different DID** than the target, is **refused** (`derive_id(signer) != did`);
- a record whose `seq` is **not strictly greater** than a supplied prior `seq` is
  refused (rollback/replay);
- a `readers[]` entry that is not a well-formed `Did` is refused;
- a tampered field (readers/class/seq changed after signing) fails the signature;
- `owner`/`world` records need no `readers[]`; a `grantees` record with empty
  `readers[]` is accepted and means owner-only (equivalent to `owner`).

**Build (GREEN).** `PolicyRecord { target, read_class, readers[], seq, signer, sig }`
+ `verify_policy(record, prior_seq) -> Result<VerifiedPolicy, PolicyError>`, over a
canonical versioned preimage `ciss/v1/policy:<target>:<seq>:<read_class>:<readers…>`
— mirroring `manifest::signing_preimage` byte-discipline (`canonical.rs`). Reuse
`ciss-auth` verify primitives; `read_class` is a small enum; `target` is an opaque
string (`<did>` | `<did>/<cid>`) so range targets slot in later (spec §7).

**Validation.** `cargo test` for the `policy` module green; property test on the
preimage round-trip if cheap. No wiring yet.

**Depends on.** Nothing (pure).

### Phase 2 — Policy storage + resolution (`persist::Store`)

**Problem.** A verified policy must persist per target and resolve at read time with
the finest-grain-wins order, monotonic-`seq` supersede, and fail-closed on any
malformed state.

**Done means (RED).** Unit tests over `Store`:
- `put_policy` persists a namespace policy (`target=<did>`) and an object policy
  (`target=<did>/<cid>`); a later `seq` **supersedes**, an equal/lower `seq` is
  rejected (and the stored policy is unchanged);
- `resolve_policy(did, cid)` returns the **object** policy if present, else the
  **namespace** policy, else the `world` default;
- a stored row that fails to parse **never widens access** — resolution fails
  closed to the tighter of {stored-or-default} (an unreadable object policy does
  not fall through to a permissive namespace default);
- policies are per-`did`, isolated (one DID's policy never affects another's).

**Build (GREEN).** Two tables — `namespace_policy(did PK, seq, read_class, readers,
sig, signer)` and `object_policy((did,cid) PK, …)`. `put_policy(verified)` writes
after `verify_policy` (Phase 1) + a `seq`-monotonic guard in the same transaction;
`resolve_policy(did, cid) -> ResolvedPolicy`. Defensive `ALTER`/migration as the
existing store does. Readers stored as a canonical joined string (parsed on read).

**Validation.** `Store` unit suite green; the existing `persist`/`wiring_persist`
suites still green (additive schema).

**Depends on.** Phase 1 (`verify_policy`, `PolicyRecord`).

### Phase 3 — Authorize reads at `dispatch` (the choke point)

**Problem.** Reads are flat-allow today (`authorize` returns `Ok` for `GetObject`/
`ListBlobs`). Enforcement must live at the single `server::dispatch`→`authorize`
choke point so there is one place to reason about, and a denied read must not leak
existence.

**Done means (RED).** Unit + `wiring_*` tests on `authorize` for `GetObject`:
- `world` (default, no policy) → allow — **PDS-compat unbroken** (regression guard);
- `grantees`/`owner` → allow **iff** `principal.did == owner OR principal.did ∈
  readers`;
- a denied `GetObject` → **`404` (NotFound)**, never `403`/`401` (no existence
  oracle, no auth-required hint);
- an **anonymous** caller to a gated object → `404`;
- the **owner** always reads its own gated object.

**Build (GREEN).** `authorize` (and/or the `GetObject` handler) calls
`state.store.resolve_policy(did, cid)` and evaluates membership against the
`Principal`; deny maps to `ServerError::NotFound`. `GetObject` gains the `cid` it
already has; keep the world default a fast path (no policy row → allow) so the
common case adds one indexed lookup.

**Validation.** All existing read flows (public read, atproto getBlob) still green;
new gated-read unit/wiring green; `cargo clippy` clean.

**Depends on.** Phase 2 (`resolve_policy`).

### Phase 4 — `listBlobs` omission (no CID leak)

**Problem.** `listBlobs` currently returns every CID for a DID — a gated namespace
would leak the existence of hidden objects through the listing even if `getBlob`
404s.

**Done means (RED).** Unit + wiring for `ListBlobs` over a DID with mixed
`world`/gated objects:
- an **anonymous** caller sees only `world` objects;
- a **grantee** sees `world` objects plus the ones granted to it;
- the **owner** sees all;
- a non-grantee sees none of the gated CIDs (the response neither lists nor counts
  them).

**Build (GREEN).** After building the CID list, filter each through
`resolve_policy` + the Phase-3 membership check for the requesting `Principal`;
emit only allowed CIDs. (Namespace-level `world` short-circuits the per-object
check for the public case.)

**Validation.** `listBlobs` public behavior unchanged for ungated DIDs; omission
proven; no N+1 surprise (batch the policy lookups per DID).

**Depends on.** Phase 3 (membership evaluation), Phase 2 (`resolve_policy`).

### Phase 5 — Set/change policy over HTTP (owner-signed)

**Problem.** An owner needs to set and change policy over the wire, and the change
must take effect on subsequent reads — with the same owner-signature discipline as
the manifest.

**Done means (RED).** Wiring + the first flow steps:
- `PUT /{did}/policy` with a valid owner-signed namespace record → stored; a
  wrong-signer or lower-`seq` record → refused (4xx), access unchanged;
- `PUT /{did}/objects/{cid}/policy` with a valid object record → stored;
- after setting `grantees:[alice]`, `alice` reads and `bob`/anon `404`; after a
  higher-`seq` grant of `bob`, `bob` reads; after a higher-`seq` revoke, `bob`
  `404`s again;
- a per-object `world` override in a gated namespace makes just that object public;
- the owner can `GET` its current effective policy (read-back); a grantee's
  read-back does not disclose the full `readers[]` (spec §6 disclosure choice).

**Build (GREEN).** The two policy routes (verify → `put_policy`) + read-back `GET`;
`ServerError` mappings (bad signature/lower-seq → a distinct 4xx). Reuse the
manifest handler shape (owner-signed body, `x-croft-pubkey`/service-auth identity).

**Validation.** The lifecycle is live over real HTTP; existing manifest/quota
handlers unaffected.

**Depends on.** Phases 1–4.

### Phase 6 — Flow corpus + posture + ADR

**Problem.** The relational stories (grant/revoke lifecycle, override, omission,
adversarial policy) must be permanent regression guards, and the design intent must
be recorded as invariants and a closed ADR question.

**Done means (RED→GREEN, then docs).** `tests/flow_gated_reads.rs` over the
World/Actor + AtprotoActor harness:
- grant → read; revoke → `404`; per-object `world` override; `listBlobs` omission;
  anon → `404`; owner-always; cross-DID denial (alice's grant does not admit her to
  bob's namespace); a **forged** policy (attacker signs, names victim target) →
  refused; a **replayed lower-`seq`** policy → refused (no silent un-revoke).

**Build/docs.**
- `SECURITY-POSTURE.md`: new invariants — owner-signed policy (Z-tier), authorize-
  read-at-dispatch, `404`-on-deny (no existence oracle), `listBlobs` omission,
  monotonic-`seq` anti-rollback; **close the §14.1 gated-read design gap**.
- `ADR 0001 §2`: record the resolved grain decision (both, composed) + the
  policy-record shape; link the spec.
- `docs/spec/gated-reads.md`: flip settled sections from "planned build" to "live";
  update the change log.

**Validation.** `cargo test --workspace` + `cargo clippy --all-targets` clean; the
26 pre-existing flow tests still green; the spec/posture/ADR agree.

**Depends on.** Phases 1–5.

## Rollout / risk

- **Additive + reads-only.** No write path or existing read changes until a
  non-`world` policy exists, so the increment can merge and deploy **dark**; gating
  a namespace is then a data operation (an owner writes a policy), reversible by a
  higher-`seq` `world` policy. Low blast radius.
- **Perf.** The hot path adds one indexed policy lookup per read (short-circuited
  for the `world` default). `listBlobs` batches lookups per DID. Watch the
  `listBlobs` fan-out on large namespaces (Phase 4 validation).
- **Deploy.** Ships in a normal CISS release (schema migration is additive; the
  policy tables are created on open). No croft-stack change required.

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
