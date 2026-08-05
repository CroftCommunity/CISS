# CISS gated reads — integrator specification (v1, built)

**Status: LIVE — v1 built (8-phase TDD increment, 2026-08-05).** All three design
questions are resolved (Q1 read model, Q2 dedicated policy record, Q3 range grain
deferred) and the model is shipped. Sections marked **[LIVE]**/**[SETTLED]** are
built and covered by tests; **[PLANNED]** marks a tracked future extension (out of
v1 — do not rely on). This document is the **contract for integrators**; the
build/TDD plan is `docs/plans/2026-08-05-gated-reads-authorization.md`, the
enforcement invariants are in `docs/SECURITY-POSTURE.md`, and the decision is
ADR 0001 §2.

---

## 1. What this is, and why it is not a standard PDS feature

A standard atproto PDS has **no per-repo or per-object read ACL** — repo data is
either public (on the replication surface) or gated only by *account*-level
controls. CISS adds **gated reads**: an owner can make a namespace (a repo /
data-structure) or an individual object readable only by a named set of DIDs,
while everything else stays exactly PDS-compatible (public reads, authenticated
writes).

This is a deliberate divergence. An integrator who only speaks vanilla atproto
sees CISS as a normal PDS (public reads work, `uploadBlob` needs auth). Gated
reads are **additive**: they only change behavior for namespaces/objects an owner
has explicitly restricted, and a gated resource is **invisible** to an
unauthorized caller (see §5, denial semantics) rather than returning a
recognizable "forbidden."

**Two divergence properties an integrator must understand:**

1. A read that vanilla atproto would answer publicly may return **404** here, if
   the owner gated it and the caller is not authorized. 404 does not mean "gone" —
   it means "not visible to you" (no existence oracle).
2. `listBlobs` may **omit** objects that exist — it returns only what the caller
   may read. Do not treat `listBlobs` as an authoritative object count.

Gated resources are **off the public-replication surface** (they are not published
to `subscribeRepos`/relays). **[PLANNED — no such surface exists yet.]**

## 2. Concepts

| Term | Meaning |
|---|---|
| **Identity** | a verified DID. Either `id:<64hex>` (CISS-native, key-hash session) or `did:plc`/`did:web` (atproto, service-auth JWT). See `SECURITY-POSTURE.md` §4. |
| **Namespace** | a DID's repo / data-structure — the default grain for policy (`target = <did>`). |
| **Object** | one content-addressed blob within a namespace (`target = <did>/<cid>`). Finest grain for policy. |
| **Policy** | an **owner-signed record** stating who may read a namespace or object. |
| **Owner** | the DID that owns the namespace (`derive_id(signing key) == did`). Always allowed to read its own resources. |

## 3. The read-authorization model  **[SETTLED — Q1]**

A read is authorized by resolving the applicable policy, finest grain first:

```
  read(caller, did, cid):
    1. object policy for (did, cid)?  → use it        # finest grain wins
    2. else namespace policy for did? → use it
    3. else                           → read_class = world   # PDS-compat default
```

`read_class` is one of three values (explicit, matching the ADR's Unix-mode
archetypes):

| `read_class` | Who may read | Unix analogy |
|---|---|---|
| `world` | anyone (no auth) | `0755` |
| `grantees` | the owner **plus** every DID in `readers[]` | `0750` |
| `owner` | the owner only | `0700` |

- **The owner is always allowed** — it never needs to appear in `readers[]`.
- `readers[]` applies only to `read_class: grantees` and is a list of **explicit
  DIDs** (`did:plc`/`did:web`/`id:`). Authorization is a pure set-membership check:
  `allow ⇔ caller == owner OR caller ∈ readers`.
- **No groups, handles, or nesting in v1.** `readers[]` is DIDs only. Group and
  nested-group grants are a **[PLANNED]** extension (see §8); they are expected to
  be needed for large/churning grantee sets (e.g. history-convergence) but are not
  specified until that surface is concrete.
- **Writes are unchanged** — owner-only (`SECURITY-POSTURE.md` Z2). `write_class`
  is reserved in the record but v1 enforces owner-only writes; delegated writes are
  **[PLANNED]**, not v1.

## 4. The signed policy record  **[SETTLED]**

Policy is a **dedicated, self-authorizing record** — its own signed artifact,
**separate from the customer manifest**. CISS trusts it because it is signed by the
key that derives the target's owning DID (the same trust model as the manifest,
invariant Z3) — not because of who was logged in when it was submitted.

**Why a dedicated record, not a field on the manifest (Q2).** The manifest's
signature is load-bearing for **billing** integrity — the B-tier invariants rest
on "rent is a pure function of the customer's signed manifest." Read policy is a
**separate concern** (authorization), changing on a different cadence and under a
different threat model. Keeping them as two records with two signatures keeps each
signature's claim precise: the manifest attests **what is stored (rent)**; the
policy attests **who may read it (authz)**. Consequences an integrator can rely on:
a grant/revoke **never re-signs or touches the manifest** (no billing side-effects),
and per-object policy is first-class (a whole-namespace manifest cannot carry
per-object ACLs without bloat).

Fields (canonical form TBD in Phase 1; illustrative):

```json
{
  "target":     "did:plc:alice",              // a namespace; or "did:plc:alice/<cid>" for an object
  "read_class": "grantees",                    // world | grantees | owner
  "readers":    ["did:plc:bob", "did:web:carol.example"],   // DIDs; only for grantees
  "seq":        7,                             // monotonic per target (anti-rollback)
  "signer":     "<owner pubkey hex>",
  "sig":        "<signature over the canonical preimage>"
}
```

**Verification (what CISS checks before honoring a policy):**

1. `signer` derives the target's owning DID (`derive_id(signer) == <did>`).
2. `sig` verifies over a canonical, versioned preimage
   (shape: `ciss/v1/policy:<target>:<seq>:<read_class>:<readers…>`, mirroring the
   manifest preimage) under `signer`.
3. `seq` is strictly greater than the stored `seq` for that target (a replayed or
   older policy is refused — no silent rollback of a revocation).
4. every `readers[]` entry is a well-formed DID.

A record failing any check is **refused and does not change access** (fail-closed).

Because it is a dedicated record, a policy is submitted on its own endpoint (§6),
independently of the manifest, and carries its own `seq` lifecycle.

### 4.1 Who may set policy — two authorization forms  **[SETTLED]**

The owner authorizes a policy in one of two ways, depending on whether they hold a
signing key locally. Both produce a record CISS can durably verify on later reads;
readers/grantees may be **any** DID either way.

- **`id:` owner → owner-signed (Model A).** A Croft-native owner holds its ed25519
  key (the DID is its hash), so it signs the policy record itself. The signature is
  the proof — self-contained, content-binding, and durable. No external provider,
  works offline.
- **External-provider (`did:`) owner → provider-attested (Model C).** An owner whose
  key lives at an **external identity provider** — CISS has *offloaded authentication*
  to one (today Bluesky via `account.croft.ing`, but the mechanism is the atproto
  **service-auth** path, not Bluesky-specific) — cannot self-sign. It instead presents
  a **service-auth JWT** (`iss`=owner DID, `aud`=CISS, `lxm`=the set-policy method,
  short `exp`). The provider vouches, via the owner's repo key, that the owner
  authorized a *set-policy action*. CISS verifies the JWT (the same DID-resolution
  path it uses for `uploadBlob`), then **counter-signs the resulting policy with its
  provider key** (a domain-separated attestation) so the stored record stays durably
  verifiable after the short-lived JWT expires.

**Property to understand (Model C):** the JWT authorizes the *action*, not the
*bytes* — it proves "this DID said set-policy now," and the policy body rides the
same authenticated request. Content integrity in transit therefore rests on TLS +
the short `exp` + a single-use `jti`, exactly as `uploadBlob` already works; the
provider counter-sign is what makes the *result* durable. Model A binds the content
cryptographically and forever; Model C is no weaker than the existing upload path.

## 5. Denial semantics — the leakage rules  **[SETTLED]**

A gate that reveals what it hides is not a gate. So:

- **`getBlob` / object GET on a resource the caller may not read → `404`**, never
  `403`. 404 is indistinguishable from "does not exist" — no existence oracle. An
  anonymous caller to a gated object also gets `404`.
- **`listBlobs` omits** every object the caller may not read. The owner sees all;
  a grantee sees `world` objects plus the ones granted to it; an anonymous caller
  sees only `world` objects.
- A `world` resource behaves exactly as a standard PDS (public read) — no change.

Integrators: a `404` from a CISS read is **not** proof of non-existence, and a
`listBlobs` result is a caller-scoped view, not a census.

## 6. Wire API  **[LIVE — built]**

Policy is written to a **dedicated endpoint**, never as part of a manifest write:

- `PUT /{did}/policy` — set/replace the **namespace** policy.
- `PUT /{did}/objects/{cid}/policy` — set/replace a **per-object** policy.
- `GET` on either path — **read back** the current policy.

The request body depends on the owner's authorization form (§4.1):

- **Model A (`id:` owner).** The body is a full **signed `PolicyRecord`** (JSON,
  §4) carrying `authorization: {OwnerSigned: {signer, sig}}`. No auth header — the
  record's own signature is the authorization. The record's `did`/`cid` must match
  the route.
- **Model C (`did:` owner).** The request carries `Authorization: Bearer <service-
  auth JWT>` (`lxm = ing.croft.ciss.setPolicy`, `aud =` the CISS service DID,
  `iss =` the owning DID) and the body is a **`PolicyIntent`**: `{"read_class":
  "world|grantees|owner", "readers": ["did:…", …], "seq": <n>}`. CISS verifies the
  JWT, asserts the authenticated DID equals the target DID, then builds and
  provider-attests the record. A present-but-invalid JWT is a hard `403`.

On success both return `{"seq": <n>}`. Failures are distinct: `400` (malformed
body / target-route mismatch), `403` (unauthorized — bad/forged signature, wrong
signer, non-`id:` target for `OwnerSigned`, or a failed/wrong-target JWT), `409`
(the `seq` does not supersede the stored policy — anti-rollback).

**Revoke / re-grant** is just a higher-`seq` policy with the new `readers[]` /
`read_class`; there is no delete verb — a policy is superseded, never rolled back.

**Read-back visibility (owner-only, resolved).** On `GET`, the **owner** receives
the full signed record (including `readers[]`); a **grantee** receives only
`{"read_class": …, "may_read": true}` — never the reader set; any other caller
gets `404`. Read-back authenticates the caller by either an `id:` session or a
`did:` service-auth JWT (`lxm = ing.croft.ciss.getPolicy`), so a `did:` owner —
which holds no `id:` session — can read its own policy back.

**Read endpoints are unchanged on the wire.** `getBlob`/`getObject`/`listBlobs`
keep their paths and shapes — only the **authorization outcome** changes (§3, §5):
a gated resource `404`s an unauthorized caller and `listBlobs` omits it. Reads now
**authenticate the caller** (an `id:` session, or a `did:` service-auth JWT bound
to the read method on the atproto surface) so a grantee is recognized; no
credential is anonymous (world-readable objects only).

## 7. Range-scoped policy (history-convergence)  **[PLANNED — deferred, Q3]**

The history-convergence backend is a range-based crypto-chain query surface; its
reads may eventually need policy scoped to a **key range**, not just a namespace or
a single object. **Decision: not in v1.** v1 covers namespace + object grain; range
grain is a tracked extension, designed **when that query surface is concrete**
(designing it now would be guessing the query shape). The object grain is the
interim escape hatch if some segment-level differentiation is needed before then.

**Design constraint kept in mind:** v1's model must not preclude adding
range-scoped policy later — the policy `target` is an opaque, extensible string
(`<did>` / `<did>/<cid>` today), so a future `<did>/range/<lo>-<hi>` target slots
in without reshaping the record or the resolution order (finest grain wins). If a
v1 choice would conflict with range grain, prefer the choice that leaves room for
it.

## 8. Not in v1 (explicit, so integrators don't rely on them)

- **Groups / handles / nested groups** in `readers[]` — DIDs only for now
  ([PLANNED]). See §8.1 for the deferred design and why.
- **Delegated writes** (`write_class: grantees`) — writes stay owner-only
  ([PLANNED]).
- **Range-scoped policy** — [OPEN — Q3].
- **Public-replication of gated resources** — gated resources are off
  `subscribeRepos`/relay; there is no such surface yet ([PLANNED]).

### 8.1 The group model (deferred) — the tension to solve later

v1 grants to **explicit DIDs listed in each policy record** (§3). This is correct
and simple, but it has a known long-term cost, and there are two candidate futures.
Recording both so a later design starts from the real tradeoff, not a blank page:

- **(i) Static DID set — what v1 does.** `readers[]` is a literal DID list, signed
  into each policy record. Cost: the membership is **set in stone per record**.
  Changing "the group" (add/remove a member) means re-signing and bumping `seq` on
  **every** policy record that lists those DIDs — O(records) churn, and no single
  place that *is* the group.
- **(ii) Dynamic group pointer — the future.** A policy record references a **named
  group** (a group id/DID); membership lives in a separate, owner-maintained group
  record. Changing the group updates one record and every policy that points to it
  follows — O(1) churn. Likely needs **nesting** (groups containing groups).

**Why (ii) is deferred:** it needs a whole group-membership model we are not ready
to pin down — who may edit a group, how membership is signed/verified, nesting and
cycle rules, and group→DID resolution **on the authorization hot path** (new trust
surface + latency). Until that surface is clear, (i) is the right call: explicit,
auditable, and a pure set-membership check with no resolution step.

**The v1 obligation:** do not design (i) in a way that blocks (ii). A `readers[]`
entry is a DID today; a future group would be *another kind of entry* in the same
list (a group ref resolving to DIDs), so the record shape and the membership check
extend rather than reshape. Keep `readers[]` an opaque list of principals.

## 9. Change log

- 2026-08-05 — initial draft; §3 (read model) and §5 (denial) settled per Q1;
  §4 record shape settled, transport open (Q2); §7 range grain open (Q3).
- 2026-08-05 — Q2 settled: policy is a **dedicated record** (not a manifest field),
  submitted on its own endpoint; §4 rationale + §6 wire model filled in.
- 2026-08-05 — policy authority settled (§4.1): **two forms in v1** — `id:` owners
  self-sign (Model A), external-provider (`did:`) owners authorize via service-auth
  JWT + CISS provider counter-sign (Model C). Reframed as "offloaded auth to an
  external identity provider (today bsky, not bsky-bound)."
- 2026-08-05 — Q3 settled: **range grain deferred** (kept as a design constraint so
  v1 leaves room, §7); the **group model is deferred** with the static-vs-dynamic
  tension recorded (§8.1). All v1 design questions resolved — scope frozen.
- 2026-08-05 — **built (8-phase TDD increment).** §6 wire finalized to the shipped
  form: `PUT/GET /{did}/policy` and `/{did}/objects/{cid}/policy`; Model A body =
  signed `PolicyRecord`, Model C body = `PolicyIntent` + `Bearer` service-auth JWT
  (`lxm = ing.croft.ciss.setPolicy`); distinct `400`/`403`/`409` failures.
  Read-back visibility resolved **owner-only** (a grantee sees only `may_read`).
  Model C provider attestation uses a **dedicated** `policy-attest` key (Q3),
  separate from the receipt/billing key. Reads authenticate the caller
  (`id:` session or `did:` JWT). Enforcement invariants recorded in
  `SECURITY-POSTURE.md`; the §2 grain decision in ADR 0001.
