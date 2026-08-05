# ADR 0001 — Authentication and access-control model

- **Status:** Proposed — **amended 2026-08-04** (see "Amendment" below; §3's
  token-source model was corrected after the Phase-0 probe).
- **Date:** 2026-08-03
- **Deciders:** CISS maintainers (Croft)
- **Supersedes:** the Phase-8 mock-bearer `SEAM:` (`docs/ARCHITECTURE.md` §7 → "Auth")

> **Amendment (2026-08-04) — read with §3.** The Phase-0 probe
> (`docs/notes/atproto-token-shape.md`) found the deployed broker
> (`account.croft.ing`) is a confidential OAuth **client**, not an issuer: it mints
> **no** token for CISS to verify. §3's "DPoP-bound tokens / service-auth JWTs that
> flow from that broker" is therefore corrected: **CISS verifies an atproto
> service-auth JWT signed by the caller's own repo key (ES256K/ES256), obtained via
> `com.atproto.server.getServiceAuth` — relayed by the broker when up, or fetched
> by the client directly — and validated by resolving the caller's DID.** The broker
> is a courier, never a trust root (Model R). The full model, the rejected
> broker-as-issuer alternative (Model B), and the degraded-mode design are in
> `docs/notes/atproto-integration-model.md`. The crib source is `rsky-crypto`
> (in-corpus reference), not `rsky-pds` (not in the local corpus).
>
> This amendment's scope is the whole ADR, not only §3: the **DPoP** language in §4
> and Consequences is superseded — the built path verifies a **service-auth JWT**
> (no DPoP; DPoP is the parked Model M2) — and "cribbed from rsky-pds" (§3,
> Consequences) is superseded by the `rsky-crypto` / `croft-broker` JOSE port.

---

## Problem statement

CISS is live on a public hostname (`https://ciss.croft.ing`) with no real
authentication or authorization:

- The S3 plane (`PUT`/`GET` objects, manifest, meter) has **no auth at all** —
  any anonymous caller reads, writes, enumerates, and reads the billing meter of
  any DID's namespace.
- The atproto plane returns `401` without a bearer, which *looks* authenticated,
  but `authed_did` (`src/pds_api.rs:53`) accepts **any non-empty string** and uses
  that string verbatim as the acting DID. The lock is painted on.

This is not only an access problem. The provider signs a receipt naming the
acting DID for every transfer (`src/server.rs:398`, `src/receipts.rs:282`). So a
caller sending `Authorization: Bearer did:plc:victim` makes CISS **sign a false
billing statement against a third party** — a provider-signed record the victim
cannot repudiate from the receipt alone (audit finding F4). Authentication is
therefore load-bearing for billing integrity, not just for access.

Two related integrity findings are forcing functions for this decision — they
show the system trusts untrusted input at multiple layers, so the auth rework and
the input-hardening must land as one coherent change, not two:

- **F1/F2 (manifest billing integrity).** `Manifest.total_bytes` is
  deserialized off the wire and is never bound by the signature or recomputed
  from the leaves, and the Merkle root uses duplicate-last padding
  (CVE-2012-2459 shape), so one signature validates multiple leaf sets. The
  README's claim that "rent is a pure function of a document the customer
  authored" is currently false.
- **F3/F11 (input scoping).** `did`/`cid`/`key` path segments are unvalidated —
  they reach journald log lines (log forging), filesystem paths, and SQLite keys
  with no charset, length, or emptiness check.

We also have a product requirement that vanilla atproto does not meet: CISS must
run in **standard PDS-compatibility mode** (public reads, authenticated writes)
**and** be able to **gate reads for non-PDS data structures** (the
history-convergence backend, private repos), without reintroducing the
painted-lock anti-pattern.

## Decision

### 1. Separate the three questions

The current code fuses three distinct questions into one string check. Split
them:

```
  authentication   "who are you, provably?"        a verified session identity
  visibility       "does a read need auth here?"    a property of the NAMESPACE
  authorization    "may this identity do this op?"  policy evaluated at dispatch
```

The load-bearing invariant that kills the anti-pattern: **presence of a token
proves nothing; only a verified session identity feeds authorization. A gate is
never inferred from a token being present.**

### 2. Access-control grain = the namespace, expressed as mode bits

Access control lives on the **namespace** (a repo / a data-structure instance),
not the individual blob — matching atproto's actual grain and the Unix-mode
mental model. Each namespace carries `{ read_class, write_class }`:

```
  namespace archetype        read_class     write_class        analogy
  ─────────────────────────  ─────────────  ─────────────────  ────────
  public PDS repo            world          owner              0755
  history-convergence store  grantees       owner + delegates  0750
  private repo (PDS-shaped)  owner/grantees owner              0700
```

`read: world` is the default and is exact PDS-compatibility — no requester auth,
spec-clean, understood by stock Bluesky clients. Any tighter `read_class` turns
on requester authentication for that namespace only.

Gated namespaces diverge from stock atproto on purpose (vanilla atproto has no
per-repo read ACL): a gated read to an unauthenticated caller returns **404**
(not 403 — no existence oracle), and `listBlobs` **omits** objects the caller may
not read (otherwise the gate leaks CIDs). Gated namespaces are not on the
public-replication (`subscribeRepos`/relay) surface.

**Amendment (2026-08-05 — gated reads built).** The grain resolved to **both
namespace and per-object, composed** (finest-grain-wins: an object policy
overrides its namespace policy, which overrides the `world` default) — the minimal
composition that serves whole-repo gating *and* single-blob sharing without
bloating every object or the namespace. And the mode bits are not carried on the
manifest but as a **dedicated, owner-authorized `PolicyRecord`** per target — kept
distinct from the billing (manifest) signature so a grant/revoke never re-signs
the rent base. Two authorization forms, because who may *set* policy depends on
where the owner's key lives: **Model A** — an `id:` owner self-signs the record
(ed25519, domain `ciss/v1/policy`, valid only for a target its key derives);
**Model C** — a `did:` owner (key at an external identity provider) authorizes via
a service-auth JWT (`lxm = ing.croft.ciss.setPolicy`) and CISS counter-signs with
a dedicated `policy-attest` key (domain `ciss/v1/policy-attest`) for durability.
The record binds target (cid included), `read_class`, reader set, and a monotonic
`seq` (anti-rollback). Read classes are `world | grantees | owner`; readers are an
explicit DID list (groups deferred). Reader-set visibility on read-back is
owner-only. Full enforcement invariants: `SECURITY-POSTURE.md` Z4–Z8; integrator
contract: `docs/spec/gated-reads.md`.

### 3. CISS is a resource server, not an authorization server

CISS **verifies** atproto sessions; it **issues** nothing. The stack already runs
an OAuth broker at `account.croft.ing`; standing up a second issuer inside CISS
would be a second issuer to secure and reconcile. CISS validates the
DPoP-bound tokens / service-auth JWTs that flow from that broker, checking the
proof binds the token to this request and that the token subject is the claimed
DID. The DPoP and token-verification implementation is **cribbed from rsky-pds**
(Rust, in-corpus, already implements the atproto auth path) so we get the subtle
parts right rather than reinventing them.

### 4. Coupling: one executable, `ciss-auth` crate, authorization at `dispatch`

One binary, one systemd unit, one cgroup — the deployment model is unchanged.
The auth code splits by which half needs CISS state:

```
Caddy (TLS + routing)     ← NOT the auth boundary; cannot verify DPoP (request-bound)
   │  443 → 127.0.0.1:8301
   ▼
┌──────────── one executable · one unit · one cgroup ─────────────┐
│  tower layer → ciss-auth crate   (AUTHENTICATION only)          │
│     verify DPoP proof + token sig vs resolved DID key            │
│     attach Principal = Authenticated(did) | Anonymous           │
│        │                                                        │
│        ▼                                                        │
│  dispatch(state, principal, op)  (AUTHORIZATION — needs Store)  │
│     load namespace mode bits for op.did                         │
│     authorize(principal, mode, op) → proceed | 401 | 404        │
│        │                                                        │
│        ▼   metered byte-path (unchanged)                        │
└──────────────────────────────────────────────────────────────────┘
```

- **Authentication → `ciss-auth` crate, wired as a tower layer that runs first.**
  A separate crate because this is the highest-risk crypto surface in the system:
  it earns its own test suite, fuzz targets, dependency graph, and lint/deny
  config, and it is reusable by the other croft-stack atproto services
  (`appview-*`). It attaches a `Principal` (`Authenticated(did)` | `Anonymous`)
  to the request and does nothing else — it holds no CISS state.
- **Authorization → in-process, at the existing `dispatch` boundary.** The
  namespace mode bits live in CISS's `Store`, so "may you read this" needs CISS
  state and cannot leave the process. `dispatch` (`src/server.rs:314`) is already
  the single choke point every handler routes through and already carries the
  `did` on each `Op`; the `Principal` is threaded alongside it.

### 5. DID resolution (the verification substrate)

Verifying a session means resolving the acting identity to the keys we check
against. Two steps, one of them security-critical:

- **Handle → DID** (atproto handle resolution via DNS TXT / HTTPS well-known) —
  needed for UX and for expressing grants against human-readable handles.
- **DID → DID document → signing keys** (`did:plc` via `plc.directory`,
  `did:web` via HTTPS) — the **security-critical** path; this is what token
  signatures are verified against.

Resolution requirements (these are first-class, not implementation detail — an
unbounded or synchronous resolve on the request path is a hang and a memory sink,
per the availability findings):

- **Runtime cache with a TTL.** Bounds both per-request latency and staleness.
- **Async, hard-timeout-bounded, and fail-closed.** An unresolvable or
  timed-out DID is a rejection, never a fall-through.
- **Pinned admin DID set.** A hard-coded / config set of privileged DIDs whose
  verification keys are baked in and **always resolved locally**, so poisoning of
  `plc.directory` or DNS cannot rotate an admin key underneath us, and admin
  auth still works as break-glass when the resolver is down. Acknowledged
  tradeoff: admin key rotation becomes a config change rather than a live PLC
  update — acceptable for the small privileged set, and the safer default for
  identities that can change policy.
- **Non-admin DIDs:** TTL cache + fail-closed now; verifying the `did:plc`
  signed operation log (so a poisoned directory cannot silently forge current
  state) is a follow-up, tracked, not v1.

## Reasoning

- **Why separate the three questions.** Fusing them is the root cause of both the
  fake-auth pattern (authentication unproven) and the inability to gate
  (visibility/authorization don't exist). Separating them is what lets one design
  serve PDS-compat *and* gated reads without special cases.
- **Why namespace-grain, not per-blob.** It matches atproto's real grain, maps
  directly onto the "one store, two consumers" architecture (the PDS-repo
  consumer mounts `read: world` namespaces; the history-convergence consumer
  mounts gated ones over the same metered byte-path), and avoids the complexity
  and leakage surface of per-object ACLs.
- **Why resource-server, not our own AS.** One issuer to secure instead of two;
  reuses the existing broker; spec-aligned with atproto inter-service auth.
- **Why one process with a crate boundary, not a sidecar.** The authorization
  half needs the `Store` and cannot cleanly leave the process. A front auth proxy
  would hand off by asserting an internal header (`X-Verified-DID`) that CISS must
  then *trust* — a spoofable boundary the moment anything reaches `:8301`
  directly (local process, SSRF, misconfig). That is the painted lock again,
  relocated. Inline verification means the thing that checks the token is the
  thing that uses the result, with no trust gap. A sidecar also doubles the
  hardening/cgroup/ops surface for a service whose governance model wants one
  envelope per tenant.
- **Why pin admin DIDs.** DID resolution trusts `plc.directory`/DNS for current
  key state; for the small set of identities that can change policy, that trust
  root is worth removing entirely via local pinning, at the cost of manual
  rotation.

## Consequences

**Positive**

- Exact PDS-compatibility is preserved; read-gating is purely additive.
- Single artifact keeps the hardened-unit / cgroup governance model intact.
- No spoofable internal trust handoff.
- Billing integrity is restored: a receipt can no longer name an unverified DID.

**Costs / negative**

- DID resolution adds an external dependency and a cache that must be secured and
  must fail closed.
- DPoP verification is subtle — mitigated by cribbing rsky-pds rather than
  writing it fresh.
- Admin-DID pinning trades rotation agility for poisoning resistance.
- Gated namespaces are unintelligible to stock atproto clients — by design; they
  are off the public-replication surface.

**Rejected alternatives**

- **Standalone authorization server inside CISS** — a second issuer to secure and
  reconcile against the existing broker.
- **Front auth proxy / sidecar** — spoofable `X-Verified-DID` handoff, doubles the
  ops surface, and cannot own the authorization half (which needs the `Store`).

## Forcing-function findings (land with this work)

Not re-litigated here; captured so the auth rework and the integrity hardening
ship as one story. Full detail in the audit report.

- **F4 — identity-as-string.** Closed by real requester verification; separately,
  put the `id:<hex>` and `did:*` identity spaces behind a discriminated type so
  the atproto plane cannot assert an internal identifier and vice versa.
- **F1/F2 — manifest integrity.** Bind `total_bytes` and the leaf multiset into a
  versioned signed preimage; reject duplicate cids and stop duplicate-last Merkle
  padding. The billing story does not hold until this lands.
- **F3/F11 — input scoping.** A single `parse_did` newtype at the extractor
  boundary (non-empty, length-capped, charset-constrained) closes both the
  journald log-forging vector and the empty/control-char/homoglyph DID
  acceptance. Highest leverage, smallest change.

## Open questions

- ~~Exact token type CISS accepts from `account.croft.ing` (OAuth access token vs
  service-auth JWT)~~ — **RESOLVED 2026-08-04 (Phase 0).** CISS accepts an atproto
  **service-auth JWT** signed by the caller's repo key, verified via DID resolution
  (Model R). The broker issues no CISS token. See the Amendment and
  `docs/notes/atproto-integration-model.md`.
- Namespace policy storage shape, and how a namespace's mode bits are set and
  changed (an owner-signed policy record is the likely form).
- `did:plc` audit-log verification: v1 or a tracked follow-up.
