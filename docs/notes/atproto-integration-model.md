# CISS ↔ atproto identity — the integration model

- **Date:** 2026-08-04
- **Status:** Decided — **Model R** (relay bsky-signed service-auth JWTs) + **cold
  fallback**. Records the design behind the atproto-identity increment.
- **Supersedes:** the token-source assumption in ADR 0001 §3 (see the amendment in
  that ADR). Grounded in the Phase-0 probe (`atproto-token-shape.md`).
- **Related:** `pds-capability-gap.md` (what CISS would need to *be* a PDS),
  `../plans/2026-08-04-atproto-identity.md` (the build plan).

---

## Design tenet

> The helper infrastructure (`account.croft.ing`) is a **helper**, not a gate.
> **PWA/SPA-direct is the floor.** CISS relies on bsky for the PDS, the OAuth
> authorization server, and the DID directory — **openly**, as external trust
> roots we name, not hidden dependencies. CISS issues no identity, holds no
> session, and mints no token; it **verifies delegated, DID-signed authorization**.

Every decision below follows from that tenet. The floor is that a browser client
talks to bsky directly and to CISS directly; the broker only makes that nicer when
it is up, and its absence degrades UX, never correctness.

## CISS's role: resource provider, verify-only

atproto keeps two roles separate, and CISS is only the second:

```
  a PDS ............... ISSUES identity sessions, IS your repo host, runs the OAuth AS.
  a resource provider  VERIFIES an identity it did not issue. Holds no session.
```

CISS is a **metered storage resource provider**. The "atproto PDS blob API"
(`uploadBlob`/`getBlob`/`listBlobs`) is a *compatibility surface* so atproto
tooling can talk to it — not a claim that CISS is anyone's PDS. This dissolves the
"do we need our own OAuth server" question: no. bsky is the AS.

## Token taxonomy — what CISS actually verifies

Three layers, and CISS only ever sees the third:

```
  LAYER 1 — LOGIN            LAYER 2 — SESSION          LAYER 3 — DELEGATION
  app password  ───────▶     bsky session       ─────▶  service-auth JWT
  OR OAuth consent           (access/refresh)           (com.atproto.server.getServiceAuth)
  what YOU use to log in     only bsky verifies          ANYONE verifies via DID resolution
       CISS never sees these  ─────────────────────▶     THIS is all CISS handles
```

| | App password | OAuth session | **Service-auth JWT** |
|---|---|---|---|
| Layer | login credential | session | **delegation** |
| Signed by | (exchanged for a session) | bsky server key | **user's repo key** (ES256K, the DID-doc `#atproto` key) |
| Who verifies | only bsky | only bsky | **anyone, via DID resolution** |
| Lifetime | — | long | **~60s, `aud`+`lxm`-scoped** |
| CISS uses it? | never | never | **yes — the only token CISS accepts** |

Handing CISS a bsky access token is useless — it is signed by bsky's own key and
CISS has no way to verify it (like handing a delivery driver your house key). The
service-auth JWT is a **notarized, 60-second, single-errand permission slip** signed
by *your* key and checkable by anyone against your published DID.

**The contract CISS validates** (verified from rsky `get_service_auth.rs` +
`create_service_jwt`):

```
  header: { "alg": "ES256K", "typ": "JWT" }        // ES256K (secp256k1) or ES256
  claims: { iss = <caller DID>,                     // resolved to a signing key
            aud = did:web:ciss.croft.ing,           // for CISS specifically
            lxm = "com.atproto.repo.uploadBlob",    // this method only
            exp = now+60s (max +1h),                 // short-lived
            jti = <nonce> }                          // optional replay id
  signature: ECDSA over the user's repo signing key  // verify via DID resolution
```

## How the token is obtained — Model R vs Model B

"`account.croft.ing` mints a token for CISS" can mean two very different things.
This was the key fork.

```
  MODEL R — broker RELAYS a bsky-minted token          MODEL B — broker MINTS its own token
  (signed by the USER's DID key)                        (signed by the BROKER's key)

  broker ─(held session)─▶ bsky getServiceAuth          broker signs a token asserting
       ◀─ JWT signed by user's repo key                      "this is did:plc:alice"
  relays to pad ─▶ CISS                                  hands to pad ─▶ CISS
  CISS verifies vs the USER's DID (plc.directory)        CISS verifies vs the BROKER's key
       trust root = the user's own key                        trust root = the broker
```

| | **Model R — relay bsky-signed** | Model B — broker-signed |
|---|---|---|
| Who signs | the user's repo key (at bsky) | account.croft.ing's key |
| CISS trust root | the **user's DID** (canonical) | the broker |
| Cryptographically tied to the user? | **yes** — bsky signs *as the DID* | no — broker *asserts* the DID |
| Broker compromised ⇒ | mint only for held sessions, ≤60s, requested `lxm` | **impersonate any DID** — full forgery |
| Standard atproto / interop | **yes**, broker optional | no, proprietary |
| CISS verification | DID resolution (building anyway) | pin broker JWKS |

**Decision: Model R.** Model B is the `X-Verified-DID` painted-lock the ADR §Reasoning
rejected, now wearing a JWT — CISS would trust the broker's *word*, not the user's
signature. Model R makes the broker a **courier, never a trust root**: a compromised
courier cannot forge a user, only fetch a 60-second, method-scoped pass for a
session it already legitimately holds.

The one legitimate pull toward B — identities that are **not** on bsky (no user repo
key to sign with) — is parked with the Croft-native `id:` path (see "Dependencies").
For all bsky-backed identities, R is strictly better.

## Client modes and the two flows

```
  ┌─ Confidential client (broker up, PREFERRED) ──────────────────────────┐
  │  pad ─▶ broker ─(held long session)─▶ bsky getServiceAuth ─▶ JWT ─▶ pad │
  └───────────────────────────────────────────────────────────────────────┘
  ┌─ Public client (broker down, the FLOOR) ──────────────────────────────┐
  │  pad ─(own in-browser session)──────▶ bsky getServiceAuth ─▶ JWT ─▶ pad │
  └───────────────────────────────────────────────────────────────────────┘
                         both paths end: pad ─Bearer JWT─▶ CISS
                         CISS resolves iss DID → key → verify sig+aud+lxm+exp
                         → Principal::Authenticated(did) → meter + receipt   (IDENTICAL)
```

The token that reaches CISS is the same minimally-scoped JWT in both modes; only
*who fetched it* changes. **All current consumers are already the public-client
shape** — the broker is an add-on for session longevity and keeping tokens out of
the browser, not a prerequisite.

## Broker outage — the degraded mode (cold fallback)

When `account.croft.ing` is down, the PWA falls back to its own public OAuth client
against bsky and calls `getServiceAuth` itself. CISS sees no difference.

**Decision: cold fallback** (spin up the PWA's own session only on broker failure),
not hot standby:

| | **Cold fallback (chosen)** | Hot standby |
|---|---|---|
| PWA own session | created only when the broker fails | always maintained in parallel |
| Failover | a consent redirect at failure time | instant, invisible |
| Happy-path token exposure | none (tokens stay server-side) | a browser-held session always exists |

Reasoning: cold fallback keeps the broker's "tokens never in the browser" benefit in
the normal case and only accepts browser-held tokens when there is no alternative —
matching the security intent. Hot standby buys instant failover at the cost of always
holding a browser session; not worth it for now.

**What the PWA must self-provide for the floor to hold:**

- Its **own hosted `client-metadata.json`** at the PWA's *own* origin (that URL *is*
  its atproto `client_id` — no registration step). **Do not host it on
  `account.croft.ing`** — if the broker's origin serves the fallback client's
  metadata, the fallback dies with the broker. The PWA must be self-describing.
- An **in-browser atproto OAuth client** (`@atproto/oauth-client-browser`-shape:
  PAR + DPoP + PKCE + refresh) to establish and keep its own session.
- **Client-side handle→DID→PDS resolution** to find the user's authserver without
  the broker.

## Failure matrix

| Down | Public `world` reads | Authenticated writes |
|---|---|---|
| **Broker only** | ✅ | ✅ via the PWA's own bsky session |
| **bsky / user's PDS** | ✅ | ❌ can't mint a fresh JWT → **fail closed (401)** |
| **plc.directory (CISS's resolver)** | ✅ | ⚠️ works for **cached + pinned** DIDs; else fail closed |
| **Broker + bsky both** | ✅ | ❌ fail closed; only an unexpired ≤60s token still works |

Broker-down (token *acquisition*, client side) and resolver-down (token
*verification*, server side) are **independent failure domains** — neither cascades.
Fail-closed on writes while public reads keep serving is the intended posture.

## Dependencies, stated openly

- **bsky** — the user's PDS + OAuth AS + the signer of service-auth JWTs (via the
  user's repo key). CISS trusts it exactly as much as atproto already does: it
  controls the user's repo key.
- **plc.directory / `did:web` hosts** — the DID directory; CISS's *own* external
  dependency for verification. Mitigated by the resolver design: TTL cache,
  pinned-admin set resolved locally, hard timeout, fail-closed.
- **`account.croft.ing` (the broker)** — an **optional** session-longevity helper.
  Removable without affecting CISS correctness.
- **Croft-native `id:` space** — depends on none of the above (the DID *is* the hash
  of a presented key). Parked per the "piggyback bsky for now" decision, but it is
  the only path that keeps CISS writes working through a total bsky/plc outage, and
  the home for non-bsky identities. Kept as a deliberate future lever.

## What this requires us to build

1. **`did:web:ciss.croft.ing`** — CISS's atproto service identity, so a service-auth
   JWT can be *addressed* to it (`aud`). Serve `/.well-known/did.json`. Small; the
   anchor for the whole federated path. (Today CISS's identity is `id:b82d…`, which
   cannot be an atproto `aud`.)
2. **Service-auth JWT verification in CISS** — the atproto-identity increment:
   resolve the `iss` DID, verify sig (ES256K/ES256) + `aud`==CISS + `lxm` + `exp`,
   attach `Principal::Authenticated(did)`. Self-contained; works for *any* caller who
   can produce a valid JWT, broker or not.
3. **Broker `getServiceAuth` relay endpoint** — a new `account.croft.ing` endpoint
   that mints/relays a service-auth JWT (`aud`+`lxm`) using the held session. This is
   **croft-stack work** and comes *after* CISS can verify (the floor works without it).

## Downstream option — per-object read ACLs (the private-"PDS" read case)

Verified DIDs make read-gating cheap: the hard part is proving "you are `did:X`"
(this increment); authorization is then a lookup. So an object can be stored with
an **allowed-reader DID list**, and a read requires a service-auth JWT proving a
DID on that list — the private-repo read case that falls out of piggybacking on
bsky, with **no new trust root** (same DID verification, same delegation).

```
  stored:   { bytes, reader_dids: [did:plc:alice, did:plc:bob] }   (owner-set, write-side)
  read:     Bearer <service-auth JWT, iss=did:plc:alice, lxm=getBlob>
  CISS:     verify JWT (proves alice) → alice ∈ reader_dids?
              yes → bytes ;  no / anonymous → 404 (no existence oracle; listBlobs omits)
  scope:    exactly this object — the JWT proved identity, nothing more
```

**This is an authorization-layer decision, after this (authentication) increment.**
It reopens a **grain** choice: ADR 0001 §2 chose namespace-grain `{read_class,
write_class}` mode bits and *explicitly rejected per-object ACLs* ("the complexity
and leakage surface of per-object ACLs"). Per-object reader lists are finer than
that; the two compose (namespace default + per-object override) but the tradeoff
(a `reader_dids` list as object metadata, the `listBlobs` leakage rule, the
existence-oracle 404 discipline) must be decided when the authorization model is
built, not assumed here. Tracked, not designed.

## Security notes

- The public-client fallback holds the bsky **session** in the browser (more exposed
  to XSS than the broker's server-side custody). But what reaches **CISS** is always
  the 60-second, `lxm`-scoped service-auth JWT — so even a stolen browser session's
  blast radius *at CISS* is "mint short, method-bound tokens for that one user while
  the session lives," identical to any atproto service. The broker reduces *session*
  exposure; it never widens *CISS* exposure.
- `lxm` binding is load-bearing: a token minted for `uploadBlob` must not be
  replayable to another method. CISS enforces `lxm`==the called XRPC.
- `jti` + short `exp` bound replay; CISS keeps a small TTL replay-guard.
