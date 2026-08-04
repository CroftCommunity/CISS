# Phase 0 findings — atproto token shape + DID resolution (probed 2026-08-04)

Deliverable of the atproto-identity increment's Phase 0
(`docs/plans/2026-08-04-atproto-identity.md`). Probes only; no production code.
Captured against live services on 2026-08-04.

## Headline: the deployed broker contradicts ADR 0001 §3

ADR 0001 §3 says CISS "validates the DPoP-bound tokens / service-auth JWTs that
flow from that broker [`account.croft.ing`]." **The deployed broker issues no such
token to CISS.**

- `account.croft.ing` returns **HTTP 404** for every authorization-server path:
  `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`,
  `/.well-known/openid-configuration`, `/oauth/authorize`. (Caddy fronts it —
  `via: 1.1 Caddy` — so the vhost is live; the backend simply serves none of these.)
- `croft-stack/broker/README.md` is explicit: it is a **confidential atproto OAuth
  _client_**, not an authorization server. It brokers a user's session against the
  user's *upstream* PDS/AS (e.g. `bsky.social`), holds the DPoP-bound tokens
  server-side, and hands a pad only an **opaque ticket**. "The tokens never leave
  the broker." Its endpoints are `/login`, `/callback`, `/api/whoami`,
  `/client-metadata.json`, `/jwks.json` — a client, plus a ticket-exchange. No
  `/token`, no `/authorize`, no `/par` of its own (the only such strings in the
  broker source are a *test fixture* naming `bsky.social`'s endpoints, which it
  consumes as a client).

So there is no broker-minted access token for CISS to verify. The premise
"validate tokens that flow from the broker" does not hold against what is
deployed. This is the exact class of assumption Phase 0 exists to catch before
Phase 3 writes verification code.

## What actually fits — two models (decision required)

### M1 — atproto service-auth JWT, verified via DID resolution  **(recommended)**

The atproto-native way a caller authenticates to a service it does **not** own:
`com.atproto.server.getServiceAuth` mints a short-lived compact JWS signed by the
caller's **repo signing key** (the `did:plc`/`did:web` key), with:

- `iss = <caller DID>`
- `aud = <CISS's service DID>`
- `lxm = <allowed XRPC method>` (e.g. `com.atproto.repo.uploadBlob`)
- short `exp` / `iat`

CISS verifies the JWT signature against the **DID's resolved signing key** and
checks `aud`==CISS, `lxm`==the called method, and the `exp`/`iat` window. This is
exactly the DID-resolution substrate the plan already builds (Phase 2); the
"DPoP" step is simply replaced by the `aud`/`lxm`/`exp` binding. No broker
involvement, no DPoP, no issuer — honors ADR §3's "CISS is a resource server, it
issues nothing." This is the model AppView→PDS and service-to-service calls use.

### M2 — DPoP-bound OAuth access token, CISS in the OAuth trust chain

The "CISS is the user's PDS" model: an authorization server issues DPoP-bound
access tokens *for CISS's protected resources*, and CISS validates token + DPoP
proof. This needs either **CISS as its own AS** (ADR §3 explicitly rejects a
second issuer) or **extending `croft-broker` to issue resource tokens for CISS**
(net-new broker work, not a CISS-only change). Not achievable against the broker
as deployed.

**Recommendation: M1.** Atproto-native for a non-issuing resource server, needs no
new broker capability, verified purely by DID resolution (the substrate we are
already building), and consistent with ADR §3. It changes Phase 3 from "DPoP
proof verification" to "service-auth JWT verification (sig via resolved DID key +
`aud`/`lxm`/`exp`/`iat`)". DPoP re-enters only if we later adopt M2 as a tracked
follow-up.

## DID resolution — captured shape (security-critical path)

`GET https://plc.directory/{did}` works and returns the DID document.
Fixture frozen at `tests/fixtures/did/did-plc-bsky-app.json`
(`did:plc:z72i7hdynmk6r22z27h6tvur`, resolved live from handle `bsky.app`):

```json
"verificationMethod":[{
  "id":"did:plc:…#atproto",
  "type":"Multikey",
  "controller":"did:plc:…",
  "publicKeyMultibase":"zQ3shQo6TF2moaqMTrUZEM1jeuYRQXeHEx4evX9751y2qPqRA"
}]
```

We extract the `#atproto` verification method's `publicKeyMultibase`.

**Curve fact (load-bearing for `ciss-auth`):** the `zQ3s…` multibase prefix + the
`secp256k1-2019` `@context` entry mean this key is **secp256k1 (ES256K)**, not
ed25519. atproto repo signing keys are commonly **secp256k1**; some are **P-256**
(`zDna…` prefix). So `ciss-auth`'s verifier must support **ES256K (k256)** as the
primary and **ES256 (p256)** as a secondary, dispatched by the multikey prefix.
`ed25519-dalek` alone is insufficient for the `did:` space.

`did:web`: resolution is `GET https://{host}/.well-known/did.json` (same
verificationMethod shape). A real Croft-relevant `did:web` doc was not captured in
this pass (the handy public examples are `did:plc`); capture one as a fixture when
the first `did:web` identity we must accept exists.

## Crib source — in-corpus, better than rsky-pds

`rsky-pds` is **not** in the local corpus (confirmed by searching all of
`CroftC/`). But `croft-stack/broker` already hand-rolls the JOSE we need and is
same-workspace / same-identity:

- `broker/src/jose.rs` — ES256 compact JWS sign/**verify**, `b64url`, `sha256`,
  JWK export, RFC 7638 thumbprint (deps: `p256` 0.13, `sha2`, `base64`).
- `broker/src/dpop.rs` — DPoP proof build with `htm`/`htu`/`ath`/`nonce` (if M2).
- `broker/src/assertion.rs` — `private_key_jwt` (ES256) client assertion.

Crib the compact-JWS **verify** path from `broker/src/jose.rs`. Note the curve
gap: the broker is **P-256** (its own client keys); CISS verifying a `did:plc`
service-auth JWT needs **secp256k1/ES256K** (add `k256`), reusing the broker's
compact-JWS framing but swapping the curve. Vendoring rsky-pds is therefore
unnecessary — port the in-corpus broker JOSE instead.

## Consequences for the plan

- **ADR 0001 §3 + §Open-questions** must be updated: the token CISS accepts is (if
  M1) an **atproto service-auth JWT verified via DID resolution**, not a
  broker-issued token. The "flows from that broker" wording is wrong.
- **Phase 2 (DID resolution)** is unchanged and is the centerpiece; the `did:plc`
  fixture is captured, the key type (secp256k1) is pinned.
- **Phase 3** shape flips from DPoP proof verification to **service-auth JWT**
  verification (unless M2 is chosen). Primitive: `k256` (ES256K) + `p256` (ES256),
  compact-JWS verify ported from `croft-broker/src/jose.rs`.
- **Crib step** in the plan changes from "vendor rsky-pds" to "port
  `croft-broker/src/jose.rs` verify path" — in-corpus, no external vendor.
- **`did:web` fixture** deferred until a real one is needed (endpoint + shape known).
