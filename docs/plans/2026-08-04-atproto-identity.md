# Plan — atproto-identity increment (service-auth JWT + DID resolution)

- **Date:** 2026-08-04
- **Status:** Proposed (TDD-first). **Phase 0 done** — model decided: **Model R**
  (verify a bsky-delegated service-auth JWT via DID resolution; not DPoP, not a
  broker-issued token). See `docs/notes/atproto-integration-model.md`.
- **Owns:** ADR 0001 §5 (DID resolution) + §3 as **amended 2026-08-04**
  (resource-server verifies a service-auth JWT), and the tracked follow-on in
  `docs/plans/2026-08-03-hardening-and-auth.md` §"Phase 3 status & tracked follow-on".
- **Closes:** the `did:plc` / `did:web` half of A2 (the interim auth is `id:`-only).

---

## Problem statement

CISS authenticates only the **`id:` identity space** today: `ciss-auth::verify_session`
proves possession of the key whose SHA-256 *is* the DID, so no resolution is
needed. That closes A1/A2 for `id:` callers but does not make CISS an atproto
resource server. A real Bluesky/atproto caller presents a **`did:plc:…`** or
**`did:web:…`** identity and an atproto **service-auth JWT** (`iss`=caller DID,
`aud`=CISS, `lxm`=method, ~60s `exp`) signed by the caller's **repo signing key**
and obtained via `com.atproto.server.getServiceAuth` (relayed by the broker when
up, or fetched by the client directly — Phase-0 finding: the broker is a *client*
that issues no CISS token). CISS cannot yet verify any of that: it has no way to
resolve a `did:plc`/`did:web` to the signing key, and no JWT-verification path.

Until this lands, the `did:` space is unauthenticated in exactly the A2-shaped
way the ADR calls out: a caller could present `Authorization: Bearer did:plc:victim`
and — absent verification — make CISS sign a false receipt against a third party.
The `id:`-space guard does not cover `did:` callers.

The resolution path is **security-critical and a fresh availability surface**: it
reaches the network (`plc.directory`, `did:web` hosts) on the request path, so an
unbounded or synchronous resolve is a hang and a memory sink, and a poisoned
directory could rotate a key underneath us. It must be async, hard-timeout-bounded,
cached, fail-closed, and it must not be able to rotate a *privileged* identity's
key at all.

## Approach

Two capabilities that compose, split by a hard crypto/network boundary.

```
  ┌───────────────────── one executable · one unit (unchanged) ──────────────────┐
  │                                                                              │
  │  ciss-auth  (PURE crypto, zero network — unchanged isolation)                │
  │    verify_session(...)                       ← existing id: path             │
  │    verify_service_auth_jwt(jwt, aud, lxm, resolved_key, now) → Principal  NEW │
  │    trait DidResolver { async resolve(&Did) -> Result<ResolvedKeys,…> }   NEW │
  │    ES256K (k256) + ES256 (p256) verify, low-S enforced (rsky-crypto port)     │
  │        ▲ key handed in                                                        │
  │        │                                                                      │
  │  ciss-resolve  (NEW crate — all network/cache/timeout lives here)            │
  │    PinnedResolver(admin set, always local)                                    │
  │      └─ CachingResolver(TTL)                                                   │
  │           └─ PlcWebResolver(reqwest+rustls, hard timeout, fail-closed)        │
  │                                                                              │
  │  server::authenticate(headers, resolver) async  → Principal   (rewired)      │
  │    select: Bearer <service-auth jwt> → jwt path · x-croft-* → session · Anon │
  │       │                                                                        │
  │       ▼  dispatch(state, principal, op)   (authorization + lxm check)         │
  └──────────────────────────────────────────────────────────────────────────────┘
```

**Decision — crate topology (confirmed 2026-08-04):** a new `ciss-resolve` crate,
behind a `DidResolver` trait defined in `ciss-auth`. `ciss-auth` stays pure crypto
and never grows a TLS stack; the resolver *produces* a key, `ciss-auth` *consumes*
it. Symmetric with the ciss-auth isolation rationale and reusable by the
`appview-*` services.

**Decision — crypto source (confirmed 2026-08-04):** port `rsky-crypto`'s
verify path into `ciss-auth` (Apache-2.0, with attribution) — did-key/multibase
parse + ES256K (`secp256k1` C-lib) + ES256 (`p256`) verify with **low-S /
malleability rejection** — over the trivial JWT structural split. `rsky-crypto`
(not `rsky-pds`, which is not in the local corpus) is the reference: it is the real
atproto verify path and defends adversarial-input failure modes (alg-confusion,
high-S malleability, non-canonical encodings) that the broker's sign-only
`jose.rs` never had to. We use the same battle-tested curve crates it does — no
hand-rolled curve math, no external JWT dependency on the auth path.

## Reasoning

- **Why resolution is a separate crate, not inside ciss-auth.** ciss-auth is the
  highest-risk crypto surface and is deliberately pure/fuzzable/dependency-light.
  Network resolution is the opposite: I/O, TLS, caches, timeouts, external trust.
  Keeping them apart means the thing that verifies a signature has no network in
  its graph, and the resolver can be tested with fixture DID docs with no live
  dependency. The trait boundary is the seam: ciss-auth declares what a resolver
  must yield; ciss-resolve implements it.
- **Why port `rsky-crypto`, not depend or hand-roll.** JWT *verification* of an
  adversary's token is load-bearing for billing integrity; owning the code means
  owning the tests, and the security-critical parts (low-S rejection, curve dispatch
  from the DID key, canonical encoding) are exactly what a sign-only helper omits.
  Porting the ~372 lines of `rsky-crypto` over the same curve crates gives that
  correctness without a third-party crate on the auth path. (Depending directly on
  `rsky-crypto` was the alternative; porting keeps blacksky off our supply chain
  while keeping their vetted logic and tests.)
- **Why Phase 0 gated everything.** Per the "never guess an API shape" rule, we did
  not write verification code against an assumed token type. Phase 0 probed the live
  broker + `plc.directory`, froze a real `did:plc` doc, and found the token is a
  **service-auth JWT** (Model R), the key is **secp256k1**, and the broker issues
  nothing. Resolution (Phase 2) was unblocked by fixtures; the verification shape
  (Phase 3) waited for this and is now pinned.
- **Why pin admin DIDs.** For the small set of identities that can change policy,
  the trust in `plc.directory`/DNS is worth removing entirely via local pinning, so
  a poisoned or unreachable directory can neither rotate an admin key nor lock
  admins out (break-glass). Cost: admin rotation becomes a config change. (ADR 0001
  §5, "Reasoning".)

## Phases (TDD-first — every phase RED before GREEN)

### Phase 0 — Pin the externals (no production code) · GATING · **DONE 2026-08-04**

Probed the live services, captured fixtures, decided the model. Findings in
`docs/notes/atproto-token-shape.md`; full model in
`docs/notes/atproto-integration-model.md`.

- **Broker issues no CISS token.** `account.croft.ing` 404s all AS paths; it is a
  confidential OAuth *client*. → CISS verifies a **service-auth JWT** (Model R), not
  a broker/DPoP token. ADR 0001 §3 amended.
- **`did:plc` doc frozen** at `tests/fixtures/did/did-plc-bsky-app.json`; key type is
  **secp256k1 (ES256K)** (`zQ3s…` multikey + `secp256k1-2019` context).
- **Crib source is `rsky-crypto`** (in-corpus reference clone), not `rsky-pds` (absent
  from the local corpus). `did:web` fixture deferred until a real one is needed.

### Phase 1 — Type the identity spaces (unblocked, pure)

The A2 residual: discriminate `id:<hex>` vs `did:<method>:<msid>` at the type level
so the atproto plane can never assert an internal `id:` and the session plane can
never accept a `did:*`.

- **RED:** an atproto token whose subject parses as `id:<hex>` is rejected at the
  atproto boundary; a `did:plc:…` cannot enter the signed-session path.
- **GREEN:** method discriminant on the identity newtype; route by space.

### Phase 2 — DID resolution substrate (`ciss-resolve`; fixtures, no live net)

- **RED (unit):**
  - a **pinned admin DID** resolves **locally, never calling the network arm** — the
    fixture resolver's network arm panics if invoked for an admin DID;
  - an unreachable / unknown DID → `ResolveError` (**fail-closed**, never a key);
  - a resolve exceeding the hard timeout → `ResolveError::Timeout` (fail-closed);
  - **TTL cache:** a second resolve within TTL hits cache (network arm called once);
    after TTL it re-resolves;
  - a `did:plc` fixture doc → the correct key; a `did:web` fixture doc → its key;
  - a malformed / poisoned DID doc → no key extracted (rejected).
- **GREEN:** `trait DidResolver` (in ciss-auth); `PinnedResolver` (admin set first,
  always local) → `CachingResolver<TtlCache>` → `PlcWebResolver` (reqwest + rustls,
  `tokio::time::timeout`). Network strictly behind the trait; tests use a fixture
  impl seeded from the Phase-0 docs.

### Phase 3 — Service-auth JWT verification (`ciss-auth`, pure)

Verify a service-auth JWT (Model R). No DPoP (that is M2, a parked follow-up).

- **RED (unit, resolved key injected):**
  - valid sig under the resolved key (ES256K/ES256, **low-S enforced**), `aud`==CISS,
    `lxm`==the called method, unexpired → `Authenticated(iss)`;
  - `aud` ≠ CISS (token minted for another service) → refused;
  - `lxm` ≠ the called method (cross-method replay) → refused;
  - expired (`exp` past) or not-yet-valid → refused;
  - signature does not verify under the resolved key → refused;
  - **high-S / non-canonical signature → refused** (malleability, the sign-only
    helper's blind spot — the reason we port `rsky-crypto`);
  - `jti` replay (same token twice within its window) → refused;
  - a `did:plc` `iss` whose resolved key is secp256k1 verifies; a P-256 `iss` verifies.
- **GREEN:** `verify_service_auth_jwt(...)`; did-key/multibase + curve verify ported
  from `rsky-crypto` (Apache-2.0, attributed); a TTL `jti` replay-guard (bounded
  seen-set).

### Phase 3.5 — CISS's `did:web:ciss.croft.ing` service identity · **DONE 2026-08-04**

The `aud` anchor: a service-auth JWT must be *addressed* to CISS.

- **CISS serves `/.well-known/did.json`** (an axum route, public, beside `/healthz`)
  — **not Caddy**, which already reverse-proxies `ciss.croft.ing/*` to CISS, so the
  path reaches the app with no Caddy change. The doc reflects the configured
  `service_did` (`CISS_SERVICE_DID`, default `did:web:ciss.croft.ing`) and a
  `serviceEndpoint`. `SEAM:` publishing the provider key here (external receipt
  verification via the DID) is a tracked follow-on.
- Guarded by `ciss_serves_its_own_did_web_document` (200, `id`==service DID,
  service endpoint). No croft-stack change required for Phase 3.5.

### Phase 4 — Wire the request path (workflow tier)

- `authenticate` → async `authenticate(headers, resolver) -> Principal`; select by
  header: `Authorization: Bearer <service-auth jwt>` → Phase-3 path (pass the called
  `lxm` + CISS `aud`); `x-croft-*` → existing signed session; neither → `Anonymous`.
  A **present-but-invalid** atproto credential yields `Anonymous` (→ dispatch 401),
  **never** a fall-through to the DID it named.
- Thread the resolver through `AppState`.
- **RED (`tests/flow_atproto_identity.rs`, World/Actor):**
  - a `did:plc` actor with a valid service-auth JWT uploads a blob; the receipt names
    the **resolved** DID;
  - a forged JWT naming a victim `did:plc` → 401 and **no receipt for the victim**
    (A2, now on the `did:` space);
  - a JWT with the wrong `lxm` or `aud` → 401;
  - resolver-down → the **pinned admin** DID still authenticates (break-glass); a
    non-admin DID **fails closed** (401);
  - a `read: world` `getBlob` stays public (PDS-compat unbroken).
- **GREEN:** wiring; `AppState` resolver; config for the pinned admin set, the plc
  endpoint, timeout, TTL, CISS `aud`.

### Phase 5 — Posture + ADR + deploy surface · **DONE 2026-08-04**

- Production resolver wired into `main.rs` (`src/did_resolver.rs`): `Pinned →
  Caching → Timeout → PlcWeb(ReqwestFetcher, rustls)`, config via `ResolveConfig::
  from_env`; malformed admin-pin file fails startup loudly (`parse_admin_pins`).
- `docs/SECURITY-POSTURE.md`: new invariants **A3–A7** (JWT verified vs resolved
  key + curve-from-key; `aud`/`lxm`/`exp` binding; canonical low-S; `jti` replay;
  resolution fail-closed + admin pin) + checklist rows.
- Man page + `docs/DEPLOYMENT.md`: `CISS_SERVICE_DID`, `CISS_PLC_DIRECTORY_URL`,
  `CISS_DID_RESOLVE_TIMEOUT_MS`, `CISS_DID_CACHE_TTL_S`, `CISS_ADMIN_PINS_FILE`
  (defaults safe; admin-pin file flowed like `provider-seed`). `/.well-known/did.json`
  documented as must-stay-public (not gated by the `/healthz` allowlist TODO).
- **croft-stack (when deploying):** provision the admin-pin credential, optionally
  set `CISS_SERVICE_DID`; ensure no edge allowlist gates `/.well-known/*`. No
  change required for defaults. *(Deploy itself is out of this increment — the
  branch is unmerged.)*

## Tracked follow-ons

- **Resolver cache observability (built, always-on).** `CachingResolver` tracks
  relaxed atomic hits/misses + a `CacheStats` snapshot (size, hits, misses,
  hit_rate), reachable through the composed resolver via `DidResolver::cache_stats()`
  (Pinned/Timeout delegate inward). A **periodic INFO heartbeat** (`main.rs`, 60s,
  change-gated so idle is silent) samples it for ongoing monitoring via journald —
  no prod DEBUG needed. A per-network-resolve line stays at DEBUG for detail. Auth
  decisions log too: grants DEBUG, denials INFO. **Follow-up:** feed it to the
  cgroup-based telemetry poller (croft-stack) if it should appear on the dashboard,
  not just in journald.
- **Populate `CISS_ADMIN_PINS_FILE`** — empty as deployed (no `did:` break-glass yet).

## Cross-repo follow-ons (not this increment)

- **Broker `getServiceAuth` relay endpoint** (croft-stack) — mints/relays a
  service-auth JWT (`aud`+`lxm`) from the held session. The floor (PWA-direct) works
  without it; it is the convenience path. See `atproto-integration-model.md`.
- **DPoP OAuth access tokens (Model M2)** — only if CISS later joins an OAuth
  access-token chain. Parked.
- **Per-object read ACLs (private-"PDS" reads)** — an authorization-layer feature
  that falls out of verified DIDs: an object stored with an allowed-reader DID list,
  read-gated by a service-auth JWT proving a listed DID (404 + `listBlobs`-omit on
  denial). Reopens ADR 0001 §2's namespace-vs-per-object grain choice; decide when
  the authorization model is built. See `docs/notes/atproto-integration-model.md`
  §"Downstream option".
- **`did:plc` signed-oplog verification** — so a poisoned directory cannot forge
  current key state (ADR 0001 §5, last bullet). Tracked, not v1.
- **Handle→DID resolution** (DNS TXT / HTTPS well-known) — only when grants against
  human-readable handles are needed; not on the token-verification path.
