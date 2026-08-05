# CISS security posture

How CISS is **designed** to be secure — the intended trust model, the invariants
it aims to guarantee, and where each is enforced. This is the standing reference
for auditing: read it first, then compare the code (and any finding) against it.

## How to use this document

Security review answers "what is broken." This document answers "what is it
*supposed* to do," which is what lets you classify a problem:

- **Bug** — the code violates an invariant stated here. Fix the code; the design
  is sound.
- **Design failure** — the code faithfully implements this document, but the
  invariant here is missing, too weak, or wrong. Fix the design (an ADR), then
  the code.

When you audit, walk each invariant below and ask: *is it actually enforced, at
every entry point, with no bypass?* A "no" is a bug. Then ask: *if perfectly
enforced, does it actually stop the threat?* A "no" is a design failure.

Companion docs: [`SECURITY-REVIEW-2026-08-03.md`](SECURITY-REVIEW-2026-08-03.md)
(findings + status), [`adr/0001-auth-and-access-control-model.md`](adr/0001-auth-and-access-control-model.md),
[`adr/0002-healthz-exposure-and-limit-exemption.md`](adr/0002-healthz-exposure-and-limit-exemption.md),
[`ARCHITECTURE.md`](ARCHITECTURE.md), [`DEPLOYMENT.md`](DEPLOYMENT.md).

## 1. What CISS is, in security terms

A cooperative metered-storage server: an S3-compatible object interface and an
atproto PDS blob API over one metered byte-path, where **the network boundary is
the metering boundary**. Two parties (a customer/DID and the provider) must be
able to bill each other honestly **without either trusting the other's word**,
and without trusting the storage backend. Security is therefore not a bolt-on —
the core value proposition *is* a set of cryptographic integrity guarantees.

## 2. Trust model

| Actor / surface | Trusted for | NOT trusted for | Caught by |
|---|---|---|---|
| Layer-1 blob backend | holding bytes under a key | content, integrity, provenance, size honesty | Layer-2 re-verify on read + size cap |
| The customer (a DID) | signing their own manifest | byte counts; owning another DID; a manifest's byte total | provider-measured receipts; owner authz; signed+bound preimage |
| The provider | signing receipts (own-side measurement) | the rent base (the customer's manifest is authoritative) | customer recomputes rent from their own signed doc |
| The network / any caller | delivering requests | identity, authorization, honesty of any field | signatures, content addressing, boundary validation |
| plc.directory / DNS | resolving non-admin DIDs | resolving admin DIDs; being available/untampered | pinned admin keys + fail-closed TTL cache (`ciss-resolve`; the admin-pin file is provisioned-but-empty, DEPLOYMENT §2 TODO) |

The two load-bearing ideas: **meter the boundary, not the machine** (a blind
backend can't forge a bill or slip a bad blob past Layer 2), and **provenance
comes from the parties' keys, never from stored state**.

## 3. Layered architecture (why the split is a security control)

```
  HTTP boundary  ── Layer 2: content-address, re-verify, meter, authorize, sign
  S3 · atproto      (the trust boundary; server.rs · pds_api.rs · manifest.rs · ciss-auth)
        │
        ▼
  BlobStore trait ── Layer 1: dumb bytes-under-a-key (blobstore.rs)
                     never meters · never verifies content · holds no provenance · not trusted
```

**Invariant L1.** Layer 1 is untrusted. A compromised or buggy backend cannot
forge a bill (metering is Layer 2 + keys) or return a blob the caller accepts
(Layer 2 re-verifies the content address on read). Layer 1 *does* enforce
resource safety (size cap, non-regular refusal) because that is the only place a
read can be bounded before allocation.

## 4. Identity & authentication

**Design.** An actor is a keypair; its identifier is a pure function of its
public key. There are two identity spaces, kept distinct by type:

- `id:<64-hex>` — `"id:" ++ SHA-256(pubkey)` (full digest, finding I7). This
  codebase's native space; needs no external resolution (the DID *is* the key
  hash).
- `did:plc` / `did:web` — atproto identities resolved from an external document.
  **Built** (Model R: service-auth JWT verification + DID resolution, ADR 0001 §3
  amended / §5; `docs/notes/atproto-integration-model.md`). CISS is a resource
  server: it verifies a bsky-delegated service-auth JWT signed by the caller's repo
  key, and issues nothing.

**Invariant A1 — no unauthenticated identity assertion.** A caller may only act
as a DID it can prove it holds the key for. Enforced by `ciss-auth::verify_session`:
the caller presents its pubkey + a signature over `ciss-session/v1/<did>`;
authentication requires the key to derive the claimed DID, be canonically encoded,
be non-weak, and strictly verify the signature. Merely *naming* a DID authenticates
as nobody (`Principal::Anonymous`).

**Invariant A2 — authentication is non-rejecting; authorization decides.** The
auth layer only produces a `Principal` (`Anonymous | Authenticated(did)`); it
never grants access by the mere presence of a credential. The allow/deny decision
lives at the `dispatch` boundary (§5). This is the anti-pattern the audit's A2
finding was about (a "401 that authenticates any string").

**Invariant A3 — a service-auth JWT is verified against the resolved DID key, and
the verification curve comes from the key, never the token.** `iss` is resolved
to its `did:key` (secp256k1/P-256), and `ciss_auth::verify_service_auth_jwt` checks
the signature under that key with the curve the key declares — so a forged
`alg` (`none`/`HS256`) cannot downgrade the check. The signature is verified
**before** any claim is trusted. A token that merely *names* a victim `iss` but is
signed by another key fails (`SignatureInvalid`) — A2 on the `did:` space.

**Invariant A4 — request binding: `aud`, `lxm`, `exp`.** A verified token must name
this service (`aud` == `CISS_SERVICE_DID`), be bound to the called method
(`lxm` == the XRPC), and be unexpired. A method-less token is refused (it would be
replayable across methods). This bounds a stolen bearer to one service, one method,
~60s.

**Invariant A5 — canonical signatures only.** ECDSA signatures must be low-S
(high-S is rejected as malleable) and fixed-length; ported from `rsky-crypto`.

**Invariant A6 — `jti` replay defense.** A token carrying a `jti` is single-use
within its validity window (`ReplayGuard`, a bounded seen-set pruned by `exp`).

**Invariant A7 — resolution fails closed, admins are pinned.** DID resolution is
async, hard-timeout-bounded, and TTL-cached; any failure (timeout, transport,
unknown DID, malformed/wrong-subject document) is a **rejection**, never a
fall-through to an unverified key. A pinned admin-DID set is resolved **locally**
and never via the network (even under cache force-refresh), so a poisoned or
unreachable `plc.directory`/DNS can neither rotate an admin key nor lock admins out
(break-glass, ADR 0001 §5). A present-but-invalid credential yields `Anonymous`
(→ dispatch 401), never the DID it named.

**Known interim limitations (by design, tracked):** the `id:` session signature is
not nonce-bound (replay-limited); `did:plc` signed-oplog verification (so a poisoned
directory cannot forge current key state) is a tracked follow-on; DPoP access-token
(Model M2) auth is not built (not needed for the resource-server path).

## 5. Authorization (namespace mode bits)

**Design.** Access control is per **namespace** (a repo / data-structure), Unix-
mode-shaped, evaluated at the single `dispatch` choke point.

**Invariant Z1 — the default is PDS-compat.** Object/blob reads, `listBlobs`, and
the (self-signed) manifest are **world-readable**. Public reads are the contract,
not a vulnerability.

**Invariant Z2 — writes and the meter are owner-only.** An object write or a
meter read requires an authenticated principal whose DID owns the namespace:
anonymous → 401, authenticated-but-not-owner → 403 (`require_owner` at dispatch).
The provider therefore never signs a receipt naming a DID that did not consent.

**Invariant Z3 — the manifest is self-authorizing.** A manifest write proves owner
key-possession via the manifest signature + `derive_id(key) == did`, independent
of the session layer.

**Design-failure watch:** v0 has only the flat default (world read / owner
write). Gated reads for the history-convergence tier (`read: grantees` + signed
grants) are specified but **not built** — content that must not be public has no
enforcement yet. That is a *known design gap*, not a bug.

## 6. Content integrity

**Invariant C1 — the server, not the client, names content.** An object's address
is `SHA-256(bytes)` computed at the boundary; a client-supplied key is narration.

**Invariant C2 — tamper-at-rest is caught on read.** Every read re-computes the
fingerprint and refuses bytes that no longer match the address (Layer-2 check,
independent of the untrusted backend). The mismatch detail is logged, never
returned (finding I4).

## 7. Billing integrity (the core guarantee)

**Design.** Neither party can quietly cheat the bill:

- **Rent** (bytes-at-rest × days) is a pure function of the **customer's own
  signed manifest**, recomputable by the customer without trusting the provider.
- **Postage** (bytes transferred) is a **provider-signed receipt** per byte-
  crossing, appended to a hash-linked per-DID ledger.

**Invariant B1 — the manifest binds everything it claims.** The signature is over
a versioned, domain-separated preimage
`ciss/v1/manifest:signer:seq:leaf_count:total_bytes:root` (findings I1, I11). On
verify, `total_bytes` and `root` are re-derived from the leaves and must match, so
neither the byte total nor the leaf set can be altered after signing.

**Invariant B2 — the Merkle root is unambiguous.** An odd child is tagged
distinctly from a pair (`node1:` vs `node:`) and duplicate cids are rejected, so
no two leaf sets share a root (finding I2, CVE-2012-2459). Leaves are validated
(64-hex cid, bounded size) and the wire form denies unknown fields (I12).

**Invariant B3 — no rollback.** A stored manifest is replaced only by one with a
strictly greater `seq`; a replayed older manifest is refused (finding I5).

**Invariant B4 — receipts are tamper-evident and per-transfer.** A receipt signs
its own content (not a ledger position), so altering a byte count breaks the
signature; postage is charged per transfer even when bytes dedup at rest.

**Invariant B5 — the ledger cache cannot drift.** The O(1) per-DID totals cache is
updated atomically with each receipt and backfills from the ledger, so it always
equals a full scan (finding V3). *Audit hook: the cache is a derived value; if it
ever disagrees with a ledger scan, that is a bug.*

## 8. Cryptographic posture

- **Primitives:** Ed25519 signatures, SHA-256 fingerprints. Deterministic key
  derivation from a seed + role label.
- **Invariant K1 — strict verification.** `verify_strict` everywhere (rejects
  signature malleability / small-order R); `public_key_from_hex` rejects non-
  canonical encodings and small-order/weak keys (finding I6).
- **Invariant K2 — domain separation.** Every signed message carries a versioned
  type tag (`ciss/v1/manifest`, `ciss-session/v1/`, seal/rotate tags), so a
  signature for one record type cannot be replayed as another (finding I11).
- **Invariant K3 — full-width identity.** DIDs keep the full 256-bit key digest;
  no truncation (finding I7).
- **Invariant K4 — secret hygiene.** Signing keys live in `Zeroize`/`ZeroizeOnDrop`
  wrappers, `Debug` is not derived, and only the *public* provider id is ever
  logged.

## 9. Signing-key lifecycle (provider key at rest)

**Invariant S1 — the private key is never in the canonical store or a backup.**
The provider signing seed is supplied by the unit at start (a systemd credential,
or `CISS_PROVIDER_SEED`), never written to `meter.sqlite`, so it never reaches the
off-box (R2) backup (finding I8). Under systemd with no secret wired the process
**fails closed** rather than run a throwaway identity.

**Invariant S2 — history survives key loss.** The provider **public** key is
persisted to the store as a durable, non-secret verification anchor, so every
historical receipt stays verifiable even if the private key is rotated or lost.

Runtime protection layers: encrypted at rest by `systemd-creds`; decrypted into
`$CREDENTIALS_DIRECTORY` on tmpfs (0400, service-user only); zeroized in memory;
inside the hardened sandbox (§11).

## 10. Availability & resource safety

- **Invariant V1 — bounded per-request allocation.** A read is size-capped and
  refuses non-regular nodes (a FIFO/device that would block forever) — a tiny
  request cannot drive an unbounded allocation or a hang (findings V1, V2).
- **Invariant V2 — no blocking on the async runtime.** All fs/SQLite work runs on
  `spawn_blocking`, so handler I/O never parks a tokio worker; `/healthz` stays
  responsive under load.
- **Invariant V3 — bounded concurrency + timeouts.** A global in-flight cap bounds
  aggregate memory and a request timeout drops stuck requests (finding V4);
  `/healthz` is exempt so the liveness probe is never starved (ADR 0002).
- **Invariant V4 — bounded distinct storage (finding V5).** Distinct bytes at rest
  are bounded by an always-enforced whole-store ceiling (`CISS_MAX_STORE_BYTES`)
  and, when configured, an optional per-DID cap (`CISS_MAX_DID_BYTES`; absent ⇒
  DIDs fill opportunistically). A *new* store that would exceed a limit is refused
  before writing with `507`; a **dedup write consumes no quota** and is always
  allowed. Per-DID accounting is always tracked (for visibility) even when caps
  are off. *Audit hook: the global usage is `SUM` of the per-DID counters — if a
  gate ever admits a write past the ceiling other than by bounded concurrent
  overshoot, that is a bug.*
- **Visibility.** Usage is exposed as a stable read surface — the SQLite
  `did_usage` view (queryable read-only while the service runs) — with `ciss usage
  [--did <did>]` as the first consumer (store ceiling as % of partition; per-DID
  on-disk + cumulative-transferred bytes).
- **Ops backstop (tracked):** a *global disk ceiling* on `/var/lib/ciss`
  (filesystem quota / disk alert) still complements the app-level store ceiling —
  an ops item, not app code.

## 11. Boundary input handling

- **Invariant I1 — identifiers are validated before use.** Every `did`/content
  address is parsed to a typed newtype (charset/length/emptiness constrained)
  before it reaches a filesystem path, a SQL bind, or a log line — closing
  traversal, log-forging, and identity-confusion (findings A3, I3, I10).
- **Invariant I2 — untrusted values are escaped in logs.** Attacker-controlled
  strings are logged with `Debug` (escaped), never raw — no journald log forging.
- **Invariant I3 — errors don't leak internal state.** 5xx bodies are a fixed
  public string (the detail is logged); 4xx describe only the client's own request
  (finding I4). Served blobs carry `nosniff` + `attachment` + a strict CSP, and an
  uploaded media type is validated before it is echoed (findings I9, I13).

## 12. Deployment posture

- Binds **loopback only** (`127.0.0.1:<port>`); the only public path is Caddy
  (`443 → 127.0.0.1`), and nftables opens only 22/80/443. Consequence: the app is
  IP-blind behind the proxy (see ADR 0002 for `/healthz` edge-gating).
- Runs as a **hardened, cgroup-governed systemd tenant** (`NoNewPrivileges`,
  `ProtectSystem=strict`, `MemoryDenyWriteExecute`, empty `CapabilityBoundingSet`,
  `SystemCallFilter`, memory/CPU/task limits). `systemd-analyze security ≈ 1.5`.
- **Release profile:** `overflow-checks = true` — metering arithmetic panics
  loudly rather than silently wrapping a bill.

## 13. The invariant checklist (for a fast audit pass)

| # | Invariant | Enforced at |
|---|---|---|
| A1 | act only as a key-proven DID | `ciss-auth::verify_session` |
| A2 | auth never grants; authz at dispatch | `server::authorize` / `dispatch` |
| A3 | JWT verified vs resolved key; curve from key, not `alg` | `ciss-auth::verify_service_auth_jwt` |
| A4 | request binding: `aud` + `lxm` + `exp` | `verify_service_auth_jwt` |
| A5 | canonical low-S signatures only | `ciss-auth::did_key` (ported rsky-crypto) |
| A6 | `jti` single-use in its window | `ciss-auth::ReplayGuard` |
| A7 | resolution fails closed; admins pinned local | `ciss-resolve` (`Pinned`/`Caching`/`Timeout`) |
| Z1 | reads are world-readable (PDS-compat) | `authorize` (read ops → Ok) |
| Z2 | writes + meter are owner-only | `require_owner` |
| Z3 | manifest self-authorizes | `op_put_manifest` |
| C1 | server names content by hash | `op_put_object` |
| C2 | tamper-at-rest caught on read | `op_get_object` |
| B1 | manifest binds total_bytes + root | `Manifest::verify` / `signing_preimage` |
| B2 | unambiguous Merkle + no dup cids | `merkle_root` / `has_duplicate_cids` |
| B3 | no manifest rollback | `op_put_manifest` (seq) |
| B4/B5 | receipts tamper-evident; cache = ledger | `receipts` / `persist::running_totals` |
| K1–K4 | strict verify, domain sep, full DID, zeroize | `crypto` / `identity` / `manifest` |
| S1/S2 | private key off-store; pubkey durable | `with_provider_from_secret` |
| V1–V3 | bounded read/concurrency/timeout; no blocking | `blobstore` / `server::router` / `dispatch_blocking` |
| V4 | distinct storage bounded by the store ceiling; dedup free | `op_put_object` / `persist::store_usage` |
| I1–I3 | validated ids, escaped logs, no-leak errors | `identifiers` / handlers / `ServerError` |

## 14. Standing design gaps (not bugs)

1. **Gated-read namespaces** (Z-tier beyond the flat default) — specified,
   unbuilt. Content that must not be public has no enforcement yet. (Authentication
   for both identity spaces is built; this is the *authorization*-layer gap.)
2. **atproto identity residuals** — the `did:plc`/`did:web` service-auth path is
   built (§4, A3–A7). Remaining follow-ons: `did:plc` signed-oplog verification (so
   a poisoned directory cannot forge current key state), DPoP access tokens
   (Model M2), and populating the admin-pin break-glass file. The `id:` session is
   still nonce-unbound (replay-limited).
3. **Global disk ceiling (ops backstop)** — the app-level store ceiling (V4) is
   enforced, but a *box-level* disk quota/alert on `/var/lib/ciss` still
   complements it. An ops item, not app code. (The per-DID quota gap from V5 is
   now closed by invariant V4.)
4. **Provider-key at-rest hardening on the box** — the code sources the key from a
   secret and the croft-stack unit wires the systemd credential; the one-time
   on-box `.cred` provisioning is the last step that completes S1 end-to-end.

Each gap is a place where "the code is correct per this document, but this
document's guarantee is incomplete" — i.e. a design item, tracked in the plan and
ADRs, not a code bug.
