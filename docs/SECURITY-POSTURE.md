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

**Gated reads (built).** The flat default (Z1) is now overridable per target by an
owner-authorized **read policy**. Design + contract: `docs/spec/gated-reads.md`;
grain decision + record shape: ADR 0001 §2.

**Invariant Z4 — reads are authorized at the dispatch choke point.** A read op
(`GetObject`) resolves the target's policy (`Store::resolve_policy`) and checks
membership (`ResolvedPolicy::allows`) in `dispatch`, after the pure `authorize`.
`world` (the Z1 default, and any target with no policy row) is allowed on a fast
path. The check is **membership-only** — the policy signature is verified once at
write, and the stored row is CISS's own SQLite, so there is no per-read crypto.

**Invariant Z5 — denial is oracle-free.** A denied read returns **404**
(`NotFound`), indistinguishable from "no such object"; `listBlobs` **omits** every
cid the caller may not read (neither listed nor counted). A gate never returns 403
or a distinguishable status that would confirm a hidden object exists.

**Invariant Z6 — a policy is an owner-authorized, monotonic record.** A
`PolicyRecord` binds its target (namespace or `(did,cid)` object, cid included),
`read_class`, reader set, and a monotonic `seq`, under one of two forms: **Model A
(`OwnerSigned`)** — an `id:` owner's ed25519 signature over `ciss/v1/policy:…`,
valid only for an `id:` target the signer key derives; **Model C
(`ProviderAttested`)** — CISS's signature over `ciss/v1/policy-attest:…` after it
verified the owning `did:`'s service-auth JWT (`lxm = ing.croft.ciss.setPolicy`).
A record is verified (`verify_policy`) before it is stored; a forged/wrong-signer/
wrong-target/malformed record is refused and access is unchanged.

**Invariant Z7 — anti-rollback.** A policy write applies only if its `seq`
strictly exceeds the stored policy's `seq` for that target — enforced by an
explicit pre-write seq check in `op_put_policy` (a stale/equal `seq` returns a
distinct `409` before the signature is checked) and again **in-transaction** at
`Store::save_policy` (a conditional upsert, defence against a racing lower-seq
write). A replayed lower `seq` cannot un-revoke a grant.

**Invariant Z8 — the attestation key is separate from the billing key.** Model C
attestations are signed with a **dedicated** `policy-attest` key
(`derive_keypair(seed, "policy-attest")`), disjoint from the receipt/billing key
by both key and signing domain, so metering crypto and authorization crypto never
overlap.

**Invariant Z9 — usage inspection (`du`) is self-only over the wire (ADR 0003).**
`GET /{did}/du` returns per-object **sizes** (never content) for `{did}`, and only
when the authenticated caller **owns** `{did}`. A **cross-DID** query is refused
`403` **for everyone, including admins** — no one reads another user's storage
over the wire; cross-DID / store-wide inspection is an on-box operator action
(`ciss usage`). This does **not** weaken Z5: there is no admin-sees-others'-sizes
exception. The optional `CISS_ADMIN_ONLY_DU` flag only ever *narrows* access —
when set, only an admin-pin DID (ADR 0001 §5) may run `du`, still self-only. The
`403` does not vary by whether `{did}` exists (no oracle).

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
neither the byte total nor the leaf set can be altered after signing. When the
optional M3 frontier `heads` map (`device_id → cid(DeviceHead)`) is present, a
canonical digest of it is appended to the preimage (`…:heads=<sha256>`), so a
head cannot be altered, injected, or stripped after signing; with no `heads` the
preimage is byte-identical to the pre-frontier era, so legacy manifests keep
verifying. The server never interprets a head — it validates the owner signature
and seq-monotonicity (B3) and stores bytes; the fold stays client-side.

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

**Invariant B6 — billing state never gates self-egress (exit-exempt).** No
billing condition — balance, spending ceiling, throttle, dial mode — may ever
block a customer's self-directed egress of their own manifest and blobs ("they
can never keep your furniture"; discovery E89). **Enforced in code since D3**:
the server's spend-ceiling and drawdown gates live only in the *write* paths
(`op_put_object`, `op_put_manifest`) — no read op consults billing state, and
the flow tests pin it (egress serves past an exhausted ceiling and in
drawdown; the postage it accrues still bills — served, metered, never
refused, so a statement may exceed the ceiling via exempt egress by design).
The client cost twin honors the same rule from its side — its ceiling defers
*uploads* whole and is structurally absent from the restore/hydrate paths,
guarded by a regression test that restores under an exhausted ceiling.

*Design principle behind B6 (ruled 2026-08-11): CISS makes no forward price
commitments — a put-time promise about future egress or rent rates is a
liability the provider cannot underwrite, so it is ruled out entirely. The
only guarantee attempted is the exit right: prices float freely and visibly,
and the customer's protection is that they can always close the books
(drawdown) and take their data out. Drawdown egress is always METERED at the
going rate; whether it is billed in full, prorated, or at a special rate is
a human utility judgment made at statement time — never an automatic
exemption, because automatic free exit invites the abuse of freezing a
large account to use it as an unmetered fileshare. The system's job is
scaffolding for that judgment: egress that occurs while the account is in
drawdown is tagged as such on its receipts, so a statement can separate
"drawdown drain" from ordinary traffic and a human can adjust it. (The ADR
0004 reserve shape — unmetered drawdown behind a one-way commitment —
remains in reserve if judgment-at-statement-time proves insufficient.)*

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
| Z1 | reads are world-readable **by default** (PDS-compat) | `authorize` (read ops → Ok) |
| Z2 | writes + meter are owner-only | `require_owner` |
| Z3 | manifest self-authorizes | `op_put_manifest` |
| Z4 | reads authorized at dispatch (membership-only) | `authorize_read` / `Store::resolve_policy` |
| Z5 | oracle-free denial (404 + `listBlobs` omission) | `authorize_read` (→ `NotFound`) / `op_list_blobs` |
| Z6 | owner-authorized policy record (Model A / C) | `policy::verify_policy` / `op_put_policy` |
| Z7 | policy anti-rollback (monotonic seq) | `op_put_policy` / `Store::save_policy` |
| Z8 | attestation key ≠ billing key | `Provider` `derive_keypair(seed,"policy-attest")` / `attest_verifying_key()` |
| C1 | server names content by hash | `op_put_object` |
| C2 | tamper-at-rest caught on read | `op_get_object` |
| B1 | manifest binds total_bytes + root | `Manifest::verify` / `signing_preimage` |
| B2 | unambiguous Merkle + no dup cids | `merkle_root` / `has_duplicate_cids` |
| B3 | no manifest rollback | `op_put_manifest` (seq) |
| B4/B5 | receipts tamper-evident; cache = ledger | `receipts` / `persist::running_totals` |
| B6 | billing state never gates self-egress (exit-exempt) | server: spend/drawdown gates in `op_put_object`/`op_put_manifest` only — no read op consults billing state; client twin: `ciss-sync::backup::push_tree` (ceiling on push only) |
| D1–D4 | assertions bound whole; monotonic seq (typed 409); Model A/C only; every accept acknowledged | `assertion.rs` / `op_put_assertion` / `save_assertion` |
| D5/D6 | dials fail closed toward the customer; provider bounds supersede (`min()`) | `persist::{at_rest_dial,spend_dial,account_mode,receipt_mode_dial}` / `provider_at_rest_bound` |
| K1–K4 | strict verify, domain sep, full DID, zeroize | `crypto` / `identity` / `manifest` |
| S1/S2 | private key off-store; pubkey durable | `with_provider_from_secret` |
| V1–V3 | bounded read/concurrency/timeout; no blocking | `blobstore` / `server::router` / `dispatch_blocking` |
| V4 | distinct storage bounded by the store ceiling; dedup free | `op_put_object` / `persist::store_usage` |
| I1–I3 | validated ids, escaped logs, no-leak errors | `identifiers` / handlers / `ServerError` |

## 14. Standing design gaps (not bugs)

1. ~~**Gated-read namespaces** (Z-tier beyond the flat default)~~ — **CLOSED
   2026-08-05.** Built as invariants Z4–Z8 (authorize-at-dispatch, oracle-free
   404 + `listBlobs` omission, owner-authorized monotonic policy record in both
   Model A and Model C, anti-rollback, separate attestation key). Contract:
   `docs/spec/gated-reads.md`; decision: ADR 0001 §2.
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
5. **Co-signed spending ceiling** (E89/E82) — the customer's spend limit is
   enforced client-side only (the M5 twin); the binding version — a
   customer-signed, server-countersigned dial under an I5-style seq, enforced
   before serving billable transfers against bilateral receipts, with rent
   reserved rather than gated and owner-egress carved out (B6) — is designed
   in **ADR 0004** (Proposed) and not yet built. Until then,
   `ReceiptMode::Bilateral` stays `501` and no billing-conditioned serve path
   exists.

Each gap is a place where "the code is correct per this document, but this
document's guarantee is incomplete" — i.e. a design item, tracked in the plan and
ADRs, not a code bug.

## 15. Self-assertion integrity (the D-series — the dials substrate)

**Design.** Every customer setting is a **self-assertion**: the customer signs
their own requirement; the server verifies and obeys it. There is no operator
write path to any customer setting — nothing for support staff to type, secure,
or abuse. One substrate (`src/assertion.rs`) serves every kind: the read policy,
the ceiling dial (at-rest + spend), the period dial, the account-mode dial, the
receipt-mode dial — and the manifest conforms to its refusal discipline.

**Invariant D1 — an assertion is bound whole.** The signature covers a
domain-separated preimage over `(kind, did, subkey, seq, kind-fold(body))` —
`ciss/v1/assertion:<kind>:…` — so no field can change, and a signature for one
kind, target, or seq can never verify as another (both Model A and Model C;
every binding mutation-tested).

**Invariant D2 — seq is strictly monotonic per `(did, kind, subkey)`.** Checked
before the signature with the uniform typed 409 staleness (shared with the
manifest since D1.4), and re-guarded in-transaction at persistence — a
replayed or lower-seq assertion can never roll a customer back.

**Invariant D3 — authorization is Model A or Model C only.** An `OwnerSigned`
record verifies only when the signing key *derives* the target DID; a
`ProviderAttested` record only under the dedicated attestation key after a
verified service-auth JWT. No third path exists.

**Invariant D4 — every accepted assertion is acknowledged.** The server
countersigns the stored record's digest (`ciss/v1/assertion-ack:<kind>`) with
the attestation key — published in `/.well-known/did.json` — and returns the
ack on write and read-back. A customer can *prove* a setting took effect;
success is discernible from failure.

**Invariant D5 — dials fail closed, toward the customer.** An unparseable
stored dial resolves to the customer-protective extreme — at-rest cap 0, spend
cap 0¢, drawdown mode, bilateral receipts — loudly, never silently
permissive. (Reads are never affected: B6.)

**Invariant D6 — provider bounds supersede dials.** A dial asserting past the
provider's effective bound is refused at set with the bound quoted, and
enforcement applies `min(provider, dial)` regardless — neither party's limit
can loosen the other's.
