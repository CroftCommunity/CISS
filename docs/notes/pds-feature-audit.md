# PDS feature audit — CISS vs the reference implementation, endpoint by endpoint

- **Date:** 2026-08-11
- **Status:** point-in-time audit. Companion to `pds-capability-gap.md` (the
  capability-level delta and its takeaways); this doc is the **full operation
  inventory** — every operation the reference PDS serves, with CISS's status,
  and every operation CISS serves, with the reference PDS's status.
- **Grounding:** the TypeScript reference PDS, `bluesky-social/atproto` `main`
  as of 2026-08-11 — the endpoint list is the file tree of
  `packages/pds/src/api/` (one file per XRPC method), plus the non-XRPC routes
  in `auth-routes.ts` (OAuth), `pipethrough.ts` (service proxying), and the
  well-known handlers. CISS's list is the router in `src/server.rs` plus
  `src/pds_api.rs`.

Legend: ✔ implemented · ◐ partial / different shape · ✘ absent ·
**n/a** absent *by design* under the chosen model ("storage provider, not
PDS" — `pds-capability-gap.md`), where building it would be a scope change,
not a fix.

---

## 1. What the reference PDS can do (and whether CISS can)

### 1.1 `com.atproto.server.*` — accounts, sessions, delegation

| Operation | CISS | Note |
|---|---|---|
| createAccount | **n/a** | bsky owns accounts; CISS principals arrive by DID or `id:` key |
| createSession / getSession / refreshSession / deleteSession | **n/a** | CISS holds no sessions in this sense; `id:` challenge-response is per-request proof, not a stored session |
| createAppPassword / listAppPasswords / revokeAppPassword | **n/a** | app-passwords are an AS concern |
| activateAccount / deactivateAccount / checkAccountStatus | **n/a** | account lifecycle is bsky's |
| deleteAccount / requestAccountDelete | ✘ | no account-erasure ceremony; nearest CISS concepts are manifest-driven erasure + the seal **tombstone** (key destruction). A cooperative member-exit story will eventually need a deliberate analogue |
| confirmEmail / requestEmailConfirmation / requestEmailUpdate / updateEmail | **n/a** | no email anywhere in CISS |
| requestPasswordReset / resetPassword | **n/a** | no passwords |
| createInviteCode / createInviteCodes / getAccountInviteCodes | **n/a** | invite-gating is a signup concern; the cooperative's membership gate lives outside CISS |
| describeServer | ◐ | the identity/crypto half exists: `did.json` (`src/server.rs:846`) publishes both provider keys with roles (`#assertion-ack`, `#receipts`) and a typed `CissItemStorage` service entry, with a `SEAM:` for more. The **operational** half (auth modes, limits, pricing, contact) is served nowhere — see `pds-adoptable-features.md` §1 |
| getServiceAuth | ◐ | **verifies** service-auth JWTs (`ciss-auth::service_jwt` + replay guard); issues nothing — deliberate resource-server stance |
| reserveSigningKey | **n/a** | key issuance is identity work |

### 1.2 `com.atproto.identity.*` — handles and DID operations

| Operation | CISS | Note |
|---|---|---|
| resolveHandle | ✘ | CISS **consumes** DID resolution (`ciss-resolve`); it serves none. Handle→DID is the caller's problem |
| updateHandle | **n/a** | |
| getRecommendedDidCredentials / requestPlcOperationSignature / signPlcOperation / submitPlcOperation | **n/a** | did:plc issuance/rotation is bsky's |

### 1.3 `com.atproto.repo.*` — records and the blob upload path

| Operation | CISS | Note |
|---|---|---|
| applyWrites / createRecord / putRecord / deleteRecord / getRecord / listRecords / describeRepo | **n/a** | CISS has no record repo — the defining scope line |
| importRepo | **n/a** | repo-coupled migration |
| listMissingBlobs | ✘ | "blobs referenced by records but not uploaded" — needs records to exist. CISS's analogue is manifest-vs-store reconciliation, which the audit machinery (E5) covers differently |
| **uploadBlob** | ✔ | `/xrpc/com.atproto.repo.uploadBlob` — over the metered byte-path: authenticated principal, quota-checked, receipt-signed |

### 1.4 `com.atproto.sync.*` — the read/replication surface

| Operation | CISS | Note |
|---|---|---|
| **getBlob** | ✔ | `/xrpc/com.atproto.sync.getBlob` — plus **gated reads** (Z4–Z8) on top: owner-directed read authorization the reference PDS does not have |
| **listBlobs** | ✔ | `/xrpc/com.atproto.sync.listBlobs` — derived from upload receipts, hidden cids omitted |
| getRepo / getBlocks / getRecord / getLatestCommit / getRepoStatus / listRepos | **n/a** | repo-coupled |
| subscribeRepos (firehose) | **n/a** now | no sequencer, no event stream; named in the gap doc as needed only "for federation later" |
| getCheckout / getHead (deprecated) | **n/a** | deprecated upstream |

### 1.5 `com.atproto.admin.*` + moderation

| Operation | CISS | Note |
|---|---|---|
| getAccountInfo(s) / getSubjectStatus / updateSubjectStatus | ✘ | no admin plane over the wire — **deliberate** (memory: cross-user/admin views stay on the box, `ciss usage`) |
| updateAccountEmail / updateAccountHandle / updateAccountPassword / sendEmail | **n/a** | account-coupled |
| enable/disableAccountInvites / disableInviteCodes / getInviteCodes | **n/a** | invite-coupled |
| deleteAccount (admin) | ✘ | see member-exit note in 1.1 |
| moderation.createReport | ✘ | no reporting inlet; with no takedown machinery (no quarantine tree) there is nothing for a report to trigger yet |
| temp.checkSignupQueue | **n/a** | |

### 1.6 `app.bsky.*` served locally by the PDS

| Operation | CISS | Note |
|---|---|---|
| actor.getPreferences / putPreferences | **n/a** | app preferences are repo/account-coupled; CISS's owner-declared state is the **assertion surface** (dials, policy), a different animal with stronger authorship (owner-signed, seq-monotonic) |
| actor.getProfile(s), feed.getTimeline / getAuthorFeed / getActorLikes / getFeed / getPostThread | **n/a** | read-after-write munging of appview responses — requires the repo + proxying |
| notification.registerPush / unregisterPush | **n/a** | |

### 1.7 Non-XRPC surfaces

| Surface | CISS | Note |
|---|---|---|
| OAuth **authorization server** (`/oauth/*`, `.well-known/oauth-authorization-server`, consent UI) | **n/a** | bsky is the AS — the settled stance |
| OAuth **resource-server metadata** (`/.well-known/oauth-protected-resource`) + DPoP token verification | ✘ | **the real "no OAuth" gap** — every reference PDS serves this even behind an entryway (`auth-routes.ts:31`). Tracked: ROADMAP_TODO **E101** |
| Service proxying / pipethrough (`atproto-proxy` header → appview, service-auth minted per request) | **n/a** | CISS is a terminal resource server |
| `/.well-known/did.json` (did:web) | ✔ | CISS serves its own service identity — the reference PDS does this differently (did:plc for accounts; `atproto-did` for handle verification) |
| Health probe | ✔ | `/healthz`, deliberately outside the data plane's timeout/concurrency gates; reference PDS: `/xrpc/_health` |
| Per-route + per-IP rate limits | ✘ | CISS has a global in-flight cap + request timeout + storage ceilings; no per-DID/per-route request-rate limits. Tracked: ROADMAP_TODO **E102** |
| Blob quarantine (reversible set-aside) | ✘ | `FsBlobStore` has `blocks/` + `tmp/` only; nearest tool is erasure (irreversible) |
| Image CDN (`image/`) | **n/a** | byte-exact returns are an integrity stance |
| Mailer | **n/a** | |

**Score, reference-PDS side:** of the ~60 operations the reference PDS serves,
CISS implements **3** (`uploadBlob`, `getBlob`, `listBlobs` — the entire blob
transfer surface, which is the point), partially matches **1**
(`getServiceAuth`: verify-not-issue), and the rest split into **n/a by design**
(the large majority: accounts, sessions, identity issuance, records, repo sync,
app.bsky) and a short list of **true gaps** worth watching: OAuth-RS metadata
(E101), per-route rate limiting (E102), `describeServer`, blob quarantine,
moderation inlet, and a member-exit/account-deletion ceremony.

---

## 2. What CISS can do (and whether the reference PDS can)

| CISS operation | Reference PDS | Note |
|---|---|---|
| `PUT/GET /{did}/objects/{addr}` — content-addressed object plane, S3-shaped | ◐ | blobs only via record-coupled uploadBlob/getBlob; no standalone addressable object plane |
| **Metered byte-path** — every transfer counted, quota-enforced | ✘ | reference PDS has blob size/mime policy, no metering |
| **Provider-signed receipts** per transfer; hash-linked per-actor ledger | ✘ | no analogue |
| `POST /{did}/receipt/{hash}/countersign` — **bilateral (co-signed) receipts** (ADR 0004 line) | ✘ | no analogue |
| `PUT/GET /{did}/manifest` — customer-signed Merkle manifest: the rent base, seq-monotonic, anti-rollback | ✘ | nearest concept is the repo commit (signed, versioned) — but that binds records, not a storage claim, and carries no billing meaning |
| **Rent** — byte-days over the manifest; monthly balance-forward **statements** (chain + rollup/purge) | ✘ | no billing machinery at all |
| `PUT/GET /{did}/assertion/{kind}[/{subkey}]` — owner-signed dials: ceiling, period, account-mode, receipt-mode, policy, kv.flag | ✘ | actor preferences are unsigned server-held state; assertions are signed, seq-monotonic, provider-acked |
| **Gated reads** (Z4–Z8): owner grants/revokes read access per object to `did:` grantees | ✘ | reference PDS blobs are public-once-referenced (or taken down); no owner-directed read authz |
| `GET /{did}/meter`, `GET /{did}/du` — self-only usage/meter views | ◐ | admin `getAccountInfo` exposes stats to admins; CISS's are **self-only over the wire** by deliberate policy |
| **Spot-check audit + dial** (E5–E6): priced, seeded, deterministic verification with detection math | ✘ | no storage-assurance concept |
| **Seal / tombstone** (E7–E8): pin-a-root cold storage; fail-closed key-destruction ceremony | ✘ | takedown is the only removal concept, and it is not cryptographic |
| **Grace** (E9): co-signed, nets-to-zero waived charges, on the books | ✘ | no billing to forgive |
| Dual identity spaces: `id:` (native, resolution-free) alongside `did:plc`/`did:web` | ✘ | DID-only |
| Layer-2 **re-verify on read** (tamper-at-rest → loud 500, never a served bad blob) | ◐ | reference PDS trusts its blobstore on read; CID verification happens at write |
| Client-side stack riding this surface: `ciss-sync` (CDC chunking, canonical DAG-CBOR fs-manifest), `ciss-iroh` (p2p + relay), cost twin | ✘ | no PDS-side analogue; atproto's portability story is repo-based (importRepo/CAR) |

**Score, CISS side:** the reference PDS can do **none** of CISS's
metering/accounting/read-authz stack — which is CISS's reason to exist. The
one place it half-overlaps (blob transfer) is exactly where CISS chose
lexicon-compatibility, so the shared surface is *identical paths*, not
parallel inventions.

---

## 3. Reading the audit

The two lists barely overlap, and that is the design: CISS implements the
**3-endpoint blob lexicon** an atproto client needs, verifies bsky-delegated
identity, and puts everything else it owns into a plane atproto does not have.
The audit's actionable residue is not "build more PDS" — it is the short
true-gap list in §1: **E101** (OAuth-RS surface, the day non-broker atproto
apps should reach CISS), **E102** (per-DID/route rate limiting, a hardening
gap today), and the smaller items (describeServer, quarantine, moderation
inlet, member-exit ceremony) that become due if/when the cooperative takes on
third-party or adversarial traffic.

Related: object lifecycle (deletion/GC) is already decided and planned
separately — `docs/plans/2026-08-11-object-lifecycle.md` (ROADMAP_TODO E95:
manifest-driven reclamation + owner-declared retention).
