# PDS capability gap — what CISS would need to *be* a PDS

- **Date:** 2026-08-04 · **walked out 2026-08-11** (statuses refreshed, missing
  rows added from the TypeScript reference PDS, OAuth row split AS/RS)
- **Status:** Inventory only — a **parked, separate effort**. Under the chosen
  integration model (`atproto-integration-model.md`), CISS needs almost none of this.
- **Purpose:** so "make CISS a standalone PDS" is scoped and understood, not
  accidentally half-built while adding service-auth verification.
- **Companion:** `pds-feature-audit.md` (2026-08-11) — the endpoint-by-endpoint
  inventory behind this capability-level view: every reference-PDS operation
  with CISS's status, and every CISS operation with the reference PDS's.

---

## Framing

CISS is a **metered storage resource provider**, not a PDS. It **verifies**
bsky-delegated, DID-signed authorization; it **issues** nothing and **holds** no
session (see the integration model + ADR 0001). This inventory exists to answer a
standing question — "what does a full bsky/blacksky PDS have that we don't?" — and
to make clear that becoming a PDS is a large, distinct project, deliberately *not*
in scope now.

Grounded in two surfaces: `rsky-pds` (the atproto Rust PDS: `apis/com/atproto/
{server,identity,repo,sync,admin,moderation}` + the `oauth/` authorization
server), and — per the 2026-08-11 walk-out — the TypeScript reference PDS
(`bluesky-social/atproto` `packages/pds/src`: `account-manager`, `actor-store`,
`api`, `did-cache`, `handle`, `image`, `mailer`, `read-after-write`, `repo`,
`sequencer`, `auth-routes.ts`, `pipethrough.ts`, `disk-blobstore.ts`). The
original inventory, grounded in rsky-pds alone, missed several reference-PDS
subsystems — added below the original rows.

## The gap

| PDS capability | What it is | CISS today | Needed under "piggyback bsky"? |
|---|---|---|---|
| **OAuth authorization server** | `/oauth/{authorize,token,par,jwks}`, `.well-known/oauth-authorization-server`, sign-in / consent / select / accept / reject UI | none | **No** — bsky is the AS |
| **OAuth resource-server surface** | `/.well-known/oauth-protected-resource` (RFC 9728: `authorization_servers` pointer) + verifying DPoP-bound OAuth access tokens on XRPC. **Every reference PDS serves this, even behind an entryway** (`packages/pds/src/auth-routes.ts`) — being "not the AS" does not remove the RS obligations | none — CISS accepts service-auth JWTs and `id:` sessions only; no RS metadata, no OAuth-token verification | **Not yet** — but this is the real cost of "no OAuth": atproto-OAuth clients cannot address CISS directly. Needed the day a third-party atproto app (not the broker) should talk to CISS with a user's OAuth grant |
| **Account lifecycle** | createAccount, createSession (app-pw), refresh/deleteSession, app-password CRUD, email confirm / reset | none | **No** — bsky owns accounts |
| **Identity issuance** | did:plc genesis, signPlcOperation / submitPlcOperation, rotation keys, updateHandle, resolveHandle | consumes DID resolution only (`ciss-resolve`, TTL cache) — and **serves** its own `did:web` document | **No** — bsky issues identity |
| **Repo (MST / records)** | applyWrites, {create,put,delete,get,list}Record, describeRepo, importRepo, getRepo (CAR), commit signing | none (object store, not a record repo) | **No** — bsky holds the repo |
| **Sync / firehose** | `com.atproto.sync.subscribeRepos` (sequencer + event stream), getRepo, getBlocks, getLatestCommit, listRepos, relay crawl requests | none (off replication by design) | **No** now; needed for federation later |
| **Moderation / labels** | createReport, label emission, admin takedowns | none | **No** now |
| **`getServiceAuth` issuance** | mint the delegated JWT from a session | **verifies** (shipped: `ciss-auth::service_jwt` + replay guard, `ciss-resolve` DID resolution), does not issue | **No** — bsky issues, CISS verifies |
| **Blob lifecycle** | uploadBlob / getBlob / listBlobs **+** record-tied refcount + GC of unreferenced blobs, mime/size policy | **has the transfer surface** (mounted at the XRPC paths) + gated reads (Z4–Z8) on top | partial — lacks record-tied GC (CISS's analogue is manifest-driven erasure + rent, deliberate) |
| **Blob quarantine** | `DiskBlobStore`'s third tree: move a suspect blob aside (reversible) without deleting it | none — `FsBlobStore` has `blocks/` + `tmp/` only; the nearest tool is erasure (irreversible) | **No** now — becomes relevant with any takedown/moderation obligation |
| **Service proxying (pipethrough)** | the PDS as the user's gateway: forwards XRPC to appviews per the `atproto-proxy` header, with service-auth minted on the fly (`pipethrough.ts`) | none — CISS is a terminal resource server, proxies nothing | **No** — clients reach appviews via their real PDS |
| **Read-after-write** | patch appview responses with the user's own not-yet-indexed writes (`read-after-write/`) | n/a — no appview reads to patch | **No** — repo-coupled |
| **Handle management** | resolveHandle serving, handle validation/reservation (`handle/`, `reservedKeyDir`) | none — CISS deals in DIDs only; handle→DID is the resolver's input, not served | **No** |
| **Image CDN** | blob-derived thumbnails/transforms (`image/`) | none — blobs are returned byte-exact (integrity model forbids transforms on the metered path) | **No** — an appview/CDN concern; would be a separate unmetered derived-cache surface if ever wanted |
| **Mailer / email flows** | templated account email (confirm, reset, delete) (`mailer/`) | none | **No** — account-lifecycle-coupled |
| **Per-route rate limiting** | reference PDS rate-limits per lexicon method (and per-IP) | global in-flight cap + request timeout + storage ceilings; **no per-DID/per-route request-rate limits** (adjacent seam: E83 per-DID compute observability) | **Partial gap even under the chosen model** — the byte-path is metered but the request path is only globally capped; a hostile client can burn compute inside the global cap |
| **Account migration / activation** | importRepo + blob import, activateAccount / deactivateAccount, checkAccountStatus, describeServer | none — the file-sync engine (`ciss-sync`) is CISS's own portability story, not atproto's | **No** — repo-coupled; CISS blobs migrate with the account's real PDS |

## What CISS has that a vanilla PDS does not

- A **metered byte-path** with **provider-signed receipts** (per-transfer,
  signed), escalating to **bilateral/co-signed receipts** (ADR 0004 line).
- The full **accounting stack** above it: hash-linked ledger, monthly
  balance-forward **statements** (chain + rollup/purge), **rent** as byte-days
  over the customer-signed manifest, audit dial, seal/tombstone, grace.
- **Gated reads** (spec'd invariants Z4–Z8, shipped v0.4.0) — owner-directed
  read authorization a PDS blob surface has no analogue for.
- **Self-assertion dials** (ceiling, period, account-mode, receipt-mode) and
  the assertion surface generally.
- An **S3-compatible** object boundary.
- **Distinct-bytes storage quota** (whole-store ceiling + optional per-DID cap).
- The native **`id:` identity space** (no external resolution).
- A **file-sync engine** (`ciss-sync`: content-defined chunking, canonical
  DAG-CBOR fs-manifest) and an **iroh** p2p/relay transport (`ciss-iroh`).
- The **cooperative multi-tenant provider** model.

CISS is *ahead* on metering/billing/read-authz, *behind* on everything
identity/repo — which is exactly correct for "storage provider, not PDS."

## Takeaway

To become a standalone PDS is essentially the entire left column: an OAuth AS +
accounts + identity issuance + a real MST repo + firehose. Large and separate.

Under the chosen model, CISS needs **none of it** — the two increments it did
need are now **shipped**:

1. its own `did:web:ciss.croft.ing` service identity (an `aud` anchor) —
   served at `/.well-known/did.json`, and
2. service-auth JWT verification (`ciss-auth` + `ciss-resolve`),

plus the broker's `getServiceAuth` relay (croft-stack). The rest stays bsky's
job, openly.

Two rows are worth watching rather than parking, because they are gaps *under
the chosen model*, not just under "be a PDS":

- **OAuth resource-server surface.** "No OAuth" was scoped against the AS role;
  the RS half (`/.well-known/oauth-protected-resource` + DPoP-bound token
  verification) is what would let third-party atproto apps hold a user's grant
  to CISS without going through the broker. Not needed while the broker is the
  only client pathway; it is the first thing to build if that assumption changes.
- **Per-route/per-DID rate limiting.** The byte-path is metered but the request
  path is only globally capped (timeout + in-flight limit); compute per DID is
  neither observed (seam E83) nor limited. This is a hardening gap independent
  of any PDS ambition.
