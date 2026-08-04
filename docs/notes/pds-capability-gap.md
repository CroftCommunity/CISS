# PDS capability gap — what CISS would need to *be* a PDS

- **Date:** 2026-08-04
- **Status:** Inventory only — a **parked, separate effort**. Under the chosen
  integration model (`atproto-integration-model.md`), CISS needs almost none of this.
- **Purpose:** so "make CISS a standalone PDS" is scoped and understood, not
  accidentally half-built while adding service-auth verification.

---

## Framing

CISS is a **metered storage resource provider**, not a PDS. It **verifies**
bsky-delegated, DID-signed authorization; it **issues** nothing and **holds** no
session (see the integration model + ADR 0001). This inventory exists to answer a
standing question — "what does a full bsky/blacksky PDS have that we don't?" — and
to make clear that becoming a PDS is a large, distinct project, deliberately *not*
in scope now.

Grounded in the `rsky-pds` surface (the atproto Rust PDS): `apis/com/atproto/{server,
identity,repo,sync,admin,moderation}` + the `oauth/` authorization server.

## The gap

| PDS capability | What it is | CISS today | Needed under "piggyback bsky"? |
|---|---|---|---|
| **OAuth authorization server** | `/oauth/{authorize,token,par,jwks}`, `.well-known/oauth-*`, sign-in / consent / select / accept / reject UI | none | **No** — bsky is the AS |
| **Account lifecycle** | createAccount, createSession (app-pw), refresh/deleteSession, app-password CRUD, email confirm / reset | none | **No** — bsky owns accounts |
| **Identity issuance** | did:plc genesis, signPlcOperation / submitPlcOperation, rotation keys, updateHandle, resolveHandle | consumes DID resolution only | **No** — bsky issues identity |
| **Repo (MST / records)** | applyWrites, {create,put,delete,get,list}Record, describeRepo, importRepo, getRepo (CAR), commit signing | none (object store, not a record repo) | **No** — bsky holds the repo |
| **Sync / firehose** | `com.atproto.sync.subscribeRepos`, getRepo, getBlocks, getLatestCommit, listRepos, relay crawl requests | none (off replication by design) | **No** now; needed for federation later |
| **Moderation / labels** | createReport, label emission, admin takedowns | none | **No** now |
| **`getServiceAuth` issuance** | mint the delegated JWT from a session | **verifies**, does not issue | **No** — bsky issues, CISS verifies |
| **Blob lifecycle** | uploadBlob / getBlob / listBlobs **+** record-tied refcount + GC of unreferenced blobs, mime/size policy | **has the transfer surface** | partial — lacks record-tied GC |

## What CISS has that a vanilla PDS does not

- A **metered byte-path** with **provider-signed receipts** (per-transfer, signed).
- An **S3-compatible** object boundary.
- **Distinct-bytes storage quota** (whole-store ceiling + optional per-DID cap).
- The native **`id:` identity space** (no external resolution).
- The **cooperative multi-tenant provider** model.

CISS is *ahead* on metering/billing, *behind* on everything identity/repo — which is
exactly correct for "storage provider, not PDS."

## Takeaway

To become a standalone PDS is essentially the entire left column: an OAuth AS +
accounts + identity issuance + a real MST repo + firehose. Large and separate.

Under the chosen model, CISS needs **none of it** — only:

1. its own `did:web:ciss.croft.ing` service identity (an `aud` anchor), and
2. service-auth JWT verification (the atproto-identity increment),

plus the broker's `getServiceAuth` relay (croft-stack). The rest stays bsky's job,
openly.
