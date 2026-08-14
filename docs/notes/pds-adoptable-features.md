# PDS features CISS could adopt — the in-scope candidates

- **Date:** 2026-08-11
- **Status:** discussion draft — nothing here is committed work. Feeds from
  `pds-feature-audit.md` (the full inventory) and `pds-capability-gap.md`
  (the capability delta): this file is the filtered list of reference-PDS
  features that are **compatible with "storage provider, not PDS"** — each
  would deepen the storage role rather than drift toward being a PDS.
- **Excluded on purpose:** everything the audit marks **n/a by design** —
  OAuth (both the authorization-server role *and*, for now, the
  resource-server surface: parked with its reasoning as ROADMAP_TODO E101),
  accounts/sessions/passwords/email/invites, identity issuance, the record
  repo, app.bsky, service proxying, image CDN, mailer. Adopting any of those
  is a scope change and gets an ADR first, not a row here.

Effort: **S** (a day-ish) · **M** (a phase) · **L** (a plan with milestones).

## The candidates

| # | Feature | PDS analogue | Effort | Already tracked | Recommend |
|---|---|---|---|---|---|
| 1 | `describeServer` — public self-description | `com.atproto.server.describeServer` | S | **E103 — on the build list** (2026-08-11, shape (a) decided) | **yes, early** |
| 2 | getBlob Content-Type echo | `blob.mimeType` stored at upload, echoed on read | S | **E104 — on the build list** (2026-08-11, design settled; the walk-through also surfaced + fixed the `account_mode` verify-compat defect) | **yes, early** |
| 3 | Manifest-vs-store reconciliation report | `com.atproto.repo.listMissingBlobs` (shape only) | S–M | adjacent to E5 audit machinery | yes |
| 4 | Per-DID / per-route rate limiting | per-lexicon + per-IP rate limits | M | **E102** (observability E83 first) | **yes — hardening, not compat** |
| 5 | Blob quarantine (reversible set-aside) | `DiskBlobStore`'s quarantine tree; `takedownRef` | M | audit §1.7 | yes, before any moderation obligation |
| 6 | Moderation/report inlet | `com.atproto.moderation.createReport` | S (inlet) | audit §1.5 | maybe — inlet only |
| 7 | Member-exit ceremony | `deleteAccount` / `requestAccountDelete` (shape only) | M | audit §1.1 note | yes — co-op flavored, not atproto's |
| 8 | Event stream / firehose | `com.atproto.sync.subscribeRepos` | L | gap doc: "federation later" | **park** — listed so parking is a decision |

## Per-candidate detail

### 1. `describeServer` — extend the self-description CISS already serves

CISS **already has** a native self-description surface: `/.well-known/did.json`
(`src/server.rs:846`) publishes both provider public keys with their roles
(`#assertion-ack` — the attestation key, so a customer can verify offline that
an assertion took effect (D2); `#receipts` — the billing key (D4)) and a typed
service entry (`CissItemStorage` + endpoint), and `ciss-ctl` already consumes
it (`client.rs` reads the advertised service DID). The handler carries a
tracked `SEAM:` for publishing more through it.

What is genuinely missing is the **operational** half: auth modes accepted
(`id:` session, service-auth JWT + `aud`), the blob lexicon implemented,
ceilings and body limits, pricing posture, contact. So this candidate is
*extend, not create* — and the real open question is **where the operational
half lives**, given DID-document hygiene (a DID doc is an identity document;
stuffing limits/pricing into it is nonstandard):

- **(a)** a second document (e.g. the existing `service` entry gains a
  pointer to it), keeping `did.json` pure identity+keys — the shape the DID
  spec expects;
- **(b)** the atproto path `/xrpc/com.atproto.server.describeServer`,
  lexicon-shaped, so generic atproto tooling reads it — but that lexicon's
  fields (invites, links) fit CISS poorly and the useful CISS fields are
  extensions anyway;
- **(c)** both: the native document is canonical, the lexicon endpoint is a
  thin projection of it.

### 2. getBlob Content-Type echo (close an existing seam)

`uploadBlob` already sanitizes and *reports* the mime in its response
(`pds_api.rs`), but nothing persists it, so `getBlob` returns
`application/octet-stream` always (declared seam, ARCHITECTURE §7). The
reference PDS stores `mimeType` in its `blob` table and echoes it. CISS's
analogue store is the upload receipt — the mime belongs in the receipt body
(it is a fact about the transfer, which is what receipts attest), making the
echo derivable exactly the way `listBlobs` already derives cids.

**The open question is answered (2026-08-11): no schema rev needed.** Adding
`mime: Option<String>` with `#[serde(default, skip_serializing_if =
"Option::is_none")]` leaves absent-field receipts (native object plane, all
historical) byte-identical under canonicalization, so existing signed hashes
are untouched. Walking this question also surfaced a real defect — `account_mode`
had been added to `ReceiptCore` with parse-compat only, silently breaking
`core_matches()` for every pre-tag signed receipt — fixed the same day inside
the unreleased window, with a permanent guard test
(`receipts.rs::a_receipt_persisted_before_the_account_mode_tag_still_verifies`).
Standing rule bought by the fix: **a field added to any signed record body
ships with `skip_serializing_if` on its default, or it breaks verify-compat
for everything already signed.** Tracked as ROADMAP_TODO **E104**.

### 3. Manifest-vs-store reconciliation report

> **Re-grounded 2026-08-12** against the object-lifecycle plan's finding
> ("the manifest is not an index of what exists",
> `docs/plans/2026-08-11-object-lifecycle.md`): the first framing here made
> the same mistake that plan's first draft did.

`listMissingBlobs` answers "what do my records reference that was never
uploaded?" CISS has no records, but the manifest is the same shape of claim.
The report has **two directions with very different meanings**, and only one
is a problem set:

- **Claimed-but-missing** (the `listMissingBlobs` analogue, and the alarming
  set): manifest leaves for which `blobs.has(did, cid)` is false. The owner
  is **paying rent** on these (byte-days run over the manifest) for bytes
  that either never arrived or vanished — an integrity *and* billing
  discrepancy either way, and full-coverage existence checking complements
  the E5 spot-check audit (sampled *content* verification) exactly.
- **Stored-but-unclaimed** (NOT a problem set — the ordinary case):
  `op_put_object` never touches the manifest, so never-manifested objects
  are routine. The honest framing is a **quota-vs-claim line**: "N bytes
  count against your quota (receipts/`du`) but sit outside your rent-bearing
  claim (manifest)." Useful legibility, never "garbage," and the report must
  not imply reclamation — the lifecycle plan owns deletion semantics.

Mechanics are all in place: manifest walk + `BlobStore::has` for the first
set; the receipt-derived cid inventory (`listBlobs`'s derivation) intersected
with the manifest leaf set for the second. Self-only over the wire (the
cross-user rule: aggregate views stay on-box). Open: a dedicated
`GET /{did}/reconcile` vs a `ciss-ctl` verb composing existing reads
client-side; and whether v1 ships direction one only (the unambiguous half).

### 4. Per-DID / per-route rate limiting (E102)

Filed with full reasoning as ROADMAP_TODO E102; on this list because it is
the one candidate that is a **standing hardening gap today**, not a
compat/completeness item. Order: per-DID compute counters at the dispatch
boundary (seam E83 — the attach point already exists), then limits fed by
them. The cooperative twist worth discussing: **declared, owner-visible
limits** (the dials pattern) rather than hidden operator tunables — possibly
even a dial the owner can set *below* the house limit for their own devices.

### 5. Blob quarantine — a reversible set-aside tier

Today CISS can only erase (irreversible). A quarantine tree
(`{root}/quarantine/{did}/{cid}`, mirroring upstream's third tree) gives the
operator a reversible action for disputes/legal holds — and it must be visible
in the storage-model axes (ARCHITECTURE §5a), not bolted on: it is a new
serving-state, orthogonal to retention. **The interesting design questions
are CISS-specific:** (a) does a quarantined blob still accrue rent? (bytes are
still held — but the owner is denied service; grace (E9) exists for exactly
this kind of on-the-books mercy); (b) does `listBlobs`/`du` show it, and as
what? (the gated-reads hidden-cid precedent says: visible to the owner,
absent to others); (c) who can invoke it — on-box only (`ciss usage`
precedent: admin views stay off the wire) seems right for v1.

### 6. Moderation/report inlet — accept and record, nothing more

`createReport` without machinery behind it is still worth something: an
authenticated, rate-limited inlet that appends to an operator-visible log.
It only makes sense **after** quarantine exists (a report with no possible
action is noise), and the minimal shape deliberately excludes labels,
takedown automation, and any admin wire surface (kept on-box). **Maybe** —
the trigger is external traffic: the day non-cooperative parties can reach
gated-read grants, reports acquire a purpose.

### 7. Member-exit ceremony — account deletion, cooperative-flavored

Not atproto's deleteAccount (that is account-system-coupled) but the same
user right: a deliberate, complete exit. CISS already owns every piece —
empty-manifest (Design A reclaims all objects), final statement
(balance-forward close), assertion clearing, and optionally the tombstone
posture for "prove it is gone." The work is the **composition**: one
documented, tested ceremony ("leave the co-op") rather than four manual
steps, with a defined end-state for the ledger (history is `chain`/
`permanent` — the exit nets the account to zero and stops accrual; it does
not rewrite history, and saying so honestly is part of the design). Waits on
E95 Design A landing.

### 8. Event stream / firehose — park, explicitly

The only candidate that changes CISS's *category* (from request-serving to
event-emitting). Real uses exist — a second CISS mirroring a member's data,
cooperative-level replication, cache invalidation for gated reads — but every
one of them is federation-shaped, and the gap doc already scopes federation
as "later." Listed so that parking it is a decision on the record, not an
omission. If it ever wakes, CISS's version is receipts/statements as the
event log (they already exist, signed and ordered — `seq`-monotonic per
actor) rather than atproto's repo-commit stream.

## Suggested order (for discussion)

1. **Now / cheap:** describeServer (§1) + Content-Type echo (§2) — two small
   compat/transparency wins; §2 closes a declared seam.
2. **Next / hardening:** E83 counters → rate limits (§4) — the only item that
   defends against something today.
3. **With E95:** reconciliation report (§3) rides the same manifest-walk
   machinery; member-exit (§7) composes on Design A.
4. **When moderation pressure is real:** quarantine (§5), then the report
   inlet (§6), in that order.
5. **Parked:** firehose (§8), OAuth-RS (E101) — each with a named wake
   condition (federation; a non-broker client pathway).
