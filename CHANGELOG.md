# Changelog — CISS (server)

Changes to the CISS server (the `ciss` crate: S3-compat + atproto blob planes,
metering, keep-set manifests). The client CLI has its own changelog at
`crates/ciss-cli/CHANGELOG.md`. Server and client versions move in lockstep;
a version may appear here with "no server changes" when a release was
client-only.

Format: [Keep a Changelog](https://keepachangelog.com/); one entry per tagged
release, written at release time as part of the release flow (the entry is the
GitHub release notes).

## [0.9.0] — 2026-08-24

Server-only follow-ons to the kind-semantics release: the RFC 9728 discovery
pointer, stage-1 compute observability, and the receipt verify-compat fix.
No client changes (`ciss-ctl` bumps in lockstep with no behavior change).

### Added
- **`GET /.well-known/oauth-protected-resource`** (RFC 9728) — OAuth
  resource-server discovery, the pointer half only: names the resource and
  bsky as its AS. CISS still accepts no OAuth tokens (credentials remain
  `id:` sessions + service-auth JWTs); the DPoP-verification half stays
  parked (`docs/notes/pds-capability-gap.md`, E101).
- **Compute observability, stage 1** (E83; design:
  `docs/notes/rate-limiting-design.md`). Every dispatched request is timed
  and attributed per caller × operation class into a bounded in-memory
  ledger (`src/compute.rs`: LRS-evicted past 1024 callers, anonymous
  traffic one shared row, monotonic time only), flushed to the derived
  `compute_usage` table every 60s and at checkpoint, and surfaced as a
  compute section in `ciss usage` (self-scoped under `--did`). Observation
  only — no enforcement rides on it; stage 2 (shaping) is gated on this
  stage's live data. What is timed is dispatch itself: network drain is
  excluded, so a slow reader inflates nothing.

### Fixed
- **Verify-compat for pre-`account_mode` receipts.** The account-mode tag
  had landed with parse-compat only (`#[serde(default)]`); canonical
  serialization includes every present field, so every receipt signed
  before the tag re-canonicalized to different bytes and read as
  *tampered* to any honest verifier. The tag shipped in v0.8.0, so a
  v0.8.0 verifier read every older receipt as tampered; fixed here:
  the default (`Active`) is omitted from serialized form
  (`skip_serializing_if`), so pre-tag receipts keep their signed bytes and
  drawdown receipts still carry the mode inside the hash. Permanent guard:
  `receipts::a_receipt_persisted_before_the_account_mode_tag_still_verifies`.
  Standing rule (also in the design notes): a field added to any *signed*
  record body ships with `skip_serializing_if` on its default.

## [0.8.0] — 2026-08-12

The **kind-semantics release** (ADR 0005): every stored kind now declares its
point in a six-axis space (`src/kind_spec.rs`), and the accounting substrate
learns a tamper-evident chain. This is the release the downstream consumer
(`croft-stack/relay/source`, croft-relay-admit) bumps its pin to; the notes
below are its migration reading. That pin does not see any of this until it
deliberately bumps to a commit including it (README "Downstream consumers").

### Added
- **Drawdown legibility — the signed account-mode tag + the drain meter
  line** (PR #36, per the 2026-08-11 exit-pricing ruling). CISS makes no
  forward price commitments; the exit right is the only guarantee, and
  drawdown egress stays fully **metered** — whether it bills in full,
  prorated, or at a special rate is a human utility judgment at statement
  time (automatic free exit invites freezing a large account as an
  unmetered fileshare). The scaffolding that judgment needs:
  `ReceiptCore.account_mode` (the mode in effect at transfer time, signed
  into the content hash — an attested fact, and the seam for future
  accounting classes like service/bot/staff), `drawdown_download_bytes`
  through the B5 totals cache (append + backfill, cache-vs-scan guarded),
  and the drain line surfaced on `GET /{did}/meter`. `grace.rs` is the
  existing co-signed machinery a human credits against it. POSTURE B6
  records the principle. Workflow guard: `tests/flow_drawdown_meter.rs`.
- **`KindSpec` and the six-axis storage model** (`src/kind_spec.rs`, ADR 0005 /
  ARCHITECTURE §5a): every kind declares retention, authorship, erasure,
  enumeration, hashing (posture × algorithm), and sizing as data. A compile-time
  invariant enforces `Chain ⇒ Permanent`.
- **Body ceilings** — a kind-specific body-byte ceiling enforced at the write
  boundary, refused with the limit quoted (independent of count guards like
  policy's `MAX_READERS`).
- **`kv.flag`** — a per-subkey boolean (a tenant's membership roster): erasable,
  listable, `Setting` retention.
- **Generic `DELETE` and `LIST`, gated by declaration**:
  `DELETE /{did}/assertion/{kind}[/{subkey}]` (owner-only; allowed only for an
  `Erasable` kind — a hard delete leaving no residue, so a re-write starts at
  seq 1; a `Permanent` kind refused 405) and
  `GET /{did}/assertions/{kind}` (owner-and-self-only subkey listing for a
  `Listable` kind; a `PointOnly` kind refused 405; the owner-gate runs before
  any row is read, so a refusal is never an existence oracle).
- **`chain.counter`** — an append-only, hash-linked accounting chain
  (`src/chain_kind.rs`). Each entry is a signed `{delta, total, prev_entry_hash}`
  step, verified at write to *follow* the chain (total, seq contiguity, and the
  predecessor link) and refused with the real values quoted otherwise.
  `?chain=1` returns the entry history plus a server-recomputed, verified total
  (recomputation catches tampering after the fact — the point of a chain over a
  cell). Verification path is mutation-clean.
- **Checkpoints + compaction** (ADR 0005 A4): a signed checkpoint entry
  `{closing_total, chain_head_hash, prev_checkpoint}` closes the books forward;
  entries behind an acknowledged checkpoint may be compacted so a chain stays
  bounded while its aggregate survives. Compaction is a configured policy —
  `on_ack` (default) or `deferred` to an explicit
  `POST /{did}/assertion/{kind}/{subkey}/compact` (a billing marker); compaction
  with no acknowledged checkpoint is refused (no shredding before agreement).

### Removed
- **`kv.counter`** — the per-subkey latest-wins total, added earlier in this
  unreleased cycle and **removed before release**: a latest-wins slot lets a
  compromised writer silently rewrite a running total, which accounting cannot
  allow. Its role moves to the tamper-evident `chain.counter`. **Consumer
  migration (B1):** usage accounting moves from `kv.counter` (read-modify-write a
  total) to `chain.counter` (read-head-then-append a `{delta, total, prev_hash}`
  entry); the once-retry survives. Membership stays `kv.flag` (a roster wants
  erasure, not permanence). The consumer's `remove()`/`keys()` workarounds retire
  onto the real `DELETE`/`LIST`.

## [0.7.0] — 2026-08-09

The self-assertion release: one substrate for every customer-signed setting
(the dials plan, D1–D5 — PRs #29–#33), plus the client follow-on wave that
landed after v0.6.0 (PRs #21–#28).

### Added
- **The self-assertion substrate** (`src/assertion.rs`): one envelope for
  every customer-signed setting — Model A (key-derives-DID) and Model C
  (JWT-authorized, provider-attested), domain-separated preimages per kind,
  strictly-monotonic seq, and the provider **ack** countersigned on every
  accepted write (success is provable, not assumed). Generic wire:
  `PUT/GET /{did}/assertion/{kind}[/{subkey}]`.
- **The dials**: `dial.ceiling` (at-rest cap — provider bounds supersede,
  refused-at-set with the bound quoted, `min()` at the quota gate; spend
  cap — 402 refuse-with-quote before serving billable writes),
  `dial.period` (customer-initiated spend periods; acceptance snapshots the
  meter baseline — monotonic, never a clock), `dial.account-mode` (drawdown:
  books closed, keep-set shrink-only, egress served and billed; reversible
  by dial), `dial.receipt-mode` (bilateral receipts as seq'd customer
  opt-in).
- **Bilateral receipts** — the `501` seam unstubbed: provider-signed
  partials completed by `POST /{did}/receipt/{hash}/countersign`; a
  completed receipt is a doubly-signed fact verifiable offline.
- `/.well-known/did.json` now publishes both verification keys
  (`#assertion-ack`, `#receipts`) — the whole proof chain is public.
- POSTURE: invariants **B6** (exit-exempt, enforced in code — no read op
  consults billing state) and the **D-series** (§15, D1–D6) + checklist.

### Changed
- **Policy records re-homed** onto the substrate as the `policy` kind
  (semantics unchanged: Z4–Z8, oracle-free 404, Q4 visibility; wire shape
  and lxm changed — pre-1.0, stored policy records on the server are wiped).
- **Uniform typed staleness**: every stale write — policy, dials, and the
  manifest — is the same typed 409 (clients detect by status, never by
  matching error text).

## [0.6.1] — never released

(Changes below shipped on `main` between v0.6.0 and v0.7.0 with no server
impact; listed under the client changelog: monotonic spend ledger, relay
default, serverless persistence, metered transports + meter reconciliation.)

## [0.6.0] — 2026-08-07

The file-sync ladder release (M1–M5, PRs #14–#19). The server change is
deliberately tiny — the whole ladder needed exactly one field:

### Added
- `Manifest.heads` — optional owner-signed `device_id → cid(DeviceHead)` map
  for multi-device sync (M3). Bound into the signing preimage via a canonical
  digest; absent heads produce the byte-identical legacy preimage, so every
  pre-frontier manifest still verifies. Still governed by the I5 monotonic-seq
  CAS; the server validates and stores, never interprets (POSTURE B1 updated).
- CI gate (`.github/workflows/ci.yml`): `cargo test --workspace` +
  `cargo clippy --all-targets --workspace` on every PR and push to `main`;
  toolchain pinned via `rust-toolchain.toml` (1.97.1).

### Docs
- `SECURITY-POSTURE.md` invariant **B6** (exit-exempt): no billing state —
  balance, ceiling, throttle, dial — may ever gate a customer's self-directed
  egress of their own manifest + blobs. Pins the rule for future dials; no
  billing-conditioned read path exists today.

## [0.5.6] — 2026-08-06

- `du` made strictly self-only over the wire (no cross-DID inspection for
  anyone; the flag is an admin lockdown). Cross-user views stay on-box.

## [0.5.x] — 2026-08-06 · [0.4.0] · [0.3.x] — earlier

Pre-changelog releases: gated reads (Model A/C, invariants Z4–Z8, v0.4.0),
auth/authz hardening per ADR 0001, metering/receipts, healthz edge-gating
(ADR 0002). See `docs/plans/` and the git tags for detail.
