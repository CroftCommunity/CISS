# Changelog — CISS (server)

Changes to the CISS server (the `ciss` crate: S3-compat + atproto blob planes,
metering, keep-set manifests). The client CLI has its own changelog at
`crates/ciss-cli/CHANGELOG.md`. Server and client versions move in lockstep;
a version may appear here with "no server changes" when a release was
client-only.

Format: [Keep a Changelog](https://keepachangelog.com/); one entry per tagged
release, written at release time as part of the release flow (the entry is the
GitHub release notes).

## [Unreleased]

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
- **Generic KV kinds on the self-assertion substrate** (`src/kv.rs`):
  `kv.flag` (a per-subkey boolean) and `kv.counter` (a per-subkey total,
  ordered by the substrate's strictly-monotonic `seq`). Both require a
  bounded, charset-checked subkey; bodies are typed and folded like every
  other kind, and unregistered kinds remain refused. No consumer vocabulary —
  any tenant can use a flag or a counter. First consumer:
  `croft-stack/relay/source` (croft-relay-admit's membership/accounting store
  on a private instance; see README "Downstream consumers" — that pin does
  not see this change until it deliberately bumps to a commit including it).

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
