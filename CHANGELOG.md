# Changelog — CISS

One file for the server (the `ciss` crate: S3-compat + atproto blob planes, metering,
keep-set manifests) and the client (`ciss-ctl`: the `ciss-cli` crate and the engine crates
it fronts, `ciss-sync`, `ciss-iroh`). Versions move in lockstep; every entry names which
half it changed. The Homebrew tap (`croftcommunity/tap/ciss-ctl`) tracks tagged releases.

Contexts: server · cli

Format: [Keep a Changelog](https://keepachangelog.com/), per the workspace rule
(`CroftC/.claude/CHANGELOGS.md`): the branch that changes something a consumer runs adds
its entry under `[Unreleased]` before it lands; at release the section is renamed in the
bump commit. Until 2026-08-29 the client kept its own file at `crates/ciss-cli/CHANGELOG.md`;
folded here because two files for one lockstep version were two places for the same
release to disagree (`[0.6.1] — never released` below is the residue).

## [Unreleased]

## [0.10.0] — 2026-08-29

The TODO-close release: both auth planes on the meter, an honest du-lockdown
refusal, and the source-tarball release asset the Homebrew formula builds from.
Also carries everything landed since v0.9.0 outside this batch: the h2
dependency fix with the workspace supply-chain gates (`security.yml`), the
changelog fold (the cli file merged into this one), and the CI/land process
docs.

### Added
- **server:** `GET /{did}/meter` accepts a `did:` **service-auth JWT**
  (`lxm=ing.croft.ciss.meter`) alongside the `id:` session plane — the same two
  planes as `du`, closing the "a `did:` account can't read its own meter
  remotely" limitation (TODO §4). Owner-only as ever; an lxm-mismatched token
  is an unauthenticated caller (401), a cross-DID read stays 403. Guards:
  `tests/wiring_meter.rs`.
- **cli:** `--identity did meter` — relays a meter-scoped service-auth JWT and
  prints the account's own meter; the client-side "not available for a did:
  identity" refusal is gone with the server limitation it described
  (`Client::get_meter_bearer`; guard: `crates/ciss-cli/tests/cli_meter.rs`).
- **cli:** releases now also ship a **source tarball**
  (`ciss-vX.Y.Z-src.tar.gz` + `.sha256`) — the Homebrew formula's build input,
  restoring an uploaded asset with a hash we control (TODO §6; the formula had
  been pointed at GitHub's auto-generated tag tarball as a stopgap).

### Security
- **server:** (the same workspace dependency serves the cli) `h2` 0.4.15 →
  0.4.19 retires **RUSTSEC-2026-0258** (in the
  production path via axum/reqwest). Four advisories remain recorded as dated
  exceptions with per-artifact reachability, none with an upstream fix
  (`security.yml` gates the set).

### Fixed
- **server:** the `du` admin-lockdown refusal now says what it means:
  `403 "forbidden: du is restricted to admins on this server"` instead of the
  misleading "not the owner of this namespace" a locked-out **owner** used to
  get (TODO §3 — the log line was always accurate; the wire body now matches).
  Guard: `wiring_du::the_lockdown_refusal_names_the_lockdown_not_ownership`.

## [0.9.0] — 2026-08-24

Server-only follow-ons to the kind-semantics release: the RFC 9728 discovery
pointer, stage-1 compute observability, and the receipt verify-compat fix.
No client changes (`ciss-ctl` bumps in lockstep with no behavior change).

### Added
- **server:** **`GET /.well-known/oauth-protected-resource`** (RFC 9728) — OAuth
  resource-server discovery, the pointer half only: names the resource and
  bsky as its AS. CISS still accepts no OAuth tokens (credentials remain
  `id:` sessions + service-auth JWTs); the DPoP-verification half stays
  parked (`docs/notes/pds-capability-gap.md`, E101).
- **server:** **Compute observability, stage 1** (E83; design:
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
- **server:** **Verify-compat for pre-`account_mode` receipts.** The account-mode tag
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

### Client
No client changes — the version moves in lockstep with the server release
(RFC 9728 discovery pointer, E83 stage-1 compute observability, receipt
verify-compat fix; see the server changelog).

## [0.8.0] — 2026-08-12

The **kind-semantics release** (ADR 0005): every stored kind now declares its
point in a six-axis space (`src/kind_spec.rs`), and the accounting substrate
learns a tamper-evident chain. This is the release the downstream consumer
(`croft-stack/relay/source`, croft-relay-admit) bumps its pin to; the notes
below are its migration reading. That pin does not see any of this until it
deliberately bumps to a commit including it (README "Downstream consumers").

### Added
- **server:** **Drawdown legibility — the signed account-mode tag + the drain meter
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
- **server:** **`KindSpec` and the six-axis storage model** (`src/kind_spec.rs`, ADR 0005 /
  ARCHITECTURE §5a): every kind declares retention, authorship, erasure,
  enumeration, hashing (posture × algorithm), and sizing as data. A compile-time
  invariant enforces `Chain ⇒ Permanent`.
- **server:** **Body ceilings** — a kind-specific body-byte ceiling enforced at the write
  boundary, refused with the limit quoted (independent of count guards like
  policy's `MAX_READERS`).
- **server:** **`kv.flag`** — a per-subkey boolean (a tenant's membership roster): erasable,
  listable, `Setting` retention.
- **server:** **Generic `DELETE` and `LIST`, gated by declaration**:
  `DELETE /{did}/assertion/{kind}[/{subkey}]` (owner-only; allowed only for an
  `Erasable` kind — a hard delete leaving no residue, so a re-write starts at
  seq 1; a `Permanent` kind refused 405) and
  `GET /{did}/assertions/{kind}` (owner-and-self-only subkey listing for a
  `Listable` kind; a `PointOnly` kind refused 405; the owner-gate runs before
  any row is read, so a refusal is never an existence oracle).
- **server:** **`chain.counter`** — an append-only, hash-linked accounting chain
  (`src/chain_kind.rs`). Each entry is a signed `{delta, total, prev_entry_hash}`
  step, verified at write to *follow* the chain (total, seq contiguity, and the
  predecessor link) and refused with the real values quoted otherwise.
  `?chain=1` returns the entry history plus a server-recomputed, verified total
  (recomputation catches tampering after the fact — the point of a chain over a
  cell). Verification path is mutation-clean.
- **server:** **Checkpoints + compaction** (ADR 0005 A4): a signed checkpoint entry
  `{closing_total, chain_head_hash, prev_checkpoint}` closes the books forward;
  entries behind an acknowledged checkpoint may be compacted so a chain stays
  bounded while its aggregate survives. Compaction is a configured policy —
  `on_ack` (default) or `deferred` to an explicit
  `POST /{did}/assertion/{kind}/{subkey}/compact` (a billing marker); compaction
  with no acknowledged checkpoint is refused (no shredding before agreement).

### Removed
- **server:** **`kv.counter`** — the per-subkey latest-wins total, added earlier in this
  unreleased cycle and **removed before release**: a latest-wins slot lets a
  compromised writer silently rewrite a running total, which accounting cannot
  allow. Its role moves to the tamper-evident `chain.counter`. **Consumer
  migration (B1):** usage accounting moves from `kv.counter` (read-modify-write a
  total) to `chain.counter` (read-head-then-append a `{delta, total, prev_hash}`
  entry); the once-retry survives. Membership stays `kv.flag` (a roster wants
  erasure, not permanence). The consumer's `remove()`/`keys()` workarounds retire
  onto the real `DELETE`/`LIST`.

### Client
### Added
- **cli:** `Meter` (from `GET /{did}/meter`) now carries `drawdown_download_bytes` —
  the separable drawdown "drain" line (fully counted in `download_bytes`
  too; see the server changelog's drawdown-legibility entry).
- **cli:** The kind-semantics client surface (ADR 0005): `Client::delete_assertion` /
  `Client::list_assertions` — the generic owner-only `DELETE` and subkey `LIST`
  (return the HTTP status so refusals are observable); `Client::get_chain` — the
  `?chain=1` read (entry history + recomputed total); `Client::compact_chain` —
  the explicit `POST .../compact` billing-marker path.

## [0.7.0] — 2026-08-09

The self-assertion release: one substrate for every customer-signed setting
(the dials plan, D1–D5 — PRs #29–#33), plus the client follow-on wave that
landed after v0.6.0 (PRs #21–#28).

### Added
- **server:** **The self-assertion substrate** (`src/assertion.rs`): one envelope for
  every customer-signed setting — Model A (key-derives-DID) and Model C
  (JWT-authorized, provider-attested), domain-separated preimages per kind,
  strictly-monotonic seq, and the provider **ack** countersigned on every
  accepted write (success is provable, not assumed). Generic wire:
  `PUT/GET /{did}/assertion/{kind}[/{subkey}]`.
- **server:** **The dials**: `dial.ceiling` (at-rest cap — provider bounds supersede,
  refused-at-set with the bound quoted, `min()` at the quota gate; spend
  cap — 402 refuse-with-quote before serving billable writes),
  `dial.period` (customer-initiated spend periods; acceptance snapshots the
  meter baseline — monotonic, never a clock), `dial.account-mode` (drawdown:
  books closed, keep-set shrink-only, egress served and billed; reversible
  by dial), `dial.receipt-mode` (bilateral receipts as seq'd customer
  opt-in).
- **server:** **Bilateral receipts** — the `501` seam unstubbed: provider-signed
  partials completed by `POST /{did}/receipt/{hash}/countersign`; a
  completed receipt is a doubly-signed fact verifiable offline.
- **server:** `/.well-known/did.json` now publishes both verification keys
  (`#assertion-ack`, `#receipts`) — the whole proof chain is public.
- **server:** POSTURE: invariants **B6** (exit-exempt, enforced in code — no read op
  consults billing state) and the **D-series** (§15, D1–D6) + checklist.

### Changed
- **server:** **Policy records re-homed** onto the substrate as the `policy` kind
  (semantics unchanged: Z4–Z8, oracle-free 404, Q4 visibility; wire shape
  and lxm changed — pre-1.0, stored policy records on the server are wiped).
- **server:** **Uniform typed staleness**: every stale write — policy, dials, and the
  manifest — is the same typed 409 (clients detect by status, never by
  matching error text).

### Client
Everything since the ladder release, in two waves.

### Added — the dials (customer-signed settings; PRs #29–#32)
- **cli:** **`ciss-ctl dial`** — settings you sign, the server countersigns:
  `dial ceiling --at-rest-bytes N | --spend-cents N | --clear` (provider
  bounds supersede; over-bound refused with the real bound quoted),
  `dial period` (start a spend period), `dial account-mode
  --drawdown|--active` (books closed / re-opened, reversible, every
  transition on the record), `dial receipt-mode --bilateral|--unilateral`
  and `dial countersign <hash>` (complete a bilateral receipt into a
  doubly-signed fact).
- **cli:** `acl` now rides the generic assertion wire (`/{did}/assertion/policy…`)
  and every write returns the provider ack.
- **cli:** Stale writes detected by the typed 409 status — the old error-text
  matching is gone.

### Added — the post-0.6.0 client wave (PRs #21–#24)
- **cli:** **Monotonic spend ledger** (periods by counter, never clock; reset
  preserves history) + the **per-profile aggregate ceiling**
  (`sync ceiling --profile`) and the complete cost picture (`sync price` /
  `sync status` show at-rest + rent ¢/day; the ceiling caps transfer).
- **cli:** **Relay by default**: p2p rides `relay.croft.ing:8443`
  (`--relay <url>` / `--no-relay` / profile `relay` file); tickets carry
  the relay transport; an unreachable relay degrades to direct paths
  (pinned hermetically).
- **cli:** **Serverless persistence**: fs-backed iroh store + durable alias index
  under the tree's state root — multi-round p2p converge survives full
  restarts.
- **cli:** **Metered transports**: free p2p transfers are never deferred or
  ledgered; `sync ceiling --reconcile` pulls other devices' spend from
  the meter (baseline-adopt, catch-up rows, nothing ever subtracted).

## [0.6.1] — never released

(Changes below shipped on `main` between v0.6.0 and v0.7.0 with no server
impact; listed under the client changelog: monotonic spend ledger, relay
default, serverless persistence, metered transports + meter reconciliation.)

## [0.6.0] — 2026-08-07

The file-sync ladder release (M1–M5, PRs #14–#19). The server change is
deliberately tiny — the whole ladder needed exactly one field:

### Added
- **server:** `Manifest.heads` — optional owner-signed `device_id → cid(DeviceHead)` map
  for multi-device sync (M3). Bound into the signing preimage via a canonical
  digest; absent heads produce the byte-identical legacy preimage, so every
  pre-frontier manifest still verifies. Still governed by the I5 monotonic-seq
  CAS; the server validates and stores, never interprets (POSTURE B1 updated).
- **server:** CI gate (`.github/workflows/ci.yml`): `cargo test --workspace` +
  `cargo clippy --all-targets --workspace` on every PR and push to `main`;
  toolchain pinned via `rust-toolchain.toml` (1.97.1).

### Docs
- **server:** `SECURITY-POSTURE.md` invariant **B6** (exit-exempt): no billing state —
  balance, ceiling, throttle, dial — may ever gate a customer's self-directed
  egress of their own manifest + blobs. Pins the rule for future dials; no
  billing-conditioned read path exists today.

### Client
The file-sync release: the whole M1–M5 ladder (PRs #14–#19).

### Added
- **cli:** **`ciss-ctl sync`** — a full own-device file-sync client over CISS:
  - `sync backup` / `sync restore` (M1): FastCDC content-defined chunking
    (dual sha-256/blake3 refs), canonical DAG-CBOR fs-manifest, have/want
    dedup via `du`, keep-set commit under I5, verify-on-receipt everywhere,
    cold restore by manifest self-tag, chunk-level resume.
  - `sync evict` / `sync hydrate` / `sync status` (M2): bounded local
    footprint — budgeted chunk cache, placeholders, the logical-tree
    no-data-loss rule (an eviction never shrinks the committed tree).
  - `sync converge` (M3): multi-device — self-verifying `DeviceHead`s,
    slot-discipline non-lossy frontier commits, and a deterministic
    clock-free fold; conflicts preserved as `<path>.conflict-<device>`.
  - `sync p2p share` / `sync p2p converge` (M4, new crate `ciss-iroh`):
    blobs from a peer over iroh (blake3/Bao verified, sha-256 re-verified on
    receipt), and the same converge running serverless over iroh-gossip;
    pairing via a printed ticket. LAN/loopback posture in this release.
  - `sync price` / `sync ceiling` (M5): pre-flight quotes via the server's
    own linked tariff, and a per-tree spending ceiling that defers
    over-ceiling syncs whole — never partial, never billed; restore is
    exit-exempt by construction (POSTURE B6).
- **cli:** Per-profile `device_id` (auto-generated) for multi-device backup.

### Notes
- **cli:** Serverless (p2p) converge state is process-lifetime in this release: a
  multi-round serverless converge across restarts falls back to the server
  path (fails loud, corrupts nothing). A persistent iroh store/alias layer is
  the planned follow-on.

## [0.5.6] — 2026-08-06

- **server:** `du` made strictly self-only over the wire (no cross-DID inspection for
  anyone; the flag is an admin lockdown). Cross-user views stay on-box.

### Client
Pre-changelog releases: `key gen/import/show/list`, `login`, `whoami`,
`put`/`get` (both planes), `meter`, `ls`, `du`, `acl set/get` (gated reads),
`--identity id|did`, `--json`, man page. See the git tags.

## [0.5.x] — 2026-08-06 · [0.4.0] · [0.3.x] — earlier

Pre-changelog releases: gated reads (Model A/C, invariants Z4–Z8, v0.4.0),
auth/authz hardening per ADR 0001, metering/receipts, healthz edge-gating
(ADR 0002). See `docs/plans/` and the git tags for detail.
