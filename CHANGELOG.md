# Changelog — CISS (server)

Changes to the CISS server (the `ciss` crate: S3-compat + atproto blob planes,
metering, keep-set manifests). The client CLI has its own changelog at
`crates/ciss-cli/CHANGELOG.md`. Server and client versions move in lockstep;
a version may appear here with "no server changes" when a release was
client-only.

Format: [Keep a Changelog](https://keepachangelog.com/); one entry per tagged
release, written at release time as part of the release flow (the entry is the
GitHub release notes).

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
