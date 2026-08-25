# CISS — agent orientation

CISS (Croft Item Storage Server) is a cooperative metered-storage server in Rust:
an S3-compatible object interface + an atproto PDS blob API over one metered
byte-path. Its core value proposition is a set of **cryptographic integrity
guarantees**, so security is not a bolt-on — treat every change as
security-relevant.

## Read this first for any security work or audit

**`docs/SECURITY-POSTURE.md` is the source of truth for how CISS is *designed* to
be secure** — the trust model and the security invariants (auth, authz, content,
billing, crypto, key lifecycle, availability, input) with their enforcement
points, an invariant checklist, and the standing design gaps.

Use it to classify any problem:

- **Bug** — the code violates an invariant stated in the posture doc. Fix the
  code; the design is sound.
- **Design failure** — the code faithfully implements the posture doc, but the
  invariant is missing, too weak, or wrong. Fix the design (write/update an ADR),
  then the code.

Do not start a security review, propose a remediation, or reason about a finding
without first reading the posture doc and locating the relevant invariant.

## Security document map

| Doc | Role |
|---|---|
| `docs/SECURITY-POSTURE.md` | **design intent + invariants** — read first |
| `docs/SECURITY-REVIEW-2026-08-03.md` | audit findings + remediation status |
| `docs/adr/0001-auth-and-access-control-model.md` | auth/authz model decision (amended) |
| `docs/spec/gated-reads.md` | **gated reads (read-authz) integrator contract** — invariants Z4–Z8, shipped v0.4.0 |
| `docs/notes/atproto-integration-model.md` | **atproto identity design** (Model R: service-auth JWT + DID resolution) |
| `docs/adr/0002-healthz-exposure-and-limit-exemption.md` | healthz edge-gating |
| `docs/adr/0004-co-signed-spending-ceiling.md` | **co-signed ceiling design (Proposed)** — bilateral receipts, rent reservation, B6 carve-out |
| `docs/plans/2026-08-03-hardening-and-auth.md` | phased remediation plan + follow-ons |
| `docs/TESTING-STRATEGY.md` | the workflow (`World`/`Actor`) test tier |
| `docs/ARCHITECTURE.md` · `docs/DEPLOYMENT.md` | design internals · deploy/ops |

## Working conventions

- **TDD-first, always.** No production change without a failing test first
  (RED → GREEN). Security fixes land as a guard that was RED against the
  vulnerable code and is GREEN after — then stays as a permanent regression wall.
- **Two test tiers.** Pointwise unit/wiring/`e*` suites, plus the **workflow tier**
  (`tests/flow_*.rs` over the `World`/`Actor` persona harness in `tests/common`)
  for multi-actor, stateful stories. Every security finding has a workflow or unit
  guard.
- **Keep it green + clippy-pedantic clean.** `cargo test --workspace` and
  `cargo clippy --all-targets --workspace` must both be clean before a commit.
- **Cross-repo:** the deployment (systemd unit, Caddy, backup) lives in
  `croft-stack`, not here. Provider-key provisioning, the `/healthz` edge
  allowlist, etc. are croft-stack changes referenced from CISS docs/ADRs.

Workspace-level git identity and "don't commit/push unless asked" conventions are
in the CroftC workspace orientation (`discovery/AGENTS.md`), auto-loaded above
this file.

## Concurrent sessions (workspace norm)

Multiple agent sessions share the `CroftC/` workspace. Do multi-turn work in a dedicated
worktree — `git -C CISS worktree add ../worktrees/CISS/<slug> -b claude/<slug>` — never in
this checkout (peer sessions stage with `git add -A`; loose files get swept into unrelated
commits). Contested surfaces here — claim in `CroftC/.coordination/claims/` before
touching: **landing on `main`** (the store/chain semantics other repos pin to — see the dependency pins in croft-stack). Full protocol and the reasons behind it: `CroftC/.claude/COORDINATION.md`.
