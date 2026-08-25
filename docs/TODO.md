# CISS — outstanding TODO

> Repo operations / deferred items only. The product/design backlog of record is
> `discovery/alpha/ROADMAP_TODO.md`; the tracking scheme is `CroftC/.claude/TRACKING.md`.
> Cross-reference E-numbers where an item here implements a backlog row.

Open items after the `ciss-ctl` client effort (delivered through **v0.5.6**,
2026-08-06). Full history: `docs/plans/2026-08-06-ciss-ctl-client-cli.md`. The
client is shipped via Homebrew (`brew install croftcommunity/tap/ciss-ctl`); the
server + client are one workspace (root `ciss` crate + `crates/ciss-cli`).

---

## 0. ADR 0005 IMPLEMENTED — kind semantics + the accounting chain ✅ (2026-08-12)

Built and merged. ADR 0005
(`docs/adr/0005-kind-semantics-and-accounting-chain.md`) is now code: **six**
declared axes per kind (retention, authorship, erasure, enumeration, hashing
posture×algorithm, sizing) in `src/kind_spec.rs`, with `Chain ⇒ Permanent`
enforced at compile time. Milestone A landed on `main` (**release 0.8.0, PR
#37, `2d1e685`**): A1 KindSpec + body ceilings → A2 generic declaration-gated
DELETE/LIST → A3 `chain.counter` (append-only hash-linked, **mutation-clean
16/16**) → A4 checkpoints + compaction (configurable `on_ack`/`deferred` policy,
no shredding before an acked checkpoint, **mutation-clean 35/35**) → A5
`kv.counter` removed before release. Milestone B (the consumer pin bump)
landed on `croft-stack` (**PR #7, `b882d8f`**), retiring all three recorded
`CissStore` workarounds: usage `kv.counter` → `chain.counter`, `remove()` →
the real DELETE (no roster residue), `keys()` → the real LIST. `kv.flag`
stays erasable + listable (a roster wants erasure; usage wants permanence).
Execution record: `docs/plans/2026-08-11-kind-semantics-implementation.md`.


## 1. Redeploy the VPS — public `ciss.croft.ing` runs v0.4.0; v0.9.0 is released  ⟵ biggest

The deployed public `https://ciss.croft.ing` runs **v0.4.0** (the ansible pin in
`croft-stack/ansible/group_vars/all.yml`, `ciss` entry): it enforces auth (unauth
`PUT` → 401, gated reads + `did:` service-auth all verified live 2026-08-06), but
it predates every release since. Concretely, `GET /{did}/du` (added v0.5.5)
returns **501** there — re-confirmed live 2026-08-24 — so `ciss-ctl du` fails
against the VPS until a redeploy.

Do not conflate with **ciss-admit**: the private loopback CISS instance backing
croft-admit already runs **v0.8.0** (activated 2026-08-25, croft-stack RUNBOOK).
The two instances version independently by design; this item is the public one.

- **Action:** bump the `ciss` `active_tenants` pin (`binary_version`,
  `binary_url`, `binary_sha256`) to the **v0.9.0** release asset — the release
  workflow (`.github/workflows/release.yml`) builds, gates, and checksums it on
  the tag — then an owner-authorized converge. Deploy shape (DEPLOYMENT.md):
  systemd `ciss.service` → `/opt/ciss/current/ciss --data-dir /var/lib/ciss
  --listen 127.0.0.1:8301`, Caddy `443 → 127.0.0.1:8301`.
- **Optional (`du` lockdown):** to restrict remote `du` to admins, set
  `CISS_ADMIN_ONLY_DU=1` in the unit **and** populate `CISS_ADMIN_PINS_FILE`
  (currently provisioned-but-empty — DEPLOYMENT.md §2 TODO). With the flag set but
  no pins, **all** `du` is denied (nobody is an admin). Leave the flag unset for
  self-service `du` (any authenticated caller, own namespace only).
- **After redeploy:** `du` works against the VPS for `id:` and `did:` (self-only);
  re-run the `du` steps in `docs/CLIENT-TESTING.md`.
- This redeploy also picks up **every** post-v0.4.0 server change bundled into the
  release tarball (it's the whole repo), not just `du`.

## 2. Rust toolchain — pin, or resolve the 2 pedantic lints (1.94 vs 1.97)

The `brew install` pulled Homebrew **Rust 1.97** as a build dep, which became the
active `cargo`/`clippy` and surfaces 2 pre-existing pedantic warnings the repo's
prior **1.94** did not. `ciss-cli` itself is clean on both.

- `src/server.rs` — `map(<f>).unwrap_or(<a>)` on a `Result` (`clippy::map_unwrap_or`).
  Safe, portable fix: `.map_or(<a>, <f>)`.
- `crates/ciss-resolve/src/timeout.rs:55` — `Duration::from_secs(3600)`
  (`clippy::duration_suboptimal_units`). Clippy suggests `Duration::from_hours(1)`
  — **but `from_hours` is 1.97-only and would break a 1.94 build** (portability
  regression). Use `#[allow]` + comment, or commit to 1.97.
- **Decision needed:** add a `rust-toolchain.toml` pinning a version (then fix the
  lints for it), or keep dual-toolchain support and `#[allow]` the `from_hours`
  lint. The repo has no CI, so nothing gates this today — it's hygiene under the
  now-active 1.97.

## 3. `du` lockdown 403 message (minor clarity)

When `CISS_ADMIN_ONLY_DU=1` and a **non-admin owner** runs `du`, the server returns
`403` with the generic body "forbidden: not the owner of this namespace" — which
is misleading (they *are* the owner, just not an admin). The **server log is
accurate** (`"du locked to admins"`). Consider a distinct `ServerError` /message
for the lockdown case (e.g. "du is restricted to admins on this server"). `op_du`
in `src/server.rs`.

## 4. `did:` metering (server change to lift a current limitation)

`meter` is **`id:`-session only**: `get_meter_handler` uses `authenticate` (not
`authenticate_atproto`), so a `did:` account can't read its meter remotely
(`ciss-ctl --identity did meter` refuses with a clear message). To support it, the
meter endpoint would accept a `did:` service-auth JWT (like `du`/`listBlobs`/
`uploadBlob` do). Tracked, not built. (`ls` and `du` already work under `did:`.)

## 5. Minor / deferred (already noted in the plan's SEAMs)

- **Actionable exit codes:** every `ciss-ctl` error exits `1`; the messages are
  actionable but there are no distinct per-class exit codes (deferred, plan §4).
- ~~**Bilateral (client co-signed) receipts**~~ — DONE (D4, v0.7.0): the
  `dial.receipt-mode` assertion opts in; `ciss-ctl dial countersign <hash>`
  completes the doubly-signed fact. Remaining follow-on: auto-countersign
  batching in the sync client (deferred, dials plan close-out).
- **Manifest/rent client surface** — not exposed (`PUT /{did}/manifest`); the
  meter shows transferred bytes, not rent.
- **Full atproto OAuth** for the `did:` path — v1 uses an app password; OAuth
  (PAR/DPoP/PKCE) is a tracked follow-on.
- **`CISS_ADMIN_PINS_FILE` on the VPS** — provisioned-but-empty (DEPLOYMENT.md §2);
  needed before `did:` break-glass resolution (and the `du` admin lockdown) is real.
