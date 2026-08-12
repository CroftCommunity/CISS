# CISS — outstanding TODO

Open items after the `ciss-ctl` client effort (delivered through **v0.5.6**,
2026-08-06). Full history: `docs/plans/2026-08-06-ciss-ctl-client-cli.md`. The
client is shipped via Homebrew (`brew install croftcommunity/tap/ciss-ctl`); the
server + client are one workspace (root `ciss` crate + `crates/ciss-cli`).

---

## 0. ADR 0005: kind semantics classes + the accounting chain — walked through with the owner, ready to implement on final acceptance

Scoped + owner-reviewed 2026-08-11
(`docs/adr/0005-kind-semantics-and-accounting-chain.md`): **five** declared
axes per kind — retention, erasure, enumeration, **hashing (posture +
algorithm; the BLAKE3/SHA-256 ecosystem split stated per kind)**, and
**sizing (body ceilings + growth posture; nothing assumed infinite)**.
`chain.counter` brings the ledger's tamper-evidence to the substrate with
**checkpoint/compaction under the ack-before-shred rule** (balance-forward,
per the statements pattern). Agreed calls: `kv.flag` erasable+listable;
`kv.counter` REMOVED when the chain lands (no deprecated 2am traps).
Implementation order is in the ADR; croft-relay-admit's usage moves over on
a pin bump as step 5.


## 1. Redeploy the VPS to v0.5.6 — blocks `du` and any post-v0.4.0 server change  ⟵ biggest

The deployed `https://ciss.croft.ing` runs a **pre-v0.5.5** server: it enforces
auth (unauth `PUT` → 401, gated reads + `did:` service-auth all verified live on
2026-08-06), but it is **older than the client releases**. Concretely, `GET
/{did}/du` (added v0.5.5) returns **501** there, so `ciss-ctl du` fails against the
VPS until a redeploy.

- **Action:** build/deploy the **v0.5.6** release via croft-stack. Deploy shape
  (DEPLOYMENT.md): systemd `ciss.service` → `/opt/ciss/current/ciss --data-dir
  /var/lib/ciss --listen 127.0.0.1:8301`, Caddy `443 → 127.0.0.1:8301`.
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
- **Bilateral (client co-signed) receipts** — server SEAM (`BilateralUnsupported`);
  the client shows `receipt: unilateral`.
- **Manifest/rent client surface** — not exposed (`PUT /{did}/manifest`); the
  meter shows transferred bytes, not rent.
- **Full atproto OAuth** for the `did:` path — v1 uses an app password; OAuth
  (PAR/DPoP/PKCE) is a tracked follow-on.
- **`CISS_ADMIN_PINS_FILE` on the VPS** — provisioned-but-empty (DEPLOYMENT.md §2);
  needed before `did:` break-glass resolution (and the `du` admin lockdown) is real.
