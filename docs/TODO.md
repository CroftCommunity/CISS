# CISS — outstanding TODO

> Repo operations / deferred items only. The product/design backlog of record is
> `discovery/alpha/ROADMAP_TODO.md`; the tracking scheme is `CroftC/.claude/TRACKING.md`.
> Cross-reference E-numbers where an item here implements a backlog row.

Open items after the `ciss-ctl` client effort (delivered through **v0.5.6**,
2026-08-06). Full history: `docs/plans/2026-08-06-ciss-ctl-client-cli.md`. The
client is shipped via Homebrew (`brew install croftcommunity/tap/ciss-ctl`); the
server + client are one workspace (root `ciss` crate + `crates/ciss-cli`).

---

## 0. ADR 0005 IMPLEMENTED (DONE) — kind semantics + the accounting chain (2026-08-12)

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


## 1. Redeploy the VPS — RESOLVED ✅ (2026-08-25): public `ciss.croft.ing` runs v0.9.0

The owner-authorized converge landed 2026-08-25 (croft-stack
`sessions/2026-08-25-ciss-v090-converge.md` is the full record): v0.4.0 →
**v0.9.0** in one converge (`ok=96 changed=5 failed=0`; second run
`changed=0`), provider identity carried across the upgrade by the encrypted
`provider-seed.cred` (same provider id after restart). Verified live from
outside: the RFC 9728 endpoint 404→200, unauth `du` 501→403 (the real authz
refusal, `reason="not owner"` in the journal), and the CLIENT-TESTING
put/ls/du/get walk green — `du` returning ledger sizes against the VPS for
the first time since the endpoint shipped in v0.5.5.

Still open, carried by their own items/docs:
- **`du` lockdown (optional):** `CISS_ADMIN_ONLY_DU` stays unset (self-service
  `du`, own namespace only). Flipping it requires populating
  `CISS_ADMIN_PINS_FILE` first — still provisioned-but-empty (DEPLOYMENT.md §2
  TODO; with the flag set and no pins, **all** `du` is denied).
- The deployed **client** walk ran on ciss-ctl 0.7.0 from the tap; a tap bump
  to 0.9.0 is routine Homebrew housekeeping when wanted (no wire changes for
  the walked surface).

## 2. Rust toolchain — RESOLVED: pinned to 1.97.1, gated by CI

The decision was taken the "commit to a pin" way: `rust-toolchain.toml` pins
**1.97.1** (+ clippy component; CI-PATTERN rule 7 — CI resolves exactly this
toolchain, so version-skew "green locally, red in CI" cannot happen), and the
repo now HAS CI: `.github/workflows/ci.yml` gates every PR/push with the full
workspace test + pedantic clippy (`-D warnings`) run, and `release.yml` re-runs
the same gate on every tagged commit before packaging. The two pedantic lints
this item tracked are gone — the suite is pedantic-clean under the pinned
toolchain (verified green at the v0.9.0 cut). Local caveat stands: on machines
where Homebrew's rustc precedes `~/.cargo/bin` on PATH the pin does not bind
local builds — keep the Homebrew toolchain on the same minor.

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
