# M5 — cost twin: I know the cost before I sync, and it stops at my ceiling

**Status:** CLOSED — all phases shipped (the ladder's final milestone)
**Parent plan:** `docs/plans/2026-08-07-file-sync-client.md` (M5 section); ties discovery **E89**.
**Server change:** none (code). One **doc** change: the exit-exempt invariant lands in
`docs/SECURITY-POSTURE.md` as **B6** (E89 lane (a) — the highest-value structural rule).

## Problem Statement

Every sync today moves bytes first and reveals the cost afterwards (receipts).
The server's pricing is honest and linear (`floor(bytes/1000)`¢ postage) but the
client never *uses* it before transferring — the M1 "will upload" INFO line
computes exactly the right number and then only logs it. E89's dial-pattern
finding is that a synchronous meter makes a **hard spending ceiling** a
comparison-before-serving, and that a ceiling is only safe if it **throttles or
defers, never mints debt** — and never, under any state, blocks a person's
egress of their own data ("they can never keep your furniture").

## Approach

1. **P5.1 — pre-flight pricing.** Extract the plan half of `push_tree` (logical
   tree → needed set → have/want) into a shared planner; `price_backup()`
   returns a `PriceQuote { files, chunks_to_upload, chunks_skipped, bytes,
   postage_cents }` without moving a byte. The cents come from
   **`ciss::pricing::postage_cents`** — the server's own function, linked, so
   the twin cannot drift from the tariff. CLI: `ciss-ctl sync price <dir>`;
   the backup INFO line gains the cents.
2. **P5.2 — the ceiling.** Per-tree, in `SyncState`: a `ceiling_cents` config
   and a spend ledger (sqlite table: ts, bytes, cents). Enforcement sits at the
   top of the push path, **before any byte moves**: if
   `spent + quote > ceiling`, the whole sync defers with a typed
   `SyncError::CeilingDeferred { needed_cents, spent_cents, ceiling_cents }` —
   no partial upload, no keep-set commit, nothing billed. A successful push
   records its actual postage in the ledger. CLI:
   `ciss-ctl sync ceiling <dir> [--cents N | --clear | --reset-spend]`.
3. **Exit-exempt (B6).** Restore and hydrate never consult the ceiling — by
   construction (the check lives only in the push path) and by a regression
   test: with the ceiling exhausted, `restore` still runs. The invariant is
   written into `SECURITY-POSTURE.md` §7 as **B6** and the checklist: *no
   billing state — balance, ceiling, throttle — may ever gate a customer's
   self-directed egress of their own manifest + blobs.* Server-side there is
   no such gate today (reads are never billing-conditioned); B6 pins that this
   must remain true as ceilings/dials arrive.

## Reasoning

- **Why the ceiling defers the whole sync rather than uploading up to the
  limit:** a partial tree is a lie — the keep-set would either commit a tree
  the server half-holds or not commit and strand paid-for bytes. E89's rule is
  "throttle/defer, never bill": deferring the entire commit leaves both ledgers
  exactly where they were.
- **Why per-tree state:** the spend machinery (sqlite, config) already lives in
  the per-tree `SyncState`; a per-profile aggregate ceiling is a straight
  follow-on once wanted. `--no-state` backups have no ledger and therefore no
  ceiling — stateless mode is already documented as the reduced mode.
- **Why the client enforces what the server doesn't:** the ceiling is the
  customer's instrument (E89: two-sided enforcement, client twin pre-flight).
  The server stays a dumb honest meter; a *co-signed* ceiling waits on the
  bilateral-receipt seam (`Bilateral` → `501`, E82) and is out of scope.
- **Why B6 is a POSTURE invariant and not just client behavior:** the checklist
  is what future audits walk. The rule must bind *future* server mechanisms
  (dials, throttles) — exactly what the standing-gaps/invariant machinery is
  for.

## Phases (RED-first)

### P5.1 pre-flight pricing
- Unit: `PriceQuote` postage equals `ciss::pricing::postage_cents(bytes)`
  (golden values incl. the floor edge: 999 bytes → 0¢, 1000 → 1¢).
- Workflow (`tests/flow_sync_price.rs`): pricing a tree moves **zero** blobs
  and commits nothing; quote matches what the subsequent backup then uploads;
  re-price after backup quotes 0¢ (dedup is priced in).
- CLI `sync price` + cents in the backup INFO line.

### P5.2 ceiling + exit-exempt
- Unit: ledger round-trip; `CeilingDeferred` carries the three numbers.
- Workflow (`tests/flow_sync_ceiling.rs`): backup priced over the ceiling
  defers — server gains **no** blobs, keep-set seq unchanged; raising the
  ceiling lets the same backup through and the ledger records its postage;
  with the ceiling exhausted, **restore still runs** (B6).
- POSTURE §7 B6 + checklist row; CLI `sync ceiling`.

### Close-out
Drill against the flow harness (ceiling defer → raise → sync → restore under
exhausted ceiling), mutants on the pricing/ceiling logic, plan close, PR, CI,
merge, stamp milestone plan + E89 lane (a) in discovery.

## Quality gates

As M1–M4: `cargo test --workspace` + `cargo clippy --all-targets --workspace`
clean per commit; no `cargo fmt`; integrity guards RED-first; mutants on the
new logic once green.

## Out of scope

- Co-signed ceiling / bilateral receipts (E82 seam, `501` today).
- Per-profile aggregate ceilings; period auto-reset policies (the ledger keeps
  timestamps so periods can be layered later).
- Server-side dial/throttle mechanics (E89 lane (b)/(c)).

## Outcome Summary

All phases shipped on `ciss-m5`; server change: none (code); POSTURE gained B6.

- **P5.1 (pre-flight pricing)** — `4c268d7`. The push planner extracted as
  `plan_push` and shared, so the quote and the transfer cannot diverge;
  `price_backup` prices via the linked `ciss::pricing::postage_cents`. Flow
  test: a quote uploads nothing and commits nothing; the backup then moves
  exactly the quoted bytes; an unchanged tree re-prices at 0¢.
- **P5.2 (ceiling + B6)** — `113bdb1`. Per-tree ceiling + spend ledger in
  `SyncState` (bytes on the ledger, cents derived over the *total* — the
  statement's own aggregation, so per-sync flooring cannot under-count).
  Over-ceiling syncs defer whole before any byte moves; deferral leaves the
  server and the ledger untouched (asserted). **Exit-exempt** landed as
  POSTURE **invariant B6** + checklist row (E89 lane (a)); client-side it
  holds by construction and by the restore-under-exhausted-ceiling test.
- **Mutation audit** — price.rs + state.rs: baseline 32 mutants / 11 missed
  (the root-flow blind spot again: `chunks_skipped` arithmetic, plus
  pre-existing config/cache-budget plumbing in the touched file); all closed
  with crate-level kills (`Holding` mock transport, config/budget persistence
  round-trip) → re-run **27 caught, 5 unviable, 0 missed**. The ceiling
  branch in backup.rs (flow-test-only territory) audited separately with a
  workspace-tested scoped run (`--test-workspace true --re` on its lines):
  10/12, then both `>` → `>=` boundary survivors killed with real semantics —
  a ceiling set to exactly the priced total lets the sync through ("stops at
  X" means X is spendable; the deferral error's own number is actionable),
  and a 0-byte sync leaves no ledger row (asserted by row count). Final
  re-verify: **6/6 caught, 0 missed**.

Discoveries:

- The ceiling's first cut deferred a 0¢-marginal sync when the ledger already
  sat past a lowered ceiling — the flow test caught it live (RED doing its
  job on a semantic, not just a wiring, bug). The rule that survived: defer
  only a sync that would *add* priced spend past the ceiling; the ceiling
  stops new spending, it does not retroactively freeze free operations.
- Pricing the ledger as bytes-then-total-cents (not per-sync cents) is the
  faithful twin: `floor(a+b)` ≥ `floor(a)+floor(b)` — summing per-sync floors
  would drift under the real statement.
