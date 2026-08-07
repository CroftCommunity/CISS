# Spend ledger: monotonic periods + the per-profile ceiling

**Status:** CLOSED — shipped (plus two user-directed additions: `SYNC-MODEL.md` and the at-rest cost picture)
**Follow-on to:** `docs/plans/2026-08-07-file-sync-m5-cost-twin.md` (M5).
**Server change:** none.

## Problem Statement

Two corrections to the M5 cost twin, both user-directed (2026-08-07):

1. **Timestamps must not be the authority for anything.** The M5 spend ledger
   stored `(id, ts, bytes)` and the close-out framed `ts` as the hook future
   period logic would derive from. That violates the corpus's own rule
   ("timestamps are an assertion, never authoritative" — the E90 design
   decision the fs-manifest already honors). Also, `reset_spend` *deletes* the
   ledger — an accounting record that destroys its own history on reset.
2. **The ceiling is per-tree, but the bill is per-DID.** The server statement
   meters the account; "spend stops at X" is an account-level intent. Three
   synced trees today mean three independent ceilings the user must slice by
   hand.

## Approach

1. **Monotonic periods.** The ledger gains a `period_seq` column (backfilled
   `0` for existing rows via guarded `ALTER TABLE` — v0.6.0 state dirs exist
   in the wild). The current period is a monotonic config counter
   (`spend_period`). `spent` = `SUM(bytes) WHERE period_seq = current`.
   `reset_spend` becomes **increment the counter** — history is preserved, a
   "reset" is just a new period. `ts` stays on the row as human reference
   only, consulted by no query.
2. **`SpendLedger` extracted** (`crates/ciss-sync/src/ledger.rs`): the
   ceiling + period + record + spent surface as its own struct, openable at
   any sqlite path. `SyncState` owns the per-tree one (API unchanged for
   callers); the CLI opens a second, per-profile one at
   `$XDG_DATA_HOME/ciss-ctl/profiles/<profile>/ledger.sqlite` and attaches it
   via `SyncState::attach_profile_ledger`.
3. **Enforcement**: `push_tree`'s pre-flight check runs against *every*
   attached ledger (tree, then profile) — the first ceiling the sync would
   break defers it whole, same `CeilingDeferred` semantics (0¢-marginal never
   blocked; exactly-at-ceiling passes; B6 exit-exempt untouched — the check
   still lives only in the push path). A successful push records its bytes in
   every attached ledger.
4. **CLI**: `sync ceiling` gains `--profile` (operate on the profile ledger
   instead of the tree's); the no-flag display shows both scopes.

## Reasoning

- **Why a monotonic counter and not date-derived periods:** wall clocks
  drift, jump, and differ across devices; the fold already refuses to trust
  them. A period boundary that moves when the clock does is not an
  accounting boundary. The counter also makes "reset" an append-only
  operation — the ledger becomes a permanent record, which is what a spend
  ledger is *for*.
- **Why extraction instead of a second copy:** one `SpendLedger`
  implementation means the tree and profile scopes cannot drift in schema or
  semantics; the profile ledger is the same object at a different path.
- **Why check-all-then-record-all:** the tree ceiling answers "this tree's
  budget", the profile ceiling "my account's budget" — both must hold, and
  both ledgers must see every transfer or the aggregate under-counts.

## Phases (RED-first)

1. `SpendLedger` + periods: unit tests — period increments on reset, rows
   preserved, spent scoped to the current period, ceiling round-trip, the
   v0.6.0-schema migration (open a ledger created with the old table, rows
   land in period 0).
2. Profile attachment + enforcement: flow test — profile ceiling defers with
   no tree ceiling set; both ledgers record a successful push; tree + profile
   ceilings compose (tightest wins); reset preserves history (row count).
3. CLI `--profile`, docs, mutants on the ledger/enforcement logic, close.

## Outcome Summary

Shipped on `ciss-spend-ledger`:

- **`4d362ba`** — `SpendLedger` extracted with monotonic `period_seq` as the
  only accounting authority (`ts` reference-only, consulted by no query);
  `reset_spend` increments the period and deletes nothing; v0.6.0 tables
  migrate in place (old rows = period 0). The ceiling rule moved into
  `SpendLedger::check` (unit-tested at its boundaries); the push path checks
  and records every attached scope; the CLI always attaches the profile
  aggregate (`.../profiles/<profile>/ledger.sqlite`);
  `sync ceiling --profile`; `CeilingDeferred` names the deferring scope.
- **`bd31531`** — `docs/SYNC-MODEL.md` (user-directed): the sync semantics
  reference, centered on the 3-way fold — three versions not devices, the
  who-moved table, why a baseless 2-way merge is unacceptable, fail-loud,
  the manual authoritative-restore escape hatch.
- **`fdd3a34`** — the complete cost picture (user design decision: the
  ceiling caps **transfer only**; at-rest is **always queryable** and the
  numbers stack). `sync price`: at-rest now → after + rent ¢/day
  (`rent_cents` — the server's own tariff); `sync status`: committed
  keep-set at-rest + run-rate. Per-DID at-rest limits remain the server's
  separate lever (`Limits::did_cap`).
- **Mutation audit** (ledger + price): 39 mutants → 33 caught, 3 unviable,
  3 missed; `spent_cents → Ok(1)` killed (the suite had only ever pinned
  cents at 1), `scope()` accessor stubs excluded per the repo's
  pure-accessor convention. Re-verify: 2/2 caught.

Deferred by explicit decision: rent inside any ceiling (transfer-only cap);
statement reconciliation for the profile ledger (the multi-device blind
spot — a candidate next increment); the co-signed ceiling (E82 ADR, where
the rent-reservation question now lives).
