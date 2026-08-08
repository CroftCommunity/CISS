# Metered transports + meter reconciliation

**Status:** CLOSED — shipped
**Follow-on to:** the spend-ledger work (`2026-08-07-spend-ledger-periods-and-profile-ceiling.md`).
**Server change:** none (the client reads the existing owner-only `GET /{did}/meter`).

## Problem Statement

Two related defects in the cost twin, one shipped and one structural:

1. **The ceiling meters free transfers.** `push_tree` checks the ceiling and
   records spend for *every* transport — including the p2p mesh, whose
   transfers cost nothing on the real bill (less metered egress is M4's
   point). Today an exhausted ceiling defers a serverless sync that would
   have been free, and the ledger inflates with unbilled bytes. E89's rule
   is about *billed* spend; the twin must price what the meter prices.
2. **The profile ledger only sees this device.** Each device self-records
   its transfers; another device on the same account spends against the
   same real bill invisibly. The server's `/meter` already exposes the
   account truth — cumulative transferred bytes across every device,
   owner-only — but nothing reads it back into the ledger.

(The fuller fix — per-period statements with rent — exists server-side only
as a library; the statement-close scheduler is an explicit SEAM. When that
endpoint lands, it supersedes the baseline arithmetic below; the ledger
schema needs nothing new for it.)

## Approach

1. **`BlobTransport::metered()`** (default `true`): `HttpCiss` is metered;
   `IrohPeer`/`MeshPeer` are not; `PeerFirst` is metered (its writes go to
   the origin). `push_tree` checks ceilings and records spend **only when
   the transport is metered** — a free transfer is never deferred and never
   ledgered.
2. **Reconciliation against `/meter`** — `sync ceiling --reconcile`:
   - The profile ledger keeps a `baseline_bytes` marker (config): the
     meter's `running_total_bytes` at the moment the current view began.
   - First reconcile initializes `baseline = meter_total − local_spent`
     (adopts the ledger's history without double-counting).
   - Each reconcile computes `account_spent = meter_total − baseline` and
     records the positive difference vs the local ledger as a catch-up row —
     the spend other devices did. The meter is monotonic and (after fix 1)
     a superset of the ledger, so a negative difference is a WARN, not an
     adjustment.
   - Explicit, not automatic: reconciliation needs the server; ceiling
     checks stay local and offline-capable. (Auto-reconcile-on-backup can
     be layered later as a flag.)

## Reasoning

- **Why `metered()` on the transport and not a flag on the call**: whether
  bytes are billed is a property of *where they go*, known to the transport
  and nothing else. The default `true` fails safe — an unknown transport is
  assumed billed, so the ceiling over-protects rather than under-protects.
- **Why baseline arithmetic instead of per-receipt sync**: `/meter` exposes
  cumulative totals, not receipts-by-range; a monotonic baseline plus
  differences is exact for cumulative counters and needs no new endpoint.
  It is also timestamp-free — the baseline is a byte-count marker, not a
  moment.
- **Why explicit reconcile**: the ceiling must keep working offline and in
  p2p-only use; making its correctness depend on server reachability would
  invert the M4 posture.

## Phases (RED-first)

1. **A — metered transports.** Unit: ledger check skipped/recorded per
   `metered()`. Flow: with the ceiling exhausted, a p2p backup still runs
   and the ledger gains nothing; the server path still defers.
2. **B — reconcile.** Unit: baseline arithmetic (first-reconcile adoption,
   catch-up delta, negative-delta WARN path). Flow (`World`): device A
   backs up (ledger + meter agree); a second session on the same DID
   uploads bytes A never saw; A reconciles → the profile ledger now shows
   the account total; the ceiling binds against it.
3. CLI (`sync ceiling --reconcile`), docs, mutants, close.

## Outcome Summary

Shipped on `ciss-meter-reconcile`. Server change: none.

- **A — `BlobTransport::metered()`** (default `true`, fail-safe): `IrohPeer`
  and `MeshPeer` return `false`, `PeerFirst` follows its origin. The push
  path checks ceilings and records spend only when metered. The RED flow
  test caught the shipped bug live: an exhausted ceiling was deferring a
  free p2p backup; now the transfer runs and the ledger gains nothing,
  while the server path still defers.
- **B — `SpendLedger::reconcile_to_meter`**: baseline arithmetic against
  the meter's cumulative account total. First reconcile of a period adopts
  (`baseline = meter − local`; history and other periods are never charged
  to this one); later reconciles record the positive delta — spend other
  devices did, and unledgered download postage — as catch-up rows; a local
  ledger ahead of the meter is surfaced (`LocalAhead`), never subtracted.
  Timestamp-free: the baseline is a byte-count marker. CLI:
  `sync ceiling --reconcile` (targets the profile ledger — account truth ↔
  account twin).
- Flow evidence: a bare same-account upload this ledger never saw is pulled
  in exactly (`CaughtUp {250_000}`), and the profile ceiling then defers
  the next sync against the *account* total.
- Mutants (ledger.rs incl. reconcile): **47 → 44 caught, 3 unviable, 0
  missed**. Workspace 68 suites green; clippy-pedantic clean.

Superseded-by note: when the server's statement endpoint lands (the
statement-close scheduler SEAM), per-period rent+postage reconciliation
replaces the baseline arithmetic; the ledger schema needs nothing new.
