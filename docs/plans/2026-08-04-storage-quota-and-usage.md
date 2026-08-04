# CISS storage quota + usage visibility — phased plan

- **Date:** 2026-08-04
- **Closes:** finding V5 (unbounded disk / no quota) + adds operator visibility.
- **Companion docs:** [`../SECURITY-POSTURE.md`](../SECURITY-POSTURE.md) (§10),
  [`../SECURITY-REVIEW-2026-08-03.md`](../SECURITY-REVIEW-2026-08-03.md) (V5),
  [`../DEPLOYMENT.md`](../DEPLOYMENT.md).

## Problem statement

CISS has no storage ceiling: a caller can grow disk without bound (finding V5),
and the operator has no way to see how much a DID (or the whole store) is using
against the box's disk. Both need fixing together — the quota needs the same
per-DID accounting the visibility tool reports.

## Decisions (locked)

| Decision | Value |
|---|---|
| Quota metric | **distinct bytes at rest** (dedup-aware; the real disk footprint) |
| Store ceiling | `CISS_MAX_STORE_BYTES`, **always enforced**, default **50 GiB** (box has 91 G free) |
| Per-DID cap | `CISS_MAX_DID_BYTES`, **optional**; set → enforced; **absent → opportunistic** (default) |
| Per-DID accounting | always tracked (for visibility), even when the cap is off |
| Over-quota signal | **`507 Insufficient Storage`**, distinct bodies: `store at capacity` vs `did storage quota exceeded` |
| Exposure surface | a SQLite **`did_usage` view** = the stable read API |
| First consumer | `ciss usage [--did <did>]` CLI (adds `statvfs` % math) |
| Later consumer | a loopback HTTP `usage` endpoint (C), built on the same view — deferred |

## Approach & reasoning

Enforcement is a single wall (the store ceiling) with an optional per-DID cap,
because the co-op wants DIDs to share disk opportunistically by default but retain
the ability to cap a runaway tenant. Accounting is always on so the visibility
tool is useful regardless of enforcement. Exposure is a **read surface, not a
CLI**: the usage state already lives in `meter.sqlite`, so a documented view makes
it consumable by any tool (CLI now, HTTP or monitors later) without coupling to
the binary — "expose once, write N tools." Enforcement uses the same O(1) per-DID
counters as the V3 ledger cache, extended with a distinct-`stored_bytes` column
and an O(1) global total.

---

## Phase 1 — Quota core (enforcement + accounting)

**Problem:** unbounded disk (V5); no distinct-bytes accounting.

**Done means (RED):** flow guards —
- a new store that would push the store past `CISS_MAX_STORE_BYTES` is refused
  `507` ("store at capacity");
- with a per-DID cap set, a DID's new store past it is refused `507` ("did
  storage quota exceeded");
- **a dedup write is always allowed** even when full (it adds no disk);
- **with no per-DID cap set, a DID fills opportunistically** up to the store
  ceiling (no per-DID refusal);
- reads and metering are never refused by the quota.

**Build (GREEN):**
- `persist`: add `stored_bytes` to `did_total`; add an O(1) global store total
  (a singleton row / meta). `record_new_store(did, size)` increments both in one
  transaction; `store_usage()` / per-DID `stored_bytes()` read them O(1).
- `server`: load `CISS_MAX_STORE_BYTES` (default 50 GiB) and optional
  `CISS_MAX_DID_BYTES` at startup into `AppState`; persist the **effective** limits
  to `meta` (so the view/CLI report what is actually enforced).
- `op_put_object`: `is_new = !backend.has(did, cid)`. If new, gate before writing:
  `store_total + size > ceiling → StoreFull`; `did_cap` set and
  `stored + size > did_cap → DidQuotaExceeded`. On success, after the write, call
  `record_new_store`. A dedup (`has`) store bypasses the gate and the counter.
  (Mild TOCTOU under concurrency overshoots by at most `concurrency × 2 MiB` —
  bounded and within headroom; acceptable for a resource guard.)
- `ServerError::StoreFull` / `DidQuotaExceeded` → `507`, distinct messages.

**Validation:** flow_storage_quota guards green; existing metering tests
unaffected (dedup/replay still metered).

## Phase 2 — The `did_usage` read surface (the API)

**Problem:** no stable, tool-agnostic way to read usage.

**Done means (RED):** a persist/unit test that the `did_usage` view returns, per
DID, `stored_bytes`, `upload_bytes`, `download_bytes`, `transferred_bytes`
(upload+download), and `receipt_count`, and that it stays consistent with the
counters after stores/transfers.

**Build (GREEN):**
- A SQLite `VIEW did_usage AS SELECT did, stored_bytes, upload_bytes,
  download_bytes, upload_bytes + download_bytes AS transferred_bytes,
  receipt_count FROM did_total`. Created in the migration.
- Document it (in this plan + a short "read surface" note) as the stable API:
  any tool opens `meter.sqlite` **read-only** (WAL allows concurrent reads while
  the service runs) and queries `did_usage`; the effective ceilings live in `meta`.

## Phase 3 — `ciss usage` admin CLI (first consumer)

**Problem:** the operator wants a one-shot on-box report.

**Done means (RED):** a test driving `ciss usage --data-dir <dir>` (and
`--did <did>`) that prints: the store ceiling and its **% of the partition** the
data dir is on; per-DID **stored bytes on disk**; and **cumulative transferred
bytes** alongside; with `--did` scoping to one DID.

**Build (GREEN):**
- `main`: a `usage` subcommand (argv[1]) that keeps the service invocation
  (`--data-dir`/`--listen`) unchanged; reads `--data-dir` (+ optional `--did`).
- Opens `meter.sqlite` read-only, queries `did_usage` + the `meta` ceilings.
- `statvfs` the data-dir partition (a small `libc` FFI, unix) for total/free →
  compute "ceiling as % of partition" and "used as % of ceiling / of partition".
- Print a store summary + a per-DID table (or a single-DID detail).

Illustrative output:

```
CISS storage — data-dir /var/lib/ciss (partition 99.0 GiB, 91.0 GiB free)
  store ceiling   50.0 GiB   (50.5% of partition)
  store used       0.2 MiB   (0.0% of ceiling · 0.0% of partition)
  per-DID cap      (none — opportunistic)

  DID                         stored (disk)   transferred (cum)   receipts
  id:abcd…                          1.2 GiB            3.4 GiB         412
  id:ef01…                          8.0 GiB            9.1 GiB        1203
```

## Phase 4 — croft-stack unit wiring

**Build:** emit `Environment=CISS_MAX_STORE_BYTES=…` (and optionally
`CISS_MAX_DID_BYTES=…`) into the generated `ciss.service`, via a per-tenant
manifest field (the `healthz_allowlist` / `provider_seed_credential` pattern),
scoped to ciss only; other tenants byte-identical; render tests TDD-first; no
deploy. (Executed in the croft-stack repo.)

## Phase 5 — Posture + docs

**Build:** add a V-series invariant to `SECURITY-POSTURE.md` ("distinct bytes at
rest are bounded by the store ceiling; per-DID cap optional; a dedup write never
consumes quota"); note the `did_usage` read surface in `README`/`CLAUDE.md`;
mark V5 closed in the security review.

## Definition of done

- The store ceiling is enforced; the optional per-DID cap works; opportunistic is
  the default; dedup writes never consume quota — all with green flow guards.
- `did_usage` is a documented, concurrent-read-safe API; `ciss usage` reports
  ceiling/%-partition/per-DID stored/transferred, with a `--did` filter.
- croft-stack sets the ceilings; posture doc + review updated.

## Deferred (tracked)

- **(C) loopback HTTP `usage` endpoint** — a second consumer of `did_usage`, built
  after Phases 2–3 if wanted.
- **Global disk ceiling as an ops backstop** (filesystem quota / disk alert on
  `/var/lib/ciss`) — complements the app-level store ceiling.
- **Per-DID cap as a stored policy attribute + admin API** — the env cap is the
  interim; a per-DID policy store is the graduation.
