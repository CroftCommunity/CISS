# CISS file-sync — M2 execution plan (bounded local footprint)

date: 2026-08-07
status: **CLOSED (2026-08-07). All three phases shipped; M2 delivered:** *local footprint is bounded
regardless of logical tree size* — `ciss-ctl sync evict|hydrate|status`.

## Outcome Summary

| Phase | Outcome | Commit | Note |
|---|---|---|---|
| 1 state/cache/placeholder | ✅ | `941d0f9` | primitives; mutants 41 caught / 0 missed (1 timeout = kill) |
| 2 evict + logical-tree backup | ✅ | `f721203` | no-data-loss guard (identical fs-manifest cid across evict); live drill green |
| 3 hydrate | ✅ | `2d022bd` | cache read-through (0 metered gets on hit); shared materializer; live drills green |
parent: `docs/plans/2026-08-07-file-sync-client.md` (milestone ladder; this doc executes **M2**).
skill: authored under the `phase-plan` workflow (abbreviated passes — see Review Log).

## Problem Statement

Deliver **M2**: *"local footprint is bounded regardless of logical tree size."* After M1, a backed-up
tree's bytes all live locally AND on the server. M2 lets a device **evict** cold files (drop the local
bytes, keep the logical entry) and **hydrate** them back on demand — so the logical tree can be larger
than the disk it syncs from. Server change: **none.** The dangerous edge is silent data loss: an evicted
file must never fall out of the fs-manifest/keep-set (a later backup that "forgets" evicted entries would
GC their chunks server-side), and eviction must be refused unless the bytes are provably on the server.

## Reasoning

**Placeholders are state-records, not stub files.** An evicted file is *absent from disk* and recorded in
the sync state DB. Rejected: zero-byte stub files (they masquerade as real empty files to every other
program — silent corruption by another name) and xattr/sparse tricks (platform-specific, M4+ concern).
"Hydrate on access" without a VFS layer means an explicit `sync hydrate` (FUSE/File Provider integration
is out of scope for a CLI milestone; the engine API is what a future VFS would call).

**The logical tree = scanned files ∪ placeholders.** `backup` must merge placeholder entries into the
manifest it commits — this is the no-data-loss invariant, and it lands RED-first before any evict code
exists. A file that reappears locally wins over its placeholder (the placeholder is dropped).

**The chunk cache is the footprint dial and the M4/M5 seam.** Evict may spill chunks into a budgeted
content-addressed cache (cheap re-hydrate, zero metered egress); hydrate reads through it (cache hit =
no server fetch = no download receipt — the economics are observable and tested). LRU + pinned flag;
"starred/working-set" pin *policies* stay M3+ — the mechanism (a pin bit) ships now.

**A per-tree state root** (`$XDG_DATA_HOME/ciss-ctl/sync/<tree-id>/`, `--state-dir` override; `tree-id` =
sha-256 of profile + canonical path, first 16 hex) holds the scan index (M1's, now actually wired into the
CLI), the placeholder table, config (cache budget), and the cache dir. The state root must live outside
the tree (M1 learning: scanning your own mutating sqlite poisons the manifest).

## Verified Assumptions

- M1 base (all shipped, `docs/plans/2026-08-07-file-sync-m1-chunk-and-backup.md`): `scan_tree_indexed` +
  `Index` (hit/miss counters); `BlobTransport`/`ManifestSlot` seams; `verify_content` engine-layer check;
  restore's per-file verify-before-rename materializer (Phase 3 refactors it into a shared helper —
  hydrate is restore-for-one-file); `backup` flow at `backup.rs` (Phase 2 inserts the placeholder merge).
- `ciss-cli/src/config.rs` resolves `$XDG_CONFIG_HOME`/`$HOME/.config` manually — the data-dir resolution
  mirrors it (`$XDG_DATA_HOME`/`$HOME/.local/share`), no new dependency.
- No new crates: rusqlite/sha2/serde/tracing all present in `ciss-sync`.

## Documentation Impact

- `README.md` — `sync evict|hydrate|status` lines in the client section. **Phase 3.**
- `docs/plans/2026-08-07-file-sync-client.md` — M2 status stamp at close-out. **Phase 3.**
- Module docs in new `ciss-sync` files (`state.rs`, `cache.rs`, `placeholder.rs`, `hydrate.rs`). **Each phase.**

## Concurrency Map

**All phases sequential** (each builds on the prior's write-set in `crates/ciss-sync/**`). No worktrees.

## Phases

### Phase 1: state root + chunk cache + placeholder store (pure) — ✅ SHIPPED (`941d0f9`)
**Goal:** the three storage primitives, fully unit-tested offline.
**Changes:**
- [ ] `state.rs`: `SyncState::open(state_dir)` — one sqlite (`state.sqlite`: scan_index [reuse `Index`
  schema], placeholders, config KV) + `cache/` dir; `tree_id(profile, path)` helper.
- [ ] `cache.rs`: `ChunkCache` — `insert(cid, bytes)`, `get(cid) -> Option<Vec<u8>>` (verified against
  cid on read — a corrupt cache entry is deleted + treated as a miss, fail-safe not fail-open),
  `pin/unpin(cid)`, budget enforcement on insert: evict LRU unpinned until `total ≤ budget`; a single
  blob larger than the budget is refused, never stored-then-immediately-evicted.
- [ ] `placeholder.rs`: `PlaceholderStore` — `record(path, &FileEntry)`, `remove(path)`, `get(path)`,
  `all() -> BTreeMap<String, FileEntry>` (entry serialized as DAG-CBOR, like the index).
**Test-first order (RED → GREEN):** `cache_budget_lru` (inserts beyond budget evict oldest-accessed
unpinned; pinned survive; get refreshes recency; edges: exact-budget fit, oversize refusal, budget 0),
`cache_corrupt_entry_is_a_miss` (flip a byte in a cached file → get returns None and removes it),
`placeholder_roundtrip` (record/get/all/remove; entries survive reopen), `state_reopen` (config KV +
tables persist).
**Wiring test:** crate-level `crates/ciss-sync/tests/state_cache.rs` through the public API only
(pure-lib phase; CLI wiring is Phases 2–3).
**Done when:** `cargo test -p ciss-sync` green incl. the new suites.
**Validation:** Narrow — unit + crate-integration sufficient. Mutation audit: `cargo mutants` scoped to
`cache.rs` (the LRU/budget boundary logic) once green.

### Phase 2: evict + placeholder-aware backup (`sync evict`, `sync status`) — ✅ SHIPPED (`f721203`)
**Goal:** drop a file's local bytes safely; the logical tree survives every later backup.
**Changes:**
- [ ] `evict.rs`: `evict(dir, state, server, paths) -> EvictReport` — per file: entry from the current
  scan; **refuse unless every chunk cid is in the server's have-set AND in the committed keep-set
  manifest** (both: `have` proves the bytes exist, the keep-set proves billing/GC protection); spill
  chunks into the cache within budget (best-effort, never a failure); record placeholder; delete the
  file. INFO per eviction (path, bytes freed, chunks cached); ERROR naming the unbacked chunks on refusal.
- [ ] `backup.rs`: merge `PlaceholderStore::all()` into the scanned manifest (file-on-disk wins and drops
  its placeholder; placeholder fills in for an absent file) — the manifest/keep-set never shrinks from an
  eviction. `backup` gains an optional `&SyncState` (index + placeholders together).
- [ ] CLI: `sync evict <dir> <path>...`, `sync status <dir>` (present/evicted per file, cache usage vs
  budget, keep-set seq); `sync backup` now opens the state root by default (wires M1's index in —
  `--state-dir` override, `--no-state` opt-out).
**Test-first order (RED → GREEN):** flow `tests/flow_sync_footprint.rs` —
1. `backup_preserves_evicted_entries` (**the no-data-loss guard, RED-first**): backup → evict a file →
   backup again → the new fs-manifest still contains the evicted entry; the keep-set still names all its
   chunks; local file absent.
2. `evict_refuses_unbacked_file` (**integrity guard**): a file modified after its last backup (or never
   backed up) is refused with the unbacked chunk cids named; the file is untouched.
3. `evicted_file_restores_cleanly`: M1's `restore` of the tree elsewhere still reproduces the evicted
   file byte-identically (server-side truth unaffected by local eviction).
**Done when:** `cargo test -p ciss --test flow_sync_footprint` green; behavioral: after evict, local
bytes shrink, `sync status` shows the file as evicted, and a re-backup changes nothing server-side.
**Validation:** Moderate — flow + unit + a live CLI pass (evict against the real server, `sync status`,
re-backup, `du` unchanged).

### Phase 3: hydrate (`sync hydrate`) + the footprint capability end-to-end — ✅ SHIPPED (`2d022bd`)
**Goal:** bytes come back on demand — from the cache when possible, the server when not — verified.
**Changes:**
- [ ] Refactor restore's per-file materializer (fetch chunks → verify each → assemble → verify size →
  tmp-write → mode/mtime → rename) into a shared `materialize.rs` used by both `restore` and `hydrate`
  (no drift between the two verified-write paths).
- [ ] `hydrate.rs`: `hydrate(dir, state, server, paths|all) -> HydrateReport` — per placeholder: chunks
  via cache read-through (hit = no server fetch; miss = `transport.get` + populate cache within budget),
  materialize, drop the placeholder, refresh the index. **Refuses to overwrite an existing file** (a
  reappeared file wins; fail loud, never clobber).
- [ ] CLI: `sync hydrate <dir> [<path>...]` (default: all placeholders); README + milestone-plan doc
  updates.
**Test-first order (RED → GREEN):** extend `flow_sync_footprint.rs` —
4. `footprint_bounded_while_tree_grows` (**the M2 capability gate**): tree larger than the budget →
   backup → evict to fit → local bytes ≤ budget while the keep-set covers the whole tree → hydrate one
   file → byte-identical (content + mode + mtime).
5. `cache_hit_hydrate_fetches_nothing` (a counting transport wrapper): evict with cache spill → hydrate
   → zero `get` calls reach the server (the metered-egress win, observable).
6. `eviction_never_loses_data`: evict, wipe the cache entirely → hydrate refetches from the server and
   verifies (M1's tamper guard inherited via the shared materializer).
7. `hydrate_refuses_overwrite`: place a new file at an evicted path → hydrate refuses; the file is
   untouched; backup prefers the on-disk file and drops the placeholder.
**Done when:** the full flow suite green; behavioral: a directory whose logical size exceeds local disk
budget round-trips through evict → status → hydrate with every byte verified.
**Validation:** Moderate — flow + unit + a live drill: real server, evict a big file, `sync hydrate`,
`diff`; then wipe the cache and hydrate again (server path). Mutation audit: `cache.rs` +
`placeholder.rs` survivors triaged.

## Open Questions — resolved by default (user delegated execution 2026-08-07; overrides welcome)

- **Placeholder representation** — RESOLVED: absent file + state-DB record (stubs masquerade; see
  Reasoning). *ADVISORY.*
- **State root location** — RESOLVED: `$XDG_DATA_HOME/ciss-ctl/sync/<tree-id>/` (mirrors config.rs's
  XDG resolution), `--state-dir` override. *ADVISORY.*
- **Cache budget default** — RESOLVED: 256 MiB, persisted in state config, `--cache-budget` to change.
  *ADVISORY.*
- **Pin policy scope** — RESOLVED: the pin *mechanism* (bit + never-evict) ships; recent/starred/
  working-set *policies* deferred to M3+ where the working set becomes observable. *ADVISORY.*

## Review Log

- **2026-08-07 (abbreviated passes, one context)** — Pass 1: plan authored from the milestone M2 slice on
  shipped M1 ground. Pass 2 checks folded in: placeholder-merge is in `backup.rs` (not a wrapper) so every
  caller inherits it; evict requires *both* have-set and keep-set membership; the cache verifies on read
  (fail-safe); hydrate shares restore's materializer (single verified-write path); state root outside the
  tree (M1 learning). Pass 3 gates: every guard named RED-first above (no-data-loss, refuse-unbacked,
  budget/LRU, corrupt-cache-is-miss, refuse-overwrite, cache-hit-zero-fetch); tracing spec'd per flow;
  validation calibrated (narrow/moderate/moderate); concurrency map all-sequential; docs scheduled in the
  phases that stale them; mutation target `cache.rs`+`placeholder.rs`.

### Plan close-out — 2026-08-07
**Shipped:** all three phases, one session, on the M1 spine. `941d0f9` (SyncState root + budgeted
ChunkCache with deterministic counter-LRU/pin/verify-on-read + PlaceholderStore), `f721203` (evict with
the both-sides backed gate; backup commits the logical tree = scanned ∪ placeholders; cache-recovery
re-upload for server-lost chunks; CLI evict/status; backup state-wired by default — closing the M1
follow-up), `2d022bd` (hydrate via cache read-through + the shared verify-before-rename materializer;
CLI hydrate). Observable: a tree larger than the local budget round-trips evict → status → hydrate
byte-identically (content+mode+mtime); an eviction can never change the committed tree (identical
fs-manifest cid proven) nor lose data (cache wiped → server refetch, verified); a cache-hit hydrate
performs zero metered fetches.
**Stopped or skipped:** nothing. Pin *policies* (recent/starred/working-set) deferred as planned — the
mechanism shipped.
**Discoveries:** (1) the placeholder merge belongs inside `backup` (any wrapper would eventually be
bypassed — the no-data-loss invariant must sit on the committed path); (2) an evicted file whose chunks
the server loses is recoverable from the spill cache — that fallback turned the cache from a pure
optimization into a second line of defense; (3) `backup --no-state` had to *refuse* when placeholders
exist (a stateless backup would silently shrink the tree — caught at design time); (4) zsh's no-word-split
default bit the live drill script (`$FLAGS` as one word), worth remembering for future drills.
