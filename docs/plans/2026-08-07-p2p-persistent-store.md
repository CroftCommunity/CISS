# Serverless persistence: the fs-backed iroh store + the alias index

**Status:** IN PROGRESS
**Follow-on to:** M4 (`docs/plans/2026-08-07-file-sync-m4-iroh-peer-fetch.md`,
the "Out of scope" limitation it named).
**Server change:** none.

## Problem Statement

M4's serverless converge state is process-lifetime: the iroh blob store is a
`MemStore` and the sha256→blake3 alias index is an in-memory map. The 3-way
fold's *base* (the last agreed tree) has a durable identity (its cid, in the
per-tree sqlite) but not durable *bytes* — so a serverless converge whose
base predates every running process (round 2+ across restarts, edits on both
sides) fails loud on the base fetch. Recovery today is the server path. See
`docs/SYNC-MODEL.md` §4 and the user story in the accepted proposal
(2026-08-07): Tuesday's converge works; Wednesday's — after every process
restarted and both trees changed — cannot fetch the base.

## Approach

1. **Persist the alias index** — `AliasStore` in ciss-sync (sqlite,
   path-based, same shape as `SpendLedger`): `cid → blake3`, owned by
   `SyncState` (in the tree's `state.sqlite`). `ciss-iroh` write-throughs
   every learned alias (put / learn / announcement / manifest self-prime)
   and loads the table at spawn.
2. **Persist the blobs** — the mesh's store becomes
   `iroh_blobs::store::fs::FsStore` rooted in the tree's state dir
   (`<state>/iroh/`); both store flavors deref to the same `Store` handle,
   so `IrohPeer` holds `Store` and nothing else changes. At spawn, loaded
   aliases whose blobs the store holds are marked local — the peer can serve
   (and fold from) last round's bytes with no provider at all.
3. **Wiring**: `MeshPeer::spawn` gains `persist: Option<MeshPersist>`
   (`{store_dir, aliases}`); the CLI passes it always (persistence just
   starts working — no new flags). Tests without persistence pass `None`
   and keep the hermetic `MemStore` behavior.

The proposal's P3 (consult the ChunkCache as a bytes source) is **dropped as
redundant**: the fs store retains every byte the mesh put or fetched, which
is a superset of what the cache spill holds for this purpose.

## Reasoning

- **Why sqlite for aliases and not the iroh store's own tags**: the alias is
  engine vocabulary (the C1 sha-256 ↔ transport blake3 bridge); keeping it
  beside the rest of the tree's durable state (index, placeholders, ledger)
  means one file owns the tree's memory and backup/inspection stays one
  `state.sqlite`.
- **Why the store lives under the state dir**: the state root is already
  documented as "outside the synced tree, one directory per tree" — blobs
  belong to the same lifecycle (delete the state root = forget the tree).
- **Why no providers are persisted**: providers churn; announcements and
  manifest self-priming re-teach them within one gossip round, and after P2
  the base's bytes are local anyway — the case that needed a provider after
  restart no longer exists.

## Phases (RED-first)

1. `AliasStore` unit tests (round-trip, idempotent overwrite, `all()`)
   in ciss-sync.
2. ciss-iroh persistence: spawn with persist → put → **shutdown** → respawn
   same dirs → `get` serves locally with zero providers (crate test).
3. The acceptance flow (`tests/flow_sync_p2p_restart.rs`, no `World`):
   two devices converge (round 1) → **every mesh process is dropped** →
   both trees edited → fresh meshes on the same state → round 2 converges
   to identical trees. This is exactly the Wednesday story that fails today.
4. CLI wiring, drill (real processes, kill + restart), mutants, close.

## Outcome Summary

(to be filled at close-out)
