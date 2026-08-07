# M4 — iroh peer-fetch: the same sync runs over iroh, and blobs can come from a peer

**Status:** CLOSED — all phases shipped
**Parent plan:** `docs/plans/2026-08-07-file-sync-client.md` (M4 section)
**Server change:** none — CISS becomes one blob source among peers.

## Problem Statement

M1–M3 built a complete own-device sync (chunk → backup/restore → bounded
footprint → two-device converge), but every byte moves through CISS: all reads
are metered origin egress, and a device pair on the same LAN still round-trips
the server. Every `ChunkRef` has carried a blake3 hash since M1 *for exactly
this milestone* — the engine was designed so a peer-to-peer, blake3-addressed
transport could slot in under the same `BlobTransport`/`ManifestSlot` seams
without touching the engine or the server. M4 cashes that in: blobs can be
fetched from a peer device (Bao-verified streaming), and the whole converge
flow can run device↔device over iroh-gossip with the server offline.

## Approach

Two phases behind the existing seams; zero engine-semantics change; zero server
change.

1. **P1 — `IrohPeer`: `BlobTransport` over iroh-blobs, plus `PeerFirst`
   fallback.** New workspace crate `crates/ciss-iroh` (mirrors the HttpCiss
   placement rule: transport impls live outside the engine). `IrohPeer` keys by
   the canonical sha-256 cid (C1 stays the address of record) and maintains an
   internal sha256→(blake3, providers) index; bytes live in an iroh-blobs
   `MemStore` served via `BlobsProtocol` behind a `Router`. `get` resolves the
   blake3, downloads from a provider if local-missing (Bao verifies blake3 in
   transit), then **re-verifies sha-256 on receipt** — C1 enforcement is not
   delegated to iroh. `PeerFirst` composes `IrohPeer` over an origin
   `BlobTransport`: `get` tries the peer, falls back to origin per blob
   (including on integrity mismatch — a poisoned sha256→blake3 mapping degrades
   to an origin fetch, never to wrong bytes); `put`/`have` delegate to origin
   (the keep-set and billing semantics of backup are unchanged).

2. **P2 — serverless converge over iroh-gossip.** `IrohPeer` additionally
   implements `ManifestSlot` + `AccountKey`, making `converge()` run unchanged
   with no server: `frontier()` is the union-by-device of gossip head
   announcements (per-device newest `counter` wins — each device only ever
   writes its own slot, so no cross-device CAS is needed; `DeviceHead` records
   stay self-verifying exactly as in M3); `commit_frontier` records own heads
   locally and broadcasts an announcement. The announcement carries only two
   hash-pairs — `(head_cid_sha256, head_blake3)` and `(fs_root_sha256,
   fs_root_blake3)` — everything else is derivable: fetch the head, decode
   (signature-verified), fetch the fs-manifest, and every `ChunkRef` inside it
   populates the sha256→blake3 index. Topic = `sha256("croft.sync-topic/v1:" +
   account_pubkey_z32)` — both devices derive it independently
   (`discovery/alpha/thinking/multi-device.md` §10: TopicId = derive(lineage
   root); the lineage root today is the shared account key). CLI:
   `ciss-ctl sync p2p share` (serve + announce; prints a base64 JSON ticket of
   the local `EndpointAddr`) and `ciss-ctl sync p2p converge --ticket <t>`.

## Reasoning

- **Why a new crate, not a feature in ciss-sync:** the iroh stack is heavy
  (~450 deps); the engine stays lean and its consumers (a future GUI, the meer)
  don't inherit iroh. Same dependency-direction logic that put `HttpCiss` in
  ciss-cli (M1 OQ1).
- **Why sha-256 stays the key:** C1 says the server names content by sha-256;
  the engine, manifests, and keep-set all speak it. blake3 is a transport-level
  alias carried since M1. Re-verifying sha-256 on every peer-served blob means
  a malicious/buggy peer (or poisoned mapping) can waste a fetch but never
  corrupt a tree — the same fail-closed posture as the M1 tamper guard.
- **Why union-by-device replaces the seq-CAS serverless:** I5's monotonic seq
  exists to serialize *shared-slot* writes on one server. Serverless, each
  device is the sole writer of its own head slot and `DeviceHead.counter`
  (signed) already gives per-writer ordering — union + newest-counter is the
  natural CRDT of that structure, and `converge`'s decode-verify step remains
  the integrity gate. No new trust is granted: same shared account key as M3.
- **Why LAN-first (no relay/discovery infra):** relay selection and n0/global
  discovery are deployment posture (croft-stack), not engine semantics. The
  ticket carries full direct addresses; `presets::Minimal` +
  `RelayMode::Disabled` keeps the probe-verified surface. Relay enablement is a
  flag away when wanted (out of scope, noted below).

## Phase 0 — discovery (DONE, probes in session scratchpad)

Pinned versions: **iroh 1.0.3, iroh-blobs 0.103.0, iroh-gossip 0.101.0**
(current patch releases of the FACTCHECK-registered 1.0.0/0.102/0.100 lines);
MSRV 1.91 ≤ pinned toolchain 1.97.1; probes built and ran on rustc 1.97.1.
Core endpoint surface was already source-verified in
`experiments/alpha/iroh/relay-lab-runs/IROH-1.0.0-API-VERIFIED.md`.

Verified by running probes (two endpoints, loopback, `RelayMode::Disabled`):

- `store.blobs().add_bytes(bytes)` → tag whose `hash` **is byte-identical to
  `blake3::hash(bytes)`** — every `ChunkRef.blake3` is directly the iroh
  address, no re-hash needed.
- Serve: `BlobsProtocol::new(&store, None)` +
  `Router::builder(ep).accept(iroh_blobs::ALPN, blobs).spawn()`.
- Fetch: `store.downloader(&endpoint).download(hash, Some(node_id)).await` with
  the provider's `EndpointAddr` registered in the fetcher's `MemoryLookup`;
  `blobs().has(hash)` / `get_bytes(hash)` for local checks. Fetched bytes
  byte-identical; sha-256 recomputation matches.
- Endpoint recipe: `Endpoint::builder(presets::Minimal)
  .address_lookup(MemoryLookup).relay_mode(RelayMode::Disabled)
  .bind_addr(127.0.0.1:0)` (`presets::Empty` fails: no rustls crypto provider).
- Gossip: `Gossip::builder().spawn(ep)` + accept `GOSSIP_ALPN`;
  `subscribe_and_join(topic, bootstrap_ids)` → `(GossipSender,
  GossipReceiver)`; `sender.broadcast(Bytes)` delivered as
  `Event::Received(msg)`, content intact; `TopicId::from_bytes([u8; 32])`
  accepts a sha-256 digest.

## Phases

### P1 — `IrohPeer` blob path + `PeerFirst` fallback

RED-first, in `crates/ciss-iroh` (crate tests use an in-memory origin mock —
no CISS `World` dependency inside the crate):

1. `IrohPeer` put→have→get local roundtrip, sha-256 keyed (put verifies the
   cid matches the bytes — same contract HttpCiss enforces).
2. Two `IrohPeer`s on loopback: A `put`s, B learns the mapping + provider,
   B `get`s → bytes identical, sha-256 verified.
3. A **poisoned mapping** (sha256 key → blake3 of different content) on `get`
   fails closed with a cid-naming error (crate level), and through `PeerFirst`
   degrades to an origin fetch with correct bytes (fallback level).
4. `PeerFirst`: `get` prefers peer, falls back per blob when the peer lacks
   it; `put`/`have`/`ManifestSlot`/`AccountKey` delegate to origin untouched.

Workflow tier (root `tests/flow_sync_peer_fetch.rs`, real `World` origin):
backup to CISS, seed a peer, restore via `PeerFirst` → tree byte-identical
AND the origin served strictly fewer blob gets than the blob count (peer-fetch
= less metered egress, observed not asserted-by-faith).

### P2 — serverless converge over gossip

RED-first:

1. `ManifestSlot` on `IrohPeer`: commit_frontier records own heads + rebroadcast;
   frontier() unions announcements by device with newest-counter-wins (unit).
2. Announcement decode is fail-closed (unknown/garbled announcement ignored,
   never folded — the DeviceHead signature check in converge remains the gate).
3. Workflow tier (`tests/flow_sync_p2p_converge.rs`, **no `World` at all** —
   the server is offline by construction): two devices, disjoint + same-path
   conflicting edits, `converge()` each over gossip+blobs → identical trees,
   conflict-copy preserved on both (same assertions as `flow_sync_converge`).
4. CLI wiring: `sync p2p share` / `sync p2p converge --ticket <t>`.

### Close-out

Live drill (two real processes on loopback, server untouched), mutation audit
on the index/fallback and frontier-union code, plan Outcome Summary, PR, CI
green, merge, stamp milestone plan + memory.

## Quality gates

- `cargo test --workspace` + `cargo clippy --all-targets --workspace` clean
  before each commit; **no `cargo fmt`** (hand-format).
- Every integrity guard RED-first: poisoned mapping, cid mismatch on peer
  bytes, garbled announcement.
- `cargo mutants` on `ciss-iroh` mapping/fallback + frontier-union modules
  once green (encoder/state-machine shape).

## Out of scope (follow-ons)

- Relay + global discovery posture (`presets::N0`, relay URLs) — croft-stack
  deployment concern; the engine seam is a builder flag.
- RBSR set reconciliation, croft-group multi-lineage sync, bilateral receipts
  (parent plan "Future" section).
- Persistent iroh blob store (`MemStore` now; the ChunkCache remains the
  durable local layer — an fs-backed iroh store is an optimization). This has
  a concrete consequence worth naming: the sha256→blake3 alias index and the
  blob store are **process-lifetime**, so a *serverless* converge whose 3-way
  base predates the current processes (round 2+ across restarts, with edits
  on both sides) fails loud on the base fetch ("no mapping"). Recovery today:
  converge via the server path (M3), or keep the sharing process alive across
  rounds. A persistent store/alias layer is the follow-on that dissolves this.

## Outcome Summary

All phases shipped on `ciss-m4`; server change: **none** (as planned).

- **Phase 0 (discovery)** — `1322781` (plan incl. verified-assumptions
  ledger). Probes pinned iroh 1.0.3 / iroh-blobs 0.103.0 / iroh-gossip
  0.101.0 (MSRV 1.91 ≤ toolchain 1.97.1) and the exact API surface; the
  key fact: `add_bytes`' hash IS `blake3(bytes)`, so every `ChunkRef.blake3`
  is directly the iroh address.
- **Phase 1 (`IrohPeer` + `PeerFirst`)** — `11da13b`. New crate
  `crates/ciss-iroh`. Flow test: a restore through `PeerFirst` served every
  chunk from the peer; the origin's blob egress was exactly **one get** (the
  fs-manifest). Poisoned-alias and lying-cid guards RED-first; sha-256
  re-verified on receipt (C1 never delegated to Bao).
- **Phase 2 (`MeshPeer` serverless converge)** — `4ee319c`. `converge()`
  runs unchanged over gossip+blobs; flow test has **no `World` at all**.
  CLI: `sync p2p share` (ticket = base64-JSON `EndpointAddr`) and
  `sync p2p converge --ticket`.
- **Live drill** — two real `ciss-ctl` processes, two profiles sharing the
  account key, disjoint + same-path-conflict trees: both converged to
  fs-manifest `1ceb3f7c…`, `diff -r` byte-identical, conflict preserved as
  `notes.txt.conflict-6e63cebc` on both, **server never contacted**.
- **Mutation audit** (`cargo mutants -p ciss-iroh`, close-out commit) —
  baseline 98 mutants: 47 caught, 16 unviable, **35 missed**. Every survivor
  was one of the two cheap patterns the CLAUDE.md guidance names (a
  delegation-only trait impl no crate test called; a convenience API with no
  behavioral assertion) — none was a logic gap in the fetch/verify/merge
  paths. All 35 closed with kill tests: `PeerFirst` delegation round-trip,
  shutdown-stops-serving (both types), hand-crafted-announcement wire-format
  pin, mesh keep-set slot + `StaleSeq` refusal, and manifest-self-priming
  chunk fetch. Targeted re-run: every family killed except the two
  `shutdown → ()` mutants, which are **equivalent** — `shutdown(self)`
  consumes self, so a no-op body still drops (and thereby closes) the
  router/endpoint; the stops-serving tests pass under both bodies. Recorded
  in `.cargo/mutants.toml` per the repo convention.

Discoveries recorded along the way:

- A raw gossip broadcast that races mesh formation is silently lost —
  only *committed heads* are re-announced on `NeighborUp`. Tests (and any
  future one-shot messaging) must rebroadcast-until-seen.
- `presets::Empty` fails at bind with "missing rustls crypto provider";
  `presets::Minimal` is the floor (matches the corpus's
  `IROH-1.0.0-API-VERIFIED.md`).
- The announcement only ever needs two hash-pairs: everything deeper
  (chunks, base) is derivable because a fetched fs-manifest self-primes the
  alias index — the closure walk needs no further introductions.
