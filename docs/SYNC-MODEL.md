# The sync model — how `ciss-ctl sync` thinks

The reference for the file-sync client's semantics: what a tree commit is,
how two devices converge without either being in charge, exactly what the
3-way fold does and why it needs its third input, and what happens when that
input is unavailable. Commands and walkthroughs live in `CLIENT.md`; this
document is the model. Built across milestones M1–M5
(`docs/plans/2026-08-07-file-sync-*.md`).

## 1. A tree is content, addressed

A backup chunks every file (FastCDC, content-defined boundaries) and writes a
**fs-manifest**: `path → {mode, mtime, chunk refs, size}`, serialized
canonically (DAG-CBOR) and stored as a blob whose address is the sha-256 of
its own bytes. Each chunk ref carries two hashes of the same bytes — sha-256
(the CISS address) and blake3 (the iroh address). Identical content anywhere
in any tree is the same chunk: dedup, rename detection, and "what changed"
all fall out of addressing, with no machinery.

Two facts follow that everything else builds on:

- **Two trees are equal iff their fs-manifest cids are equal.** Comparing a
  whole directory is one string comparison.
- **mtimes are restored metadata, never evidence.** A timestamp is an
  assertion by whichever clock wrote it; nothing in sync ordering, conflict
  resolution, or accounting ever consults one. (The same rule governs the
  spend ledger: monotonic counters are the authority, timestamps are
  reference.)

## 2. Devices publish heads; nobody is in charge

Each device publishes its tree as a signed **DeviceHead** — `{device_id,
counter, fs_root, parent, base}`, signed by the account key, every field
bound by the signature. The shared **frontier** is a map `device_id →
head-cid` in which *each device only ever writes its own slot* (on the
server, under the manifest's monotonic-seq CAS; serverless, as gossip
announcements ordered by the head's own signed counter).

There is deliberately **no primary**. No device is authoritative, no server
mints a HEAD, and no election happens. The current tree is *derived*, not
decreed: every device runs the same pure function over the same inputs and
must land on the same answer.

## 3. The fold: three versions, two devices

`sync converge` computes a **3-way merge**. The "3" counts *versions*, not
devices:

```
              base   ← the last tree both devices agreed on
             /    \      (the previous converge's result — a VERSION,
     A's tree      B's tree                 not a third machine)
             \    /
              fold   → deterministic; both devices derive the SAME tree
```

The base exists to answer the one question two current trees cannot answer
alone: **who moved?** Per path:

| base | A now | B now | verdict |
|---|---|---|---|
| v1 | v1 | v1 | unchanged |
| v1 | v2 | v1 | A edited; B didn't move → **v2**, no conflict |
| v1 | *absent* | v1 | A deleted; B didn't move → **deletion propagates** |
| v1 | *absent* | v2 | delete vs edit → **the edit wins** (non-lossy default) |
| v1 | v2 | v3 | both moved, differently → **conflict** (below) |
| — | v1 | — | A added → v1 |

A real conflict is never resolved by guessing and never lossy: the
content-address tiebreak (smallest entry digest — a pure function of the
bytes, so every device picks the same winner) keeps the path, and the loser
is preserved as `<path>.conflict-<device_id>` — **both contents, on both
devices**.

### Why a 2-way merge is not an acceptable fallback

Without the base, "A lacks `notes.txt`, B has it" is *byte-for-byte
indistinguishable* from "B just created `notes.txt`". A baseless merge must
guess, and both guesses are bad: union resurrects every deletion on every
converge; conflict-copying everything that differs buries the tree in noise.
This is why the engine **fails loud** when it cannot fetch the base rather
than silently downgrading — a converge that cannot be correct refuses,
corrupting nothing.

### Self-healing, and the escape hatch

Because the fold is deterministic, convergence needs no coordination round:
after A folds and republishes, B's converge re-derives the *identical* tree
(same fs-manifest cid) and both devices settle in two rounds.

If you ever *want* one side to be authoritative, that is a manual act, not a
merge outcome: `sync restore --manifest <cid>` (or plainly overwriting a
tree and backing it up) declares a winner deliberately. The fold will never
do it for you.

## 4. Where the base's bytes come from

The base's *identity* (its cid) is durable — each device records it in its
per-tree state (sqlite) at every converge. Its *bytes* must be fetchable at
fold time:

- **Server path** (`sync converge`): always available — the keep-set retains
  every head's closure including bases, so the base manifest is one verified
  `GET` away. Restart-proof.
- **Serverless path** (`sync p2p converge`): durable too — the mesh's blob
  store is fs-backed under the tree's state root and the sha256→blake3
  alias index persists in the same sqlite, so the base's bytes and identity
  both survive any number of process restarts (the acceptance test:
  converge, kill every process, edit both trees, converge again). A peer
  running *without* persistence (the hermetic in-memory posture) keeps the
  old lifetime and the old fail-loud behavior; the fold's semantics never
  change either way.

## 5. Serverless is the same model, minus the middleman

Over iroh (`sync p2p`), blobs move peer-to-peer (blake3/Bao verified in
transit, sha-256 re-verified on receipt — the CISS address is never taken on
faith) and the frontier rides gossip on a topic derived from the account
key. Ordering authority changes shape but not trust: the server's
monotonic-seq CAS is replaced by each head's own signed per-device counter
(newest wins, per slot). Announcements are hints; nothing is folded until
the DeviceHead signature verifies. The fold itself is byte-identical to the
server path — the server was never part of its semantics.

## 6. What this model refuses to do

- **No clocks in decisions** (§1). A device with a wrong clock produces a
  cosmetically odd mtime, never a wrong merge.
- **No quiet data loss.** Deletions propagate only when the base proves they
  were deletions; conflicts always preserve both contents; an over-ceiling
  sync defers whole rather than committing a partial tree; a failed
  verification refuses the blob rather than writing it.
- **No authority.** Any device can be lost, wiped, or restored from the
  keep-set alone (`sync restore` with no arguments cold-discovers the
  manifest); no device holds state the others cannot re-derive.
