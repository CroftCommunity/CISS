# Changelog — ciss-ctl (client CLI)

Changes to the `ciss-ctl` client (the `ciss-cli` crate and the engine crates
it fronts: `ciss-sync`, `ciss-iroh`). The server has its own changelog at the
repo root. Versions move in lockstep with the server; the Homebrew tap
(`croftcommunity/tap/ciss-ctl`) tracks tagged releases.

## [0.6.0] — 2026-08-07

The file-sync release: the whole M1–M5 ladder (PRs #14–#19).

### Added
- **`ciss-ctl sync`** — a full own-device file-sync client over CISS:
  - `sync backup` / `sync restore` (M1): FastCDC content-defined chunking
    (dual sha-256/blake3 refs), canonical DAG-CBOR fs-manifest, have/want
    dedup via `du`, keep-set commit under I5, verify-on-receipt everywhere,
    cold restore by manifest self-tag, chunk-level resume.
  - `sync evict` / `sync hydrate` / `sync status` (M2): bounded local
    footprint — budgeted chunk cache, placeholders, the logical-tree
    no-data-loss rule (an eviction never shrinks the committed tree).
  - `sync converge` (M3): multi-device — self-verifying `DeviceHead`s,
    slot-discipline non-lossy frontier commits, and a deterministic
    clock-free fold; conflicts preserved as `<path>.conflict-<device>`.
  - `sync p2p share` / `sync p2p converge` (M4, new crate `ciss-iroh`):
    blobs from a peer over iroh (blake3/Bao verified, sha-256 re-verified on
    receipt), and the same converge running serverless over iroh-gossip;
    pairing via a printed ticket. LAN/loopback posture in this release.
  - `sync price` / `sync ceiling` (M5): pre-flight quotes via the server's
    own linked tariff, and a per-tree spending ceiling that defers
    over-ceiling syncs whole — never partial, never billed; restore is
    exit-exempt by construction (POSTURE B6).
- Per-profile `device_id` (auto-generated) for multi-device backup.

### Notes
- Serverless (p2p) converge state is process-lifetime in this release: a
  multi-round serverless converge across restarts falls back to the server
  path (fails loud, corrupts nothing). A persistent iroh store/alias layer is
  the planned follow-on.

## [0.5.6] — 2026-08-06 and earlier

Pre-changelog releases: `key gen/import/show/list`, `login`, `whoami`,
`put`/`get` (both planes), `meter`, `ls`, `du`, `acl set/get` (gated reads),
`--identity id|did`, `--json`, man page. See the git tags.
