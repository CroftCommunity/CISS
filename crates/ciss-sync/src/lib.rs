//! `ciss-sync` — the file-sync engine over CISS.
//!
//! This crate is the pure core of the sync client (M1 of the file-sync plan,
//! `docs/plans/2026-08-07-file-sync-m1-chunk-and-backup.md`): content-defined
//! chunking with dual sha-256/blake3 addressing, the canonical DAG-CBOR
//! filesystem manifest, a deterministic tree scanner, and a minimal
//! mtime/size scan index. No network — transport lands in a later phase
//! behind a `BlobTransport` seam.
//!
//! Design anchors (see the plan's "Foundations & corpus tie-in"): the
//! fs-manifest is the client's one invented artifact; its `content_id` is
//! sha-256 over the canonical bytes — bit-for-bit the cid CISS assigns the
//! stored blob; the `kind` self-tag domain-separates and versions the format;
//! blake3 rides along so the M4 iroh transport needs no re-hash.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]

pub mod aliases;
pub mod backup;
pub mod cache;
pub mod chunk;
pub mod converge;
pub mod device_head;
pub mod error;
pub mod evict;
pub mod fold;
pub mod frontier;
pub mod hydrate;
pub mod index;
pub mod manifest;
mod materialize;
pub mod ledger;
pub mod placeholder;
pub mod price;
pub mod restore;
pub mod scan;
pub mod state;
pub mod transport;

pub use backup::{backup, BackupReport};
pub use cache::ChunkCache;
pub use converge::{converge, ConvergeReport};
pub use device_head::{DeviceHead, DEVICE_HEAD_KIND};
pub use fold::{fold, ConflictNote, FoldOutcome};
pub use evict::{evict, EvictReport};
pub use frontier::{backup_frontier, FrontierReport};
pub use hydrate::{hydrate, HydrateReport};
pub use aliases::AliasStore;
pub use ledger::{ReconcileOutcome, SpendLedger};
pub use placeholder::PlaceholderStore;
pub use price::{price_backup, PriceQuote};
pub use restore::{restore, RestoreReport};
pub use state::{SyncState, DEFAULT_CACHE_BUDGET};
pub use chunk::{
    chunk_file, Chunk, ChunkRef, Hash32, CHUNK_AVG_BYTES, CHUNK_MAX_BYTES, CHUNK_MIN_BYTES,
};
pub use error::SyncError;
pub use index::Index;
pub use manifest::{DagCbor, FileEntry, FsManifest, ManifestCodec, PrettyJson, FS_MANIFEST_KIND};
pub use scan::{scan_tree, scan_tree_indexed};
pub use transport::{
    missing_blobs, verify_content, verify_server_cid, AccountKey, BlobTransport, FrontierView,
    ManifestSlot,
};
