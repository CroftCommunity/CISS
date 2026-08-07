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

pub mod backup;
pub mod cache;
pub mod chunk;
pub mod error;
pub mod index;
pub mod manifest;
pub mod placeholder;
pub mod restore;
pub mod scan;
pub mod state;
pub mod transport;

pub use backup::{backup, BackupReport};
pub use cache::ChunkCache;
pub use placeholder::PlaceholderStore;
pub use restore::{restore, RestoreReport};
pub use state::{SyncState, DEFAULT_CACHE_BUDGET};
pub use chunk::{
    chunk_file, Chunk, ChunkRef, Hash32, CHUNK_AVG_BYTES, CHUNK_MAX_BYTES, CHUNK_MIN_BYTES,
};
pub use error::SyncError;
pub use index::Index;
pub use manifest::{DagCbor, FileEntry, FsManifest, ManifestCodec, PrettyJson, FS_MANIFEST_KIND};
pub use scan::{scan_tree, scan_tree_indexed};
pub use transport::{missing_blobs, verify_content, verify_server_cid, BlobTransport, ManifestSlot};
