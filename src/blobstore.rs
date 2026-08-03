//! The pluggable Layer-1 blob backend: dumb bytes-under-a-key storage.
//!
//! This is Layer 1 of the two-layer split (the plan's "meter the boundary, not
//! the machine"): the backend just holds bytes keyed by `(DID, CID)` and never
//! meters, never verifies content, never holds any provenance. Content
//! addressing and the metering ledger are the **boundary's** job (Layer 2, in
//! [`crate::server`]); the backend is deliberately dumb so any S3-compatible
//! store can stand in and nothing in the storage layer must be trusted.
//!
//! Two backends ship in v0: [`MemoryBlobStore`] (the default / test backend)
//! and [`FsBlobStore`] (a local filesystem store laid out `{root}/blocks/{did}/
//! {cid}`, mirroring rsky-pds's `blocks/{did}/{cid}`). The [`BlobStore`] trait
//! is the attach point for the deferred kernel-performance tier
//! (`ROADMAP_TODO` E84: `io_uring`/zero-copy backends).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Why a blob-backend operation failed.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// No bytes are stored under `(did, cid)`.
    #[error("no blob stored for {did}/{cid}")]
    Missing {
        /// The DID whose blob was requested.
        did: String,
        /// The content address requested.
        cid: String,
    },
    /// An underlying I/O operation failed.
    #[error("blob io error for {did}/{cid}: {source}")]
    Io {
        /// The DID being operated on.
        did: String,
        /// The content address being operated on.
        cid: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// A dumb, pluggable byte store keyed by `(DID, CID)`.
///
/// The backend does **not** content-check: [`BlobStore::get`] returns whatever
/// bytes are stored under the key, even if they no longer fingerprint to the
/// CID. Re-verifying the content address (tamper-at-rest detection) is the
/// boundary's responsibility, so a compromised or buggy backend cannot pass a
/// forged blob past the Layer-2 check.
pub trait BlobStore: Send + Sync {
    /// Store `bytes` under `(did, cid)`, returning the number of bytes written
    /// so the boundary can assert byte-count integrity. Content-addressed
    /// storage is idempotent: writing the same `(did, cid)` again is dedup, not
    /// duplication.
    ///
    /// # Errors
    ///
    /// [`BlobError::Io`] if the bytes could not be persisted.
    fn put(&self, did: &str, cid: &str, bytes: &[u8]) -> Result<usize, BlobError>;

    /// Fetch the raw stored bytes for `(did, cid)` — unverified (see the trait
    /// docs: the backend is dumb).
    ///
    /// # Errors
    ///
    /// [`BlobError::Missing`] if nothing is stored; [`BlobError::Io`] on a read
    /// failure.
    fn get(&self, did: &str, cid: &str) -> Result<Vec<u8>, BlobError>;

    /// Whether any bytes are stored under `(did, cid)`.
    fn has(&self, did: &str, cid: &str) -> bool;
}

/// An in-memory backend: a map keyed by `(DID, CID)`. The default backend and
/// the one tests use — real storage code, no files.
#[derive(Debug, Default)]
pub struct MemoryBlobStore {
    blobs: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl MemoryBlobStore {
    /// A new, empty in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), Vec<u8>>> {
        // A poisoned lock means a writer panicked mid-insert; the map is a plain
        // key->bytes map with no cross-entry invariant, so recovering the guard
        // and continuing is safe (no partial-state corruption to observe).
        self.blobs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl BlobStore for MemoryBlobStore {
    fn put(&self, did: &str, cid: &str, bytes: &[u8]) -> Result<usize, BlobError> {
        self.lock()
            .insert((did.to_owned(), cid.to_owned()), bytes.to_vec());
        Ok(bytes.len())
    }

    fn get(&self, did: &str, cid: &str) -> Result<Vec<u8>, BlobError> {
        self.lock()
            .get(&(did.to_owned(), cid.to_owned()))
            .cloned()
            .ok_or_else(|| BlobError::Missing {
                did: did.to_owned(),
                cid: cid.to_owned(),
            })
    }

    fn has(&self, did: &str, cid: &str) -> bool {
        self.lock().contains_key(&(did.to_owned(), cid.to_owned()))
    }
}

/// A local-filesystem backend laid out `{root}/blocks/{did}/{cid}` (permanent)
/// with a `{root}/tmp/{did}/{cid}` staging path, mirroring rsky-pds. FS-first
/// per Phase 0 D5 (matches the official-PDS disk default); Garage/SeaweedFS/R2
/// are later pluggable backends behind the same trait.
#[derive(Debug)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// A backend rooted at `root` (created lazily on first write).
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn permanent_path(&self, did: &str, cid: &str) -> PathBuf {
        self.root.join("blocks").join(did).join(cid)
    }

    fn temp_path(&self, did: &str, cid: &str) -> PathBuf {
        self.root.join("tmp").join(did).join(cid)
    }

    fn io_err(did: &str, cid: &str, source: std::io::Error) -> BlobError {
        BlobError::Io {
            did: did.to_owned(),
            cid: cid.to_owned(),
            source,
        }
    }

    fn ensure_parent(path: &Path, did: &str, cid: &str) -> Result<(), BlobError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Self::io_err(did, cid, e))?;
        }
        Ok(())
    }
}

impl BlobStore for FsBlobStore {
    fn put(&self, did: &str, cid: &str, bytes: &[u8]) -> Result<usize, BlobError> {
        let permanent = self.permanent_path(did, cid);
        // Content-addressed dedup: the same (did, cid) is byte-identical, so a
        // second write is a no-op.
        if permanent.exists() {
            return Ok(bytes.len());
        }
        let temp = self.temp_path(did, cid);
        Self::ensure_parent(&temp, did, cid)?;
        Self::ensure_parent(&permanent, did, cid)?;
        std::fs::write(&temp, bytes).map_err(|e| Self::io_err(did, cid, e))?;
        // SEAM (E84): v0 uses `std::fs::rename` — an atomic same-filesystem
        // temp->permanent move. The kernel-performance tier upgrades this to
        // `copy_file_range`/`FICLONE` reflink for copy-on-write dedup and
        // cross-filesystem moves (gated on the Phase-9 VPS-kernel probe).
        std::fs::rename(&temp, &permanent).map_err(|e| Self::io_err(did, cid, e))?;
        Ok(bytes.len())
    }

    fn get(&self, did: &str, cid: &str) -> Result<Vec<u8>, BlobError> {
        match std::fs::read(self.permanent_path(did, cid)) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(BlobError::Missing {
                did: did.to_owned(),
                cid: cid.to_owned(),
            }),
            Err(e) => Err(Self::io_err(did, cid, e)),
        }
    }

    fn has(&self, did: &str, cid: &str) -> bool {
        self.permanent_path(did, cid).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::{BlobError, BlobStore, FsBlobStore, MemoryBlobStore};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    /// A unique temp dir for an FS-backend test (no external tempdir crate).
    fn temp_root(tag: &str) -> PathBuf {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ciss-blobtest-{}-{tag}-{seq}", std::process::id()))
    }

    fn round_trips(store: &dyn BlobStore) {
        let (did, cid, bytes) = ("id:alice", "cid-abc", b"payload".as_slice());
        assert!(!store.has(did, cid), "absent before a write");
        let written = store.put(did, cid, bytes).expect("put");
        assert_eq!(written, bytes.len(), "put reports the boundary byte count");
        assert!(store.has(did, cid), "present after a write");
        assert_eq!(
            store.get(did, cid).expect("get"),
            bytes,
            "get returns the bytes"
        );
    }

    fn dedups(store: &dyn BlobStore) {
        let (did, cid, bytes) = ("id:bob", "cid-dup", b"same".as_slice());
        assert_eq!(store.put(did, cid, bytes).expect("put 1"), bytes.len());
        assert_eq!(
            store.put(did, cid, bytes).expect("put 2"),
            bytes.len(),
            "a second identical write is idempotent dedup, still reporting the byte count",
        );
        assert_eq!(store.get(did, cid).expect("get"), bytes);
    }

    fn missing_is_reported(store: &dyn BlobStore) {
        let err = store
            .get("id:nobody", "cid-nope")
            .expect_err("must be Missing");
        assert!(
            matches!(err, BlobError::Missing { .. }),
            "absent key -> Missing"
        );
        assert!(
            !store.has("id:nobody", "cid-nope"),
            "has() is false for an absent key"
        );
    }

    /// The dumb-backend contract: `get` returns raw stored bytes even when they
    /// do NOT match the CID. Content verification is the boundary's job, so the
    /// backend must not silently "help" by checking or rejecting.
    fn backend_does_not_content_check(store: &dyn BlobStore) {
        // Store bytes under a CID that is not their fingerprint.
        store
            .put("id:carol", "a-lie-of-a-cid", b"not the hash of this")
            .expect("put");
        assert_eq!(
            store.get("id:carol", "a-lie-of-a-cid").expect("get"),
            b"not the hash of this",
            "the backend hands back whatever it was given, unverified",
        );
    }

    #[test]
    fn memory_backend_behaviors() {
        let store = MemoryBlobStore::new();
        round_trips(&store);
        dedups(&store);
        missing_is_reported(&store);
        backend_does_not_content_check(&store);
    }

    #[test]
    fn fs_backend_behaviors() {
        let root = temp_root("behaviors");
        let store = FsBlobStore::new(root.clone());
        round_trips(&store);
        dedups(&store);
        missing_is_reported(&store);
        backend_does_not_content_check(&store);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fs_backend_lays_out_blocks_did_cid() {
        let root = temp_root("layout");
        let store = FsBlobStore::new(root.clone());
        store.put("id:dave", "cid-xyz", b"bytes").expect("put");
        assert!(
            root.join("blocks").join("id:dave").join("cid-xyz").exists(),
            "permanent path is {{root}}/blocks/{{did}}/{{cid}}",
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fs_backend_read_error_is_io_not_missing() {
        // A non-NotFound read failure must surface as Io, never masquerade as
        // Missing. Put a *directory* where the blob file would be, so read()
        // fails with a non-NotFound error. (Pins the NotFound match guard: a
        // mutant that treats every read error as Missing must fail here.)
        let root = temp_root("ioerr");
        let store = FsBlobStore::new(root.clone());
        let blob_path = root.join("blocks").join("id:e").join("cid-dir");
        std::fs::create_dir_all(&blob_path).expect("mkdir at the blob path");
        let err = store
            .get("id:e", "cid-dir")
            .expect_err("reading a directory fails");
        assert!(
            matches!(err, BlobError::Io { .. }),
            "a non-NotFound read error is Io, not Missing; got {err:?}",
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
