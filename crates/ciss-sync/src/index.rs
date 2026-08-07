//! The minimal local scan index — an mtime/size fast-path, nothing more.
//!
//! Maps `path → (mtime, size, serialized FileEntry)` in sqlite so an
//! unchanged file skips re-reading and re-chunking. A stale or missing index
//! only costs time, never correctness. Heavier uses (placeholders, working
//! sets) arrive in M2/M3.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncError;
use crate::manifest::FileEntry;

/// A sqlite-backed `path → probably-unchanged` cache with hit/miss counters.
pub struct Index {
    conn: Connection,
    hits: u64,
    misses: u64,
}

impl Index {
    /// Open (or create) the index at `path`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Index`] if sqlite cannot open or migrate the file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SyncError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan_index (
                 path        TEXT PRIMARY KEY,
                 mtime_secs  INTEGER NOT NULL,
                 mtime_nanos INTEGER NOT NULL,
                 size        INTEGER NOT NULL,
                 entry_cbor  BLOB NOT NULL
             );",
        )?;
        Ok(Self { conn, hits: 0, misses: 0 })
    }

    /// Return the stored entry iff `(mtime, size)` still match exactly.
    ///
    /// # Errors
    ///
    /// [`SyncError::Index`] on sqlite failures, [`SyncError::Decode`] if a
    /// stored blob no longer decodes (fail loud — never guess).
    pub fn lookup(
        &mut self,
        path: &str,
        mtime_secs: i64,
        mtime_nanos: u32,
        size: u64,
    ) -> Result<Option<FileEntry>, SyncError> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT entry_cbor FROM scan_index
                 WHERE path = ?1 AND mtime_secs = ?2 AND mtime_nanos = ?3 AND size = ?4",
                rusqlite::params![path, mtime_secs, mtime_nanos, size],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(blob) = row {
            let entry: FileEntry = serde_ipld_dagcbor::from_slice(&blob)
                .map_err(|e| SyncError::Decode(format!("index entry for {path}: {e}")))?;
            self.hits += 1;
            Ok(Some(entry))
        } else {
            self.misses += 1;
            Ok(None)
        }
    }

    /// Upsert the freshly-scanned entry for `path`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Encode`] / [`SyncError::Index`] on serialize or sqlite
    /// failures.
    pub fn store(&mut self, path: &str, entry: &FileEntry) -> Result<(), SyncError> {
        let blob = serde_ipld_dagcbor::to_vec(entry)
            .map_err(|e| SyncError::Encode(format!("index entry for {path}: {e}")))?;
        self.conn.execute(
            "INSERT INTO scan_index (path, mtime_secs, mtime_nanos, size, entry_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(path) DO UPDATE SET
                 mtime_secs = ?2, mtime_nanos = ?3, size = ?4, entry_cbor = ?5",
            rusqlite::params![path, entry.mtime_secs, entry.mtime_nanos, entry.size, blob],
        )?;
        Ok(())
    }

    /// Fast-path hits since open.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Fast-path misses since open.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses
    }
}
