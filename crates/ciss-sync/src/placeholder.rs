//! The placeholder store: evicted files' logical entries.
//!
//! An evicted file is *absent from disk* and recorded here — deliberately not
//! a zero-byte stub, which would masquerade as a real empty file to every
//! other program. The logical tree a backup commits is the scanned files
//! ∪ these records; losing a record here would let a later backup shrink the
//! keep-set and orphan server-side chunks, so this table is as load-bearing
//! as the manifest itself.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncError;
use crate::manifest::FileEntry;

/// `path → FileEntry` for files whose bytes were evicted locally.
pub struct PlaceholderStore {
    conn: Connection,
}

impl PlaceholderStore {
    /// Open (or create) the store in the sqlite file at `db_path`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Index`] if sqlite cannot open or migrate.
    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self, SyncError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS placeholders (
                 path       TEXT PRIMARY KEY,
                 entry_cbor BLOB NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    /// Record (or replace) the placeholder for `path`.
    ///
    /// # Errors
    ///
    /// Serialization or sqlite failures.
    pub fn record(&mut self, path: &str, entry: &FileEntry) -> Result<(), SyncError> {
        let blob = serde_ipld_dagcbor::to_vec(entry)
            .map_err(|e| SyncError::Encode(format!("placeholder for {path}: {e}")))?;
        self.conn.execute(
            "INSERT INTO placeholders (path, entry_cbor) VALUES (?1, ?2)
             ON CONFLICT(path) DO UPDATE SET entry_cbor = ?2",
            rusqlite::params![path, blob],
        )?;
        Ok(())
    }

    /// The placeholder for `path`, if one exists.
    ///
    /// # Errors
    ///
    /// Sqlite failures, or [`SyncError::Decode`] if a stored blob no longer
    /// decodes (fail loud — never guess at a logical entry).
    pub fn get(&self, path: &str) -> Result<Option<FileEntry>, SyncError> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT entry_cbor FROM placeholders WHERE path = ?1", [path], |r| r.get(0))
            .optional()?;
        row.map(|blob| {
            serde_ipld_dagcbor::from_slice(&blob)
                .map_err(|e| SyncError::Decode(format!("placeholder for {path}: {e}")))
        })
        .transpose()
    }

    /// Drop the placeholder for `path` (idempotent).
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn remove(&mut self, path: &str) -> Result<(), SyncError> {
        self.conn.execute("DELETE FROM placeholders WHERE path = ?1", [path])?;
        Ok(())
    }

    /// Every placeholder, path-sorted — the shape `backup` merges.
    ///
    /// # Errors
    ///
    /// Sqlite or decode failures.
    pub fn all(&self) -> Result<BTreeMap<String, FileEntry>, SyncError> {
        let mut stmt = self.conn.prepare("SELECT path, entry_cbor FROM placeholders")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (path, blob) = row?;
            let entry = serde_ipld_dagcbor::from_slice(&blob)
                .map_err(|e| SyncError::Decode(format!("placeholder for {path}: {e}")))?;
            out.insert(path, entry);
        }
        Ok(out)
    }
}
