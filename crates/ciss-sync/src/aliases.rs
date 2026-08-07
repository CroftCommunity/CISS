//! The persistent sha256→blake3 alias index: the durable half of the C1
//! bridge between the engine's canonical address (sha-256) and the iroh
//! transport address (blake3). Lives in the tree's `state.sqlite` beside
//! the scan index, placeholders, and spend ledger — one file owns the
//! tree's memory. Providers are deliberately NOT persisted: they churn,
//! gossip re-teaches them in one round, and with a persistent blob store
//! the restart case that needed one no longer exists.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncError;

/// A persistent `cid → blake3` map at one sqlite path.
#[derive(Debug, Clone)]
pub struct AliasStore {
    db: PathBuf,
}

impl AliasStore {
    /// Open (or create) the alias table at `db`.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn open(db: impl AsRef<Path>) -> Result<Self, SyncError> {
        let store = Self { db: db.as_ref().to_path_buf() };
        store.conn()?;
        Ok(store)
    }

    fn conn(&self) -> Result<Connection, SyncError> {
        let conn = Connection::open(&self.db)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS alias (
                cid TEXT PRIMARY KEY,
                blake3 BLOB NOT NULL
            );",
        )?;
        Ok(conn)
    }

    /// Record (or re-record — idempotent) an alias.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn set(&self, cid_hex: &str, blake3: [u8; 32]) -> Result<(), SyncError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO alias (cid, blake3) VALUES (?1, ?2)
             ON CONFLICT(cid) DO UPDATE SET blake3 = ?2",
            rusqlite::params![cid_hex, blake3.as_slice()],
        )?;
        Ok(())
    }

    /// The blake3 alias for `cid_hex`, if known.
    ///
    /// # Errors
    ///
    /// Sqlite failures; a stored value that is not 32 bytes.
    pub fn get(&self, cid_hex: &str) -> Result<Option<[u8; 32]>, SyncError> {
        let conn = self.conn()?;
        let raw: Option<Vec<u8>> = conn
            .query_row("SELECT blake3 FROM alias WHERE cid = ?1", [cid_hex], |r| r.get(0))
            .optional()?;
        raw.map(|v| {
            <[u8; 32]>::try_from(v.as_slice())
                .map_err(|_| SyncError::Decode(format!("alias for {cid_hex}: not 32 bytes")))
        })
        .transpose()
    }

    /// Every known alias (spawn-time load).
    ///
    /// # Errors
    ///
    /// Sqlite failures; a stored value that is not 32 bytes.
    pub fn all(&self) -> Result<Vec<(String, [u8; 32])>, SyncError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT cid, blake3 FROM alias")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (cid, raw) = row?;
            let blake3 = <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| SyncError::Decode(format!("alias for {cid}: not 32 bytes")))?;
            out.push((cid, blake3));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set/get/all round-trip; re-recording is idempotent (last write wins,
    /// no duplicate rows); unknown cids are None.
    #[test]
    fn aliases_round_trip_idempotently() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AliasStore::open(dir.path().join("state.sqlite")).expect("open");

        assert_eq!(store.get("deadbeef").expect("get"), None);
        store.set("deadbeef", [1u8; 32]).expect("set");
        assert_eq!(store.get("deadbeef").expect("get"), Some([1u8; 32]));

        store.set("deadbeef", [2u8; 32]).expect("overwrite");
        assert_eq!(store.get("deadbeef").expect("get"), Some([2u8; 32]), "last write wins");

        store.set("cafe", [3u8; 32]).expect("set");
        let mut all = store.all().expect("all");
        all.sort();
        assert_eq!(
            all,
            vec![("cafe".to_owned(), [3u8; 32]), ("deadbeef".to_owned(), [2u8; 32])],
            "exactly two rows — idempotent, no duplicates"
        );
    }
}
