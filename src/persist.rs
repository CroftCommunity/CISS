//! Per-user (per-DID) SQLite persistence.
//!
//! One store co-locates a DID's records — the **manifest** (a single-author
//! repo record) and its **receipts** and **statements** (the co-signed structure
//! alongside) — mirroring the official PDS's per-actor SQLite (Phase 0 D5). Each
//! record is stored as its canonical JSON; `load_*` reconstruct the typed values
//! and the callers re-verify (`Manifest::verify`, `verify_chain`), so persistence
//! is not a trust boundary.
//!
//! Tests use `Store::open_in_memory` (SQLite `:memory:`) — the same code path as
//! a file-backed store, no files, no mocking.
//!
//! `SEAM:` a `rusqlite::Connection` is single-threaded (`!Sync`); the networked
//! service (Phase 7) will need a per-DID connection pool or a guard. Blob *bytes*
//! stay in the pluggable Layer-1 backend — only the signed records live here.

use rusqlite::{Connection, OptionalExtension};

use crate::manifest::Manifest;
use crate::receipts::Receipt;
use crate::statements::Statement;

/// An error persisting or loading records.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// The underlying SQLite layer failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A record failed to (de)serialize as JSON.
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// A per-DID record store backed by SQLite.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open an in-memory store (SQLite `:memory:`) — real persistence code, no file.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the database cannot be opened or migrated.
    pub fn open_in_memory() -> Result<Self, PersistError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// Open a file-backed store at `path`, creating it if needed.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the database cannot be opened or migrated.
    pub fn open(path: &str) -> Result<Self, PersistError> {
        Self::from_connection(Connection::open(path)?)
    }

    fn from_connection(conn: Connection) -> Result<Self, PersistError> {
        // WAL for file-backed stores (Phase 0 D5: the official-PDS per-actor
        // layout); ignored for an in-memory store. Enables the E87
        // `wal_checkpoint(TRUNCATE)` graceful-shutdown seam to do real work.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS manifest (
                 did  TEXT PRIMARY KEY,
                 json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS receipt (
                 id   INTEGER PRIMARY KEY AUTOINCREMENT,
                 did  TEXT NOT NULL,
                 json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS statement (
                 id   INTEGER PRIMARY KEY AUTOINCREMENT,
                 did  TEXT NOT NULL,
                 json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS receipt_did   ON receipt(did);
             CREATE INDEX IF NOT EXISTS statement_did ON statement(did);",
        )?;
        Ok(Self { conn })
    }

    /// Upsert a server-held metadata value (a small key/value singleton table).
    ///
    /// Used for durable server state that is not per-DID — e.g. the provider's
    /// key seed, which lives here so Litestream backs it up and the signing
    /// identity survives a backup/restore.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn put_meta(&self, key: &str, value: &str) -> Result<(), PersistError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Load a server-held metadata value, if set.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, PersistError> {
        let value: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(value)
    }

    /// Upsert the DID's current signed manifest (single-author repo record).
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or serialization failure.
    pub fn save_manifest(&self, did: &str, manifest: &Manifest) -> Result<(), PersistError> {
        let json = serde_json::to_string(manifest)?;
        self.conn.execute(
            "INSERT INTO manifest (did, json) VALUES (?1, ?2)
             ON CONFLICT(did) DO UPDATE SET json = excluded.json",
            rusqlite::params![did, json],
        )?;
        Ok(())
    }

    /// Load the DID's manifest, if any.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or deserialization failure.
    pub fn load_manifest(&self, did: &str) -> Result<Option<Manifest>, PersistError> {
        let json: Option<String> = self
            .conn
            .query_row("SELECT json FROM manifest WHERE did = ?1", [did], |row| {
                row.get(0)
            })
            .optional()?;
        match json {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// Append a receipt to the DID's co-signed record set.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or serialization failure.
    pub fn append_receipt(&self, did: &str, receipt: &Receipt) -> Result<(), PersistError> {
        let json = serde_json::to_string(receipt)?;
        self.conn.execute(
            "INSERT INTO receipt (did, json) VALUES (?1, ?2)",
            rusqlite::params![did, json],
        )?;
        Ok(())
    }

    /// Load the DID's receipts in insertion order.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or deserialization failure.
    pub fn load_receipts(&self, did: &str) -> Result<Vec<Receipt>, PersistError> {
        self.load_json_rows("SELECT json FROM receipt WHERE did = ?1 ORDER BY id", did)
    }

    /// Append a statement to the DID's chain.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or serialization failure.
    pub fn append_statement(&self, did: &str, statement: &Statement) -> Result<(), PersistError> {
        let json = serde_json::to_string(statement)?;
        self.conn.execute(
            "INSERT INTO statement (did, json) VALUES (?1, ?2)",
            rusqlite::params![did, json],
        )?;
        Ok(())
    }

    /// Load the DID's statement chain in insertion (chain) order.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or deserialization failure.
    pub fn load_statements(&self, did: &str) -> Result<Vec<Statement>, PersistError> {
        self.load_json_rows("SELECT json FROM statement WHERE did = ?1 ORDER BY id", did)
    }

    /// Checkpoint the write-ahead log, truncating it (`wal_checkpoint(TRUNCATE)`).
    ///
    /// The graceful-shutdown seam (E87): after the networked server drains
    /// in-flight requests it calls this so a restart opens a checkpointed
    /// database. A no-op for an in-memory store (no WAL); harmless either way.
    ///
    /// # Errors
    /// Returns [`PersistError`] if the checkpoint statement fails.
    pub fn checkpoint_truncate(&self) -> Result<(), PersistError> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Run a `SELECT json ...` query for a DID and deserialize each row.
    fn load_json_rows<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        did: &str,
    ) -> Result<Vec<T>, PersistError> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([did], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::Store;
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;
    use crate::manifest::{build_manifest, ManifestLeaf};

    #[test]
    fn manifest_upsert_keeps_only_the_latest() {
        let customer = derive_keypair("m", "c");
        let did = derive_id(&customer.verifying_key());
        let store = Store::open_in_memory().expect("open");

        let m1 = build_manifest(&[ManifestLeaf::new("aaaa", 1)], &did, &customer, 1);
        let m2 = build_manifest(&[ManifestLeaf::new("bbbb", 2)], &did, &customer, 2);
        store.save_manifest(&did, &m1).expect("save m1");
        store.save_manifest(&did, &m2).expect("save m2 (upsert)");

        let loaded = store.load_manifest(&did).expect("load").expect("present");
        assert_eq!(loaded.root(), m2.root(), "upsert keeps the latest manifest");
    }

    #[test]
    fn missing_did_loads_nothing() {
        let store = Store::open_in_memory().expect("open");
        assert!(store.load_manifest("id:absent").expect("load").is_none());
        assert!(store.load_receipts("id:absent").expect("load").is_empty());
        assert!(store.load_statements("id:absent").expect("load").is_empty());
    }

    #[test]
    fn meta_round_trips_and_upserts() {
        let store = Store::open_in_memory().expect("open");
        assert!(
            store.get_meta("provider_seed").expect("get").is_none(),
            "an unset key is absent, not an error",
        );
        store.put_meta("provider_seed", "abc123").expect("put");
        assert_eq!(
            store.get_meta("provider_seed").expect("get").as_deref(),
            Some("abc123"),
        );
        store.put_meta("provider_seed", "def456").expect("upsert");
        assert_eq!(
            store.get_meta("provider_seed").expect("get").as_deref(),
            Some("def456"),
            "put on an existing key upserts",
        );
    }
}
