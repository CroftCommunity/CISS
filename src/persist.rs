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
use crate::receipts::{Direction, Receipt};
use crate::statements::Statement;

/// A DID's cumulative transfer totals — maintained incrementally so a metered
/// request is O(1) rather than re-summing the whole ledger every time (V3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiptTotals {
    /// Number of receipts recorded for the DID.
    pub receipt_count: u64,
    /// Total bytes uploaded (customer -> provider).
    pub upload_bytes: u64,
    /// Total bytes downloaded (provider -> customer).
    pub download_bytes: u64,
}

impl ReceiptTotals {
    /// Bytes transferred both ways.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.upload_bytes + self.download_bytes
    }
}

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

/// One row of the `did_usage` read surface: a DID's storage + transfer usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow {
    /// The DID.
    pub did: String,
    /// Distinct bytes at rest (the store footprint this DID contributes).
    pub stored_bytes: u64,
    /// Cumulative bytes uploaded.
    pub upload_bytes: u64,
    /// Cumulative bytes downloaded.
    pub download_bytes: u64,
    /// Cumulative bytes transferred (upload + download).
    pub transferred_bytes: u64,
    /// Number of receipts.
    pub receipt_count: u64,
}

/// Map a `did_usage` row to a [`UsageRow`] (SQLite integers are `i64`).
fn row_to_usage(row: &rusqlite::Row) -> rusqlite::Result<UsageRow> {
    let u = |i: usize| -> rusqlite::Result<u64> { Ok(u64::try_from(row.get::<_, i64>(i)?).unwrap_or(0)) };
    Ok(UsageRow {
        did: row.get(0)?,
        stored_bytes: u(1)?,
        upload_bytes: u(2)?,
        download_bytes: u(3)?,
        transferred_bytes: u(4)?,
        receipt_count: u(5)?,
    })
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

    /// Open an existing store **read-only**, without migrating — for tooling (the
    /// `ciss usage` CLI, monitors) reading the live database while the service
    /// holds the writer (WAL allows concurrent readers).
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the database cannot be opened.
    pub fn open_readonly(path: &str) -> Result<Self, PersistError> {
        let conn =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    /// Every DID's usage from the `did_usage` read surface, heaviest first.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn usage_all(&self) -> Result<Vec<UsageRow>, PersistError> {
        let mut stmt = self.conn.prepare(
            "SELECT did, stored_bytes, upload_bytes, download_bytes, transferred_bytes, \
             receipt_count FROM did_usage ORDER BY stored_bytes DESC, did",
        )?;
        let rows = stmt.query_map([], row_to_usage)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// One DID's usage from the `did_usage` read surface, if present.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn usage_for(&self, did: &str) -> Result<Option<UsageRow>, PersistError> {
        self.conn
            .query_row(
                "SELECT did, stored_bytes, upload_bytes, download_bytes, transferred_bytes, \
                 receipt_count FROM did_usage WHERE did = ?1",
                [did],
                row_to_usage,
            )
            .optional()
            .map_err(PersistError::from)
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
             CREATE TABLE IF NOT EXISTS did_total (
                 did            TEXT PRIMARY KEY,
                 receipt_count  INTEGER NOT NULL DEFAULT 0,
                 upload_bytes   INTEGER NOT NULL DEFAULT 0,
                 download_bytes INTEGER NOT NULL DEFAULT 0,
                 stored_bytes   INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS receipt_did   ON receipt(did);
             CREATE INDEX IF NOT EXISTS statement_did ON statement(did);
             CREATE VIEW IF NOT EXISTS did_usage AS
                 SELECT did,
                        stored_bytes,
                        upload_bytes,
                        download_bytes,
                        upload_bytes + download_bytes AS transferred_bytes,
                        receipt_count
                 FROM did_total;",
        )?;
        // Defensive migration for a did_total created before `stored_bytes`
        // existed (a dev database); ignore the duplicate-column error.
        if let Err(e) = conn.execute(
            "ALTER TABLE did_total ADD COLUMN stored_bytes INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                return Err(e.into());
            }
        }
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

    /// Append a receipt to the DID's co-signed record set, keeping the cached
    /// [`ReceiptTotals`] in step — atomically, so the O(1) cache can never drift
    /// from the ledger (V3).
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or serialization failure.
    ///
    /// # Panics
    /// Only if a receipt's byte count exceeds `u64` — impossible on a 64-bit
    /// machine, where a `usize` byte count fits `u64`.
    pub fn append_receipt(&self, did: &str, receipt: &Receipt) -> Result<(), PersistError> {
        let json = serde_json::to_string(receipt)?;
        let bytes = u64::try_from(receipt.bytes()).expect("a byte count fits u64");
        let (up, down) = match receipt.core().direction {
            Direction::Upload => (bytes, 0),
            Direction::Download => (0, bytes),
        };
        let tx = self.conn.unchecked_transaction()?;
        // Backfill the cache row from any pre-existing receipts the first time we
        // touch this DID, so the incremental counter is correct even for a ledger
        // written before the cache existed.
        self.ensure_total_row(did)?;
        self.conn.execute(
            "INSERT INTO receipt (did, json) VALUES (?1, ?2)",
            rusqlite::params![did, json],
        )?;
        self.conn.execute(
            "UPDATE did_total
                 SET receipt_count = receipt_count + 1,
                     upload_bytes = upload_bytes + ?2,
                     download_bytes = download_bytes + ?3
             WHERE did = ?1",
            rusqlite::params![did, up, down],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The DID's cumulative transfer totals, read from the O(1) cache (or computed
    /// from the ledger once if the cache row is not yet populated).
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or deserialization failure.
    pub fn running_totals(&self, did: &str) -> Result<ReceiptTotals, PersistError> {
        let cached = self
            .conn
            .query_row(
                "SELECT receipt_count, upload_bytes, download_bytes FROM did_total WHERE did = ?1",
                [did],
                |row| {
                    Ok(ReceiptTotals {
                        receipt_count: row.get(0)?,
                        upload_bytes: row.get(1)?,
                        download_bytes: row.get(2)?,
                    })
                },
            )
            .optional()?;
        match cached {
            Some(totals) => Ok(totals),
            None => self.sum_receipts(did),
        }
    }

    /// The total distinct bytes at rest across all DIDs — the store footprint the
    /// store ceiling bounds. Derived (`SUM`) so it cannot drift from the per-DID
    /// counters; cheap for a co-op's small DID set.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn store_usage(&self) -> Result<u64, PersistError> {
        let total: i64 =
            self.conn
                .query_row("SELECT COALESCE(SUM(stored_bytes), 0) FROM did_total", [], |row| {
                    row.get(0)
                })?;
        Ok(u64::try_from(total).unwrap_or(0))
    }

    /// The distinct bytes at rest for one DID.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn did_stored_bytes(&self, did: &str) -> Result<u64, PersistError> {
        let bytes: Option<i64> = self
            .conn
            .query_row("SELECT stored_bytes FROM did_total WHERE did = ?1", [did], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(bytes.and_then(|b| u64::try_from(b).ok()).unwrap_or(0))
    }

    /// Record a genuinely-new (non-dedup) blob store: add its size to the DID's
    /// distinct bytes at rest. A dedup write must NOT call this (it consumes no
    /// disk). Ensures the DID's cache row exists first.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn add_stored_bytes(&self, did: &str, size: u64) -> Result<(), PersistError> {
        let tx = self.conn.unchecked_transaction()?;
        self.ensure_total_row(did)?;
        self.conn.execute(
            "UPDATE did_total SET stored_bytes = stored_bytes + ?2 WHERE did = ?1",
            rusqlite::params![did, size],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Insert a backfilled cache row for `did` if one does not already exist.
    fn ensure_total_row(&self, did: &str) -> Result<(), PersistError> {
        let present = self
            .conn
            .query_row("SELECT 1 FROM did_total WHERE did = ?1", [did], |_| Ok(()))
            .optional()?
            .is_some();
        if !present {
            let totals = self.sum_receipts(did)?;
            self.conn.execute(
                "INSERT INTO did_total (did, receipt_count, upload_bytes, download_bytes)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    did,
                    totals.receipt_count,
                    totals.upload_bytes,
                    totals.download_bytes
                ],
            )?;
        }
        Ok(())
    }

    /// Compute a DID's totals by scanning its ledger — the O(n) path, used only to
    /// backfill the cache once (or read a DID whose cache is not yet populated).
    fn sum_receipts(&self, did: &str) -> Result<ReceiptTotals, PersistError> {
        let receipts = self.load_receipts(did)?;
        let mut totals = ReceiptTotals::default();
        for receipt in &receipts {
            let bytes = u64::try_from(receipt.bytes()).expect("a byte count fits u64");
            totals.receipt_count += 1;
            match receipt.core().direction {
                Direction::Upload => totals.upload_bytes += bytes,
                Direction::Download => totals.download_bytes += bytes,
            }
        }
        Ok(totals)
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
    fn running_totals_track_appends_and_match_the_ledger() {
        use super::ReceiptTotals;
        use crate::receipts::{make_unilateral_receipt, Direction, ReceiptCore};

        let provider = derive_keypair("m", "p");
        let store = Store::open_in_memory().expect("open");
        let did = "id:tester";
        let mk = |dir, bytes, rt| {
            make_unilateral_receipt(
                ReceiptCore::new(dir, "cid", (0, bytes), rt, 0, "id:r", "id:s"),
                "id:s",
                &provider,
            )
        };

        store.append_receipt(did, &mk(Direction::Upload, 10, 10)).expect("up");
        store.append_receipt(did, &mk(Direction::Download, 5, 15)).expect("down");
        store.append_receipt(did, &mk(Direction::Upload, 20, 35)).expect("up");

        let totals = store.running_totals(did).expect("totals");
        assert_eq!(totals.receipt_count, 3);
        assert_eq!(totals.upload_bytes, 30);
        assert_eq!(totals.download_bytes, 5);
        assert_eq!(totals.total_bytes(), 35);

        // The cache equals a full scan of the ledger (no drift).
        let scanned: u64 = store
            .load_receipts(did)
            .expect("load")
            .iter()
            .map(|r| u64::try_from(r.bytes()).unwrap())
            .sum();
        assert_eq!(totals.total_bytes(), scanned, "cache matches the ledger");

        // A DID with no receipts totals zero.
        assert_eq!(
            store.running_totals("id:none").expect("empty"),
            ReceiptTotals::default(),
        );
    }

    #[test]
    fn did_usage_view_reflects_stores_and_transfers() {
        use crate::receipts::{make_unilateral_receipt, Direction, ReceiptCore};
        let provider = derive_keypair("m", "p");
        let store = Store::open_in_memory().expect("open");
        let did = "id:u";
        store
            .append_receipt(
                did,
                &make_unilateral_receipt(
                    ReceiptCore::new(Direction::Upload, "cid", (0, 100), 100, 0, "id:r", "id:s"),
                    "id:s",
                    &provider,
                ),
            )
            .expect("receipt");
        store.add_stored_bytes(did, 100).expect("store");

        let row = store.usage_for(did).expect("query").expect("present");
        assert_eq!(row.stored_bytes, 100);
        assert_eq!(row.upload_bytes, 100);
        assert_eq!(row.transferred_bytes, 100);
        assert_eq!(row.receipt_count, 1);
        assert_eq!(store.usage_all().expect("all").len(), 1);
        assert!(store.usage_for("id:none").expect("absent").is_none());
    }

    #[test]
    fn stored_bytes_accounting_is_per_did_and_summed_globally() {
        let store = Store::open_in_memory().expect("open");
        assert_eq!(store.store_usage().expect("usage"), 0);
        assert_eq!(store.did_stored_bytes("id:a").expect("a"), 0);

        store.add_stored_bytes("id:a", 100).expect("a1");
        store.add_stored_bytes("id:a", 50).expect("a2");
        store.add_stored_bytes("id:b", 30).expect("b1");

        assert_eq!(store.did_stored_bytes("id:a").expect("a"), 150);
        assert_eq!(store.did_stored_bytes("id:b").expect("b"), 30);
        assert_eq!(store.store_usage().expect("usage"), 180, "global = sum of per-DID");
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
