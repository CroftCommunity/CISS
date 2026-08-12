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
use crate::assertion::{Ack, SignedAssertion};
use crate::policy::{PolicyBody, ResolvedPolicy, POLICY_KIND};
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
    /// An assertion write did not supersede the stored record for its
    /// `(did, kind, subkey)` — the new `seq` was not strictly greater. The
    /// write is rejected (anti-rollback), the stored record is unchanged.
    #[error("assertion seq {seq} does not supersede the stored record for {target}")]
    StaleAssertionSeq {
        /// The rejected target (`did/kind` or `did/kind/subkey`).
        target: String,
        /// The rejected sequence number.
        seq: u64,
    },
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
             DROP TABLE IF EXISTS namespace_policy;
             DROP TABLE IF EXISTS object_policy;
             CREATE TABLE IF NOT EXISTS assertion (
                 did    TEXT NOT NULL,
                 kind   TEXT NOT NULL,
                 subkey TEXT NOT NULL DEFAULT '',
                 seq    INTEGER NOT NULL,
                 json   TEXT NOT NULL,
                 ack    TEXT NOT NULL,
                 PRIMARY KEY (did, kind, subkey)
             );
             CREATE TABLE IF NOT EXISTS chain_entry (
                 did             TEXT NOT NULL,
                 kind            TEXT NOT NULL,
                 subkey          TEXT NOT NULL DEFAULT '',
                 seq             INTEGER NOT NULL,
                 delta           INTEGER NOT NULL,
                 total           INTEGER NOT NULL,
                 prev_entry_hash TEXT NOT NULL,
                 entry_hash      TEXT NOT NULL,
                 json            TEXT NOT NULL,
                 ack             TEXT NOT NULL,
                 PRIMARY KEY (did, kind, subkey, seq)
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

    /// Persist a verified assertion + its provider ack for `(did, kind,
    /// subkey)`, enforcing anti-rollback **in-transaction**: the write applies
    /// only if its `seq` strictly exceeds the stored record's for the same
    /// target. A stale/equal `seq` is rejected with
    /// [`PersistError::StaleAssertionSeq`] and the stored record is unchanged.
    ///
    /// The caller (the put-assertion op) verifies the record *before* calling
    /// this; persistence is not a trust boundary. The in-transaction seq guard
    /// is defense-in-depth against a racing lower-seq write.
    ///
    /// # Errors
    /// Returns [`PersistError::StaleAssertionSeq`] if the write does not
    /// supersede, or [`PersistError`] on a SQLite/serialization failure.
    pub fn save_assertion(
        &self,
        record: &SignedAssertion,
        ack: &Ack,
    ) -> Result<(), PersistError> {
        let json = serde_json::to_string(record)?;
        let ack_json = serde_json::to_string(ack)?;
        let seq = i64::try_from(record.seq).unwrap_or(i64::MAX);
        let subkey = record.subkey.as_deref().unwrap_or("");
        let tx = self.conn.unchecked_transaction()?;
        let applied = tx.execute(
            "INSERT INTO assertion (did, kind, subkey, seq, json, ack)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(did, kind, subkey) DO UPDATE
                 SET seq = excluded.seq, json = excluded.json, ack = excluded.ack
             WHERE excluded.seq > assertion.seq",
            rusqlite::params![record.did, record.kind, subkey, seq, json, ack_json],
        )?;
        tx.commit()?;
        if applied == 0 {
            let target = match record.subkey.as_deref() {
                None => format!("{}/{}", record.did, record.kind),
                Some(sk) => format!("{}/{}/{sk}", record.did, record.kind),
            };
            return Err(PersistError::StaleAssertionSeq { target, seq: record.seq });
        }
        Ok(())
    }

    /// The stored `seq` for `(did, kind, subkey)`, if a record exists — the
    /// `prior_seq` fed to verification at write time so a replayed/lower-seq
    /// assertion is refused before it is stored.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn assertion_seq(
        &self,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
    ) -> Result<Option<u64>, PersistError> {
        let seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM assertion WHERE did = ?1 AND kind = ?2 AND subkey = ?3",
                rusqlite::params![did, kind, subkey.unwrap_or("")],
                |row| row.get(0),
            )
            .optional()?;
        Ok(seq.map(|s| u64::try_from(s).unwrap_or(0)))
    }

    /// Erase the assertion at `(did, kind, subkey)` — a hard delete leaving no
    /// row and **no seq residue** (ADR 0005 / A2), so a re-write starts fresh at
    /// seq 1. Returns whether a row was removed (so the caller can 404 an absent
    /// target). Erasability is a kind-declaration check made upstream; this is the
    /// raw removal.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn delete_assertion(
        &self,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
    ) -> Result<bool, PersistError> {
        let n = self.conn.execute(
            "DELETE FROM assertion WHERE did = ?1 AND kind = ?2 AND subkey = ?3",
            rusqlite::params![did, kind, subkey.unwrap_or("")],
        )?;
        Ok(n > 0)
    }

    /// The subkeys a DID holds for one kind, sorted (ADR 0005 / A2). A namespace
    /// row (no subkey) is stored as `''` and returned as-is when present. Self-only
    /// enumeration is enforced upstream (owner-authz); this is the raw query.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn list_assertion_subkeys(&self, did: &str, kind: &str) -> Result<Vec<String>, PersistError> {
        let mut stmt = self
            .conn
            .prepare("SELECT subkey FROM assertion WHERE did = ?1 AND kind = ?2 ORDER BY subkey")?;
        let rows = stmt.query_map(rusqlite::params![did, kind], |row| row.get::<_, String>(0))?;
        let mut subkeys = Vec::new();
        for row in rows {
            subkeys.push(row?);
        }
        Ok(subkeys)
    }

    /// The head of a chain (ADR 0005 / A3) — the highest-seq entry's seq, total,
    /// and hash, which a proposed successor must follow and link to. `None` for an
    /// empty chain (the next entry is genesis).
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn latest_chain_entry(
        &self,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
    ) -> Result<Option<crate::chain_kind::PrevEntry>, PersistError> {
        let row = self
            .conn
            .query_row(
                "SELECT seq, total, entry_hash FROM chain_entry
                 WHERE did = ?1 AND kind = ?2 AND subkey = ?3
                 ORDER BY seq DESC LIMIT 1",
                rusqlite::params![did, kind, subkey.unwrap_or("")],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)),
            )
            .optional()?;
        Ok(row.map(|(seq, total, entry_hash)| crate::chain_kind::PrevEntry {
            seq: u64::try_from(seq).unwrap_or(0),
            total: u64::try_from(total).unwrap_or(0),
            entry_hash,
        }))
    }

    /// Append a verified chain entry (ADR 0005 / A3) in one transaction: the entry
    /// is inserted into the append-only `chain_entry` history, and the `assertion`
    /// row is upserted to the same signed record so a point read returns the latest
    /// total. The seq's uniqueness in the chain PRIMARY KEY is the last-line fork
    /// guard. Verification (`verify_step`) is the caller's; this is the durable
    /// write.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite/serialization failure (including a
    /// duplicate seq — a fork — surfaced as a constraint violation).
    pub fn append_chain_entry(
        &self,
        record: &SignedAssertion,
        ack: &Ack,
        body: &crate::chain_kind::ChainCounterBody,
        entry_hash: &str,
    ) -> Result<(), PersistError> {
        let json = serde_json::to_string(record)?;
        let ack_json = serde_json::to_string(ack)?;
        let seq = i64::try_from(record.seq).unwrap_or(i64::MAX);
        let total = i64::try_from(body.total).unwrap_or(i64::MAX);
        let subkey = record.subkey.as_deref().unwrap_or("");
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO chain_entry
                 (did, kind, subkey, seq, delta, total, prev_entry_hash, entry_hash, json, ack)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                record.did, record.kind, subkey, seq, body.delta, total,
                body.prev_entry_hash, entry_hash, json, ack_json
            ],
        )?;
        tx.execute(
            "INSERT INTO assertion (did, kind, subkey, seq, json, ack)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(did, kind, subkey) DO UPDATE
                 SET seq = excluded.seq, json = excluded.json, ack = excluded.ack
             WHERE excluded.seq > assertion.seq",
            rusqlite::params![record.did, record.kind, subkey, seq, json, ack_json],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Every entry of a chain, seq-ordered, each with its signed JSON (ADR 0005 /
    /// A3) — the input to recomputation and the `?chain=1` read. (Checkpoint-bounded
    /// windows arrive with A4; A3 returns the whole chain.)
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn chain_entries(
        &self,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
    ) -> Result<Vec<(crate::chain_kind::ChainEntry, String)>, PersistError> {
        let sk = subkey.unwrap_or("");
        let mut stmt = self.conn.prepare(
            "SELECT seq, delta, total, prev_entry_hash, json FROM chain_entry
             WHERE did = ?1 AND kind = ?2 AND subkey = ?3 ORDER BY seq",
        )?;
        let rows = stmt.query_map(rusqlite::params![did, kind, sk], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, delta, total, prev_entry_hash, json) = row?;
            out.push((
                crate::chain_kind::ChainEntry {
                    did: did.to_owned(),
                    kind: kind.to_owned(),
                    subkey: subkey.map(str::to_owned),
                    seq: u64::try_from(seq).unwrap_or(0),
                    body: crate::chain_kind::ChainCounterBody {
                        delta,
                        total: u64::try_from(total).unwrap_or(0),
                        prev_entry_hash,
                    },
                },
                json,
            ));
        }
        Ok(out)
    }

    /// Load a stored assertion + its ack, if present — the durable signed
    /// artifacts, for read-back. Surfaces a parse failure as an error: an owner
    /// reading back its own record should see a loud failure, not a silent
    /// default.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or deserialization failure.
    pub fn load_assertion(
        &self,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
    ) -> Result<Option<(SignedAssertion, Ack)>, PersistError> {
        match self.assertion_json(did, kind, subkey)? {
            Some((json, ack_json)) => Ok(Some((
                serde_json::from_str(&json)?,
                serde_json::from_str(&ack_json)?,
            ))),
            None => Ok(None),
        }
    }

    /// Resolve the effective read policy for a target, finest-grain-wins: a
    /// per-object policy (the `policy` kind with the cid subkey) overrides a
    /// namespace policy (no subkey), which overrides the world-readable
    /// default. A stored row that fails to parse resolves **fail-closed** to
    /// [`ResolvedPolicy::deny`] — never to a more permissive value.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn resolve_policy(
        &self,
        did: &str,
        cid: Option<&str>,
    ) -> Result<ResolvedPolicy, PersistError> {
        if let Some(cid) = cid {
            if let Some((json, _)) = self.assertion_json(did, POLICY_KIND, Some(cid))? {
                return Ok(resolved_from_json(&json));
            }
        }
        if let Some((json, _)) = self.assertion_json(did, POLICY_KIND, None)? {
            return Ok(resolved_from_json(&json));
        }
        Ok(ResolvedPolicy::world())
    }

    /// Resolve **only** a per-object policy for `(did, cid)`, returning `None`
    /// when the object has no policy of its own (so the caller can fall back to
    /// a namespace policy it resolved once). An unparseable row fails closed to
    /// [`ResolvedPolicy::deny`]. The batch primitive for `listBlobs`.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn resolve_object_policy(
        &self,
        did: &str,
        cid: &str,
    ) -> Result<Option<ResolvedPolicy>, PersistError> {
        Ok(self
            .assertion_json(did, POLICY_KIND, Some(cid))?
            .map(|(json, _)| resolved_from_json(&json)))
    }

    /// The customer's at-rest cap from their ceiling dial, if one is set.
    /// A stored dial that fails to parse **fails closed to a cap of 0** —
    /// new stores refuse loudly (egress is untouched, B6) rather than
    /// silently dropping the customer's protection.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn at_rest_dial(&self, did: &str) -> Result<Option<u64>, PersistError> {
        let Some((json, _)) = self.assertion_json(did, crate::dials::CEILING_DIAL_KIND, None)?
        else {
            return Ok(None);
        };
        let parsed = serde_json::from_str::<SignedAssertion>(&json)
            .ok()
            .and_then(|a| serde_json::from_value::<crate::dials::CeilingDialBody>(a.body).ok());
        if let Some(body) = parsed {
            return Ok(body.at_rest_bytes);
        }
        tracing::warn!(%did, "unparseable ceiling dial — failing closed to cap 0");
        Ok(Some(0))
    }

    /// The customer's per-period spend cap from their ceiling dial, if set.
    /// An unparseable dial fails closed to 0¢ (loud write refusals; egress
    /// untouched).
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn spend_dial(&self, did: &str) -> Result<Option<u64>, PersistError> {
        let Some((json, _)) = self.assertion_json(did, crate::dials::CEILING_DIAL_KIND, None)?
        else {
            return Ok(None);
        };
        let parsed = serde_json::from_str::<SignedAssertion>(&json)
            .ok()
            .and_then(|a| serde_json::from_value::<crate::dials::CeilingDialBody>(a.body).ok());
        if let Some(body) = parsed {
            return Ok(body.spend_cents);
        }
        tracing::warn!(%did, "unparseable ceiling dial — failing closed to 0¢ spend");
        Ok(Some(0))
    }

    /// The account's asserted mode (`active` unless a drawdown dial is in
    /// force). An unparseable mode dial fails closed to **drawdown** —
    /// books shut loudly rather than silently open.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn account_mode(&self, did: &str) -> Result<crate::dials::AccountMode, PersistError> {
        let Some((json, _)) =
            self.assertion_json(did, crate::dials::ACCOUNT_MODE_DIAL_KIND, None)?
        else {
            return Ok(crate::dials::AccountMode::Active);
        };
        let parsed = serde_json::from_str::<SignedAssertion>(&json)
            .ok()
            .and_then(|a| serde_json::from_value::<crate::dials::AccountModeBody>(a.body).ok());
        if let Some(body) = parsed {
            return Ok(body.mode);
        }
        tracing::warn!(%did, "unparseable account-mode dial — failing closed to drawdown");
        Ok(crate::dials::AccountMode::Drawdown)
    }

    /// The current spend period's meter baseline (0 = no period dial ever —
    /// the period is the whole history).
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure; a non-numeric stored value.
    pub fn period_baseline(&self, did: &str) -> Result<u64, PersistError> {
        match self.get_meta(&format!("period_baseline:{did}"))? {
            Some(v) => v.parse::<u64>().map_err(|e| {
                PersistError::Json(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("period_baseline:{did}: {e}"),
                )))
            }),
            None => Ok(0),
        }
    }

    /// The customer's asserted receipt mode (`unilateral` unless a
    /// bilateral dial is in force). An unparseable dial fails toward
    /// **bilateral** — the stronger non-repudiation the customer signed
    /// *something* asking for; it never weakens silently.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn receipt_mode_dial(
        &self,
        did: &str,
    ) -> Result<crate::dials::ReceiptModeChoice, PersistError> {
        let Some((json, _)) =
            self.assertion_json(did, crate::dials::RECEIPT_MODE_DIAL_KIND, None)?
        else {
            return Ok(crate::dials::ReceiptModeChoice::Unilateral);
        };
        let parsed = serde_json::from_str::<SignedAssertion>(&json)
            .ok()
            .and_then(|a| serde_json::from_value::<crate::dials::ReceiptModeBody>(a.body).ok());
        if let Some(body) = parsed {
            return Ok(body.mode);
        }
        tracing::warn!(%did, "unparseable receipt-mode dial — failing toward bilateral");
        Ok(crate::dials::ReceiptModeChoice::Bilateral)
    }

    /// Add `signer`'s countersignature to the stored receipt whose content
    /// hash is `content_hash`. Returns the completed receipt. `None` if no
    /// such receipt exists for `did`.
    ///
    /// The caller verifies the signature *before* calling this; persistence
    /// is not a trust boundary.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite or (de)serialization failure.
    pub fn countersign_receipt(
        &self,
        did: &str,
        content_hash: &str,
        signer: &str,
        sig: &str,
    ) -> Result<Option<crate::receipts::Receipt>, PersistError> {
        let row: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT rowid, json FROM receipt
                  WHERE did = ?1 AND json LIKE ?2
                  ORDER BY rowid DESC LIMIT 1",
                rusqlite::params![did, format!("%{content_hash}%")],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((rowid, json)) = row else {
            return Ok(None);
        };
        let receipt: crate::receipts::Receipt = serde_json::from_str(&json)?;
        if receipt.content_hash() != content_hash {
            return Ok(None);
        }
        let mut sigs = receipt.sigs().clone();
        sigs.insert(signer.to_owned(), sig.to_owned());
        let completed = crate::receipts::Receipt::from_parts(
            receipt.core().clone(),
            receipt.content_hash().to_owned(),
            receipt.mode(),
            sigs,
        );
        self.conn.execute(
            "UPDATE receipt SET json = ?2 WHERE rowid = ?1",
            rusqlite::params![rowid, serde_json::to_string(&completed)?],
        )?;
        Ok(Some(completed))
    }

    /// Whether `did` has any per-object policy rows at all — a single `EXISTS`
    /// query that lets `listBlobs` skip per-cid checks entirely for the common
    /// fully-ungated DID.
    ///
    /// # Errors
    /// Returns [`PersistError`] on a SQLite failure.
    pub fn has_object_policies(&self, did: &str) -> Result<bool, PersistError> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM assertion
                            WHERE did = ?1 AND kind = ?2 AND subkey != '')",
            rusqlite::params![did, POLICY_KIND],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    /// Fetch an assertion row's stored `(json, ack)` for a target, if present.
    fn assertion_json(
        &self,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
    ) -> Result<Option<(String, String)>, PersistError> {
        Ok(self
            .conn
            .query_row(
                "SELECT json, ack FROM assertion
                  WHERE did = ?1 AND kind = ?2 AND subkey = ?3",
                rusqlite::params![did, kind, subkey.unwrap_or("")],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
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

/// Build a [`ResolvedPolicy`] from a stored policy row's JSON, **failing closed**:
/// a row that will not parse resolves to owner-only ([`ResolvedPolicy::deny`]),
/// never to the permissive world default. A stored row means the owner set a
/// policy; if we cannot read it, we must not widen access.
fn resolved_from_json(json: &str) -> ResolvedPolicy {
    let body = serde_json::from_str::<SignedAssertion>(json)
        .ok()
        .and_then(|a| serde_json::from_value::<PolicyBody>(a.body).ok());
    match body {
        Some(body) => ResolvedPolicy::from_body(&body),
        None => ResolvedPolicy::deny(),
    }
}

#[cfg(test)]
mod tests {
    use super::Store;
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;
    use crate::manifest::{build_manifest, ManifestLeaf};
    use super::{Ack, SignedAssertion};
    use crate::policy::{PolicyBody, ReadClass, POLICY_KIND};

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

    /// Build + Model-A-sign a policy assertion (the test helper the old
    /// `PolicyRecord::sign_owner` tests used, on the substrate).
    fn policy_assertion(
        did: &str,
        cid: Option<&str>,
        class: ReadClass,
        readers: &[String],
        seq: u64,
        owner: &crate::crypto::Keypair,
    ) -> (SignedAssertion, Ack) {
        let body = PolicyBody { read_class: class, readers: readers.to_vec() };
        let record = SignedAssertion::sign_owner(
            POLICY_KIND,
            did,
            cid,
            seq,
            serde_json::to_value(&body).expect("json"),
            &crate::policy::policy_body_fold(&body),
            owner,
        );
        let ack = crate::assertion::make_ack(&record, &crate::crypto::derive_keypair("m", "attest"))
            .expect("ack");
        (record, ack)
    }

    #[test]
    fn resolve_is_object_over_namespace_over_world() {
        let owner = derive_keypair("m", "policy-owner");
        let did = derive_id(&owner.verifying_key());
        let cid = crate::crypto::sha256_hex(b"obj");
        let alice = "did:plc:alice".to_owned();
        let store = Store::open_in_memory().expect("open");

        // No rows anywhere → the world default.
        assert_eq!(
            store.resolve_policy(&did, Some(&cid)).expect("resolve").read_class(),
            ReadClass::World,
        );

        // A namespace policy gates the whole DID.
        let (ns, ns_ack) = policy_assertion(
            &did,
            None,
            ReadClass::Grantees,
            std::slice::from_ref(&alice),
            1,
            &owner,
        );
        store.save_assertion(&ns, &ns_ack).expect("save namespace");
        assert_eq!(
            store.resolve_policy(&did, None).expect("resolve").read_class(),
            ReadClass::Grantees,
        );
        // An object with no policy of its own inherits the namespace policy.
        assert_eq!(
            store.resolve_policy(&did, Some(&cid)).expect("resolve").read_class(),
            ReadClass::Grantees,
            "object inherits namespace when it has no own policy",
        );

        // A per-object policy overrides the namespace for that object only.
        let (obj, obj_ack) =
            policy_assertion(&did, Some(&cid), ReadClass::World, &[], 1, &owner);
        store.save_assertion(&obj, &obj_ack).expect("save object");
        assert_eq!(
            store.resolve_policy(&did, Some(&cid)).expect("resolve").read_class(),
            ReadClass::World,
            "object policy overrides namespace",
        );
        assert_eq!(
            store.resolve_policy(&did, None).expect("resolve").read_class(),
            ReadClass::Grantees,
            "namespace policy is unchanged by the object override",
        );
        assert!(store.has_object_policies(&did).expect("exists"), "object rows are visible");

        // Read-back returns the stored record AND its ack, verbatim.
        let (loaded, loaded_ack) = store
            .load_assertion(&did, POLICY_KIND, Some(&cid))
            .expect("load")
            .expect("present");
        assert_eq!(loaded, obj);
        assert_eq!(loaded_ack, obj_ack, "the ack is stored and returned with the record");
    }

    #[test]
    fn higher_seq_supersedes_equal_or_lower_is_rejected() {
        let owner = derive_keypair("m", "policy-owner");
        let did = derive_id(&owner.verifying_key());
        let alice = "did:plc:alice".to_owned();
        let bob = "did:plc:bob".to_owned();
        let store = Store::open_in_memory().expect("open");

        let (s1, a1) = policy_assertion(
            &did,
            None,
            ReadClass::Grantees,
            std::slice::from_ref(&alice),
            1,
            &owner,
        );
        store.save_assertion(&s1, &a1).expect("save seq 1");
        assert_eq!(store.assertion_seq(&did, POLICY_KIND, None).expect("seq"), Some(1));

        // Equal seq is rejected; the stored policy is unchanged.
        let (equal, ea) = policy_assertion(
            &did,
            None,
            ReadClass::Grantees,
            &[alice.clone(), bob.clone()],
            1,
            &owner,
        );
        assert!(
            matches!(
                store.save_assertion(&equal, &ea),
                Err(super::PersistError::StaleAssertionSeq { .. })
            ),
            "equal seq is rejected",
        );
        assert_eq!(
            store.resolve_policy(&did, None).expect("resolve").readers(),
            std::slice::from_ref(&alice),
            "a rejected write leaves the stored policy unchanged",
        );

        // Lower seq is rejected.
        let (lower, la) = policy_assertion(&did, None, ReadClass::Owner, &[], 0, &owner);
        assert!(store.save_assertion(&lower, &la).is_err(), "lower seq is rejected");

        // Strictly-higher seq supersedes.
        let (s2, a2) = policy_assertion(
            &did,
            None,
            ReadClass::Grantees,
            &[alice.clone(), bob.clone()],
            2,
            &owner,
        );
        store.save_assertion(&s2, &a2).expect("save seq 2");
        assert_eq!(
            store.resolve_policy(&did, None).expect("resolve").readers().len(),
            2,
            "the higher-seq policy is now in force",
        );
    }

    #[test]
    fn unparseable_row_resolves_fail_closed_to_deny() {
        let store = Store::open_in_memory().expect("open");
        let did = "id:corrupt";
        // A garbage row (corruption, or a hostile direct write) must never widen
        // access — it fails closed to owner-only, not to the world default.
        store
            .conn
            .execute(
                "INSERT INTO assertion (did, kind, subkey, seq, json, ack)
                 VALUES (?1, 'policy', '', ?2, ?3, '{}')",
                rusqlite::params![did, 1_i64, "{ not valid json"],
            )
            .expect("raw insert");
        let resolved = store.resolve_policy(did, None).expect("resolve");
        assert_eq!(
            resolved.read_class(),
            ReadClass::Owner,
            "an unparseable row is owner-only (fail-closed)",
        );
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
