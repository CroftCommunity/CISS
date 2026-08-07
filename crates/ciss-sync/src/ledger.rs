//! The spend ledger (M5 follow-on): an append-only record of transferred
//! bytes with a **monotonic period counter** as the only accounting
//! authority. Timestamps ride along as human reference and are consulted by
//! no query — the corpus rule ("timestamps are an assertion, never
//! authoritative") applies to money exactly as it applies to the fold.
//!
//! One implementation serves both scopes: the per-tree ledger lives in the
//! tree's `state.sqlite`; the per-profile ledger is the same object at
//! `.../profiles/<profile>/ledger.sqlite`. "Reset" never deletes — it
//! increments the period, so the ledger is a permanent record.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncError;

const KEY_CEILING: &str = "ceiling_cents";
const KEY_PERIOD: &str = "spend_period";

/// A spend ledger at one sqlite path (tree or profile scope).
#[derive(Debug, Clone)]
pub struct SpendLedger {
    db: PathBuf,
    /// Names the scope in errors/logs ("tree" / "profile").
    scope: String,
}

impl SpendLedger {
    /// Open (or create) the ledger at `db`, migrating a pre-period (v0.6.0)
    /// `spend` table in place — old rows land in period 0.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn open(db: impl AsRef<Path>, scope: &str) -> Result<Self, SyncError> {
        let ledger = Self { db: db.as_ref().to_path_buf(), scope: scope.to_owned() };
        ledger.conn()?;
        Ok(ledger)
    }

    /// The scope label this ledger names itself with.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    fn conn(&self) -> Result<Connection, SyncError> {
        let conn = Connection::open(&self.db)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS spend (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                period_seq INTEGER NOT NULL DEFAULT 0
             );",
        )?;
        // v0.6.0 shipped `spend` without `period_seq` — migrate in place.
        let has_period: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('spend') WHERE name = 'period_seq'")?
            .query_row([], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !has_period {
            conn.execute_batch(
                "ALTER TABLE spend ADD COLUMN period_seq INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        Ok(conn)
    }

    fn config_get_u64(&self, key: &str) -> Result<Option<u64>, SyncError> {
        let conn = self.conn()?;
        let value: Option<String> = conn
            .query_row("SELECT value FROM config WHERE key = ?1", [key], |r| r.get(0))
            .optional()?;
        value
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|e| SyncError::Decode(format!("ledger config {key}={v:?}: {e}")))
            })
            .transpose()
    }

    fn config_set_u64(&self, key: &str, value: u64) -> Result<(), SyncError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            rusqlite::params![key, value.to_string()],
        )?;
        Ok(())
    }

    /// The configured ceiling in cents, if any.
    ///
    /// # Errors
    ///
    /// Sqlite failures; a non-numeric stored value.
    pub fn ceiling_cents(&self) -> Result<Option<u64>, SyncError> {
        self.config_get_u64(KEY_CEILING)
    }

    /// Set or clear the ceiling.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn set_ceiling_cents(&self, cents: Option<u64>) -> Result<(), SyncError> {
        if let Some(c) = cents {
            return self.config_set_u64(KEY_CEILING, c);
        }
        let conn = self.conn()?;
        conn.execute("DELETE FROM config WHERE key = ?1", [KEY_CEILING])?;
        Ok(())
    }

    /// The current accounting period (monotonic; starts at 0).
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn current_period(&self) -> Result<u64, SyncError> {
        Ok(self.config_get_u64(KEY_PERIOD)?.unwrap_or(0))
    }

    /// Start a new period: increment the counter. **Nothing is deleted** —
    /// the old period's rows remain queryable forever. Returns the new
    /// period number.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn reset_spend(&self) -> Result<u64, SyncError> {
        let next = self.current_period()? + 1;
        self.config_set_u64(KEY_PERIOD, next)?;
        Ok(next)
    }

    /// Append a transfer's bytes to the current period. The timestamp is
    /// recorded as reference only.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn record_bytes(&self, bytes: u64) -> Result<(), SyncError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let period = self.current_period()?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO spend (ts, bytes, period_seq) VALUES (?1, ?2, ?3)",
            rusqlite::params![ts, bytes, period],
        )?;
        Ok(())
    }

    /// Total bytes recorded in period `period`.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn spent_bytes_in(&self, period: u64) -> Result<u64, SyncError> {
        let conn = self.conn()?;
        let total: i64 = conn.query_row(
            "SELECT COALESCE(SUM(bytes), 0) FROM spend WHERE period_seq = ?1",
            [period],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(total).unwrap_or(0))
    }

    /// Total bytes in the current period.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn spent_bytes(&self) -> Result<u64, SyncError> {
        self.spent_bytes_in(self.current_period()?)
    }

    /// The current period priced by the server's own tariff, over total
    /// bytes (a statement's aggregation — per-transfer flooring would
    /// under-count).
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn spent_cents(&self) -> Result<u64, SyncError> {
        Ok(ciss::pricing::postage_cents(self.spent_bytes()?))
    }

    /// The ceiling rule, pre-flight: would transferring `want_bytes` more
    /// take this period's priced total past the ceiling? Defers only a
    /// transfer that *adds* priced spend past it — a 0¢-marginal transfer
    /// is never blocked, and a total landing exactly at the ceiling passes
    /// ("stops at X" means X is spendable).
    ///
    /// # Errors
    ///
    /// [`SyncError::CeilingDeferred`] when the rule defers; sqlite failures.
    pub fn check(&self, want_bytes: u64) -> Result<(), SyncError> {
        let Some(ceiling_cents) = self.ceiling_cents()? else {
            return Ok(());
        };
        let spent_bytes = self.spent_bytes()?;
        let spent_cents = ciss::pricing::postage_cents(spent_bytes);
        let needed_cents = ciss::pricing::postage_cents(spent_bytes + want_bytes);
        if needed_cents > ceiling_cents && needed_cents > spent_cents {
            return Err(SyncError::CeilingDeferred {
                scope: self.scope.clone(),
                needed_cents,
                spent_cents,
                ceiling_cents,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(dir: &Path) -> SpendLedger {
        SpendLedger::open(dir.join("ledger.sqlite"), "tree").expect("open")
    }

    /// Periods are the only authority: reset increments the counter, spend
    /// scopes to the current period, and NOTHING is deleted — the old
    /// period's rows stay queryable.
    #[test]
    fn periods_are_monotonic_and_preserve_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(dir.path());

        assert_eq!(l.current_period().expect("period"), 0);
        l.record_bytes(600).expect("record");
        l.record_bytes(600).expect("record");
        assert_eq!(l.spent_bytes().expect("bytes"), 1200);
        assert_eq!(l.spent_cents().expect("cents"), 1, "the TOTAL is priced: 1200 → 1¢");

        let p1 = l.reset_spend().expect("reset");
        assert_eq!(p1, 1, "reset = a new period, monotonic");
        assert_eq!(l.spent_bytes().expect("bytes"), 0, "the new period starts empty");
        assert_eq!(l.spent_cents().expect("cents"), 0, "…and prices at zero");
        assert_eq!(l.spent_bytes_in(0).expect("bytes"), 1200, "history preserved, not deleted");

        l.record_bytes(500).expect("record");
        assert_eq!(l.spent_bytes().expect("bytes"), 500);
        assert_eq!(l.spent_bytes_in(0).expect("bytes"), 1200, "old period untouched");
    }

    /// A v0.6.0 ledger (no `period_seq` column) opens cleanly: old rows land
    /// in period 0 and new records work.
    #[test]
    fn migrates_the_v060_schema_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("state.sqlite");
        let conn = rusqlite::Connection::open(&db).expect("open raw");
        conn.execute_batch(
            "CREATE TABLE spend (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                bytes INTEGER NOT NULL
             );
             INSERT INTO spend (ts, bytes) VALUES (1754500000, 2500);",
        )
        .expect("seed old schema");
        drop(conn);

        let l = SpendLedger::open(&db, "tree").expect("open migrates");
        assert_eq!(l.spent_bytes_in(0).expect("bytes"), 2500, "old rows are period 0");
        l.record_bytes(100).expect("new record");
        assert_eq!(l.spent_bytes().expect("bytes"), 2600);
    }

    /// The ceiling rule's boundaries, unit-level: exactly-at passes,
    /// 0¢-marginal passes even past the ceiling, over-and-adding defers
    /// with the scope named.
    #[test]
    fn check_boundaries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(dir.path());
        assert!(l.check(u64::MAX / 2).is_ok(), "no ceiling: everything passes");

        l.set_ceiling_cents(Some(2)).expect("set");
        assert!(l.check(2000).is_ok(), "landing exactly at 2¢ passes");
        let err = l.check(3000).expect_err("3¢ over a 2¢ ceiling defers");
        match err {
            SyncError::CeilingDeferred { scope, needed_cents, spent_cents, ceiling_cents } => {
                assert_eq!(scope, "tree");
                assert_eq!((needed_cents, spent_cents, ceiling_cents), (3, 0, 2));
            }
            other => panic!("expected CeilingDeferred, got {other}"),
        }

        l.record_bytes(3000).expect("record past the ceiling anyway (unilateral ledger)");
        assert!(l.check(900).is_ok(), "0¢-marginal passes even with the ceiling exceeded");
        assert!(l.check(2000).is_err(), "adding priced spend past the ceiling defers");

        l.set_ceiling_cents(None).expect("clear");
        assert!(l.check(u64::MAX / 2).is_ok(), "cleared ceiling: everything passes");
    }
}
