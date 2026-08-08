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
const KEY_BASELINE: &str = "reconcile_baseline_bytes";
const KEY_BASELINE_PERIOD: &str = "reconcile_baseline_period";

/// What one reconciliation against the meter did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// First reconcile of this period: a baseline was adopted so that
    /// history is not charged to the current period. Records nothing.
    Adopted {
        /// The meter total assigned as this period's zero point.
        baseline_bytes: u64,
    },
    /// The meter moved past the ledger: the difference — spend other
    /// devices (or unledgered downloads) did — was recorded.
    CaughtUp {
        /// Bytes recorded as the catch-up row.
        bytes: u64,
    },
    /// Ledger and meter agree.
    InSync,
    /// The local ledger is ahead of the meter. Surfaced, never subtracted —
    /// the ledger is append-only and the meter is monotonic, so this means
    /// something was ledgered that was never billed.
    LocalAhead {
        /// How far ahead the local ledger is, in bytes.
        bytes: u64,
    },
}

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

    /// Reconcile this ledger against the meter's cumulative account total
    /// (`GET /{did}/meter` → `running_total_bytes` — every device's billed
    /// transfers, both directions). The baseline is a byte-count marker,
    /// not a moment: on the first reconcile of a period it is set to
    /// `meter_total − local_spent` (history and other periods are not
    /// charged to this one); afterwards the positive difference between
    /// the meter's movement and the local ledger is recorded as a catch-up
    /// row — the spend this device never saw.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn reconcile_to_meter(
        &self,
        meter_total_bytes: u64,
    ) -> Result<ReconcileOutcome, SyncError> {
        let period = self.current_period()?;
        let local = self.spent_bytes()?;
        let baseline = self.config_get_u64(KEY_BASELINE)?;
        let baseline_period = self.config_get_u64(KEY_BASELINE_PERIOD)?;

        if baseline.is_none() || baseline_period != Some(period) {
            let adopted = meter_total_bytes.saturating_sub(local);
            self.config_set_u64(KEY_BASELINE, adopted)?;
            self.config_set_u64(KEY_BASELINE_PERIOD, period)?;
            tracing::info!(scope = %self.scope, baseline = adopted, period, "reconcile: baseline adopted");
            return Ok(ReconcileOutcome::Adopted { baseline_bytes: adopted });
        }

        let account_spent = meter_total_bytes.saturating_sub(baseline.unwrap_or(0));
        if account_spent > local {
            let bytes = account_spent - local;
            self.record_bytes(bytes)?;
            tracing::info!(scope = %self.scope, bytes, "reconcile: caught up to the meter");
            return Ok(ReconcileOutcome::CaughtUp { bytes });
        }
        if local > account_spent {
            let bytes = local - account_spent;
            tracing::warn!(
                scope = %self.scope,
                bytes,
                "reconcile: local ledger is ahead of the meter (unbilled rows?)"
            );
            return Ok(ReconcileOutcome::LocalAhead { bytes });
        }
        Ok(ReconcileOutcome::InSync)
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

    /// Reconciliation against the meter's cumulative account total: the
    /// first reconcile (or the first after a period change) ADOPTS a
    /// baseline so history isn't double-counted; later reconciles record
    /// the catch-up — spend other devices did — as ledger rows; a local
    /// ledger ahead of the meter is surfaced, never "corrected".
    #[test]
    fn reconcile_baselines_then_catches_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = ledger(dir.path());

        // This device already spent 1_000 bytes (billed) before the first
        // reconcile; the account meter shows 5_000 (other devices + history).
        l.record_bytes(1_000).expect("record");
        assert_eq!(
            l.reconcile_to_meter(5_000).expect("reconcile"),
            ReconcileOutcome::Adopted { baseline_bytes: 4_000 },
            "first reconcile adopts: history is not charged to this period"
        );
        assert_eq!(l.spent_bytes().expect("spent"), 1_000, "adoption records nothing");

        // The meter moves by 3_000 that this ledger never saw (another
        // device) — the catch-up lands as a row.
        assert_eq!(
            l.reconcile_to_meter(8_000).expect("reconcile"),
            ReconcileOutcome::CaughtUp { bytes: 3_000 }
        );
        assert_eq!(l.spent_bytes().expect("spent"), 4_000, "account truth in the ledger");

        // Nothing moved: in sync.
        assert_eq!(l.reconcile_to_meter(8_000).expect("reconcile"), ReconcileOutcome::InSync);

        // Local ahead of the meter (should not happen now that free
        // transfers are unledgered) — surfaced, never subtracted.
        l.record_bytes(10_000).expect("record");
        assert_eq!(
            l.reconcile_to_meter(8_000).expect("reconcile"),
            ReconcileOutcome::LocalAhead { bytes: 10_000 },
            "the ledger is never silently shrunk"
        );

        // A period change re-adopts: the new period starts at the meter's
        // now, minus whatever this period already recorded locally.
        l.reset_spend().expect("reset");
        l.record_bytes(500).expect("offline spend after reset");
        assert_eq!(
            l.reconcile_to_meter(20_000).expect("reconcile"),
            ReconcileOutcome::Adopted { baseline_bytes: 19_500 },
            "period change: fresh baseline; old meter history is not charged"
        );
        assert_eq!(l.spent_bytes().expect("spent"), 500);
        assert_eq!(
            l.reconcile_to_meter(21_000).expect("reconcile"),
            ReconcileOutcome::CaughtUp { bytes: 1_000 },
            "catch-up works in the new period"
        );
    }
}
