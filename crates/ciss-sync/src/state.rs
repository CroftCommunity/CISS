//! The per-tree sync state root: one directory holding the scan index, the
//! placeholder store, the chunk cache, and config. Always lives *outside*
//! the synced tree (scanning your own mutating sqlite poisons the manifest —
//! an M1 lesson encoded as structure).
//!
//! Layout:
//! ```text
//! <state_dir>/
//!   state.sqlite   scan_index + placeholders + config
//!   cache/         cache.sqlite + one file per cached chunk (by cid)
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::cache::ChunkCache;
use crate::error::SyncError;
use crate::index::Index;
use crate::placeholder::PlaceholderStore;

/// The default chunk-cache budget when none was ever configured (256 MiB).
pub const DEFAULT_CACHE_BUDGET: u64 = 256 * 1024 * 1024;

/// A tree's sync state, opened from its state root.
pub struct SyncState {
    /// The mtime/size scan fast-path (M1's, now wired in by default).
    pub index: Index,
    /// The evicted files' logical entries.
    pub placeholders: PlaceholderStore,
    /// The budgeted chunk cache.
    pub cache: ChunkCache,
    dir: PathBuf,
}

impl SyncState {
    /// Open (or create) the state root at `dir`. The cache budget comes from
    /// the persisted config (default [`DEFAULT_CACHE_BUDGET`]).
    ///
    /// # Errors
    ///
    /// Filesystem or sqlite failures.
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, SyncError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| SyncError::Io { path: dir.clone(), source: e })?;
        let db = dir.join("state.sqlite");
        let budget = read_config_u64(&db, "cache_budget")?.unwrap_or(DEFAULT_CACHE_BUDGET);
        Ok(Self {
            index: Index::open(&db)?,
            placeholders: PlaceholderStore::open(&db)?,
            cache: ChunkCache::open(dir.join("cache"), budget)?,
            dir,
        })
    }

    /// Persist a new cache budget and reopen the cache under it.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn set_cache_budget(&mut self, budget: u64) -> Result<(), SyncError> {
        write_config_u64(&self.dir.join("state.sqlite"), "cache_budget", budget)?;
        self.cache = ChunkCache::open(self.dir.join("cache"), budget)?;
        Ok(())
    }

    /// The state root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Read a persisted config value (the frontier keeps `device_counter`,
    /// `last_head_cid`, and `base_fs_root` here).
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn config_get(&self, key: &str) -> Result<Option<String>, SyncError> {
        let conn = config_conn(&self.dir.join("state.sqlite"))?;
        let value: Option<String> = conn
            .query_row("SELECT value FROM config WHERE key = ?1", [key], |r| r.get(0))
            .optional()?;
        Ok(value)
    }

    /// Persist a config value.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn config_set(&self, key: &str, value: &str) -> Result<(), SyncError> {
        let conn = config_conn(&self.dir.join("state.sqlite"))?;
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// The configured spending ceiling in cents, if any (M5 cost twin).
    ///
    /// # Errors
    ///
    /// Sqlite failures; a non-numeric stored value.
    pub fn ceiling_cents(&self) -> Result<Option<u64>, SyncError> {
        read_config_u64(&self.dir.join("state.sqlite"), "ceiling_cents")
    }

    /// Set or clear the spending ceiling.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn set_ceiling_cents(&mut self, cents: Option<u64>) -> Result<(), SyncError> {
        if let Some(c) = cents {
            return write_config_u64(&self.dir.join("state.sqlite"), "ceiling_cents", c);
        }
        let conn = config_conn(&self.dir.join("state.sqlite"))?;
        conn.execute("DELETE FROM config WHERE key = 'ceiling_cents'", [])?;
        Ok(())
    }

    /// Ledger a completed transfer's bytes (M5). The ledger stores bytes and
    /// derives cents over the *total*, exactly as a server statement does —
    /// per-sync flooring would under-count against the real bill.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn record_spend_bytes(&self, bytes: u64) -> Result<(), SyncError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let conn = spend_conn(&self.dir.join("state.sqlite"))?;
        conn.execute(
            "INSERT INTO spend (ts, bytes) VALUES (?1, ?2)",
            rusqlite::params![ts, bytes],
        )?;
        Ok(())
    }

    /// Total transferred bytes on the ledger.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn spent_bytes(&self) -> Result<u64, SyncError> {
        let conn = spend_conn(&self.dir.join("state.sqlite"))?;
        let total: i64 =
            conn.query_row("SELECT COALESCE(SUM(bytes), 0) FROM spend", [], |r| r.get(0))?;
        Ok(u64::try_from(total).unwrap_or(0))
    }

    /// The ledger priced by the server's own tariff, over total bytes.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn spent_cents(&self) -> Result<u64, SyncError> {
        Ok(ciss::pricing::postage_cents(self.spent_bytes()?))
    }

    /// Clear the spend ledger (a new period).
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn reset_spend(&self) -> Result<(), SyncError> {
        let conn = spend_conn(&self.dir.join("state.sqlite"))?;
        conn.execute("DELETE FROM spend", [])?;
        Ok(())
    }

    /// A stable 16-hex identifier for (profile, tree path) — the state root's
    /// directory name under the per-user data dir.
    #[must_use]
    pub fn tree_id(profile: &str, tree: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(profile.as_bytes());
        hasher.update([0]);
        hasher.update(tree.as_os_str().as_encoded_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        crate::chunk::Hash32(digest).to_hex()[..16].to_owned()
    }
}

fn config_conn(db: &Path) -> Result<Connection, SyncError> {
    let conn = Connection::open(db)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
    )?;
    Ok(conn)
}

fn spend_conn(db: &Path) -> Result<Connection, SyncError> {
    let conn = Connection::open(db)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS spend (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            bytes INTEGER NOT NULL
        );",
    )?;
    Ok(conn)
}

fn read_config_u64(db: &Path, key: &str) -> Result<Option<u64>, SyncError> {
    let conn = config_conn(db)?;
    let value: Option<String> = conn
        .query_row("SELECT value FROM config WHERE key = ?1", [key], |r| r.get(0))
        .optional()?;
    value
        .map(|v| {
            v.parse::<u64>()
                .map_err(|e| SyncError::Decode(format!("config {key}={v:?}: {e}")))
        })
        .transpose()
}

fn write_config_u64(db: &Path, key: &str, value: u64) -> Result<(), SyncError> {
    let conn = config_conn(db)?;
    conn.execute(
        "INSERT INTO config (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = ?2",
        rusqlite::params![key, value.to_string()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SyncState;

    /// The M5 cost-twin state: the ceiling round-trips (set, read, clear)
    /// and the spend ledger accumulates bytes, pricing the TOTAL — two
    /// 600-byte transfers are 1200 bytes = 1¢, where per-sync flooring
    /// would have said 0¢ + 0¢ and under-counted the statement.
    #[test]
    fn ceiling_and_spend_ledger_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = SyncState::open(dir.path().join("s")).expect("open");

        assert_eq!(state.ceiling_cents().expect("read"), None, "unset by default");
        state.set_ceiling_cents(Some(250)).expect("set");
        assert_eq!(state.ceiling_cents().expect("read"), Some(250));
        state.set_ceiling_cents(None).expect("clear");
        assert_eq!(state.ceiling_cents().expect("read"), None);

        assert_eq!(state.spent_bytes().expect("bytes"), 0);
        assert_eq!(state.spent_cents().expect("cents"), 0);
        state.record_spend_bytes(600).expect("record");
        assert_eq!(state.spent_cents().expect("cents"), 0, "600 bytes floors to 0¢");
        state.record_spend_bytes(600).expect("record");
        assert_eq!(state.spent_bytes().expect("bytes"), 1200);
        assert_eq!(state.spent_cents().expect("cents"), 1, "the TOTAL is priced: 1200 → 1¢");

        state.reset_spend().expect("reset");
        assert_eq!(state.spent_bytes().expect("bytes"), 0, "a new period starts at zero");
    }

    /// Config is a real round-trip (set → get → overwrite; unknown = None),
    /// the cache-budget setter persists across a reopen, and the default
    /// budget is the documented 256 MiB — pinned so plumbing stubs and
    /// constant drift fail loudly.
    #[test]
    fn config_and_cache_budget_persist() {
        assert_eq!(super::DEFAULT_CACHE_BUDGET, 256 * 1024 * 1024);

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("s");
        {
            let mut state = SyncState::open(&root).expect("open");
            assert_eq!(state.cache.budget(), super::DEFAULT_CACHE_BUDGET);
            assert_eq!(state.config_get("never-set").expect("get"), None);
            state.config_set("k", "v1").expect("set");
            assert_eq!(state.config_get("k").expect("get"), Some("v1".to_owned()));
            state.config_set("k", "v2").expect("overwrite");
            assert_eq!(state.config_get("k").expect("get"), Some("v2".to_owned()));
            state.set_cache_budget(12_345).expect("set budget");
            assert_eq!(state.cache.budget(), 12_345, "applied immediately");
        }
        let reopened = SyncState::open(&root).expect("reopen");
        assert_eq!(reopened.cache.budget(), 12_345, "budget persisted");
        assert_eq!(reopened.config_get("k").expect("get"), Some("v2".to_owned()));
    }
}
