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
    /// This tree's spend ledger (in `state.sqlite`).
    spend: crate::ledger::SpendLedger,
    /// The optional per-profile aggregate ledger (attached by the CLI).
    profile_spend: Option<crate::ledger::SpendLedger>,
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
            spend: crate::ledger::SpendLedger::open(&db, "tree")?,
            profile_spend: None,
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

    /// This tree's spend ledger (ceiling, monotonic periods, history).
    #[must_use]
    pub fn ledger(&self) -> &crate::ledger::SpendLedger {
        &self.spend
    }

    /// Attach the per-profile aggregate ledger: ceilings are then checked —
    /// and transfers recorded — against **both** scopes.
    pub fn attach_profile_ledger(&mut self, ledger: crate::ledger::SpendLedger) {
        self.profile_spend = Some(ledger);
    }

    /// The attached profile ledger, if any.
    #[must_use]
    pub fn profile_ledger(&self) -> Option<&crate::ledger::SpendLedger> {
        self.profile_spend.as_ref()
    }

    /// Pre-flight the ceiling rule against every attached ledger (tree,
    /// then profile). The first ceiling the transfer would break defers it.
    ///
    /// # Errors
    ///
    /// [`SyncError::CeilingDeferred`] naming the deferring scope; sqlite
    /// failures.
    pub fn check_ceilings(&self, want_bytes: u64) -> Result<(), SyncError> {
        self.spend.check(want_bytes)?;
        if let Some(profile) = &self.profile_spend {
            profile.check(want_bytes)?;
        }
        Ok(())
    }

    /// Record a completed transfer in every attached ledger — both scopes
    /// must see every transfer or the aggregate under-counts.
    ///
    /// # Errors
    ///
    /// Sqlite failures.
    pub fn record_spend_all(&self, bytes: u64) -> Result<(), SyncError> {
        self.spend.record_bytes(bytes)?;
        if let Some(profile) = &self.profile_spend {
            profile.record_bytes(bytes)?;
        }
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

    /// The tree ledger opens with the state, and the two-scope surface
    /// composes: the tighter ceiling defers with its scope named, and a
    /// recorded transfer lands on BOTH ledgers.
    #[test]
    fn ceilings_and_recording_span_both_scopes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = SyncState::open(dir.path().join("s")).expect("open");
        assert_eq!(state.ledger().ceiling_cents().expect("read"), None, "unset by default");

        let profile = crate::ledger::SpendLedger::open(dir.path().join("profile.sqlite"), "profile")
            .expect("open profile");
        profile.set_ceiling_cents(Some(1)).expect("set profile ceiling");
        state.attach_profile_ledger(profile);

        // No tree ceiling; the profile's 1¢ is the binding one.
        let err = state.check_ceilings(5000).expect_err("profile ceiling binds");
        match err {
            crate::error::SyncError::CeilingDeferred { scope, .. } => assert_eq!(scope, "profile"),
            other => panic!("expected CeilingDeferred, got {other}"),
        }
        state.check_ceilings(900).expect("0¢-marginal passes both scopes");

        state.record_spend_all(600).expect("record");
        assert_eq!(state.ledger().spent_bytes().expect("tree"), 600);
        assert_eq!(
            state.profile_ledger().expect("attached").spent_bytes().expect("profile"),
            600,
            "both scopes see every transfer"
        );
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
