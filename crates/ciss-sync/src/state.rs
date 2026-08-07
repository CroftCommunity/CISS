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
