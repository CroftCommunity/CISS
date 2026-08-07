//! The budgeted content-addressed chunk cache — the local-footprint dial.
//!
//! Blobs live as files under the cache dir, named by their sha-256 hex;
//! metadata (size, recency, pin) lives in a sqlite table beside them. Reads
//! verify the bytes against the address before serving — a corrupt entry is
//! deleted and treated as a miss (fail-safe, never fail-open). Recency is a
//! monotonic access counter, not wall-clock, so LRU order is deterministic
//! and testable.
//!
//! The cache is always an optimization: a miss costs a (metered) server
//! fetch, never correctness. Eviction policy is LRU over unpinned entries;
//! the pin *mechanism* ships here, richer pin policies arrive with M3+.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncError;
use crate::transport::verify_content;

/// A content-addressed blob cache with a byte budget.
pub struct ChunkCache {
    dir: PathBuf,
    conn: Connection,
    budget: u64,
}

impl ChunkCache {
    /// Open (or create) a cache under `dir` with the given byte `budget`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] / [`SyncError::Index`] if the dir or sqlite cannot
    /// be created.
    pub fn open<P: AsRef<Path>>(dir: P, budget: u64) -> Result<Self, SyncError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| SyncError::Io { path: dir.clone(), source: e })?;
        let conn = Connection::open(dir.join("cache.sqlite"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chunks (
                 cid        TEXT PRIMARY KEY,
                 size       INTEGER NOT NULL,
                 access_seq INTEGER NOT NULL,
                 pinned     INTEGER NOT NULL DEFAULT 0
             );",
        )?;
        Ok(Self { dir, conn, budget })
    }

    /// Where `cid`'s bytes live on disk (exposed for tests that corrupt it).
    #[must_use]
    pub fn blob_path(&self, cid_hex: &str) -> PathBuf {
        self.dir.join(cid_hex)
    }

    /// Bytes currently accounted to the cache.
    ///
    /// # Errors
    ///
    /// [`SyncError::Index`] on sqlite failure.
    ///
    /// # Panics
    ///
    /// Never in practice: sqlite `SUM(size)` over non-negative sizes.
    pub fn total_bytes(&self) -> Result<u64, SyncError> {
        let total: i64 = self
            .conn
            .query_row("SELECT COALESCE(SUM(size), 0) FROM chunks", [], |r| r.get(0))?;
        Ok(u64::try_from(total).expect("not possible: sizes are non-negative"))
    }

    fn next_seq(&self) -> Result<i64, SyncError> {
        let seq: i64 = self
            .conn
            .query_row("SELECT COALESCE(MAX(access_seq), 0) + 1 FROM chunks", [], |r| r.get(0))?;
        Ok(seq)
    }

    /// Store `bytes` under `cid_hex` if the budget allows, evicting LRU
    /// unpinned entries to make room. Returns whether the bytes ended up
    /// cached: an oversize blob (or one that pinned entries leave no room
    /// for) is refused outright — never stored-then-immediately-evicted.
    /// Caching is best-effort by design; `false` is an outcome, not an error.
    ///
    /// # Errors
    ///
    /// Filesystem or sqlite failures only.
    ///
    /// # Panics
    ///
    /// Never in practice: internal `expect`s guard non-negative sqlite sums
    /// and blob sizes far below `i64::MAX`.
    pub fn insert(&mut self, cid_hex: &str, bytes: &[u8]) -> Result<bool, SyncError> {
        let len = bytes.len() as u64;
        let pinned_bytes: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM chunks WHERE pinned = 1",
            [],
            |r| r.get(0),
        )?;
        if len > self.budget
            || len + u64::try_from(pinned_bytes).expect("non-negative") > self.budget
        {
            tracing::debug!(cid = %&cid_hex[..cid_hex.len().min(12)], len, budget = self.budget, "cache refuses blob (budget)");
            return Ok(false);
        }

        let path = self.blob_path(cid_hex);
        fs::write(&path, bytes).map_err(|e| SyncError::Io { path: path.clone(), source: e })?;
        let seq = self.next_seq()?;
        self.conn.execute(
            "INSERT INTO chunks (cid, size, access_seq, pinned) VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(cid) DO UPDATE SET size = ?2, access_seq = ?3",
            rusqlite::params![cid_hex, i64::try_from(len).expect("blob fits i64"), seq],
        )?;
        self.evict_to_budget()?;
        Ok(true)
    }

    /// Evict LRU unpinned entries until the total fits the budget.
    fn evict_to_budget(&mut self) -> Result<(), SyncError> {
        while self.total_bytes()? > self.budget {
            let victim: Option<String> = self
                .conn
                .query_row(
                    "SELECT cid FROM chunks WHERE pinned = 0 ORDER BY access_seq ASC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(cid) = victim else {
                // Everything left is pinned; the invariant "pinned ≤ budget"
                // is enforced at insert, so this cannot loop forever.
                break;
            };
            self.remove(&cid)?;
            tracing::debug!(cid = %&cid[..cid.len().min(12)], "cache evicted (LRU)");
        }
        Ok(())
    }

    fn remove(&mut self, cid_hex: &str) -> Result<(), SyncError> {
        let path = self.blob_path(cid_hex);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| SyncError::Io { path, source: e })?;
        }
        self.conn.execute("DELETE FROM chunks WHERE cid = ?1", [cid_hex])?;
        Ok(())
    }

    /// Fetch `cid_hex`'s bytes if cached and intact. The bytes are verified
    /// against the address; a corrupt entry is deleted and reported as a
    /// miss. A hit refreshes recency.
    ///
    /// # Errors
    ///
    /// Filesystem or sqlite failures only — corruption is a miss, not an error.
    pub fn get(&mut self, cid_hex: &str) -> Result<Option<Vec<u8>>, SyncError> {
        let known: Option<i64> = self
            .conn
            .query_row("SELECT size FROM chunks WHERE cid = ?1", [cid_hex], |r| r.get(0))
            .optional()?;
        if known.is_none() {
            return Ok(None);
        }
        let path = self.blob_path(cid_hex);
        let Ok(bytes) = fs::read(&path) else {
            // The blob vanished underneath us: drop the row, miss.
            self.remove(cid_hex)?;
            return Ok(None);
        };
        if verify_content(cid_hex, &bytes).is_err() {
            tracing::warn!(cid = %&cid_hex[..cid_hex.len().min(12)], "corrupt cache entry dropped");
            self.remove(cid_hex)?;
            return Ok(None);
        }
        let seq = self.next_seq()?;
        self.conn
            .execute("UPDATE chunks SET access_seq = ?2 WHERE cid = ?1", rusqlite::params![cid_hex, seq])?;
        Ok(Some(bytes))
    }

    /// Pin `cid_hex` (never evicted). Returns whether the entry existed.
    ///
    /// # Errors
    ///
    /// Sqlite failures only.
    pub fn pin(&mut self, cid_hex: &str) -> Result<bool, SyncError> {
        Ok(self.conn.execute("UPDATE chunks SET pinned = 1 WHERE cid = ?1", [cid_hex])? > 0)
    }

    /// Unpin `cid_hex`. Returns whether the entry existed.
    ///
    /// # Errors
    ///
    /// Sqlite failures only.
    pub fn unpin(&mut self, cid_hex: &str) -> Result<bool, SyncError> {
        Ok(self.conn.execute("UPDATE chunks SET pinned = 0 WHERE cid = ?1", [cid_hex])? > 0)
    }

    /// The configured byte budget.
    #[must_use]
    pub fn budget(&self) -> u64 {
        self.budget
    }
}
