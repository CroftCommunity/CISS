//! The crate's error type. Fail loud, fail early: no silent fallbacks.

use std::path::PathBuf;

/// Everything that can go wrong in the sync engine core.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// A chunk length violated the invariant `0 < len < MAX_OBJECT_BYTES`.
    #[error("chunk length {len} outside (0, {max}) — would be refused by the server")]
    InvalidChunkLen {
        /// The offending length.
        len: u64,
        /// The exclusive upper bound (the server's object cap).
        max: u64,
    },

    /// A filesystem operation failed; the path names the culprit.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path the operation touched.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Canonical (DAG-CBOR) or inspect (JSON) encoding failed.
    #[error("manifest encode failed: {0}")]
    Encode(String),

    /// Decoding bytes into a manifest failed — wrong bytes or wrong schema.
    #[error("manifest decode failed: {0}")]
    Decode(String),

    /// The decoded document is not a `croft.fs-manifest/v1`.
    #[error("not a croft fs-manifest (kind = {0:?})")]
    WrongKind(String),

    /// The local scan index (sqlite) failed.
    #[error("scan index error: {0}")]
    Index(#[from] rusqlite::Error),

    /// A scanned path was not valid UTF-8 and cannot be a manifest key.
    #[error("path is not valid utf-8: {0:?}")]
    NonUtf8Path(PathBuf),

    /// The server assigned a different cid than we derived locally (G3): a
    /// lying or misrouting server, or local hashing drift. Always fatal —
    /// a chunk stored under the wrong address is silent corruption later.
    #[error("server cid {got} != local sha-256 {expected} — refusing to trust the transfer")]
    CidMismatch {
        /// Our locally derived sha-256 hex.
        expected: String,
        /// The cid the server claims it stored.
        got: String,
    },

    /// The transport failed (connect error, non-2xx, interrupted stream).
    #[error("transport: {0}")]
    Transport(String),

    /// A file's bytes changed between scan and upload (TOCTOU) — the manifest
    /// no longer describes what would be uploaded, so the backup must restart.
    #[error("{path} changed between scan and upload — re-run the backup")]
    ChangedDuringBackup {
        /// The manifest key of the file that moved underneath us.
        path: String,
    },

    /// Eviction refused: the file's current bytes are not provably backed
    /// (every chunk must be in the server's have-set AND the committed
    /// keep-set). Dropping local bytes that exist nowhere else is data loss.
    #[error("refusing to evict {path}: {} chunk(s) not backed (first: {})",
            missing_cids.len(),
            missing_cids.first().map_or("-", |c| &c[..c.len().min(12)]))]
    EvictUnbacked {
        /// The manifest key of the file that was refused.
        path: String,
        /// The chunk cids the server does not provably hold.
        missing_cids: Vec<String>,
    },

    /// Hydration refused: a file already exists at the placeholder's path.
    /// The on-disk file wins — the next backup will commit it and drop the
    /// placeholder; hydrating over it would destroy new content.
    #[error("refusing to hydrate {path}: a file already exists there (the on-disk file wins)")]
    HydrateWouldOverwrite {
        /// The contested path.
        path: String,
    },

    /// Hydration asked for a path that has no placeholder.
    #[error("no placeholder for {path} — nothing to hydrate")]
    NoPlaceholder {
        /// The path with nothing recorded.
        path: String,
    },

    /// The server refused a commit because its seq was not strictly newer
    /// (I5) — another device landed first. The frontier commit loop treats
    /// this as "re-read, re-apply own slot, retry"; anything else surfaces it.
    #[error("keep-set commit at seq {attempted} was stale — another writer landed first")]
    StaleSeq {
        /// The seq the refused commit carried.
        attempted: u64,
    },

    /// The sync would take total postage past the configured ceiling, so it
    /// was deferred **whole** before any byte moved — no partial upload, no
    /// keep-set commit, nothing billed (E89: throttle/defer, never mint
    /// debt). Egress of your own data is never gated by this (POSTURE B6).
    #[error(
        "sync deferred: total postage would reach {needed_cents}¢ \
         (spent {spent_cents}¢, ceiling {ceiling_cents}¢) — nothing was transferred; \
         raise the ceiling or reset the spend ledger to proceed"
    )]
    CeilingDeferred {
        /// The total cents the ledger would reach if this sync ran.
        needed_cents: u64,
        /// Cents already on the spend ledger.
        spent_cents: u64,
        /// The configured ceiling.
        ceiling_cents: u64,
    },
}
