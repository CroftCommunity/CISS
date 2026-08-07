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
}
