//! The filesystem manifest — the one artifact this client invents.
//!
//! CISS stores no paths (the S3 `key` is narration); the tree lives here:
//! `path → {mode, mtime, size, [ChunkRef]}`, serialized canonically as
//! DAG-CBOR and addressed by `content_id` = sha-256 over those bytes — the
//! same derivation the server applies when the blob is stored (invariant C1),
//! so the address is bit-for-bit the cid CISS will assign.
//!
//! The leading `kind` self-tag domain-separates the hashed pre-image
//! (Drystone §4.2 spirit), versions the schema, and is the match target for
//! Phase 3's cold-restore scan. Canonical DAG-CBOR orders map keys
//! length-first, so the 4-byte `kind` leads the 7-byte `entries` on the wire.
//!
//! Serialization is pluggable behind [`ManifestCodec`] (the E85 "keep
//! addressing pluggable" seam), but the addressed identity is **always** the
//! DAG-CBOR bytes; the pretty-JSON view exists for human inspection and is
//! never stored or addressed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chunk::ChunkRef;
use crate::error::SyncError;

/// The self-tag every fs-manifest leads with; decode refuses anything else.
pub const FS_MANIFEST_KIND: &str = "croft.fs-manifest/v1";

/// One file's metadata plus its chunk list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Unix permission bits (e.g. `0o644`); applied on restore.
    pub mode: u32,
    /// mtime seconds since the epoch — restored metadata, an *assertion*:
    /// never consulted for ordering or conflict resolution.
    pub mtime_secs: i64,
    /// mtime sub-second nanoseconds.
    pub mtime_nanos: u32,
    /// File length in bytes (equals the sum of chunk lengths).
    pub size: u64,
    /// The file's content, in order, as dual-hash chunk references.
    pub chunks: Vec<ChunkRef>,
}

/// The whole tree: relative forward-slash paths → entries, deterministically
/// ordered. Construct with [`FsManifest::new`] + [`FsManifest::insert`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsManifest {
    /// The `croft.fs-manifest/v1` self-tag (domain separation + version).
    pub kind: String,
    /// `relative/path → FileEntry`, sorted by the map itself.
    pub entries: BTreeMap<String, FileEntry>,
}

impl FsManifest {
    /// An empty manifest carrying the current `kind` tag.
    #[must_use]
    pub fn new() -> Self {
        Self { kind: FS_MANIFEST_KIND.to_owned(), entries: BTreeMap::new() }
    }

    /// Insert (or replace) a file entry under its relative path.
    pub fn insert(&mut self, path: &str, entry: FileEntry) {
        self.entries.insert(path.to_owned(), entry);
    }

    /// The addressed identity: sha-256 over the canonical DAG-CBOR bytes —
    /// exactly the cid CISS assigns when this manifest is stored as a blob.
    ///
    /// # Errors
    ///
    /// [`SyncError::Encode`] if canonical encoding fails.
    pub fn content_id(&self) -> Result<String, SyncError> {
        let bytes = DagCbor.encode(self)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(crate::chunk::Hash32(digest).to_hex())
    }
}

impl Default for FsManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// A way to turn a manifest into bytes and back. The canonical implementation
/// is [`DagCbor`]; [`PrettyJson`] is a non-authoritative inspect view.
pub trait ManifestCodec {
    /// Serialize the manifest.
    ///
    /// # Errors
    ///
    /// [`SyncError::Encode`] on serializer failure.
    fn encode(&self, manifest: &FsManifest) -> Result<Vec<u8>, SyncError>;

    /// Deserialize bytes into a manifest, refusing a wrong `kind` tag.
    ///
    /// # Errors
    ///
    /// [`SyncError::Decode`] on malformed bytes, [`SyncError::WrongKind`] if
    /// the self-tag is not [`FS_MANIFEST_KIND`].
    fn decode(&self, bytes: &[u8]) -> Result<FsManifest, SyncError>;
}

fn check_kind(manifest: FsManifest) -> Result<FsManifest, SyncError> {
    if manifest.kind == FS_MANIFEST_KIND {
        Ok(manifest)
    } else {
        Err(SyncError::WrongKind(manifest.kind))
    }
}

/// The canonical, deterministic encoding — the only bytes `content_id` sees.
pub struct DagCbor;

impl ManifestCodec for DagCbor {
    fn encode(&self, manifest: &FsManifest) -> Result<Vec<u8>, SyncError> {
        serde_ipld_dagcbor::to_vec(manifest).map_err(|e| SyncError::Encode(e.to_string()))
    }

    fn decode(&self, bytes: &[u8]) -> Result<FsManifest, SyncError> {
        let manifest: FsManifest =
            serde_ipld_dagcbor::from_slice(bytes).map_err(|e| SyncError::Decode(e.to_string()))?;
        check_kind(manifest)
    }
}

/// Human-readable JSON for inspection tooling. Never stored, never addressed:
/// `content_id` is defined over the DAG-CBOR bytes only.
pub struct PrettyJson;

impl ManifestCodec for PrettyJson {
    fn encode(&self, manifest: &FsManifest) -> Result<Vec<u8>, SyncError> {
        serde_json::to_vec_pretty(manifest).map_err(|e| SyncError::Encode(e.to_string()))
    }

    fn decode(&self, bytes: &[u8]) -> Result<FsManifest, SyncError> {
        let manifest: FsManifest =
            serde_json::from_slice(bytes).map_err(|e| SyncError::Decode(e.to_string()))?;
        check_kind(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_refuses_wrong_kind() {
        let mut m = FsManifest::new();
        m.kind = "not.a.manifest/v9".to_owned();
        let bytes = DagCbor.encode(&m).expect("encode");
        assert!(matches!(DagCbor.decode(&bytes), Err(SyncError::WrongKind(k)) if k.contains("v9")));
    }

    #[test]
    fn content_id_matches_server_derivation() {
        let m = FsManifest::new();
        let bytes = DagCbor.encode(&m).expect("encode");
        assert_eq!(m.content_id().expect("cid"), ciss::crypto::sha256_hex(&bytes));
    }
}
