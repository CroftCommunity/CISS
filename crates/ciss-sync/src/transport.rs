//! The transport seam: how the engine reaches a blob store and the keep-set
//! manifest slot. The CISS implementation lives in `ciss-cli` (next to the
//! `Client` it wraps — the dependency points that way so the CLI can consume
//! this crate); an iroh implementation arrives at M4 behind the same trait.

use std::collections::HashSet;

use crate::error::SyncError;

/// A content-addressed blob store, addressed by sha-256 hex.
///
/// Addressing by expected-cid (rather than `ChunkRef`) lets the fs-manifest
/// blob ride the same path as chunks — everything stored is "bytes whose
/// address we already know."
#[async_trait::async_trait]
pub trait BlobTransport {
    /// The cid set the store already holds for this namespace (the "have"
    /// side of have/want — via `du` on CISS, an existence check only).
    async fn have(&self) -> Result<HashSet<String>, SyncError>;

    /// Store `bytes` whose sha-256 hex is `cid_hex`. Implementations MUST
    /// verify the store's assigned address equals `cid_hex` (G3) — see
    /// [`verify_server_cid`].
    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError>;

    /// Fetch the bytes addressed by `cid_hex`, verified against that address
    /// before they are returned.
    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError>;
}

/// The committed frontier as one read: the seq, the `heads` map, and the
/// keep-set leaves — everything a frontier commit or a fold starts from.
#[derive(Debug, Clone)]
pub struct FrontierView {
    /// The committed manifest seq (the only ordering the server provides).
    pub seq: u64,
    /// `device_id → cid(DeviceHead)`; empty for a pre-frontier manifest.
    pub heads: std::collections::BTreeMap<String, String>,
    /// The keep-set `(cid, size)` leaves.
    pub leaves: Vec<(String, u64)>,
}

/// The keep-set manifest slot: the billing surface the backup commits to
/// (on CISS, the signed `Manifest` under the I5 monotonic-seq CAS).
#[async_trait::async_trait]
pub trait ManifestSlot {
    /// The currently committed keep-set seq, if any manifest exists.
    async fn current_seq(&self) -> Result<Option<u64>, SyncError>;

    /// The committed keep-set as `(cid, size)` leaves, if any manifest exists
    /// (the cold-restore discovery surface: everything this namespace keeps).
    async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError>;

    /// The committed frontier (seq + heads + leaves), if any manifest exists.
    async fn frontier(&self) -> Result<Option<FrontierView>, SyncError>;

    /// Commit `(cid, size)` leaves as the keep-set at `seq`. A stale `seq`
    /// MUST surface as an error (the server refuses it under I5), never be
    /// retried silently — in M1's one-device world a conflict is an anomaly.
    async fn commit_keep_set(&self, leaves: &[(String, u64)], seq: u64)
        -> Result<(), SyncError>;

    /// Commit leaves **plus the frontier `heads` map** at `seq`. A stale seq
    /// MUST surface as [`SyncError::StaleSeq`] so the frontier commit loop
    /// can re-read and re-apply only its own slot (M3's non-lossy retry).
    async fn commit_frontier(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
        heads: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), SyncError>;
}

/// Access to the account keypair — what signs `DeviceHead`s and verifies the
/// heads a fold reads (shared-key era: one key is the whole pool).
pub trait AccountKey {
    /// The account keypair.
    fn keypair(&self) -> &ciss::crypto::Keypair;
}

/// The G3 guard as a pure function: the store's assigned cid must equal the
/// locally derived one, else the transfer cannot be trusted.
///
/// # Errors
///
/// [`SyncError::CidMismatch`] naming both sides.
pub fn verify_server_cid(expected_hex: &str, server_cid: &str) -> Result<(), SyncError> {
    if expected_hex == server_cid {
        Ok(())
    } else {
        Err(SyncError::CidMismatch { expected: expected_hex.to_owned(), got: server_cid.to_owned() })
    }
}

/// Verify `bytes` content-address to `expected_hex` (sha-256). The engine
/// runs this on every fetched blob regardless of what the transport promises
/// — defense in depth that a future transport (iroh, M4) inherits for free.
///
/// # Errors
///
/// [`SyncError::CidMismatch`] naming the expected cid and the actual digest.
pub fn verify_content(expected_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    verify_server_cid(expected_hex, &crate::chunk::Hash32(digest).to_hex())
}

/// The want side of have/want: the `(cid, size)` blobs not yet on the server,
/// input order preserved. Pure — the upload set is exactly `local − have`.
#[must_use]
pub fn missing_blobs<S: std::hash::BuildHasher>(
    local: Vec<(String, u64)>,
    have: &HashSet<String, S>,
) -> Vec<(String, u64)> {
    local.into_iter().filter(|(cid, _)| !have.contains(cid)).collect()
}
