//! The restore flow: locate the fs-manifest, fetch every chunk (verified),
//! and materialize the tree atomically — a file appears at its final path
//! only after all of its bytes verified (write to a temp name, rename last).
//! A tampered or substituted chunk fails the restore closed: the error names
//! the cid and the target path, and no partial file is left behind.

use std::path::Path;

use crate::error::SyncError;
use crate::manifest::{DagCbor, FsManifest, ManifestCodec};
use crate::materialize::write_verified_file;
use crate::transport::{verify_content, BlobTransport, ManifestSlot};

/// What a restore did.
#[derive(Debug, Clone)]
pub struct RestoreReport {
    /// Files materialized.
    pub files: u64,
    /// Chunks fetched from the transport.
    pub chunks_fetched: u64,
    /// Bytes fetched.
    pub bytes_fetched: u64,
    /// The fs-manifest the tree was restored from.
    pub fs_manifest_cid: String,
}

/// Cold-restore discovery: find the self-tagged fs-manifest among the
/// keep-set leaves (M1's rare disaster path — a live device knows its
/// manifest cid locally; the discoverable `heads` field arrives at M3).
/// Candidates are tried smallest-first; a leaf that fails to decode or
/// carries the wrong kind is simply not the manifest.
async fn discover_fs_manifest<S>(server: &S) -> Result<(String, Vec<u8>), SyncError>
where
    S: BlobTransport + ManifestSlot + Sync,
{
    let Some(mut leaves) = server.keep_set().await? else {
        return Err(SyncError::Decode("no keep-set manifest on the server".to_owned()));
    };
    leaves.sort_by_key(|(_, size)| *size);
    let candidates = leaves.len();
    for (cid, size) in leaves {
        let bytes = server.get(&cid).await?;
        verify_content(&cid, &bytes)?;
        if DagCbor.decode(&bytes).is_ok() {
            tracing::info!(cid = %&cid[..12], size, candidates, "cold restore: fs-manifest found");
            return Ok((cid, bytes));
        }
        tracing::debug!(cid = %&cid[..12], size, "cold restore: not a manifest, skipping");
    }
    Err(SyncError::Decode(format!(
        "no fs-manifest among the {candidates} keep-set leaves"
    )))
}

/// Restore the tree described by `fs_manifest_cid` (or, when `None`, by the
/// manifest discovered from the keep-set) into `dir`. Every fetched blob is
/// verified against its address before any of it reaches its final path;
/// `mode` and `mtime` are restored (mtime as an assertion, second+nanos).
///
/// # Errors
///
/// Transport failures, a cid mismatch on any blob (fail closed — the target
/// file is not written), a wrong-kind manifest, or filesystem errors.
///
/// # Panics
///
/// Never in practice: the internal `expect`s guard invariants held by
/// construction (manifest paths are relative; a checked-non-negative mtime).
pub async fn restore<S>(
    dir: &Path,
    server: &S,
    fs_manifest_cid: Option<&str>,
) -> Result<RestoreReport, SyncError>
where
    S: BlobTransport + ManifestSlot + Sync,
{
    // 1. The manifest: by cid, or discovered cold from the keep-set.
    let (cid, manifest_bytes) = match fs_manifest_cid {
        Some(cid) => {
            let bytes = server.get(cid).await?;
            verify_content(cid, &bytes)?;
            (cid.to_owned(), bytes)
        }
        None => discover_fs_manifest(server).await?,
    };
    let manifest: FsManifest = DagCbor.decode(&manifest_bytes)?;

    // 2. Materialize each file: fetch + verify every chunk, then land it via
    // the shared verify-before-rename path — a failure never leaves a
    // partial file at the final path.
    let mut chunks_fetched = 0u64;
    let mut bytes_fetched = 0u64;
    for (path, entry) in &manifest.entries {
        let final_path = dir.join(path);
        let mut content = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
        for chunk in &entry.chunks {
            let chunk_cid = chunk.sha256_hex();
            let bytes = server.get(&chunk_cid).await.inspect_err(|_| {
                tracing::error!(cid = %&chunk_cid[..12], path = %path, "chunk fetch failed");
            })?;
            if let Err(e) = verify_content(&chunk_cid, &bytes) {
                tracing::error!(cid = %&chunk_cid[..12], path = %path, "chunk failed verification — refusing to write");
                return Err(e);
            }
            chunks_fetched += 1;
            bytes_fetched += bytes.len() as u64;
            tracing::debug!(cid = %&chunk_cid[..12], len = bytes.len(), path = %path, "chunk verified");
            content.extend_from_slice(&bytes);
        }
        write_verified_file(&final_path, path, entry, &content)?;
        tracing::debug!(path = %path, size = entry.size, chunks = entry.chunks.len(), "restored");
    }

    let report = RestoreReport {
        files: manifest.entries.len() as u64,
        chunks_fetched,
        bytes_fetched,
        fs_manifest_cid: cid,
    };
    tracing::info!(
        files = report.files,
        chunks_fetched = report.chunks_fetched,
        bytes_fetched = report.bytes_fetched,
        fs_manifest = %&report.fs_manifest_cid[..12],
        "restore complete"
    );
    Ok(report)
}

