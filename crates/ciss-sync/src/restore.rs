//! The restore flow: locate the fs-manifest, fetch every chunk (verified),
//! and materialize the tree atomically — a file appears at its final path
//! only after all of its bytes verified (write to a temp name, rename last).
//! A tampered or substituted chunk fails the restore closed: the error names
//! the cid and the target path, and no partial file is left behind.

use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use crate::error::SyncError;
use crate::manifest::{DagCbor, FsManifest, ManifestCodec};
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

fn io_err(path: &Path, source: std::io::Error) -> SyncError {
    SyncError::Io { path: path.to_path_buf(), source }
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

    // 2. Materialize each file: fetch + verify every chunk into a temp file,
    // set metadata, then rename into place — verify-before-rename means a
    // failure never leaves a partial file at the final path.
    let mut chunks_fetched = 0u64;
    let mut bytes_fetched = 0u64;
    for (path, entry) in &manifest.entries {
        let final_path = dir.join(path);
        let parent = final_path.parent().expect("manifest paths are relative, never bare root");
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;

        let tmp_path = parent.join(format!(
            ".ciss-restore-{}.tmp",
            final_path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
        ));
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
        if content.len() as u64 != entry.size {
            return Err(SyncError::Decode(format!(
                "{path}: reassembled {} bytes, manifest says {}",
                content.len(),
                entry.size
            )));
        }

        fs::write(&tmp_path, &content).map_err(|e| io_err(&tmp_path, e))?;
        restore_metadata(&tmp_path, entry)?;
        fs::rename(&tmp_path, &final_path).map_err(|e| io_err(&final_path, e))?;
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

/// Apply `mode` and `mtime` to the restored file. The mtime is an assertion
/// being replayed, never an ordering input; a pre-epoch mtime is skipped
/// with a warning rather than guessed at.
fn restore_metadata(path: &Path, entry: &crate::manifest::FileEntry) -> Result<(), SyncError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(entry.mode))
            .map_err(|e| io_err(path, e))?;
    }
    if entry.mtime_secs >= 0 {
        let mtime = UNIX_EPOCH
            + Duration::new(
                u64::try_from(entry.mtime_secs).expect("not possible: checked non-negative"),
                entry.mtime_nanos,
            );
        let file = fs::File::open(path).map_err(|e| io_err(path, e))?;
        file.set_modified(mtime).map_err(|e| io_err(path, e))?;
    } else {
        tracing::warn!(path = %path.display(), "pre-epoch mtime not restored");
    }
    Ok(())
}
