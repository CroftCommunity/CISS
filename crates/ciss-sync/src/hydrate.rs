//! The hydrate flow: bring an evicted file's bytes back — from the local
//! cache when it still holds them (zero metered egress), from the server
//! when it doesn't — verified either way, materialized through the same
//! verify-before-rename path restore uses. A file that reappeared at the
//! placeholder's path wins: hydrate refuses to overwrite it.

use std::path::Path;

use crate::error::SyncError;
use crate::materialize::write_verified_file;
use crate::state::SyncState;
use crate::transport::{verify_content, BlobTransport};

/// What a hydration did.
#[derive(Debug, Clone)]
pub struct HydrateReport {
    /// Files materialized.
    pub files: u64,
    /// Chunks served from the local cache.
    pub chunks_from_cache: u64,
    /// Chunks fetched from the server.
    pub chunks_from_server: u64,
    /// Bytes written to disk.
    pub bytes_written: u64,
}

/// Hydrate `paths` (or, when `None`, every placeholder) into `dir`. Each
/// chunk comes from the cache if intact there (the cache verifies on read),
/// else from `server` — verified at this layer and cached best-effort for
/// next time. The placeholder is dropped only after the file lands.
///
/// # Errors
///
/// [`SyncError::NoPlaceholder`] for an unknown path,
/// [`SyncError::HydrateWouldOverwrite`] when a file exists at the target,
/// plus transport / verification / filesystem failures.
pub async fn hydrate<S>(
    dir: &Path,
    state: &mut SyncState,
    server: &S,
    paths: Option<&[&str]>,
) -> Result<HydrateReport, SyncError>
where
    S: BlobTransport + Sync,
{
    let targets: Vec<String> = match paths {
        Some(list) => list.iter().map(|p| (*p).to_owned()).collect(),
        None => state.placeholders.all()?.into_keys().collect(),
    };

    let mut report =
        HydrateReport { files: 0, chunks_from_cache: 0, chunks_from_server: 0, bytes_written: 0 };
    for path in &targets {
        let entry = state
            .placeholders
            .get(path)?
            .ok_or_else(|| SyncError::NoPlaceholder { path: path.clone() })?;
        let final_path = dir.join(path);
        if final_path.exists() {
            return Err(SyncError::HydrateWouldOverwrite { path: path.clone() });
        }

        let mut content = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
        for chunk in &entry.chunks {
            let cid = chunk.sha256_hex();
            if let Some(bytes) = state.cache.get(&cid)? {
                report.chunks_from_cache += 1;
                tracing::debug!(cid = %&cid[..12], len = bytes.len(), "chunk from cache");
                content.extend_from_slice(&bytes);
            } else {
                let bytes = server.get(&cid).await?;
                verify_content(&cid, &bytes)?;
                report.chunks_from_server += 1;
                tracing::debug!(cid = %&cid[..12], len = bytes.len(), "chunk from server");
                let _ = state.cache.insert(&cid, &bytes)?;
                content.extend_from_slice(&bytes);
            }
        }

        write_verified_file(&final_path, path, &entry, &content)?;
        state.placeholders.remove(path)?;
        report.files += 1;
        report.bytes_written += entry.size;
        tracing::info!(path = %path, size = entry.size, "hydrated");
    }
    tracing::info!(
        files = report.files,
        chunks_from_cache = report.chunks_from_cache,
        chunks_from_server = report.chunks_from_server,
        bytes_written = report.bytes_written,
        "hydrate complete"
    );
    Ok(report)
}
