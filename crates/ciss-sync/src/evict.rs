//! The evict flow: drop a file's local bytes, keep its logical entry.
//!
//! Safety before space: eviction is refused unless every chunk of the file's
//! *current* bytes is provably backed — present in the server's have-set
//! (the bytes exist) **and** named in the committed keep-set manifest (the
//! billing/GC surface protects them). Only then are the chunks spilled into
//! the local cache (best-effort, within budget), the placeholder recorded,
//! and the file deleted — in that order, so a crash at any point loses
//! nothing.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::chunk::chunk_file;
use crate::error::SyncError;
use crate::scan::file_entry_for;
use crate::state::SyncState;
use crate::transport::{BlobTransport, ManifestSlot};

/// What an eviction did.
#[derive(Debug, Clone)]
pub struct EvictReport {
    /// Files whose bytes were dropped.
    pub evicted: u64,
    /// Local bytes freed.
    pub bytes_freed: u64,
    /// Chunks spilled into the local cache (cheap re-hydrate).
    pub chunks_cached: u64,
}

/// Evict `paths` (manifest-relative) under `dir`: refuse anything unbacked,
/// spill what fits into the cache, record placeholders, delete the files.
/// Fails fast on the first refusal — files already evicted stay evicted.
///
/// # Errors
///
/// [`SyncError::EvictUnbacked`] when a file's current chunks are not all on
/// the server; I/O, transport, or state failures otherwise.
pub async fn evict<S>(
    dir: &Path,
    state: &mut SyncState,
    server: &S,
    paths: &[&str],
) -> Result<EvictReport, SyncError>
where
    S: BlobTransport + ManifestSlot + Sync,
{
    let have = server.have().await?;
    let keep: HashSet<String> = server
        .keep_set()
        .await?
        .unwrap_or_default()
        .into_iter()
        .map(|(cid, _)| cid)
        .collect();

    let mut report = EvictReport { evicted: 0, bytes_freed: 0, chunks_cached: 0 };
    for path in paths {
        let file_path = dir.join(path);
        let bytes = fs::read(&file_path)
            .map_err(|e| SyncError::Io { path: file_path.clone(), source: e })?;
        let meta = fs::metadata(&file_path)
            .map_err(|e| SyncError::Io { path: file_path.clone(), source: e })?;
        let entry = file_entry_for(&file_path, &meta, &bytes)?;

        // The safety gate: every current chunk must be provably backed.
        let missing: Vec<String> = entry
            .chunks
            .iter()
            .map(super::chunk::ChunkRef::sha256_hex)
            .filter(|cid| !have.contains(cid) || !keep.contains(cid))
            .collect();
        if !missing.is_empty() {
            tracing::error!(path = %path, missing = missing.len(), "evict refused: unbacked chunks");
            return Err(SyncError::EvictUnbacked {
                path: (*path).to_owned(),
                missing_cids: missing,
            });
        }

        // Spill chunks into the cache (best-effort), then record, then delete.
        for chunk in chunk_file(&bytes) {
            let cid = chunk.chunk_ref.sha256_hex();
            if state.cache.insert(&cid, &bytes[chunk.range.clone()])? {
                report.chunks_cached += 1;
            }
        }
        state.placeholders.record(path, &entry)?;
        fs::remove_file(&file_path)
            .map_err(|e| SyncError::Io { path: file_path.clone(), source: e })?;

        report.evicted += 1;
        report.bytes_freed += entry.size;
        tracing::info!(
            path = %path,
            bytes_freed = entry.size,
            chunks_cached = report.chunks_cached,
            "evicted"
        );
    }
    Ok(report)
}
