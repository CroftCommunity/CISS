//! The backup flow: scan → have/want diff → upload only what's missing →
//! commit the keep-set. Fail loud at every step — an interrupted backup
//! never commits a keep-set, and the next run resumes by skipping whatever
//! already landed (chunk-level resume; CISS has no byte-range resume).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::chunk::{chunk_file, ChunkRef};
use crate::error::SyncError;
use crate::index::Index;
use crate::manifest::{DagCbor, ManifestCodec};
use crate::scan::{scan_tree, scan_tree_indexed};
use crate::transport::{missing_blobs, BlobTransport, ManifestSlot};

/// What a backup did — the numbers the CLI prints and the flow tests assert.
#[derive(Debug, Clone)]
pub struct BackupReport {
    /// Files in the scanned tree.
    pub files: u64,
    /// Distinct chunks the tree references.
    pub chunks_total: u64,
    /// Chunks actually transferred (the have/want complement).
    pub chunks_uploaded: u64,
    /// Bytes actually transferred (chunks + the fs-manifest blob if it moved).
    pub bytes_uploaded: u64,
    /// The fs-manifest blob's content id (= its stored cid).
    pub fs_manifest_cid: String,
    /// The keep-set seq this backup committed.
    pub manifest_seq: u64,
}

/// Back up `dir` to `server`: upload the chunks and fs-manifest the server
/// lacks, then commit the keep-set (∪ chunk cids + fs-manifest cid) at
/// `last_seq + 1`. Pass an [`Index`] to skip re-chunking probably-unchanged
/// files (the index must live *outside* `dir`).
///
/// # Errors
///
/// Any scan, transport, cid-mismatch (G3), or keep-set-commit failure — an
/// error before the final commit leaves the previous keep-set untouched.
pub async fn backup<S>(
    dir: &Path,
    server: &S,
    index: Option<&mut Index>,
) -> Result<BackupReport, SyncError>
where
    S: BlobTransport + ManifestSlot + Sync,
{
    // 1. Scan.
    let manifest = match index {
        Some(idx) => scan_tree_indexed(dir, idx)?,
        None => scan_tree(dir)?,
    };
    let manifest_bytes = DagCbor.encode(&manifest)?;
    let fs_manifest_cid = manifest.content_id()?;

    // 2. The full blob set this tree needs: every distinct chunk + the
    // fs-manifest blob itself (first-seen order; dedup within the tree).
    let mut needed: Vec<(String, u64)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for entry in manifest.entries.values() {
        for c in &entry.chunks {
            let cid = c.sha256_hex();
            if seen.insert(cid.clone()) {
                needed.push((cid, u64::from(c.len)));
            }
        }
    }
    let chunks_total = needed.len() as u64;
    needed.push((fs_manifest_cid.clone(), manifest_bytes.len() as u64));

    // 3. have/want.
    let have = server.have().await?;
    let want = missing_blobs(needed.clone(), &have);
    let want_bytes: u64 = want.iter().map(|(_, b)| b).sum();
    let want_cids: HashSet<&str> = want.iter().map(|(c, _)| c.as_str()).collect();
    let chunks_to_upload =
        want.iter().filter(|(c, _)| c != &fs_manifest_cid).count() as u64;
    // The pre-transfer pricing line: the exact number a cost ceiling will
    // compare against, logged before any byte moves (the M5 cost-twin embryo).
    tracing::info!(
        chunks = chunks_to_upload,
        bytes = want_bytes,
        skipped = chunks_total - chunks_to_upload,
        "will upload"
    );

    // 4. Upload missing chunks, re-reading each file that owns one. The
    // re-chunk must reproduce the scanned refs — a file that changed since
    // the scan fails the backup rather than uploading a tree the manifest
    // doesn't describe.
    let mut chunks_uploaded = 0u64;
    let mut bytes_uploaded = 0u64;
    for (path, entry) in &manifest.entries {
        let entry_cids: Vec<String> = entry.chunks.iter().map(ChunkRef::sha256_hex).collect();
        if !entry_cids.iter().any(|c| want_cids.contains(c.as_str())) {
            tracing::debug!(path = %path, chunks = entry.chunks.len(), "all chunks present");
            continue;
        }
        let file_path = dir.join(path);
        let bytes = fs::read(&file_path)
            .map_err(|e| SyncError::Io { path: file_path.clone(), source: e })?;
        let rechunked = chunk_file(&bytes);
        let by_cid: HashMap<String, &std::ops::Range<usize>> =
            rechunked.iter().map(|c| (c.chunk_ref.sha256_hex(), &c.range)).collect();
        if rechunked.len() != entry.chunks.len()
            || !entry_cids.iter().all(|c| by_cid.contains_key(c))
        {
            return Err(SyncError::ChangedDuringBackup { path: path.clone() });
        }
        for cid in &entry_cids {
            if !want_cids.contains(cid.as_str()) {
                tracing::debug!(cid = %&cid[..12], "skip (server has it)");
                continue;
            }
            let range = by_cid[cid];
            server.put(cid, &bytes[range.start..range.end]).await?;
            chunks_uploaded += 1;
            bytes_uploaded += range.len() as u64;
            tracing::debug!(cid = %&cid[..12], len = range.len(), "uploaded");
        }
        tracing::debug!(path = %path, size = entry.size, chunks = entry.chunks.len(), "file done");
    }

    // 5. Upload the fs-manifest blob itself (unless an identical tree was
    // already backed up and the server holds it).
    if want_cids.contains(fs_manifest_cid.as_str()) {
        server.put(&fs_manifest_cid, &manifest_bytes).await?;
        bytes_uploaded += manifest_bytes.len() as u64;
        tracing::debug!(cid = %&fs_manifest_cid[..12], len = manifest_bytes.len(), "fs-manifest uploaded");
    }

    // 6. Commit the keep-set at last+1 (seq 1 on a cold namespace). A stale
    // seq is surfaced, never retried — one device cannot race itself (OQ5).
    let seq = server.current_seq().await?.map_or(1, |s| s + 1);
    server.commit_keep_set(&needed, seq).await?;

    let report = BackupReport {
        files: manifest.entries.len() as u64,
        chunks_total,
        chunks_uploaded,
        bytes_uploaded,
        fs_manifest_cid,
        manifest_seq: seq,
    };
    tracing::info!(
        files = report.files,
        chunks_total = report.chunks_total,
        chunks_uploaded = report.chunks_uploaded,
        bytes_uploaded = report.bytes_uploaded,
        seq = report.manifest_seq,
        fs_manifest = %&report.fs_manifest_cid[..12],
        "backup committed"
    );
    Ok(report)
}
