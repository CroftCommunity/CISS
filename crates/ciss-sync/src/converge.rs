//! The converge flow: commit local state, fold every device's head against
//! the base, materialize the folded tree, and publish it as this device's
//! new head. Both devices compute the same fold from the same inputs, so
//! they land on byte-identical trees — convergence is derived, not decreed.
//!
//! Local edits are committed (as this device's head) *before* the fold, so
//! materializing the folded tree can never destroy unpublished work: every
//! byte the fold replaces is already reachable through this device's head
//! chain on the server.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::device_head::DeviceHead;
use crate::error::SyncError;
use crate::fold::fold;
use crate::frontier::backup_frontier;
use crate::manifest::{DagCbor, FsManifest, ManifestCodec};
use crate::materialize::write_verified_file;
use crate::state::SyncState;
use crate::transport::{verify_content, AccountKey, BlobTransport, ManifestSlot};

/// What a converge did.
#[derive(Debug, Clone)]
pub struct ConvergeReport {
    /// Files in the converged tree.
    pub files: u64,
    /// Files this device had to write (fetched from cache/server).
    pub files_written: u64,
    /// Files this device deleted (deletions that propagated).
    pub files_deleted: u64,
    /// Conflict-copies the fold preserved (paths).
    pub conflicts: Vec<String>,
    /// The converged tree's fs-manifest cid (the new shared base).
    pub fs_manifest_cid: String,
    /// The frontier seq this device's converged head committed at.
    pub manifest_seq: u64,
}

/// Fetch and decode-verify the fs-manifest at `cid`.
async fn fetch_manifest<S: BlobTransport + Sync>(
    server: &S,
    cid: &str,
) -> Result<FsManifest, SyncError> {
    let bytes = server.get(cid).await?;
    verify_content(cid, &bytes)?;
    DagCbor.decode(&bytes)
}

/// Converge `dir` with every other device's head. See the module docs for
/// the safety argument; the fold itself is `fold::fold`.
///
/// # Errors
///
/// Transport/verification failures, an unverifiable head (rejected outright),
/// or filesystem failures during materialization.
pub async fn converge<S>(
    dir: &Path,
    state: &mut SyncState,
    server: &S,
    device_id: &str,
) -> Result<ConvergeReport, SyncError>
where
    S: BlobTransport + ManifestSlot + AccountKey + Sync,
{
    // 1. Publish local state first — nothing local is ever at risk after this.
    backup_frontier(dir, server, state, device_id).await?;

    // 2. Read the frontier; decode + verify every head (self-verified fold:
    // an unverifiable head is rejected, never folded).
    let frontier = server
        .frontier()
        .await?
        .ok_or_else(|| SyncError::Decode("no frontier to converge with".to_owned()))?;
    let verifier = server.keypair().verifying_key();
    let mut heads: BTreeMap<String, FsManifest> = BTreeMap::new();
    for (dev, head_cid) in &frontier.heads {
        let head_bytes = server.get(head_cid).await?;
        let head = DeviceHead::decode_verified(&head_bytes, &verifier)?;
        heads.insert(dev.clone(), fetch_manifest(server, &head.fs_root).await?);
    }

    // 3. The base: the last converged tree this device recorded.
    let base = match state.config_get("base_fs_root")? {
        Some(cid) => Some(fetch_manifest(server, &cid).await?),
        None => None,
    };

    // 4. Fold — pure and deterministic; every device gets the same answer.
    let outcome = fold(&heads, base.as_ref())?;
    let my_tree = heads.get(device_id).cloned().unwrap_or_default();

    // 5. Materialize the delta: write what differs (cache first, then
    // server, every chunk verified), delete what the fold dropped.
    let mut files_written = 0u64;
    let mut files_deleted = 0u64;
    for (path, entry) in &outcome.tree.entries {
        if my_tree.entries.get(path).is_some_and(|mine| mine == entry) {
            continue;
        }
        let mut content = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
        for chunk in &entry.chunks {
            let cid = chunk.sha256_hex();
            if let Some(bytes) = state.cache.get(&cid)? {
                content.extend_from_slice(&bytes);
            } else {
                let bytes = server.get(&cid).await?;
                verify_content(&cid, &bytes)?;
                let _ = state.cache.insert(&cid, &bytes)?;
                content.extend_from_slice(&bytes);
            }
        }
        write_verified_file(&dir.join(path), path, entry, &content)?;
        files_written += 1;
        tracing::debug!(path = %path, "converge: written");
    }
    for path in my_tree.entries.keys() {
        if !outcome.tree.entries.contains_key(path) {
            let full = dir.join(path);
            fs::remove_file(&full).map_err(|e| SyncError::Io { path: full.clone(), source: e })?;
            files_deleted += 1;
            tracing::debug!(path = %path, "converge: deletion propagated");
        }
    }

    // 6. Publish the converged tree as this device's new head, then record
    // it as the shared base for the next fold.
    let report = backup_frontier(dir, server, state, device_id).await?;
    state.config_set("base_fs_root", &report.fs_manifest_cid)?;

    let conflicts: Vec<String> =
        outcome.conflicts.iter().map(|c| c.loser_path.clone()).collect();
    tracing::info!(
        files = outcome.tree.entries.len(),
        files_written,
        files_deleted,
        conflicts = conflicts.len(),
        seq = report.manifest_seq,
        "converged"
    );
    Ok(ConvergeReport {
        files: outcome.tree.entries.len() as u64,
        files_written,
        files_deleted,
        conflicts,
        fs_manifest_cid: report.fs_manifest_cid,
        manifest_seq: report.manifest_seq,
    })
}
