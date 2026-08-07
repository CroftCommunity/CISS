//! The frontier commit: publish this device's tree as a signed `DeviceHead`
//! and fold it into the shared `Frontier.heads` map, non-lossily.
//!
//! Slot discipline makes concurrency safe: a device writes only
//! `heads[its own device_id]`; a stale-seq refusal (I5) means another device
//! landed first, so the loop re-reads the frontier, re-applies its own slot
//! onto the fresh heads, recomputes the keep-set, and retries (bounded).
//! The keep-set it commits covers **every** head's closure — `DeviceHead`
//! blobs, fs-manifests, all chunks, and base manifests — never just its own
//! tree: a commit that listed only its own closure would orphan the other
//! device's bytes (the M3 no-data-loss invariant).

use std::collections::BTreeMap;
use std::path::Path;

use crate::backup::push_tree;
use crate::device_head::DeviceHead;
use crate::error::SyncError;
use crate::manifest::{DagCbor, ManifestCodec};
use crate::state::SyncState;
use crate::transport::{AccountKey, BlobTransport, FrontierView, ManifestSlot};

const MAX_COMMIT_RETRIES: u32 = 3;
const KEY_COUNTER: &str = "device_counter";
const KEY_LAST_HEAD: &str = "last_head_cid";
const KEY_BASE: &str = "base_fs_root";

/// What a frontier backup did.
#[derive(Debug, Clone)]
pub struct FrontierReport {
    /// Files in this device's logical tree.
    pub files: u64,
    /// Distinct chunks the tree references.
    pub chunks_total: u64,
    /// Chunks actually transferred.
    pub chunks_uploaded: u64,
    /// Bytes actually transferred.
    pub bytes_uploaded: u64,
    /// This device's fs-manifest cid.
    pub fs_manifest_cid: String,
    /// The seq the frontier committed at.
    pub manifest_seq: u64,
    /// The cid of the `DeviceHead` this backup published.
    pub device_head_cid: String,
    /// Stale-seq retries the commit needed (0 = landed first try).
    pub commit_retries: u32,
}

/// This device's persisted frontier state (counter/parent/base).
fn read_chain(state: &SyncState) -> Result<(u64, Option<String>, Option<String>), SyncError> {
    let counter = state
        .config_get(KEY_COUNTER)?
        .map(|v| v.parse::<u64>().map_err(|e| SyncError::Decode(format!("device_counter: {e}"))))
        .transpose()?
        .unwrap_or(0);
    Ok((counter, state.config_get(KEY_LAST_HEAD)?, state.config_get(KEY_BASE)?))
}

/// Add every blob of `head`'s closure (head blob + fs-manifest + chunks +
/// base manifest) into `leaves`, fetching what sizes require. The head is
/// verified before anything of it is trusted.
async fn extend_with_head_closure<S: BlobTransport + Sync>(
    server: &S,
    verifier: &ed25519_dalek::VerifyingKey,
    head_cid: &str,
    leaves: &mut BTreeMap<String, u64>,
) -> Result<(), SyncError> {
    let head_bytes = server.get(head_cid).await?;
    let head = DeviceHead::decode_verified(&head_bytes, verifier)?;
    leaves.insert(head_cid.to_owned(), head_bytes.len() as u64);

    let manifest_bytes = server.get(&head.fs_root).await?;
    let manifest = DagCbor.decode(&manifest_bytes)?;
    leaves.insert(head.fs_root.clone(), manifest_bytes.len() as u64);
    for entry in manifest.entries.values() {
        for chunk in &entry.chunks {
            leaves.insert(chunk.sha256_hex(), u64::from(chunk.len));
        }
    }
    if let Some(base) = &head.base {
        if !leaves.contains_key(base) {
            let base_bytes = server.get(base).await?;
            leaves.insert(base.clone(), base_bytes.len() as u64);
        }
    }
    Ok(())
}

/// Publish `dir` as this device's head and commit the frontier, non-lossily.
///
/// # Errors
///
/// Push/transport failures; a commit that stays stale past the retry bound
/// surfaces the final [`SyncError::StaleSeq`].
pub async fn backup_frontier<S>(
    dir: &Path,
    server: &S,
    state: &mut SyncState,
    device_id: &str,
) -> Result<FrontierReport, SyncError>
where
    S: BlobTransport + ManifestSlot + AccountKey + Sync,
{
    // 1. Push this device's tree (chunks + fs-manifest; have/want inside).
    let pushed = push_tree(dir, server, Some(state)).await?;

    // 2. Build + upload this commit's DeviceHead (once — the head does not
    // depend on the frontier it lands into; only the heads map does).
    let (counter, parent, base) = read_chain(state)?;
    let head = DeviceHead::new_signed(
        device_id,
        counter + 1,
        &pushed.fs_manifest_cid,
        parent,
        base,
        server.keypair(),
    );
    let head_bytes = head.encode()?;
    let head_cid = {
        use sha2::Digest as _;
        let digest: [u8; 32] = sha2::Sha256::digest(&head_bytes).into();
        crate::chunk::Hash32(digest).to_hex()
    };
    server.put(&head_cid, &head_bytes).await?;

    // 3. The commit loop: read the frontier, apply only our slot, cover every
    // head's closure in the keep-set, and retry on a stale seq.
    let verifier = server.keypair().verifying_key();
    let mut retries = 0u32;
    loop {
        let frontier = server.frontier().await?;
        let (seq, mut heads) = match &frontier {
            Some(FrontierView { seq, heads, .. }) => (seq + 1, heads.clone()),
            None => (1, BTreeMap::new()),
        };
        heads.insert(device_id.to_owned(), head_cid.clone());

        let mut leaves: BTreeMap<String, u64> =
            pushed.needed.iter().cloned().collect();
        leaves.insert(head_cid.clone(), head_bytes.len() as u64);
        for (other_id, other_cid) in &heads {
            if other_id == device_id {
                continue;
            }
            extend_with_head_closure(server, &verifier, other_cid, &mut leaves).await?;
        }
        let leaves: Vec<(String, u64)> = leaves.into_iter().collect();

        tracing::info!(
            seq,
            heads = heads.len(),
            leaves = leaves.len(),
            retries,
            "committing frontier"
        );
        match server.commit_frontier(&leaves, seq, &heads).await {
            Ok(()) => {
                state.config_set(KEY_COUNTER, &(counter + 1).to_string())?;
                state.config_set(KEY_LAST_HEAD, &head_cid)?;
                return Ok(FrontierReport {
                    files: pushed.files,
                    chunks_total: pushed.chunks_total,
                    chunks_uploaded: pushed.chunks_uploaded,
                    bytes_uploaded: pushed.bytes_uploaded,
                    fs_manifest_cid: pushed.fs_manifest_cid,
                    manifest_seq: seq,
                    device_head_cid: head_cid,
                    commit_retries: retries,
                });
            }
            Err(SyncError::StaleSeq { attempted }) if retries < MAX_COMMIT_RETRIES => {
                retries += 1;
                tracing::info!(attempted, retries, "stale seq — re-reading the frontier");
            }
            Err(e) => return Err(e),
        }
    }
}
