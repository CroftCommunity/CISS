//! The CISS implementation of `ciss-sync`'s transport seam.
//!
//! Lives here — next to the [`Client`] it wraps — rather than in `ciss-sync`,
//! because the CLI consumes the engine (`ciss-cli → ciss-sync`); the engine
//! depending back on the CLI would be a package cycle. Reusing this crate's
//! `Client` keeps the metered-call + `verify_cid` path single-sourced (the
//! OQ1 decision), and `HttpCiss` is the only glue.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use ciss::crypto::Keypair;
use ciss::manifest::{build_manifest, build_manifest_with_heads, ManifestLeaf};
use ciss_sync::{
    verify_server_cid, AccountKey, BlobTransport, FrontierView, ManifestSlot, SyncError, SyncState,
};

use crate::client::{session_for, Client, Session};

/// This install's stable device label for the M3 frontier: read from the
/// profile dir's `device_id` file, generated once (8 random hex) on first use.
/// Self-asserted (shared-key era) — a real device key replaces it later.
///
/// # Errors
///
/// Filesystem failures reading/creating the file.
pub fn device_id(config: &crate::config::Config) -> anyhow::Result<String> {
    let path = config.profile_dir().join("device_id");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_owned();
        anyhow::ensure!(!trimmed.is_empty(), "empty device_id at {}", path.display());
        return Ok(trimmed);
    }
    let mut raw = [0u8; 4];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow::anyhow!("entropy: {e}"))?;
    let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::create_dir_all(config.profile_dir())?;
    std::fs::write(&path, format!("{id}\n"))?;
    tracing::info!(device_id = %id, "generated this install's device id");
    Ok(id)
}

/// The default state root for (profile, tree): `$XDG_DATA_HOME` (or
/// `$HOME/.local/share`) `/ciss-ctl/sync/<tree-id>/`. The tree path is
/// canonicalized first so `./notes` and `/home/u/notes` share state.
///
/// # Errors
///
/// If the tree path cannot be canonicalized or no home directory is set.
pub fn default_state_dir(profile: &str, tree: &Path) -> anyhow::Result<PathBuf> {
    let canonical = tree
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve {}: {e}", tree.display()))?;
    let data_home = match std::env::var("XDG_DATA_HOME") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var("HOME")
                .map_err(|_| anyhow::anyhow!("neither XDG_DATA_HOME nor HOME is set"))?;
            PathBuf::from(home).join(".local/share")
        }
    };
    Ok(data_home
        .join("ciss-ctl/sync")
        .join(SyncState::tree_id(profile, &canonical)))
}

/// The per-profile aggregate spend ledger:
/// `$XDG_DATA_HOME/ciss-ctl/profiles/<profile>/ledger.sqlite` — one ledger
/// for the account, spanning every synced tree.
///
/// # Errors
///
/// If no home directory is set, or the directory cannot be created.
pub fn profile_ledger(profile: &str) -> anyhow::Result<ciss_sync::SpendLedger> {
    let data_home = match std::env::var("XDG_DATA_HOME") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var("HOME")
                .map_err(|_| anyhow::anyhow!("neither XDG_DATA_HOME nor HOME is set"))?;
            PathBuf::from(home).join(".local/share")
        }
    };
    let dir = data_home.join("ciss-ctl/profiles").join(profile);
    std::fs::create_dir_all(&dir)?;
    Ok(ciss_sync::SpendLedger::open(dir.join("ledger.sqlite"), "profile")?)
}

/// A CISS server as the sync engine sees it: blobs over the metered S3 plane,
/// the keep-set over the signed manifest slot, all as one identity.
pub struct HttpCiss {
    client: Client,
    session: Session,
    keypair: Keypair,
}

impl HttpCiss {
    /// Wrap `client` acting as `keypair`'s derived `id:` DID.
    #[must_use]
    pub fn new(client: Client, keypair: Keypair) -> Self {
        Self { session: session_for(&keypair), client, keypair }
    }

    /// The wrapped client (for callers that need direct object access).
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The DID this transport acts as.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.session.did
    }
}

fn transport_err(e: anyhow::Error) -> SyncError {
    SyncError::Transport(format!("{e:#}"))
}

#[async_trait::async_trait]
impl BlobTransport for HttpCiss {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        let usage = self
            .client
            .du(Some(&self.session), &self.session.did)
            .await
            .map_err(transport_err)?;
        Ok(usage.objects.into_iter().map(|o| o.cid).collect())
    }

    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        // The key is narration on CISS, but using the cid as the key makes
        // GET-by-cid address the same object the server stored.
        let result =
            self.client.put_s3(&self.session, cid_hex, bytes).await.map_err(transport_err)?;
        verify_server_cid(cid_hex, &result.cid)
    }

    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        // get_s3 verifies the bytes against the requested cid before returning.
        let result = self
            .client
            .get_s3(Some(&self.session), &self.session.did, cid_hex)
            .await
            .map_err(transport_err)?;
        Ok(result.bytes)
    }
}

#[async_trait::async_trait]
impl ManifestSlot for HttpCiss {
    async fn current_seq(&self) -> Result<Option<u64>, SyncError> {
        let manifest =
            self.client.get_manifest(&self.session.did).await.map_err(transport_err)?;
        Ok(manifest.map(|m| m.seq()))
    }

    async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError> {
        let manifest =
            self.client.get_manifest(&self.session.did).await.map_err(transport_err)?;
        Ok(manifest.map(|m| {
            m.leaves()
                .iter()
                .map(|l| (l.cid().to_owned(), l.size() as u64))
                .collect()
        }))
    }

    async fn frontier(&self) -> Result<Option<FrontierView>, SyncError> {
        let manifest =
            self.client.get_manifest(&self.session.did).await.map_err(transport_err)?;
        Ok(manifest.map(|m| FrontierView {
            seq: m.seq(),
            heads: m.heads().cloned().unwrap_or_default(),
            leaves: m
                .leaves()
                .iter()
                .map(|l| (l.cid().to_owned(), l.size() as u64))
                .collect(),
        }))
    }

    async fn commit_keep_set(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
    ) -> Result<(), SyncError> {
        let manifest =
            build_manifest(&to_leaves(leaves), &self.session.did, &self.keypair, seq);
        self.client.put_manifest(&self.session, &manifest).await.map_err(transport_err)
    }

    async fn commit_frontier(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
        heads: &BTreeMap<String, String>,
    ) -> Result<(), SyncError> {
        let manifest = build_manifest_with_heads(
            &to_leaves(leaves),
            &self.session.did,
            &self.keypair,
            seq,
            heads,
        );
        self.client.put_manifest(&self.session, &manifest).await.map_err(|e| {
            // The server's I5 refusal ("manifest seq is not newer…") is the
            // frontier loop's retry signal. Text-matching our own server's
            // message is a known seam, pinned by the flow tests.
            if format!("{e:#}").contains("seq is not newer") {
                SyncError::StaleSeq { attempted: seq }
            } else {
                transport_err(e)
            }
        })
    }
}

impl AccountKey for HttpCiss {
    fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

fn to_leaves(leaves: &[(String, u64)]) -> Vec<ManifestLeaf> {
    leaves
        .iter()
        .map(|(cid, size)| {
            ManifestLeaf::new(cid, usize::try_from(*size).expect("blob sizes are far below usize::MAX"))
        })
        .collect()
}
