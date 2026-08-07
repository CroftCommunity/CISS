//! The CISS implementation of `ciss-sync`'s transport seam.
//!
//! Lives here — next to the [`Client`] it wraps — rather than in `ciss-sync`,
//! because the CLI consumes the engine (`ciss-cli → ciss-sync`); the engine
//! depending back on the CLI would be a package cycle. Reusing this crate's
//! `Client` keeps the metered-call + `verify_cid` path single-sourced (the
//! OQ1 decision), and `HttpCiss` is the only glue.

use std::collections::HashSet;

use ciss::crypto::Keypair;
use ciss::manifest::{build_manifest, ManifestLeaf};
use ciss_sync::{verify_server_cid, BlobTransport, ManifestSlot, SyncError};

use crate::client::{session_for, Client, Session};

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

    async fn commit_keep_set(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
    ) -> Result<(), SyncError> {
        let leaves: Vec<ManifestLeaf> = leaves
            .iter()
            .map(|(cid, size)| {
                ManifestLeaf::new(
                    cid,
                    usize::try_from(*size).expect("blob sizes are far below usize::MAX"),
                )
            })
            .collect();
        let manifest = build_manifest(&leaves, &self.session.did, &self.keypair, seq);
        self.client.put_manifest(&self.session, &manifest).await.map_err(transport_err)
    }
}
