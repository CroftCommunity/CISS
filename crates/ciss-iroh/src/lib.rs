//! iroh transport for the ciss-sync engine.
//!
//! [`IrohPeer`] is a [`BlobTransport`] keyed by the canonical sha-256 cid
//! (C1 — the server's address of record) whose bytes live in an iroh-blobs
//! store addressed by blake3 — the second hash every `ChunkRef` has carried
//! since M1, precisely for this transport. Peer fetches ride iroh's
//! Bao-verified streaming (blake3 integrity in transit), and the sha-256 is
//! **re-verified on receipt**: a poisoned sha256→blake3 mapping can waste a
//! fetch but never corrupt a tree.
//!
//! [`PeerFirst`] composes an `IrohPeer` over an origin transport (CISS):
//! reads prefer the peer and fall back per blob; writes and the keep-set
//! stay on the origin, so backup/billing semantics are unchanged.

#![warn(missing_docs)]

mod mesh;

pub use mesh::{addr_from_ticket, ticket_for, MeshPeer, MeshPersist, ANNOUNCE_KIND};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ciss_sync::{BlobTransport, SyncError};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode};
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::{BlobsProtocol, Hash};
use sha2::Digest;

fn transport_err(context: &str, e: impl std::fmt::Display) -> SyncError {
    SyncError::Transport(format!("iroh {context}: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        write!(out, "{b:02x}").expect("write to String cannot fail");
    }
    out
}

/// What the peer knows about one sha-256 cid: its blake3 alias, who is
/// believed to hold it, and whether the local store holds it.
#[derive(Debug, Clone)]
pub(crate) struct Mapping {
    pub(crate) blake3: Hash,
    pub(crate) providers: Vec<EndpointId>,
    pub(crate) local: bool,
}

pub(crate) type MappingIndex = Arc<Mutex<HashMap<String, Mapping>>>;

/// Register (or extend) a sha256→blake3 mapping in `index`, optionally
/// adding a provider; a full provider address also lands in `lookup` so the
/// endpoint can dial it. When a durable [`ciss_sync::AliasStore`] is
/// attached, the alias write-throughs immediately (a persistence failure is
/// logged, never fatal — it degrades a *future* restart, not this run).
pub(crate) fn register_mapping(
    index: &MappingIndex,
    lookup: &MemoryLookup,
    aliases: Option<&ciss_sync::AliasStore>,
    cid_hex: &str,
    blake3: [u8; 32],
    provider: Option<&EndpointAddr>,
) {
    if let Some(addr) = provider {
        lookup.add_endpoint_info(addr.clone());
    }
    if let Some(store) = aliases {
        if let Err(e) = store.set(cid_hex, blake3) {
            tracing::warn!(cid = %cid_hex, error = %e, "alias write-through failed");
        }
    }
    let mut index = index.lock().expect("index mutex poisoned");
    let entry = index.entry(cid_hex.to_owned()).or_insert(Mapping {
        blake3: Hash::from(blake3),
        providers: Vec::new(),
        local: false,
    });
    if let Some(addr) = provider {
        if !entry.providers.contains(&addr.id) {
            entry.providers.push(addr.id);
        }
    }
}

/// A [`BlobTransport`] backed by iroh-blobs: serves its local blobs to peers
/// and fetches missing blobs from known providers by blake3 (Bao-verified),
/// keyed externally by the canonical sha-256 cid.
#[derive(Debug)]
pub struct IrohPeer {
    endpoint: Endpoint,
    router: iroh::protocol::Router,
    store: iroh_blobs::api::Store,
    downloader: iroh_blobs::api::downloader::Downloader,
    lookup: MemoryLookup,
    index: MappingIndex,
    /// Optional durable alias index (write-through; see `register_mapping`).
    aliases: Option<ciss_sync::AliasStore>,
}

/// The relay this deployment runs (croft-stack: `relay.croft.ing`, mode B).
/// The relay is one transport among several — an unreachable relay degrades
/// to direct paths (probe-verified, and pinned by a hermetic test), so this
/// default never breaks LAN-only use.
pub const DEFAULT_RELAY_URL: &str = "https://relay.croft.ing:8443";

/// Resolve an optional relay URL string into a [`RelayMode`].
fn relay_mode(relay: Option<&str>) -> Result<RelayMode, SyncError> {
    match relay {
        None => Ok(RelayMode::Disabled),
        Some(url) => {
            let parsed: iroh::RelayUrl = url
                .parse()
                .map_err(|e| SyncError::Decode(format!("relay url {url:?}: {e}")))?;
            Ok(RelayMode::Custom(parsed.into()))
        }
    }
}

impl IrohPeer {
    /// Bind an endpoint (`presets::Minimal`) — the probe-verified recipe
    /// shared by [`IrohPeer::spawn`] and the mesh. The bind posture follows
    /// the relay choice: relay-less peers bind loopback (the hermetic
    /// test/LAN-drill posture), relay-configured peers bind all interfaces
    /// (a peer that expects to be dialed from elsewhere must be reachable
    /// on more than 127.0.0.1).
    pub(crate) async fn bind_endpoint(
        lookup: &MemoryLookup,
        relay: Option<&str>,
    ) -> Result<Endpoint, SyncError> {
        let bind_ip = if relay.is_some() {
            std::net::Ipv4Addr::UNSPECIFIED
        } else {
            std::net::Ipv4Addr::LOCALHOST
        };
        Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .relay_mode(relay_mode(relay)?)
            .bind_addr(std::net::SocketAddrV4::new(bind_ip, 0))
            .map_err(|e| transport_err("bind_addr", e))?
            .bind()
            .await
            .map_err(|e| transport_err("bind", e))
    }

    /// Assemble a peer from parts (the mesh builds the router itself so it
    /// can accept the gossip ALPN alongside blobs, and chooses the store —
    /// in-memory or fs-backed — plus the durable alias index).
    pub(crate) fn from_parts(
        endpoint: Endpoint,
        router: iroh::protocol::Router,
        store: iroh_blobs::api::Store,
        lookup: MemoryLookup,
        aliases: Option<ciss_sync::AliasStore>,
    ) -> Self {
        let downloader = store.downloader(&endpoint);
        Self {
            endpoint,
            router,
            store,
            downloader,
            lookup,
            index: Arc::new(Mutex::new(HashMap::new())),
            aliases,
        }
    }

    /// Bind an endpoint (relay per `relay`; `None` = loopback-only), spawn
    /// the blobs protocol behind a router, and return a ready peer.
    ///
    /// # Errors
    ///
    /// Endpoint bind failures and an unparseable relay URL surface as
    /// [`SyncError::Transport`] / [`SyncError::Decode`].
    pub async fn spawn(relay: Option<&str>) -> Result<Self, SyncError> {
        let lookup = MemoryLookup::new();
        let endpoint = Self::bind_endpoint(&lookup, relay).await?;
        let store: iroh_blobs::api::Store = (*MemStore::new()).clone();
        let blobs = BlobsProtocol::new(&store, None);
        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        Ok(Self::from_parts(endpoint, router, store, lookup, None))
    }

    /// Wait (bounded) until this peer has attached to its home relay — a
    /// peer is only dialable *through* the relay after this. Returns `true`
    /// on attach, `false` on timeout (direct paths still work; callers log
    /// and continue — an unreachable relay must never wedge LAN use).
    pub async fn await_online(&self, timeout: std::time::Duration) -> bool {
        tokio::time::timeout(timeout, self.endpoint.online()).await.is_ok()
    }

    pub(crate) fn index_handle(&self) -> MappingIndex {
        Arc::clone(&self.index)
    }

    pub(crate) fn lookup_handle(&self) -> MemoryLookup {
        self.lookup.clone()
    }

    pub(crate) fn aliases_handle(&self) -> Option<ciss_sync::AliasStore> {
        self.aliases.clone()
    }

    pub(crate) fn store_handle(&self) -> iroh_blobs::api::Store {
        self.store.clone()
    }

    /// This peer's dialable address (direct sockets; no relay).
    #[must_use]
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Register that `provider` holds the blob whose sha-256 cid is
    /// `cid_hex` and whose iroh (blake3) address is `blake3`. The claim is
    /// trusted only up to the fetch: [`IrohPeer::get`] re-verifies sha-256.
    ///
    /// # Errors
    ///
    /// Currently infallible in practice; the `Result` keeps room for
    /// address-book failures without breaking callers.
    pub fn learn(
        &self,
        cid_hex: &str,
        blake3: [u8; 32],
        provider: &EndpointAddr,
    ) -> Result<(), SyncError> {
        register_mapping(&self.index, &self.lookup, self.aliases.as_ref(), cid_hex, blake3, Some(provider));
        Ok(())
    }

    /// Gracefully shut down the router and endpoint.
    pub async fn shutdown(self) {
        if let Err(e) = self.router.shutdown().await {
            tracing::debug!(error = %e, "iroh router shutdown");
        }
        self.endpoint.close().await;
    }

    fn mapping(&self, cid_hex: &str) -> Option<Mapping> {
        self.index.lock().expect("index mutex poisoned").get(cid_hex).cloned()
    }

    fn mark_local(&self, cid_hex: &str) {
        if let Some(m) = self.index.lock().expect("index mutex poisoned").get_mut(cid_hex) {
            m.local = true;
        }
    }
}

#[async_trait::async_trait]
impl BlobTransport for IrohPeer {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        let index = self.index.lock().expect("index mutex poisoned");
        Ok(index.iter().filter(|(_, m)| m.local).map(|(cid, _)| cid.clone()).collect())
    }

    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        let actual = sha256_hex(bytes);
        if actual != cid_hex {
            return Err(SyncError::CidMismatch { expected: cid_hex.to_owned(), got: actual });
        }
        let tag = self
            .store
            .blobs()
            .add_bytes(bytes.to_vec())
            .await
            .map_err(|e| transport_err("add_bytes", e))?;
        if let Some(aliases) = &self.aliases {
            if let Err(e) = aliases.set(cid_hex, *tag.hash.as_bytes()) {
                tracing::warn!(cid = %cid_hex, error = %e, "alias write-through failed");
            }
        }
        let mut index = self.index.lock().expect("index mutex poisoned");
        let entry = index.entry(cid_hex.to_owned()).or_insert(Mapping {
            blake3: tag.hash,
            providers: Vec::new(),
            local: true,
        });
        entry.blake3 = tag.hash;
        entry.local = true;
        Ok(())
    }

    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        let mapping = self.mapping(cid_hex).ok_or_else(|| {
            SyncError::Transport(format!("no sha256→blake3 mapping for {cid_hex}"))
        })?;
        let held = self
            .store
            .blobs()
            .has(mapping.blake3)
            .await
            .map_err(|e| transport_err("has", e))?;
        if !held {
            self.downloader
                .download(mapping.blake3, mapping.providers.clone())
                .await
                .map_err(|e| transport_err(&format!("download {cid_hex}"), e))?;
        }
        let bytes = self
            .store
            .blobs()
            .get_bytes(mapping.blake3)
            .await
            .map_err(|e| transport_err("get_bytes", e))?;
        // C1 is not delegated to iroh: Bao proved the blake3; the sha-256 —
        // the address the engine and server speak — is proven here.
        let actual = sha256_hex(&bytes);
        if actual != cid_hex {
            return Err(SyncError::CidMismatch { expected: cid_hex.to_owned(), got: actual });
        }
        self.mark_local(cid_hex);
        Ok(bytes.to_vec())
    }

    fn metered(&self) -> bool {
        false // peer-to-peer bytes are never billed by the meter
    }
}

/// Reads prefer the peer, falling back to the origin per blob (including on
/// a peer-side integrity failure); writes, the have-set, the keep-set slot,
/// and the account key all stay on the origin.
#[derive(Debug)]
pub struct PeerFirst<'a, O> {
    /// The iroh peer consulted first for reads.
    pub peer: &'a IrohPeer,
    /// The origin transport (CISS) — the source of truth for writes.
    pub origin: &'a O,
}

#[async_trait::async_trait]
impl<O: BlobTransport + Sync> BlobTransport for PeerFirst<'_, O> {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        self.origin.have().await
    }

    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        self.origin.put(cid_hex, bytes).await
    }

    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        match self.peer.get(cid_hex).await {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                tracing::debug!(cid = %cid_hex, error = %e, "peer fetch failed; origin fallback");
                self.origin.get(cid_hex).await
            }
        }
    }

    fn metered(&self) -> bool {
        self.origin.metered() // writes land on the origin — its billing applies
    }
}

#[async_trait::async_trait]
impl<O: ciss_sync::ManifestSlot + Sync> ciss_sync::ManifestSlot for PeerFirst<'_, O> {
    async fn current_seq(&self) -> Result<Option<u64>, SyncError> {
        self.origin.current_seq().await
    }

    async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError> {
        self.origin.keep_set().await
    }

    async fn frontier(&self) -> Result<Option<ciss_sync::FrontierView>, SyncError> {
        self.origin.frontier().await
    }

    async fn commit_keep_set(&self, leaves: &[(String, u64)], seq: u64) -> Result<(), SyncError> {
        self.origin.commit_keep_set(leaves, seq).await
    }

    async fn commit_frontier(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
        heads: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), SyncError> {
        self.origin.commit_frontier(leaves, seq, heads).await
    }
}

impl<O: ciss_sync::AccountKey> ciss_sync::AccountKey for PeerFirst<'_, O> {
    fn keypair(&self) -> &ciss::crypto::Keypair {
        self.origin.keypair()
    }
}
