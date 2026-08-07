//! The serverless frontier: `MeshPeer` implements the engine's full
//! transport surface (`BlobTransport` + `ManifestSlot` + `AccountKey`) over
//! iroh alone, so `ciss_sync::converge` runs unchanged with no server.
//!
//! The trust story does not change from M3: `DeviceHead` records stay
//! self-verifying and the fold rejects anything that fails the signature —
//! a gossip announcement is only a *hint* (frontier entry + sha256→blake3
//! mappings). What changes is the ordering authority: I5's monotonic
//! seq-CAS serialized shared-slot writes on one server; serverless, each
//! device is the sole writer of its own head slot and its signed per-device
//! `counter` already gives per-writer ordering, so the frontier is the
//! union of announcements with newest-counter-wins per device.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciss_sync::device_head::DeviceHead;
use ciss_sync::manifest::{DagCbor, ManifestCodec, FS_MANIFEST_KIND};
use ciss_sync::{BlobTransport, FrontierView, ManifestSlot, SyncError};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::EndpointAddr;
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::BlobsProtocol;
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;
use n0_future::StreamExt;
use sha2::Digest;

use crate::{register_mapping, transport_err, IrohPeer, MappingIndex};

/// The self-tag every announcement carries.
pub const ANNOUNCE_KIND: &str = "croft.sync-announce/v1";

const TOPIC_DOMAIN: &str = "croft.sync-topic/v1:";

/// One device's head, broadcast on the lineage topic. Advisory only: the
/// receiver folds nothing until the `DeviceHead` blob itself verifies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Announcement {
    kind: String,
    device_id: String,
    counter: u64,
    head_sha256: String,
    head_blake3: [u8; 32],
    fs_root_sha256: String,
    fs_root_blake3: [u8; 32],
    addr: EndpointAddr,
}

/// The local slot: this device's committed state plus what gossip taught us.
#[derive(Debug, Default)]
struct SlotState {
    seq: Option<u64>,
    leaves: Vec<(String, u64)>,
    own_head: Option<(String, String)>,
    /// `device_id → (counter, head_cid)` from announcements.
    remote: BTreeMap<String, (u64, String)>,
}

/// Merge one announcement into the slot: newest counter wins per device.
/// Pure — this is the serverless replacement for the I5 ordering rule.
fn merge_announcement(slot: &mut SlotState, device_id: &str, counter: u64, head_cid: &str) -> bool {
    match slot.remote.get(device_id) {
        Some((have, _)) if *have >= counter => false,
        _ => {
            slot.remote.insert(device_id.to_owned(), (counter, head_cid.to_owned()));
            true
        }
    }
}

/// Derive the gossip topic from the lineage root — today the shared account
/// key, so every device of the account lands on the same topic with no
/// coordination (`multi-device.md` §10: `TopicId = derive(lineage_root)`).
fn topic_for(keypair: &ciss::crypto::Keypair) -> TopicId {
    let mut hasher = sha2::Sha256::new();
    hasher.update(TOPIC_DOMAIN.as_bytes());
    hasher.update(keypair.verifying_key().to_bytes());
    TopicId::from_bytes(hasher.finalize().into())
}

/// Encode an [`EndpointAddr`] as a pairing ticket (URL-safe base64 JSON) —
/// the one string a user carries between devices; the topic itself is
/// derived from the account key, so the ticket is only "where to dial".
///
/// # Errors
///
/// [`SyncError::Encode`] if the address fails to serialize.
pub fn ticket_for(addr: &EndpointAddr) -> Result<String, SyncError> {
    use base64::Engine as _;
    let json = serde_json::to_vec(addr).map_err(|e| SyncError::Encode(format!("ticket: {e}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

/// Decode a pairing ticket back into an [`EndpointAddr`].
///
/// # Errors
///
/// [`SyncError::Decode`] on anything that is not a valid ticket.
pub fn addr_from_ticket(ticket: &str) -> Result<EndpointAddr, SyncError> {
    use base64::Engine as _;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ticket.trim())
        .map_err(|e| SyncError::Decode(format!("ticket base64: {e}")))?;
    serde_json::from_slice(&json).map_err(|e| SyncError::Decode(format!("ticket json: {e}")))
}

/// A device on the lineage mesh: blobs over iroh-blobs, frontier over
/// iroh-gossip, `converge()` runs against it unchanged.
pub struct MeshPeer {
    peer: IrohPeer,
    keypair: ciss::crypto::Keypair,
    device_id: String,
    sender: GossipSender,
    slot: Arc<Mutex<SlotState>>,
    last_announce: Arc<Mutex<Option<Announcement>>>,
    recv_task: tokio::task::JoinHandle<()>,
}

// Hand-written: the account keypair is secret material and must never be
// Debug-printed; everything else is fair game.
impl std::fmt::Debug for MeshPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshPeer")
            .field("device_id", &self.device_id)
            .field("addr", &self.peer.addr())
            .finish_non_exhaustive()
    }
}

impl MeshPeer {
    /// Join the account's lineage topic as `device_id`, bootstrapping from
    /// `bootstrap` peers (empty = wait to be found).
    ///
    /// # Errors
    ///
    /// Endpoint bind or gossip subscribe failures as [`SyncError::Transport`].
    pub async fn spawn(
        keypair: ciss::crypto::Keypair,
        device_id: &str,
        bootstrap: &[EndpointAddr],
    ) -> Result<Self, SyncError> {
        let lookup = MemoryLookup::new();
        let endpoint = IrohPeer::bind_endpoint(&lookup).await?;
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();
        let peer = IrohPeer::from_parts(endpoint, router, store, lookup);

        for addr in bootstrap {
            peer.lookup_handle().add_endpoint_info(addr.clone());
        }
        let topic = topic_for(&keypair);
        let bootstrap_ids = bootstrap.iter().map(|a| a.id).collect();
        let (sender, receiver) = gossip
            .subscribe(topic, bootstrap_ids)
            .await
            .map_err(|e| transport_err("gossip subscribe", e))?
            .split();

        let slot = Arc::new(Mutex::new(SlotState::default()));
        let last_announce = Arc::new(Mutex::new(None));
        let recv_task = tokio::spawn(receive_loop(
            receiver,
            sender.clone(),
            Arc::clone(&slot),
            Arc::clone(&last_announce),
            peer.index_handle(),
            peer.lookup_handle(),
        ));

        Ok(Self {
            peer,
            keypair,
            device_id: device_id.to_owned(),
            sender,
            slot,
            last_announce,
            recv_task,
        })
    }

    /// This device's dialable address (goes in the pairing ticket).
    #[must_use]
    pub fn addr(&self) -> EndpointAddr {
        self.peer.addr()
    }

    /// Broadcast raw bytes on the topic — a diagnostic/test hook proving
    /// the receive side is fail-closed against non-announcements.
    ///
    /// # Errors
    ///
    /// Gossip broadcast failures as [`SyncError::Transport`].
    pub async fn broadcast_raw(&self, bytes: Vec<u8>) -> Result<(), SyncError> {
        self.sender
            .broadcast(bytes::Bytes::from(bytes))
            .await
            .map_err(|e| transport_err("broadcast", e))
    }

    /// Wait until at least `n` *other* devices' heads are known, or time out.
    ///
    /// # Errors
    ///
    /// [`SyncError::Transport`] on timeout — gossip is asynchronous, so
    /// "the frontier is still empty" is indistinguishable from "nobody is
    /// there"; the caller chooses how long that distinction is worth.
    pub async fn await_devices(&self, n: usize, timeout: Duration) -> Result<(), SyncError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let known = {
                let slot = self.slot.lock().expect("slot mutex poisoned");
                slot.remote.keys().filter(|d| **d != self.device_id).count()
            };
            if known >= n {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SyncError::Transport(format!(
                    "timed out waiting for {n} peer device(s); {known} known"
                )));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Shut down the receive loop, router, and endpoint.
    pub async fn shutdown(self) {
        self.recv_task.abort();
        self.peer.shutdown().await;
    }

    /// Build the announcement for this device's committed head, resolving
    /// counter + fs_root from the (locally stored) head blob and the blake3
    /// aliases from the index. Fail-loud: a missing piece is a bug in the
    /// commit path, not a condition to paper over.
    async fn announcement_for(&self, head_cid: &str) -> Result<Announcement, SyncError> {
        let head_bytes = self.peer.get(head_cid).await?;
        let head = DeviceHead::decode_verified(&head_bytes, &self.keypair.verifying_key())?;
        let index = self.peer.index_handle();
        let blake3_of = |cid: &str| -> Result<[u8; 32], SyncError> {
            index
                .lock()
                .expect("index mutex poisoned")
                .get(cid)
                .map(|m| *m.blake3.as_bytes())
                .ok_or_else(|| {
                    SyncError::Transport(format!("no blake3 alias for {cid} at announce time"))
                })
        };
        Ok(Announcement {
            kind: ANNOUNCE_KIND.to_owned(),
            device_id: self.device_id.clone(),
            counter: head.counter,
            head_sha256: head_cid.to_owned(),
            head_blake3: blake3_of(head_cid)?,
            fs_root_sha256: head.fs_root.clone(),
            fs_root_blake3: blake3_of(&head.fs_root)?,
            addr: self.addr(),
        })
    }
}

/// Ingest one announcement: frontier entry + the two blob mappings.
fn ingest(
    slot: &Mutex<SlotState>,
    index: &MappingIndex,
    lookup: &MemoryLookup,
    ann: &Announcement,
) -> bool {
    register_mapping(index, lookup, &ann.head_sha256, ann.head_blake3, Some(&ann.addr));
    register_mapping(index, lookup, &ann.fs_root_sha256, ann.fs_root_blake3, Some(&ann.addr));
    let mut slot = slot.lock().expect("slot mutex poisoned");
    merge_announcement(&mut slot, &ann.device_id, ann.counter, &ann.head_sha256)
}

async fn receive_loop(
    mut receiver: GossipReceiver,
    sender: GossipSender,
    slot: Arc<Mutex<SlotState>>,
    last_announce: Arc<Mutex<Option<Announcement>>>,
    index: MappingIndex,
    lookup: MemoryLookup,
) {
    while let Some(event) = receiver.next().await {
        match event {
            Ok(Event::Received(msg)) => {
                let Ok(ann) = serde_json::from_slice::<Announcement>(&msg.content) else {
                    tracing::debug!("ignoring non-announcement gossip message");
                    continue;
                };
                if ann.kind != ANNOUNCE_KIND {
                    tracing::debug!(kind = %ann.kind, "ignoring unknown announcement kind");
                    continue;
                }
                if ingest(&slot, &index, &lookup, &ann) {
                    tracing::info!(
                        device = %ann.device_id,
                        counter = ann.counter,
                        "frontier: head announced"
                    );
                }
            }
            Ok(Event::NeighborUp(id)) => {
                // A late joiner missed earlier broadcasts — re-announce.
                tracing::debug!(neighbor = %id, "neighbor up; re-announcing");
                let ann = last_announce.lock().expect("announce mutex poisoned").clone();
                if let Some(ann) = ann {
                    if let Ok(bytes) = serde_json::to_vec(&ann) {
                        if let Err(e) = sender.broadcast(bytes.into()).await {
                            tracing::debug!(error = %e, "re-announce failed");
                        }
                    }
                }
            }
            Ok(Event::NeighborDown(_) | Event::Lagged) => {}
            Err(e) => {
                tracing::debug!(error = %e, "gossip receive stream error");
                return;
            }
        }
    }
}

#[async_trait::async_trait]
impl BlobTransport for MeshPeer {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        self.peer.have().await
    }

    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        self.peer.put(cid_hex, bytes).await
    }

    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        let bytes = self.peer.get(cid_hex).await?;
        // Self-priming: a fetched fs-manifest teaches us the blake3 alias of
        // every chunk it references, attributed to the manifest's providers —
        // the closure walk that follows needs no further introductions.
        if let Ok(manifest) = DagCbor.decode(&bytes) {
            if manifest.kind == FS_MANIFEST_KIND {
                let index = self.peer.index_handle();
                let lookup = self.peer.lookup_handle();
                let providers = {
                    let idx = index.lock().expect("index mutex poisoned");
                    idx.get(cid_hex).map(|m| m.providers.clone()).unwrap_or_default()
                };
                for entry in manifest.entries.values() {
                    for chunk in &entry.chunks {
                        register_mapping(&index, &lookup, &chunk.sha256_hex(), chunk.blake3.0, None);
                        let mut idx = index.lock().expect("index mutex poisoned");
                        if let Some(m) = idx.get_mut(&chunk.sha256_hex()) {
                            for p in &providers {
                                if !m.providers.contains(p) {
                                    m.providers.push(*p);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(bytes)
    }
}

#[async_trait::async_trait]
impl ManifestSlot for MeshPeer {
    async fn current_seq(&self) -> Result<Option<u64>, SyncError> {
        Ok(self.slot.lock().expect("slot mutex poisoned").seq)
    }

    async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError> {
        let slot = self.slot.lock().expect("slot mutex poisoned");
        Ok(slot.seq.map(|_| slot.leaves.clone()))
    }

    async fn frontier(&self) -> Result<Option<FrontierView>, SyncError> {
        let slot = self.slot.lock().expect("slot mutex poisoned");
        if slot.seq.is_none() && slot.remote.is_empty() {
            return Ok(None);
        }
        let mut heads: BTreeMap<String, String> =
            slot.remote.iter().map(|(d, (_, cid))| (d.clone(), cid.clone())).collect();
        if let Some((dev, cid)) = &slot.own_head {
            heads.insert(dev.clone(), cid.clone());
        }
        Ok(Some(FrontierView {
            seq: slot.seq.unwrap_or(0),
            heads,
            leaves: slot.leaves.clone(),
        }))
    }

    async fn commit_keep_set(&self, leaves: &[(String, u64)], seq: u64) -> Result<(), SyncError> {
        let mut slot = self.slot.lock().expect("slot mutex poisoned");
        if slot.seq.is_some_and(|cur| seq <= cur) {
            return Err(SyncError::StaleSeq { attempted: seq });
        }
        slot.seq = Some(seq);
        slot.leaves = leaves.to_vec();
        Ok(())
    }

    async fn commit_frontier(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
        heads: &BTreeMap<String, String>,
    ) -> Result<(), SyncError> {
        let own_head = heads.get(&self.device_id).cloned().ok_or_else(|| {
            SyncError::Transport(format!(
                "frontier commit without a head for this device ({})",
                self.device_id
            ))
        })?;
        {
            let mut slot = self.slot.lock().expect("slot mutex poisoned");
            if slot.seq.is_some_and(|cur| seq <= cur) {
                return Err(SyncError::StaleSeq { attempted: seq });
            }
            slot.seq = Some(seq);
            slot.leaves = leaves.to_vec();
            slot.own_head = Some((self.device_id.clone(), own_head.clone()));
        }
        // Announce: the commit is not "landed" for the mesh until broadcast.
        let ann = self.announcement_for(&own_head).await?;
        let bytes = serde_json::to_vec(&ann)
            .map_err(|e| SyncError::Encode(format!("announcement: {e}")))?;
        *self.last_announce.lock().expect("announce mutex poisoned") = Some(ann);
        self.sender
            .broadcast(bytes.into())
            .await
            .map_err(|e| transport_err("announce broadcast", e))
    }
}

impl ciss_sync::AccountKey for MeshPeer {
    fn keypair(&self) -> &ciss::crypto::Keypair {
        &self.keypair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Newest counter wins; equal or older is ignored — the pure ordering
    /// rule the serverless frontier stands on.
    #[test]
    fn merge_keeps_the_newest_counter() {
        let mut slot = SlotState::default();
        assert!(merge_announcement(&mut slot, "dev-x", 2, "cid-2"));
        assert!(!merge_announcement(&mut slot, "dev-x", 1, "cid-1"), "older ignored");
        assert!(!merge_announcement(&mut slot, "dev-x", 2, "cid-2b"), "equal ignored");
        assert_eq!(slot.remote["dev-x"], (2, "cid-2".to_owned()));
        assert!(merge_announcement(&mut slot, "dev-x", 3, "cid-3"));
        assert_eq!(slot.remote["dev-x"], (3, "cid-3".to_owned()));
    }

    /// Devices are independent slots: one device's announcements never
    /// touch another's entry.
    #[test]
    fn merge_is_per_device() {
        let mut slot = SlotState::default();
        assert!(merge_announcement(&mut slot, "dev-a", 5, "cid-a"));
        assert!(merge_announcement(&mut slot, "dev-b", 1, "cid-b"));
        assert_eq!(slot.remote.len(), 2);
        assert_eq!(slot.remote["dev-a"], (5, "cid-a".to_owned()));
        assert_eq!(slot.remote["dev-b"], (1, "cid-b".to_owned()));
    }

    /// The topic is a pure function of the account key: same key → same
    /// topic (devices meet without coordination), different key → different
    /// topic (lineages do not collide).
    #[test]
    fn topic_derivation_is_stable_and_key_scoped() {
        let k1 = ciss::crypto::derive_keypair("topic-master", "one");
        let k1b = ciss::crypto::derive_keypair("topic-master", "one");
        let k2 = ciss::crypto::derive_keypair("topic-master", "two");
        assert_eq!(topic_for(&k1), topic_for(&k1b));
        assert_ne!(topic_for(&k1), topic_for(&k2));
    }

    /// The pairing ticket round-trips an `EndpointAddr`; garbage is refused
    /// with a decode error, not a panic.
    #[test]
    fn ticket_round_trips_and_rejects_garbage() {
        let id = iroh::SecretKey::generate().public();
        let addr = EndpointAddr::from_parts(
            id,
            [iroh::TransportAddr::Ip("127.0.0.1:4242".parse().expect("sockaddr"))],
        );
        let ticket = ticket_for(&addr).expect("encode");
        let back = addr_from_ticket(&ticket).expect("decode");
        assert_eq!(back, addr);

        assert!(addr_from_ticket("definitely-not-a-ticket").is_err());
        assert!(addr_from_ticket("").is_err());
    }
}
