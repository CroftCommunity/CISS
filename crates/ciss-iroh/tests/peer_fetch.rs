//! P1 contract: `IrohPeer` is a `BlobTransport` keyed by the canonical
//! sha-256 cid, backed by iroh-blobs (blake3/Bao) underneath; `PeerFirst`
//! composes it over an origin with per-blob fallback. Integrity is never
//! delegated to iroh: sha-256 is re-verified on every peer-served blob.

use std::collections::HashSet;

use ciss_iroh::{IrohPeer, PeerFirst};
use ciss_sync::{BlobTransport, SyncError};
use sha2::Digest;

fn cid_of(bytes: &[u8]) -> String {
    hex_of(&sha2::Sha256::digest(bytes))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// put → have → get on one peer: sha-256 keyed end to end, and put refuses
/// a cid that does not match the bytes (fail closed, same contract as CISS).
#[tokio::test]
async fn local_roundtrip_is_sha256_keyed_and_put_verifies() {
    let peer = IrohPeer::spawn().await.expect("spawn");
    let payload = b"m4: the blake3 half was waiting for this".to_vec();
    let cid = cid_of(&payload);

    assert!(peer.have().await.expect("have").is_empty(), "fresh peer holds nothing");
    peer.put(&cid, &payload).await.expect("put");
    assert!(peer.have().await.expect("have").contains(&cid));
    assert_eq!(peer.get(&cid).await.expect("get"), payload);

    // A lying cid must be refused outright — nothing stored under it.
    let wrong = cid_of(b"different content");
    let err = peer.put(&wrong, &payload).await.expect_err("wrong cid refused");
    assert!(matches!(err, SyncError::CidMismatch { .. }), "got: {err}");
    assert!(!peer.have().await.expect("have").contains(&wrong));

    peer.shutdown().await;
}

/// Two peers on loopback: B learns the mapping + provider from A and fetches
/// the blob over iroh — byte-identical, sha-256 verified on receipt.
#[tokio::test]
async fn peer_served_blob_is_byte_identical() {
    let a = IrohPeer::spawn().await.expect("spawn a");
    let b = IrohPeer::spawn().await.expect("spawn b");
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let cid = cid_of(&payload);
    a.put(&cid, &payload).await.expect("put");

    b.learn(&cid, *blake3::hash(&payload).as_bytes(), &a.addr()).expect("learn");
    let got = b.get(&cid).await.expect("peer fetch");
    assert_eq!(got, payload, "peer-served bytes are byte-identical");
    assert!(b.have().await.expect("have").contains(&cid), "fetched blob is now held locally");

    a.shutdown().await;
    b.shutdown().await;
}

/// A blob nobody taught B about — and one whose mapping is poisoned (the
/// blake3 of *different* content): both fail closed with an error that names
/// the cid; wrong bytes are never returned.
#[tokio::test]
async fn unknown_and_poisoned_mappings_fail_closed() {
    let a = IrohPeer::spawn().await.expect("spawn a");
    let b = IrohPeer::spawn().await.expect("spawn b");
    let payload = b"the real content".to_vec();
    let decoy = b"a different blob entirely".to_vec();
    let cid = cid_of(&payload);
    let decoy_cid = cid_of(&decoy);
    a.put(&cid, &payload).await.expect("put real");
    a.put(&decoy_cid, &decoy).await.expect("put decoy");

    let err = b.get(&cid).await.expect_err("unknown mapping cannot resolve");
    assert!(err.to_string().contains(&cid[..12]), "error names the cid: {err}");

    // Poisoned: sha256 key → the decoy's blake3. Bao verifies the decoy
    // transfers intact, but the sha-256 re-check must reject it.
    b.learn(&cid, *blake3::hash(&decoy).as_bytes(), &a.addr()).expect("learn poisoned");
    let err = b.get(&cid).await.expect_err("poisoned mapping must not yield wrong bytes");
    assert!(matches!(err, SyncError::CidMismatch { .. }), "got: {err}");

    a.shutdown().await;
    b.shutdown().await;
}

/// `shutdown` is real: a peer that shut down stops serving — a fetch that
/// would have succeeded against it now fails instead of hanging onto a
/// half-alive endpoint. (Mutation-audit kill: `shutdown` replaced with a
/// no-op would leave the provider serving.)
#[tokio::test]
async fn a_shut_down_peer_stops_serving() {
    let a = IrohPeer::spawn().await.expect("spawn a");
    let b = IrohPeer::spawn().await.expect("spawn b");
    let payload = b"bytes that die with the provider".to_vec();
    let cid = cid_of(&payload);
    a.put(&cid, &payload).await.expect("put");
    let addr = a.addr();
    a.shutdown().await;

    b.learn(&cid, *blake3::hash(&payload).as_bytes(), &addr).expect("learn");
    // Refused or unreachable — either is "stopped"; only success is failure.
    let fetch = tokio::time::timeout(std::time::Duration::from_secs(10), b.get(&cid)).await;
    if let Ok(Ok(_)) = fetch {
        panic!("a shut-down peer must not serve blobs");
    }
    b.shutdown().await;
}

/// An in-memory origin standing in for CISS in crate-level tests.
#[derive(Default)]
struct MemOrigin {
    blobs: tokio::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    gets: std::sync::atomic::AtomicU64,
    slot: tokio::sync::Mutex<OriginSlot>,
}

#[derive(Default)]
struct OriginSlot {
    seq: Option<u64>,
    leaves: Vec<(String, u64)>,
    heads: std::collections::BTreeMap<String, String>,
}

#[async_trait::async_trait]
impl ciss_sync::ManifestSlot for MemOrigin {
    async fn current_seq(&self) -> Result<Option<u64>, SyncError> {
        Ok(self.slot.lock().await.seq)
    }
    async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError> {
        let slot = self.slot.lock().await;
        Ok(slot.seq.map(|_| slot.leaves.clone()))
    }
    async fn frontier(&self) -> Result<Option<ciss_sync::FrontierView>, SyncError> {
        let slot = self.slot.lock().await;
        Ok(slot.seq.map(|seq| ciss_sync::FrontierView {
            seq,
            heads: slot.heads.clone(),
            leaves: slot.leaves.clone(),
        }))
    }
    async fn commit_keep_set(&self, leaves: &[(String, u64)], seq: u64) -> Result<(), SyncError> {
        let mut slot = self.slot.lock().await;
        slot.seq = Some(seq);
        slot.leaves = leaves.to_vec();
        Ok(())
    }
    async fn commit_frontier(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
        heads: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), SyncError> {
        let mut slot = self.slot.lock().await;
        slot.seq = Some(seq);
        slot.leaves = leaves.to_vec();
        slot.heads = heads.clone();
        Ok(())
    }
}

#[async_trait::async_trait]
impl BlobTransport for MemOrigin {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        Ok(self.blobs.lock().await.keys().cloned().collect())
    }
    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        self.blobs.lock().await.insert(cid_hex.to_owned(), bytes.to_vec());
        Ok(())
    }
    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.blobs
            .lock()
            .await
            .get(cid_hex)
            .cloned()
            .ok_or_else(|| SyncError::Transport(format!("origin lacks {cid_hex}")))
    }
}

/// `PeerFirst`: a blob the peer holds never touches the origin; a blob the
/// peer lacks falls back per blob; a poisoned peer mapping degrades to a
/// correct origin fetch — never to wrong bytes, never to an error.
#[tokio::test]
async fn peer_first_falls_back_per_blob() {
    let provider = IrohPeer::spawn().await.expect("spawn provider");
    let local = IrohPeer::spawn().await.expect("spawn local");
    let origin = MemOrigin::default();

    let on_peer = b"blob the peer can serve".to_vec();
    let only_origin = b"blob only the origin holds".to_vec();
    let poisoned = b"blob whose peer mapping lies".to_vec();
    let decoy = b"decoy content for the poisoned mapping".to_vec();
    let (cid_peer, cid_origin, cid_poisoned, cid_decoy) =
        (cid_of(&on_peer), cid_of(&only_origin), cid_of(&poisoned), cid_of(&decoy));

    for (cid, bytes) in
        [(&cid_peer, &on_peer), (&cid_origin, &only_origin), (&cid_poisoned, &poisoned)]
    {
        origin.put(cid, bytes).await.expect("origin put");
    }
    provider.put(&cid_peer, &on_peer).await.expect("provider put");
    provider.put(&cid_decoy, &decoy).await.expect("provider put decoy");
    local.learn(&cid_peer, *blake3::hash(&on_peer).as_bytes(), &provider.addr()).expect("learn");
    local
        .learn(&cid_poisoned, *blake3::hash(&decoy).as_bytes(), &provider.addr())
        .expect("learn poisoned");

    let t = PeerFirst { peer: &local, origin: &origin };

    assert_eq!(t.get(&cid_peer).await.expect("via peer"), on_peer);
    assert_eq!(origin.gets.load(std::sync::atomic::Ordering::SeqCst), 0, "peer hit skips origin");

    assert_eq!(t.get(&cid_origin).await.expect("via origin"), only_origin);
    assert_eq!(t.get(&cid_poisoned).await.expect("poisoned degrades to origin"), poisoned);
    assert_eq!(origin.gets.load(std::sync::atomic::Ordering::SeqCst), 2);

    // put/have stay origin semantics: a put lands on the origin, not the peer.
    let fresh = b"newly pushed".to_vec();
    let cid_fresh = cid_of(&fresh);
    t.put(&cid_fresh, &fresh).await.expect("put");
    assert!(origin.have().await.expect("have").contains(&cid_fresh));
    assert!(!local.have().await.expect("have").contains(&cid_fresh));

    provider.shutdown().await;
    local.shutdown().await;
}

/// Every `PeerFirst` slot/have delegation really reaches the origin — the
/// have-set is the origin's, and a keep-set/frontier committed through the
/// composite reads back with the exact values the origin stored. (Mutation
/// audit: a delegation stubbed to a constant would answer differently.)
#[tokio::test]
async fn peer_first_delegates_slot_and_have_to_origin() {
    use ciss_sync::ManifestSlot;

    let local = IrohPeer::spawn().await.expect("spawn local");
    let origin = MemOrigin::default();
    let t = PeerFirst { peer: &local, origin: &origin };

    let blob = b"origin-held blob".to_vec();
    let cid = cid_of(&blob);
    origin.put(&cid, &blob).await.expect("origin put");
    assert_eq!(
        t.have().await.expect("have"),
        HashSet::from([cid.clone()]),
        "have() is the origin's set, verbatim"
    );

    assert_eq!(t.current_seq().await.expect("seq"), None, "no slot committed yet");
    assert_eq!(t.keep_set().await.expect("keep"), None);
    assert!(t.frontier().await.expect("frontier").is_none());

    t.commit_keep_set(&[(cid.clone(), 16)], 3).await.expect("commit keep");
    assert_eq!(t.current_seq().await.expect("seq"), Some(3));
    assert_eq!(t.keep_set().await.expect("keep"), Some(vec![(cid.clone(), 16)]));

    let heads = std::collections::BTreeMap::from([("dev-z".to_owned(), cid.clone())]);
    t.commit_frontier(&[(cid.clone(), 16)], 7, &heads).await.expect("commit frontier");
    let f = t.frontier().await.expect("frontier").expect("exists");
    assert_eq!(f.seq, 7);
    assert_eq!(f.heads, heads);
    assert_eq!(f.leaves, vec![(cid, 16)]);

    local.shutdown().await;
}
