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

/// An in-memory origin standing in for CISS in crate-level tests.
#[derive(Default)]
struct MemOrigin {
    blobs: tokio::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    gets: std::sync::atomic::AtomicU64,
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
