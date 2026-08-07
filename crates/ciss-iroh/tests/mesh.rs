//! P2 contract: `MeshPeer` carries the frontier over iroh-gossip with no
//! server — each device is the sole writer of its own head slot (per-device
//! signed counters give the ordering I5's seq-CAS gave on the server), and
//! a head announcement teaches the receiver both the frontier entry and the
//! sha256→blake3 mappings needed to fetch the head over the blob path.

use std::time::Duration;

use ciss_iroh::MeshPeer;
use ciss_sync::{BlobTransport, DagCbor, DeviceHead, ManifestCodec, ManifestSlot, SyncError};
use sha2::Digest;

fn cid_of(bytes: &[u8]) -> String {
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

async fn mesh_pair() -> (MeshPeer, MeshPeer) {
    let key_a = ciss::crypto::derive_keypair("mesh-master", "pool");
    let key_b = ciss::crypto::derive_keypair("mesh-master", "pool");
    let a = MeshPeer::spawn(key_a, "dev-a", &[], None, None).await.expect("spawn a");
    let b = MeshPeer::spawn(key_b, "dev-b", &[a.addr()], None, None).await.expect("spawn b");
    (a, b)
}

/// Commit a (real, signed) head on one device with a frontier commit; the
/// other device's frontier gains it, and the head blob is fetchable there
/// over the blob path — the announcement carried everything needed.
#[tokio::test]
async fn committed_head_reaches_the_other_device() {
    let (a, b) = mesh_pair().await;

    let fs_root = b"stand-in fs-manifest bytes".to_vec();
    let fs_root_cid = cid_of(&fs_root);
    a.put(&fs_root_cid, &fs_root).await.expect("put fs_root");

    let key = ciss::crypto::derive_keypair("mesh-master", "pool");
    let head =
        DeviceHead::new_signed("dev-a", 1, &fs_root_cid, None, None, &key);
    let head_bytes = head.encode().expect("encode");
    let head_cid = cid_of(&head_bytes);
    a.put(&head_cid, &head_bytes).await.expect("put head");

    let leaves = vec![
        (head_cid.clone(), head_bytes.len() as u64),
        (fs_root_cid.clone(), fs_root.len() as u64),
    ];
    let heads = std::collections::BTreeMap::from([("dev-a".to_owned(), head_cid.clone())]);
    a.commit_frontier(&leaves, 1, &heads).await.expect("commit");

    b.await_devices(1, Duration::from_secs(20)).await.expect("announcement arrives");
    let frontier = b.frontier().await.expect("frontier").expect("exists");
    assert_eq!(frontier.heads.get("dev-a"), Some(&head_cid), "the head propagated");

    // The blob path was primed by the same announcement: fetch + verify.
    let fetched = b.get(&head_cid).await.expect("fetch head over iroh");
    let verifier = key.verifying_key();
    let decoded = DeviceHead::decode_verified(&fetched, &verifier).expect("verifies");
    assert_eq!(decoded.fs_root, fs_root_cid);

    // A mesh peer that shut down stops serving: the fs_root was announced
    // but never fetched, so this get must now fail instead of succeeding.
    // (Mutation-audit kill: a no-op `shutdown` would keep serving it.)
    a.shutdown().await;
    let fetch = tokio::time::timeout(Duration::from_secs(10), b.get(&fs_root_cid)).await;
    if let Ok(Ok(_)) = fetch {
        panic!("a shut-down mesh peer must not serve blobs");
    }
    b.shutdown().await;
}

/// Garbage on the topic is ignored — fail closed, and the stream survives:
/// a real commit after the garbage still propagates.
#[tokio::test]
async fn garbled_announcement_is_ignored() {
    let (a, b) = mesh_pair().await;

    a.broadcast_raw(b"not an announcement at all".to_vec())
        .await
        .expect("raw broadcast");

    let payload = b"real content".to_vec();
    let cid = cid_of(&payload);
    a.put(&cid, &payload).await.expect("put");
    let key = ciss::crypto::derive_keypair("mesh-master", "pool");
    let head = DeviceHead::new_signed("dev-a", 1, &cid, None, None, &key);
    let head_bytes = head.encode().expect("encode");
    let head_cid = cid_of(&head_bytes);
    a.put(&head_cid, &head_bytes).await.expect("put head");
    let heads = std::collections::BTreeMap::from([("dev-a".to_owned(), head_cid.clone())]);
    a.commit_frontier(&[(head_cid.clone(), head_bytes.len() as u64)], 1, &heads)
        .await
        .expect("commit");

    b.await_devices(1, Duration::from_secs(20)).await.expect("real announcement survives");
    let frontier = b.frontier().await.expect("frontier").expect("exists");
    assert_eq!(frontier.heads.len(), 1, "only the real head is present");
    assert_eq!(frontier.heads.get("dev-a"), Some(&head_cid));

    a.shutdown().await;
    b.shutdown().await;
}

/// The announcement wire format is public behavior: a hand-crafted
/// `croft.sync-announce/v1` JSON broadcast raw moves the receiver's
/// frontier — pinning the format AND proving `broadcast_raw` really
/// broadcasts (a no-op stub would leave the frontier untouched).
#[tokio::test]
async fn hand_crafted_announcement_moves_the_frontier() {
    let (a, b) = mesh_pair().await;
    assert!(
        format!("{a:?}").contains("dev-a"),
        "Debug names the device (and never the key material)"
    );

    let head_bytes = b"a ghost head blob";
    let fs_bytes = b"a ghost fs-manifest";
    let ann = serde_json::json!({
        "kind": "croft.sync-announce/v1",
        "device_id": "dev-ghost",
        "counter": 9,
        "head_sha256": cid_of(head_bytes),
        "head_blake3": blake3::hash(head_bytes).as_bytes().to_vec(),
        "fs_root_sha256": cid_of(fs_bytes),
        "fs_root_blake3": blake3::hash(fs_bytes).as_bytes().to_vec(),
        "addr": serde_json::to_value(a.addr()).expect("addr json"),
    });
    // A raw broadcast is not re-announced on NeighborUp (only committed
    // heads are), so a send that races mesh formation is simply lost —
    // rebroadcast until the receiver has it (bounded). A no-op
    // `broadcast_raw` stub never lands anything and times out here.
    let bytes = serde_json::to_vec(&ann).expect("json");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        a.broadcast_raw(bytes.clone()).await.expect("broadcast");
        tokio::time::sleep(Duration::from_millis(300)).await;
        if b.await_devices(1, Duration::from_millis(1)).await.is_ok() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "ghost never announced");
    }
    let frontier = b.frontier().await.expect("frontier").expect("exists");
    assert_eq!(frontier.heads.get("dev-ghost"), Some(&cid_of(head_bytes)));

    a.shutdown().await;
    b.shutdown().await;
}

/// The mesh keep-set slot behaves like the server's: `have` reflects local
/// puts, a committed keep-set reads back verbatim, and a non-newer seq is
/// refused with `StaleSeq` — never silently accepted.
#[tokio::test]
async fn mesh_keep_set_slot_round_trips_and_rejects_stale() {
    let key = ciss::crypto::derive_keypair("mesh-master", "slot-pool");
    let peer = MeshPeer::spawn(key, "dev-solo", &[], None, None).await.expect("spawn");

    let payload = b"slot test blob".to_vec();
    let cid = cid_of(&payload);
    peer.put(&cid, &payload).await.expect("put");
    assert_eq!(
        peer.have().await.expect("have"),
        std::collections::HashSet::from([cid.clone()]),
        "have() reflects exactly what was put"
    );

    assert_eq!(peer.current_seq().await.expect("seq"), None);
    let leaves = vec![(cid.clone(), payload.len() as u64)];
    peer.commit_keep_set(&leaves, 5).await.expect("commit");
    assert_eq!(peer.current_seq().await.expect("seq"), Some(5));
    assert_eq!(peer.keep_set().await.expect("keep"), Some(leaves.clone()));

    for stale in [5, 4] {
        let err = peer.commit_keep_set(&leaves, stale).await.expect_err("stale refused");
        assert!(matches!(err, SyncError::StaleSeq { attempted } if attempted == stale));
    }
    peer.commit_keep_set(&leaves, 6).await.expect("newer accepted");
    assert_eq!(peer.current_seq().await.expect("seq"), Some(6));

    peer.shutdown().await;
}

/// Fetching a real fs-manifest self-primes the chunk aliases: after B pulls
/// the manifest, it can fetch a chunk it was never told about — the
/// announcement carried two hash-pairs and the manifest taught the rest.
#[tokio::test]
async fn fetched_manifest_primes_chunk_fetches() {
    let (a, b) = mesh_pair().await;
    let key = ciss::crypto::derive_keypair("mesh-master", "pool");

    // A real one-file tree: chunk bytes + fs-manifest, all put on A.
    let content: Vec<u8> = (0..300_000u32).map(|i| (i % 197) as u8).collect();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("data.bin"), &content).expect("write");
    let manifest = ciss_sync::scan_tree(dir.path()).expect("scan");
    let chunks = ciss_sync::chunk_file(&content);
    for chunk in &chunks {
        a.put(&chunk.chunk_ref.sha256_hex(), &content[chunk.range.clone()])
            .await
            .expect("put chunk");
    }
    let manifest_bytes = DagCbor.encode(&manifest).expect("encode");
    let fs_root_cid = cid_of(&manifest_bytes);
    a.put(&fs_root_cid, &manifest_bytes).await.expect("put manifest");

    let head = DeviceHead::new_signed("dev-a", 1, &fs_root_cid, None, None, &key);
    let head_bytes = head.encode().expect("encode");
    let head_cid = cid_of(&head_bytes);
    a.put(&head_cid, &head_bytes).await.expect("put head");
    let heads = std::collections::BTreeMap::from([("dev-a".to_owned(), head_cid.clone())]);
    a.commit_frontier(&[(head_cid, head_bytes.len() as u64)], 1, &heads).await.expect("commit");

    b.await_devices(1, Duration::from_secs(20)).await.expect("announced");
    let fetched = b.get(&fs_root_cid).await.expect("manifest via announcement mapping");
    assert_eq!(fetched, manifest_bytes);

    // The chunk was never announced — only the manifest taught its alias.
    let first = &chunks[0];
    let got = b.get(&first.chunk_ref.sha256_hex()).await.expect("chunk via self-priming");
    assert_eq!(got, &content[first.range.clone()], "chunk bytes identical");

    a.shutdown().await;
    b.shutdown().await;
}

/// A second commit from the same device replaces its head (newest counter
/// wins); the other device converges on the latest.
#[tokio::test]
async fn newer_commit_replaces_the_head() {
    let (a, b) = mesh_pair().await;
    let key = ciss::crypto::derive_keypair("mesh-master", "pool");

    let mut last_head_cid = String::new();
    for counter in 1..=2u64 {
        let payload = format!("tree at counter {counter}").into_bytes();
        let cid = cid_of(&payload);
        a.put(&cid, &payload).await.expect("put");
        let parent = (counter > 1).then(|| last_head_cid.clone());
        let head =
            DeviceHead::new_signed("dev-a", counter, &cid, parent, None, &key);
        let head_bytes = head.encode().expect("encode");
        last_head_cid = cid_of(&head_bytes);
        a.put(&last_head_cid, &head_bytes).await.expect("put head");
        let heads =
            std::collections::BTreeMap::from([("dev-a".to_owned(), last_head_cid.clone())]);
        a.commit_frontier(&[(last_head_cid.clone(), head_bytes.len() as u64)], counter, &heads)
            .await
            .expect("commit");
    }

    // Wait until B sees the *second* head specifically.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(f) = b.frontier().await.expect("frontier") {
            if f.heads.get("dev-a") == Some(&last_head_cid) {
                break;
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "B never saw the newer head");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    a.shutdown().await;
    b.shutdown().await;
}
