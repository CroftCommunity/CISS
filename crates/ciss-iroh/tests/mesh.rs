//! P2 contract: `MeshPeer` carries the frontier over iroh-gossip with no
//! server — each device is the sole writer of its own head slot (per-device
//! signed counters give the ordering I5's seq-CAS gave on the server), and
//! a head announcement teaches the receiver both the frontier entry and the
//! sha256→blake3 mappings needed to fetch the head over the blob path.

use std::time::Duration;

use ciss_iroh::MeshPeer;
use ciss_sync::{BlobTransport, DeviceHead, ManifestSlot};
use sha2::Digest;

fn cid_of(bytes: &[u8]) -> String {
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

async fn mesh_pair() -> (MeshPeer, MeshPeer) {
    let key_a = ciss::crypto::derive_keypair("mesh-master", "pool");
    let key_b = ciss::crypto::derive_keypair("mesh-master", "pool");
    let a = MeshPeer::spawn(key_a, "dev-a", &[]).await.expect("spawn a");
    let b = MeshPeer::spawn(key_b, "dev-b", &[a.addr()]).await.expect("spawn b");
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

    a.shutdown().await;
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
