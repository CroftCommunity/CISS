//! The serverless-persistence contract: a mesh peer spawned with a persist
//! root (fs-backed iroh store + the tree's alias index) still holds — and
//! serves — its blobs after a full process-equivalent restart, with no
//! provider taught to anyone. This is the capability the M4 plan's
//! restart limitation was missing.

use ciss_iroh::{MeshPeer, MeshPersist};
use ciss_sync::{AliasStore, BlobTransport};
use sha2::Digest;

fn cid_of(bytes: &[u8]) -> String {
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// put → shutdown → respawn on the same dirs → get serves locally: the
/// alias survived in sqlite, the bytes survived in the fs store, and no
/// provider exists anywhere to fall back to.
#[tokio::test]
async fn a_respawned_peer_still_serves_its_blobs() {
    let root = tempfile::tempdir().expect("tempdir");
    let aliases = AliasStore::open(root.path().join("state.sqlite")).expect("aliases");
    let persist =
        MeshPersist { store_dir: root.path().join("iroh"), aliases: aliases.clone() };

    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 211) as u8).collect();
    let cid = cid_of(&payload);
    {
        let key = ciss::crypto::derive_keypair("persist-master", "pool");
        let a = MeshPeer::spawn(key, "dev-a", &[], None, Some(persist.clone()))
            .await
            .expect("spawn");
        a.put(&cid, &payload).await.expect("put");
        assert!(a.have().await.expect("have").contains(&cid));
        a.shutdown().await;
    }

    // The alias landed durably (write-through, not shutdown-time flush).
    assert_eq!(
        aliases.get(&cid).expect("get"),
        Some(*blake3::hash(&payload).as_bytes()),
        "the sha256→blake3 alias is in sqlite"
    );

    // A fresh spawn on the same dirs: the blob is local again — have()
    // shows it, get() serves it, nobody was ever taught a provider.
    let key = ciss::crypto::derive_keypair("persist-master", "pool");
    let a2 = MeshPeer::spawn(key, "dev-a", &[], None, Some(persist)).await.expect("respawn");
    assert!(
        a2.have().await.expect("have").contains(&cid),
        "a persisted blob is local after respawn"
    );
    assert_eq!(a2.get(&cid).await.expect("get"), payload, "…and serves byte-identically");
    a2.shutdown().await;
}
