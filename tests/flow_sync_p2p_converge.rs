//! Workflow tier — the M4 P2 capability gate: two devices converge to the
//! same tree **with the server offline** — there is no `World` in this test
//! at all. The frontier rides iroh-gossip, the blobs ride iroh-blobs, and
//! `ciss_sync::converge` runs unchanged: the fold neither knows nor cares
//! that no server exists.

use std::fs;
use std::time::Duration;

use ciss_iroh::MeshPeer;
use ciss_sync::{backup_frontier, converge, scan_tree, SyncState};

struct Device {
    dir: tempfile::TempDir,
    state: SyncState,
    id: &'static str,
    _home: tempfile::TempDir,
}

fn device(id: &'static str) -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("tempdir");
    let state = SyncState::open(home.path().join("s")).expect("state");
    Device { dir, state, id, _home: home }
}

async fn mesh_pair() -> (MeshPeer, MeshPeer) {
    let key_a = ciss::crypto::derive_keypair("p2p-master", "lineage");
    let key_b = ciss::crypto::derive_keypair("p2p-master", "lineage");
    let a = MeshPeer::spawn(key_a, "dev-a", &[], None, None).await.expect("spawn a");
    let b = MeshPeer::spawn(key_b, "dev-b", &[a.addr()], None, None).await.expect("spawn b");
    (a, b)
}

fn assert_converged(a: &Device, b: &Device) {
    let ma = scan_tree(a.dir.path()).expect("scan a");
    let mb = scan_tree(b.dir.path()).expect("scan b");
    assert_eq!(
        ma.entries.keys().collect::<Vec<_>>(),
        mb.entries.keys().collect::<Vec<_>>(),
        "same paths on both devices"
    );
    for (path, ea) in &ma.entries {
        let eb = &mb.entries[path];
        assert_eq!(ea.chunks, eb.chunks, "{path}: same content on both devices");
    }
}

/// Disjoint edits + one same-path conflict, no server anywhere: both devices
/// converge to the identical tree and both contents of the conflict survive
/// on both devices — the M3 semantics, over iroh alone.
#[tokio::test]
async fn two_devices_converge_with_the_server_offline() {
    let (mesh_a, mesh_b) = mesh_pair().await;
    let mut a = device("dev-a");
    let mut b = device("dev-b");

    fs::write(a.dir.path().join("alpha.txt"), b"only on device a").expect("write");
    let beta: Vec<u8> = (0..400_000).map(|i| (i % 233) as u8).collect();
    fs::write(b.dir.path().join("beta.bin"), &beta).expect("write");
    fs::write(a.dir.path().join("notes.txt"), b"A's take on the notes").expect("write");
    fs::write(b.dir.path().join("notes.txt"), b"B's rather different notes").expect("write");

    backup_frontier(a.dir.path(), &mesh_a, &mut a.state, a.id).await.expect("a backup");
    backup_frontier(b.dir.path(), &mesh_b, &mut b.state, b.id).await.expect("b backup");

    // Gossip is asynchronous: converge once each device can see the other.
    mesh_a.await_devices(1, Duration::from_secs(20)).await.expect("a sees b");
    mesh_b.await_devices(1, Duration::from_secs(20)).await.expect("b sees a");

    let ra = converge(a.dir.path(), &mut a.state, &mesh_a, a.id).await.expect("a converge");
    assert_eq!(ra.conflicts.len(), 1, "the same-path divergence is a conflict");
    assert!(a.dir.path().join("beta.bin").exists(), "A received B's file over iroh");
    assert_eq!(
        fs::read(a.dir.path().join("beta.bin")).expect("read"),
        beta,
        "peer-served bytes are byte-identical"
    );

    // A's converge republished its folded tree; B folds against it.
    mesh_b.await_devices(1, Duration::from_secs(20)).await.expect("b sees a's new head");
    let rb = converge(b.dir.path(), &mut b.state, &mesh_b, b.id).await.expect("b converge");
    assert!(b.dir.path().join("alpha.txt").exists(), "B received A's file over iroh");
    assert_eq!(ra.fs_manifest_cid, rb.fs_manifest_cid, "both devices derived the SAME tree");

    // Both contents of the conflict, on both devices.
    for d in [&a, &b] {
        let main = fs::read(d.dir.path().join("notes.txt")).expect("read");
        let conflicts: Vec<_> = fs::read_dir(d.dir.path())
            .expect("dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".conflict-"))
            .collect();
        assert_eq!(conflicts.len(), 1, "exactly one conflict-copy on {}", d.id);
        let copy = fs::read(d.dir.path().join(&conflicts[0])).expect("read");
        let mut both = [main, copy];
        both.sort();
        assert_eq!(
            both,
            [b"A's take on the notes".to_vec(), b"B's rather different notes".to_vec()],
            "both contents preserved on {}",
            d.id
        );
    }
    assert_converged(&a, &b);

    mesh_a.shutdown().await;
    mesh_b.shutdown().await;
}
