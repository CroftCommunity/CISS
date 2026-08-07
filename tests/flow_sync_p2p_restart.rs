//! Workflow tier — the persistence acceptance gate: multi-round serverless
//! converge ACROSS RESTARTS. This is exactly the "Wednesday story" the M4
//! plan documented as its limitation (`SYNC-MODEL.md` §4): round 1
//! converges, every mesh process dies, both trees are edited, and round 2
//! must still converge — the 3-way base's bytes now survive in the
//! fs-backed store, its alias in sqlite. No `World`; no server anywhere.

mod common;

use std::fs;
use std::time::Duration;

use ciss_iroh::{MeshPeer, MeshPersist};
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

fn persist_of(d: &Device) -> MeshPersist {
    MeshPersist {
        store_dir: d.state.dir().join("iroh"),
        aliases: d.state.aliases().clone(),
    }
}

async fn mesh_first(d: &Device) -> MeshPeer {
    let key = ciss::crypto::derive_keypair("restart-master", "lineage");
    MeshPeer::spawn(key, d.id, &[], None, Some(persist_of(d))).await.expect("spawn")
}

async fn mesh_joined(d: &Device, other: &MeshPeer) -> MeshPeer {
    let key = ciss::crypto::derive_keypair("restart-master", "lineage");
    MeshPeer::spawn(key, d.id, &[other.addr()], None, Some(persist_of(d)))
        .await
        .expect("spawn")
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
        assert_eq!(ea.chunks, mb.entries[path].chunks, "{path}: same content");
    }
}

#[tokio::test]
async fn serverless_converge_survives_full_restarts() {
    let mut a = device("dev-a");
    let mut b = device("dev-b");
    fs::write(a.dir.path().join("alpha.txt"), b"round one, from a").expect("write");
    fs::write(b.dir.path().join("beta.txt"), b"round one, from b").expect("write");

    // Round 1: converge as in M4 — but with persistence attached.
    {
        let mesh_a = mesh_first(&a).await;
        let mesh_b = mesh_joined(&b, &mesh_a).await;
        backup_frontier(a.dir.path(), &mesh_a, &mut a.state, a.id).await.expect("a backup");
        backup_frontier(b.dir.path(), &mesh_b, &mut b.state, b.id).await.expect("b backup");
        mesh_a.await_devices(1, Duration::from_secs(20)).await.expect("a sees b");
        mesh_b.await_devices(1, Duration::from_secs(20)).await.expect("b sees a");
        converge(a.dir.path(), &mut a.state, &mesh_a, a.id).await.expect("a converge 1");
        mesh_b.await_devices(1, Duration::from_secs(20)).await.expect("b sees a's head");
        converge(b.dir.path(), &mut b.state, &mesh_b, b.id).await.expect("b converge 1");
        assert_converged(&a, &b);

        // EVERY mesh process dies. (The SyncStates — sqlite — survive, as
        // they would on a real machine.)
        mesh_a.shutdown().await;
        mesh_b.shutdown().await;
    }

    // Overnight: both devices edit. The 3-way base is now a tree neither
    // current tree can reproduce.
    fs::write(a.dir.path().join("alpha.txt"), b"round two, A edited").expect("write");
    fs::write(b.dir.path().join("gamma.txt"), b"round two, B added").expect("write");

    // Round 2, fresh processes on the same state: this is the story that
    // failed loud before persistence ("no sha256→blake3 mapping" on the
    // base fetch). Now the base's alias is in sqlite and its bytes are in
    // the fs store.
    let mesh_a = mesh_first(&a).await;
    let mesh_b = mesh_joined(&b, &mesh_a).await;
    backup_frontier(a.dir.path(), &mesh_a, &mut a.state, a.id).await.expect("a backup 2");
    backup_frontier(b.dir.path(), &mesh_b, &mut b.state, b.id).await.expect("b backup 2");
    mesh_a.await_devices(1, Duration::from_secs(20)).await.expect("a sees b");
    mesh_b.await_devices(1, Duration::from_secs(20)).await.expect("b sees a");

    let ra = converge(a.dir.path(), &mut a.state, &mesh_a, a.id).await.expect("a converge 2");
    assert!(ra.conflicts.is_empty(), "disjoint round-2 edits are not conflicts");
    mesh_b.await_devices(1, Duration::from_secs(20)).await.expect("b sees a's new head");
    let rb = converge(b.dir.path(), &mut b.state, &mesh_b, b.id).await.expect("b converge 2");
    assert_eq!(ra.fs_manifest_cid, rb.fs_manifest_cid, "identical trees after restart");

    for d in [&a, &b] {
        assert_eq!(
            fs::read(d.dir.path().join("alpha.txt")).expect("read"),
            b"round two, A edited",
            "{}: A's edit propagated",
            d.id
        );
        assert!(d.dir.path().join("gamma.txt").exists(), "{}: B's add propagated", d.id);
        assert!(d.dir.path().join("beta.txt").exists(), "{}: round-1 file survived", d.id);
    }
    assert_converged(&a, &b);

    mesh_a.shutdown().await;
    mesh_b.shutdown().await;
}
