//! Workflow tier — the M3 capability gate: two devices converge to the SAME
//! tree, deterministically and clock-free; a real conflict is preserved as a
//! conflict-copy on both devices, never lost; a rename transfers zero chunks
//! (dedup carries it — no detection machinery needed).

mod common;

use std::fs;

use ciss_cli::client::Client;
use ciss_cli::sync::HttpCiss;
use ciss_sync::{backup_frontier, converge, scan_tree, SyncState};
use common::World;

fn syncer(world: &World) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", "converge-pool");
    HttpCiss::new(Client::new(world.url("")), keypair)
}

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

/// Both trees byte-identical? Compare the deterministic scan content ids.
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
        assert_eq!(ea.size, eb.size);
    }
}

/// Disjoint edits merge cleanly: each device ends up with both files, and the
/// two trees are identical.
#[tokio::test]
async fn disjoint_edits_merge() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let mut a = device("dev-a");
    let mut b = device("dev-b");
    fs::write(a.dir.path().join("alpha.txt"), b"from device a").expect("write");
    fs::write(b.dir.path().join("beta.txt"), vec![7u8; 200_000]).expect("write");

    backup_frontier(a.dir.path(), &server, &mut a.state, a.id).await.expect("a backup");
    backup_frontier(b.dir.path(), &server, &mut b.state, b.id).await.expect("b backup");

    let ra = converge(a.dir.path(), &mut a.state, &server, a.id).await.expect("a converge");
    assert!(ra.conflicts.is_empty(), "disjoint edits are not conflicts");
    assert!(a.dir.path().join("beta.txt").exists(), "A received B's file");

    let rb = converge(b.dir.path(), &mut b.state, &server, b.id).await.expect("b converge");
    assert!(rb.conflicts.is_empty());
    assert!(b.dir.path().join("alpha.txt").exists(), "B received A's file");

    assert_converged(&a, &b);
    world.shutdown().await;
}

/// Same-path divergence: the content-address winner keeps the path, the loser
/// is preserved as `<path>.conflict-<device>` — both contents on BOTH devices.
#[tokio::test]
async fn same_path_divergence_preserved() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let mut a = device("dev-a");
    let mut b = device("dev-b");
    fs::write(a.dir.path().join("notes.txt"), b"device A's version").expect("write");
    fs::write(b.dir.path().join("notes.txt"), b"device B's very different take").expect("write");

    backup_frontier(a.dir.path(), &server, &mut a.state, a.id).await.expect("a backup");
    backup_frontier(b.dir.path(), &server, &mut b.state, b.id).await.expect("b backup");

    let ra = converge(a.dir.path(), &mut a.state, &server, a.id).await.expect("a converge");
    assert_eq!(ra.conflicts.len(), 1, "one real conflict surfaced");
    let rb = converge(b.dir.path(), &mut b.state, &server, b.id).await.expect("b converge");

    // Both devices hold both contents: the winner at notes.txt, the loser at
    // exactly one conflict path; the split is identical on both devices.
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
        let mut both = [main.clone(), copy];
        both.sort();
        assert_eq!(
            both,
            [b"device A's version".to_vec(), b"device B's very different take".to_vec()],
            "both contents preserved on {}",
            d.id
        );
    }
    assert_converged(&a, &b);
    let _ = rb;
    world.shutdown().await;
}

/// A rename is delete+add whose chunks the server already holds: the
/// re-backup transfers zero chunks (dedup — no detection machinery).
#[tokio::test]
async fn rename_transfers_zero_chunks() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let mut a = device("dev-a");
    let payload: Vec<u8> = (0..600_000).map(|i| (i % 229) as u8).collect();
    fs::write(a.dir.path().join("old-name.bin"), &payload).expect("write");
    backup_frontier(a.dir.path(), &server, &mut a.state, a.id).await.expect("backup");

    fs::rename(a.dir.path().join("old-name.bin"), a.dir.path().join("new-name.bin"))
        .expect("rename");
    let r = backup_frontier(a.dir.path(), &server, &mut a.state, a.id).await.expect("rebackup");
    assert_eq!(r.chunks_uploaded, 0, "a rename moves no bytes — dedup carries it");

    world.shutdown().await;
}

/// Modify-vs-delete: the modification wins (non-lossy default).
#[tokio::test]
async fn modify_beats_delete() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let mut a = device("dev-a");
    let mut b = device("dev-b");

    // A shared base: A creates the file, B receives it via converge.
    fs::write(a.dir.path().join("shared.txt"), b"the original").expect("write");
    backup_frontier(a.dir.path(), &server, &mut a.state, a.id).await.expect("a backup");
    backup_frontier(b.dir.path(), &server, &mut b.state, b.id).await.expect("b backup");
    converge(a.dir.path(), &mut a.state, &server, a.id).await.expect("a converge");
    converge(b.dir.path(), &mut b.state, &server, b.id).await.expect("b converge");
    assert!(b.dir.path().join("shared.txt").exists());

    // A deletes; B modifies. The modification survives on both.
    fs::remove_file(a.dir.path().join("shared.txt")).expect("rm");
    fs::write(b.dir.path().join("shared.txt"), b"B's improvement").expect("write");
    backup_frontier(a.dir.path(), &server, &mut a.state, a.id).await.expect("a backup 2");
    backup_frontier(b.dir.path(), &server, &mut b.state, b.id).await.expect("b backup 2");
    converge(a.dir.path(), &mut a.state, &server, a.id).await.expect("a converge 2");
    converge(b.dir.path(), &mut b.state, &server, b.id).await.expect("b converge 2");

    for d in [&a, &b] {
        assert_eq!(
            fs::read(d.dir.path().join("shared.txt")).expect("read"),
            b"B's improvement",
            "the modification wins over the delete on {}",
            d.id
        );
    }
    assert_converged(&a, &b);
    world.shutdown().await;
}
