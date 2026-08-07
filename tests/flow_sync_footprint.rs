//! Workflow tier — M2 (bounded local footprint). Evict drops a file's local
//! bytes without ever shrinking the server-side truth: the logical tree a
//! backup commits is the scanned files ∪ placeholders, eviction is refused
//! unless the bytes are provably backed, and a restore elsewhere still
//! reproduces everything byte-identically.

mod common;

use std::fs;

use ciss_cli::client::Client;
use ciss_cli::sync::HttpCiss;
use ciss_sync::{backup, evict, restore, ManifestSlot, SyncError, SyncState};
use common::World;

fn syncer(world: &World, name: &str) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", name);
    HttpCiss::new(Client::new(world.url("")), keypair)
}

fn build_tree(root: &std::path::Path) -> Vec<u8> {
    fs::write(root.join("small.txt"), b"stays local").expect("write");
    let big: Vec<u8> = (0..1_500_000).map(|i| (i % 239) as u8).collect();
    fs::write(root.join("big.bin"), &big).expect("write");
    big
}

/// The no-data-loss guard: after evicting a file, the next backup commits the
/// SAME logical tree — the placeholder fills in for the absent bytes, the
/// fs-manifest cid is unchanged, and the keep-set never shrinks.
#[tokio::test]
async fn backup_preserves_evicted_entries() {
    let world = World::spawn().await;
    let server = syncer(&world, "evictor");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_home = tempfile::tempdir().expect("tempdir");
    build_tree(dir.path());
    let mut state = SyncState::open(state_home.path().join("s")).expect("state");

    let b1 = backup(dir.path(), &server, Some(&mut state)).await.expect("backup 1");
    assert_eq!(b1.files, 2);

    let report = evict(dir.path(), &mut state, &server, &["big.bin"]).await.expect("evict");
    assert_eq!(report.evicted, 1);
    assert!(report.bytes_freed >= 1_500_000);
    assert!(!dir.path().join("big.bin").exists(), "the bytes are gone locally");
    assert!(state.placeholders.get("big.bin").expect("get").is_some());

    // The next backup commits the identical logical tree.
    let b2 = backup(dir.path(), &server, Some(&mut state)).await.expect("backup 2");
    assert_eq!(b2.files, 2, "the evicted file is still part of the logical tree");
    assert_eq!(
        b2.fs_manifest_cid, b1.fs_manifest_cid,
        "an eviction must not change the committed tree"
    );
    assert_eq!(b2.chunks_uploaded, 0);
    assert!(b2.manifest_seq > b1.manifest_seq);

    // The keep-set still names every chunk of the evicted file.
    let keep: std::collections::HashSet<String> = server
        .keep_set()
        .await
        .expect("keep")
        .expect("exists")
        .into_iter()
        .map(|(cid, _)| cid)
        .collect();
    let entry = state.placeholders.get("big.bin").expect("get").expect("some");
    for chunk in &entry.chunks {
        assert!(keep.contains(&chunk.sha256_hex()), "keep-set must never shrink on evict");
    }

    world.shutdown().await;
}

/// Eviction is refused unless every current chunk is provably backed (in the
/// server's have-set AND the committed keep-set) — modified or never-backed
/// bytes stay on disk, untouched.
#[tokio::test]
async fn evict_refuses_unbacked_file() {
    let world = World::spawn().await;
    let server = syncer(&world, "cautious");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_home = tempfile::tempdir().expect("tempdir");
    build_tree(dir.path());
    let mut state = SyncState::open(state_home.path().join("s")).expect("state");

    // Never backed up at all: refused.
    let err = evict(dir.path(), &mut state, &server, &["big.bin"])
        .await
        .expect_err("no backup yet");
    assert!(matches!(err, SyncError::EvictUnbacked { .. }), "got: {err}");
    assert!(dir.path().join("big.bin").exists(), "a refused evict touches nothing");

    // Backed up, then modified: the new bytes are unbacked → refused.
    backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    let mut grown = fs::read(dir.path().join("big.bin")).expect("read");
    grown.extend_from_slice(b"fresh unbacked bytes");
    fs::write(dir.path().join("big.bin"), &grown).expect("modify");
    let err = evict(dir.path(), &mut state, &server, &["big.bin"])
        .await
        .expect_err("modified since backup");
    match err {
        SyncError::EvictUnbacked { path, missing_cids } => {
            assert_eq!(path, "big.bin");
            assert!(!missing_cids.is_empty(), "the refusal names the unbacked chunks");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(fs::read(dir.path().join("big.bin")).expect("read"), grown);
    assert!(state.placeholders.get("big.bin").expect("get").is_none());

    world.shutdown().await;
}

/// Local eviction never touches server-side truth: a restore into a fresh
/// directory reproduces the evicted file byte-identically.
#[tokio::test]
async fn evicted_file_restores_cleanly() {
    let world = World::spawn().await;
    let server = syncer(&world, "restorer");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_home = tempfile::tempdir().expect("tempdir");
    let big = build_tree(dir.path());
    let mut state = SyncState::open(state_home.path().join("s")).expect("state");

    let b = backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    evict(dir.path(), &mut state, &server, &["big.bin"]).await.expect("evict");

    let dst = tempfile::tempdir().expect("tempdir");
    restore(dst.path(), &server, Some(&b.fs_manifest_cid)).await.expect("restore");
    assert_eq!(fs::read(dst.path().join("big.bin")).expect("read"), big);
    assert_eq!(fs::read(dst.path().join("small.txt")).expect("read"), b"stays local");

    world.shutdown().await;
}
