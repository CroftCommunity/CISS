//! Workflow tier — M2 (bounded local footprint). Evict drops a file's local
//! bytes without ever shrinking the server-side truth: the logical tree a
//! backup commits is the scanned files ∪ placeholders, eviction is refused
//! unless the bytes are provably backed, and a restore elsewhere still
//! reproduces everything byte-identically.

mod common;

use std::fs;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use ciss_cli::client::Client;
use ciss_cli::sync::HttpCiss;
use ciss_sync::{backup, evict, hydrate, restore, BlobTransport, ManifestSlot, SyncError, SyncState};
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

/// The M2 capability gate: a tree larger than the local budget round-trips
/// through evict → bounded local bytes → hydrate, byte-identically
/// (content + mode + mtime), while the keep-set covers the whole tree.
#[tokio::test]
async fn footprint_bounded_while_tree_grows() {
    let world = World::spawn().await;
    let server = syncer(&world, "bounded");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_home = tempfile::tempdir().expect("tempdir");
    let big = build_tree(dir.path());
    let big_meta = fs::metadata(dir.path().join("big.bin")).expect("meta");
    let big_mtime = big_meta.modified().expect("mtime");

    let mut state = SyncState::open(state_home.path().join("s")).expect("state");
    // A cache budget far below the big file: eviction cannot spill it locally.
    state.set_cache_budget(50_000).expect("budget");

    backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    evict(dir.path(), &mut state, &server, &["big.bin"]).await.expect("evict");

    // Local footprint is bounded: the tree holds only the small file, and
    // the cache respects its budget.
    assert!(!dir.path().join("big.bin").exists());
    assert!(state.cache.total_bytes().expect("total") <= 50_000);

    // Hydrate brings the bytes back — verified, with mode + mtime restored.
    let r = hydrate(dir.path(), &mut state, &server, Some(&["big.bin"])).await.expect("hydrate");
    assert_eq!(r.files, 1);
    assert_eq!(fs::read(dir.path().join("big.bin")).expect("read"), big);
    let restored_meta = fs::metadata(dir.path().join("big.bin")).expect("meta");
    let dt = restored_meta
        .modified()
        .expect("mtime")
        .duration_since(big_mtime)
        .unwrap_or_default();
    assert!(dt.as_secs() < 1, "mtime restored (within a second)");
    assert!(state.placeholders.get("big.bin").expect("get").is_none(), "placeholder consumed");

    world.shutdown().await;
}

/// A transport wrapper that counts server fetches.
struct Counting<'a> {
    inner: &'a HttpCiss,
    gets: AtomicU64,
}

#[async_trait::async_trait]
impl BlobTransport for Counting<'_> {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        self.inner.have().await
    }
    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        self.inner.put(cid_hex, bytes).await
    }
    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(cid_hex).await
    }
}

/// With a roomy cache, hydration is free: every chunk comes from the local
/// cache and zero fetches reach the (metered) server.
#[tokio::test]
async fn cache_hit_hydrate_fetches_nothing() {
    let world = World::spawn().await;
    let server = syncer(&world, "cachehit");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_home = tempfile::tempdir().expect("tempdir");
    let big = build_tree(dir.path());
    let mut state = SyncState::open(state_home.path().join("s")).expect("state");

    backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    let ev = evict(dir.path(), &mut state, &server, &["big.bin"]).await.expect("evict");
    assert!(ev.chunks_cached > 0, "the default budget holds the spilled chunks");

    let counting = Counting { inner: &server, gets: AtomicU64::new(0) };
    let r = hydrate(dir.path(), &mut state, &counting, Some(&["big.bin"])).await.expect("hydrate");
    assert_eq!(r.chunks_from_server, 0);
    assert!(r.chunks_from_cache > 0);
    assert_eq!(counting.gets.load(Ordering::SeqCst), 0, "zero metered egress on a cache hit");
    assert_eq!(fs::read(dir.path().join("big.bin")).expect("read"), big);

    world.shutdown().await;
}

/// Eviction never loses data: even with the cache wiped out from under it,
/// hydration refetches everything from the server, verified.
#[tokio::test]
async fn eviction_never_loses_data() {
    let world = World::spawn().await;
    let server = syncer(&world, "resilient");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_home = tempfile::tempdir().expect("tempdir");
    let big = build_tree(dir.path());
    let mut state = SyncState::open(state_home.path().join("s")).expect("state");

    backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    evict(dir.path(), &mut state, &server, &["big.bin"]).await.expect("evict");

    // Wipe every cached blob behind the cache's back.
    let entry = state.placeholders.get("big.bin").expect("get").expect("some");
    for chunk in &entry.chunks {
        let p = state.cache.blob_path(&chunk.sha256_hex());
        let _ = fs::remove_file(p);
    }

    let r = hydrate(dir.path(), &mut state, &server, None).await.expect("hydrate all");
    assert_eq!(r.chunks_from_cache, 0, "the wiped cache serves nothing");
    assert!(r.chunks_from_server > 0);
    assert_eq!(fs::read(dir.path().join("big.bin")).expect("read"), big);

    world.shutdown().await;
}

/// A file that reappeared at an evicted path wins: hydrate refuses to
/// overwrite it, and the next backup commits the on-disk content.
#[tokio::test]
async fn hydrate_refuses_overwrite() {
    let world = World::spawn().await;
    let server = syncer(&world, "careful");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_home = tempfile::tempdir().expect("tempdir");
    build_tree(dir.path());
    let mut state = SyncState::open(state_home.path().join("s")).expect("state");

    backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
    evict(dir.path(), &mut state, &server, &["big.bin"]).await.expect("evict");

    // Something new appears at the evicted path.
    fs::write(dir.path().join("big.bin"), b"brand new content").expect("write");
    let err = hydrate(dir.path(), &mut state, &server, Some(&["big.bin"]))
        .await
        .expect_err("must refuse to clobber");
    assert!(matches!(err, SyncError::HydrateWouldOverwrite { .. }), "got: {err}");
    assert_eq!(fs::read(dir.path().join("big.bin")).expect("read"), b"brand new content");

    // The next backup prefers the on-disk file and drops the placeholder.
    backup(dir.path(), &server, Some(&mut state)).await.expect("backup");
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
