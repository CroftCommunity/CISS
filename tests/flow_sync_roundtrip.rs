//! Workflow tier — the M1 capability gate: back up a tree, wipe local state,
//! `sync restore` reproduces it byte-identically; a tampered chunk is refused,
//! never written; a cold restore (zero local state) discovers the fs-manifest
//! from the keep-set alone.

mod common;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use ciss_cli::client::Client;
use ciss_cli::sync::HttpCiss;
use ciss_sync::{backup, restore, BlobTransport, ManifestSlot, SyncError};
use common::World;

fn build_tree(root: &std::path::Path) {
    fs::create_dir_all(root.join("docs/nested")).expect("mkdir");
    fs::write(root.join("hello.txt"), b"round trip").expect("write");
    fs::write(root.join("docs/tiny.md"), b"x").expect("write");
    let big: Vec<u8> = (0..2 * 1024 * 1024 + 777).map(|i| (i % 241) as u8).collect();
    fs::write(root.join("docs/nested/big.bin"), big).expect("write");
    let script = root.join("run.sh");
    fs::write(&script, b"#!/bin/sh\necho hi\n").expect("write");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn syncer(world: &World, name: &str) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", name);
    HttpCiss::new(Client::new(world.url("")), keypair)
}

/// Walk `dir` into (relative path → (bytes, mode, mtime_secs)).
fn snapshot(dir: &std::path::Path) -> std::collections::BTreeMap<String, (Vec<u8>, u32, i64)> {
    fn walk(
        root: &std::path::Path,
        dir: &std::path::Path,
        out: &mut std::collections::BTreeMap<String, (Vec<u8>, u32, i64)>,
    ) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).expect("rel").to_str().expect("utf8").to_owned();
                let meta = entry.metadata().expect("meta");
                let mtime = meta
                    .modified()
                    .expect("mtime")
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("post-epoch")
                    .as_secs();
                out.insert(
                    rel,
                    (
                        fs::read(&path).expect("read"),
                        meta.permissions().mode() & 0o7777,
                        i64::try_from(mtime).expect("fits"),
                    ),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// The end-to-end M1 gate: backup → wipe → restore → byte-identical
/// (content + mode; mtime restored to the second).
#[tokio::test]
async fn backup_wipe_restore_is_byte_identical() {
    let world = World::spawn().await;
    let server = syncer(&world, "roundtripper");
    let src = tempfile::tempdir().expect("tempdir");
    build_tree(src.path());
    let before = snapshot(src.path());

    let b = backup(src.path(), &server, None).await.expect("backup");

    // "Wipe local": restore into a fresh directory, using only the manifest cid.
    let dst = tempfile::tempdir().expect("tempdir");
    let r = restore(dst.path(), &server, Some(&b.fs_manifest_cid)).await.expect("restore");
    assert_eq!(r.files, b.files);
    assert_eq!(r.fs_manifest_cid, b.fs_manifest_cid);

    let after = snapshot(dst.path());
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "the restored tree must have exactly the backed-up paths"
    );
    for (path, (bytes, mode, mtime)) in &before {
        let (r_bytes, r_mode, r_mtime) = &after[path];
        assert_eq!(r_bytes, bytes, "{path}: bytes must be identical");
        assert_eq!(r_mode, mode, "{path}: mode must be restored");
        assert_eq!(r_mtime, mtime, "{path}: mtime must be restored (second precision)");
    }

    world.shutdown().await;
}

/// A transport that substitutes one chunk's bytes — the engine must fail
/// closed on its own verification: the error names the cid, and the
/// destination file is never written (no partial/poisoned output).
struct Substituting<'a> {
    inner: &'a HttpCiss,
    target_cid: String,
}

#[async_trait::async_trait]
impl BlobTransport for Substituting<'_> {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        self.inner.have().await
    }
    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        self.inner.put(cid_hex, bytes).await
    }
    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        if cid_hex == self.target_cid {
            return Ok(b"substituted bytes, wrong hash".to_vec());
        }
        self.inner.get(cid_hex).await
    }
}

#[async_trait::async_trait]
impl ManifestSlot for Substituting<'_> {
    async fn current_seq(&self) -> Result<Option<u64>, SyncError> {
        self.inner.current_seq().await
    }
    async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError> {
        self.inner.keep_set().await
    }
    async fn frontier(&self) -> Result<Option<ciss_sync::FrontierView>, SyncError> {
        self.inner.frontier().await
    }
    async fn commit_keep_set(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
    ) -> Result<(), SyncError> {
        self.inner.commit_keep_set(leaves, seq).await
    }
    async fn commit_frontier(
        &self,
        leaves: &[(String, u64)],
        seq: u64,
        heads: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), SyncError> {
        self.inner.commit_frontier(leaves, seq, heads).await
    }
}

#[tokio::test]
async fn tampered_chunk_rejected_and_nothing_written() {
    let world = World::spawn().await;
    let server = syncer(&world, "tamper-victim");
    let src = tempfile::tempdir().expect("tempdir");
    fs::write(src.path().join("precious.txt"), b"the only file").expect("write");
    let b = backup(src.path(), &server, None).await.expect("backup");

    // The one chunk of the one file is the substitution target.
    let keep = server.keep_set().await.expect("keep").expect("exists");
    let target_cid = keep
        .iter()
        .map(|(c, _)| c.clone())
        .find(|c| c != &b.fs_manifest_cid)
        .expect("the file's chunk is in the keep-set");

    let lying = Substituting { inner: &server, target_cid: target_cid.clone() };
    let dst = tempfile::tempdir().expect("tempdir");
    let err = restore(dst.path(), &lying, Some(&b.fs_manifest_cid))
        .await
        .expect_err("substituted bytes must fail the restore");
    let msg = err.to_string();
    assert!(msg.contains(&target_cid[..12]), "the error names the cid: {msg}");
    assert!(
        !dst.path().join("precious.txt").exists(),
        "a tampered chunk must not leave a file behind (fail closed)"
    );

    world.shutdown().await;
}

/// Cold restore: zero local state — not even the fs-manifest cid. The keep-set
/// scan finds the self-tagged manifest among many small non-manifest leaves.
#[tokio::test]
async fn cold_restore_discovers_the_fs_manifest() {
    let world = World::spawn().await;
    let server = syncer(&world, "cold-restorer");
    let src = tempfile::tempdir().expect("tempdir");
    // Many tiny files: the keep-set fills with small non-manifest leaves, so
    // discovery must reject decoy candidates by the kind tag, not by size.
    for i in 0..8 {
        fs::write(src.path().join(format!("tiny-{i}.txt")), format!("tiny {i}")).expect("write");
    }
    let b = backup(src.path(), &server, None).await.expect("backup");
    let before = snapshot(src.path());

    let dst = tempfile::tempdir().expect("tempdir");
    let r = restore(dst.path(), &server, None).await.expect("cold restore");
    assert_eq!(r.fs_manifest_cid, b.fs_manifest_cid, "discovery must find the real manifest");

    let after = snapshot(dst.path());
    assert_eq!(before.len(), after.len());
    for (path, (bytes, ..)) in &before {
        assert_eq!(&after[path].0, bytes, "{path}: restored bytes identical");
    }

    world.shutdown().await;
}
