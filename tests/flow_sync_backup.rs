//! Workflow tier — `sync backup` (M1 Phase 2). One device pushes a tree to an
//! in-process CISS: only missing chunks transfer, the fs-manifest blob is
//! stored, and the keep-set Manifest advances under the I5 seq-CAS. This is
//! the phase's wiring test: it proves the engine reaches the real server
//! boundary, not just that the chunker works.

mod common;

use std::collections::HashSet;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use ciss_cli::client::{self, Client};
use ciss_cli::sync::HttpCiss;
use ciss_sync::{backup, BlobTransport, DagCbor, ManifestCodec, ManifestSlot, SyncError};
use common::World;

fn build_tree(root: &std::path::Path) {
    fs::create_dir_all(root.join("sub")).expect("mkdir");
    fs::write(root.join("small.txt"), b"hello sync").expect("write");
    let big: Vec<u8> = (0..2 * 1024 * 1024 + 999).map(|i| (i % 249) as u8).collect();
    fs::write(root.join("sub/big.bin"), big).expect("write");
}

fn syncer(world: &World) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", "syncer");
    HttpCiss::new(Client::new(world.url("")), keypair)
}

/// The core backup story: first push uploads everything + the fs-manifest and
/// commits keep-set seq 1; an unchanged re-push uploads **zero** chunks
/// (have/want skip) and the keep-set still advances strictly (I5).
#[tokio::test]
async fn backup_uploads_once_then_skips_and_keep_set_advances_under_i5() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let dir = tempfile::tempdir().expect("tempdir");
    build_tree(dir.path());

    // First backup: everything transfers.
    let r1 = backup(dir.path(), &server, None).await.expect("backup 1");
    assert_eq!(r1.files, 2);
    assert!(r1.chunks_total >= 3, "the 2 MiB file must chunk (got {})", r1.chunks_total);
    assert_eq!(r1.chunks_uploaded, r1.chunks_total, "cold server: all chunks upload");
    assert_eq!(r1.manifest_seq, 1, "the first keep-set commit is seq 1");

    // The fs-manifest blob is stored and decodes back to a manifest whose
    // content_id is the stored cid (the address is the server's own sha-256).
    let keypair = ciss::crypto::derive_keypair("flow-master", "syncer");
    let session = client::session_for(&keypair);
    let fetched = server
        .client()
        .get_s3(Some(&session), &session.did, &r1.fs_manifest_cid)
        .await
        .expect("fs-manifest stored");
    let decoded = DagCbor.decode(&fetched.bytes).expect("decode fs-manifest");
    assert_eq!(decoded.content_id().expect("cid"), r1.fs_manifest_cid);
    assert_eq!(decoded.entries.len(), 2);

    // The keep-set Manifest names every chunk cid + the fs-manifest cid.
    let keep = server
        .client()
        .get_manifest(&session.did)
        .await
        .expect("get_manifest")
        .expect("a keep-set exists after backup");
    assert_eq!(keep.seq(), 1);
    let leaf_cids: HashSet<&str> = keep.leaves().iter().map(|l| l.cid()).collect();
    assert!(leaf_cids.contains(r1.fs_manifest_cid.as_str()));
    for entry in decoded.entries.values() {
        for c in &entry.chunks {
            assert!(leaf_cids.contains(c.sha256_hex().as_str()), "keep-set must hold every chunk");
        }
    }

    // Unchanged re-push: zero chunks move, seq still strictly advances.
    let r2 = backup(dir.path(), &server, None).await.expect("backup 2");
    assert_eq!(r2.chunks_uploaded, 0, "have/want must skip everything");
    assert_eq!(r2.bytes_uploaded, 0);
    assert_eq!(r2.manifest_seq, 2, "keep-set commits are strictly newer (I5)");

    // I5 guard: a stale/equal-seq commit is refused by the server and surfaced
    // as an error, never swallowed.
    let stale = ciss::manifest::build_manifest(
        &[ciss::manifest::ManifestLeaf::new(&r1.fs_manifest_cid, 1)],
        &session.did,
        &keypair,
        2, // equal to the stored seq — I5 demands strictly newer
    );
    let err = server
        .client()
        .put_manifest(&session, &stale)
        .await
        .expect_err("an equal-seq manifest must be refused");
    assert!(err.to_string().contains("seq"), "the error names the seq conflict: {err}");

    world.shutdown().await;
}

/// A transport that fails after `allow` puts — the "network died mid-backup"
/// story. The re-run must transfer only what is still missing (chunk-level
/// resume replaces byte-range resume).
struct FailAfter<'a> {
    inner: &'a HttpCiss,
    allow: u64,
    puts: AtomicU64,
}

#[async_trait::async_trait]
impl BlobTransport for FailAfter<'_> {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        self.inner.have().await
    }
    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        if self.puts.fetch_add(1, Ordering::SeqCst) >= self.allow {
            return Err(SyncError::Transport("injected: connection lost".to_owned()));
        }
        self.inner.put(cid_hex, bytes).await
    }
    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        self.inner.get(cid_hex).await
    }
}

#[async_trait::async_trait]
impl ManifestSlot for FailAfter<'_> {
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
async fn interrupted_backup_resumes_by_skipping_stored_chunks() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let dir = tempfile::tempdir().expect("tempdir");
    build_tree(dir.path());

    // Fail after 2 chunk uploads: the backup must error (fail loud, no
    // partial keep-set commit pretending success).
    let flaky = FailAfter { inner: &server, allow: 2, puts: AtomicU64::new(0) };
    let err = backup(dir.path(), &flaky, None).await.expect_err("must fail mid-transfer");
    assert!(err.to_string().contains("connection lost"), "surfaced: {err}");
    let keypair = ciss::crypto::derive_keypair("flow-master", "syncer");
    let session = client::session_for(&keypair);
    assert!(
        server.client().get_manifest(&session.did).await.expect("get").is_none(),
        "an interrupted backup must not commit a keep-set"
    );

    // The re-run transfers only the chunks the server still lacks.
    let resumed = backup(dir.path(), &server, None).await.expect("resume");
    assert!(
        resumed.chunks_uploaded < resumed.chunks_total,
        "resume must skip the {} chunks that already landed",
        2
    );
    assert_eq!(resumed.manifest_seq, 1, "the first successful commit is seq 1");

    world.shutdown().await;
}
