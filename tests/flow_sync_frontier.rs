//! Workflow tier — M3 Phase 2: the non-lossy frontier commit. Two devices of
//! one account each write only their own `heads` slot; a stale-seq refusal
//! (I5) triggers a re-read + re-apply-own-slot retry, so concurrent commits
//! both land and neither device's data ever leaves the keep-set.

mod common;

use std::collections::HashSet;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ciss_cli::client::Client;
use ciss_cli::sync::HttpCiss;
use ciss_sync::{
    backup_frontier, BlobTransport, DeviceHead, ManifestSlot, SyncError, SyncState,
    DEVICE_HEAD_KIND,
};
use common::World;

fn syncer(world: &World) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", "frontier-pool");
    HttpCiss::new(Client::new(world.url("")), keypair)
}

/// A wrapper that injects device B's whole frontier backup between device A's
/// frontier read and A's first commit attempt — the deterministic version of
/// "two devices race." A's first PUT is stale; the retry must land.
struct RaceInjector<'a> {
    inner: &'a HttpCiss,
    b_dir: std::path::PathBuf,
    b_state: tokio::sync::Mutex<&'a mut SyncState>,
    injected: AtomicBool,
    commits: AtomicU64,
}

#[async_trait::async_trait]
impl BlobTransport for RaceInjector<'_> {
    async fn have(&self) -> Result<HashSet<String>, SyncError> {
        self.inner.have().await
    }
    async fn put(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), SyncError> {
        self.inner.put(cid_hex, bytes).await
    }
    async fn get(&self, cid_hex: &str) -> Result<Vec<u8>, SyncError> {
        self.inner.get(cid_hex).await
    }
}

#[async_trait::async_trait]
impl ManifestSlot for RaceInjector<'_> {
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
        if !self.injected.swap(true, Ordering::SeqCst) {
            // Device B lands its whole backup first — right under A's feet.
            let mut b_state = self.b_state.lock().await;
            backup_frontier(&self.b_dir, self.inner, &mut b_state, "dev-b")
                .await
                .expect("B's backup lands");
        }
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.inner.commit_frontier(leaves, seq, heads).await
    }
}

impl ciss_sync::AccountKey for RaceInjector<'_> {
    fn keypair(&self) -> &ciss::crypto::Keypair {
        self.inner.keypair()
    }
}

#[tokio::test]
async fn two_devices_both_land_and_keep_set_covers_both() {
    let world = World::spawn().await;
    let server = syncer(&world);

    // Two devices, two local trees, one account.
    let a_dir = tempfile::tempdir().expect("tempdir");
    let b_dir = tempfile::tempdir().expect("tempdir");
    fs::write(a_dir.path().join("from-a.txt"), b"alpha device content").expect("write");
    let b_payload: Vec<u8> = (0..900_000).map(|i| (i % 233) as u8).collect();
    fs::write(b_dir.path().join("from-b.bin"), &b_payload).expect("write");
    let sa = tempfile::tempdir().expect("tempdir");
    let sb = tempfile::tempdir().expect("tempdir");
    let mut a_state = SyncState::open(sa.path().join("s")).expect("state");
    let mut b_state = SyncState::open(sb.path().join("s")).expect("state");

    // A commits through the injector: B's backup lands mid-flight, so A's
    // first commit is stale and the retry re-applies only A's slot.
    let racer = RaceInjector {
        inner: &server,
        b_dir: b_dir.path().to_path_buf(),
        b_state: tokio::sync::Mutex::new(&mut b_state),
        injected: AtomicBool::new(false),
        commits: AtomicU64::new(0),
    };
    let a_report =
        backup_frontier(a_dir.path(), &racer, &mut a_state, "dev-a").await.expect("A lands");
    assert_eq!(
        racer.commits.load(Ordering::SeqCst),
        2,
        "A needed exactly one stale attempt + one retry"
    );
    assert_eq!(a_report.manifest_seq, 2, "B took seq 1; A's retry landed at 2");

    // Both heads present; neither overwritten.
    let frontier = server.frontier().await.expect("frontier").expect("exists");
    assert_eq!(frontier.heads.len(), 2);
    let a_head_cid = &frontier.heads["dev-a"];
    let b_head_cid = &frontier.heads["dev-b"];

    // The keep-set covers BOTH devices' closures: head blobs, fs-manifests,
    // and every chunk — A's commit must not orphan B's bytes (the M3
    // no-data-loss guard).
    let keep: HashSet<String> =
        frontier.leaves.iter().map(|(cid, _)| cid.clone()).collect();
    for head_cid in [a_head_cid, b_head_cid] {
        assert!(keep.contains(head_cid), "DeviceHead blob in keep-set");
        let head_bytes = server.get(head_cid).await.expect("head blob");
        let head = DeviceHead::decode_verified(
            &head_bytes,
            &ciss::crypto::derive_keypair("flow-master", "frontier-pool").verifying_key(),
        )
        .expect("verified head");
        assert_eq!(head.kind, DEVICE_HEAD_KIND);
        assert!(keep.contains(&head.fs_root), "fs-manifest in keep-set");
        let manifest_bytes = server.get(&head.fs_root).await.expect("fs-manifest");
        let manifest = ciss_sync::DagCbor.decode(&manifest_bytes).expect("decode");
        use ciss_sync::ManifestCodec as _;
        for entry in manifest.entries.values() {
            for chunk in &entry.chunks {
                assert!(keep.contains(&chunk.sha256_hex()), "every chunk of every head kept");
            }
        }
    }

    world.shutdown().await;
}

#[tokio::test]
async fn device_head_chain_advances_and_forgeries_are_rejected() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("f.txt"), b"v1").expect("write");
    let s = tempfile::tempdir().expect("tempdir");
    let mut state = SyncState::open(s.path().join("s")).expect("state");
    let keypair = ciss::crypto::derive_keypair("flow-master", "frontier-pool");

    let r1 = backup_frontier(dir.path(), &server, &mut state, "dev-a").await.expect("b1");
    fs::write(dir.path().join("f.txt"), b"v2 changed").expect("write");
    let r2 = backup_frontier(dir.path(), &server, &mut state, "dev-a").await.expect("b2");
    assert!(r2.manifest_seq > r1.manifest_seq);

    // The per-device chain: counter advanced, parent links to the prior head.
    let frontier = server.frontier().await.expect("frontier").expect("exists");
    let head_bytes = server.get(&frontier.heads["dev-a"]).await.expect("head");
    let head =
        DeviceHead::decode_verified(&head_bytes, &keypair.verifying_key()).expect("verified");
    assert_eq!(head.counter, 2);
    assert_eq!(head.parent.as_deref(), Some(r1.device_head_cid.as_str()));

    // A forged head (signature over different content) is rejected on read.
    let mut forged = head.clone();
    forged.fs_root = "ff".repeat(32);
    let forged_bytes = forged.encode().expect("encode");
    assert!(
        DeviceHead::decode_verified(&forged_bytes, &keypair.verifying_key()).is_err(),
        "a tampered DeviceHead must not verify — even from a sibling device"
    );

    world.shutdown().await;
}
