//! Workflow tier — the M4 P1 capability gate: a restore through `PeerFirst`
//! pulls its chunks from a peer device and only touches the metered origin
//! for what the peer cannot serve. The tree is byte-identical either way —
//! the peer changes *where bytes come from*, never *what bytes are*.

mod common;

use std::collections::HashSet;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use ciss_cli::client::{self, Client};
use ciss_cli::sync::HttpCiss;
use ciss_iroh::{IrohPeer, PeerFirst};
use ciss_sync::{backup, restore, BlobTransport, DagCbor, ManifestCodec, ManifestSlot, SyncError};
use common::World;

fn syncer(world: &World) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", "peer-fetcher");
    HttpCiss::new(Client::new(world.url("")), keypair)
}

/// Counts blob gets served by the origin — the metered egress we are saving.
struct Metered<'a> {
    inner: &'a HttpCiss,
    gets: AtomicU64,
}

#[async_trait::async_trait]
impl BlobTransport for Metered<'_> {
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

#[async_trait::async_trait]
impl ManifestSlot for Metered<'_> {
    async fn current_seq(&self) -> Result<Option<u64>, SyncError> {
        self.inner.current_seq().await
    }
    async fn keep_set(&self) -> Result<Option<Vec<(String, u64)>>, SyncError> {
        self.inner.keep_set().await
    }
    async fn frontier(&self) -> Result<Option<ciss_sync::FrontierView>, SyncError> {
        self.inner.frontier().await
    }
    async fn commit_keep_set(&self, leaves: &[(String, u64)], seq: u64) -> Result<(), SyncError> {
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

impl ciss_sync::AccountKey for Metered<'_> {
    fn keypair(&self) -> &ciss::crypto::Keypair {
        self.inner.keypair()
    }
}

/// Backup to CISS, seed a peer device with the chunks, restore via
/// `PeerFirst`: the tree comes back byte-identical and every chunk is
/// peer-served — the origin's blob egress is only the fs-manifest.
#[tokio::test]
async fn restore_pulls_chunks_from_peer_not_origin() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let src = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(src.path().join("sub")).expect("mkdir");
    fs::write(src.path().join("small.txt"), b"peer-fetch me").expect("write");
    let big: Vec<u8> = (0..2 * 1024 * 1024 + 555).map(|i| (i % 239) as u8).collect();
    fs::write(src.path().join("sub/big.bin"), big).expect("write");

    let b = backup(src.path(), &server, None).await.expect("backup");

    // Seed the "other device": it holds every chunk (it has the same tree),
    // and the restoring device learns the mappings — in P2 gossip carries
    // them; here the flow test plays that messenger.
    let keypair = ciss::crypto::derive_keypair("flow-master", "peer-fetcher");
    let session = client::session_for(&keypair);
    let manifest_bytes = server
        .client()
        .get_s3(Some(&session), &session.did, &b.fs_manifest_cid)
        .await
        .expect("fs-manifest")
        .bytes;
    let decoded = DagCbor.decode(&manifest_bytes).expect("decode");

    let provider = IrohPeer::spawn(None).await.expect("spawn provider");
    let local = IrohPeer::spawn(None).await.expect("spawn local");
    let mut chunk_cids = HashSet::new();
    for entry in decoded.entries.values() {
        for chunk in &entry.chunks {
            let cid = chunk.sha256_hex();
            if chunk_cids.insert(cid.clone()) {
                let bytes = server.get(&cid).await.expect("chunk from origin (seeding)");
                provider.put(&cid, &bytes).await.expect("seed provider");
                local.learn(&cid, chunk.blake3.0, &provider.addr()).expect("learn");
            }
        }
    }

    // The restore: chunks via the peer, everything else via the origin.
    let metered = Metered { inner: &server, gets: AtomicU64::new(0) };
    let t = PeerFirst { peer: &local, origin: &metered };
    let dst = tempfile::tempdir().expect("tempdir");
    let r = restore(dst.path(), &t, Some(&b.fs_manifest_cid)).await.expect("restore");
    assert_eq!(r.fs_manifest_cid, b.fs_manifest_cid);

    for (path, entry) in &decoded.entries {
        let restored = fs::read(dst.path().join(path)).expect("read restored");
        assert_eq!(restored.len() as u64, entry.size, "{path}: size matches");
    }
    assert_eq!(
        fs::read(dst.path().join("sub/big.bin")).expect("read"),
        fs::read(src.path().join("sub/big.bin")).expect("read"),
        "the big file is byte-identical through the peer path"
    );

    let origin_gets = metered.gets.load(Ordering::SeqCst);
    assert_eq!(
        origin_gets, 1,
        "only the fs-manifest comes from the origin — every chunk is peer-served \
         (origin served {origin_gets} blob gets for {} chunks)",
        chunk_cids.len()
    );

    provider.shutdown().await;
    local.shutdown().await;
    world.shutdown().await;
}
