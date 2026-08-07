//! Workflow tier — M5 P1: `price_backup` quotes a sync **before** any byte
//! moves, in the server's own tariff (`ciss::pricing::postage_cents`,
//! linked — the twin cannot drift). Pricing is free and side-effect free;
//! the quote equals what the backup then actually transfers; a re-price
//! after backup is 0¢ because dedup is priced in.

mod common;

use std::fs;

use ciss_cli::client::{self, Client};
use ciss_cli::sync::HttpCiss;
use ciss_sync::{backup, price_backup};
use common::World;

fn syncer(world: &World) -> HttpCiss {
    let keypair = ciss::crypto::derive_keypair("flow-master", "pricer");
    HttpCiss::new(Client::new(world.url("")), keypair)
}

#[tokio::test]
async fn quote_moves_nothing_and_matches_the_backup() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("small.txt"), b"price me").expect("write");
    let big: Vec<u8> = (0..2 * 1024 * 1024 + 321).map(|i| (i % 251) as u8).collect();
    fs::write(dir.path().join("big.bin"), big).expect("write");

    // The quote: bytes > 0, cents = the server's own floor tariff.
    let quote = price_backup(dir.path(), &server, None).await.expect("price");
    assert_eq!(quote.files, 2);
    assert!(quote.chunks_to_upload >= 3, "the 2 MiB file chunks");
    assert_eq!(quote.chunks_skipped, 0, "cold server: nothing to skip");
    assert!(quote.bytes > 2 * 1024 * 1024, "quote covers the tree + manifest");
    assert_eq!(
        quote.postage_cents,
        ciss::pricing::postage_cents(quote.bytes),
        "the twin IS the server's tariff"
    );
    assert!(quote.postage_cents >= 2097, "2 MiB+ is at least 2097¢ at 1¢/KB");

    // Pricing moved nothing: no blobs, no keep-set.
    let keypair = ciss::crypto::derive_keypair("flow-master", "pricer");
    let session = client::session_for(&keypair);
    let du = server.client().du(Some(&session), &session.did).await.expect("du");
    assert_eq!(du.objects.len(), 0, "a quote uploads no blobs");
    assert!(
        server.client().get_manifest(&session.did).await.expect("get").is_none(),
        "a quote commits no keep-set"
    );

    // The backup then transfers exactly what was quoted.
    let report = backup(dir.path(), &server, None).await.expect("backup");
    assert_eq!(report.bytes_uploaded, quote.bytes, "quote == actual transfer");
    assert_eq!(report.chunks_uploaded, quote.chunks_to_upload);

    // Re-price: dedup is priced in — an unchanged tree costs zero.
    let again = price_backup(dir.path(), &server, None).await.expect("re-price");
    assert_eq!(again.bytes, 0);
    assert_eq!(again.postage_cents, 0);
    assert_eq!(again.chunks_skipped, quote.chunks_to_upload, "everything already held");

    world.shutdown().await;
}

/// The floor edge is the tariff's own: 999 bytes quotes 0¢, 1000 quotes 1¢
/// (the manifest blob rides in the byte total, so pin via the tariff fn on
/// the quote's own byte count rather than hand-picked file sizes).
#[tokio::test]
async fn tiny_trees_price_at_the_floor() {
    let world = World::spawn().await;
    let server = syncer(&world);
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("tiny.txt"), b"x").expect("write");

    let quote = price_backup(dir.path(), &server, None).await.expect("price");
    assert!(quote.bytes < 1000, "one byte of content + a small manifest");
    assert_eq!(quote.postage_cents, 0, "below the 1000-byte floor: free");

    world.shutdown().await;
}
