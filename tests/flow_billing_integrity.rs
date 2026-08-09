//! Workflow tier — billing-integrity guards (Phase 4). The manifest is the rent
//! base, so a forged or replayed manifest must be refused at the boundary.
//! Finding IDs refer to `docs/SECURITY-REVIEW-2026-08-03.md`.

mod common;

use common::World;

use ciss::crypto::{derive_keypair, sha256_hex};
use ciss::identity::derive_id;
use ciss::manifest::{build_manifest, Manifest, ManifestLeaf};

fn cid(tag: &str) -> String {
    sha256_hex(tag.as_bytes())
}

async fn put_manifest(world: &World, did: &str, pubkey_hex: &str, body: Vec<u8>) -> u16 {
    reqwest::Client::new()
        .put(world.url(&format!("/{did}/manifest")))
        .header("x-croft-pubkey", pubkey_hex)
        .body(body)
        .send()
        .await
        .expect("put manifest")
        .status()
        .as_u16()
}

/// I5 — a stale (replayed) manifest cannot roll the declared state backward.
#[tokio::test]
async fn a_replayed_older_manifest_is_refused() {
    let world = World::spawn().await;
    let customer = derive_keypair("bill", "c");
    let did = derive_id(&customer.verifying_key());
    let pk = customer.public_key_hex();

    let m1 = build_manifest(&[ManifestLeaf::new(&cid("a"), 100)], &did, &customer, 1);
    let m2 = build_manifest(
        &[
            ManifestLeaf::new(&cid("a"), 100),
            ManifestLeaf::new(&cid("b"), 200),
        ],
        &did,
        &customer,
        2,
    );

    let body = |m: &Manifest| serde_json::to_vec(m).expect("json");
    assert_eq!(put_manifest(&world, &did, &pk, body(&m1)).await, 200, "seq 1 accepted");
    assert_eq!(put_manifest(&world, &did, &pk, body(&m2)).await, 200, "seq 2 accepted");
    assert_eq!(
        put_manifest(&world, &did, &pk, body(&m1)).await,
        409,
        "replaying seq 1 over seq 2 is refused with the uniform typed staleness (D1.4)",
    );

    world.shutdown().await;
}

/// I1 — the declared byte total is bound by the signature: a forged `total_bytes`
/// cannot pass at the boundary.
#[tokio::test]
async fn a_forged_total_bytes_manifest_is_refused() {
    let world = World::spawn().await;
    let customer = derive_keypair("bill", "c");
    let did = derive_id(&customer.verifying_key());
    let pk = customer.public_key_hex();

    let honest = build_manifest(&[ManifestLeaf::new(&cid("a"), 1_000_000)], &did, &customer, 1);
    let mut forged: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&honest).expect("json")).expect("value");
    forged["total_bytes"] = serde_json::json!(1); // under-declare the rent base.

    assert_eq!(
        put_manifest(&world, &did, &pk, serde_json::to_vec(&forged).expect("json")).await,
        400,
        "a forged total_bytes breaks the signature and is refused",
    );

    world.shutdown().await;
}
