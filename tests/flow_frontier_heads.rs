//! Workflow tier — the M3 server change: the additive owner-signed
//! `Manifest.heads` map over the wire, still governed by I5. The server
//! validates the signature and seq and stores bytes; it never interprets a
//! head. A second reader sees both devices' heads; a stale-seq commit cannot
//! alter them.

mod common;

use std::collections::BTreeMap;

use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::manifest::{build_manifest_with_heads, Manifest, ManifestLeaf};
use common::World;

async fn put_manifest(world: &World, did: &str, pubkey_hex: &str, manifest: &Manifest) -> u16 {
    reqwest::Client::new()
        .put(world.url(&format!("/{did}/manifest")))
        .header("x-croft-pubkey", pubkey_hex)
        .body(serde_json::to_vec(manifest).expect("json"))
        .send()
        .await
        .expect("send")
        .status()
        .as_u16()
}

async fn get_manifest_json(world: &World, did: &str) -> serde_json::Value {
    let body = reqwest::Client::new()
        .get(world.url(&format!("/{did}/manifest")))
        .send()
        .await
        .expect("send")
        .text()
        .await
        .expect("body");
    serde_json::from_str(&body).expect("manifest json")
}

fn heads(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(d, c)| ((*d).to_owned(), (*c).to_owned())).collect()
}

#[tokio::test]
async fn heads_round_trip_and_i5_protects_them() {
    let world = World::spawn().await;
    let customer = derive_keypair("flow-master", "frontier-owner");
    let did = derive_id(&customer.verifying_key());
    let pk = customer.public_key_hex();
    let leaf = ManifestLeaf::new(&"ab".repeat(32), 64);
    let cid_a = "11".repeat(32);
    let cid_b = "22".repeat(32);

    // Device A commits seq 1 with its own head.
    let m1 = build_manifest_with_heads(
        std::slice::from_ref(&leaf),
        &did,
        &customer,
        1,
        &heads(&[("dev-a", &cid_a)]),
    );
    assert_eq!(put_manifest(&world, &did, &pk, &m1).await, 200, "seq 1 with heads accepted");

    // Device B reads the frontier, re-applies its own slot, commits seq 2.
    let fetched = get_manifest_json(&world, &did).await;
    assert_eq!(fetched["heads"]["dev-a"], cid_a, "a second device reads A's head");
    let m2 = build_manifest_with_heads(
        std::slice::from_ref(&leaf),
        &did,
        &customer,
        2,
        &heads(&[("dev-a", &cid_a), ("dev-b", &cid_b)]),
    );
    assert_eq!(put_manifest(&world, &did, &pk, &m2).await, 200, "seq 2 with both heads accepted");

    // A stale/equal-seq commit with different heads is refused (I5), and the
    // stored heads are untouched — a lagging device cannot roll back a head.
    let rollback = build_manifest_with_heads(
        std::slice::from_ref(&leaf),
        &did,
        &customer,
        2,
        &heads(&[("dev-a", &cid_a)]),
    );
    let status = put_manifest(&world, &did, &pk, &rollback).await;
    assert!((400..500).contains(&status), "stale seq refused (got {status})");
    let after = get_manifest_json(&world, &did).await;
    assert_eq!(after["seq"], 2);
    assert_eq!(after["heads"]["dev-a"], cid_a);
    assert_eq!(after["heads"]["dev-b"], cid_b, "both heads survive the stale attempt");

    // A manifest whose heads were tampered after signing is refused outright.
    let mut forged: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&m2).expect("json")).expect("value");
    forged["seq"] = serde_json::json!(3);
    let forged: Manifest = serde_json::from_value(forged).expect("manifest");
    let status = put_manifest(&world, &did, &pk, &forged).await;
    assert!((400..500).contains(&status), "seq not covered by the old signature (got {status})");

    world.shutdown().await;
}
