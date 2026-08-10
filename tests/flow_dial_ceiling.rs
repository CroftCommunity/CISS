//! Workflow tier — D2: the at-rest cap dial (`dial.ceiling`). The customer
//! asserts their own storage limit; the provider's limits supersede
//! (over-bound dials are refused at set with the real bound quoted), the
//! effective cap is `min(provider bounds, dial)` at the existing quota
//! gate, reads are never touched (B6), and every accepted dial returns an
//! ack verifiable against the key published in `/.well-known/did.json`.

mod common;

use ciss::assertion::{verify_ack, Ack, SignedAssertion};
use ciss::crypto::{derive_keypair, public_key_from_hex};
use ciss::dials::{ceiling_body_fold, CeilingDialBody, CEILING_DIAL_KIND};
use ciss::identity::derive_id;
use ciss_cli::client::{session_for, Client};
use common::World;

fn dial(did: &str, seq: u64, at_rest: Option<u64>, kp: &ciss::crypto::Keypair) -> SignedAssertion {
    let body = CeilingDialBody { at_rest_bytes: at_rest, spend_cents: None };
    SignedAssertion::sign_owner(
        CEILING_DIAL_KIND,
        did,
        None,
        seq,
        serde_json::to_value(body).expect("json"),
        &ceiling_body_fold(&body),
        kp,
    )
}

/// The full at-rest dial story against a 10 kB store ceiling and no
/// provider per-DID cap: refuse-at-set above the bound, enforce min() at
/// the put gate, never touch reads, refuse rollback, clear restores the
/// provider-only bound.
#[tokio::test]
async fn at_rest_dial_binds_writes_never_reads() {
    let world = World::spawn_with_limits(10_000, None).await;
    let kp = derive_keypair("flow-master", "dialer");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // 1. Provider supersedes: a dial above min(store_ceiling, did_cap) is
    // refused at set, and the refusal quotes the real bound.
    let err = client
        .put_assertion(&did, CEILING_DIAL_KIND, None, &serde_json::to_vec(&dial(&did, 1, Some(20_000), &kp)).unwrap())
        .await
        .expect_err("a dial above the provider bound is refused at set");
    let msg = format!("{err:#}");
    assert!(msg.contains("400"), "refused as a bad assertion: {msg}");
    assert!(msg.contains("10000"), "the refusal quotes the provider bound: {msg}");

    // 2. A dial inside the bound is accepted, and the ack verifies against
    // the attest key published in the well-known document.
    let record = dial(&did, 1, Some(1_500), &kp);
    let (seq, ack_json) = client
        .put_assertion(&did, CEILING_DIAL_KIND, None, &serde_json::to_vec(&record).unwrap())
        .await
        .expect("in-bound dial accepted");
    assert_eq!(seq, 1);
    let ack: Ack = serde_json::from_value(ack_json).expect("ack json");
    let doc: serde_json::Value = reqwest::get(world.url("/.well-known/did.json"))
        .await
        .expect("well-known")
        .json()
        .await
        .expect("json");
    let key_hex = doc["verificationMethod"][0]["publicKeyHex"]
        .as_str()
        .expect("the attest key is published");
    let key = public_key_from_hex(key_hex).expect("valid key");
    assert!(verify_ack(&record, &ack, &key), "the ack verifies against the PUBLISHED key");

    // 3. The dial binds new stores at the quota gate: first kilobyte fits
    // under 1_500; a second new kilobyte would exceed it → refused 507.
    let blob1 = vec![1u8; 1_000];
    client.put_s3(&session, "a.bin", &blob1).await.expect("first store fits the dial");
    let blob2 = vec![2u8; 1_000];
    let err = client
        .put_s3(&session, "b.bin", &blob2)
        .await
        .expect_err("the customer's own cap refuses the second store");
    assert!(format!("{err:#}").contains("507"), "dial cap refuses like a quota: {err:#}");

    // 4. B6: reads are never gated by any cap — the stored blob serves.
    let cid1 = ciss::crypto::sha256_hex(&blob1);
    let got = client.get_s3(Some(&session), &did, &cid1).await.expect("read unaffected");
    assert_eq!(got.bytes, blob1);

    // 5. Rollback refused with the uniform typed staleness.
    let err = client
        .put_assertion(&did, CEILING_DIAL_KIND, None, &serde_json::to_vec(&dial(&did, 1, Some(2_000), &kp)).unwrap())
        .await
        .expect_err("a replayed seq is refused");
    assert!(format!("{err:#}").contains("409"), "stale dial is the typed 409: {err:#}");

    // 6. Clearing the dial (at_rest null, higher seq) restores the
    // provider-only bound: the second store now fits.
    client
        .put_assertion(&did, CEILING_DIAL_KIND, None, &serde_json::to_vec(&dial(&did, 2, None, &kp)).unwrap())
        .await
        .expect("clearing dial accepted");
    client.put_s3(&session, "b.bin", &blob2).await.expect("cleared dial no longer binds");

    world.shutdown().await;
}

/// The provider's per-DID cap supersedes independently: with did_cap=800,
/// a dial of 5_000 is refused at set (the bound is min(store, did_cap)),
/// and the provider cap binds even with no dial at all.
#[tokio::test]
async fn provider_did_cap_supersedes_the_dial() {
    let world = World::spawn_with_limits(10_000, Some(800)).await;
    let kp = derive_keypair("flow-master", "capped");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    let err = client
        .put_assertion(&did, CEILING_DIAL_KIND, None, &serde_json::to_vec(&dial(&did, 1, Some(5_000), &kp)).unwrap())
        .await
        .expect_err("cannot assert above the provider's per-DID cap");
    assert!(format!("{err:#}").contains("800"), "the bound quoted is the did_cap: {err:#}");

    let err = client
        .put_s3(&session, "big.bin", &vec![7u8; 900])
        .await
        .expect_err("the provider cap binds with no dial");
    assert!(format!("{err:#}").contains("507"), "provider cap refuses: {err:#}");

    world.shutdown().await;
}
