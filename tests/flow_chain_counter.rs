//! Workflow tier — the `chain.counter` accounting chain (ADR 0005, phase A3).
//!
//! Every entry is a signed step `{delta, total, prev_entry_hash}`; the substrate
//! verifies at write time that the total follows its predecessor and that the
//! entry names the predecessor's hash. A latest-wins slot (`kv.counter`) let a
//! writer silently rewrite the total; a chain refuses a total that does not
//! follow and refuses a link to a forged head — and recomputation over the stored
//! entries re-derives the verified total, catching tampering after the fact.

mod common;

use ciss::assertion::SignedAssertion;
use ciss::chain_kind::{
    chain_counter_body_fold, entry_hash, ChainCounterBody, CHAIN_COUNTER_KIND, GENESIS_PREV_HASH,
};
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss_cli::client::{session_for, Client};
use common::World;

const ACCT: &str = "9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a";

fn entry(
    did: &str,
    subkey: &str,
    seq: u64,
    delta: i64,
    total: u64,
    prev_hash: &str,
    kp: &ciss::crypto::Keypair,
) -> (SignedAssertion, String) {
    let body = ChainCounterBody { delta, total, prev_entry_hash: prev_hash.to_owned() };
    let rec = SignedAssertion::sign_owner(
        CHAIN_COUNTER_KIND,
        did,
        Some(subkey),
        seq,
        serde_json::to_value(&body).expect("json"),
        &chain_counter_body_fold(&body),
        kp,
    );
    let hash = entry_hash(did, CHAIN_COUNTER_KIND, Some(subkey), seq, &body);
    (rec, hash)
}

async fn put(
    client: &Client,
    did: &str,
    rec: &SignedAssertion,
) -> Result<(u64, serde_json::Value), String> {
    client
        .put_assertion(did, CHAIN_COUNTER_KIND, Some(ACCT), &serde_json::to_vec(rec).unwrap())
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tokio::test]
async fn a_chain_appends_verifies_and_recomputes() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "chain-owner");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // Genesis (+100 → 100), then +150 → 250, then a -50 correction → 200.
    let (e1, h1) = entry(&did, ACCT, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("genesis accepted");
    let (e2, h2) = entry(&did, ACCT, 2, 150, 250, &h1, &kp);
    put(&client, &did, &e2).await.expect("successor accepted");
    let (e3, _h3) = entry(&did, ACCT, 3, -50, 200, &h2, &kp);
    put(&client, &did, &e3).await.expect("a signed negative correction is accepted");

    // A point read returns the latest total.
    let latest = client
        .get_assertion(Some(&session), &did, CHAIN_COUNTER_KIND, Some(ACCT))
        .await
        .expect("get")
        .expect("present");
    assert_eq!(latest["assertion"]["body"]["total"], serde_json::json!(200));

    // ?chain=1 returns the entries and the server-recomputed, verified total.
    let chain = client
        .get_chain(Some(&session), &did, CHAIN_COUNTER_KIND, ACCT)
        .await
        .expect("chain read");
    assert_eq!(chain["total"], serde_json::json!(200), "recompute equals the asserted total");
    assert_eq!(chain["entries"].as_array().map(Vec::len), Some(3), "all three entries returned");
}

#[tokio::test]
async fn a_total_that_does_not_follow_is_refused_quoting_the_real_total() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "chain-total");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    let (e1, h1) = entry(&did, ACCT, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("genesis");

    // delta 10 from total 100 must be 110; assert 999 instead.
    let (bad, _) = entry(&did, ACCT, 2, 10, 999, &h1, &kp);
    let msg = put(&client, &did, &bad).await.expect_err("a wrong total is refused");
    assert!(msg.contains("110"), "the refusal quotes the real total 110: {msg}");
    assert!(msg.contains("999"), "and the rejected total 999: {msg}");
}

#[tokio::test]
async fn a_link_to_a_forged_head_is_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "chain-link");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    let (e1, _h1) = entry(&did, ACCT, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("genesis");

    // Correct total, but the link points at a hash that is not the chain head.
    let forged = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef0";
    let (bad, _) = entry(&did, ACCT, 2, 50, 150, forged, &kp);
    assert!(put(&client, &did, &bad).await.is_err(), "a forged predecessor link is refused");
}

#[tokio::test]
async fn a_fork_at_an_existing_seq_is_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "chain-fork");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    let (e1, h1) = entry(&did, ACCT, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("genesis");
    let (e2, _h2) = entry(&did, ACCT, 2, 50, 150, &h1, &kp);
    put(&client, &did, &e2).await.expect("seq 2");

    // A second, different entry at seq 2 — a fork — is refused.
    let (fork, _) = entry(&did, ACCT, 2, 70, 170, &h1, &kp);
    assert!(put(&client, &did, &fork).await.is_err(), "a fork at an existing seq is refused");
}
