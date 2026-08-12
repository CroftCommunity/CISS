//! Workflow tier — checkpoints and compaction (ADR 0005, phase A4).
//!
//! A checkpoint is a signed chain entry `{closing_total, chain_head_hash,
//! prev_checkpoint}` the owner writes to close the books forward. It is verified
//! at write like any entry (its `closing_total` must equal the running total, its
//! `chain_head_hash` must link the entry it closes). Once acknowledged it lets the
//! entries behind it be compacted — deleted — so the chain stays bounded while its
//! aggregate survives. Compaction is a configured policy: automatic on ack here
//! (the default / starting case), or deferred to an explicit call (a billing
//! marker) in production. Compaction is refused where there is no acknowledged
//! checkpoint — no shredding before agreement.

mod common;

use ciss::assertion::SignedAssertion;
use ciss::chain_kind::{
    chain_counter_body_fold, checkpoint_body_fold, checkpoint_hash, entry_hash, ChainCounterBody,
    CheckpointBody, CHAIN_COUNTER_KIND, GENESIS_PREV_HASH,
};
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::server::CompactionPolicy;
use ciss_cli::client::{session_for, Client};
use common::World;

const ACCT: &str = "9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a";

fn step(did: &str, seq: u64, delta: i64, total: u64, prev: &str, kp: &ciss::crypto::Keypair) -> (SignedAssertion, String) {
    let body = ChainCounterBody { delta, total, prev_entry_hash: prev.to_owned() };
    let rec = SignedAssertion::sign_owner(
        CHAIN_COUNTER_KIND, did, Some(ACCT), seq,
        serde_json::to_value(&body).expect("json"), &chain_counter_body_fold(&body), kp,
    );
    (rec, entry_hash(did, CHAIN_COUNTER_KIND, Some(ACCT), seq, &body))
}

fn checkpoint(did: &str, seq: u64, closing: u64, head: &str, prev_ckpt: &str, kp: &ciss::crypto::Keypair) -> (SignedAssertion, String) {
    let body = CheckpointBody {
        closing_total: closing,
        chain_head_hash: head.to_owned(),
        prev_checkpoint: prev_ckpt.to_owned(),
    };
    let rec = SignedAssertion::sign_owner(
        CHAIN_COUNTER_KIND, did, Some(ACCT), seq,
        serde_json::to_value(&body).expect("json"), &checkpoint_body_fold(&body), kp,
    );
    (rec, checkpoint_hash(did, CHAIN_COUNTER_KIND, Some(ACCT), seq, &body))
}

async fn put(client: &Client, did: &str, rec: &SignedAssertion) -> Result<(u64, serde_json::Value), String> {
    client
        .put_assertion(did, CHAIN_COUNTER_KIND, Some(ACCT), &serde_json::to_vec(rec).unwrap())
        .await
        .map_err(|e| format!("{e:#}"))
}

/// The main story: build a chain, checkpoint it, and (default on-ack policy) watch
/// the entries behind the checkpoint disappear while the aggregate survives and the
/// chain keeps going and still recomputes.
#[tokio::test]
async fn a_checkpoint_compacts_the_history_and_the_chain_continues() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "ckpt-owner");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // +100, +50, +30 → running total 180 at e3 (seq 3).
    let (e1, h1) = step(&did, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("e1");
    let (e2, h2) = step(&did, 2, 50, 150, &h1, &kp);
    put(&client, &did, &e2).await.expect("e2");
    let (e3, h3) = step(&did, 3, 30, 180, &h2, &kp);
    put(&client, &did, &e3).await.expect("e3");

    // Checkpoint at seq 4 closing 180 over e3. Default policy compacts on ack.
    let (c1, hc1) = checkpoint(&did, 4, 180, &h3, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &c1).await.expect("checkpoint accepted");

    // The chain read now walks from the anchor: only the checkpoint remains, and
    // the recomputed total is the closing total.
    let chain = client.get_chain(Some(&session), &did, CHAIN_COUNTER_KIND, ACCT).await.expect("chain");
    assert_eq!(chain["entries"].as_array().map(Vec::len), Some(1), "e1..e3 compacted; only the checkpoint remains");
    assert_eq!(chain["total"], serde_json::json!(180), "the aggregate survives compaction");

    // The chain continues past the checkpoint: e4 links the checkpoint's hash.
    let (e4, _h4) = step(&did, 5, 20, 200, &hc1, &kp);
    put(&client, &did, &e4).await.expect("a step after the checkpoint links its hash");
    let chain = client.get_chain(Some(&session), &did, CHAIN_COUNTER_KIND, ACCT).await.expect("chain");
    assert_eq!(chain["total"], serde_json::json!(200), "recompute continues across the checkpoint boundary");
    assert_eq!(chain["entries"].as_array().map(Vec::len), Some(2), "storage stays bounded: checkpoint + one step");
}

/// A checkpoint whose `closing_total` does not equal the running total is refused,
/// quoting the real total.
#[tokio::test]
async fn a_checkpoint_that_misstates_the_total_is_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "ckpt-wrong");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    let (e1, h1) = step(&did, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("e1");

    // Running total is 100; the checkpoint claims 999.
    let (bad, _) = checkpoint(&did, 2, 999, &h1, GENESIS_PREV_HASH, &kp);
    let msg = put(&client, &did, &bad).await.expect_err("a mis-stated close is refused");
    assert!(msg.contains("999") && msg.contains("100"), "the refusal quotes both totals: {msg}");
}

/// A checkpoint that links a head hash not matching the entry it claims to close
/// is refused — the transitive commitment is the tamper guard.
#[tokio::test]
async fn a_checkpoint_with_a_forged_head_is_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "ckpt-forge");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    let (e1, _h1) = step(&did, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("e1");

    let forged = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef0";
    let (bad, _) = checkpoint(&did, 2, 100, forged, GENESIS_PREV_HASH, &kp);
    assert!(put(&client, &did, &bad).await.is_err(), "a checkpoint over a forged head is refused");
}

/// Compaction is refused when there is no acknowledged checkpoint to compact
/// behind — the no-shredding-before-agreement rule.
#[tokio::test]
async fn compaction_without_a_checkpoint_is_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "ckpt-noack");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    let (e1, _h1) = step(&did, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("e1");

    let status = client.compact_chain(Some(&session), &did, CHAIN_COUNTER_KIND, ACCT).await.expect("runs");
    assert_eq!(status, 409, "no checkpoint to compact behind: refused");
}

/// Under the `Deferred` policy a checkpoint write leaves the history intact; only
/// an explicit compaction call (the billing-marker path) shreds it.
#[tokio::test]
async fn deferred_policy_compacts_only_on_the_explicit_call() {
    let world = World::spawn_with_compaction(CompactionPolicy::Deferred).await;
    let kp = derive_keypair("flow-master", "ckpt-deferred");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    let (e1, h1) = step(&did, 1, 100, 100, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &e1).await.expect("e1");
    let (e2, h2) = step(&did, 2, 50, 150, &h1, &kp);
    put(&client, &did, &e2).await.expect("e2");
    let (c1, _hc1) = checkpoint(&did, 3, 150, &h2, GENESIS_PREV_HASH, &kp);
    put(&client, &did, &c1).await.expect("checkpoint");

    // Deferred: writing the checkpoint did NOT compact — all three entries remain.
    let before = client.get_chain(Some(&session), &did, CHAIN_COUNTER_KIND, ACCT).await.expect("chain");
    assert_eq!(before["entries"].as_array().map(Vec::len), Some(3), "deferred: history intact after checkpoint");
    assert_eq!(before["total"], serde_json::json!(150));

    // The explicit billing-marker call compacts behind the checkpoint.
    assert_eq!(
        client.compact_chain(Some(&session), &did, CHAIN_COUNTER_KIND, ACCT).await.expect("runs"),
        200
    );
    let after = client.get_chain(Some(&session), &did, CHAIN_COUNTER_KIND, ACCT).await.expect("chain");
    assert_eq!(after["entries"].as_array().map(Vec::len), Some(1), "only the checkpoint anchor remains");
    assert_eq!(after["total"], serde_json::json!(150), "the aggregate is unchanged by compaction");
}
