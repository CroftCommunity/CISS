//! Workflow tier — D4: the receipt-mode dial + bilateral receipts. The
//! customer asserts `bilateral` (a seq'd dial, so the provider cannot
//! silently revert it); every metered transfer then produces a receipt the
//! customer **countersigns** — the period total becomes a sum of
//! doubly-signed facts neither side can dispute. The `501` seam is gone
//! from the metered path; both verification keys (receipts + acks) are
//! published in the well-known document, so the whole proof chain
//! verifies offline.

mod common;

use std::collections::BTreeMap;

use ciss::assertion::SignedAssertion;
use ciss::crypto::{derive_keypair, public_key_from_hex};
use ciss::dials::{
    receipt_mode_body_fold, ReceiptModeBody, ReceiptModeChoice, RECEIPT_MODE_DIAL_KIND,
};
use ciss::identity::derive_id;
use ciss::receipts::Receipt;
use ciss_cli::client::{session_for, Client};
use common::World;

fn mode_dial(
    did: &str,
    seq: u64,
    mode: ReceiptModeChoice,
    kp: &ciss::crypto::Keypair,
) -> Vec<u8> {
    let body = ReceiptModeBody { mode };
    serde_json::to_vec(&SignedAssertion::sign_owner(
        RECEIPT_MODE_DIAL_KIND,
        did,
        None,
        seq,
        serde_json::to_value(body).expect("json"),
        &receipt_mode_body_fold(&body),
        kp,
    ))
    .expect("serialize")
}

/// The bilateral loop end-to-end: dial on → upload yields a bilateral
/// receipt hash → the customer countersigns → the completed receipt
/// verifies under BOTH published keys; a forged countersign is refused;
/// an unknown hash 404s; dialing back to unilateral restores the default.
#[tokio::test]
async fn bilateral_receipts_become_doubly_signed_facts() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "cosigner");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // Opt in: bilateral receipts by customer assertion.
    client
        .put_assertion(
            &did,
            RECEIPT_MODE_DIAL_KIND,
            None,
            &mode_dial(&did, 1, ReceiptModeChoice::Bilateral, &kp),
        )
        .await
        .expect("bilateral asserted");

    // A metered upload now yields a bilateral (provider-signed, pending
    // countersign) receipt — no 501 anywhere.
    let put = client.put_s3(&session, "x.bin", &vec![4u8; 1_000]).await.expect("upload serves");
    let receipt_hash = put.receipt_hash.clone().expect("bilateral response carries the receipt hash");
    assert_eq!(put.receipt_mode, "bilateral");

    // The customer countersigns: sig over the receipt's content hash, under
    // the key that derives the DID.
    let sig = kp.sign_message(&receipt_hash);
    let completed = client
        .countersign_receipt(&session, &did, &receipt_hash, &sig)
        .await
        .expect("countersign accepted");
    let receipt: Receipt = serde_json::from_value(completed).expect("completed receipt json");
    assert_eq!(receipt.sigs().len(), 2, "both parties have signed");

    // The doubly-signed fact verifies offline: both keys come from the
    // well-known document (receipts key + the customer's own key).
    let doc: serde_json::Value = reqwest::get(world.url("/.well-known/did.json"))
        .await
        .expect("well-known")
        .json()
        .await
        .expect("json");
    let receipt_key_hex = doc["verificationMethod"]
        .as_array()
        .expect("vm list")
        .iter()
        .find(|m| m["id"].as_str().is_some_and(|i| i.ends_with("#receipts")))
        .and_then(|m| m["publicKeyHex"].as_str())
        .expect("the receipt key is published");
    let mut keyring = BTreeMap::new();
    let provider_id = receipt
        .sigs()
        .keys()
        .find(|k| *k != &did)
        .expect("the provider party")
        .clone();
    keyring.insert(provider_id, public_key_from_hex(receipt_key_hex).expect("key"));
    keyring.insert(did.clone(), kp.verifying_key());
    assert!(
        receipt.verify_bilateral(&keyring),
        "the completed receipt verifies under both PUBLISHED-or-owned keys"
    );

    // A forged countersign (a stranger's signature) is refused.
    let stranger = derive_keypair("flow-master", "forger");
    let bad_sig = stranger.sign_message(&receipt_hash);
    let err = client
        .countersign_receipt(&session, &did, &receipt_hash, &bad_sig)
        .await
        .expect_err("a forged countersign is refused");
    assert!(format!("{err:#}").contains("403"), "forgery is 403: {err:#}");

    // An unknown receipt hash 404s.
    let err = client
        .countersign_receipt(&session, &did, &"0".repeat(64), &kp.sign_message(&"0".repeat(64)))
        .await
        .expect_err("unknown receipt");
    assert!(format!("{err:#}").contains("404"), "unknown hash is 404: {err:#}");

    // Dial back to unilateral (seq'd — the provider could never do this
    // silently): uploads return to the default.
    client
        .put_assertion(
            &did,
            RECEIPT_MODE_DIAL_KIND,
            None,
            &mode_dial(&did, 2, ReceiptModeChoice::Unilateral, &kp),
        )
        .await
        .expect("back to unilateral");
    let put = client.put_s3(&session, "y.bin", &vec![5u8; 500]).await.expect("upload");
    assert_eq!(put.receipt_mode, "unilateral");

    world.shutdown().await;
}
