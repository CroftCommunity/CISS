//! Workflow tier — the **body ceiling** every kind declares (ADR 0005, the
//! sizing axis; ARCHITECTURE §5a).
//!
//! Nothing CISS stores is assumed infinite. Each kind declares a body-byte
//! ceiling, and a body above it is refused at the write boundary with the
//! limit quoted — the ceiling-dial refusal pattern, generalized to every
//! kind. The ceiling is an *independent* bound: `policy` already caps its
//! reader set by count (`MAX_READERS`), but a reader set of long DIDs can be
//! valid by count and still oversized by bytes. This suite proves the byte
//! ceiling binds where the count guard does not, and that a legitimately
//! sized body is untouched.
//!
//! `policy` is the vehicle because it is the one assertion kind with a
//! variable-length body (its reader list); the fixed-shape kinds (dials,
//! `kv.*`) declare a small ceiling their bodies never approach.

mod common;

use ciss::assertion::SignedAssertion;
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::policy::{policy_body_fold, PolicyBody, ReadClass, POLICY_KIND};
use ciss_cli::client::Client;
use common::World;

/// A unique, valid 256-char DID (`did:web:` + 248 chars). Long DIDs are how a
/// reader set stays under `MAX_READERS` by count while overrunning the byte
/// ceiling.
fn long_did(i: usize) -> String {
    format!("did:web:{:0>248}", format!("r{i}"))
}

fn policy(did: &str, seq: u64, readers: Vec<String>, kp: &ciss::crypto::Keypair) -> SignedAssertion {
    let body = PolicyBody { read_class: ReadClass::Grantees, readers };
    SignedAssertion::sign_owner(
        POLICY_KIND,
        did,
        None,
        seq,
        serde_json::to_value(&body).expect("json"),
        &policy_body_fold(&body),
        kp,
    )
}

#[tokio::test]
async fn an_over_ceiling_body_is_refused_and_an_ordinary_one_is_kept() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "ceiling-tenant");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    // A grantees policy with 400 long readers: valid by count (< MAX_READERS)
    // and by DID shape, but its serialized body is ~100 KiB — well past the
    // policy body ceiling. Refused at the boundary.
    let big: Vec<String> = (0..400).map(long_did).collect();
    let over = policy(&did, 1, big, &kp);
    let body = serde_json::to_vec(&over).expect("json");
    assert!(
        serde_json::to_vec(&over.body).expect("json").len() > 64 * 1024,
        "the test body must actually exceed the ceiling it is probing"
    );
    let err = client
        .put_assertion(&did, POLICY_KIND, None, &body)
        .await;
    assert!(err.is_err(), "a body past the declared ceiling must be refused");

    // An ordinary policy (a handful of readers) is nowhere near the ceiling
    // and is stored — the ceiling never touches legitimate bodies.
    let ok = policy(&did, 1, vec![long_did(0), long_did(1), long_did(2)], &kp);
    client
        .put_assertion(&did, POLICY_KIND, None, &serde_json::to_vec(&ok).expect("json"))
        .await
        .expect("an ordinary policy is accepted");
}
