//! Workflow tier — the generic `kv.flag` kind on the self-assertion substrate.
//!
//! Why it exists: a tenant service (first consumer: croft-relay-admit, the
//! relay's admission authority, running against a private CISS instance —
//! see README "Downstream consumers") needs a per-subkey boolean (its
//! membership roster). The substrate already gives owner-signed writes,
//! strictly-monotonic `seq`, and acked reads; the kind adds the smallest useful
//! body with **no consumer vocabulary** — any tenant can use a flag. (A sibling
//! `kv.counter` was superseded by `chain.counter` and removed in A5;
//! accounting is on the chain, see `flow_chain_counter.rs`.)
//!
//! Kinds remain code, not data: `kv.flag` is registered like every other kind,
//! and an unregistered kind is still refused (asserted below as the control).

mod common;

use ciss::assertion::SignedAssertion;
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::kv::{flag_body_fold, FlagBody, FLAG_KIND};
use ciss_cli::client::{session_for, Client};
use common::World;

fn flag(did: &str, subkey: &str, seq: u64, set: bool, kp: &ciss::crypto::Keypair) -> SignedAssertion {
    let body = FlagBody { set };
    SignedAssertion::sign_owner(
        FLAG_KIND,
        did,
        Some(subkey),
        seq,
        serde_json::to_value(body).expect("json"),
        &flag_body_fold(&body),
        kp,
    )
}

/// A subkey shaped like the consumers' keys: 64 hex chars (a peppered digest).
const SUBKEY: &str = "9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a";

#[tokio::test]
async fn flags_round_trip_and_advance_with_monotonic_seq() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "kv-tenant");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // Absent is 404/None, not an error.
    let absent = client
        .get_assertion(Some(&session), &did, FLAG_KIND, Some(SUBKEY))
        .await
        .expect("get runs");
    assert!(absent.is_none(), "an unset flag is absent");

    // Set the flag; read it back.
    client
        .put_assertion(&did, FLAG_KIND, Some(SUBKEY), &serde_json::to_vec(&flag(&did, SUBKEY, 1, true, &kp)).unwrap())
        .await
        .expect("flag set accepted");
    let got = client
        .get_assertion(Some(&session), &did, FLAG_KIND, Some(SUBKEY))
        .await
        .expect("get runs")
        .expect("flag present");
    assert_eq!(got["assertion"]["body"]["set"], serde_json::json!(true));
    assert!(got["ack"].is_object(), "accepted writes carry the provider ack");

    // Advance the flag with a rising seq; read the latest.
    client
        .put_assertion(&did, FLAG_KIND, Some(SUBKEY), &serde_json::to_vec(&flag(&did, SUBKEY, 2, false, &kp)).unwrap())
        .await
        .expect("flag update accepted");
    let got = client
        .get_assertion(Some(&session), &did, FLAG_KIND, Some(SUBKEY))
        .await
        .expect("get runs")
        .expect("flag present");
    assert_eq!(got["assertion"]["body"]["set"], serde_json::json!(false));
    assert_eq!(got["assertion"]["seq"], serde_json::json!(2));

    // A stale/equal seq is refused — the substrate's monotonicity, on our kind.
    let err = client
        .put_assertion(&did, FLAG_KIND, Some(SUBKEY), &serde_json::to_vec(&flag(&did, SUBKEY, 2, true, &kp)).unwrap())
        .await;
    assert!(err.is_err(), "equal seq must be refused");

    // Two subkeys are two independent slots.
    let other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let none = client
        .get_assertion(Some(&session), &did, FLAG_KIND, Some(other))
        .await
        .expect("get runs");
    assert!(none.is_none(), "a different subkey is a different slot");
}

#[tokio::test]
async fn kv_flag_validates_and_unknown_kinds_stay_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "kv-tenant2");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    // The kv.flag kind REQUIRES a subkey (a flag with no key is nothing).
    let bare = SignedAssertion::sign_owner(
        FLAG_KIND,
        &did,
        None,
        1,
        serde_json::json!({"set": true}),
        &flag_body_fold(&FlagBody { set: true }),
        &kp,
    );
    let err = client
        .put_assertion(&did, FLAG_KIND, None, &serde_json::to_vec(&bare).unwrap())
        .await;
    assert!(err.is_err(), "kv.flag without a subkey is refused");

    // A malformed body is refused with a 400, not stored.
    let bad = SignedAssertion::sign_owner(
        FLAG_KIND,
        &did,
        Some(SUBKEY),
        1,
        serde_json::json!({"set": "not-a-bool"}),
        "bogus-fold",
        &kp,
    );
    let err = client
        .put_assertion(&did, FLAG_KIND, Some(SUBKEY), &serde_json::to_vec(&bad).unwrap())
        .await;
    assert!(err.is_err(), "malformed flag body refused");

    // Control: an unregistered kind is still refused — kinds are code.
    let unknown = SignedAssertion::sign_owner(
        "kv.made-up",
        &did,
        Some(SUBKEY),
        1,
        serde_json::json!({}),
        "fold",
        &kp,
    );
    let err = client
        .put_assertion(&did, "kv.made-up", Some(SUBKEY), &serde_json::to_vec(&unknown).unwrap())
        .await;
    assert!(err.is_err(), "unregistered kinds stay refused");
}
