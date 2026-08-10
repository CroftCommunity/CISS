//! Workflow tier — the generic KV kinds (`kv.flag`, `kv.counter`) on the
//! self-assertion substrate.
//!
//! Why they exist: a tenant service (first consumer: croft-relay-admit, the
//! relay's admission authority, running against a private CISS instance —
//! see README "Downstream consumers") needs exactly two shapes of mutable,
//! restart-surviving state: a per-subkey boolean and a per-subkey counter.
//! The substrate already gives owner-signed writes, strictly-monotonic
//! `seq`, and acked reads; these kinds add the two smallest useful bodies
//! with **no consumer vocabulary** — any tenant can use a flag or a counter.
//!
//! Kinds remain code, not data: `kv.*` is registered like every other kind,
//! and an unregistered kind is still refused (asserted below as the control).

mod common;

use ciss::assertion::SignedAssertion;
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::kv::{counter_body_fold, flag_body_fold, CounterBody, FlagBody, COUNTER_KIND, FLAG_KIND};
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

fn counter(did: &str, subkey: &str, seq: u64, total: u64, kp: &ciss::crypto::Keypair) -> SignedAssertion {
    let body = CounterBody { total };
    SignedAssertion::sign_owner(
        COUNTER_KIND,
        did,
        Some(subkey),
        seq,
        serde_json::to_value(body).expect("json"),
        &counter_body_fold(&body),
        kp,
    )
}

/// A subkey shaped like the consumers' keys: 64 hex chars (a peppered digest).
const SUBKEY: &str = "9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a";

#[tokio::test]
async fn flags_and_counters_round_trip_with_monotonic_seq() {
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

    // Counter: write, bump with rising seq, read the latest.
    client
        .put_assertion(&did, COUNTER_KIND, Some(SUBKEY), &serde_json::to_vec(&counter(&did, SUBKEY, 1, 1000, &kp)).unwrap())
        .await
        .expect("counter accepted");
    client
        .put_assertion(&did, COUNTER_KIND, Some(SUBKEY), &serde_json::to_vec(&counter(&did, SUBKEY, 2, 1234, &kp)).unwrap())
        .await
        .expect("counter update accepted");
    let got = client
        .get_assertion(Some(&session), &did, COUNTER_KIND, Some(SUBKEY))
        .await
        .expect("get runs")
        .expect("counter present");
    assert_eq!(got["assertion"]["body"]["total"], serde_json::json!(1234));
    assert_eq!(got["assertion"]["seq"], serde_json::json!(2));

    // A stale/equal seq is refused — the substrate's monotonicity, on our kinds.
    let err = client
        .put_assertion(&did, COUNTER_KIND, Some(SUBKEY), &serde_json::to_vec(&counter(&did, SUBKEY, 2, 9, &kp)).unwrap())
        .await;
    assert!(err.is_err(), "equal seq must be refused");

    // Two subkeys are two independent slots.
    let other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let none = client
        .get_assertion(Some(&session), &did, COUNTER_KIND, Some(other))
        .await
        .expect("get runs");
    assert!(none.is_none(), "a different subkey is a different slot");
}

#[tokio::test]
async fn kv_kinds_validate_and_unknown_kinds_stay_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "kv-tenant2");
    let did = derive_id(&kp.verifying_key());
    let client = Client::new(world.url(""));

    // The kv kinds REQUIRE a subkey (a flag/counter with no key is nothing).
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
    assert!(err.is_err(), "kv kinds without a subkey are refused");

    // A malformed body is refused with a 400, not stored.
    let bad = SignedAssertion::sign_owner(
        COUNTER_KIND,
        &did,
        Some(SUBKEY),
        1,
        serde_json::json!({"total": "not-a-number"}),
        "bogus-fold",
        &kp,
    );
    let err = client
        .put_assertion(&did, COUNTER_KIND, Some(SUBKEY), &serde_json::to_vec(&bad).unwrap())
        .await;
    assert!(err.is_err(), "malformed counter body refused");

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
