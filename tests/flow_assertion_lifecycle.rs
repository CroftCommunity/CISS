//! Workflow tier — the generic **DELETE** and **LIST** endpoints (ADR 0005 /
//! §5a, phase A2). Two operations the substrate offers *by declaration*: a kind
//! is deletable only if it declares `Erasable`, and listable only if it declares
//! `Listable`. The refusals are as load-bearing as the successes — a `Permanent`
//! kind refuses DELETE with its reason, a `PointOnly` kind refuses LIST, and both
//! endpoints are owner-only (the `du` discipline: self-only, never an existence
//! oracle).
//!
//! The vehicles: `kv.flag` (erasable, listable — the tenant service's removable
//! per-subkey state), `policy` (permanent — superseded by a new seq, never
//! deleted), and `dial.*` (point-only — addressed by its fixed kind, not listed).

mod common;

use ciss::assertion::SignedAssertion;
use ciss::crypto::derive_keypair;
use ciss::dials::{ceiling_body_fold, CeilingDialBody, CEILING_DIAL_KIND};
use ciss::identity::derive_id;
use ciss::kv::{flag_body_fold, FlagBody, FLAG_KIND};
use ciss::policy::{policy_body_fold, PolicyBody, ReadClass, POLICY_KIND};
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

const A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// Erasing an `Erasable` kind removes the row entirely: a later read 404s, and —
/// the pinned post-erase seq semantics — a re-write starts fresh at seq 1
/// (there is no residual high-water mark; erasure leaves nothing behind).
#[tokio::test]
async fn erasing_a_flag_removes_the_row_and_resets_the_seq() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "lifecycle-owner");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    // Advance the flag to seq 3, then confirm it is present.
    for seq in 1..=3 {
        client
            .put_assertion(&did, FLAG_KIND, Some(A), &serde_json::to_vec(&flag(&did, A, seq, true, &kp)).unwrap())
            .await
            .expect("flag set accepted");
    }
    assert!(
        client.get_assertion(Some(&session), &did, FLAG_KIND, Some(A)).await.expect("get").is_some(),
        "the flag is present before erase"
    );

    // The owner erases it: the row is gone.
    let status = client
        .delete_assertion(Some(&session), &did, FLAG_KIND, Some(A))
        .await
        .expect("delete runs");
    assert_eq!(status, 200, "an erasable kind is deleted for its owner");
    assert!(
        client.get_assertion(Some(&session), &did, FLAG_KIND, Some(A)).await.expect("get").is_none(),
        "the erased flag is absent"
    );

    // Post-erase: a re-write starts at seq 1 (no residual seq high-water mark).
    client
        .put_assertion(&did, FLAG_KIND, Some(A), &serde_json::to_vec(&flag(&did, A, 1, true, &kp)).unwrap())
        .await
        .expect("a re-write starts fresh at seq 1 after erase");
}

/// Erasure is owner-only, and a refused erasure changes nothing: an anonymous
/// caller is a 401, a non-owner a 403, and the row survives both.
#[tokio::test]
async fn erasure_is_owner_only_and_a_refusal_leaves_the_row() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "lifecycle-owner2");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let stranger = session_for(&derive_keypair("flow-master", "stranger"));
    let client = Client::new(world.url(""));

    client
        .put_assertion(&did, FLAG_KIND, Some(A), &serde_json::to_vec(&flag(&did, A, 1, true, &kp)).unwrap())
        .await
        .expect("flag set");

    assert_eq!(
        client.delete_assertion(None, &did, FLAG_KIND, Some(A)).await.expect("runs"),
        401,
        "an anonymous erase is unauthorized"
    );
    assert_eq!(
        client.delete_assertion(Some(&stranger), &did, FLAG_KIND, Some(A)).await.expect("runs"),
        403,
        "a non-owner erase is forbidden"
    );
    assert!(
        client.get_assertion(Some(&session), &did, FLAG_KIND, Some(A)).await.expect("get").is_some(),
        "a refused erase leaves the row untouched"
    );
}

/// A `Permanent` kind refuses DELETE by declaration, quoting the kind; the record
/// is unchanged. `policy` is superseded by a higher-seq write, never deleted.
#[tokio::test]
async fn deleting_a_permanent_kind_is_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "lifecycle-policy");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    let body = PolicyBody { read_class: ReadClass::Owner, readers: vec![] };
    let rec = SignedAssertion::sign_owner(
        POLICY_KIND,
        &did,
        None,
        1,
        serde_json::to_value(&body).expect("json"),
        &policy_body_fold(&body),
        &kp,
    );
    client
        .put_assertion(&did, POLICY_KIND, None, &serde_json::to_vec(&rec).unwrap())
        .await
        .expect("policy set");

    assert_eq!(
        client.delete_assertion(Some(&session), &did, POLICY_KIND, None).await.expect("runs"),
        405,
        "a permanent kind refuses DELETE"
    );
    assert!(
        client.get_assertion(Some(&session), &did, POLICY_KIND, None).await.expect("get").is_some(),
        "the policy is untouched by a refused DELETE"
    );
}

/// LIST returns an owner their subkeys for a `Listable` kind — and only theirs.
/// It is not an existence oracle: a non-owner is refused identically (403)
/// whether the target has keys or not, so the refusal reveals nothing.
#[tokio::test]
async fn listing_is_owner_only_and_not_an_existence_oracle() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "lifecycle-list");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let stranger = session_for(&derive_keypair("flow-master", "list-stranger"));
    let empty_did = derive_id(&derive_keypair("flow-master", "list-empty").verifying_key());
    let client = Client::new(world.url(""));

    for sk in [A, B] {
        client
            .put_assertion(&did, FLAG_KIND, Some(sk), &serde_json::to_vec(&flag(&did, sk, 1, true, &kp)).unwrap())
            .await
            .expect("flag set");
    }

    // The owner sees exactly their two subkeys.
    let (status, mut subkeys) = client.list_assertions(Some(&session), &did, FLAG_KIND).await.expect("list");
    assert_eq!(status, 200, "the owner may list a listable kind");
    subkeys.sort();
    assert_eq!(subkeys, vec![A.to_owned(), B.to_owned()], "exactly the owner's subkeys");

    // Anonymous → 401; a non-owner → 403 — and 403 for an *empty* did too, so the
    // refusal is not an oracle for whether keys exist.
    assert_eq!(client.list_assertions(None, &did, FLAG_KIND).await.expect("runs").0, 401);
    assert_eq!(client.list_assertions(Some(&stranger), &did, FLAG_KIND).await.expect("runs").0, 403);
    assert_eq!(
        client.list_assertions(Some(&stranger), &empty_did, FLAG_KIND).await.expect("runs").0,
        403,
        "a non-owner is refused identically whether or not the target has keys"
    );
}

/// A `PointOnly` kind refuses LIST by declaration: you address a dial by its
/// fixed kind, you do not enumerate.
#[tokio::test]
async fn listing_a_point_only_kind_is_refused() {
    let world = World::spawn().await;
    let kp = derive_keypair("flow-master", "lifecycle-dial");
    let did = derive_id(&kp.verifying_key());
    let session = session_for(&kp);
    let client = Client::new(world.url(""));

    let body = CeilingDialBody { at_rest_bytes: Some(1000), spend_cents: None };
    let rec = SignedAssertion::sign_owner(
        CEILING_DIAL_KIND,
        &did,
        None,
        1,
        serde_json::to_value(body).expect("json"),
        &ceiling_body_fold(&body),
        &kp,
    );
    client
        .put_assertion(&did, CEILING_DIAL_KIND, None, &serde_json::to_vec(&rec).unwrap())
        .await
        .expect("dial set");

    assert_eq!(
        client.list_assertions(Some(&session), &did, CEILING_DIAL_KIND).await.expect("runs").0,
        405,
        "a point-only kind refuses LIST"
    );
}
