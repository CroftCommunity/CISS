//! Phase 2 wiring test (gated reads) — a policy record round-trips through a real
//! `Store`: an owner-signed policy is saved and then resolved back through the
//! public persistence API, with finest-grain-wins resolution and the world
//! default in place. Uses SQLite in-memory mode, so this exercises the REAL
//! persistence path (same code, file-backed in production) with no mocking.
//!
//! This is the wiring proof that `save_assertion` → `resolve_policy` is a live
//! call chain, not two components tested only in isolation (the policy kind on
//! the self-assertion substrate, dials plan D1).

use ciss::assertion::{make_ack, SignedAssertion};
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::persist::Store;
use ciss::policy::{policy_body_fold, PolicyBody, ReadClass, POLICY_KIND};

#[test]
fn saved_policy_resolves_back_through_a_real_store() {
    let owner = derive_keypair("ciss::wiring_policy", "owner");
    let did = derive_id(&owner.verifying_key());
    let alice = "did:plc:alice".to_owned();
    let cid = ciss::crypto::sha256_hex(b"a-blob");

    let store = Store::open_in_memory().expect("open in-memory store");

    // Before any policy: the world-readable default.
    let before = store
        .resolve_policy(&did, Some(&cid))
        .expect("resolve default");
    assert_eq!(before.read_class(), ReadClass::World);
    assert!(before.allows(None, &did), "anon reads world by default");

    // The owner grants alice at the namespace grain (a policy assertion).
    let body = PolicyBody { read_class: ReadClass::Grantees, readers: vec![alice.clone()] };
    let grant = SignedAssertion::sign_owner(
        POLICY_KIND,
        &did,
        None,
        1,
        serde_json::to_value(&body).expect("json"),
        &policy_body_fold(&body),
        &owner,
    );
    let ack = make_ack(&grant, &derive_keypair("ciss::wiring_policy", "attest")).expect("ack");
    store.save_assertion(&grant, &ack).expect("save namespace grant");

    // Resolve pulls the saved policy back, and membership reflects it.
    let resolved = store
        .resolve_policy(&did, Some(&cid))
        .expect("resolve grant");
    assert_eq!(resolved.read_class(), ReadClass::Grantees);
    assert!(
        resolved.allows(Some(&alice), &did),
        "granted reader may read"
    );
    assert!(resolved.allows(Some(&did), &did), "owner always reads");
    assert!(
        !resolved.allows(Some("did:plc:bob"), &did),
        "unlisted denied"
    );
    assert!(!resolved.allows(None, &did), "anon denied under a grant");
}
