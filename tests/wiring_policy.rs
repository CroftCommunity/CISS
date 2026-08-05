//! Phase 2 wiring test (gated reads) — a policy record round-trips through a real
//! `Store`: an owner-signed policy is saved and then resolved back through the
//! public persistence API, with finest-grain-wins resolution and the world
//! default in place. Uses SQLite in-memory mode, so this exercises the REAL
//! persistence path (same code, file-backed in production) with no mocking.
//!
//! This is the wiring proof that `save_policy` → `resolve_policy` is a live call
//! chain, not two components tested only in isolation.

use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::persist::Store;
use ciss::policy::{PolicyRecord, ReadClass};

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

    // The owner grants alice at the namespace grain.
    let grant = PolicyRecord::sign_owner(
        &did,
        None,
        ReadClass::Grantees,
        std::slice::from_ref(&alice),
        1,
        &owner,
    );
    store.save_policy(&grant).expect("save namespace grant");

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
