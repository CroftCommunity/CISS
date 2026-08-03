//! Phase 6 wiring test — ports E8 (the tombstone, permanent tier) from the
//! oracle (`src/exp/e8_tombstone.ts`): repeat the seal ceremony, then destroy the
//! customer's rotation capability as well and prove the unseal path now fails
//! closed. Audits still verify against the pinned root; every write and unseal
//! path from both actors fails — the collection is frozen for all parties,
//! including the co-op. The tombstone tier is a feature.

use ciss::audit::audit_sample;
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::item::{ContentStore, Item};
use ciss::manifest::ManifestLeaf;
use ciss::rng::Rng;
use ciss::seal::{CollectionWriter, SealError, UnsealAuthority};

const MASTER: &str = "ciss::e8::seed";
const COLLECTION: &str = "ada-family-vault";

fn build_corpus() -> (Vec<ManifestLeaf>, ContentStore) {
    let mut store = ContentStore::new();
    let mut leaves = Vec::new();
    for i in 0..8_u8 {
        let item = Item::from_bytes(&format!("f-{i}"), vec![i; 64 + usize::from(i)]);
        leaves.push(ManifestLeaf::new(item.cid(), item.size()));
        store.put(&item);
    }
    (leaves, store)
}

#[test]
fn the_tombstone_freezes_all_paths_yet_audits_still_verify() {
    let customer = derive_keypair(MASTER, "customer");
    let customer_id = derive_id(&customer.verifying_key());
    let (leaves, mut store) = build_corpus();

    // Seal ceremony: destroy the provider write credential.
    let mut writer = CollectionWriter::new(derive_keypair(MASTER, "provider/write-cred"));
    writer.destroy_credential();

    // Tombstone ceremony: destroy the customer's unseal capability too. Prove it
    // by showing the unseal function fails closed after destruction.
    let mut unseal = UnsealAuthority::new(&customer_id, derive_keypair(MASTER, "customer"));
    assert!(
        unseal.rotate(COLLECTION, "a-new-root", 10).is_some(),
        "unseal works before the tombstone ceremony",
    );
    unseal.destroy();
    assert!(unseal.is_destroyed());
    assert!(
        unseal.rotate(COLLECTION, "deadbeef", 20).is_none(),
        "unseal fails closed after the tombstone",
    );

    // Audits still verify against the pinned root across further periods.
    let mut rng = Rng::new("e8/audits");
    for p in 0..3 {
        let out = audit_sample(&leaves, &store, &mut rng, leaves.len());
        assert!(out.passed, "tombstone period {p} audits still verify");
    }

    // Every write and unseal path from both actors fails — frozen for all.
    let frozen_write = writer.write(&mut store, &Item::from_bytes("x", b"x".to_vec()));
    assert!(
        matches!(frozen_write, Err(SealError::Sealed)),
        "provider write fails (no credential)"
    );
    assert!(
        unseal.rotate(COLLECTION, "beef", 30).is_none(),
        "customer unseal fails (capability destroyed)",
    );
    assert!(
        !writer.has_credential() && unseal.is_destroyed(),
        "the collection is frozen for all parties",
    );
}
