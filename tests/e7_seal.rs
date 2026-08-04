//! Phase 6 wiring test — ports E7 (the seal, revocable tier) from the oracle
//! (`src/seal.ts` + `src/exp/e7_seal.ts`): the customer pins a root and signs a
//! seal; the provider destroys its write credential so the write path fails
//! closed; a rotation watch classifies root changes. Adversarial: a normal write
//! fails for lack of key; a compromised path that mutates bytes directly is
//! caught by an audit against the pinned root; a customer-signed unseal is
//! classified customer-initiated and a forged one alarms.

use ciss::audit::audit_sample;
use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::item::{ContentStore, Item};
use ciss::manifest::{build_manifest, ManifestLeaf};
use ciss::rng::Rng;
use ciss::seal::{
    sign_seal, CollectionWriter, RootAnnouncement, RotationWatch, SealError, UnsealAuthority,
};

const MASTER: &str = "ciss::e7::seed";
const COLLECTION: &str = "ada-family-vault";

/// A fixed corpus + its manifest leaves + the stored items (for restore).
fn build_corpus() -> (Vec<ManifestLeaf>, ContentStore, Vec<Item>) {
    let mut store = ContentStore::new();
    let mut leaves = Vec::new();
    let mut items = Vec::new();
    for i in 0..8_u8 {
        let item = Item::from_bytes(&format!("f-{i}"), vec![i; 64 + usize::from(i)]);
        leaves.push(ManifestLeaf::new(item.cid(), item.size()));
        store.put(&item);
        items.push(item);
    }
    (leaves, store, items)
}

#[test]
fn sealing_pins_the_root_and_makes_the_write_path_fail_closed() {
    let customer = derive_keypair(MASTER, "customer");
    let customer_id = derive_id(&customer.verifying_key());
    let (leaves, mut store, _items) = build_corpus();
    let manifest = build_manifest(&leaves, &customer_id, &customer, 1);
    let pinned = manifest.root().to_owned();

    // Ada signs the seal; it verifies under her key, and not under another's.
    let seal = sign_seal(COLLECTION, &pinned, 0, &customer_id, &customer);
    assert!(
        seal.verify(&customer.verifying_key()),
        "seal verifies under the signer"
    );
    let other = derive_keypair(MASTER, "other");
    assert!(
        !seal.verify(&other.verifying_key()),
        "seal is bound to the signer"
    );

    // The write path is live before the ceremony and fails closed after it.
    let mut writer = CollectionWriter::new(derive_keypair(MASTER, "provider/write-cred"));
    assert!(writer.has_credential());
    writer
        .write(&mut store, &Item::from_bytes("pre-seal", b"ok".to_vec()))
        .expect("write works before the ceremony");

    writer.destroy_credential();
    assert!(!writer.has_credential());
    let denied = writer.write(&mut store, &Item::from_bytes("smuggled", b"late".to_vec()));
    assert!(
        matches!(denied, Err(SealError::Sealed)),
        "write fails closed after the seal ceremony",
    );
}

#[test]
fn sealed_audits_pass_and_a_direct_mutation_is_caught_against_the_pinned_root() {
    let customer = derive_keypair(MASTER, "customer");
    let customer_id = derive_id(&customer.verifying_key());
    let (leaves, mut store, items) = build_corpus();
    // Pin the root (the manifest the audits verify against).
    let _pinned = build_manifest(&leaves, &customer_id, &customer, 1);

    // Honest sealed periods: every scheduled audit passes.
    let mut rng = Rng::new("e7/sealed-audits");
    for p in 0..3 {
        for a in 0..4 {
            let out = audit_sample(&leaves, &store, &mut rng, 3);
            assert!(
                out.passed,
                "sealed period {p} audit {a} passes against the pinned root"
            );
        }
    }

    // A compromised path mutates stored bytes directly (no new signature) — the
    // dumb Layer-1 overwrite. The next full audit catches it and names the item.
    let victim = leaves[0].cid().to_owned();
    store.write(&victim, b"corrupted-at-rest");
    let full = audit_sample(&leaves, &store, &mut rng, leaves.len());
    assert!(!full.passed, "direct byte mutation is caught");
    assert!(
        full.failures.contains(&victim),
        "the audit names the tampered item"
    );

    // The co-op re-fetches good bytes from Ada; audits pass again.
    let good = items
        .iter()
        .find(|i| i.cid() == victim)
        .expect("victim is in the corpus");
    store.put(good);
    let after = audit_sample(&leaves, &store, &mut rng, leaves.len());
    assert!(
        after.passed,
        "audit passes again once good bytes are restored"
    );
}

#[test]
fn the_rotation_watch_classifies_customer_signed_vs_forged() {
    let customer = derive_keypair(MASTER, "customer");
    let customer_id = derive_id(&customer.verifying_key());
    let provider = derive_keypair(MASTER, "provider");
    let provider_id = derive_id(&provider.verifying_key());

    // The unseal authority holds the same (deterministic) customer key the watch
    // pins, so a legitimate rotation verifies.
    let unseal = UnsealAuthority::new(&customer_id, derive_keypair(MASTER, "customer"));
    let mut watch = RotationWatch::new(COLLECTION, &customer_id, customer.verifying_key());

    let new_root = format!("{}1", "0".repeat(63));
    let legit = unseal
        .rotate(COLLECTION, &new_root, 100)
        .expect("a held capability produces a rotation");
    assert!(
        watch.observe(&legit).is_customer_initiated(),
        "a customer-signed rotation is classified customer-initiated",
    );

    // A forged rotation — claimed by the provider, invalid customer signature.
    let forged = RootAnnouncement {
        collection_id: COLLECTION.to_owned(),
        new_root,
        day: 100,
        signer_id: provider_id,
        signature: "00".repeat(64),
    };
    assert!(
        watch.observe(&forged).is_alarm(),
        "a non-customer root change alarms"
    );

    assert_eq!(watch.events().len(), 2);
    assert!(
        watch
            .events()
            .iter()
            .all(|e| e.is_customer_initiated() || e.is_alarm()),
        "every observed root change is either customer-signed or alarmed",
    );
}
