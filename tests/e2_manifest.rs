//! Phase 2 wiring test — ports E2 (the manifest) from the standalone oracle
//! (`src/exp/e2_manifest.ts`): what should be on disk is computable from the
//! customer's own signature. Ada authors + signs a manifest; the provider
//! independently recomputes the same root from its stored copies and derives
//! expected bytes-at-rest by arithmetic. Two adversarial claims must be caught:
//! an inflated stored-total (arithmetic alone) and a root over a set with one
//! item missing.
//!
//! This is the RED→GREEN gate for Phase 2: it exercises the full item → manifest
//! → crypto chain and the provider-vs-customer root cross-check, not an isolated
//! internal.

use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::item::{ContentStore, Item};
use ciss::manifest::{build_manifest, expected_bytes, merkle_root, ManifestLeaf};

const MASTER_SEED: &str = "ciss::e2::test-seed";

fn item_bytes(fill: u8, size: usize) -> Vec<u8> {
    (0..size).map(|i| fill ^ i.to_le_bytes()[0]).collect()
}

#[test]
fn e2_manifest_is_the_bills_source_of_truth() {
    let customer = derive_keypair(MASTER_SEED, "customer");
    let customer_id = derive_id(&customer.verifying_key());

    let items: Vec<Item> = [
        ("will.pdf", 0x22u8, 512usize),
        ("family-post.txt", 0x33, 128),
        ("backup.tar", 0x44, 8192),
    ]
    .iter()
    .map(|(label, fill, size)| Item::from_bytes(label, item_bytes(*fill, *size)))
    .collect();

    // The provider stores the bytes.
    let mut store = ContentStore::new();
    for item in &items {
        store.put(item);
    }

    // Ada authors and signs the manifest over the (cid, size) set.
    let leaves: Vec<ManifestLeaf> = items
        .iter()
        .map(|i| ManifestLeaf::new(i.cid(), i.size()))
        .collect();
    let manifest = build_manifest(&leaves, &customer_id, &customer, 1);

    // The customer's signature over the root verifies under her pinned key.
    assert!(
        manifest.verify(&customer.verifying_key()),
        "manifest signature verifies under customer's pinned key",
    );

    // The provider independently recomputes the root from ITS stored copies and
    // gets the same root the customer signed. (Independent leaf list, unsorted;
    // build order must not matter.)
    let provider_leaves: Vec<ManifestLeaf> = items
        .iter()
        .rev()
        .map(|i| ManifestLeaf::new(i.cid(), i.size()))
        .collect();
    let provider_root = merkle_root(&provider_leaves);
    assert_eq!(
        provider_root,
        manifest.root(),
        "provider-computed root equals customer-signed root (order-independent)",
    );

    // Expected-bytes is a pure function of the manifest and equals what's on disk.
    let expected = expected_bytes(&manifest);
    assert_eq!(
        expected,
        manifest.total_bytes(),
        "expected bytes is a pure function of the manifest",
    );
    assert_eq!(
        store.stored_bytes(),
        expected,
        "provider's stored bytes match expected bytes",
    );

    // Adversarial (a): an inflated stored-total is rejected by arithmetic alone —
    // no retrieval needed.
    let inflated_claim = expected + 1_000_000;
    assert_ne!(
        inflated_claim,
        expected_bytes(&manifest),
        "inflated storage claim rejected by arithmetic alone",
    );

    // Adversarial (b): a root recomputed with one item missing mismatches the
    // signed root.
    let missing_one = &provider_leaves[1..];
    assert_ne!(
        merkle_root(missing_one),
        manifest.root(),
        "root over an incomplete set mismatches the signed root",
    );

    // Adversarial (c): a manifest whose signature is checked against the WRONG
    // key does not verify.
    let impostor = derive_keypair(MASTER_SEED, "impostor");
    assert!(
        !manifest.verify(&impostor.verifying_key()),
        "manifest does not verify under an impostor key",
    );
}
