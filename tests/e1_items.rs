//! Phase 2 test — ports E1 (items and fingerprints) from the standalone oracle
//! (`src/exp/e1_items.ts`): an item's name is its content, so an item cannot
//! quietly become a different item, and a byte-flip at rest is caught on the way
//! out — for exactly the tampered item, and no other.

use std::collections::HashSet;

use ciss::item::{ContentStore, Item, RetrieveError};

/// Distinct, deterministic bytes per item so fingerprints are stable and unique
/// without pulling in the (Phase-5) seeded RNG.
fn item_bytes(fill: u8, size: usize) -> Vec<u8> {
    (0..size).map(|i| fill ^ i.to_le_bytes()[0]).collect()
}

#[test]
fn e1_items_are_content_addressed_and_tamper_evident() {
    let specs: [(&str, u8, usize); 5] = [
        ("wedding-photo.jpg", 0x11, 4096),
        ("will.pdf", 0x22, 512),
        ("family-post.txt", 0x33, 128),
        ("backup.tar", 0x44, 8192),
        ("voice-note.ogg", 0x55, 1500),
    ];
    let items: Vec<Item> = specs
        .iter()
        .map(|(label, fill, size)| Item::from_bytes(label, item_bytes(*fill, *size)))
        .collect();

    let mut store = ContentStore::new();
    for item in &items {
        store.put(item);
    }

    // Every untampered item round-trips (retrieve + re-fingerprint).
    for item in &items {
        assert!(
            store.retrieve_verified(item.cid()).is_ok(),
            "every untampered item round-trips: {}",
            item.label(),
        );
    }

    // All fingerprints are distinct across distinct content.
    let cids: HashSet<&str> = items.iter().map(Item::cid).collect();
    assert_eq!(cids.len(), items.len(), "all fingerprints are distinct");

    // Sizes are recorded from the content.
    assert_eq!(items[0].size(), 4096, "size is taken from the bytes");

    // Adversarial: a byte of one stored item is flipped at rest (modelled with
    // the dumb `write` primitive — the boundary computes the cid, the backend
    // just stores bytes under a key, so writing tampered bytes under a cid IS the
    // at-rest-corruption scenario).
    let victim = &items[2];
    let mut corrupted = item_bytes(0x33, 128);
    corrupted[0] ^= 0x01;
    store.write(victim.cid(), &corrupted);

    let result = store.retrieve_verified(victim.cid());
    assert!(result.is_err(), "tampered item fails verification");
    let err = result.unwrap_err();
    assert!(
        matches!(err, RetrieveError::Tampered { .. }),
        "tamper is reported as tampering, not loss",
    );
    assert!(
        err.to_string().contains(victim.cid()),
        "detection identifies exactly which item was tampered",
    );

    // The damage is localized: every other item still verifies.
    for item in &items {
        if item.cid() == victim.cid() {
            continue;
        }
        assert!(
            store.retrieve_verified(item.cid()).is_ok(),
            "tamper is localized; other items still verify: {}",
            item.label(),
        );
    }

    // Restoring the good bytes makes it verify again.
    store.put(victim);
    assert!(
        store.retrieve_verified(victim.cid()).is_ok(),
        "restored item verifies again",
    );

    // Loss (drop) is distinguished from tampering.
    store.remove(victim.cid());
    assert!(
        matches!(
            store.retrieve_verified(victim.cid()),
            Err(RetrieveError::Missing { .. })
        ),
        "a dropped item is reported as missing, not tampered",
    );
}
