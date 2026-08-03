//! Phase 1 wiring test — ports E0 (identity) from the standalone oracle
//! (`src/exp/e0_identity.ts`): recognition (signature verification) and counting
//! (identifier derivation) rest on the same public key.
//!
//! This is the RED→GREEN gate for Phase 1: it exercises the crate's public API
//! (derive keypair → sign → verify under a pinned key → derive id), not an
//! isolated internal.

use ciss::crypto::{derive_keypair, public_key_from_hex, verify_message};
use ciss::identity::derive_id;

const MASTER_SEED: &str = "ciss::e0::test-seed";

/// Ports E0's four assertions plus a tamper edge:
/// 1. a message signed by the customer verifies under the customer's pinned key;
/// 2. it does NOT verify under the provider's key (a forged attribution);
/// 3. identifier derivation is a deterministic function of the public key;
/// 4. distinct keys yield distinct identifiers;
/// 5. (edge) a tampered message does not verify under the true key.
#[test]
fn e0_identity_recognize_and_count() {
    let customer = derive_keypair(MASTER_SEED, "customer");
    let provider = derive_keypair(MASTER_SEED, "provider");

    let customer_id = derive_id(&customer.verifying_key());
    let provider_id = derive_id(&provider.verifying_key());

    // Each party pins the other's public key by reconstructing it from the
    // published hex — the same path a networked peer would take.
    let customer_pin =
        public_key_from_hex(&customer.public_key_hex()).expect("customer key is valid hex");
    let provider_pin =
        public_key_from_hex(&provider.public_key_hex()).expect("provider key is valid hex");

    let message = "I, Ada, am bringing my items to the co-op.";
    let signature = customer.sign_message(message);

    // 1. verifies under the customer's pinned key
    assert!(
        verify_message(&customer_pin, message, &signature),
        "customer signature verifies under customer's pinned key",
    );

    // 2. does NOT verify under the provider's key (adversarial: forged attribution)
    assert!(
        !verify_message(&provider_pin, message, &signature),
        "customer signature must not verify under provider's key",
    );

    // 3. identifier derivation is deterministic in the public key alone —
    //    deriving from the reconstructed (pinned) key reproduces the id.
    assert_eq!(
        derive_id(&customer_pin),
        customer_id,
        "identifier derivation is deterministic (customer)",
    );
    assert_eq!(
        derive_id(&provider_pin),
        provider_id,
        "identifier derivation is deterministic (provider)",
    );

    // 4. distinct keys yield distinct identifiers
    assert_ne!(
        customer_id, provider_id,
        "distinct keys yield distinct identifiers",
    );

    // 5. (edge) tampering with the message breaks verification under the true key
    let tampered = "I, Ada, am bringing my items to the co-op!";
    assert!(
        !verify_message(&customer_pin, tampered, &signature),
        "a tampered message must not verify under the true key",
    );
}
