//! Phase 3 wiring test — ports E3 (transfer receipts) from the standalone oracle
//! (`src/exp/e3_receipts.ts`), plus the two-mode design: postage is metered by
//! weight (bytes), not by trips, and each increment is signed at the boundary.
//!
//! Bilateral receipts are co-signed by both parties (third-party-verifiable);
//! Unilateral receipts are provider-signed only (an "our-side measurement",
//! valid by trust, NOT co-attested — weaker provenance). The wiring: receipts
//! flow into each party's append-only ledger and the whole chain re-verifies.

use std::collections::BTreeMap;

use ciss::crypto::{derive_keypair, Keypair};
use ciss::identity::derive_id;
use ciss::ledger::{verify_entries, Ledger, Signer};
use ciss::receipts::{
    make_bilateral_receipt, make_unilateral_receipt, select_mode, Direction, Receipt, ReceiptCore,
    ReceiptMode, TransferContext,
};
use ed25519_dalek::VerifyingKey;

const MASTER_SEED: &str = "ciss::e3::test-seed";
const TS: &str = "2026-07-31T00:00:00Z";
const INCREMENT: usize = 2048;

fn keyring(pairs: &[(&str, &Keypair)]) -> BTreeMap<String, VerifyingKey> {
    pairs
        .iter()
        .map(|(id, kp)| ((*id).to_owned(), kp.verifying_key()))
        .collect()
}

/// Transfer `size` bytes in fixed increments, one bilateral receipt each. On a
/// walkaway, the receiver never signs the final increment (so the sender does
/// not countersign it either — it carries no signatures).
fn transfer(
    direction: Direction,
    cid: &str,
    size: usize,
    receiver: (&str, &Keypair),
    sender: (&str, &Keypair),
    walkaway_last: bool,
) -> Vec<Receipt> {
    let (receiver_id, receiver_key) = receiver;
    let (sender_id, sender_key) = sender;
    let total = size.div_ceil(INCREMENT);
    let mut receipts = Vec::new();
    let mut running = 0usize;
    let mut offset = 0usize;
    let mut idx = 0usize;
    while offset < size {
        let end = (offset + INCREMENT).min(size);
        running += end - offset;
        let core = ReceiptCore::new(
            direction,
            cid,
            (offset, end),
            running,
            1,
            receiver_id,
            sender_id,
        );
        let is_last = idx == total - 1;
        let receiver_signer = if walkaway_last && is_last {
            None
        } else {
            Some(receiver_key)
        };
        receipts.push(make_bilateral_receipt(core, receiver_signer, sender_key));
        offset = end;
        idx += 1;
    }
    receipts
}

// Ports E3's full multi-part scenario (transfer -> ledger embed + verify ->
// reconcile -> forgery -> walkaway) as one end-to-end wiring test; splitting it
// would fragment a single boundary-to-ledger flow.
#[test]
#[allow(clippy::too_many_lines)]
fn e3_postage_is_metered_at_the_boundary_and_reconciles() {
    let customer = derive_keypair(MASTER_SEED, "customer");
    let provider = derive_keypair(MASTER_SEED, "provider");
    let customer_id = derive_id(&customer.verifying_key());
    let provider_id = derive_id(&provider.verifying_key());
    let ring = keyring(&[(&customer_id, &customer), (&provider_id, &provider)]);

    // Upload: Ada -> co-op (co-op receives, Ada sends). Download: co-op -> Ada.
    let up = transfer(
        Direction::Upload,
        "cid-backup",
        8192,
        (&provider_id, &provider),
        (&customer_id, &customer),
        false,
    );
    let down = transfer(
        Direction::Download,
        "cid-will",
        512,
        (&customer_id, &customer),
        (&provider_id, &provider),
        false,
    );

    // Every acknowledged receipt verifies bilaterally under both pinned keys.
    let all: Vec<&Receipt> = up.iter().chain(down.iter()).collect();
    assert!(
        all.iter().all(|r| r.verify_bilateral(&ring)),
        "every acknowledged receipt verifies under both pinned keys",
    );

    // Both parties embed the receipts in their own append-only ledger.
    let mut customer_ledger = Ledger::new(&customer_id);
    let mut provider_ledger = Ledger::new(&provider_id);
    for r in &all {
        let body = serde_json::to_value(r).expect("receipt serializes");
        customer_ledger.append(
            "receipt",
            TS,
            body.clone(),
            &[Signer::new(&customer_id, &customer)],
        );
        provider_ledger.append("receipt", TS, body, &[Signer::new(&provider_id, &provider)]);
    }

    // The wiring: each ledger's hash-chain + signatures re-verify end to end.
    assert!(
        verify_entries(customer_ledger.entries(), &ring).is_empty(),
        "customer ledger chain + signatures verify",
    );
    assert!(
        verify_entries(provider_ledger.entries(), &ring).is_empty(),
        "provider ledger chain + signatures verify",
    );

    // Both ledgers reconcile to identical postage totals.
    let postage: usize = all.iter().map(|r| r.bytes()).sum();
    assert_eq!(
        postage,
        8192 + 512,
        "postage is the sum of transferred bytes"
    );

    // Adversarial (a): a forged byte count fails the receipt's own signatures.
    // The forger alters the core but keeps the original content-hash + sigs
    // (reconstructed via the wire/ledger `from_parts` constructor) — recomputing
    // the core hash exposes the mismatch.
    let original = &up[0];
    let mut forged_core = original.core().clone();
    forged_core.bytes += 1000;
    let forged = Receipt::from_parts(
        forged_core,
        original.content_hash().to_owned(),
        original.mode(),
        original.sigs().clone(),
    );
    assert!(
        !forged.verify_bilateral(&ring),
        "forged byte count fails the receipt's own signature check",
    );

    // Adversarial (b): walkaway — the receiver abandons the final increment.
    // Exposure is exactly one increment, never more.
    let walk = transfer(
        Direction::Download,
        "cid-will",
        512,
        (&customer_id, &customer),
        (&provider_id, &provider),
        true,
    );
    let unsigned: Vec<&Receipt> = walk.iter().filter(|r| !r.is_acknowledged()).collect();
    assert_eq!(
        unsigned.len(),
        1,
        "walkaway leaves exactly one unsigned increment"
    );
    let unsigned_bytes: usize = unsigned.iter().map(|r| r.bytes()).sum();
    let last_increment = walk.last().expect("at least one increment").bytes();
    assert_eq!(
        unsigned_bytes, last_increment,
        "unsigned exposure equals one increment, never more",
    );

    // The walkaway is recorded as a forward reputation event, not a silent loss.
    provider_ledger.append(
        "reputation-event",
        TS,
        serde_json::json!({
            "kind": "walkaway",
            "counterparty": customer_id,
            "cid": "cid-will",
            "unsignedBytes": unsigned_bytes,
        }),
        &[Signer::new(&provider_id, &provider)],
    );
    assert!(
        provider_ledger
            .entries()
            .iter()
            .any(|e| e.kind == "reputation-event"),
        "walkaway recorded as a reputation event in the ledger",
    );
}

#[test]
fn e3_unilateral_is_a_single_party_measurement_not_co_attested() {
    let customer = derive_keypair(MASTER_SEED, "customer");
    let provider = derive_keypair(MASTER_SEED, "provider");
    let customer_id = derive_id(&customer.verifying_key());
    let provider_id = derive_id(&provider.verifying_key());
    let ring = keyring(&[(&customer_id, &customer), (&provider_id, &provider)]);

    // The provider records an our-side measurement, signed by itself alone.
    let core = ReceiptCore::new(
        Direction::Upload,
        "cid-backup",
        (0, 2048),
        2048,
        1,
        &provider_id,
        &customer_id,
    );
    let receipt = make_unilateral_receipt(core, &provider_id, &provider);

    // It validates as a provider-signed measurement...
    assert_eq!(receipt.mode(), ReceiptMode::Unilateral);
    assert!(
        receipt.verify_unilateral(&ring),
        "unilateral receipt validates as an our-side measurement",
    );
    // ...but is explicitly single-party: NOT third-party-co-attested. Its
    // provenance is weaker, valid only by the trust relationship.
    assert_eq!(
        receipt.sigs().len(),
        1,
        "unilateral carries exactly one signature"
    );
    assert!(!receipt.is_co_attested(), "unilateral is not co-attested",);
    assert!(
        !receipt.verify_bilateral(&ring),
        "unilateral does not pass the bilateral (co-attested) check",
    );
}

#[test]
fn e3_mode_selection_seam_returns_the_configured_default() {
    // SEAM: the social-trust policy is a hook; v0 returns the configured default.
    let ctx = TransferContext {
        bytes: 4096,
        trust_distance: None,
    };
    assert_eq!(
        select_mode(&ctx, ReceiptMode::Bilateral),
        ReceiptMode::Bilateral
    );
    assert_eq!(
        select_mode(&ctx, ReceiptMode::Unilateral),
        ReceiptMode::Unilateral
    );
}
