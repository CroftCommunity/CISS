//! Phase 4b wiring test — per-user SQLite persistence (D5: co-locate the
//! manifest as a single-author record and receipts/statements as the co-signed
//! structure alongside, in one per-DID store). Uses SQLite's in-memory mode, so
//! the test runs against the REAL persistence path (same code, file-backed in
//! production) with no files and no mocking.
//!
//! RED→GREEN gate: records saved for a DID load back intact — the manifest still
//! verifies, the statement chain still verifies, receipts round-trip — and a
//! different DID's records are isolated.

use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::item::Item;
use ciss::manifest::{build_manifest, ManifestLeaf};
use ciss::persist::Store;
use ciss::receipts::{make_bilateral_receipt, Direction, ReceiptCore};
use ciss::statements::{
    build_statement, verify_chain, Statement, StatementBody, GENESIS_STATEMENT,
};

const SEED: &str = "ciss::persist::test";

fn stmt(period: u64, prev: &str) -> Statement {
    build_statement(StatementBody {
        period,
        period_start_day: period * 30,
        period_end_day: period * 30 + 30,
        opening_root: "r".to_owned(),
        closing_root: "r".to_owned(),
        byte_days: 300,
        rent_cents: 0,
        postage_bytes: 0,
        postage_cents: 0,
        audit_count: 0,
        audit_bytes: 0,
        audit_cents: 0,
        audit_tier: "none".to_owned(),
        grace_cents: 0,
        fees_cents: 0,
        total_cents: 0,
        prev_statement_hash: prev.to_owned(),
    })
}

#[test]
fn per_did_records_round_trip_through_sqlite() {
    let customer = derive_keypair(SEED, "customer");
    let provider = derive_keypair(SEED, "provider");
    let did = derive_id(&customer.verifying_key());
    let pid = derive_id(&provider.verifying_key());

    // Records to persist: a signed manifest, two receipts, a two-statement chain.
    let a = Item::from_bytes("a", vec![1u8; 100]);
    let b = Item::from_bytes("b", vec![2u8; 200]);
    let leaves = vec![
        ManifestLeaf::new(a.cid(), a.size()),
        ManifestLeaf::new(b.cid(), b.size()),
    ];
    let manifest = build_manifest(&leaves, &did, &customer);

    let r0 = make_bilateral_receipt(
        ReceiptCore::new(
            Direction::Upload,
            a.cid(),
            (0, a.size()),
            a.size(),
            1,
            &pid,
            &did,
        ),
        Some(&provider),
        &customer,
    );
    let r1 = make_bilateral_receipt(
        ReceiptCore::new(
            Direction::Upload,
            b.cid(),
            (0, b.size()),
            b.size(),
            2,
            &pid,
            &did,
        ),
        Some(&provider),
        &customer,
    );
    let s0 = stmt(0, GENESIS_STATEMENT);
    let s1 = stmt(1, s0.hash());

    // Real SQLite, in-memory mode.
    let store = Store::open_in_memory().expect("open in-memory store");
    store.save_manifest(&did, &manifest).expect("save manifest");
    store.append_receipt(&did, &r0).expect("append r0");
    store.append_receipt(&did, &r1).expect("append r1");
    store.append_statement(&did, &s0).expect("append s0");
    store.append_statement(&did, &s1).expect("append s1");

    // Manifest loads back and still verifies under the customer's key.
    let loaded_manifest = store
        .load_manifest(&did)
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(
        loaded_manifest.root(),
        manifest.root(),
        "manifest root round-trips"
    );
    assert!(
        loaded_manifest.verify(&customer.verifying_key()),
        "loaded manifest still verifies",
    );

    // Receipts round-trip in insertion order.
    let loaded_receipts = store.load_receipts(&did).expect("load receipts");
    assert_eq!(loaded_receipts.len(), 2);
    assert_eq!(loaded_receipts[0].content_hash(), r0.content_hash());
    assert_eq!(loaded_receipts[1].content_hash(), r1.content_hash());

    // The statement chain loads back and still verifies genesis→head.
    let loaded_statements = store.load_statements(&did).expect("load statements");
    assert_eq!(loaded_statements.len(), 2);
    assert!(
        verify_chain(&loaded_statements).is_ok(),
        "loaded chain verifies"
    );

    // Per-DID isolation: a DID that was never written has no records.
    assert!(
        store.load_manifest(&pid).expect("load").is_none(),
        "other DID has no manifest"
    );
    assert!(
        store.load_receipts(&pid).expect("load").is_empty(),
        "other DID has no receipts"
    );
    assert!(
        store.load_statements(&pid).expect("load").is_empty(),
        "other DID has no statements"
    );
}
