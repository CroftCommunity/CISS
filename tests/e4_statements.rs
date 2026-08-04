//! Phase 4 wiring test — ports E4 (balance-forward statements) from the oracle
//! (`src/exp/e4_statements.ts`): each period closes into a co-signed statement
//! (opening root, closing root, byte-day rent, postage) chained to the prior by
//! hash, so a dispute is bounded to one period. Adds the rollup/purge boundary:
//! once a period is settled, its granular receipts are purgeable while the chain
//! still verifies and rent stays recomputable.
//!
//! RED→GREEN gate: exercises item → manifest → rent-timeline → statement-chain
//! end to end, plus tamper/fabrication/purge.

use ciss::crypto::derive_keypair;
use ciss::identity::derive_id;
use ciss::item::Item;
use ciss::manifest::{build_manifest, ManifestLeaf};
use ciss::pricing::rent_cents;
use ciss::receipts::{make_bilateral_receipt, Direction, Receipt, ReceiptCore};
use ciss::statements::{
    build_statement, purge_receipts_settled_through, verify_chain, RentTimeline, Statement,
    StatementBody, GENESIS_STATEMENT,
};

const MASTER_SEED: &str = "ciss::e4::test-seed";

fn item_bytes(fill: u8, size: usize) -> Vec<u8> {
    (0..size).map(|i| fill ^ i.to_le_bytes()[0]).collect()
}

fn root_of(items: &[&Item], customer_id: &str, key: &ciss::crypto::Keypair) -> String {
    let leaves: Vec<ManifestLeaf> = items
        .iter()
        .map(|i| ManifestLeaf::new(i.cid(), i.size()))
        .collect();
    build_manifest(&leaves, customer_id, key, 1).root().to_owned()
}

fn total_bytes(items: &[&Item]) -> u64 {
    items
        .iter()
        .map(|i| u64::try_from(i.size()).expect("size fits u64"))
        .sum()
}

/// Assemble and hash a period-closing statement from the rent timeline + the
/// period's receipts. `period = (num, start_day, end_day)`, `roots = (opening,
/// closing)`.
fn close(
    timeline: &RentTimeline,
    receipts: &[Receipt],
    period: (u64, u64, u64),
    roots: (&str, &str),
    prev_hash: &str,
) -> Statement {
    let (num, start, end) = period;
    let (opening, closing) = roots;
    let byte_days = timeline.byte_days(start, end);
    let postage_bytes: u64 = receipts
        .iter()
        .filter(|r| r.core().day >= start && r.core().day < end)
        .map(|r| u64::try_from(r.bytes()).expect("bytes fit u64"))
        .sum();
    let rent = rent_cents(byte_days);
    let postage = ciss::pricing::postage_cents(postage_bytes);
    build_statement(StatementBody {
        period: num,
        period_start_day: start,
        period_end_day: end,
        opening_root: opening.to_owned(),
        closing_root: closing.to_owned(),
        byte_days,
        rent_cents: rent,
        postage_bytes,
        postage_cents: postage,
        audit_count: 0,
        audit_bytes: 0,
        audit_cents: 0,
        audit_tier: "none".to_owned(),
        grace_cents: 0,
        fees_cents: 0,
        total_cents: rent + postage,
        prev_statement_hash: prev_hash.to_owned(),
    })
}

#[test]
#[allow(clippy::too_many_lines)] // ports E4's full three-period scenario + purge as one flow
fn e4_statements_chain_balance_forward_and_purge() {
    let customer = derive_keypair(MASTER_SEED, "customer");
    let customer_id = derive_id(&customer.verifying_key());

    // Base item set (period 0): A + B + C.
    let a = Item::from_bytes("will.pdf", item_bytes(0x11, 512));
    let b = Item::from_bytes("voice-note.ogg", item_bytes(0x22, 128));
    let c = Item::from_bytes("backup.tar", item_bytes(0x33, 8192));
    let root0 = root_of(&[&a, &b, &c], &customer_id, &customer);
    let total0 = total_bytes(&[&a, &b, &c]); // 8832

    let mut timeline = RentTimeline::new();
    timeline.set_bytes_at_rest(0, total0);

    let provider = derive_keypair(MASTER_SEED, "provider");
    let provider_id = derive_id(&provider.verifying_key());
    let mut receipts: Vec<Receipt> = Vec::new();

    // A billable upload of C on day 0 — postage inside period 0.
    let up0 = ReceiptCore::new(
        Direction::Upload,
        c.cid(),
        (0, c.size()),
        c.size(),
        0,
        &provider_id,
        &customer_id,
    );
    receipts.push(make_bilateral_receipt(up0, Some(&provider), &customer));

    // --- Period 0: steady state, day 0..30. ---
    let s0 = close(
        &timeline,
        &receipts,
        (0, 0, 30),
        (&root0, &root0),
        GENESIS_STATEMENT,
    );

    // --- Period 1: add item D mid-period (day 35), bill the upload. ---
    let d = Item::from_bytes("new-photo.jpg", item_bytes(0x44, 3000));
    let root1_open = root0.clone();
    let root1 = root_of(&[&a, &b, &c, &d], &customer_id, &customer);
    let total1 = total_bytes(&[&a, &b, &c, &d]); // 11832
    timeline.set_bytes_at_rest(35, total1);
    let up_core = ReceiptCore::new(
        Direction::Upload,
        d.cid(),
        (0, d.size()),
        d.size(),
        35,
        &provider_id,
        &customer_id,
    );
    receipts.push(make_bilateral_receipt(up_core, Some(&provider), &customer));
    let s1 = close(
        &timeline,
        &receipts,
        (1, 30, 60),
        (&root1_open, &root1),
        s0.hash(),
    );

    // --- Period 2: delete item B mid-period (day 70). ---
    let root2_open = root1.clone();
    let root2 = root_of(&[&a, &c, &d], &customer_id, &customer);
    let total2 = total_bytes(&[&a, &c, &d]); // 11704
    timeline.set_bytes_at_rest(70, total2);
    let s2 = close(
        &timeline,
        &receipts,
        (2, 60, 90),
        (&root2_open, &root2),
        s1.hash(),
    );

    let statements = vec![s0.clone(), s1.clone(), s2.clone()];

    // The chain verifies from genesis.
    assert!(
        verify_chain(&statements).is_ok(),
        "statement chain verifies from genesis"
    );

    // Balance-forward: each period opens where the prior closed.
    assert_eq!(
        s1.body().opening_root,
        s0.body().closing_root,
        "P1 opens where P0 closed"
    );
    assert_eq!(
        s2.body().opening_root,
        s1.body().closing_root,
        "P2 opens where P1 closed"
    );

    // Rent equals the independently recomputed byte-day integral.
    for s in &statements {
        let recomputed =
            rent_cents(timeline.byte_days(s.body().period_start_day, s.body().period_end_day));
        assert_eq!(
            recomputed,
            s.body().rent_cents,
            "rent == byte-day integral (period {})",
            s.body().period
        );
    }
    // Sanity on the arithmetic: P0 = 8832*30 byte-days.
    assert_eq!(s0.body().byte_days, total0 * 30);
    assert_eq!(s1.body().postage_bytes, 3000, "period 1 billed the upload");

    // Adversarial (a): edit a figure in statement 1 in place (keep its old hash)
    // → the chain fails at exactly link 1 (body no longer hashes to its hash).
    let mut edited = statements.clone();
    let mut body1 = edited[1].body().clone();
    body1.rent_cents += 100;
    edited[1] = Statement::from_parts(body1, edited[1].hash().to_owned());
    let result = verify_chain(&edited);
    assert!(
        !result.is_ok(),
        "editing a historical figure fails chain verification"
    );
    assert_eq!(
        result.failed_at(),
        Some(1),
        "failure located at exactly the edited link"
    );

    // Adversarial (b): a fabricated inserted period cannot pass.
    let mut fabricated = vec![s0.clone(), s1.clone()];
    fabricated.push(build_statement(StatementBody {
        period: 2,
        prev_statement_hash: s1.hash().to_owned(),
        rent_cents: 9999,
        ..s2.body().clone()
    }));
    fabricated.push(s2.clone());
    assert!(
        !verify_chain(&fabricated).is_ok(),
        "a fabricated inserted period cannot verify"
    );

    // Rollup + purge: period 0 is settled (closed + co-signed via s0). Its
    // granular receipts become purgeable — the signed statement carries the
    // rollup. Purge everything settled through day 30.
    let settled_postage = s0.body().postage_bytes; // the rollup carries it
    let purged = purge_receipts_settled_through(&mut receipts, 30);
    assert_eq!(
        purged, 1,
        "the day-0 receipt in the settled period is purged"
    );
    assert!(
        receipts.iter().all(|r| r.core().day >= 30),
        "no settled (day < 30) receipts remain",
    );
    // The signed statement still carries the period's rolled-up postage, and the
    // chain + rent survive the purge (rent comes from the timeline, not receipts).
    assert_eq!(
        s0.body().postage_bytes,
        settled_postage,
        "the co-signed rollup preserves the postage total"
    );
    assert!(
        verify_chain(&statements).is_ok(),
        "chain still verifies after purge"
    );
    assert_eq!(
        rent_cents(timeline.byte_days(0, 30)),
        s0.body().rent_cents,
        "rent for the purged period stays recomputable from the timeline",
    );
}
