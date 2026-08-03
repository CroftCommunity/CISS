//! Phase 5 wiring test — ports E6 (the dial) from the oracle
//! (`src/exp/e6_dial.ts` + `src/pricing.ts`): audit assurance is a declared,
//! signed setting with a true, linear cost. Tiers are priced from the E5 cost
//! model (bytes read per audit) + a fixed per-audit overhead; the chosen tier is
//! a signed ledger declaration; audit cost is exactly linear in the audit count
//! (no discount/step at the tier edges); the chosen tier appears in the period
//! statement; and a mid-period dial change bills the sum of its two pro-rated
//! legs.
//!
//! RED→GREEN gate: exercises dial pricing + the signed declaration (into the
//! real ledger, re-verified) + the statement `audit_*` fields.

use std::collections::BTreeMap;

use ciss::crypto::derive_keypair;
use ciss::dial::{audits_for, declare_tier, per_audit_cents, tier_cost, DialDeclaration, Tier};
use ciss::identity::derive_id;
use ciss::ledger::{verify_entries, Ledger, Signer};
use ciss::statements::{build_statement, StatementBody, GENESIS_STATEMENT};

const AVG_ITEM_BYTES: u64 = 256;
const PERIOD: u64 = 30;

fn tiers() -> Vec<Tier> {
    vec![
        Tier::new("monthly", 5, 1),
        Tier::new("weekly", 5, 4),
        Tier::new("daily", 20, 30),
        Tier::new("hourly", 20, 720),
    ]
}

#[test]
fn audit_cost_is_exactly_linear_in_count_at_the_tier_edges() {
    let t = tiers();
    // weekly vs monthly share k=5; weekly runs 4x the audits => exactly 4x cost.
    assert_eq!(
        tier_cost(&t[1], AVG_ITEM_BYTES),
        4 * tier_cost(&t[0], AVG_ITEM_BYTES),
        "weekly = 4 x monthly (same k, linear in count)",
    );
    // daily vs hourly share k=20; hourly runs 24x the audits => exactly 24x cost.
    assert_eq!(
        tier_cost(&t[3], AVG_ITEM_BYTES),
        24 * tier_cost(&t[2], AVG_ITEM_BYTES),
        "hourly = 24 x daily (same k, linear in count)",
    );
    // No volume discount / step anywhere: N audits cost exactly N x one audit,
    // asserted at each tier's own count (the boundary sample points), not one
    // interior value. (Pass-3 mutation-resistance: kills a per-count discount.)
    for tier in &t {
        let one = per_audit_cents(tier.k, AVG_ITEM_BYTES);
        assert_eq!(
            tier_cost(tier, AVG_ITEM_BYTES),
            tier.audits_per_period * one,
            "{}: cost is exactly audits x per-audit (no discount)",
            tier.name,
        );
    }
}

#[test]
fn per_audit_cost_tracks_k_and_the_fixed_overhead() {
    // per-audit = floor(k*avg / 1000) + 2 overhead; avg=256:
    // k=5  -> floor(1280/1000)+2 = 3 ; k=20 -> floor(5120/1000)+2 = 7
    assert_eq!(per_audit_cents(5, AVG_ITEM_BYTES), 3);
    assert_eq!(per_audit_cents(20, AVG_ITEM_BYTES), 7);
    assert!(
        per_audit_cents(20, AVG_ITEM_BYTES) > per_audit_cents(5, AVG_ITEM_BYTES),
        "a larger k costs strictly more",
    );
}

#[test]
fn the_chosen_tier_is_a_signed_ledger_declaration() {
    let customer = derive_keypair("m", "customer");
    let id = derive_id(&customer.verifying_key());
    let mut ledger = Ledger::new(&id);
    let daily = Tier::new("daily", 20, 30);
    declare_tier(&mut ledger, &daily, "t0", Signer::new(&id, &customer));

    let entry = &ledger.entries()[0];
    assert_eq!(entry.kind, "dial-declaration");
    let decl: DialDeclaration =
        serde_json::from_value(entry.body.clone()).expect("declaration body round-trips");
    assert_eq!(decl.tier, "daily");
    assert_eq!(decl.k, 20);
    assert_eq!(decl.audits_per_period, 30);

    let ring: BTreeMap<String, _> = [(id.clone(), customer.verifying_key())]
        .into_iter()
        .collect();
    assert!(
        verify_entries(ledger.entries(), &ring).is_empty(),
        "the signed declaration verifies under the customer's key",
    );
}

#[test]
fn the_chosen_tier_appears_in_the_period_statement() {
    let daily = Tier::new("daily", 20, 30);
    let ac = tier_cost(&daily, AVG_ITEM_BYTES);
    let body = StatementBody {
        period: 0,
        period_start_day: 0,
        period_end_day: PERIOD,
        opening_root: "r".to_owned(),
        closing_root: "r".to_owned(),
        byte_days: 0,
        rent_cents: 0,
        postage_bytes: 0,
        postage_cents: 0,
        audit_count: daily.audits_per_period,
        audit_bytes: daily.audits_per_period * daily.k * AVG_ITEM_BYTES,
        audit_cents: ac,
        audit_tier: daily.name.clone(),
        grace_cents: 0,
        fees_cents: 0,
        total_cents: ac,
        prev_statement_hash: GENESIS_STATEMENT.to_owned(),
    };
    let stmt = build_statement(body);
    assert_eq!(stmt.body().audit_tier, "daily");
    assert_eq!(stmt.body().audit_cents, ac);
    assert_eq!(stmt.body().audit_count, 30);
}

#[test]
fn a_mid_period_dial_change_bills_the_sum_of_the_two_prorated_legs() {
    let weekly = Tier::new("weekly", 5, 4);
    let daily = Tier::new("daily", 20, 30);
    // First half weekly, second half daily; audit counts pro-rate by days.
    let first = audits_for(weekly.audits_per_period, 15, PERIOD); // round(4*15/30) = 2
    let second = audits_for(daily.audits_per_period, 15, PERIOD); // round(30*15/30) = 15
    assert_eq!(first, 2);
    assert_eq!(second, 15);

    let first_cost = first * per_audit_cents(weekly.k, AVG_ITEM_BYTES);
    let second_cost = second * per_audit_cents(daily.k, AVG_ITEM_BYTES);
    let prorated = first_cost + second_cost;

    // A full period at each tier, for the between-ness bound.
    let full_weekly = tier_cost(&weekly, AVG_ITEM_BYTES);
    let full_daily = tier_cost(&daily, AVG_ITEM_BYTES);
    assert!(
        prorated > full_weekly && prorated < full_daily,
        "pro-rated {prorated} sits between full-weekly {full_weekly} and full-daily {full_daily}",
    );
}
