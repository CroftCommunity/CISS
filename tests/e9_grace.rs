//! Phase 6 wiring test — ports E9 (the grace ledger) from the oracle
//! (`src/exp/e9_grace.ts`): grace is represented in the books, not off-book.
//! Grace events are first-class co-signed ledger entries (fee waiver, deceased-
//! member hold, throttle-instead-of-cutoff); each nets to zero against the co-op
//! grace account; none edits history (all forward entries, so the provider
//! ledger still verifies unbroken); grace totals are reportable per event; and a
//! waived fee lands in the period statement as rent only.

use std::collections::BTreeMap;

use ciss::crypto::derive_keypair;
use ciss::grace::{GraceAccount, GRACE_EVENT_KIND};
use ciss::identity::derive_id;
use ciss::ledger::{verify_entries, Ledger, Signer};
use ciss::statements::{build_statement, verify_chain, StatementBody, GENESIS_STATEMENT};

#[test]
fn grace_events_are_cosigned_forward_entries_that_net_to_zero() {
    let provider = derive_keypair("e9", "provider");
    let provider_id = derive_id(&provider.verifying_key());
    let customer = derive_keypair("e9", "customer");
    let customer_id = derive_id(&customer.verifying_key());

    let mut ledger = Ledger::new(&provider_id);
    let mut grace = GraceAccount::new();

    // Scenario 1: a one-off fee waiver.
    let ev = grace.record_event(
        &mut ledger,
        "t1",
        "FIRST_TIME_HARDSHIP",
        25,
        "waived a late fee, once, because we could afford to",
        &[
            Signer::new(&provider_id, &provider),
            Signer::new(&customer_id, &customer),
        ],
    );
    assert_eq!(ev.customer_credit_cents, -25);
    assert_eq!(ev.grace_account_charge_cents, 25);
    assert_eq!(ev.grace_account_balance_cents, 25);
    assert_eq!(grace.balance_cents() + grace.customer_credits_cents(), 0);

    // Scenario 2: deceased-member hold — rent carried by the co-op, three periods.
    for held in 0..3 {
        let ev = grace.record_event(
            &mut ledger,
            "t2",
            "DECEASED_MEMBER_HOLD",
            40,
            &format!("estate hold period {}/3", held + 1),
            &[
                Signer::new(&provider_id, &provider),
                Signer::new(&customer_id, &customer),
            ],
        );
        assert_eq!(ev.customer_credit_cents, -40);
        assert_eq!(grace.balance_cents() + grace.customer_credits_cents(), 0);
    }

    // Scenario 3: throttle-instead-of-cutoff during a payment lapse.
    grace.record_event(
        &mut ledger,
        "t3",
        "PAYMENT_LAPSE_THROTTLE",
        40,
        "service throttled, not cut off; rent carried this period",
        &[
            Signer::new(&provider_id, &provider),
            Signer::new(&customer_id, &customer),
        ],
    );

    // Five forward grace entries; totals reportable; credits and charges balance.
    let grace_entries = ledger
        .entries()
        .iter()
        .filter(|e| e.kind == GRACE_EVENT_KIND)
        .count();
    assert_eq!(
        grace_entries, 5,
        "grace events are reportable (all forward entries)"
    );
    assert_eq!(
        grace.balance_cents() + grace.customer_credits_cents(),
        0,
        "credits and charges net to zero",
    );
    assert_eq!(grace.balance_cents(), 25 + 40 * 3 + 40);
    assert_eq!(grace.customer_credits_cents(), -(25 + 40 * 3 + 40));

    // Co-signed by both parties, the append-only provider ledger verifies unbroken.
    let ring: BTreeMap<String, _> = [
        (provider_id.clone(), provider.verifying_key()),
        (customer_id.clone(), customer.verifying_key()),
    ]
    .into_iter()
    .collect();
    assert!(
        verify_entries(ledger.entries(), &ring).is_empty(),
        "the co-signed grace ledger verifies as an unbroken append-only chain",
    );
}

#[test]
fn a_waived_fee_lands_in_the_statement_as_rent_only() {
    // fees_cents = fee, grace_cents = -fee (a credit), so the member's total is
    // rent only; the statement still hashes and chains.
    let rent: u64 = 12;
    let fee: u64 = 25;
    let body = StatementBody {
        period: 0,
        period_start_day: 0,
        period_end_day: 30,
        opening_root: "r".to_owned(),
        closing_root: "r".to_owned(),
        byte_days: 0,
        rent_cents: rent,
        postage_bytes: 0,
        postage_cents: 0,
        audit_count: 0,
        audit_bytes: 0,
        audit_cents: 0,
        audit_tier: "none".to_owned(),
        grace_cents: -i64::try_from(fee).expect("fee fits i64"),
        fees_cents: fee,
        total_cents: rent, // rent + fee - fee
        prev_statement_hash: GENESIS_STATEMENT.to_owned(),
    };
    let stmt = build_statement(body);
    assert_eq!(
        stmt.body().grace_cents,
        -25,
        "the waiver is a negative grace credit"
    );
    assert_eq!(stmt.body().total_cents, rent, "member pays rent only");
    assert!(
        verify_chain(std::slice::from_ref(&stmt)).is_ok(),
        "the statement chains"
    );
}
