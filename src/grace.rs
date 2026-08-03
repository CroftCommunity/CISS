//! The grace ledger — mercy is represented in the books, not off-book. Grace
//! events are first-class **co-signed** ledger entries: a fee waiver with a
//! reason code, a deceased-member hold (rent carried by the co-op for a fixed
//! term), throttle-instead-of-cutoff during a payment lapse. Each is a **forward
//! entry** (never an edit to history) that nets to zero against the co-op grace
//! account — the member is credited `-amount` and the grace account is charged
//! `+amount` — so the books still balance and grace totals are reportable per
//! period.
//!
//! Ports `item-storage-protocol-standalone/src/exp/e9_grace.ts` (the standalone
//! has no `grace.ts` src module — the grace logic lives in the experiment over
//! `ledger.ts`; `grace.rs` consolidates it).

use serde::{Deserialize, Serialize};

use crate::ledger::{Ledger, Signer};

/// The kind recorded on a grace ledger entry.
pub const GRACE_EVENT_KIND: &str = "grace-event";

/// A single grace event — the co-signed body appended to the provider ledger.
/// The member credit (`-amount`) and the grace-account charge (`+amount`) net to
/// zero by construction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraceEvent {
    /// Why grace was extended (e.g. `FIRST_TIME_HARDSHIP`, `DECEASED_MEMBER_HOLD`).
    pub reason_code: String,
    /// The grace amount, in cents (always positive).
    pub amount_cents: u64,
    /// A human note explaining the grace.
    pub note: String,
    /// The credit applied to the member's bill (`-amount_cents`).
    pub customer_credit_cents: i64,
    /// The charge booked to the co-op grace account (`+amount_cents`).
    pub grace_account_charge_cents: i64,
    /// The running grace-account balance after this event.
    pub grace_account_balance_cents: i64,
}

/// The co-op's grace account: a running balance of grace charges, plus the
/// mirror running total of member credits. The two must always net to zero.
#[derive(Debug, Default)]
pub struct GraceAccount {
    balance_cents: i64,
    customer_credits_cents: i64,
}

impl GraceAccount {
    /// A new, empty grace account.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The co-op grace-account balance (sum of charges).
    #[must_use]
    pub fn balance_cents(&self) -> i64 {
        self.balance_cents
    }

    /// The running total of member credits (negative). Balances against
    /// [`GraceAccount::balance_cents`] — the two always sum to zero (each event
    /// credits the member `-amount` and charges the account `+amount`), which
    /// callers assert directly (`balance_cents() + customer_credits_cents() == 0`).
    #[must_use]
    pub fn customer_credits_cents(&self) -> i64 {
        self.customer_credits_cents
    }

    /// Record a grace event: credit the member (`-amount`), charge the co-op
    /// grace account (`+amount`), and append a **co-signed** `grace-event` entry
    /// to the provider ledger. `cosigners` are the two parties whose signatures
    /// the entry carries (the co-op + the member). Returns the recorded event.
    ///
    /// # Panics
    ///
    /// Panics only if `amount_cents` exceeds `i64::MAX` or the event cannot be
    /// represented as JSON — both impossible for a cents amount, so these are
    /// unreachable paths.
    pub fn record_event(
        &mut self,
        ledger: &mut Ledger,
        ts: &str,
        reason_code: &str,
        amount_cents: u64,
        note: &str,
        cosigners: &[Signer<'_>; 2],
    ) -> GraceEvent {
        let amount = i64::try_from(amount_cents).expect("grace amount (cents) fits i64");
        self.customer_credits_cents -= amount;
        self.balance_cents += amount;
        let event = GraceEvent {
            reason_code: reason_code.to_owned(),
            amount_cents,
            note: note.to_owned(),
            customer_credit_cents: -amount,
            grace_account_charge_cents: amount,
            grace_account_balance_cents: self.balance_cents,
        };
        let body = serde_json::to_value(&event).expect("GraceEvent is always JSON-representable");
        ledger.append(GRACE_EVENT_KIND, ts, body, cosigners);
        event
    }
}

#[cfg(test)]
mod tests {
    use super::{GraceAccount, GRACE_EVENT_KIND};
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;
    use crate::ledger::{Ledger, Signer};

    #[test]
    fn a_grace_event_nets_to_zero_and_appends_a_cosigned_entry() {
        let provider = derive_keypair("m", "p");
        let pid = derive_id(&provider.verifying_key());
        let customer = derive_keypair("m", "c");
        let cid = derive_id(&customer.verifying_key());
        let mut ledger = Ledger::new(&pid);
        let mut grace = GraceAccount::new();

        let ev = grace.record_event(
            &mut ledger,
            "t",
            "WAIVER",
            25,
            "note",
            &[Signer::new(&pid, &provider), Signer::new(&cid, &customer)],
        );
        assert_eq!(ev.customer_credit_cents, -25);
        assert_eq!(ev.grace_account_charge_cents, 25);
        assert_eq!(ev.amount_cents, 25);
        assert_eq!(grace.balance_cents(), 25);
        assert_eq!(grace.customer_credits_cents(), -25);
        assert_eq!(
            grace.balance_cents() + grace.customer_credits_cents(),
            0,
            "credit and charge net to zero",
        );
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].kind, GRACE_EVENT_KIND);
        assert_eq!(
            ledger.entries()[0].sigs.len(),
            2,
            "co-signed by both parties"
        );
    }

    #[test]
    fn multiple_events_accumulate_and_still_net_to_zero() {
        let provider = derive_keypair("m", "p");
        let pid = derive_id(&provider.verifying_key());
        let customer = derive_keypair("m", "c");
        let cid = derive_id(&customer.verifying_key());
        let mut ledger = Ledger::new(&pid);
        let mut grace = GraceAccount::new();
        for _ in 0..4 {
            grace.record_event(
                &mut ledger,
                "t",
                "HOLD",
                40,
                "n",
                &[Signer::new(&pid, &provider), Signer::new(&cid, &customer)],
            );
        }
        assert_eq!(grace.balance_cents(), 160);
        assert_eq!(grace.customer_credits_cents(), -160);
        assert_eq!(grace.balance_cents() + grace.customer_credits_cents(), 0);
    }
}
