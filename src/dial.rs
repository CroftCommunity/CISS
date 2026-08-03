//! The dial — assurance is a declared setting with a true, linear cost. Audit
//! tiers (monthly/weekly/daily/hourly, each at some `k`) are priced from the E5
//! cost model (bytes read per audit) plus a fixed per-audit overhead; the
//! customer's chosen tier is recorded as a **signed ledger declaration**; audit
//! cost is linear in the audit count (no volume discount, no penalty); and a
//! mid-period dial change pro-rates to the sum of its two legs. No judgment is
//! encoded either way — your paranoia, your bill.
//!
//! Ports `item-storage-protocol-standalone/src/exp/e6_dial.ts` (the dial logic;
//! the standalone has no `dial.ts` src module — pricing lives in `pricing.ts`).

use serde::{Deserialize, Serialize};

use crate::ledger::{Ledger, Signer};
use crate::pricing::audit_cents;

/// An audit assurance tier: a name, the items sampled per audit (`k`), and how
/// many audits run per period.
#[derive(Debug, Clone)]
pub struct Tier {
    /// The tier's name (e.g. `"monthly"`, `"daily"`).
    pub name: String,
    /// Items sampled per audit.
    pub k: u64,
    /// Number of audits run per period at this tier.
    pub audits_per_period: u64,
}

impl Tier {
    /// A tier from its name, per-audit sample size, and audits-per-period.
    #[must_use]
    pub fn new(name: &str, k: u64, audits_per_period: u64) -> Self {
        Self {
            name: name.to_owned(),
            k,
            audits_per_period,
        }
    }
}

/// Cost in cents of a single audit at sample size `k`, given the representative
/// bytes read per audited item (`k * avg_item_bytes` bytes, at cost).
#[must_use]
pub fn per_audit_cents(k: u64, avg_item_bytes: u64) -> u64 {
    audit_cents(k * avg_item_bytes, 1)
}

/// Cost in cents of running a tier for one period: `audits_per_period` audits,
/// each priced at [`per_audit_cents`] — linear in the count, by construction.
#[must_use]
pub fn tier_cost(tier: &Tier, avg_item_bytes: u64) -> u64 {
    tier.audits_per_period * per_audit_cents(tier.k, avg_item_bytes)
}

/// Pro-rate an audits-per-period rate over `days` of a `period_days` period,
/// rounding half up (integer math). Used when the dial changes mid-period.
///
/// # Panics
///
/// Panics if `period_days` is 0 (a zero-length period has no rate to pro-rate);
/// callers use whole billing periods, so this is an unreachable path.
#[must_use]
pub fn audits_for(audits_per_period: u64, days: u64, period_days: u64) -> u64 {
    assert!(period_days > 0, "period_days must be positive");
    (audits_per_period * days + period_days / 2) / period_days
}

/// A customer's chosen-tier declaration — the signed record that says "this is
/// the assurance I asked for, and its price is mine to pay".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialDeclaration {
    /// The chosen tier's name.
    pub tier: String,
    /// Items sampled per audit at the chosen tier.
    pub k: u64,
    /// Audits per period at the chosen tier.
    pub audits_per_period: u64,
}

impl DialDeclaration {
    /// The declaration for a chosen [`Tier`].
    #[must_use]
    pub fn from_tier(tier: &Tier) -> Self {
        Self {
            tier: tier.name.clone(),
            k: tier.k,
            audits_per_period: tier.audits_per_period,
        }
    }

    /// The declaration as a ledger-entry body.
    ///
    /// # Panics
    ///
    /// Panics only if the declaration cannot be represented as JSON — impossible
    /// for these plain string/integer fields, so this is an unreachable path.
    #[must_use]
    pub fn to_body(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("DialDeclaration is always JSON-representable")
    }
}

/// Append the customer's chosen tier to their ledger as a signed
/// `"dial-declaration"` entry — the tier is a declaration, recorded and signed.
pub fn declare_tier(ledger: &mut Ledger, tier: &Tier, ts: &str, signer: Signer<'_>) {
    let declaration = DialDeclaration::from_tier(tier);
    ledger.append("dial-declaration", ts, declaration.to_body(), &[signer]);
}

#[cfg(test)]
mod tests {
    use super::{audits_for, per_audit_cents, tier_cost, DialDeclaration, Tier};

    #[test]
    fn cost_is_exactly_linear_in_audit_count() {
        let one = Tier::new("one", 5, 1);
        let four = Tier::new("four", 5, 4);
        assert_eq!(tier_cost(&four, 256), 4 * tier_cost(&one, 256));
    }

    #[test]
    fn per_audit_cost_tracks_k() {
        assert_eq!(per_audit_cents(5, 256), 3); // floor(1280/1000)+2
        assert_eq!(per_audit_cents(20, 256), 7); // floor(5120/1000)+2
    }

    #[test]
    fn prorate_rounds_half_up_by_days() {
        assert_eq!(audits_for(4, 15, 30), 2); // round(2.0)
        assert_eq!(audits_for(30, 15, 30), 15); // round(15.0)
        assert_eq!(audits_for(1, 15, 30), 1); // round(0.5) half up → 1
        assert_eq!(audits_for(1, 14, 30), 0); // round(0.466…) → 0
    }

    #[test]
    fn declaration_round_trips_through_json() {
        let tier = Tier::new("daily", 20, 30);
        let decl = DialDeclaration::from_tier(&tier);
        let back: DialDeclaration = serde_json::from_value(decl.to_body()).expect("round-trips");
        assert_eq!(back.tier, "daily");
        assert_eq!(back.k, 20);
        assert_eq!(back.audits_per_period, 30);
    }
}
