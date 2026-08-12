//! Dial kinds on the self-assertion substrate (dials plan D2+): customer
//! settings with teeth. Each dial is a kind — a typed body, a canonical
//! fold, structural validation — riding the substrate's envelope
//! (signatures, Model A/C, seq anti-rollback, the provider ack).
//!
//! D2 ships the **ceiling dial**'s at-rest half: the customer's own storage
//! limit. Provider limits supersede (a dial above `min(store_ceiling,
//! did_cap)` is refused at set with the bound quoted), enforcement is
//! always `min(provider bounds, dial)` at the existing quota gate, and
//! reads are never touched (B6 — a cap throttles new spending, it never
//! holds data hostage). The spend-period fields arrive with D3.

use serde::{Deserialize, Serialize};

use crate::kind_spec::{
    Authorship, Enumeration, Erasure, Growth, HashAlgorithm, HashPosture, Hashing, KindSpec,
    Retention, Sizing, SMALL_BODY_CEILING_BYTES,
};

/// The shared six-axis point for every dial kind (ADR 0005, §5a): a customer's
/// latest-wins setting (`Setting`), superseded by a new seq rather than deleted
/// (`Permanent`), addressed by its fixed kind tag rather than listed
/// (`PointOnly`), fold-bound over SHA-256, with a small fixed-shape body.
const fn dial_spec(kind: &'static str) -> KindSpec {
    KindSpec {
        kind,
        retention: Retention::Setting,
        authorship: Authorship::OwnerSigned,
        erasure: Erasure::Permanent,
        enumeration: Enumeration::PointOnly,
        hashing: Hashing { posture: HashPosture::FoldBound, algorithm: HashAlgorithm::Sha256 },
        sizing: Sizing { body_ceiling: SMALL_BODY_CEILING_BYTES, growth: Growth::Bounded },
    }
}

/// The assertion kind tag for the ceiling dial. Dotted (not slashed): kind
/// tags ride URL path segments.
pub const CEILING_DIAL_KIND: &str = "dial.ceiling";

/// The ceiling dial's six-axis declaration.
pub const CEILING_DIAL_SPEC: KindSpec = dial_spec(CEILING_DIAL_KIND);

/// The ceiling dial's body: the at-rest half (D2) and the spend-period
/// half (D3). Either may be `None` — clearing is itself a signed, seq'd
/// dial, so absence of enforcement is only ever customer-authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeilingDialBody {
    /// The customer's asserted at-rest cap in bytes.
    pub at_rest_bytes: Option<u64>,
    /// The customer's asserted per-period postage cap in integer cents
    /// (the transfer threshold — the user's decision: the ceiling caps
    /// transfer; at-rest is the separate half above). Enforced by
    /// comparison-before-serving on billable writes; owner egress is
    /// served and billed past it, never refused (B6).
    pub spend_cents: Option<u64>,
}

/// The canonical fold of a ceiling dial body.
#[must_use]
pub fn ceiling_body_fold(body: &CeilingDialBody) -> String {
    let fold_opt = |v: Option<u64>| v.map_or("none".to_owned(), |v| v.to_string());
    format!(
        "at_rest_bytes={};spend_cents={}",
        fold_opt(body.at_rest_bytes),
        fold_opt(body.spend_cents)
    )
}

/// The period dial kind: an empty-bodied, signed "start a new spend period"
/// marker. Acceptance snapshots the meter's cumulative total as the new
/// period's baseline — a monotonic byte-count marker, never a clock (the
/// standing rule: timestamps are reference, monotonic values are
/// authority). The dial's own seq is the period ordinal.
pub const PERIOD_DIAL_KIND: &str = "dial.period";

/// The period dial's six-axis declaration.
pub const PERIOD_DIAL_SPEC: KindSpec = dial_spec(PERIOD_DIAL_KIND);

/// The period dial's canonical fold (the body is `{}` — the assertion's
/// own did/kind/seq carry all the meaning).
pub const PERIOD_BODY_FOLD: &str = "new_period";

/// The account-mode dial kind (D3, the drawdown refinement): `drawdown`
/// closes the books — no new blobs, keep-set commits only with a
/// non-increasing total (draining reduces rent on the way out) — while
/// egress stays served and fully metered. Reversible by dial (user
/// ruling): every transition is a signed, seq'd record, and a re-enabled
/// account is responsible again. The monotonic period-gate (no re-open
/// within the declaring period) is held in reserve for when privileges
/// attach.
pub const ACCOUNT_MODE_DIAL_KIND: &str = "dial.account-mode";

/// The account-mode dial's six-axis declaration.
pub const ACCOUNT_MODE_DIAL_SPEC: KindSpec = dial_spec(ACCOUNT_MODE_DIAL_KIND);

/// The two account modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountMode {
    /// Normal operation.
    Active,
    /// Books closed to new writes; egress served and metered.
    Drawdown,
}

/// The account-mode dial's body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountModeBody {
    /// The asserted mode.
    pub mode: AccountMode,
}

/// The canonical fold of an account-mode body.
#[must_use]
pub fn account_mode_body_fold(body: &AccountModeBody) -> String {
    match body.mode {
        AccountMode::Active => "mode=active".to_owned(),
        AccountMode::Drawdown => "mode=drawdown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fold distinguishes every state: distinct values, set-vs-clear,
    /// and the two halves independently.
    #[test]
    fn fold_binds_the_cap() {
        let f = |a, s| ceiling_body_fold(&CeilingDialBody { at_rest_bytes: a, spend_cents: s });
        assert_ne!(f(Some(1_500), None), f(Some(1_501), None), "the at-rest value is bound");
        assert_ne!(f(Some(1_500), None), f(None, None), "set vs cleared is bound");
        assert_ne!(f(None, Some(2)), f(None, Some(3)), "the spend value is bound");
        assert_ne!(f(Some(2), None), f(None, Some(2)), "the halves are distinct");
        assert_eq!(f(None, None), "at_rest_bytes=none;spend_cents=none");
    }

    /// The mode fold binds the mode; the two modes are distinct.
    #[test]
    fn mode_fold_binds() {
        assert_ne!(
            account_mode_body_fold(&AccountModeBody { mode: AccountMode::Active }),
            account_mode_body_fold(&AccountModeBody { mode: AccountMode::Drawdown }),
        );
    }
}

/// The receipt-mode dial kind (D4): `bilateral` is opt-in by customer
/// assertion — and seq'd, so the provider can never silently revert a
/// customer to unilateral (the E89 mode-change-only-with-customer-signature
/// rule, structural). With bilateral in force, every metered transfer's
/// receipt awaits the customer's countersignature; a completed receipt is
/// a doubly-signed fact neither side can dispute.
pub const RECEIPT_MODE_DIAL_KIND: &str = "dial.receipt-mode";

/// The receipt-mode dial's six-axis declaration.
pub const RECEIPT_MODE_DIAL_SPEC: KindSpec = dial_spec(RECEIPT_MODE_DIAL_KIND);

/// The two receipt modes a customer may assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptModeChoice {
    /// Provider-signed only (the default).
    Unilateral,
    /// Co-signed by both parties.
    Bilateral,
}

/// The receipt-mode dial's body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptModeBody {
    /// The asserted mode.
    pub mode: ReceiptModeChoice,
}

/// The canonical fold of a receipt-mode body.
#[must_use]
pub fn receipt_mode_body_fold(body: &ReceiptModeBody) -> String {
    match body.mode {
        ReceiptModeChoice::Unilateral => "mode=unilateral".to_owned(),
        ReceiptModeChoice::Bilateral => "mode=bilateral".to_owned(),
    }
}
