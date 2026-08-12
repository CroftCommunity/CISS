//! Balance-forward statements + the byte-day rent integrator + the rollup/purge
//! boundary. Each period closes into a co-signed statement (opening root,
//! closing root, byte-day rent, postage, …) that chains to the previous by hash,
//! so last period is agreed and this period only has to explain the change; any
//! edit to a historical figure breaks the chain at exactly that link.
//!
//! Ports `item-storage-protocol-standalone/src/statement.ts` + the world's
//! byte-day timeline (`world.ts` `byteDays`), and adds the rollup/purge boundary.

use serde::{Deserialize, Serialize};

use crate::canonical::to_canonical_bytes;
use crate::crypto::sha256_hex;
use crate::receipts::Receipt;

/// The `prev_statement_hash` of the first statement (64 hex zeros).
pub const GENESIS_STATEMENT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Bytes-at-rest over time, as a step function: rent is the integral of this
/// over a period. Points are recorded in day order (time only advances).
#[derive(Debug, Default)]
pub struct RentTimeline {
    points: Vec<(u64, u64)>,
}

impl RentTimeline {
    /// A new, empty timeline (bytes-at-rest is 0 until the first point).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that bytes-at-rest became `total` as of `day` (a step change).
    pub fn set_bytes_at_rest(&mut self, day: u64, total: u64) {
        if let Some(last) = self.points.last_mut() {
            if last.0 == day {
                last.1 = total;
                return;
            }
        }
        self.points.push((day, total));
    }

    /// Bytes-at-rest on `day` — the last recorded total at or before it.
    #[must_use]
    pub fn bytes_at_rest_on(&self, day: u64) -> u64 {
        let mut current = 0;
        for &(d, total) in &self.points {
            if d <= day {
                current = total;
            } else {
                break;
            }
        }
        current
    }

    /// Integrate byte-days over `[start, end)` — the rent base for a period.
    #[must_use]
    pub fn byte_days(&self, start: u64, end: u64) -> u64 {
        (start..end).map(|d| self.bytes_at_rest_on(d)).sum()
    }
}

/// The signed content of a period-closing statement. All money is integer cents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementBody {
    /// Period number (0-based; equals its chain position).
    pub period: u64,
    /// First day of the period (inclusive).
    pub period_start_day: u64,
    /// Last day of the period (exclusive).
    pub period_end_day: u64,
    /// Manifest root at the period's open.
    pub opening_root: String,
    /// Manifest root at the period's close.
    pub closing_root: String,
    /// Byte-days at rest over the period (the rent base).
    pub byte_days: u64,
    /// Rent for the period, in cents.
    pub rent_cents: u64,
    /// Bytes transferred (postage base) in the period.
    pub postage_bytes: u64,
    /// Postage for the period, in cents.
    pub postage_cents: u64,
    /// Number of audits in the period (Phase 5; 0 until then).
    pub audit_count: u64,
    /// Bytes read for audits in the period (Phase 5; 0 until then).
    pub audit_bytes: u64,
    /// Audit cost in cents (Phase 5; 0 until then).
    pub audit_cents: u64,
    /// The audit tier chosen (Phase 5; `"none"` until then).
    pub audit_tier: String,
    /// Grace credited in the period, in cents. A credit, so **negative** (or 0);
    /// e.g. a waived fee books `fees_cents: +f` and `grace_cents: -f`, netting to
    /// zero on the member's bill (see `grace.rs` / E9).
    pub grace_cents: i64,
    /// Other fees in the period, in cents.
    pub fees_cents: u64,
    /// The period total, in cents.
    pub total_cents: u64,
    /// The hash of the previous statement (or [`GENESIS_STATEMENT`]).
    pub prev_statement_hash: String,
}

/// A built statement: its body plus the hash over the body's canonical form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    body: StatementBody,
    hash: String,
}

impl Statement {
    /// The signed body.
    #[must_use]
    pub fn body(&self) -> &StatementBody {
        &self.body
    }

    /// The hash over the canonical body.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Reconstruct from parts (e.g. read back from storage/wire). `verify_chain`
    /// re-derives the hash, so a reconstruction with an edited body will not pass.
    #[must_use]
    pub fn from_parts(body: StatementBody, hash: String) -> Self {
        Self { body, hash }
    }
}

/// Build a statement: hash the canonical body.
#[must_use]
pub fn build_statement(body: StatementBody) -> Statement {
    let hash = sha256_hex(&to_canonical_bytes(&body));
    Statement { body, hash }
}

/// The outcome of verifying a statement chain.
#[derive(Debug, Clone)]
pub enum ChainResult {
    /// The chain verifies from genesis to head.
    Ok,
    /// The chain broke at position `at`, for `reason`.
    Failed {
        /// The chain position that failed.
        at: usize,
        /// Why it failed.
        reason: String,
    },
}

impl ChainResult {
    /// Whether the chain verified.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, ChainResult::Ok)
    }

    /// The position that failed, if any.
    #[must_use]
    pub fn failed_at(&self) -> Option<usize> {
        match self {
            ChainResult::Failed { at, .. } => Some(*at),
            ChainResult::Ok => None,
        }
    }
}

/// Verify the statement chain from genesis, reporting the exact link that fails:
/// each statement's `prev_statement_hash` must link to the prior hash, its body
/// must still hash to its `hash`, and its `period` must equal its position.
#[must_use]
pub fn verify_chain(statements: &[Statement]) -> ChainResult {
    let mut expected_prev = GENESIS_STATEMENT.to_owned();
    for (i, statement) in statements.iter().enumerate() {
        if statement.body.prev_statement_hash != expected_prev {
            return ChainResult::Failed {
                at: i,
                reason: "prev_statement_hash breaks the chain".to_owned(),
            };
        }
        let recomputed = sha256_hex(&to_canonical_bytes(&statement.body));
        if recomputed != statement.hash {
            return ChainResult::Failed {
                at: i,
                reason: "statement body edited (hash mismatch)".to_owned(),
            };
        }
        if usize::try_from(statement.body.period) != Ok(i) {
            return ChainResult::Failed {
                at: i,
                reason: "period number out of sequence".to_owned(),
            };
        }
        expected_prev.clone_from(&statement.hash);
    }
    ChainResult::Ok
}

/// Rollup/purge boundary: drop every receipt whose day is within a **settled**
/// (co-signed) period — i.e. strictly before `settled_through_day`. The signed
/// statement chain carries that period's rolled-up totals, so the granular
/// receipts are no longer needed; this bounds the store's growth. Returns the
/// number of receipts purged.
pub fn purge_receipts_settled_through(
    receipts: &mut Vec<Receipt>,
    settled_through_day: u64,
) -> usize {
    let before = receipts.len();
    receipts.retain(|r| r.core().day >= settled_through_day);
    before - receipts.len()
}

#[cfg(test)]
mod tests {
    use super::{
        build_statement, purge_receipts_settled_through, verify_chain, RentTimeline, Statement,
        StatementBody, GENESIS_STATEMENT,
    };
    use crate::crypto::derive_keypair;
    use crate::receipts::{make_bilateral_receipt, Direction, ReceiptCore};

    #[test]
    fn byte_days_integrates_a_step_function() {
        let mut t = RentTimeline::new();
        assert_eq!(t.bytes_at_rest_on(0), 0, "zero before the first point");
        t.set_bytes_at_rest(0, 100);
        t.set_bytes_at_rest(10, 200); // step up mid-window
                                      // [0,10): 100/day = 1000; [10,20): 200/day = 2000 → 3000 over [0,20)
        assert_eq!(t.byte_days(0, 20), 3000);
        assert_eq!(t.byte_days(0, 10), 1000);
        assert_eq!(t.byte_days(10, 20), 2000);
        assert_eq!(t.byte_days(5, 5), 0, "empty window is zero");
    }

    fn body(period: u64, prev: &str) -> StatementBody {
        StatementBody {
            period,
            period_start_day: period * 30,
            period_end_day: period * 30 + 30,
            opening_root: "r".to_owned(),
            closing_root: "r".to_owned(),
            byte_days: 0,
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
        }
    }

    #[test]
    fn a_clean_chain_verifies() {
        let s0 = build_statement(body(0, GENESIS_STATEMENT));
        let s1 = build_statement(body(1, s0.hash()));
        assert!(verify_chain(&[s0, s1]).is_ok());
    }

    #[test]
    fn a_broken_prev_link_fails_at_that_position() {
        let s0 = build_statement(body(0, GENESIS_STATEMENT));
        let s1 = build_statement(body(1, "not-s0-hash"));
        let r = verify_chain(&[s0, s1]);
        assert!(!r.is_ok());
        assert_eq!(r.failed_at(), Some(1));
    }

    #[test]
    fn an_edited_body_with_stale_hash_fails() {
        let s0 = build_statement(body(0, GENESIS_STATEMENT));
        let mut edited_body = s0.body().clone();
        edited_body.rent_cents += 1;
        let edited = Statement::from_parts(edited_body, s0.hash().to_owned());
        let r = verify_chain(&[edited]);
        assert!(!r.is_ok());
        assert_eq!(r.failed_at(), Some(0));
    }

    #[test]
    fn an_out_of_sequence_period_fails() {
        let s0 = build_statement(body(0, GENESIS_STATEMENT));
        let s_bad = build_statement(body(5, s0.hash())); // period 5 at position 1
        let r = verify_chain(&[s0, s_bad]);
        assert!(!r.is_ok());
        assert_eq!(r.failed_at(), Some(1));
    }

    #[test]
    fn purge_drops_settled_receipts_only() {
        let receiver = derive_keypair("m", "r");
        let sender = derive_keypair("m", "s");
        let mut receipts = vec![
            make_bilateral_receipt(
                ReceiptCore::new(Direction::Upload, "c1", (0, 10), 10, 5, crate::dials::AccountMode::Active, "r", "s"),
                Some(&receiver),
                &sender,
            ),
            make_bilateral_receipt(
                ReceiptCore::new(Direction::Upload, "c2", (0, 10), 10, 40, crate::dials::AccountMode::Active, "r", "s"),
                Some(&receiver),
                &sender,
            ),
        ];
        let purged = purge_receipts_settled_through(&mut receipts, 30);
        assert_eq!(purged, 1, "the day-5 receipt is settled and purged");
        assert_eq!(receipts.len(), 1);
        assert!(receipts.iter().all(|r| r.core().day >= 30));
    }
}
