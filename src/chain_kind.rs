//! The `chain.counter` kind (ADR 0005, phase A3): an **append-only accounting
//! chain**. Where `kv.counter` was a latest-wins slot (a compromised writer could
//! silently rewrite the running total), a chain records every step as a linked
//! entry — `{delta, total, prev_entry_hash}` — and verifies at write time that
//! the new total follows its predecessor and that it names its predecessor's
//! hash. History is a tamper-evident line, not a mutable cell: altering any past
//! entry changes its hash, which the next entry recorded, so the break is
//! detectable by recomputation.
//!
//! This is money-shaped code. The verification path is held to the
//! no-unexplained-survivors mutation policy (CLAUDE.md): a mutant that flips a
//! comparison or drops a link must be caught by a test.
//!
//! Retention is `Chain`, so erasure is `Permanent` by the ADR 0005 invariant (a
//! `Chain` + `Erasable` spec fails the build). Compaction behind acknowledged
//! checkpoints is A4; A3 is the plain, unbounded-until-checkpoint chain.

use serde::{Deserialize, Serialize};

use crate::crypto::sha256_hex;
use crate::kind_spec::{
    Authorship, Enumeration, Erasure, Growth, HashAlgorithm, HashPosture, Hashing, KindSpec,
    Retention, Sizing, SMALL_BODY_CEILING_BYTES,
};

/// The chain-counter kind tag.
pub const CHAIN_COUNTER_KIND: &str = "chain.counter";

/// The predecessor hash a first (genesis) entry names: 64 zero hex chars. A
/// genesis entry starts the chain from total 0, so `total == delta` and it links
/// to nothing.
pub const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// `chain.counter`'s six-axis declaration (ADR 0005 / §5a): an append-only
/// (`Chain`), owner-signed, permanent, listable accounting line, hash-linked over
/// SHA-256, rolling (compaction behind acknowledged checkpoints, A4).
pub const CHAIN_COUNTER_SPEC: KindSpec = KindSpec {
    kind: CHAIN_COUNTER_KIND,
    retention: Retention::Chain,
    authorship: Authorship::OwnerSigned,
    erasure: Erasure::Permanent,
    enumeration: Enumeration::Listable,
    hashing: Hashing { posture: HashPosture::ChainLinked, algorithm: HashAlgorithm::Sha256 },
    sizing: Sizing { body_ceiling: SMALL_BODY_CEILING_BYTES, growth: Growth::Rolling },
};

/// A `chain.counter` entry body: a signed step in the running total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainCounterBody {
    /// The signed change applied by this entry. May be negative (a correction).
    pub delta: i64,
    /// The running total **after** applying `delta`: `prev.total + delta`
    /// (`delta` alone at genesis). A `u64` — a chain can never carry a negative
    /// total, so a `delta` that would drive it below zero is refused.
    pub total: u64,
    /// The [`entry_hash`] of this entry's predecessor, or [`GENESIS_PREV_HASH`]
    /// for the first entry. This is the link that makes the chain tamper-evident.
    pub prev_entry_hash: String,
}

/// The canonical fold of a chain-counter body — what the assertion signature
/// binds beyond the substrate's did/kind/subkey/seq.
#[must_use]
pub fn chain_counter_body_fold(body: &ChainCounterBody) -> String {
    format!("delta={};total={};prev={}", body.delta, body.total, body.prev_entry_hash)
}

/// The hash of a chain entry — the value its successor records as
/// `prev_entry_hash`. Binds the entry's full identity (route + seq + body), so
/// altering any field of a stored entry changes this hash and breaks the link
/// the next entry recorded. SHA-256 (the declared algorithm), hex-encoded.
#[must_use]
pub fn entry_hash(did: &str, kind: &str, subkey: Option<&str>, seq: u64, body: &ChainCounterBody) -> String {
    let preimage = format!(
        "{did}|{kind}|{}|{seq}|delta={};total={};prev={}",
        subkey.unwrap_or(""),
        body.delta,
        body.total,
        body.prev_entry_hash
    );
    sha256_hex(preimage.as_bytes())
}

/// Why a proposed entry does not continue the stored chain — the precise,
/// value-quoting reason returned to the customer (never a bare "invalid").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreak {
    /// The entry's `seq` is not the successor's (`expected` = prev seq + 1).
    Seq {
        /// The seq a valid successor must carry.
        expected: u64,
        /// The seq the entry actually carried.
        got: u64,
    },
    /// The entry's `total` does not equal `prev.total + delta`.
    Total {
        /// The predecessor's total (0 at genesis).
        prev_total: u64,
        /// The entry's asserted delta.
        delta: i64,
        /// The total the entry must carry (`prev_total + delta`, in `i128` so a
        /// below-zero result is representable rather than wrapping).
        expected: i128,
        /// The total the entry actually carried.
        got: u64,
    },
    /// The entry names the wrong predecessor hash.
    PrevHash {
        /// The current chain head's hash a valid successor must name.
        expected: String,
        /// The predecessor hash the entry actually named.
        got: String,
    },
}

impl ChainBreak {
    /// A one-line reason quoting the real values (for the refusal message).
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            ChainBreak::Seq { expected, got } => {
                format!("seq {got} is not the next entry (expected {expected})")
            }
            ChainBreak::Total { prev_total, delta, expected, got } => format!(
                "total {got} does not follow: prev {prev_total} + delta {delta} = {expected}"
            ),
            ChainBreak::PrevHash { expected, got } => {
                format!("prev_entry_hash {got} does not match the chain head {expected}")
            }
        }
    }
}

/// The minimal view of the stored predecessor a verification step needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevEntry {
    /// The predecessor's sequence number.
    pub seq: u64,
    /// The predecessor's running total.
    pub total: u64,
    /// The predecessor's [`entry_hash`] — what a valid successor must name.
    pub entry_hash: String,
}

/// Verify that `body` at `seq` legitimately continues the chain whose current
/// head is `prev` (`None` at genesis). The three invariants, each refused with
/// its real values: contiguous seq, `total == prev.total + delta`, and a correct
/// predecessor-hash link.
///
/// # Errors
/// Returns the specific [`ChainBreak`] the entry violates.
pub fn verify_step(prev: Option<&PrevEntry>, body: &ChainCounterBody, seq: u64) -> Result<(), ChainBreak> {
    let (expected_seq, prev_total, expected_prev_hash) = match prev {
        None => (1, 0u64, GENESIS_PREV_HASH.to_owned()),
        Some(p) => (p.seq + 1, p.total, p.entry_hash.clone()),
    };
    if seq != expected_seq {
        return Err(ChainBreak::Seq { expected: expected_seq, got: seq });
    }
    if body.prev_entry_hash != expected_prev_hash {
        return Err(ChainBreak::PrevHash { expected: expected_prev_hash, got: body.prev_entry_hash.clone() });
    }
    let expected_total = i128::from(prev_total) + i128::from(body.delta);
    if i128::from(body.total) != expected_total {
        return Err(ChainBreak::Total {
            prev_total,
            delta: body.delta,
            expected: expected_total,
            got: body.total,
        });
    }
    Ok(())
}

/// A full chain entry as recomputation sees it (route identity + body), so the
/// recompute can re-derive each hash link independently of what was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEntry {
    /// The owning DID.
    pub did: String,
    /// The kind tag.
    pub kind: String,
    /// The subkey (the account this chain totals).
    pub subkey: Option<String>,
    /// The entry sequence.
    pub seq: u64,
    /// The entry body.
    pub body: ChainCounterBody,
}

/// Recompute a chain from its entries (seq-ordered), returning the verified final
/// total. Independently re-derives every hash link and re-adds every delta, so a
/// tampered stored entry — a changed total, a re-pointed link — is caught here
/// even though it passed verification when it was written. This is the audit the
/// `ciss usage` command and the tests run.
///
/// # Errors
/// Returns the first [`ChainBreak`] the recomputation finds, or `Seq` for an
/// empty chain queried as if non-empty is not an error — an empty chain has total 0.
pub fn recompute_total(entries: &[ChainEntry]) -> Result<u64, ChainBreak> {
    let mut prev: Option<PrevEntry> = None;
    for entry in entries {
        verify_step(prev.as_ref(), &entry.body, entry.seq)?;
        let hash = entry_hash(&entry.did, &entry.kind, entry.subkey.as_deref(), entry.seq, &entry.body);
        prev = Some(PrevEntry { seq: entry.seq, total: entry.body.total, entry_hash: hash });
    }
    Ok(prev.map_or(0, |p| p.total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(delta: i64, total: u64, prev: &str) -> ChainCounterBody {
        ChainCounterBody { delta, total, prev_entry_hash: prev.to_owned() }
    }

    #[test]
    fn genesis_starts_from_zero_and_links_to_the_sentinel() {
        assert!(verify_step(None, &body(100, 100, GENESIS_PREV_HASH), 1).is_ok());
        // Wrong genesis total (not == delta).
        assert_eq!(
            verify_step(None, &body(100, 101, GENESIS_PREV_HASH), 1),
            Err(ChainBreak::Total { prev_total: 0, delta: 100, expected: 100, got: 101 })
        );
        // Genesis must link to the sentinel.
        assert!(matches!(
            verify_step(None, &body(100, 100, "dead"), 1),
            Err(ChainBreak::PrevHash { .. })
        ));
        // Genesis is seq 1.
        assert_eq!(
            verify_step(None, &body(100, 100, GENESIS_PREV_HASH), 2),
            Err(ChainBreak::Seq { expected: 1, got: 2 })
        );
    }

    #[test]
    fn a_successor_must_follow_total_seq_and_link() {
        let g = body(100, 100, GENESIS_PREV_HASH);
        let ghash = entry_hash("did:x", CHAIN_COUNTER_KIND, Some("acct"), 1, &g);
        let prev = PrevEntry { seq: 1, total: 100, entry_hash: ghash.clone() };

        // A correct successor: +50 → 150, links to ghash, seq 2.
        assert!(verify_step(Some(&prev), &body(50, 150, &ghash), 2).is_ok());
        // A signed correction (negative delta) that keeps the invariant.
        assert!(verify_step(Some(&prev), &body(-40, 60, &ghash), 2).is_ok());
        // Wrong total.
        assert_eq!(
            verify_step(Some(&prev), &body(50, 999, &ghash), 2),
            Err(ChainBreak::Total { prev_total: 100, delta: 50, expected: 150, got: 999 })
        );
        // Wrong prev hash (a fork off a forged head).
        assert!(matches!(
            verify_step(Some(&prev), &body(50, 150, "beef"), 2),
            Err(ChainBreak::PrevHash { .. })
        ));
        // A gap or a re-used seq.
        assert_eq!(
            verify_step(Some(&prev), &body(50, 150, &ghash), 5),
            Err(ChainBreak::Seq { expected: 2, got: 5 })
        );
    }

    #[test]
    fn a_delta_below_zero_total_is_a_total_break_not_a_panic() {
        let g = body(10, 10, GENESIS_PREV_HASH);
        let ghash = entry_hash("did:x", CHAIN_COUNTER_KIND, Some("acct"), 1, &g);
        let prev = PrevEntry { seq: 1, total: 10, entry_hash: ghash.clone() };
        // delta -50 from total 10 → -40, which a u64 total can never equal.
        assert_eq!(
            verify_step(Some(&prev), &body(-50, 0, &ghash), 2),
            Err(ChainBreak::Total { prev_total: 10, delta: -50, expected: -40, got: 0 })
        );
    }

    #[test]
    fn recompute_walks_the_whole_chain_and_catches_tampering() {
        let mk = |seq, delta, total, prev: &str| ChainEntry {
            did: "did:x".to_owned(),
            kind: CHAIN_COUNTER_KIND.to_owned(),
            subkey: Some("acct".to_owned()),
            seq,
            body: body(delta, total, prev),
        };
        let e1 = mk(1, 100, 100, GENESIS_PREV_HASH);
        let h1 = entry_hash(&e1.did, &e1.kind, e1.subkey.as_deref(), 1, &e1.body);
        let e2 = mk(2, 50, 150, &h1);
        let h2 = entry_hash(&e2.did, &e2.kind, e2.subkey.as_deref(), 2, &e2.body);
        let e3 = mk(3, -30, 120, &h2);

        assert_eq!(recompute_total(&[e1.clone(), e2.clone(), e3.clone()]), Ok(120));
        assert_eq!(recompute_total(&[]), Ok(0), "an empty chain totals zero");

        // Tamper with e2's total after the fact: recomputation catches it, even
        // though e2 was valid when written (its stored total drove e3's link).
        let mut tampered = e2.clone();
        tampered.body.total = 9_999;
        assert!(matches!(
            recompute_total(&[e1, tampered, e3]),
            Err(ChainBreak::Total { .. })
        ));
    }
}
