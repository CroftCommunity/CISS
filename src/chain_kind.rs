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

/// A **checkpoint** body (ADR 0005 / A4): a signed balance-forward marker. It
/// closes over the chain up to its predecessor — `closing_total` is the running
/// total at that point, `chain_head_hash` is the predecessor's hash (committing
/// transitively to every entry behind it), and `prev_checkpoint` links the prior
/// checkpoint (or [`GENESIS_PREV_HASH`]). Once acknowledged it lets the entries
/// behind it be compacted; verification then walks back only to here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointBody {
    /// The running total this checkpoint closes at (must equal the head entry's).
    pub closing_total: u64,
    /// The [`entry_hash`] of the entry this checkpoint closes over — commits
    /// transitively to the whole compacted prefix.
    pub chain_head_hash: String,
    /// The [`checkpoint_hash`] of the prior checkpoint, or [`GENESIS_PREV_HASH`].
    pub prev_checkpoint: String,
}

/// The canonical fold of a checkpoint body — distinct from a step fold, so a
/// checkpoint can never be reinterpreted as a step (or vice versa).
#[must_use]
pub fn checkpoint_body_fold(body: &CheckpointBody) -> String {
    format!(
        "checkpoint;closing_total={};head={};prev_checkpoint={}",
        body.closing_total, body.chain_head_hash, body.prev_checkpoint
    )
}

/// The hash of a checkpoint entry — what its successor records as
/// `prev_entry_hash` and what a later checkpoint records as `prev_checkpoint`.
/// The `checkpoint;` prefix keeps it disjoint from any [`entry_hash`].
#[must_use]
pub fn checkpoint_hash(did: &str, kind: &str, subkey: Option<&str>, seq: u64, body: &CheckpointBody) -> String {
    let preimage = format!(
        "{did}|{kind}|{}|{seq}|checkpoint;closing_total={};head={};prev_checkpoint={}",
        subkey.unwrap_or(""),
        body.closing_total,
        body.chain_head_hash,
        body.prev_checkpoint
    );
    sha256_hex(preimage.as_bytes())
}

/// A chain write is one of two shapes — a step or a checkpoint — disambiguated by
/// its fields (both `deny_unknown_fields`, so exactly one matches). This is what
/// `chain.counter`'s registry arm parses and what the write path dispatches on.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ChainStep {
    /// A balance-forward checkpoint.
    Checkpoint(CheckpointBody),
    /// An ordinary `{delta, total, prev_entry_hash}` step.
    Step(ChainCounterBody),
}

impl ChainStep {
    /// The canonical fold for whichever shape this is.
    #[must_use]
    pub fn fold(&self) -> String {
        match self {
            ChainStep::Step(b) => chain_counter_body_fold(b),
            ChainStep::Checkpoint(b) => checkpoint_body_fold(b),
        }
    }

    /// Whether this write is a checkpoint.
    #[must_use]
    pub fn is_checkpoint(&self) -> bool {
        matches!(self, ChainStep::Checkpoint(_))
    }
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
    /// A checkpoint's `closing_total` does not equal the running total it closes.
    ClosingTotal {
        /// The chain's running total at the checkpoint's predecessor.
        running_total: u64,
        /// The `closing_total` the checkpoint asserted.
        closing_total: u64,
    },
    /// A checkpoint names the wrong prior checkpoint.
    PrevCheckpoint {
        /// The prior checkpoint's hash a valid checkpoint must name.
        expected: String,
        /// The prior-checkpoint hash the checkpoint actually named.
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
            ChainBreak::ClosingTotal { running_total, closing_total } => format!(
                "checkpoint closing_total {closing_total} does not equal the running total {running_total}"
            ),
            ChainBreak::PrevCheckpoint { expected, got } => {
                format!("prev_checkpoint {got} does not match the prior checkpoint {expected}")
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

/// Verify a checkpoint over the chain whose head is `prev`, given the expected
/// prior-checkpoint hash. The four invariants, each refused with its real values:
/// contiguous seq, a `chain_head_hash` linking the head it closes, a
/// `closing_total` equal to the running total, and a correct prior-checkpoint
/// link. A checkpoint always closes over a real predecessor — an empty chain has
/// nothing to check.
///
/// # Errors
/// Returns the specific [`ChainBreak`] the checkpoint violates.
pub fn verify_checkpoint(
    prev: &PrevEntry,
    expected_prev_checkpoint: &str,
    body: &CheckpointBody,
    seq: u64,
) -> Result<(), ChainBreak> {
    if seq != prev.seq + 1 {
        return Err(ChainBreak::Seq { expected: prev.seq + 1, got: seq });
    }
    if body.chain_head_hash != prev.entry_hash {
        return Err(ChainBreak::PrevHash {
            expected: prev.entry_hash.clone(),
            got: body.chain_head_hash.clone(),
        });
    }
    if body.closing_total != prev.total {
        return Err(ChainBreak::ClosingTotal {
            running_total: prev.total,
            closing_total: body.closing_total,
        });
    }
    if body.prev_checkpoint != expected_prev_checkpoint {
        return Err(ChainBreak::PrevCheckpoint {
            expected: expected_prev_checkpoint.to_owned(),
            got: body.prev_checkpoint.clone(),
        });
    }
    Ok(())
}

/// A full chain entry as recomputation sees it (route identity + the step or
/// checkpoint body), so the recompute can re-derive each hash link independently
/// of what was stored.
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
    /// The step or checkpoint body.
    pub step: ChainStep,
}

impl ChainEntry {
    /// This entry's hash — what its successor links (`entry_hash` for a step,
    /// `checkpoint_hash` for a checkpoint).
    #[must_use]
    pub fn head_hash(&self) -> String {
        match &self.step {
            ChainStep::Step(b) => entry_hash(&self.did, &self.kind, self.subkey.as_deref(), self.seq, b),
            ChainStep::Checkpoint(b) => {
                checkpoint_hash(&self.did, &self.kind, self.subkey.as_deref(), self.seq, b)
            }
        }
    }
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
    let mut head: Option<PrevEntry> = None;
    let mut last_checkpoint = GENESIS_PREV_HASH.to_owned();
    for entry in entries {
        match &entry.step {
            ChainStep::Step(body) => verify_step(head.as_ref(), body, entry.seq)?,
            ChainStep::Checkpoint(body) => match head.as_ref() {
                // A leading checkpoint is a compacted anchor: the entries it
                // closed are gone, so there is no predecessor to check it
                // against — it is the trusted balance-forward root (verified when
                // written). Every non-leading checkpoint is fully re-verified.
                None => {}
                Some(prev) => verify_checkpoint(prev, &last_checkpoint, body, entry.seq)?,
            },
        }
        let (total, hash) = match &entry.step {
            ChainStep::Step(body) => (body.total, entry.head_hash()),
            ChainStep::Checkpoint(body) => (body.closing_total, entry.head_hash()),
        };
        if entry.step.is_checkpoint() {
            last_checkpoint.clone_from(&hash);
        }
        head = Some(PrevEntry { seq: entry.seq, total, entry_hash: hash });
    }
    Ok(head.map_or(0, |h| h.total))
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
    fn entry_hash_binds_every_identity_field() {
        // The baseline entry's hash, and a hash with exactly one field changed.
        let base = entry_hash("did:x", CHAIN_COUNTER_KIND, Some("acct"), 2, &body(50, 150, "prevhash"));
        let vary = |h: String| assert_ne!(h, base, "a changed field must change the hash");
        vary(entry_hash("did:y", CHAIN_COUNTER_KIND, Some("acct"), 2, &body(50, 150, "prevhash")));
        vary(entry_hash("did:x", "other.kind", Some("acct"), 2, &body(50, 150, "prevhash")));
        vary(entry_hash("did:x", CHAIN_COUNTER_KIND, Some("other"), 2, &body(50, 150, "prevhash")));
        vary(entry_hash("did:x", CHAIN_COUNTER_KIND, None, 2, &body(50, 150, "prevhash")));
        vary(entry_hash("did:x", CHAIN_COUNTER_KIND, Some("acct"), 3, &body(50, 150, "prevhash")));
        vary(entry_hash("did:x", CHAIN_COUNTER_KIND, Some("acct"), 2, &body(51, 150, "prevhash")));
        vary(entry_hash("did:x", CHAIN_COUNTER_KIND, Some("acct"), 2, &body(50, 151, "prevhash")));
        vary(entry_hash("did:x", CHAIN_COUNTER_KIND, Some("acct"), 2, &body(50, 150, "other")));
        // It is a 64-char hex SHA-256 digest.
        assert_eq!(base.len(), 64);
        assert!(base.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn the_fold_binds_every_body_field() {
        let base = chain_counter_body_fold(&body(50, 150, "prev"));
        assert_ne!(base, chain_counter_body_fold(&body(51, 150, "prev")), "delta is bound");
        assert_ne!(base, chain_counter_body_fold(&body(50, 151, "prev")), "total is bound");
        assert_ne!(base, chain_counter_body_fold(&body(50, 150, "other")), "prev link is bound");
    }

    fn step_entry(seq: u64, delta: i64, total: u64, prev: &str) -> ChainEntry {
        ChainEntry {
            did: "did:x".to_owned(),
            kind: CHAIN_COUNTER_KIND.to_owned(),
            subkey: Some("acct".to_owned()),
            seq,
            step: ChainStep::Step(body(delta, total, prev)),
        }
    }

    fn checkpoint_entry(seq: u64, closing: u64, head: &str, prev_ckpt: &str) -> ChainEntry {
        ChainEntry {
            did: "did:x".to_owned(),
            kind: CHAIN_COUNTER_KIND.to_owned(),
            subkey: Some("acct".to_owned()),
            seq,
            step: ChainStep::Checkpoint(CheckpointBody {
                closing_total: closing,
                chain_head_hash: head.to_owned(),
                prev_checkpoint: prev_ckpt.to_owned(),
            }),
        }
    }

    #[test]
    fn recompute_walks_the_whole_chain_and_catches_tampering() {
        let e1 = step_entry(1, 100, 100, GENESIS_PREV_HASH);
        let h1 = e1.head_hash();
        let e2 = step_entry(2, 50, 150, &h1);
        let h2 = e2.head_hash();
        let e3 = step_entry(3, -30, 120, &h2);

        assert_eq!(recompute_total(&[e1.clone(), e2.clone(), e3.clone()]), Ok(120));
        assert_eq!(recompute_total(&[]), Ok(0), "an empty chain totals zero");

        // Tamper with e2's total after the fact: recomputation catches it, even
        // though e2 was valid when written (its stored total drove e3's link).
        let mut tampered = e2.clone();
        tampered.step = ChainStep::Step(body(50, 9_999, &h1));
        assert!(matches!(
            recompute_total(&[e1, tampered, e3]),
            Err(ChainBreak::Total { .. })
        ));
    }

    #[test]
    fn recompute_crosses_a_checkpoint_and_a_compacted_anchor() {
        // e1(+100)=100, e2(+50)=150, C1 closes 150 over e2, e3(+25)=175 links C1.
        let e1 = step_entry(1, 100, 100, GENESIS_PREV_HASH);
        let h1 = e1.head_hash();
        let e2 = step_entry(2, 50, 150, &h1);
        let h2 = e2.head_hash();
        let c1 = checkpoint_entry(3, 150, &h2, GENESIS_PREV_HASH);
        let hc1 = c1.head_hash();
        let e3 = step_entry(4, 25, 175, &hc1);

        // The full chain recomputes to 175 across the checkpoint.
        assert_eq!(recompute_total(&[e1, e2, c1.clone(), e3.clone()]), Ok(175));

        // After compaction the steps behind C1 are gone; C1 leads as the anchor,
        // carrying closing_total forward. Same final total, bounded storage.
        assert_eq!(recompute_total(&[c1, e3]), Ok(175), "a compacted chain totals from its anchor");
    }

    #[test]
    fn a_checkpoint_must_close_the_real_running_total_and_head() {
        let e1 = step_entry(1, 100, 100, GENESIS_PREV_HASH);
        let prev = PrevEntry { seq: 1, total: 100, entry_hash: e1.head_hash() };
        let good = CheckpointBody {
            closing_total: 100,
            chain_head_hash: e1.head_hash(),
            prev_checkpoint: GENESIS_PREV_HASH.to_owned(),
        };
        assert!(verify_checkpoint(&prev, GENESIS_PREV_HASH, &good, 2).is_ok());
        // Wrong closing total.
        assert_eq!(
            verify_checkpoint(
                &prev,
                GENESIS_PREV_HASH,
                &CheckpointBody { closing_total: 99, ..good.clone() },
                2,
            ),
            Err(ChainBreak::ClosingTotal { running_total: 100, closing_total: 99 })
        );
        // A head hash not matching the entry it claims to close (tamper detected).
        assert!(matches!(
            verify_checkpoint(
                &prev,
                GENESIS_PREV_HASH,
                &CheckpointBody { chain_head_hash: "beef".to_owned(), ..good.clone() },
                2,
            ),
            Err(ChainBreak::PrevHash { .. })
        ));
        // Wrong prior-checkpoint link.
        assert!(matches!(
            verify_checkpoint(&prev, "realprev", &good, 2),
            Err(ChainBreak::PrevCheckpoint { .. })
        ));
    }
}
