//! Phase 5 wiring test — ports E5 (spot checks + the detection math) from the
//! oracle (`src/audit.ts` + `src/exp/e5_audits.ts`): an honest provider passes
//! every audit; over a large synthetic corpus with a fraction `f` silently
//! dropped, the measured detection rate over many seeded `k`-item audits matches
//! the closed form `1 - (1 - f)^k` within tolerance; and audit cost scales with
//! `k` and item size, not with corpus size.
//!
//! RED→GREEN gate: exercises rng → corpus → `audit_sample` (real retrieval) plus
//! the seeded Monte-Carlo detection sweep. The RNG seeds are literals in this
//! file, so a Monte-Carlo failure is reproducible from the source alone (per the
//! SPEC's determinism discipline).

// Monte-Carlo statistics: the usize<->f64 conversions below are deliberately
// lossy (trial counts and corpus indices sit well within f64's exact-integer
// range), so the pedantic cast lints don't apply.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::HashSet;

use ciss::audit::{audit_sample, detection_probability};
use ciss::item::{ContentStore, Item};
use ciss::manifest::ManifestLeaf;
use ciss::rng::Rng;

const F_SWEEP: [f64; 4] = [0.001, 0.01, 0.05, 0.2];
const K_SWEEP: [u32; 4] = [1, 5, 20, 100];
const TRIALS: usize = 5_000;
const N: usize = 5_000; // large, so hypergeometric ~ binomial
const ITEM_SIZE: usize = 256;
const TOLERANCE: f64 = 0.03;

/// Build a corpus of `n` distinct, same-size items, seeded for reproducibility.
fn build_same_size_corpus(n: usize, size: usize, seed: &str) -> (Vec<ManifestLeaf>, ContentStore) {
    let mut rng = Rng::new(seed);
    let mut store = ContentStore::new();
    let mut leaves = Vec::with_capacity(n);
    for i in 0..n {
        let mut bytes = vec![0u8; size];
        // First 4 bytes = i, so items stay distinct regardless of the random tail.
        let idx = u32::try_from(i).expect("corpus index fits u32");
        bytes[..4].copy_from_slice(&idx.to_le_bytes());
        for b in bytes.iter_mut().skip(4) {
            *b = u8::try_from(rng.int(256)).expect("int(256) < 256");
        }
        let item = Item::from_bytes(&format!("s-{i}"), bytes);
        leaves.push(ManifestLeaf::new(item.cid(), size));
        store.put(&item);
    }
    (leaves, store)
}

/// Model detection as set membership over an `n`-item corpus with a fixed
/// dropped set: a `k`-item audit detects the loss iff it samples any dropped
/// index. (The honest-audit + cost checks exercise real retrieval; this keeps
/// the sweep cheap, matching the oracle's `sampleHitsDropped`.)
fn sample_hits_dropped(n: usize, k: usize, dropped: &HashSet<usize>, rng: &mut Rng) -> bool {
    let mut seen = HashSet::new();
    let count = k.min(n);
    while seen.len() < count {
        let idx = rng.int(n);
        if !seen.insert(idx) {
            continue;
        }
        if dropped.contains(&idx) {
            return true;
        }
    }
    false
}

#[test]
fn an_honest_provider_passes_every_audit() {
    let (leaves, store) = build_same_size_corpus(200, ITEM_SIZE, "e5/honest/corpus");
    let mut rng = Rng::new("e5/honest/audits");
    for _ in 0..50 {
        let k = 1 + rng.int(leaves.len());
        let outcome = audit_sample(&leaves, &store, &mut rng, k);
        assert!(outcome.passed, "an intact store passes every audit");
        assert!(outcome.failures.is_empty());
    }
}

#[test]
fn a_dropped_item_is_caught_and_named_when_sampled() {
    // Real retrieval path (paired negative to the honest happy path, E86 layer 1):
    // drop one item (loss, not tamper) and sample the full corpus so it is in the
    // sample — the audit must fail and name exactly the dropped cid.
    let (leaves, mut store) = build_same_size_corpus(10, ITEM_SIZE, "e5/drop/corpus");
    let victim = leaves[3].cid().to_owned();
    store.remove(&victim);
    let mut rng = Rng::new("e5/drop/audit");
    let outcome = audit_sample(&leaves, &store, &mut rng, leaves.len());
    assert!(
        !outcome.passed,
        "an audit that samples a dropped item fails"
    );
    assert!(
        outcome.failures.contains(&victim),
        "the audit names the dropped item",
    );
}

#[test]
fn measured_detection_matches_the_closed_form() {
    let mut max_err = 0.0_f64;
    for f in F_SWEEP {
        let m = (f * (N as f64)).round() as usize;
        let dropped: HashSet<usize> = Rng::new(&format!("e5/drop/{f}"))
            .sample_indices(N, m)
            .into_iter()
            .collect();
        for k in K_SWEEP {
            let mut rng = Rng::new(&format!("e5/trials/{f}/{k}"));
            let mut detected = 0usize;
            for _ in 0..TRIALS {
                if sample_hits_dropped(N, k as usize, &dropped, &mut rng) {
                    detected += 1;
                }
            }
            let measured = (detected as f64) / (TRIALS as f64);
            let predicted = detection_probability(f, k);
            let err = (measured - predicted).abs();
            max_err = max_err.max(err);
            assert!(
                err <= TOLERANCE,
                "f={f} k={k}: measured {measured:.4} vs predicted {predicted:.4} \
                 (err {err:.4} > tol {TOLERANCE})",
            );
        }
    }
    assert!(
        max_err <= TOLERANCE,
        "max err {max_err:.4} within tolerance"
    );
}

#[test]
fn audit_cost_scales_with_k_and_item_size_not_corpus_size() {
    let (small_leaves, small) = build_same_size_corpus(500, ITEM_SIZE, "e5/cost/small");
    let (big_leaves, big) = build_same_size_corpus(5_000, ITEM_SIZE, "e5/cost/big");
    let cost_small = audit_sample(&small_leaves, &small, &mut Rng::new("e5/cost-a"), 10).bytes_read;
    let cost_big = audit_sample(&big_leaves, &big, &mut Rng::new("e5/cost-b"), 10).bytes_read;
    assert_eq!(cost_small, cost_big, "cost is independent of corpus size");
    assert_eq!(
        cost_big,
        u64::try_from(10 * ITEM_SIZE).expect("fits u64"),
        "cost == k * item size",
    );
}
