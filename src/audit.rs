//! The audit (spot check): pick `k` items uniformly at random from the
//! manifest, retrieve them, re-fingerprint, and verify against the signed list.
//! Its power is quantifiable — if a provider has silently dropped a fraction `f`
//! of items, a `k`-item audit detects it with probability `1 - (1 - f)^k`.
//! Checking costs real work (bytes retrieved), and that cost scales with `k` and
//! item sizes, not with the size of the whole corpus — which is what makes the
//! assurance dial cheap and honest.
//!
//! Ports `item-storage-protocol-standalone/src/audit.ts`.

use crate::item::ContentStore;
use crate::manifest::ManifestLeaf;
use crate::rng::Rng;

/// Closed form: the probability that a `k`-item audit detects a fraction-`f`
/// loss. `f=0` (no loss) and `k=0` (no sample) both give 0; `k=1` gives exactly
/// `f`; detection rises monotonically toward 1 as `k` grows.
#[must_use]
pub fn detection_probability(f: f64, k: u32) -> f64 {
    1.0 - (1.0 - f).powf(f64::from(k))
}

/// The outcome of one spot-check audit.
#[derive(Debug, Clone)]
pub struct AuditOutcome {
    /// The content addresses that were sampled.
    pub sampled: Vec<String>,
    /// Whether every sampled item retrieved and re-verified.
    pub passed: bool,
    /// Bytes actually read to run the audit — its true cost.
    pub bytes_read: u64,
    /// The sampled cids that failed to retrieve/verify (loss or tamper).
    pub failures: Vec<String>,
}

/// Run one `k`-item audit against a store: sample distinct manifest leaves,
/// retrieve + re-fingerprint each, and report which (if any) failed plus the
/// bytes read.
#[must_use]
pub fn audit_sample(
    leaves: &[ManifestLeaf],
    store: &ContentStore,
    rng: &mut Rng,
    k: usize,
) -> AuditOutcome {
    let idxs = rng.sample_indices(leaves.len(), k);
    let sampled: Vec<String> = idxs.iter().map(|&i| leaves[i].cid().to_owned()).collect();
    let failures: Vec<String> = sampled
        .iter()
        .filter(|cid| store.retrieve_verified(cid).is_err())
        .cloned()
        .collect();
    let bytes_read = store.audit_read_cost(&sampled);
    AuditOutcome {
        passed: failures.is_empty(),
        bytes_read,
        sampled,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::detection_probability;

    #[test]
    fn no_loss_is_never_detected() {
        for k in [0_u32, 1, 5, 100] {
            assert!(
                detection_probability(0.0, k).abs() < 1e-12,
                "f=0 → detection 0 for any k (k={k})",
            );
        }
    }

    #[test]
    fn zero_samples_detect_nothing() {
        for f in [0.0, 0.01, 0.5, 1.0] {
            assert!(
                detection_probability(f, 0).abs() < 1e-12,
                "k=0 → detection 0 for any f (f={f})",
            );
        }
    }

    #[test]
    fn one_sample_detects_exactly_the_loss_fraction() {
        for f in [0.0, 0.01, 0.2, 0.5] {
            assert!(
                (detection_probability(f, 1) - f).abs() < 1e-12,
                "k=1 → detection == f (f={f})",
            );
        }
    }

    #[test]
    fn detection_rises_monotonically_toward_one() {
        // A real loss fraction plus enough samples is almost certain to detect.
        assert!(detection_probability(0.5, 100) > 0.999_999_9);
        assert!(detection_probability(0.05, 1_000) > 0.999_9);
        // Monotonic in k: more samples never lower detection.
        assert!(detection_probability(0.1, 20) > detection_probability(0.1, 5));
    }
}
