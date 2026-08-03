//! A seeded, deterministic pseudo-random generator (mulberry32). Every place the
//! suite needs "randomness" — which items an audit samples, which items a
//! provider secretly drops — draws from one of these, seeded from a string. Same
//! seed in, same draws out, so a Monte-Carlo experiment is exactly reproducible
//! and its assertions can be tight rather than "usually passes".
//!
//! Ports `item-storage-protocol-standalone/src/rng.ts`. We deliberately do NOT
//! use a wall-clock/global RNG: it cannot be seeded and would make runs
//! non-reproducible.

use sha2::{Digest, Sha256};

/// A seeded mulberry32 PRNG — small, fast, well-distributed, and fully
/// deterministic from its string seed.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u32,
}

impl Rng {
    /// A new generator seeded from `seed` (folded to 32 bits via SHA-256 so any
    /// label seeds cleanly).
    #[must_use]
    pub fn new(seed: &str) -> Self {
        let digest = Sha256::digest(seed.as_bytes());
        let state = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        Self { state }
    }

    /// The next float in `[0, 1)`.
    #[must_use]
    pub fn next_f64(&mut self) -> f64 {
        // mulberry32, bit-for-bit as the TS oracle (u32 wrapping arithmetic;
        // logical shifts). `f64::from(u32)` is lossless, so the final divide is
        // exact.
        self.state = self.state.wrapping_add(0x6d2b_79f5);
        let mut t = (self.state ^ (self.state >> 15)).wrapping_mul(1 | self.state);
        t = t.wrapping_add((t ^ (t >> 7)).wrapping_mul(0x3d | t)) ^ t;
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }

    /// The next integer in `[0, n)`.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    #[must_use]
    pub fn int(&mut self, n: usize) -> usize {
        // `n` is a small corpus size (exact in f64) and `next_f64()` is in
        // `[0, 1)`, so the product is in `[0, n)` and truncates to a valid index.
        (self.next_f64() * n as f64) as usize
    }

    /// A uniform sample of `min(k, n)` distinct indices from `[0, n)`, returned
    /// sorted ascending (partial Fisher-Yates).
    #[must_use]
    pub fn sample_indices(&mut self, n: usize, k: usize) -> Vec<usize> {
        let count = k.min(n);
        let mut pool: Vec<usize> = (0..n).collect();
        for i in 0..count {
            let j = i + self.int(n - i);
            pool.swap(i, j);
        }
        let mut out = pool[..count].to_vec();
        out.sort_unstable();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;
    use std::collections::HashSet;

    #[test]
    fn same_seed_yields_the_same_sequence() {
        let mut a = Rng::new("seed");
        let mut b = Rng::new("seed");
        for _ in 0..100 {
            assert!((a.next_f64() - b.next_f64()).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new("seed-a");
        let mut b = Rng::new("seed-b");
        let da: Vec<u64> = (0..10).map(|_| a.next_f64().to_bits()).collect();
        let db: Vec<u64> = (0..10).map(|_| b.next_f64().to_bits()).collect();
        assert_ne!(da, db);
    }

    #[test]
    fn next_stays_in_the_unit_interval() {
        let mut rng = Rng::new("unit");
        for _ in 0..1_000 {
            let x = rng.next_f64();
            assert!((0.0..1.0).contains(&x));
        }
    }

    #[test]
    fn int_stays_in_range() {
        let mut rng = Rng::new("int");
        for _ in 0..1_000 {
            assert!(rng.int(7) < 7);
        }
    }

    #[test]
    fn sample_indices_are_distinct_sorted_and_bounded() {
        let mut rng = Rng::new("sample");
        let s = rng.sample_indices(50, 10);
        assert_eq!(s.len(), 10);
        let set: HashSet<usize> = s.iter().copied().collect();
        assert_eq!(set.len(), 10, "distinct");
        assert!(s.windows(2).all(|w| w[0] < w[1]), "sorted ascending");
        assert!(s.iter().all(|&i| i < 50), "in range");
    }

    #[test]
    fn sample_count_caps_at_corpus_size() {
        let mut rng = Rng::new("cap");
        assert_eq!(rng.sample_indices(5, 100).len(), 5);
    }

    #[test]
    fn sample_is_reproducible_from_its_seed() {
        let a = Rng::new("repro").sample_indices(100, 20);
        let b = Rng::new("repro").sample_indices(100, 20);
        assert_eq!(a, b);
    }

    #[test]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn ports_the_oracle_sequence_bit_for_bit() {
        // Golden vectors captured from the TS oracle
        // (`item-storage-protocol-standalone/src/rng.ts`) for seed "golden-seed".
        // This pins mulberry32 to its exact sequence: it proves Rust <-> TS
        // parity and locks the bit-mixing arithmetic that uniformity/determinism
        // properties alone cannot constrain (kills the E86 mutation survivors in
        // `next_f64`). `next_f64() = t / 2^32`, so `next_f64() * 2^32` recovers the
        // exact `u32` state output `t`.
        let mut r = Rng::new("golden-seed");
        let seq: Vec<u32> = (0..6)
            .map(|_| (r.next_f64() * 4_294_967_296.0) as u32)
            .collect();
        assert_eq!(
            seq,
            [
                2_919_479_068,
                1_019_617_928,
                3_830_901_793,
                1_015_522_790,
                1_249_472_274,
                1_935_168_779,
            ],
        );

        let mut ri = Rng::new("golden-seed");
        let ints: Vec<usize> = (0..6).map(|_| ri.int(1_000)).collect();
        assert_eq!(ints, [679, 237, 891, 236, 290, 450]);

        assert_eq!(
            Rng::new("golden-seed").sample_indices(100, 8),
            [24, 25, 31, 45, 47, 56, 67, 89],
        );
    }
}
