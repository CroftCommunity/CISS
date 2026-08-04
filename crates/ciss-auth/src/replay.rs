//! [`ReplayGuard`] — a bounded `jti` seen-set that refuses a replayed token.
//!
//! A service-auth JWT is bearer: anyone who observes it can re-present it until it
//! expires. Its `aud`/`lxm`/`exp` bindings bound the blast radius (one method, one
//! service, ~60s), and this guard closes the residual window by refusing a `jti`
//! seen twice inside its validity. Time is passed in per call (the same `now` used
//! to check `exp`), so the guard needs no clock of its own; expired entries are
//! pruned on each call to keep the set bounded.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::JwtError;

/// Refuses a `jti` presented more than once before it expires.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<String, u64>>,
}

impl ReplayGuard {
    /// A new, empty guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `jti` (valid until `exp_unix_s`); refuse it if already seen and not
    /// yet expired. Prunes entries that expired at or before `now_unix_s`.
    ///
    /// # Errors
    ///
    /// [`JwtError::Replayed`] if `jti` is already recorded and still within its
    /// validity window.
    ///
    /// # Panics
    ///
    /// Panics only if the internal mutex is poisoned (a prior panic while it was
    /// held) — unreachable here, as no code panics inside the critical section.
    pub fn check_and_record(
        &self,
        jti: &str,
        exp_unix_s: u64,
        now_unix_s: u64,
    ) -> Result<(), JwtError> {
        let mut seen = self.seen.lock().expect("replay-guard mutex not poisoned");
        seen.retain(|_, exp| *exp > now_unix_s);
        if seen.contains_key(jti) {
            return Err(JwtError::Replayed);
        }
        seen.insert(jti.to_owned(), exp_unix_s);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayGuard;
    use crate::JwtError;

    const NOW: u64 = 1_000_000;

    #[test]
    fn a_fresh_jti_is_accepted() {
        let guard = ReplayGuard::new();
        assert!(guard.check_and_record("n1", NOW + 60, NOW).is_ok());
    }

    #[test]
    fn a_replayed_jti_within_its_window_is_refused() {
        let guard = ReplayGuard::new();
        guard.check_and_record("n1", NOW + 60, NOW).expect("first");
        assert_eq!(
            guard.check_and_record("n1", NOW + 60, NOW),
            Err(JwtError::Replayed),
        );
    }

    #[test]
    fn distinct_jtis_are_independent() {
        let guard = ReplayGuard::new();
        guard.check_and_record("n1", NOW + 60, NOW).expect("n1");
        assert!(guard.check_and_record("n2", NOW + 60, NOW).is_ok());
    }

    #[test]
    fn a_jti_is_reusable_once_its_window_has_passed() {
        // After expiry the entry is pruned; the same jti no longer collides. (In
        // practice the token's own exp check refuses it first — this proves the set
        // stays bounded rather than growing forever.)
        let guard = ReplayGuard::new();
        guard.check_and_record("n1", NOW + 60, NOW).expect("first");
        // Later than the entry's exp: prune removes it, so it is accepted again.
        assert!(guard.check_and_record("n1", NOW + 120, NOW + 61).is_ok());
    }
}
