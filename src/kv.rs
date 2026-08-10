//! The generic KV kinds on the self-assertion substrate: `kv.flag` and
//! `kv.counter` — the two smallest useful shapes of mutable, restart-surviving,
//! owner-signed state.
//!
//! Why they exist: a tenant *service* (first consumer: croft-relay-admit, the
//! relay's admission authority, on a private CISS instance — README
//! "Downstream consumers") needs a per-subkey boolean and a per-subkey
//! counter. The substrate already supplies everything hard — owner-signed
//! writes, strictly-monotonic `seq`, acked reads, persistence — so these
//! kinds are only a typed body, a canonical fold, and structural validation,
//! like every other kind. **No consumer vocabulary**: nothing here says
//! member, relay, or croft; any tenant can use a flag or a counter.
//!
//! Kinds stay code, not data (the `kind_fold` registry note): adding these as
//! registered kinds is the sanctioned way for a consumer to get new state
//! shapes — an unregistered kind remains refused.
//!
//! Both kinds **require a subkey** (a flag or counter with no key is
//! nothing), bounded and charset-checked here so a hostile subkey never
//! reaches storage paths.

use serde::{Deserialize, Serialize};

/// The flag kind: a per-subkey boolean.
pub const FLAG_KIND: &str = "kv.flag";
/// The counter kind: a per-subkey monotone-by-`seq` total.
pub const COUNTER_KIND: &str = "kv.counter";

/// Longest accepted subkey. Consumers use digests (64 hex) or short labels;
/// 256 is a generous ceiling that still refuses the absurd.
pub const MAX_SUBKEY_LEN: usize = 256;

/// A `kv.flag` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagBody {
    /// The flag's value. Deleting a flag is asserting `set: false` (the
    /// substrate keeps the latest record; there is no unset).
    pub set: bool,
}

/// A `kv.counter` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterBody {
    /// The running total. The substrate's strictly-monotonic `seq` orders
    /// updates; the total itself is the consumer's to compute.
    pub total: u64,
}

/// The canonical fold of a flag body.
#[must_use]
pub fn flag_body_fold(body: &FlagBody) -> String {
    format!("set={}", body.set)
}

/// The canonical fold of a counter body.
#[must_use]
pub fn counter_body_fold(body: &CounterBody) -> String {
    format!("total={}", body.total)
}

/// Structural validation for a kv subkey: required, bounded, and drawn from
/// the identifier-safe charset (no path separators, whitespace, or control
/// bytes — the same discipline as boundary identifiers).
#[must_use]
pub fn subkey_valid(subkey: Option<&str>) -> bool {
    let Some(sk) = subkey else {
        return false;
    };
    !sk.is_empty()
        && sk.len() <= MAX_SUBKEY_LEN
        && sk
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_bind_the_value() {
        assert_eq!(flag_body_fold(&FlagBody { set: true }), "set=true");
        assert_eq!(flag_body_fold(&FlagBody { set: false }), "set=false");
        assert_eq!(counter_body_fold(&CounterBody { total: 0 }), "total=0");
        assert_eq!(
            counter_body_fold(&CounterBody { total: u64::MAX }),
            format!("total={}", u64::MAX)
        );
    }

    #[test]
    fn subkeys_are_required_bounded_and_charset_checked() {
        assert!(!subkey_valid(None), "kv kinds require a subkey");
        assert!(!subkey_valid(Some("")), "empty is refused");
        assert!(subkey_valid(Some(&"a".repeat(MAX_SUBKEY_LEN))));
        assert!(!subkey_valid(Some(&"a".repeat(MAX_SUBKEY_LEN + 1))));
        // The consumers' shapes: hex digests and did-shaped dev keys.
        assert!(subkey_valid(Some(
            "9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a9c4f2b7a"
        )));
        assert!(subkey_valid(Some("did:plc:ewvi7nxzyoun6zhxrhs64oiz")));
        // Hostile shapes never reach storage.
        assert!(!subkey_valid(Some("../escape")), "path separators refused");
        assert!(!subkey_valid(Some("a b")), "whitespace refused");
        assert!(!subkey_valid(Some("a\nb")), "control bytes refused");
    }
}
