//! The generic `kv.flag` kind on the self-assertion substrate: the smallest
//! useful shape of mutable, restart-surviving, owner-signed state — a per-subkey
//! boolean.
//!
//! Why it exists: a tenant *service* (first consumer: croft-relay-admit, the
//! relay's admission authority, on a private CISS instance — README
//! "Downstream consumers") needs a per-subkey boolean (its membership roster).
//! The substrate already supplies everything hard — owner-signed writes,
//! strictly-monotonic `seq`, acked reads, persistence — so the kind is only a
//! typed body, a canonical fold, and structural validation, like every other
//! kind. **No consumer vocabulary**: nothing here says member, relay, or croft;
//! any tenant can use a flag.
//!
//! A sibling `kv.counter` (a per-subkey total) once lived here; a latest-wins
//! slot cannot protect a running total from a compromised writer, so it was
//! superseded by the tamper-evident `chain.counter` (`src/chain_kind.rs`) and
//! removed in A5 before release. Accounting lives on the chain; the roster
//! stays a flag (it wants erasure, not permanence).
//!
//! Kinds stay code, not data (the `kind_fold` registry note): adding a kind as a
//! registered kind is the sanctioned way for a consumer to get new state shapes
//! — an unregistered kind remains refused.
//!
//! `kv.flag` **requires a subkey** (a flag with no key is nothing), bounded and
//! charset-checked here so a hostile subkey never reaches storage paths.

use serde::{Deserialize, Serialize};

use crate::kind_spec::{
    Authorship, Enumeration, Erasure, Growth, HashAlgorithm, HashPosture, Hashing, KindSpec,
    Retention, Sizing, SMALL_BODY_CEILING_BYTES,
};

/// The flag kind: a per-subkey boolean.
pub const FLAG_KIND: &str = "kv.flag";

/// The `kv.flag` six-axis declaration (ADR 0005, §5a): a tenant service's
/// latest-wins per-subkey boolean (`Setting`), truly removable (`Erasable` —
/// member removal leaves no row, A2/B1), owner-listable (`Listable` — the
/// consumer's `keys()`, A2/B1), fold-bound over SHA-256, small fixed-shape body.
///
/// (A per-subkey *total* was once a sibling `kv.counter` kind here; it was
/// superseded by the tamper-evident `chain.counter` and removed in A5 before
/// release — a latest-wins slot let a compromised writer silently rewrite a
/// running total, which accounting cannot allow.)
pub const FLAG_SPEC: KindSpec = KindSpec {
    kind: FLAG_KIND,
    retention: Retention::Setting,
    authorship: Authorship::OwnerSigned,
    erasure: Erasure::Erasable,
    enumeration: Enumeration::Listable,
    hashing: Hashing { posture: HashPosture::FoldBound, algorithm: HashAlgorithm::Sha256 },
    sizing: Sizing { body_ceiling: SMALL_BODY_CEILING_BYTES, growth: Growth::Bounded },
};

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

/// The canonical fold of a flag body.
#[must_use]
pub fn flag_body_fold(body: &FlagBody) -> String {
    format!("set={}", body.set)
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
