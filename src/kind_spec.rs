//! Declarative kind semantics (ADR 0005; `ARCHITECTURE.md` §5a).
//!
//! Everything CISS stores is one record family sitting at a declared point in a
//! small semantic space. Rather than each kind hand-rolling its behaviour, a
//! kind **declares** where it sits on six axes, as data; the substrate reads the
//! declaration. This module is the vocabulary (the axes) and the registry (every
//! kind's point on them). The cross-inspection in §5a shows every existing
//! surface already fits.
//!
//! A1 wires only one behaviour off these declarations — the **body ceiling**
//! (the sizing axis), enforced at the assertion write boundary. The remaining
//! axes are declared now and become load-bearing as later phases land: erasure
//! and enumeration gate the generic DELETE/LIST endpoints (A2); retention `Chain`
//! and the hashing posture drive `chain.counter` (A3+).
//!
//! The one cross-axis invariant, enforced at compile time and re-asserted by
//! test: **`Chain` retention implies `Permanent` erasure** — an append-only,
//! predecessor-binding history cannot also offer per-entry removal (until a
//! checkpoint compacts it). A spec that claims both is self-contradictory and
//! must never exist.

/// Retention — does history exist, and how? `Setting`: latest wins, old value
/// replaced. `Immutable`: write-once per key. `Log`: append-only rows, integrity
/// via periodic roots. `Chain`: append-only, each entry binds its predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Latest write wins; the prior value is gone.
    Setting,
    /// Write-once per key, never updated (content-addressed bytes).
    Immutable,
    /// Append-only rows; integrity via periodic roots, not per-entry links.
    Log,
    /// Append-only; each entry binds its predecessor's hash.
    Chain,
}

/// Authorship — whose statement is this? `Derived` records are unsigned,
/// rebuildable caches of signed data and are never authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorship {
    /// Unsigned, rebuildable cache of signed data — never authoritative.
    Derived,
    /// The owner's statement (self-signed, or provider-attested from a JWT the
    /// owner authorized — the author is the owner either way).
    OwnerSigned,
    /// The provider's own statement.
    ProviderSigned,
    /// Signed by both parties; neither can later dispute it.
    CoSigned,
}

/// Erasure — is true removal offered? `Chain` implies `Permanent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erasure {
    /// True removal is offered (owner-authorized DELETE, A2).
    Erasable,
    /// No removal; a value is superseded by a new record, never deleted.
    Permanent,
}

/// Enumeration — can the owner list their keys, or is knowing the key the price
/// of asking? `PointOnly` is a deliberate privacy stance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enumeration {
    /// The owner may list their subkeys (owner-only, no existence oracle; A2).
    Listable,
    /// No listing — you must already know the key to ask for it.
    PointOnly,
}

/// Hash posture — what does the hash commit to?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashPosture {
    /// A canonical serialization of the record's kind-specific fields.
    FoldBound,
    /// The predecessor entry (chains).
    ChainLinked,
    /// A set, via a Merkle root over its leaves.
    MerkleRooted,
    /// The content identity itself (content-addressed bytes).
    ContentAddressed,
}

/// Hash algorithm, declared per kind: SHA-256 throughout CISS; BLAKE3 where
/// content interoperates with iroh file transfer. The split is deliberate
/// ecosystem alignment, not an accident of history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 — the CISS default.
    Sha256,
    /// BLAKE3 — where bytes interoperate with iroh file transfer.
    Blake3,
}

/// What a kind's hash commits to, and with which algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hashing {
    /// What the hash binds.
    pub posture: HashPosture,
    /// The declared algorithm.
    pub algorithm: HashAlgorithm,
}

/// Growth bound of the whole surface. Nothing is assumed infinite. `Rolling` =
/// compaction behind acknowledged checkpoints; `Unbounded` exists only as a
/// visible, deliberate choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Growth {
    /// Fixed or count-bounded; a small ceiling holds.
    Bounded,
    /// Compacted behind acknowledged checkpoints (A4).
    Rolling,
    /// Deliberately unbounded (a visible choice, never a default).
    Unbounded,
}

/// The sizing axis: a per-record body-byte ceiling and the surface's growth
/// bound. The body ceiling is enforced at the write boundary (A1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizing {
    /// The maximum serialized size of a single record's kind-specific body, in
    /// bytes. A body above this is refused at the boundary with the limit
    /// quoted.
    pub body_ceiling: usize,
    /// How the surface as a whole is bounded over time.
    pub growth: Growth,
}

/// A kind's declared point in the six-axis semantic space (ADR 0005). Held as a
/// `const` beside each kind's definition; assembled into [`REGISTRY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindSpec {
    /// The kind tag (the registry key), e.g. `policy`, `kv.flag`.
    pub kind: &'static str,
    /// Does history exist, and how?
    pub retention: Retention,
    /// Whose statement is this?
    pub authorship: Authorship,
    /// Is true removal offered?
    pub erasure: Erasure,
    /// May the owner list their keys?
    pub enumeration: Enumeration,
    /// What the hash commits to, and with which algorithm.
    pub hashing: Hashing,
    /// The body ceiling and growth bound.
    pub sizing: Sizing,
}

impl KindSpec {
    /// The one cross-axis invariant: `Chain` retention implies `Permanent`
    /// erasure. A `Chain` + `Erasable` spec is self-contradictory.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        !(matches!(self.retention, Retention::Chain) && matches!(self.erasure, Erasure::Erasable))
    }
}

/// A small body ceiling for the fixed-shape assertion kinds (dials, `kv.*`):
/// their bodies are a few dozen bytes and never approach this. The ceiling is
/// the declared sizing value and a defence-in-depth outer bound, not a limit any
/// legitimate body meets.
pub const SMALL_BODY_CEILING_BYTES: usize = 1024;

/// Every registered assertion kind's spec, in registry order. This is the single
/// list the substrate consults; `kind_fold`'s match arms and this registry must
/// name the same kinds (asserted by test).
pub const REGISTRY: &[&KindSpec] = &[
    &crate::policy::POLICY_SPEC,
    &crate::dials::CEILING_DIAL_SPEC,
    &crate::dials::PERIOD_DIAL_SPEC,
    &crate::dials::ACCOUNT_MODE_DIAL_SPEC,
    &crate::dials::RECEIPT_MODE_DIAL_SPEC,
    &crate::kv::FLAG_SPEC,
    &crate::kv::COUNTER_SPEC,
    &crate::chain_kind::CHAIN_COUNTER_SPEC,
];

/// The spec for a kind tag, or `None` for an unregistered kind (kinds are code,
/// not data — an unknown kind has no spec and is refused upstream).
#[must_use]
pub fn kind_spec(kind: &str) -> Option<&'static KindSpec> {
    REGISTRY.iter().copied().find(|spec| spec.kind == kind)
}

/// Compile-time enforcement of the chain⇒permanent invariant across the whole
/// registry: a `Chain` + `Erasable` spec fails the build, not a test run.
const fn registry_is_consistent() -> bool {
    let mut i = 0;
    while i < REGISTRY.len() {
        if !REGISTRY[i].is_consistent() {
            return false;
        }
        i += 1;
    }
    true
}
const _: () = assert!(
    registry_is_consistent(),
    "every KindSpec must satisfy chain ⇒ permanent"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The chain⇒permanent invariant rejects the one contradiction and accepts
    /// every other retention/erasure pairing.
    #[test]
    fn chain_retention_implies_permanent_erasure() {
        let spec = |retention, erasure| KindSpec {
            kind: "test",
            retention,
            authorship: Authorship::OwnerSigned,
            erasure,
            enumeration: Enumeration::PointOnly,
            hashing: Hashing { posture: HashPosture::FoldBound, algorithm: HashAlgorithm::Sha256 },
            sizing: Sizing { body_ceiling: 1, growth: Growth::Bounded },
        };
        assert!(
            !spec(Retention::Chain, Erasure::Erasable).is_consistent(),
            "a chain that offers erasure is self-contradictory"
        );
        assert!(spec(Retention::Chain, Erasure::Permanent).is_consistent());
        assert!(spec(Retention::Setting, Erasure::Erasable).is_consistent());
        assert!(spec(Retention::Log, Erasure::Permanent).is_consistent());
    }

    /// Every registered spec is self-consistent, and the registry keys are its
    /// kinds' tags (the lookup finds them, an unknown kind does not).
    #[test]
    fn registry_specs_are_consistent_and_addressable() {
        for spec in REGISTRY {
            assert!(spec.is_consistent(), "{} violates chain ⇒ permanent", spec.kind);
            assert_eq!(
                kind_spec(spec.kind).map(|s| s.kind),
                Some(spec.kind),
                "a registered kind resolves to itself"
            );
        }
        assert!(kind_spec("no.such.kind").is_none(), "an unknown kind has no spec");
    }

    /// No kind is registered twice (the registry is a map, not a bag).
    #[test]
    fn registry_kinds_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for spec in REGISTRY {
            assert!(seen.insert(spec.kind), "{} is registered twice", spec.kind);
        }
    }

    /// The spec registry and `kind_fold`'s accepted kinds must name the same
    /// set: a foldable kind absent from the registry would silently escape the
    /// body ceiling (the enforcement is `if let Some(spec)`). This pins the two
    /// lists together — add a kind to `kind_fold` and this fails until it has a
    /// spec.
    #[test]
    fn registry_covers_exactly_the_foldable_kinds() {
        let foldable = [
            crate::policy::POLICY_KIND,
            crate::dials::CEILING_DIAL_KIND,
            crate::dials::PERIOD_DIAL_KIND,
            crate::dials::ACCOUNT_MODE_DIAL_KIND,
            crate::dials::RECEIPT_MODE_DIAL_KIND,
            crate::kv::FLAG_KIND,
            crate::kv::COUNTER_KIND,
            crate::chain_kind::CHAIN_COUNTER_KIND,
        ];
        for kind in foldable {
            assert!(kind_spec(kind).is_some(), "foldable kind {kind} has no spec");
        }
        assert_eq!(
            REGISTRY.len(),
            foldable.len(),
            "the registry carries a spec for a kind kind_fold does not accept (or vice versa)"
        );
    }
}
