//! The **read-policy kind** on the self-assertion substrate: a durable,
//! customer-authorized statement of *who may read* a namespace or a single
//! object. It is the authorization twin of the manifest — the manifest is
//! the customer's signed statement of *what is stored* (the billing base);
//! a policy is their statement of *who may see it* (the access base).
//!
//! Since D1 (the dials plan) the envelope — signatures, Model A/C
//! authorization, seq anti-rollback, the provider ack — lives in
//! [`crate::assertion`]; this module supplies only what is policy-specific:
//! the typed body, its canonical fold (what the signature binds), its
//! structural validation, and the resolution logic the read gate uses
//! (`world`/`grantees`/`owner`, finest-grain-wins, fail-closed).
//!
//! A namespace policy is the `policy` kind with no subkey; a per-object
//! policy is the same kind with the object cid as the subkey — the
//! substrate binds both into the signature, so an object policy can never
//! be lifted onto a different object (the old `target_tag` guarantee,
//! inherited structurally).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::identifiers::Did;
use crate::kind_spec::{
    Authorship, Enumeration, Erasure, Growth, HashAlgorithm, HashPosture, Hashing, KindSpec,
    Retention, Sizing,
};

/// The assertion kind tag for read policies.
pub const POLICY_KIND: &str = "policy";

/// Upper bound on an explicit reader list. Groups (a dynamic reader set) are
/// a deferred design item; an explicit list is bounded so a single record
/// cannot be made unboundedly large.
const MAX_READERS: usize = 1024;

/// The policy body ceiling: the one assertion kind with a variable-length body
/// (its reader list). Bodies are bounded by *both* count (`MAX_READERS`) and
/// bytes (this ceiling), whichever binds first — long DIDs can be valid by count
/// and oversized by bytes. 64 KiB clears every ordinary grantees policy while
/// refusing the pathological (ADR 0005, the sizing axis).
pub const POLICY_BODY_CEILING_BYTES: usize = 64 * 1024;

/// The policy kind's declared point on the six axes (ADR 0005, §5a). A policy is
/// the owner's signed statement of who may read; latest-wins (`Setting`), never
/// deleted but superseded by a new seq (`Permanent`), owner-listable, fold-bound
/// over SHA-256.
pub const POLICY_SPEC: KindSpec = KindSpec {
    kind: POLICY_KIND,
    retention: Retention::Setting,
    authorship: Authorship::OwnerSigned,
    erasure: Erasure::Permanent,
    enumeration: Enumeration::Listable,
    hashing: Hashing { posture: HashPosture::FoldBound, algorithm: HashAlgorithm::Sha256 },
    sizing: Sizing { body_ceiling: POLICY_BODY_CEILING_BYTES, growth: Growth::Bounded },
};

/// The read-visibility class of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadClass {
    /// Public — any caller may read (the PDS-compatible default, invariant Z1).
    World,
    /// Restricted — only the owner and the DIDs in `readers` may read.
    Grantees,
    /// Owner-only — only the owner may read; `readers` must be empty.
    Owner,
}

impl ReadClass {
    /// The stable tag bound into the signing fold (independent of the serde
    /// wire representation, so a serde rename can never silently change a
    /// signature's meaning).
    fn tag(self) -> &'static str {
        match self {
            ReadClass::World => "world",
            ReadClass::Grantees => "grantees",
            ReadClass::Owner => "owner",
        }
    }
}

/// The policy kind's body: the fields a policy assertion carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBody {
    /// The read-visibility class.
    pub read_class: ReadClass,
    /// Explicit reader DIDs (only for `grantees`; empty otherwise).
    pub readers: Vec<String>,
}

/// The canonical fold of a policy body — what the assertion signature binds
/// beyond the substrate's did/kind/subkey/seq. Readers are sorted and
/// length-prefixed; validated DIDs cannot contain a comma, so the join is
/// unambiguous.
#[must_use]
pub fn policy_body_fold(body: &PolicyBody) -> String {
    let mut readers = body.readers.clone();
    readers.sort();
    format!("class={};readers={}:{}", body.read_class.tag(), readers.len(), readers.join(","))
}

/// Structural validation for a policy body: the reader set must fit the
/// read class (empty for `world`/`owner`; bounded, deduplicated, valid DIDs
/// for `grantees`).
#[must_use]
pub fn policy_body_valid(body: &PolicyBody) -> bool {
    match body.read_class {
        ReadClass::World | ReadClass::Owner => body.readers.is_empty(),
        ReadClass::Grantees => {
            if body.readers.len() > MAX_READERS {
                return false;
            }
            let mut seen = HashSet::new();
            body.readers.iter().all(|r| Did::parse(r).is_ok() && seen.insert(r.as_str()))
        }
    }
}

/// The effective read policy for a target after resolution — the minimal
/// data the dispatch gate needs to decide a single read. Derived from a
/// stored body (or a default); it carries no signature, as it is CISS's own
/// resolved view of a record it already verified at write time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    read_class: ReadClass,
    readers: Vec<String>,
}

impl ResolvedPolicy {
    /// The world-readable default (no stored policy).
    #[must_use]
    pub fn world() -> Self {
        Self { read_class: ReadClass::World, readers: Vec::new() }
    }

    /// The fail-closed resolution (a stored row that would not parse):
    /// owner-only, never a more permissive guess.
    #[must_use]
    pub fn deny() -> Self {
        Self { read_class: ReadClass::Owner, readers: Vec::new() }
    }

    /// Resolve from a stored policy body.
    #[must_use]
    pub fn from_body(body: &PolicyBody) -> Self {
        Self { read_class: body.read_class, readers: body.readers.clone() }
    }

    /// The resolved read class.
    #[must_use]
    pub fn read_class(&self) -> ReadClass {
        self.read_class
    }

    /// The resolved reader set.
    #[must_use]
    pub fn readers(&self) -> &[String] {
        &self.readers
    }

    /// May `caller` read the target owned by `owner_did`? The owner always
    /// may; `world` admits anyone; `grantees` admits listed DIDs; `owner`
    /// admits nobody else.
    #[must_use]
    pub fn allows(&self, caller: Option<&str>, owner_did: &str) -> bool {
        if caller == Some(owner_did) {
            return true;
        }
        match self.read_class {
            ReadClass::World => true,
            ReadClass::Owner => false,
            ReadClass::Grantees => {
                caller.is_some_and(|c| self.readers.iter().any(|r| r == c))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertion::SignedAssertion;
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;

    fn body(class: ReadClass, readers: &[&str]) -> PolicyBody {
        PolicyBody {
            read_class: class,
            readers: readers.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn grantee() -> String {
        derive_id(&derive_keypair("master", "grantee").verifying_key())
    }

    /// The fold is canonical: reader order does not change it, and every
    /// field appears (class, count, members).
    #[test]
    fn fold_is_canonical_and_complete() {
        let g1 = grantee();
        let g2 = derive_id(&derive_keypair("master", "grantee-2").verifying_key());
        let a = policy_body_fold(&body(ReadClass::Grantees, &[&g1, &g2]));
        let b = policy_body_fold(&body(ReadClass::Grantees, &[&g2, &g1]));
        assert_eq!(a, b, "reader order is canonicalized");
        assert!(a.contains("class=grantees") && a.contains("readers=2:"));
        assert_ne!(
            a,
            policy_body_fold(&body(ReadClass::Grantees, &[&g1])),
            "the member set is bound"
        );
        assert_ne!(
            policy_body_fold(&body(ReadClass::World, &[])),
            policy_body_fold(&body(ReadClass::Owner, &[])),
            "the class is bound"
        );
    }

    /// Validation: readers must fit the class — non-empty readers on
    /// world/owner, duplicates, and non-DID entries are refused.
    #[test]
    fn body_validation_fits_the_class() {
        let g = grantee();
        assert!(policy_body_valid(&body(ReadClass::World, &[])));
        assert!(policy_body_valid(&body(ReadClass::Owner, &[])));
        assert!(policy_body_valid(&body(ReadClass::Grantees, &[&g])));
        assert!(!policy_body_valid(&body(ReadClass::World, &[&g])), "world takes no readers");
        assert!(!policy_body_valid(&body(ReadClass::Owner, &[&g])), "owner takes no readers");
        assert!(!policy_body_valid(&body(ReadClass::Grantees, &[&g, &g])), "no duplicates");
        assert!(
            !policy_body_valid(&body(ReadClass::Grantees, &["not-a-did"])),
            "readers must be DIDs"
        );
    }

    /// Resolution semantics: owner always reads; world admits anyone;
    /// grantees admits exactly the listed DIDs; owner-class admits nobody
    /// else; `deny()` is owner-only.
    #[test]
    fn resolution_allows_correctly() {
        let owner = "id:aaaa";
        let g = grantee();
        let world = ResolvedPolicy::world();
        assert!(world.allows(None, owner));
        assert!(world.allows(Some("id:bbbb"), owner));

        let grantees = ResolvedPolicy::from_body(&body(ReadClass::Grantees, &[&g]));
        assert!(grantees.allows(Some(owner), owner), "the owner always reads");
        assert!(grantees.allows(Some(&g), owner));
        assert!(!grantees.allows(Some("id:bbbb"), owner));
        assert!(!grantees.allows(None, owner));

        let deny = ResolvedPolicy::deny();
        assert!(deny.allows(Some(owner), owner));
        assert!(!deny.allows(Some(&g), owner));
    }

    /// End-to-end with the substrate: a policy assertion signs, verifies,
    /// and binds the body — changing the read class breaks the signature.
    #[test]
    fn policy_rides_the_substrate()  {
        let keypair = derive_keypair("master", "policy-owner");
        let did = derive_id(&keypair.verifying_key());
        let attest = derive_keypair("master", "policy-attest");
        let b = body(ReadClass::Owner, &[]);
        let a = SignedAssertion::sign_owner(
            POLICY_KIND,
            &did,
            None,
            1,
            serde_json::to_value(&b).expect("json"),
            &policy_body_fold(&b),
            &keypair,
        );
        assert!(a.verify(&policy_body_fold(&b), None, &attest.verifying_key()));

        let opened = body(ReadClass::World, &[]);
        assert!(
            !a.verify(&policy_body_fold(&opened), None, &attest.verifying_key()),
            "a re-folded (altered) body must not verify against the old signature"
        );
    }
}
