//! The owner-authorized **read policy** record: a durable, signature-verifiable
//! statement of *who may read* a namespace or a single object. It is the
//! authorization twin of the manifest — where the manifest is the customer's
//! signed statement of *what is stored* (the billing base), a policy record is a
//! signed statement of *who may see it* (the access base). The two are kept
//! deliberately distinct (separate signatures, separate domains) so a grant or
//! revoke never re-signs the rent base and vice-versa.
//!
//! A record carries its target (a namespace DID, or a `(did, cid)` object), a
//! read class (`world`/`grantees`/`owner`), an explicit reader DID list, a
//! monotonic `seq` (rollback protection), and one of **two** authorization forms:
//!
//! - **`OwnerSigned` (Model A).** A Croft-native `id:` owner holds its ed25519 key
//!   (the DID is that key's hash), so it signs the policy body itself over a
//!   domain-separated preimage (`ciss/v1/policy`). Valid **only** for an `id:`
//!   target — the signer key must derive the target DID.
//! - **`ProviderAttested` (Model C).** An owner whose key lives at an external
//!   identity provider (a `did:` owner) cannot self-sign a CISS record; instead it
//!   authorizes a set-policy *action* via a service-auth JWT, and CISS — having
//!   verified that JWT — counter-signs the resulting record with its dedicated
//!   **attestation** key over a distinct domain (`ciss/v1/policy-attest`), so the
//!   stored record is durably verifiable afterwards without re-checking the JWT.
//!
//! Verification is a pure function ([`verify_policy`]); persistence and the HTTP
//! set-policy path are built on top of it in later phases. Both signatures bind
//! the full target (including the object `cid`), the read class, the reader set,
//! and the `seq`, so no field can be altered — and no object policy lifted onto a
//! different object — without invalidating the signature.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{public_key_from_hex, verify_message, Keypair};
use crate::identifiers::{ContentAddr, Did, IdentitySpace};
use crate::identity::derive_id;

/// Domain-separation tag for a Model-A owner-signed policy body.
const POLICY_SIG_DOMAIN: &str = "ciss/v1/policy";
/// Domain-separation tag for a Model-C provider attestation. Disjoint from the
/// owner-signed domain, the manifest domain, and the (bare-hash) receipt domain,
/// so a signature from one context can never be replayed into another.
const POLICY_ATTEST_DOMAIN: &str = "ciss/v1/policy-attest";

/// Upper bound on an explicit reader list. Groups (a dynamic reader set) are a
/// deferred design item; an explicit list is bounded so a single record cannot be
/// made unboundedly large.
const MAX_READERS: usize = 1024;

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
    /// The stable tag bound into a signing preimage (independent of the serde
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

/// A Model-A owner signature: the signer's ed25519 public key (hex) and its
/// signature over the owner-signed policy preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerSigned {
    /// The owner's ed25519 public key, hex-encoded. Must derive the target DID.
    pub signer: String,
    /// The hex signature over the `ciss/v1/policy` preimage.
    pub sig: String,
}

/// A Model-C provider attestation: CISS's own signature vouching that it verified
/// a valid owner service-auth JWT authorizing this policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttested {
    /// The DID whose namespace/object this policy governs (the JWT `iss`).
    pub owner_did: String,
    /// The single-use JWT id (`jti`) that authorized this set-policy action —
    /// recorded for audit; the replay guard enforces single use at write time.
    pub authorizing_jti: String,
    /// CISS's hex signature over the `ciss/v1/policy-attest` preimage, made with
    /// the dedicated `policy-attest` key (not the receipt/billing key).
    pub provider_sig: String,
}

/// How a policy record's authority is proven.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Authorization {
    /// Model A — the `id:` owner self-signed (see [`OwnerSigned`]).
    OwnerSigned(OwnerSigned),
    /// Model C — CISS counter-signed after verifying the owner's JWT (see
    /// [`ProviderAttested`]).
    ProviderAttested(ProviderAttested),
}

/// A signed read-policy record for a namespace or a single object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecord {
    /// The governed DID (a tenant namespace).
    did: String,
    /// The governed object's content address, when this is a per-object policy;
    /// `None` for a namespace-wide policy.
    cid: Option<String>,
    /// The read class.
    read_class: ReadClass,
    /// The explicit reader DID list (meaningful only for [`ReadClass::Grantees`]).
    readers: Vec<String>,
    /// The monotonic sequence number (rollback/replay protection).
    seq: u64,
    /// The authorization proof.
    authorization: Authorization,
}

impl PolicyRecord {
    /// The governed DID.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The governed object cid, if this is a per-object policy.
    #[must_use]
    pub fn cid(&self) -> Option<&str> {
        self.cid.as_deref()
    }

    /// The read class.
    #[must_use]
    pub fn read_class(&self) -> ReadClass {
        self.read_class
    }

    /// The reader DID list.
    #[must_use]
    pub fn readers(&self) -> &[String] {
        &self.readers
    }

    /// The sequence number.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The authorization proof.
    #[must_use]
    pub fn authorization(&self) -> &Authorization {
        &self.authorization
    }

    /// Build and **owner-sign** a Model-A policy record. The `owner_key` must be
    /// the keypair whose public key derives `did` (an `id:` owner); `cid` is
    /// `Some` for a per-object policy. Used by an `id:` owner client (and the test
    /// harness) to author a self-signed record.
    #[must_use]
    pub fn sign_owner(
        did: &str,
        cid: Option<&str>,
        read_class: ReadClass,
        readers: &[String],
        seq: u64,
        owner_key: &Keypair,
    ) -> Self {
        let record = Self {
            did: did.to_owned(),
            cid: cid.map(ToOwned::to_owned),
            read_class,
            readers: readers.to_vec(),
            seq,
            authorization: Authorization::OwnerSigned(OwnerSigned {
                signer: owner_key.public_key_hex(),
                sig: String::new(),
            }),
        };
        let sig = owner_key.sign_message(&record.owner_preimage());
        Self {
            authorization: Authorization::OwnerSigned(OwnerSigned {
                signer: owner_key.public_key_hex(),
                sig,
            }),
            ..record
        }
    }

    /// Build and **provider-attest** a Model-C policy record. Called by CISS after
    /// it has verified the owner's service-auth JWT; `attest_key` is CISS's
    /// dedicated `policy-attest` keypair (not the receipt key). `owner_did` is the
    /// JWT `iss` (the governed DID) and `authorizing_jti` its single-use id.
    #[must_use]
    pub fn attest_provider(
        did: &str,
        cid: Option<&str>,
        read_class: ReadClass,
        readers: &[String],
        seq: u64,
        authorizing_jti: &str,
        attest_key: &Keypair,
    ) -> Self {
        let record = Self {
            did: did.to_owned(),
            cid: cid.map(ToOwned::to_owned),
            read_class,
            readers: readers.to_vec(),
            seq,
            authorization: Authorization::ProviderAttested(ProviderAttested {
                owner_did: did.to_owned(),
                authorizing_jti: authorizing_jti.to_owned(),
                provider_sig: String::new(),
            }),
        };
        let provider_sig = attest_key.sign_message(&record.attest_preimage(did));
        Self {
            authorization: Authorization::ProviderAttested(ProviderAttested {
                owner_did: did.to_owned(),
                authorizing_jti: authorizing_jti.to_owned(),
                provider_sig,
            }),
            ..record
        }
    }

    /// The target tag bound into every preimage: `ns:<did>` for a namespace policy
    /// or `obj:<did>:<cid>` for an object policy. Binding the cid stops an
    /// object policy's signature from being lifted onto a different object.
    fn target_tag(&self) -> String {
        match &self.cid {
            None => format!("ns:{}", self.did),
            Some(cid) => format!("obj:{}:{cid}", self.did),
        }
    }

    /// The authorization-independent body bound by both signature forms: the
    /// target, the seq, the read class, and the canonicalized reader set (sorted,
    /// length-prefixed, comma-joined — readers are validated DIDs, which cannot
    /// contain a comma, so the join is unambiguous).
    fn body_tag(&self) -> String {
        let mut readers = self.readers.clone();
        readers.sort();
        format!(
            "{}:{}:{}:{}:{}",
            self.target_tag(),
            self.seq,
            self.read_class.tag(),
            readers.len(),
            readers.join(","),
        )
    }

    /// The Model-A owner-signed preimage.
    fn owner_preimage(&self) -> String {
        format!("{POLICY_SIG_DOMAIN}:{}", self.body_tag())
    }

    /// The Model-C provider-attestation preimage (binds the owner DID explicitly,
    /// as CISS's attestation is a statement *about* that owner).
    fn attest_preimage(&self, owner_did: &str) -> String {
        format!("{POLICY_ATTEST_DOMAIN}:{owner_did}:{}", self.body_tag())
    }
}

/// The effective read policy for a target after resolution — the minimal data the
/// dispatch gate needs to decide a single read. Derived from a stored record (or a
/// default); it carries no signature, as it is CISS's own resolved view of a row
/// it already verified at write time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    read_class: ReadClass,
    readers: Vec<String>,
}

impl ResolvedPolicy {
    /// The PDS-compatible default when no policy row exists: world-readable
    /// (invariant Z1).
    #[must_use]
    pub fn world() -> Self {
        Self {
            read_class: ReadClass::World,
            readers: Vec::new(),
        }
    }

    /// The fail-closed value: owner-only, no grantees. Used when a policy row is
    /// present but unreadable — the owner set *something* (so not the world
    /// default), but we cannot tell what, so we deny everyone but the owner.
    #[must_use]
    pub fn deny() -> Self {
        Self {
            read_class: ReadClass::Owner,
            readers: Vec::new(),
        }
    }

    /// The resolved view of a verified record.
    #[must_use]
    pub fn from_record(record: &PolicyRecord) -> Self {
        Self {
            read_class: record.read_class,
            readers: record.readers.clone(),
        }
    }

    /// The read class.
    #[must_use]
    pub fn read_class(&self) -> ReadClass {
        self.read_class
    }

    /// The grantee DID list.
    #[must_use]
    pub fn readers(&self) -> &[String] {
        &self.readers
    }

    /// Whether `caller` (a principal's DID; `None` = anonymous) may read a target
    /// owned by `owner_did`. The owner always reads its own target; otherwise
    /// `World` admits anyone, `Owner` admits no one else, and `Grantees` admits a
    /// caller whose DID is in the reader set.
    #[must_use]
    pub fn allows(&self, caller: Option<&str>, owner_did: &str) -> bool {
        if caller == Some(owner_did) {
            return true;
        }
        match self.read_class {
            ReadClass::World => true,
            ReadClass::Owner => false,
            ReadClass::Grantees => caller.is_some_and(|c| self.readers.iter().any(|r| r == c)),
        }
    }
}

/// Whether the reader set is well-formed for `read_class`: for `Grantees`, every
/// entry is a valid DID, there are no duplicates, and the list is within the
/// ceiling; for `World`/`Owner`, the reader list must be empty (readers are
/// meaningless there, and a stray entry signals a malformed record).
fn readers_well_formed(read_class: ReadClass, readers: &[String]) -> bool {
    match read_class {
        ReadClass::World | ReadClass::Owner => readers.is_empty(),
        ReadClass::Grantees => {
            if readers.len() > MAX_READERS {
                return false;
            }
            let mut seen = HashSet::new();
            readers
                .iter()
                .all(|r| Did::parse(r).is_ok() && seen.insert(r.as_str()))
        }
    }
}

/// Verify a policy record: its structure is well-formed, its `seq` advances past
/// `prior_seq`, and its authorization proof checks out. Returns `false` for any
/// failure — a malformed field, a stale/replayed `seq`, a forged or mismatched
/// signature, an `OwnerSigned` record naming a non-`id:` target, or a
/// `ProviderAttested` record whose attestation does not verify under
/// `provider_attest_pubkey`. This is the single verification choke point; a stored
/// record is written only after it passes here.
///
/// `prior_seq` is the last accepted seq for this exact target (`None` if none yet);
/// the record's `seq` must be strictly greater. `provider_attest_pubkey` is CISS's
/// dedicated attestation public key (never the receipt key).
#[must_use]
pub fn verify_policy(
    record: &PolicyRecord,
    prior_seq: Option<u64>,
    provider_attest_pubkey: &VerifyingKey,
) -> bool {
    // Structure: the target DID and (optional) object cid must be well-formed
    // boundary identifiers, and the reader set must fit its read class.
    let Ok(target_did) = Did::parse(&record.did) else {
        return false;
    };
    if let Some(cid) = &record.cid {
        if ContentAddr::parse(cid).is_err() {
            return false;
        }
    }
    if !readers_well_formed(record.read_class, &record.readers) {
        return false;
    }

    // Rollback protection: the seq must strictly advance past the last accepted.
    if let Some(prior) = prior_seq {
        if record.seq <= prior {
            return false;
        }
    }

    // Authorization proof.
    match &record.authorization {
        Authorization::OwnerSigned(owner) => {
            // Form-vs-target: an owner-signed record is valid only for an `id:`
            // target, whose DID is the hash of the signing key. (An atproto
            // `did:` can never be derived from an ed25519 key, so this also
            // holds implicitly — the space check makes the intent explicit.)
            if target_did.space() != IdentitySpace::Id {
                return false;
            }
            let Ok(signer_key) = public_key_from_hex(&owner.signer) else {
                return false;
            };
            if derive_id(&signer_key) != record.did {
                return false;
            }
            verify_message(&signer_key, &record.owner_preimage(), &owner.sig)
        }
        Authorization::ProviderAttested(attested) => {
            // The attestation is CISS's statement about `owner_did`; it must be
            // the governed DID, and the provider signature must verify under the
            // dedicated attestation key.
            if attested.owner_did != record.did {
                return false;
            }
            verify_message(
                provider_attest_pubkey,
                &record.attest_preimage(&attested.owner_did),
                &attested.provider_sig,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{verify_policy, Authorization, PolicyRecord, ReadClass};
    use crate::crypto::{derive_keypair, Keypair};
    use crate::identity::derive_id;

    fn owner() -> Keypair {
        derive_keypair("master", "policy-owner")
    }

    /// CISS's dedicated attestation key (distinct label from the receipt key).
    fn attest_key() -> Keypair {
        derive_keypair("master", "policy-attest")
    }

    fn owner_did() -> String {
        derive_id(&owner().verifying_key())
    }

    fn cid(tag: &str) -> String {
        crate::crypto::sha256_hex(tag.as_bytes())
    }

    fn grantee(tag: &str) -> String {
        format!("did:plc:{tag}")
    }

    #[test]
    fn owner_signed_namespace_policy_verifies() {
        let rec = PolicyRecord::sign_owner(
            &owner_did(),
            None,
            ReadClass::Grantees,
            &[grantee("alice")],
            1,
            &owner(),
        );
        assert!(verify_policy(&rec, None, &attest_key().verifying_key()));
    }

    #[test]
    fn owner_signed_object_policy_verifies() {
        let rec = PolicyRecord::sign_owner(
            &owner_did(),
            Some(&cid("blob")),
            ReadClass::World,
            &[],
            1,
            &owner(),
        );
        assert!(verify_policy(&rec, None, &attest_key().verifying_key()));
    }

    #[test]
    fn provider_attested_policy_verifies_under_the_attestation_key() {
        let rec = PolicyRecord::attest_provider(
            "did:plc:owner",
            None,
            ReadClass::Grantees,
            &[grantee("alice")],
            1,
            "jti-123",
            &attest_key(),
        );
        assert!(verify_policy(&rec, None, &attest_key().verifying_key()));
    }

    #[test]
    fn provider_attestation_does_not_verify_under_the_receipt_key() {
        // Key separation (Q3): the attestation is made with the dedicated
        // policy-attest key; verifying with the receipt/billing key must fail.
        let receipt_key = derive_keypair("master", "provider");
        let rec = PolicyRecord::attest_provider(
            "did:plc:owner",
            None,
            ReadClass::Grantees,
            &[grantee("alice")],
            1,
            "jti-123",
            &attest_key(),
        );
        assert!(!verify_policy(&rec, None, &receipt_key.verifying_key()));
    }

    #[test]
    fn forged_signer_that_does_not_derive_the_target_is_refused() {
        // A different key signs, but the record still names owner_did as target;
        // the signer no longer derives the target DID.
        let attacker = derive_keypair("master", "attacker");
        let mut rec = PolicyRecord::sign_owner(
            &owner_did(),
            None,
            ReadClass::Owner,
            &[],
            1,
            &attacker,
        );
        // sign_owner set target-owner-derivation to the attacker; overwrite the
        // stored did to the victim's, as a forger would.
        rec = tamper_did(&rec, &owner_did());
        assert!(!verify_policy(&rec, None, &attest_key().verifying_key()));
    }

    #[test]
    fn owner_signed_record_naming_a_did_target_is_refused() {
        // Form-vs-target rule: OwnerSigned is valid only for an id: target. A
        // did: target can never be derived from an ed25519 key.
        let rec = PolicyRecord::sign_owner(
            "did:plc:owner",
            None,
            ReadClass::Grantees,
            &[grantee("alice")],
            1,
            &owner(),
        );
        assert!(!verify_policy(&rec, None, &attest_key().verifying_key()));
    }

    #[test]
    fn lower_or_equal_seq_is_refused_and_higher_is_accepted() {
        // Monotonic seq: the boundary is prior_seq. equal and lower are rejected;
        // strictly-higher supersedes.
        let at = attest_key().verifying_key();
        let make = |seq| {
            PolicyRecord::sign_owner(&owner_did(), None, ReadClass::Owner, &[], seq, &owner())
        };
        assert!(!verify_policy(&make(5), Some(5), &at), "equal seq refused");
        assert!(!verify_policy(&make(4), Some(5), &at), "lower seq refused");
        assert!(verify_policy(&make(6), Some(5), &at), "higher seq accepted");
        assert!(verify_policy(&make(1), None, &at), "first policy accepted");
    }

    #[test]
    fn malformed_readers_are_refused() {
        let at = attest_key().verifying_key();
        // A reader that is not a valid DID (path separator, wrong shape).
        let bad = PolicyRecord::sign_owner(
            &owner_did(),
            None,
            ReadClass::Grantees,
            &["../../etc/passwd".to_owned()],
            1,
            &owner(),
        );
        assert!(!verify_policy(&bad, None, &at), "non-DID reader refused");
        // Duplicate readers.
        let dup = PolicyRecord::sign_owner(
            &owner_did(),
            None,
            ReadClass::Grantees,
            &[grantee("alice"), grantee("alice")],
            1,
            &owner(),
        );
        assert!(!verify_policy(&dup, None, &at), "duplicate reader refused");
        // A World policy with a non-empty reader list is malformed.
        let world_with_readers = PolicyRecord::sign_owner(
            &owner_did(),
            None,
            ReadClass::World,
            &[grantee("alice")],
            1,
            &owner(),
        );
        assert!(
            !verify_policy(&world_with_readers, None, &at),
            "world + readers refused",
        );
    }

    #[test]
    fn post_sign_tamper_is_refused() {
        let at = attest_key().verifying_key();
        let rec = PolicyRecord::sign_owner(
            &owner_did(),
            None,
            ReadClass::Grantees,
            &[grantee("alice")],
            1,
            &owner(),
        );
        assert!(verify_policy(&rec, None, &at));
        // Flip the read class after signing (a tamper that would widen access).
        let tampered = tamper_read_class(&rec, ReadClass::World);
        assert!(!verify_policy(&tampered, None, &at), "read_class tamper refused");
        // Add a reader after signing (silently grant an unlisted DID).
        let extra = tamper_readers(&rec, &[grantee("alice"), grantee("mallory")]);
        assert!(!verify_policy(&extra, None, &at), "readers tamper refused");
        // Bump seq after signing.
        let reseq = tamper_seq(&rec, 9);
        assert!(!verify_policy(&reseq, None, &at), "seq tamper refused");
    }

    #[test]
    fn object_policy_signature_does_not_lift_to_another_object() {
        // The cid is bound into the preimage: a policy signed for object A must
        // not verify once its cid is swapped to object B.
        let at = attest_key().verifying_key();
        let rec = PolicyRecord::sign_owner(
            &owner_did(),
            Some(&cid("A")),
            ReadClass::World,
            &[],
            1,
            &owner(),
        );
        assert!(verify_policy(&rec, None, &at));
        let lifted = tamper_cid(&rec, &cid("B"));
        assert!(!verify_policy(&lifted, None, &at), "cid is bound into the signature");
    }

    #[test]
    fn round_trips_across_the_class_and_target_matrix() {
        // Mutation-resistant round-trip: sign then verify across read classes,
        // namespace/object targets, and both authorization forms.
        let at = attest_key();
        for seq in [1_u64, 2, 7] {
            for cid_opt in [None, Some(cid("obj"))] {
                let owner_rec = PolicyRecord::sign_owner(
                    &owner_did(),
                    cid_opt.as_deref(),
                    ReadClass::Owner,
                    &[],
                    seq,
                    &owner(),
                );
                assert!(verify_policy(&owner_rec, None, &at.verifying_key()));

                let attested = PolicyRecord::attest_provider(
                    "did:plc:owner",
                    cid_opt.as_deref(),
                    ReadClass::Grantees,
                    &[grantee("alice"), grantee("bob")],
                    seq,
                    "jti",
                    &at,
                );
                assert!(verify_policy(&attested, None, &at.verifying_key()));
            }
        }
    }

    // --- tamper helpers: round-trip through JSON to mutate one field, as an
    // attacker manipulating the stored/wire form would (mirrors manifest tests). ---

    fn reparse(v: serde_json::Value) -> PolicyRecord {
        serde_json::from_value(v).expect("reparse")
    }
    fn to_value(rec: &PolicyRecord) -> serde_json::Value {
        serde_json::to_value(rec).expect("serialize")
    }
    fn tamper_did(rec: &PolicyRecord, did: &str) -> PolicyRecord {
        let mut v = to_value(rec);
        v["did"] = serde_json::json!(did);
        reparse(v)
    }
    fn tamper_cid(rec: &PolicyRecord, cid: &str) -> PolicyRecord {
        let mut v = to_value(rec);
        v["cid"] = serde_json::json!(cid);
        reparse(v)
    }
    fn tamper_read_class(rec: &PolicyRecord, class: ReadClass) -> PolicyRecord {
        let mut v = to_value(rec);
        v["read_class"] = to_value_class(class);
        reparse(v)
    }
    fn tamper_readers(rec: &PolicyRecord, readers: &[String]) -> PolicyRecord {
        let mut v = to_value(rec);
        v["readers"] = serde_json::json!(readers);
        reparse(v)
    }
    fn tamper_seq(rec: &PolicyRecord, seq: u64) -> PolicyRecord {
        let mut v = to_value(rec);
        v["seq"] = serde_json::json!(seq);
        reparse(v)
    }
    fn to_value_class(class: ReadClass) -> serde_json::Value {
        // Serialize a bare ReadClass through a wrapper so the snake_case rename
        // applies (matches the field's wire form).
        #[derive(serde::Serialize)]
        struct W {
            c: ReadClass,
        }
        serde_json::to_value(W { c: class }).expect("serialize class")["c"].clone()
    }

    #[test]
    fn authorization_form_is_reported() {
        let owner_rec =
            PolicyRecord::sign_owner(&owner_did(), None, ReadClass::Owner, &[], 1, &owner());
        assert!(matches!(
            owner_rec.authorization(),
            Authorization::OwnerSigned(_)
        ));
        let attested = PolicyRecord::attest_provider(
            "did:plc:owner",
            None,
            ReadClass::Owner,
            &[],
            1,
            "jti",
            &attest_key(),
        );
        assert!(matches!(
            attested.authorization(),
            Authorization::ProviderAttested(_)
        ));
    }

    // --- ResolvedPolicy membership (the pure gate logic Phase 3 wires in) ---

    use super::ResolvedPolicy;

    const OWNER: &str = "id:owner";

    #[test]
    fn world_allows_anonymous_and_any_caller() {
        let p = ResolvedPolicy::world();
        assert!(p.allows(None, OWNER), "anon reads world");
        assert!(p.allows(Some("did:plc:stranger"), OWNER), "any DID reads world");
    }

    #[test]
    fn owner_class_allows_only_the_owner() {
        let p = ResolvedPolicy::deny(); // owner-only, no readers
        assert!(p.allows(Some(OWNER), OWNER), "owner reads own target");
        assert!(!p.allows(None, OWNER), "anon denied");
        assert!(!p.allows(Some("did:plc:stranger"), OWNER), "stranger denied");
    }

    #[test]
    fn grantees_class_allows_owner_and_listed_readers_only() {
        let rec = PolicyRecord::sign_owner(
            &owner_did(),
            None,
            ReadClass::Grantees,
            &[grantee("alice")],
            1,
            &owner(),
        );
        let p = ResolvedPolicy::from_record(&rec);
        assert!(p.allows(Some(&owner_did()), &owner_did()), "owner always reads");
        assert!(p.allows(Some(&grantee("alice")), &owner_did()), "listed reader reads");
        assert!(!p.allows(Some(&grantee("bob")), &owner_did()), "unlisted denied");
        assert!(!p.allows(None, &owner_did()), "anon denied");
    }
}
