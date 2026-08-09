//! The self-assertion substrate (dials plan D1): one mechanism for every
//! customer-signed setting.
//!
//! CISS grew the same machine three times — the manifest (I5), the policy
//! record (Z6), the client's `DeviceHead` — and was about to grow a fourth
//! (the ceiling dial). Each is: an owner-signed record over a
//! **domain-separated structured preimage** binding every field, a
//! **strictly-monotonic `seq`**, **key↔DID self-authorization**
//! (`derive_id(key) == did` — no key registry, no operator), and a pure
//! verify choke point. This module is that machine built once. A "kind"
//! (e.g. `policy`, `dial/ceiling`, `dial/account-mode`) supplies its typed
//! body, a canonical fold of that body, and structural validation; the
//! substrate supplies domain separation, did/subkey/seq binding, the two
//! authorization models, and the provider **acknowledgment** — the
//! countersignature that lets a customer *prove their assertion took
//! effect* (without an ack, success is indistinguishable from failure).
//!
//! Authorization models (both inherited from the policy record, ADR 0001):
//!
//! - **Model A (`OwnerSigned`)** — an `id:` owner signs the record body
//!   itself; valid only when the signing key derives the target DID.
//! - **Model C (`ProviderAttested`)** — a `did:` owner authorizes the
//!   *action* via a service-auth JWT; CISS verifies the JWT and
//!   counter-signs the stored record with its dedicated attestation key.
//!
//! Not to be confused with `crate::dial` — the *assurance* dial (audit-tier
//! pricing). Assertion kinds named `dial/…` are customer settings; the
//! assurance tier will itself become one such kind when it grows a wire
//! surface.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::crypto::{public_key_from_hex, verify_message, Keypair};
use crate::identifiers::{Did, IdentitySpace};
use crate::identity::derive_id;

/// Domain prefix for the record preimage: `ciss/v1/assertion:<kind>:…`.
pub const RECORD_DOMAIN_PREFIX: &str = "ciss/v1/assertion";
/// Domain prefix for the Model-C attestation preimage.
pub const ATTEST_DOMAIN_PREFIX: &str = "ciss/v1/assertion-attest";
/// Domain prefix for the provider acknowledgment preimage.
pub const ACK_DOMAIN_PREFIX: &str = "ciss/v1/assertion-ack";

/// A Model-A owner signature (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerSigned {
    /// The owner's ed25519 public key, hex. Must derive the target DID.
    pub signer: String,
    /// Hex signature over the record preimage.
    pub sig: String,
}

/// A Model-C provider attestation (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttested {
    /// The DID this assertion governs (the JWT `iss`).
    pub owner_did: String,
    /// The single-use JWT id that authorized the action (audit trail).
    pub authorizing_jti: String,
    /// CISS's hex signature over the attestation preimage (dedicated
    /// attestation key — never the receipt/billing key).
    pub provider_sig: String,
}

/// How an assertion's authority is proven.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Authorization {
    /// Model A — the `id:` owner self-signed.
    OwnerSigned(OwnerSigned),
    /// Model C — CISS counter-signed after verifying the owner's JWT.
    ProviderAttested(ProviderAttested),
}

/// One customer-signed setting: the envelope every kind shares. The `body`
/// is kind-specific JSON; its **canonical fold** (supplied by the kind) is
/// what the signature binds, so no body field can change without
/// invalidating it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAssertion {
    /// Whose assertion.
    pub did: String,
    /// The kind tag (e.g. `policy`, `dial/ceiling`); part of the signing
    /// domain, so a signature for one kind can never verify as another.
    pub kind: String,
    /// Optional sub-target (e.g. an object cid for a per-object policy).
    pub subkey: Option<String>,
    /// Strictly-monotonic per `(did, kind, subkey)`.
    pub seq: u64,
    /// Kind-specific fields (validated and folded by the kind).
    pub body: serde_json::Value,
    /// Model A or Model C proof.
    pub authorization: Authorization,
}

/// The provider's acknowledgment: a signature binding the exact stored
/// record (its digest) under the ack domain. Returned on write and on
/// read-back; verifiable against the provider's published attestation key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    /// The provider's attestation public key, hex.
    pub signer: String,
    /// Hex signature over the ack preimage.
    pub sig: String,
}

/// The preimage tag for an absent/present subkey. `:` is forbidden inside a
/// subkey so the folded preimage cannot be ambiguous.
fn subkey_tag(subkey: Option<&str>) -> &str {
    subkey.unwrap_or("-")
}

/// A subkey is preimage-safe: non-empty, no `:` (field separator), and not
/// the literal absent-tag `-`.
fn subkey_well_formed(subkey: Option<&str>) -> bool {
    match subkey {
        None => true,
        Some(s) => !s.is_empty() && s != "-" && !s.contains(':'),
    }
}

/// The record preimage a Model-A owner signs.
#[must_use]
pub fn record_preimage(
    kind: &str,
    did: &str,
    subkey: Option<&str>,
    seq: u64,
    body_fold: &str,
) -> String {
    format!("{RECORD_DOMAIN_PREFIX}:{kind}:{did}:{}:{seq}:{body_fold}", subkey_tag(subkey))
}

/// The attestation preimage CISS signs for a Model-C record.
#[must_use]
pub fn attest_preimage(
    kind: &str,
    owner_did: &str,
    did: &str,
    subkey: Option<&str>,
    seq: u64,
    body_fold: &str,
) -> String {
    format!(
        "{ATTEST_DOMAIN_PREFIX}:{kind}:{owner_did}:{did}:{}:{seq}:{body_fold}",
        subkey_tag(subkey)
    )
}

/// The acknowledgment preimage: binds kind, target, seq, and the digest of
/// the exact stored record.
#[must_use]
pub fn ack_preimage(
    kind: &str,
    did: &str,
    subkey: Option<&str>,
    seq: u64,
    record_digest_hex: &str,
) -> String {
    format!(
        "{ACK_DOMAIN_PREFIX}:{kind}:{did}:{}:{seq}:{record_digest_hex}",
        subkey_tag(subkey)
    )
}

impl SignedAssertion {
    /// Build and Model-A-sign an assertion. `body_fold` must be the kind's
    /// canonical fold of `body` — the signature binds the fold, and
    /// [`SignedAssertion::verify`] re-derives it from the same kind fold.
    #[must_use]
    pub fn sign_owner(
        kind: &str,
        did: &str,
        subkey: Option<&str>,
        seq: u64,
        body: serde_json::Value,
        body_fold: &str,
        keypair: &Keypair,
    ) -> Self {
        let sig = keypair.sign_message(&record_preimage(kind, did, subkey, seq, body_fold));
        Self {
            did: did.to_owned(),
            kind: kind.to_owned(),
            subkey: subkey.map(str::to_owned),
            seq,
            body,
            authorization: Authorization::OwnerSigned(OwnerSigned {
                signer: keypair.public_key_hex(),
                sig,
            }),
        }
    }

    /// Build a Model-C assertion: CISS attests, having verified the owner's
    /// service-auth JWT (`jti` recorded for audit).
    #[must_use]
    #[allow(clippy::too_many_arguments)] // the envelope's fields, verbatim
    pub fn attest_provider(
        kind: &str,
        owner_did: &str,
        subkey: Option<&str>,
        seq: u64,
        body: serde_json::Value,
        body_fold: &str,
        jti: &str,
        attest_keypair: &Keypair,
    ) -> Self {
        let provider_sig = attest_keypair
            .sign_message(&attest_preimage(kind, owner_did, owner_did, subkey, seq, body_fold));
        Self {
            did: owner_did.to_owned(),
            kind: kind.to_owned(),
            subkey: subkey.map(str::to_owned),
            seq,
            body,
            authorization: Authorization::ProviderAttested(ProviderAttested {
                owner_did: owner_did.to_owned(),
                authorizing_jti: jti.to_owned(),
                provider_sig,
            }),
        }
    }

    /// Verify this assertion: structure, seq advancement, and its
    /// authorization proof. `body_fold` is the kind's canonical fold of the
    /// (already kind-validated) body — passing the fold rather than
    /// re-deriving it here keeps the substrate body-agnostic. Returns
    /// `false` on any failure; this is the single verification choke point.
    #[must_use]
    pub fn verify(
        &self,
        body_fold: &str,
        prior_seq: Option<u64>,
        provider_attest_pubkey: &VerifyingKey,
    ) -> bool {
        let Ok(target_did) = Did::parse(&self.did) else {
            return false;
        };
        if self.kind.is_empty() || self.kind.contains(':') {
            return false;
        }
        if !subkey_well_formed(self.subkey.as_deref()) {
            return false;
        }
        if let Some(prior) = prior_seq {
            if self.seq <= prior {
                return false;
            }
        }
        match &self.authorization {
            Authorization::OwnerSigned(owner) => {
                if target_did.space() != IdentitySpace::Id {
                    return false;
                }
                let Ok(signer_key) = public_key_from_hex(&owner.signer) else {
                    return false;
                };
                if derive_id(&signer_key) != self.did {
                    return false;
                }
                verify_message(
                    &signer_key,
                    &record_preimage(
                        &self.kind,
                        &self.did,
                        self.subkey.as_deref(),
                        self.seq,
                        body_fold,
                    ),
                    &owner.sig,
                )
            }
            Authorization::ProviderAttested(attested) => {
                if attested.owner_did != self.did {
                    return false;
                }
                verify_message(
                    provider_attest_pubkey,
                    &attest_preimage(
                        &self.kind,
                        &attested.owner_did,
                        &self.did,
                        self.subkey.as_deref(),
                        self.seq,
                        body_fold,
                    ),
                    &attested.provider_sig,
                )
            }
        }
    }

    /// The record digest the ack binds: sha-256 hex over the record's
    /// canonical JSON (struct field order is fixed by the definition, so
    /// serialization is deterministic for a given record).
    ///
    /// # Errors
    ///
    /// Serialization failure (never expected for well-formed records).
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        let digest = sha2::Sha256::digest(json.as_bytes());
        Ok(digest.iter().fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        }))
    }
}

/// Produce the provider acknowledgment for a stored assertion.
///
/// # Errors
///
/// Digest serialization failure (never expected).
pub fn make_ack(
    assertion: &SignedAssertion,
    attest_keypair: &Keypair,
) -> Result<Ack, serde_json::Error> {
    let digest = assertion.digest()?;
    let sig = attest_keypair.sign_message(&ack_preimage(
        &assertion.kind,
        &assertion.did,
        assertion.subkey.as_deref(),
        assertion.seq,
        &digest,
    ));
    Ok(Ack { signer: attest_keypair.public_key_hex(), sig })
}

/// Verify an acknowledgment against the exact record it claims to bind.
#[must_use]
pub fn verify_ack(
    assertion: &SignedAssertion,
    ack: &Ack,
    provider_attest_pubkey: &VerifyingKey,
) -> bool {
    let Ok(digest) = assertion.digest() else {
        return false;
    };
    verify_message(
        provider_attest_pubkey,
        &ack_preimage(
            &assertion.kind,
            &assertion.did,
            assertion.subkey.as_deref(),
            assertion.seq,
            &digest,
        ),
        &ack.sig,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_keypair;

    fn owner() -> Keypair {
        derive_keypair("master", "assertion-owner")
    }

    fn attest() -> Keypair {
        derive_keypair("master", "assertion-attest")
    }

    fn owner_did() -> String {
        derive_id(&owner().verifying_key())
    }

    fn body() -> serde_json::Value {
        serde_json::json!({"ceiling_cents": 500})
    }

    const FOLD: &str = "ceiling_cents=500";

    /// Model A round-trips, and EVERY envelope field is bound: mutating the
    /// did, kind, subkey, seq, or the body fold breaks the signature.
    #[test]
    fn model_a_binds_every_field() {
        let a = SignedAssertion::sign_owner(
            "dial/ceiling",
            &owner_did(),
            None,
            3,
            body(),
            FOLD,
            &owner(),
        );
        let key = attest().verifying_key();
        assert!(a.verify(FOLD, None, &key));
        assert!(a.verify(FOLD, Some(2), &key), "seq 3 supersedes prior 2");

        let mut kind = a.clone();
        kind.kind = "dial/account-mode".to_owned();
        assert!(!kind.verify(FOLD, None, &key), "kind is bound (domain separation)");

        let mut seq = a.clone();
        seq.seq = 4;
        assert!(!seq.verify(FOLD, None, &key), "seq is bound");

        let mut sub = a.clone();
        sub.subkey = Some("aabb".to_owned());
        assert!(!sub.verify(FOLD, None, &key), "subkey is bound");

        assert!(!a.verify("ceiling_cents=9999", None, &key), "the body fold is bound");
    }

    /// Model A is only valid for an `id:` target whose DID the signing key
    /// derives — a foreign key or a `did:` target fails.
    #[test]
    fn model_a_requires_the_deriving_key() {
        let stranger = derive_keypair("master", "assertion-stranger");
        let forged = SignedAssertion::sign_owner(
            "dial/ceiling",
            &owner_did(),
            None,
            1,
            body(),
            FOLD,
            &stranger,
        );
        assert!(
            !forged.verify(FOLD, None, &attest().verifying_key()),
            "a non-deriving signer must fail"
        );

        let did_target = SignedAssertion::sign_owner(
            "dial/ceiling",
            "did:web:example.com",
            None,
            1,
            body(),
            FOLD,
            &owner(),
        );
        assert!(
            !did_target.verify(FOLD, None, &attest().verifying_key()),
            "Model A cannot govern a did: target"
        );
    }

    /// Model C round-trips under the attestation key; a mismatched
    /// `owner_did` or a foreign attest key fails.
    #[test]
    fn model_c_attests_and_binds_the_owner() {
        let a = SignedAssertion::attest_provider(
            "dial/ceiling",
            "did:web:alice.example",
            None,
            7,
            body(),
            FOLD,
            "jti-123",
            &attest(),
        );
        assert!(a.verify(FOLD, None, &attest().verifying_key()));
        assert!(
            !a.verify(FOLD, None, &owner().verifying_key()),
            "only the dedicated attestation key verifies"
        );

        let mut hijack = a.clone();
        if let Authorization::ProviderAttested(att) = &mut hijack.authorization {
            att.owner_did = "did:web:mallory.example".to_owned();
        }
        assert!(!hijack.verify(FOLD, None, &attest().verifying_key()));
    }

    /// The seq must strictly advance past the prior: equal and lower fail.
    #[test]
    fn seq_strictly_advances() {
        let a = SignedAssertion::sign_owner(
            "dial/ceiling",
            &owner_did(),
            None,
            5,
            body(),
            FOLD,
            &owner(),
        );
        let key = attest().verifying_key();
        assert!(a.verify(FOLD, Some(4), &key));
        assert!(!a.verify(FOLD, Some(5), &key), "equal seq is a replay");
        assert!(!a.verify(FOLD, Some(6), &key), "lower seq is a rollback");
    }

    /// Subkeys must be preimage-safe: `:` (the field separator), empty, and
    /// the absent-tag `-` are all refused.
    #[test]
    fn subkey_preimage_safety() {
        let key = attest().verifying_key();
        for bad in ["a:b", "", "-"] {
            let a = SignedAssertion::sign_owner(
                "policy",
                &owner_did(),
                Some(bad),
                1,
                body(),
                FOLD,
                &owner(),
            );
            assert!(!a.verify(FOLD, None, &key), "subkey {bad:?} must be refused");
        }
    }

    /// The ack binds the EXACT record: it verifies against the record as
    /// stored, fails against a tampered body, and fails under a foreign key.
    #[test]
    fn ack_binds_the_exact_record() {
        let a = SignedAssertion::sign_owner(
            "dial/ceiling",
            &owner_did(),
            None,
            1,
            body(),
            FOLD,
            &owner(),
        );
        let ack = make_ack(&a, &attest()).expect("ack");
        assert!(verify_ack(&a, &ack, &attest().verifying_key()));

        let mut tampered = a.clone();
        tampered.body = serde_json::json!({"ceiling_cents": 9_999_999});
        assert!(
            !verify_ack(&tampered, &ack, &attest().verifying_key()),
            "an ack must not transfer to an altered record"
        );
        assert!(
            !verify_ack(&a, &ack, &owner().verifying_key()),
            "a foreign key must not verify the ack"
        );
    }
}
