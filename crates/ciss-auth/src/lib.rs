//! `ciss-auth` — authentication for CISS.
//!
//! This crate answers one question: **who is making this request, provably?** It
//! turns an untrusted credential into a [`Principal`] — either [`Principal::Anonymous`]
//! or a cryptographically verified [`Principal::Authenticated`] DID — and nothing
//! else. Authorization ("may this principal do this here?") is a separate concern
//! that stays in the metering core, at the dispatch boundary (ADR 0001).
//!
//! Isolating authentication in its own crate is deliberate: it is the highest-risk
//! crypto surface, so it gets its own test suite and dependency graph, and the
//! *mechanism* can evolve — this v0 verifies a signed session over the `id:`
//! identity space (real crypto, key-possession proof), and a later version swaps
//! in atproto OAuth/DPoP token verification with DID resolution — all behind this
//! same `Principal` boundary, without the core changing.
//!
//! ## The v0 mechanism: a signed session
//!
//! A caller proves it holds the key that derives its `id:<…>` DID by signing a
//! challenge. [`verify_session`] checks three things, all of which a forger fails:
//! the presented key derives the claimed DID, the key is canonically encoded, and
//! the signature over the challenge verifies **strictly**. A caller that merely
//! *names* a victim DID (the pre-auth "formality" bug, finding A2) cannot produce
//! the signature, so it is refused.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// The raw length of an Ed25519 public key.
const PUBLIC_KEY_LEN: usize = 32;

/// The number of hex characters of the public-key digest kept in an `id:` DID —
/// must match `ciss::identity::derive_id` (the core derives DIDs the same way).
const ID_DIGEST_HEX_LEN: usize = 16;

/// Why authentication failed. Every variant means "not authenticated"; the
/// caller maps them to a 401.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// The presented public key was not valid hex.
    #[error("public key is not valid hex")]
    BadKeyHex,
    /// The presented public key was not [`PUBLIC_KEY_LEN`] bytes.
    #[error("public key is not {PUBLIC_KEY_LEN} bytes")]
    BadKeyLen,
    /// The public key was not a valid, canonically-encoded Ed25519 point.
    #[error("public key is not a canonical Ed25519 point")]
    BadKey,
    /// The signature was not valid hex.
    #[error("signature is not valid hex")]
    BadSignatureHex,
    /// The signature bytes were not a well-formed Ed25519 signature.
    #[error("signature is malformed")]
    BadSignature,
    /// The presented key does not derive the claimed DID.
    #[error("public key does not derive the claimed DID")]
    DidMismatch,
    /// The signature over the challenge did not verify under the presented key.
    #[error("session signature did not verify")]
    Unverified,
}

/// Who is making a request, after authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// No credential presented (or none required) — an anonymous caller.
    Anonymous,
    /// A cryptographically verified DID.
    Authenticated(String),
}

impl Principal {
    /// The verified DID, if this principal is authenticated.
    #[must_use]
    pub fn did(&self) -> Option<&str> {
        match self {
            Principal::Authenticated(did) => Some(did),
            Principal::Anonymous => None,
        }
    }

    /// Whether this principal is the verified owner of `did`.
    #[must_use]
    pub fn is(&self, did: &str) -> bool {
        self.did() == Some(did)
    }

    /// Whether this principal is authenticated at all.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Principal::Authenticated(_))
    }
}

/// Derive the `id:<16 hex>` identifier for a public key. Kept byte-identical to
/// `ciss::identity::derive_id` so a session verified here names the same DID the
/// core stores under.
fn derive_id(verifying_key: &VerifyingKey) -> String {
    let digest = hex::encode(Sha256::digest(verifying_key.to_bytes()));
    format!("id:{}", &digest[..ID_DIGEST_HEX_LEN])
}

/// Parse a public key from hex, rejecting a non-canonical encoding (two encodings
/// decoding to one point would otherwise yield two DIDs — finding I7).
fn parse_public_key(public_key_hex: &str) -> Result<VerifyingKey, AuthError> {
    let bytes = hex::decode(public_key_hex).map_err(|_| AuthError::BadKeyHex)?;
    let array: [u8; PUBLIC_KEY_LEN] =
        bytes.as_slice().try_into().map_err(|_| AuthError::BadKeyLen)?;
    let key = VerifyingKey::from_bytes(&array).map_err(|_| AuthError::BadKey)?;
    // Reject a non-canonical encoding (I7) and a small-order / weak key (I6): a
    // weak session key would verify any challenge.
    if key.to_bytes() != array || key.is_weak() {
        return Err(AuthError::BadKey);
    }
    Ok(key)
}

/// Verify a signed session: the caller proves possession of the key that derives
/// `claimed_did` by signing `challenge`.
///
/// Returns [`Principal::Authenticated`] only when the key derives the claimed DID,
/// is canonically encoded, and strictly verifies the signature over `challenge`.
///
/// # Errors
///
/// Returns [`AuthError`] for any malformed input, a key that does not derive the
/// claimed DID, or a signature that does not verify.
pub fn verify_session(
    claimed_did: &str,
    public_key_hex: &str,
    challenge: &[u8],
    signature_hex: &str,
) -> Result<Principal, AuthError> {
    let key = parse_public_key(public_key_hex)?;
    if derive_id(&key) != claimed_did {
        return Err(AuthError::DidMismatch);
    }
    let signature_bytes = hex::decode(signature_hex).map_err(|_| AuthError::BadSignatureHex)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| AuthError::BadSignature)?;
    key.verify_strict(challenge, &signature)
        .map_err(|_| AuthError::Unverified)?;
    Ok(Principal::Authenticated(claimed_did.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{derive_id, verify_session, AuthError, Principal};
    use ed25519_dalek::{Signer, SigningKey};

    /// A deterministic keypair from a seed label (mirrors the crate's own derive).
    fn keypair(label: &str) -> SigningKey {
        let seed: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes()).into();
        SigningKey::from_bytes(&seed)
    }

    fn did_of(sk: &SigningKey) -> String {
        derive_id(&sk.verifying_key())
    }

    #[test]
    fn a_valid_session_authenticates_the_owner() {
        let owner = keypair("owner");
        let did = did_of(&owner);
        let challenge = b"nonce-123";
        let sig = hex::encode(owner.sign(challenge).to_bytes());
        let principal = verify_session(
            &did,
            &hex::encode(owner.verifying_key().to_bytes()),
            challenge,
            &sig,
        )
        .expect("valid session");
        assert_eq!(principal, Principal::Authenticated(did.clone()));
        assert!(principal.is(&did));
        assert!(principal.is_authenticated());
    }

    #[test]
    fn an_impostor_presenting_their_own_key_for_a_victim_did_is_refused() {
        // The attacker holds their own key but claims the victim's DID (A2).
        let attacker = keypair("attacker");
        let victim_did = did_of(&keypair("victim"));
        let challenge = b"nonce-123";
        let sig = hex::encode(attacker.sign(challenge).to_bytes());
        let err = verify_session(
            &victim_did,
            &hex::encode(attacker.verifying_key().to_bytes()),
            challenge,
            &sig,
        )
        .expect_err("must be refused");
        assert_eq!(err, AuthError::DidMismatch, "key does not derive the DID");
    }

    #[test]
    fn an_impostor_presenting_the_victims_public_key_cannot_sign_for_it() {
        // The victim's public key is public; the attacker presents it (so the DID
        // matches) but cannot produce the victim's signature (A2's sharp edge).
        let victim = keypair("victim");
        let attacker = keypair("attacker");
        let victim_did = did_of(&victim);
        let challenge = b"nonce-123";
        let forged_sig = hex::encode(attacker.sign(challenge).to_bytes());
        let err = verify_session(
            &victim_did,
            &hex::encode(victim.verifying_key().to_bytes()),
            challenge,
            &forged_sig,
        )
        .expect_err("must be refused");
        assert_eq!(err, AuthError::Unverified, "signature is not the victim's");
    }

    #[test]
    fn a_signature_over_a_different_challenge_does_not_verify() {
        let owner = keypair("owner");
        let did = did_of(&owner);
        let sig = hex::encode(owner.sign(b"nonce-A").to_bytes());
        let err = verify_session(
            &did,
            &hex::encode(owner.verifying_key().to_bytes()),
            b"nonce-B",
            &sig,
        )
        .expect_err("challenge mismatch");
        assert_eq!(err, AuthError::Unverified);
    }

    #[test]
    fn malformed_inputs_are_rejected_not_panicked() {
        let owner = keypair("owner");
        let did = did_of(&owner);
        let pk = hex::encode(owner.verifying_key().to_bytes());
        let good_sig = hex::encode(owner.sign(b"c").to_bytes());
        assert_eq!(
            verify_session(&did, "nothex", b"c", &good_sig),
            Err(AuthError::BadKeyHex),
        );
        assert_eq!(
            verify_session(&did, "00ff", b"c", &good_sig),
            Err(AuthError::BadKeyLen),
        );
        assert_eq!(
            verify_session(&did, &pk, b"c", "nothex"),
            Err(AuthError::BadSignatureHex),
        );
        assert_eq!(
            verify_session(&did, &pk, b"c", "00ff"),
            Err(AuthError::BadSignature),
        );
    }

    #[test]
    fn anonymous_principal_owns_no_did() {
        let anon = Principal::Anonymous;
        assert_eq!(anon.did(), None);
        assert!(!anon.is_authenticated());
        assert!(!anon.is("id:0000000000000000"));
    }
}
