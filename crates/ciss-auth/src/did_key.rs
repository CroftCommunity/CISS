//! `did:key` decoding + ECDSA verification for atproto signing keys.
//!
//! Ported from `rsky-crypto` (Apache-2.0): an atproto signing key is published as
//! a `did:key:z…` — multibase(base58btc) over a multicodec-prefixed compressed
//! public key. secp256k1 (ES256K) and P-256 (ES256) are the two atproto curves.
//!
//! Verification is over adversarial input, so it enforces what a sign-only helper
//! does not: **canonical low-S signatures only** (high-S is rejected as malleable),
//! fixed-length signature encoding, and curve dispatch taken from the key itself.
//! The curves are pure-Rust (`k256`/`p256`) — no C toolchain.

use k256::ecdsa::signature::Verifier as _;

use crate::JwtError;

/// The multicodec varint prefix for a secp256k1 public key (`0xe7`).
const SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];
/// The multicodec varint prefix for a P-256 public key (`0x1200`).
const P256_PREFIX: [u8; 2] = [0x80, 0x24];

/// An atproto verification key, dispatched by curve.
#[derive(Debug, Clone)]
pub enum AtprotoKey {
    /// secp256k1 (ES256K) — the common atproto repo-key curve.
    Secp256k1(k256::ecdsa::VerifyingKey),
    /// NIST P-256 (ES256).
    P256(p256::ecdsa::VerifyingKey),
}

impl AtprotoKey {
    /// Parse an atproto `did:key:z…` into a verification key.
    ///
    /// # Errors
    ///
    /// [`JwtError::BadDidKey`] for a malformed encoding or point;
    /// [`JwtError::UnsupportedKeyType`] for a non-secp256k1/P-256 codec.
    pub fn from_did_key(did_key: &str) -> Result<Self, JwtError> {
        let multikey = did_key.strip_prefix("did:key:").ok_or(JwtError::BadDidKey)?;
        let (_base, bytes) = multibase::decode(multikey).map_err(|_| JwtError::BadDidKey)?;
        if let Some(key) = bytes.strip_prefix(SECP256K1_PREFIX.as_slice()) {
            let vk =
                k256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| JwtError::BadDidKey)?;
            return Ok(AtprotoKey::Secp256k1(vk));
        }
        if let Some(key) = bytes.strip_prefix(P256_PREFIX.as_slice()) {
            let vk =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| JwtError::BadDidKey)?;
            return Ok(AtprotoKey::P256(vk));
        }
        Err(JwtError::UnsupportedKeyType)
    }

    /// Verify a fixed-length (P1363, `r‖s`) ECDSA signature over `signing_input`
    /// (the JWS `header.payload`, hashed with SHA-256 internally).
    ///
    /// # Errors
    ///
    /// [`JwtError::BadSignature`] if the bytes are not a well-formed signature;
    /// [`JwtError::MalleableSignature`] if S is high (non-canonical);
    /// [`JwtError::SignatureInvalid`] if it does not verify.
    pub fn verify(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        match self {
            AtprotoKey::Secp256k1(vk) => {
                let sig = k256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JwtError::BadSignature)?;
                // Reject a high-S (malleable) signature: `normalize_s` yields Some
                // only when the input was high-S. atproto/JWS require canonical low-S.
                if sig.normalize_s().is_some() {
                    return Err(JwtError::MalleableSignature);
                }
                vk.verify(signing_input, &sig).map_err(|_| JwtError::SignatureInvalid)
            }
            AtprotoKey::P256(vk) => {
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JwtError::BadSignature)?;
                if sig.normalize_s().is_some() {
                    return Err(JwtError::MalleableSignature);
                }
                vk.verify(signing_input, &sig).map_err(|_| JwtError::SignatureInvalid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AtprotoKey;
    use crate::JwtError;

    // --- test signers: produce a did:key + a signature the way an issuer would ---

    fn k256_did_key(vk: &k256::ecdsa::VerifyingKey) -> String {
        let point = vk.to_encoded_point(true); // compressed
        let bytes = [&[0xe7u8, 0x01], point.as_bytes()].concat();
        format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, bytes))
    }

    fn p256_did_key(vk: &p256::ecdsa::VerifyingKey) -> String {
        let point = vk.to_encoded_point(true);
        let bytes = [&[0x80u8, 0x24], point.as_bytes()].concat();
        format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, bytes))
    }

    const MSG: &[u8] = b"header.payload";

    #[test]
    fn verifies_a_valid_secp256k1_signature() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let did = k256_did_key(sk.verifying_key());
        let sig: Signature = sk.sign(MSG);
        let key = AtprotoKey::from_did_key(&did).expect("parses");
        assert!(key.verify(MSG, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn verifies_a_valid_p256_signature() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let did = p256_did_key(sk.verifying_key());
        let sig: Signature = sk.sign(MSG);
        let key = AtprotoKey::from_did_key(&did).expect("parses");
        assert!(key.verify(MSG, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn rejects_a_signature_over_different_bytes() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let did = k256_did_key(sk.verifying_key());
        let sig: Signature = sk.sign(b"header.OTHER");
        let key = AtprotoKey::from_did_key(&did).expect("parses");
        assert_eq!(
            key.verify(MSG, &sig.to_bytes()),
            Err(JwtError::SignatureInvalid),
        );
    }

    #[test]
    fn rejects_a_signature_from_a_different_key() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        let victim = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let attacker = SigningKey::from_slice(&[0x99u8; 32]).unwrap();
        let victim_did = k256_did_key(victim.verifying_key());
        let forged: Signature = attacker.sign(MSG);
        let key = AtprotoKey::from_did_key(&victim_did).expect("parses");
        assert_eq!(
            key.verify(MSG, &forged.to_bytes()),
            Err(JwtError::SignatureInvalid),
        );
    }

    #[test]
    fn rejects_a_high_s_malleable_signature() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let did = k256_did_key(sk.verifying_key());
        let low: Signature = sk.sign(MSG);
        // The high-S counterpart (-s mod n) is a second valid encoding of the same
        // signature — the malleability a JWS verifier must reject.
        let high = {
            let (r, s) = (low.r(), low.s());
            Signature::from_scalars(*r.as_ref(), -*s.as_ref()).unwrap()
        };
        let key = AtprotoKey::from_did_key(&did).expect("parses");
        assert_eq!(
            key.verify(MSG, &high.to_bytes()),
            Err(JwtError::MalleableSignature),
        );
    }

    #[test]
    fn rejects_malformed_signature_bytes() {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let did = k256_did_key(sk.verifying_key());
        let key = AtprotoKey::from_did_key(&did).expect("parses");
        assert_eq!(key.verify(MSG, b"tooshort"), Err(JwtError::BadSignature));
    }

    #[test]
    fn rejects_a_non_did_key_and_unsupported_curve() {
        assert_eq!(AtprotoKey::from_did_key("not-a-did-key").unwrap_err(), JwtError::BadDidKey);
        // An ed25519 did:key (multicodec 0xed) is a supported atproto identity key
        // but not a signing curve we verify — unsupported, not malformed.
        let ed = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, [&[0xedu8, 0x01], &[0u8; 32][..]].concat()),
        );
        assert_eq!(AtprotoKey::from_did_key(&ed).unwrap_err(), JwtError::UnsupportedKeyType);
    }
}
