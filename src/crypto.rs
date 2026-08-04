//! The cryptographic floor: fingerprints (SHA-256) and signatures (Ed25519).
//!
//! Ports `item-storage-protocol-standalone/src/crypto.ts`. Keys are derived
//! deterministically from a master seed + a role label, so every run produces
//! the same keypairs and (Ed25519 being deterministic per RFC 8032) the same
//! signatures — the reproducibility that lets every assertion be exact.
//!
//! `SEAM:` a hex-encoded SHA-256 stands in for a `CIDv1` over `DAG-CBOR` (Phase 2
//! closes this with the in-corpus `serde_ipld_dagcbor` + `ipld-core` + `sha2`
//! path). The tamper-evidence property is identical; only the encoding differs.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// The length in bytes of a raw Ed25519 public key.
const PUBLIC_KEY_LEN: usize = 32;

/// Errors from reconstructing a public key from its wire (hex) form.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The supplied string was not valid hexadecimal.
    #[error("public key is not valid hexadecimal")]
    InvalidHex,
    /// The decoded key was not exactly [`PUBLIC_KEY_LEN`] bytes.
    #[error("public key must be {PUBLIC_KEY_LEN} bytes, got {got}")]
    InvalidKeyLength {
        /// The number of bytes actually decoded.
        got: usize,
    },
    /// The bytes did not decode to a valid Ed25519 curve point.
    #[error("public key is not a valid Ed25519 point")]
    InvalidPublicKey,
}

/// SHA-256 of raw bytes, hex-encoded. This is our "fingerprint".
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// A keypair bound to a role label.
///
/// Holds the Ed25519 signing key, which is zeroized on drop (via the
/// `ed25519-dalek` `zeroize` feature). `Debug` is intentionally not derived so
/// the secret cannot leak through formatting.
pub struct Keypair {
    label: String,
    signing_key: SigningKey,
}

impl Keypair {
    /// The role label this keypair was derived for (e.g. `"customer"`).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The public (verifying) key — the pinnable identity.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The raw 32-byte public key, hex-encoded — the pinnable identity on the wire.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }

    /// Sign a UTF-8 message, returning a hex-encoded signature.
    #[must_use]
    pub fn sign_message(&self, message: &str) -> String {
        let signature = self.signing_key.sign(message.as_bytes());
        hex::encode(signature.to_bytes())
    }
}

/// Derive a deterministic Ed25519 keypair from a master seed and a role label.
///
/// The seed for the key is `SHA-256("{master_seed}::keyseed::{label}")`, matching
/// the TypeScript oracle so signatures are comparable against it.
#[must_use]
pub fn derive_keypair(master_seed: &str, label: &str) -> Keypair {
    let mut hasher = Sha256::new();
    hasher.update(format!("{master_seed}::keyseed::{label}").as_bytes());
    let mut seed: [u8; 32] = hasher.finalize().into();
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Keypair {
        label: label.to_owned(),
        signing_key,
    }
}

/// Reconstruct a verify-only public key from its raw hex form (as a peer pins it).
///
/// # Errors
///
/// Returns [`CryptoError`] if the input is not valid hex, is not
/// [`PUBLIC_KEY_LEN`] bytes, or is not a valid Ed25519 point.
pub fn public_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes = hex::decode(public_key_hex).map_err(|_| CryptoError::InvalidHex)?;
    let array: [u8; PUBLIC_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength { got: bytes.len() })?;
    let key = VerifyingKey::from_bytes(&array).map_err(|_| CryptoError::InvalidPublicKey)?;
    // Reject a non-canonical encoding (two encodings decoding to one point would
    // otherwise yield two DIDs) and a small-order / weak key (which would verify
    // *any* signature) — finding I6.
    if key.to_bytes() != array || key.is_weak() {
        return Err(CryptoError::InvalidPublicKey);
    }
    Ok(key)
}

/// Verify a hex signature over a UTF-8 message against a pinned public key.
///
/// Returns `false` for a bad signature, a malformed signature encoding, or a
/// mismatched key — verification failure is a legitimate `false`, not an error
/// to propagate (matching the oracle's semantics).
#[must_use]
pub fn verify_message(verifying_key: &VerifyingKey, message: &str, signature_hex: &str) -> bool {
    let Ok(signature_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    // Strict verification (I6): rejects malleable signatures and small-order R,
    // closing the signature-malleability gap the permissive `verify` leaves open.
    verifying_key.verify_strict(message.as_bytes(), &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{derive_keypair, public_key_from_hex, verify_message, CryptoError};

    #[test]
    fn derivation_is_deterministic_in_seed_and_label() {
        let a = derive_keypair("master", "customer");
        let b = derive_keypair("master", "customer");
        assert_eq!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn distinct_labels_derive_distinct_keys() {
        let customer = derive_keypair("master", "customer");
        let provider = derive_keypair("master", "provider");
        assert_ne!(customer.public_key_hex(), provider.public_key_hex());
    }

    #[test]
    fn public_key_hex_round_trips() {
        let kp = derive_keypair("master", "customer");
        let reconstructed = public_key_from_hex(&kp.public_key_hex()).expect("valid hex");
        assert_eq!(reconstructed.to_bytes(), kp.verifying_key().to_bytes());
    }

    #[test]
    fn small_order_and_non_canonical_keys_are_rejected() {
        // A small-order public key (the identity element and friends) would verify
        // any signature — it must be refused at the door (I6).
        let identity = "0100000000000000000000000000000000000000000000000000000000000000";
        assert!(
            matches!(public_key_from_hex(identity), Err(CryptoError::InvalidPublicKey)),
            "the identity element is a weak key",
        );
        let zero = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(public_key_from_hex(zero).is_err(), "zero is a weak key");
        // A non-canonical y-coordinate encoding decodes to a small-order point.
        let non_canonical = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        assert!(
            public_key_from_hex(non_canonical).is_err(),
            "a non-canonical encoding is refused",
        );
    }

    #[test]
    fn malformed_public_key_hex_is_rejected() {
        assert!(matches!(
            public_key_from_hex("not-hex"),
            Err(CryptoError::InvalidHex)
        ));
        assert!(matches!(
            public_key_from_hex("00ff"),
            Err(CryptoError::InvalidKeyLength { got: 2 })
        ));
    }

    #[test]
    fn signature_over_one_message_does_not_verify_another() {
        let kp = derive_keypair("master", "customer");
        let key = public_key_from_hex(&kp.public_key_hex()).expect("valid hex");
        let signature = kp.sign_message("hello");
        assert!(verify_message(&key, "hello", &signature));
        assert!(!verify_message(&key, "hell0", &signature));
    }

    #[test]
    fn garbage_signature_encoding_returns_false_not_panic() {
        let kp = derive_keypair("master", "customer");
        let key = public_key_from_hex(&kp.public_key_hex()).expect("valid hex");
        assert!(!verify_message(&key, "hello", "zz"));
    }
}
