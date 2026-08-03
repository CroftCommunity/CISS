//! Identity: an actor is a keypair and nothing more. Its identifier is a
//! deterministic function of its public key, so "who you are" and "how we
//! recognize your signature" are the same fact.
//!
//! Ports `item-storage-protocol-standalone/src/actor.ts` (`deriveId`).
//!
//! `SEAM:` a real deployment carries a `did:key` / `did:plc` identity resolvable
//! over the network; here the identifier is a short hash of the raw public key.

use ed25519_dalek::VerifyingKey;

use crate::crypto::{public_key_from_hex, sha256_hex, CryptoError};

/// The number of hex characters of the public-key digest kept in an identifier.
const ID_DIGEST_HEX_LEN: usize = 16;

/// Derive an actor's stable identifier from its public key.
///
/// The identifier is `"id:" ++ SHA-256(raw public key)[..16 hex chars]`, matching
/// the TypeScript oracle. It is a pure function of the public key, so recognition
/// (signature verification) and counting (this derivation) rest on the same fact.
#[must_use]
pub fn derive_id(verifying_key: &VerifyingKey) -> String {
    let digest = sha256_hex(&verifying_key.to_bytes());
    format!("id:{}", &digest[..ID_DIGEST_HEX_LEN])
}

/// A pinned peer identity: an identifier bound to the public key it derives from.
#[derive(Debug, Clone)]
pub struct Identity {
    id: String,
    verifying_key: VerifyingKey,
}

impl Identity {
    /// Build an identity from a public key, deriving the identifier from it.
    #[must_use]
    pub fn from_verifying_key(verifying_key: VerifyingKey) -> Self {
        Self {
            id: derive_id(&verifying_key),
            verifying_key,
        }
    }

    /// Pin a peer identity from its published public-key hex.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the hex is not a valid Ed25519 public key.
    pub fn from_public_key_hex(public_key_hex: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_verifying_key(public_key_from_hex(
            public_key_hex,
        )?))
    }

    /// The derived identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The pinned public key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// The pinned public key, hex-encoded.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_id, Identity};
    use crate::crypto::derive_keypair;

    #[test]
    fn id_is_prefixed_and_fixed_length() {
        let kp = derive_keypair("master", "customer");
        let id = derive_id(&kp.verifying_key());
        assert!(id.starts_with("id:"));
        assert_eq!(id.len(), "id:".len() + 16);
    }

    #[test]
    fn identity_from_hex_matches_derivation() {
        let kp = derive_keypair("master", "customer");
        let identity = Identity::from_public_key_hex(&kp.public_key_hex()).expect("valid hex");
        assert_eq!(identity.id(), derive_id(&kp.verifying_key()));
        assert_eq!(identity.public_key_hex(), kp.public_key_hex());
    }
}
