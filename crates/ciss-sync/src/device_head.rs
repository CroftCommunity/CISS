//! `DeviceHead` — one device's signed commit record, the frontier's unit.
//!
//! A content-addressed DAG-CBOR blob: `{kind, device_id, counter, fs_root,
//! parent, base, signature}`. The signature (account key, shared-key era)
//! covers a domain-tagged preimage of every field, so a head is
//! **self-verifying**: the fold rejects a tampered head even from a sibling
//! device (the corpus's HEAD doctrine — never accept an asserted state
//! without local validation). `parent` is the per-device hash chain;
//! `base` names the fs-manifest of the last converged tree this commit was
//! folded against (a causal reference — never a clock).

use ciss::crypto::{verify_message, Keypair};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::error::SyncError;

/// The self-tag every device head leads with; decode refuses anything else.
pub const DEVICE_HEAD_KIND: &str = "croft.device-head/v1";

/// The signing domain for a device head (versioned, distinct from every other
/// record type — a head signature can never be replayed as something else).
const HEAD_SIG_DOMAIN: &str = "croft.device-head/v1";

/// A device's signed commit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceHead {
    /// The `croft.device-head/v1` self-tag.
    pub kind: String,
    /// The stable per-install label (shared-key era; a device pubkey later).
    pub device_id: String,
    /// This device's own monotonic commit counter.
    pub counter: u64,
    /// The fs-manifest cid of the tree this commit publishes.
    pub fs_root: String,
    /// The previous `DeviceHead` cid from THIS device (per-device chain).
    pub parent: Option<String>,
    /// The fs-manifest cid of the last converged base tree (causal ref).
    pub base: Option<String>,
    /// Account-key signature over the domain-tagged field preimage.
    pub signature: String,
}

fn preimage(
    device_id: &str,
    counter: u64,
    fs_root: &str,
    parent: Option<&str>,
    base: Option<&str>,
) -> String {
    format!(
        "{HEAD_SIG_DOMAIN}:{device_id}:{counter}:{fs_root}:{}:{}",
        parent.unwrap_or("-"),
        base.unwrap_or("-")
    )
}

impl DeviceHead {
    /// Build and sign a head with the account key.
    #[must_use]
    pub fn new_signed(
        device_id: &str,
        counter: u64,
        fs_root: &str,
        parent: Option<String>,
        base: Option<String>,
        keypair: &Keypair,
    ) -> Self {
        let signature =
            keypair.sign_message(&preimage(device_id, counter, fs_root, parent.as_deref(), base.as_deref()));
        Self {
            kind: DEVICE_HEAD_KIND.to_owned(),
            device_id: device_id.to_owned(),
            counter,
            fs_root: fs_root.to_owned(),
            parent,
            base,
            signature,
        }
    }

    /// Canonical DAG-CBOR bytes (the content-addressed wire form).
    ///
    /// # Errors
    ///
    /// [`SyncError::Encode`] on serializer failure.
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        serde_ipld_dagcbor::to_vec(self).map_err(|e| SyncError::Encode(format!("device head: {e}")))
    }

    /// Decode and fully verify a head: the kind tag must match and the
    /// signature must check out against `verifier`. A head that fails either
    /// is rejected — even one fetched from your own namespace.
    ///
    /// # Errors
    ///
    /// [`SyncError::Decode`] on malformed bytes, a wrong kind, or a bad
    /// signature.
    pub fn decode_verified(bytes: &[u8], verifier: &VerifyingKey) -> Result<Self, SyncError> {
        let head: Self = serde_ipld_dagcbor::from_slice(bytes)
            .map_err(|e| SyncError::Decode(format!("device head: {e}")))?;
        if head.kind != DEVICE_HEAD_KIND {
            return Err(SyncError::Decode(format!("not a device head (kind = {:?})", head.kind)));
        }
        let pre = preimage(
            &head.device_id,
            head.counter,
            &head.fs_root,
            head.parent.as_deref(),
            head.base.as_deref(),
        );
        if !verify_message(verifier, &pre, &head.signature) {
            return Err(SyncError::Decode(format!(
                "device head {} signature invalid — refusing the asserted head",
                head.device_id
            )));
        }
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciss::crypto::derive_keypair;

    #[test]
    fn head_round_trips_and_binds_every_field() {
        let kp = derive_keypair("m3", "dev");
        let head = DeviceHead::new_signed(
            "dev-a",
            3,
            &"ab".repeat(32),
            Some("cd".repeat(32)),
            None,
            &kp,
        );
        let bytes = head.encode().expect("encode");
        let back = DeviceHead::decode_verified(&bytes, &kp.verifying_key()).expect("verify");
        assert_eq!(back, head);

        // Every field is signature-bound.
        for mutate in [
            |h: &mut DeviceHead| h.device_id = "dev-b".into(),
            |h: &mut DeviceHead| h.counter = 4,
            |h: &mut DeviceHead| h.fs_root = "ee".repeat(32),
            |h: &mut DeviceHead| h.parent = None,
            |h: &mut DeviceHead| h.base = Some("ff".repeat(32)),
        ] {
            let mut forged = head.clone();
            mutate(&mut forged);
            let forged_bytes = forged.encode().expect("encode");
            assert!(
                DeviceHead::decode_verified(&forged_bytes, &kp.verifying_key()).is_err(),
                "a mutated field must break the signature"
            );
        }

        // The wrong key never verifies.
        let other = derive_keypair("m3", "other");
        assert!(DeviceHead::decode_verified(&bytes, &other.verifying_key()).is_err());
    }
}
