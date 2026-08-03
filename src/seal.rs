//! Sealing: cold storage where the plan is no movement and verification proves
//! it. Three mechanisms compose:
//!   - a **seal declaration**: the customer pins a manifest root and signs it.
//!   - a **write-path ceremony**: the provider destroys the credential its write
//!     function requires, so the normal write path fails closed. Immutability
//!     becomes *enforced* at the key ceremony, not merely promised.
//!   - a **rotation watch**: any new signed root for the collection is an event;
//!     the watch classifies it as customer-initiated (a legitimate unseal, proven
//!     by the customer's signature) or an alarm (anything else).
//!
//! Detection and enforcement are distinct: audits against the pinned root catch a
//! compromised path that mutates bytes directly (no new signature needed to be
//! caught), while the watch catches root *rotations*. Together, every change is
//! either customer-signed or alarmed. The **tombstone** (permanent) tier is the
//! seal plus destroying the customer's unseal capability too — no party can
//! rotate, and that is the feature.
//!
//! Ports `item-storage-protocol-standalone/src/seal.ts`.
//!
//! `SEAM:` "destroying" a credential here is dropping in-memory key material and
//! making the guarded function fail closed. In production this is an HSM key
//! ceremony / deletion of signing material, irreversible by construction.

use ed25519_dalek::VerifyingKey;

use crate::crypto::{verify_message, Keypair};
use crate::item::{ContentStore, Item};

/// The customer's signed declaration that a collection is pinned to a root.
#[derive(Debug, Clone)]
pub struct SealDeclaration {
    /// The sealed collection's id.
    pub collection_id: String,
    /// The manifest root pinned by the seal.
    pub pinned_root: String,
    /// The day the seal was declared.
    pub day: u64,
    /// The customer id that signed the seal.
    pub signer_id: String,
    /// The customer's signature over `seal:{collection_id}:{pinned_root}`.
    pub signature: String,
}

impl SealDeclaration {
    /// Verify the seal was signed by `customer_key` over its pinned root.
    #[must_use]
    pub fn verify(&self, customer_key: &VerifyingKey) -> bool {
        verify_message(
            customer_key,
            &format!("seal:{}:{}", self.collection_id, self.pinned_root),
            &self.signature,
        )
    }
}

/// Sign a seal declaration pinning `collection_id` to `pinned_root`.
#[must_use]
pub fn sign_seal(
    collection_id: &str,
    pinned_root: &str,
    day: u64,
    customer_id: &str,
    customer_key: &Keypair,
) -> SealDeclaration {
    let signature = customer_key.sign_message(&format!("seal:{collection_id}:{pinned_root}"));
    SealDeclaration {
        collection_id: collection_id.to_owned(),
        pinned_root: pinned_root.to_owned(),
        day,
        signer_id: customer_id.to_owned(),
        signature,
    }
}

/// Why a sealed write failed.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The write path has no credential — the seal ceremony destroyed it.
    #[error("write path is sealed: no write credential")]
    Sealed,
}

/// The provider's write path. Requires a credential; fails closed without it.
pub struct CollectionWriter {
    credential: Option<Keypair>,
}

// Manual Debug: never print the secret write credential (rust-enforcer — key
// material is not `Debug`-printed), only whether it is still held.
impl std::fmt::Debug for CollectionWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectionWriter")
            .field("has_credential", &self.credential.is_some())
            .finish()
    }
}

impl CollectionWriter {
    /// A writer holding a live write credential.
    #[must_use]
    pub fn new(credential: Keypair) -> Self {
        Self {
            credential: Some(credential),
        }
    }

    /// Write an item — fails closed (loud typed error, never a silent no-op)
    /// once the credential is destroyed.
    ///
    /// # Errors
    ///
    /// [`SealError::Sealed`] if the write credential has been destroyed.
    pub fn write(&self, store: &mut ContentStore, item: &Item) -> Result<(), SealError> {
        if self.credential.is_none() {
            return Err(SealError::Sealed);
        }
        store.put(item);
        Ok(())
    }

    /// The seal ceremony: destroy the write credential. Irreversible here.
    pub fn destroy_credential(&mut self) {
        self.credential = None;
    }

    /// Whether the write credential is still held.
    #[must_use]
    pub fn has_credential(&self) -> bool {
        self.credential.is_some()
    }
}

/// A signed announcement rotating a collection to a new root.
#[derive(Debug, Clone)]
pub struct RootAnnouncement {
    /// The collection being rotated.
    pub collection_id: String,
    /// The proposed new manifest root.
    pub new_root: String,
    /// The day of the announcement.
    pub day: u64,
    /// The id claiming to sign the rotation.
    pub signer_id: String,
    /// The signature over `rotate:{collection_id}:{new_root}`.
    pub signature: String,
}

/// The customer's rotation (unseal) capability. Destroyed for the tombstone tier.
pub struct UnsealAuthority {
    key: Option<Keypair>,
    owner_id: String,
}

// Manual Debug: never print the secret unseal key (rust-enforcer), only the
// owner and whether the capability has been destroyed.
impl std::fmt::Debug for UnsealAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsealAuthority")
            .field("owner_id", &self.owner_id)
            .field("is_destroyed", &self.key.is_none())
            .finish()
    }
}

impl UnsealAuthority {
    /// A capability held by `owner_id`, signing with `key`.
    #[must_use]
    pub fn new(owner_id: &str, key: Keypair) -> Self {
        Self {
            key: Some(key),
            owner_id: owner_id.to_owned(),
        }
    }

    /// Sign a rotation to `new_root`. Returns `None` once destroyed (fails
    /// closed — no rotation can be produced).
    #[must_use]
    pub fn rotate(
        &self,
        collection_id: &str,
        new_root: &str,
        day: u64,
    ) -> Option<RootAnnouncement> {
        let key = self.key.as_ref()?;
        let signature = key.sign_message(&format!("rotate:{collection_id}:{new_root}"));
        Some(RootAnnouncement {
            collection_id: collection_id.to_owned(),
            new_root: new_root.to_owned(),
            day,
            signer_id: self.owner_id.clone(),
            signature,
        })
    }

    /// Destroy the capability. Irreversible here (the tombstone ceremony).
    pub fn destroy(&mut self) {
        self.key = None;
    }

    /// Whether the capability has been destroyed.
    #[must_use]
    pub fn is_destroyed(&self) -> bool {
        self.key.is_none()
    }

    /// The owning actor's id.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
}

/// How the watch classified an observed root change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    /// A root change signed by the customer — a legitimate unseal.
    CustomerInitiated {
        /// The new root.
        root: String,
        /// The day observed.
        day: u64,
    },
    /// Any other root change — an alarm.
    Alarm {
        /// The new root.
        root: String,
        /// The day observed.
        day: u64,
        /// Why it alarmed.
        reason: String,
    },
}

impl WatchEvent {
    /// Whether this event is a legitimate customer-initiated rotation.
    #[must_use]
    pub fn is_customer_initiated(&self) -> bool {
        matches!(self, WatchEvent::CustomerInitiated { .. })
    }

    /// Whether this event is an alarm.
    #[must_use]
    pub fn is_alarm(&self) -> bool {
        matches!(self, WatchEvent::Alarm { .. })
    }
}

/// Monitors root announcements for a sealed collection and classifies each as
/// customer-initiated or an alarm.
#[derive(Debug)]
pub struct RotationWatch {
    collection_id: String,
    customer_id: String,
    customer_key: VerifyingKey,
    events: Vec<WatchEvent>,
}

impl RotationWatch {
    /// A watch for `collection_id`, pinning the customer's id + verifying key.
    #[must_use]
    pub fn new(collection_id: &str, customer_id: &str, customer_key: VerifyingKey) -> Self {
        Self {
            collection_id: collection_id.to_owned(),
            customer_id: customer_id.to_owned(),
            customer_key,
            events: Vec::new(),
        }
    }

    /// Classify an announced root change by its signature, recording the event.
    /// It is customer-initiated only if the announcement carries the customer's
    /// id *and* a valid customer signature over this collection's rotation
    /// message; anything else is an alarm.
    pub fn observe(&mut self, announcement: &RootAnnouncement) -> WatchEvent {
        let valid_customer_sig = announcement.signer_id == self.customer_id
            && verify_message(
                &self.customer_key,
                &format!("rotate:{}:{}", self.collection_id, announcement.new_root),
                &announcement.signature,
            );
        let event = if valid_customer_sig {
            WatchEvent::CustomerInitiated {
                root: announcement.new_root.clone(),
                day: announcement.day,
            }
        } else {
            WatchEvent::Alarm {
                root: announcement.new_root.clone(),
                day: announcement.day,
                reason: "root change not signed by the customer".to_owned(),
            }
        };
        self.events.push(event.clone());
        event
    }

    /// The classified events, in order.
    #[must_use]
    pub fn events(&self) -> &[WatchEvent] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::{
        sign_seal, CollectionWriter, RootAnnouncement, RotationWatch, SealError, UnsealAuthority,
    };
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;
    use crate::item::{ContentStore, Item};

    #[test]
    fn seal_verifies_only_under_the_signing_key() {
        let customer = derive_keypair("m", "c");
        let id = derive_id(&customer.verifying_key());
        let seal = sign_seal("coll", "root123", 0, &id, &customer);
        assert!(seal.verify(&customer.verifying_key()));
        let other = derive_keypair("m", "other");
        assert!(
            !seal.verify(&other.verifying_key()),
            "seal is bound to the signer"
        );
    }

    #[test]
    fn write_fails_closed_after_the_ceremony() {
        let mut writer = CollectionWriter::new(derive_keypair("m", "cred"));
        let mut store = ContentStore::new();
        let item = Item::from_bytes("a", b"bytes".to_vec());
        assert!(
            writer.write(&mut store, &item).is_ok(),
            "write works with a credential"
        );
        writer.destroy_credential();
        assert!(!writer.has_credential());
        assert!(
            matches!(writer.write(&mut store, &item), Err(SealError::Sealed)),
            "write fails closed once the credential is destroyed",
        );
    }

    #[test]
    fn unseal_fails_closed_once_destroyed() {
        let key = derive_keypair("m", "unseal");
        let id = derive_id(&key.verifying_key());
        let mut auth = UnsealAuthority::new(&id, key);
        assert_eq!(auth.owner_id(), id.as_str());
        assert!(!auth.is_destroyed(), "a fresh authority is not destroyed");
        assert!(
            auth.rotate("coll", "newroot", 1).is_some(),
            "a held capability rotates"
        );
        auth.destroy();
        assert!(auth.is_destroyed());
        assert!(
            auth.rotate("coll", "newroot", 2).is_none(),
            "unseal fails closed after destroy"
        );
    }

    #[test]
    fn watch_alarms_on_a_non_customer_signature() {
        let customer = derive_keypair("m", "c");
        let cid = derive_id(&customer.verifying_key());
        let mut watch = RotationWatch::new("coll", &cid, customer.verifying_key());

        let auth = UnsealAuthority::new(&cid, derive_keypair("m", "c"));
        let legit = auth
            .rotate("coll", "r1", 1)
            .expect("held authority rotates");
        let legit_event = watch.observe(&legit);
        assert!(legit_event.is_customer_initiated());
        assert!(
            !legit_event.is_alarm(),
            "a customer-signed rotation is not an alarm"
        );

        let bogus = RootAnnouncement {
            collection_id: "coll".to_owned(),
            new_root: "r2".to_owned(),
            day: 2,
            signer_id: cid.clone(),
            signature: "00".repeat(64),
        };
        let bogus_event = watch.observe(&bogus);
        assert!(bogus_event.is_alarm(), "an invalid signature alarms");
        assert!(
            !bogus_event.is_customer_initiated(),
            "a forged rotation is not customer-initiated",
        );
        assert_eq!(watch.events().len(), 2);
    }

    #[test]
    fn debug_redacts_secret_key_material() {
        // rust-enforcer: secret key material is never `Debug`-printed. The manual
        // Debug impls expose only non-secret status, and must actually produce
        // that output (this also kills a Debug impl mutated to emit nothing).
        let writer = CollectionWriter::new(derive_keypair("m", "cred"));
        let dbg = format!("{writer:?}");
        assert!(dbg.contains("CollectionWriter"));
        assert!(
            dbg.contains("has_credential"),
            "reports status, not the key"
        );

        let auth = UnsealAuthority::new("id:owner", derive_keypair("m", "unseal"));
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("UnsealAuthority"));
        assert!(dbg.contains("owner_id"));
        assert!(dbg.contains("is_destroyed"), "reports status, not the key");
    }
}
