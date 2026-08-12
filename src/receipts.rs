//! Transfer receipts: signed acknowledgments of bytes crossing the boundary
//! between two actors. Postage is charged by weight (bytes), not by trips —
//! "meter the boundary, not the machine".
//!
//! Two modes, selected per transfer by the social-trust layer:
//! - [`ReceiptMode::Bilateral`] — co-signed by both parties; self-contained and
//!   third-party-verifiable (the co-attested form the deferred capital layer
//!   E11–E14 will require).
//! - [`ReceiptMode::Unilateral`] — provider-signed only; an "our-side
//!   measurement", valid by the trust relationship but NOT co-attested, so its
//!   provenance is weaker.
//!
//! A receipt's signatures are taken over its own content (not a ledger
//! position), so the identical receipt can be embedded in both parties' ledgers
//! and cross-checked; altering a byte count in either copy breaks the embedded
//! signatures.
//!
//! Ports `item-storage-protocol-standalone/src/receipt.ts` and adds the
//! unilateral mode + the mode-selection seam.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::canonical::to_canonical_bytes;
use crate::crypto::{sha256_hex, verify_message, Keypair};
use crate::dials::AccountMode;

/// Which way the bytes crossed the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Customer → provider.
    Upload,
    /// Provider → customer.
    Download,
}

/// How a receipt is attested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptMode {
    /// Provider-signed only — an our-side measurement, valid by trust.
    Unilateral,
    /// Co-signed by both parties — third-party-verifiable.
    Bilateral,
}

/// The signed content of a receipt (everything the signatures are taken over).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCore {
    /// Transfer direction.
    pub direction: Direction,
    /// The content address transferred.
    pub cid: String,
    /// First byte of this increment (inclusive).
    pub byte_start: usize,
    /// Last byte of this increment (exclusive).
    pub byte_end: usize,
    /// Bytes in this increment (`byte_end - byte_start`).
    pub bytes: usize,
    /// Running total transferred so far in this exchange.
    pub running_total: usize,
    /// The day the transfer occurred (byte-day accounting uses this).
    pub day: u64,
    /// The account mode in effect at transfer time (drawdown legibility,
    /// POSTURE B6): signed, so "this egress was a drawdown drain" is an
    /// attested fact the statement-time human billing judgment can rely on.
    /// Defaults to [`AccountMode::Active`] on deserialization — receipts
    /// written before the tag existed all predate drawdown.
    ///
    /// More generally, this is where a transfer's **accounting class**
    /// rides: future modes (service, bot, staff — see [`AccountMode`])
    /// classify traffic the same way, as a signed fact per receipt rather
    /// than a mutable server-side annotation.
    /// Serialization: the default (`Active`) is **omitted** so the canonical
    /// bytes — and therefore the signed content hash — of a pre-tag receipt
    /// are unchanged (see [`AccountMode::is_active`]).
    #[serde(default, skip_serializing_if = "AccountMode::is_active")]
    pub account_mode: AccountMode,
    /// The party receiving the bytes.
    pub receiver_id: String,
    /// The party sending the bytes.
    pub sender_id: String,
}

impl ReceiptCore {
    /// Build a receipt core; `bytes` is derived from the byte range so it cannot
    /// disagree with it.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // one positional core, built in two places
    pub fn new(
        direction: Direction,
        cid: &str,
        byte_range: (usize, usize),
        running_total: usize,
        day: u64,
        account_mode: AccountMode,
        receiver_id: &str,
        sender_id: &str,
    ) -> Self {
        let (byte_start, byte_end) = byte_range;
        Self {
            direction,
            cid: cid.to_owned(),
            byte_start,
            byte_end,
            bytes: byte_end - byte_start,
            running_total,
            day,
            account_mode,
            receiver_id: receiver_id.to_owned(),
            sender_id: sender_id.to_owned(),
        }
    }

    /// The content hash the receipt's signatures are taken over.
    #[must_use]
    pub fn content_hash(&self) -> String {
        sha256_hex(&to_canonical_bytes(self))
    }
}

/// A transfer receipt: a core, its content hash, its mode, and the signatures
/// gathered over the content hash (keyed by signer id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    core: ReceiptCore,
    content_hash: String,
    mode: ReceiptMode,
    sigs: BTreeMap<String, String>,
}

impl Receipt {
    /// Reconstruct a receipt from its parts — e.g. read back off the wire or out
    /// of a ledger body. (`verify_*` re-derive the content hash, so a
    /// reconstruction with an altered core will not pass verification.)
    #[must_use]
    pub fn from_parts(
        core: ReceiptCore,
        content_hash: String,
        mode: ReceiptMode,
        sigs: BTreeMap<String, String>,
    ) -> Self {
        Self {
            core,
            content_hash,
            mode,
            sigs,
        }
    }

    /// The signed core.
    #[must_use]
    pub fn core(&self) -> &ReceiptCore {
        &self.core
    }

    /// The stored content hash.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// The attestation mode.
    #[must_use]
    pub fn mode(&self) -> ReceiptMode {
        self.mode
    }

    /// Bytes metered by this receipt.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.core.bytes
    }

    /// The signatures gathered, keyed by signer id.
    #[must_use]
    pub fn sigs(&self) -> &BTreeMap<String, String> {
        &self.sigs
    }

    /// Whether the stored content hash still matches the core (tamper check).
    fn core_matches(&self) -> bool {
        self.core.content_hash() == self.content_hash
    }

    /// Fully valid as a bilateral receipt: both parties signed the content and
    /// both signatures verify under their pinned keys.
    #[must_use]
    pub fn verify_bilateral(&self, keyring: &BTreeMap<String, VerifyingKey>) -> bool {
        if self.mode != ReceiptMode::Bilateral || !self.core_matches() {
            return false;
        }
        let (Some(receiver_sig), Some(sender_sig)) = (
            self.sigs.get(&self.core.receiver_id),
            self.sigs.get(&self.core.sender_id),
        ) else {
            return false;
        };
        let (Some(receiver_key), Some(sender_key)) = (
            keyring.get(&self.core.receiver_id),
            keyring.get(&self.core.sender_id),
        ) else {
            return false;
        };
        verify_message(receiver_key, &self.content_hash, receiver_sig)
            && verify_message(sender_key, &self.content_hash, sender_sig)
    }

    /// Valid as a unilateral (provider-signed) measurement: every signature
    /// present verifies under a pinned key. Weaker than bilateral — single
    /// party, not co-attested.
    #[must_use]
    pub fn verify_unilateral(&self, keyring: &BTreeMap<String, VerifyingKey>) -> bool {
        if self.mode != ReceiptMode::Unilateral || !self.core_matches() || self.sigs.is_empty() {
            return false;
        }
        self.sigs.iter().all(|(id, sig)| {
            keyring
                .get(id)
                .is_some_and(|key| verify_message(key, &self.content_hash, sig))
        })
    }

    /// Whether both parties acknowledged (distinguishes a walkaway, which
    /// carries no signatures).
    #[must_use]
    pub fn is_acknowledged(&self) -> bool {
        self.sigs.contains_key(&self.core.receiver_id)
            && self.sigs.contains_key(&self.core.sender_id)
    }

    /// Whether this receipt is co-attested (bilateral, both parties present).
    /// A unilateral receipt is never co-attested.
    #[must_use]
    pub fn is_co_attested(&self) -> bool {
        self.mode == ReceiptMode::Bilateral
            && self.sigs.contains_key(&self.core.receiver_id)
            && self.sigs.contains_key(&self.core.sender_id)
    }
}

/// Inputs the social-trust policy weighs when choosing a receipt mode.
pub struct TransferContext {
    /// Bytes about to cross the boundary.
    pub bytes: usize,
    /// Trust distance to the counterparty, if the trust layer supplied one.
    pub trust_distance: Option<u32>,
}

/// Select the receipt mode for a transfer.
///
/// `SEAM:` the real policy is the social-trust layer deciding Unilateral vs
/// Bilateral per transfer (size / sensitivity / trust-distance), reusing the
/// same trust-distance primitive as the forum's subjective consensus. v0
/// returns the configured `default`; the policy hook lands in a later spike.
#[must_use]
pub fn select_mode(_ctx: &TransferContext, default: ReceiptMode) -> ReceiptMode {
    // SEAM: trust-distance-driven selection goes here.
    default
}

/// Build a bilateral receipt (free function matching the oracle's `makeReceipt`).
/// The receiver signs first (acknowledging receipt); the sender only
/// countersigns an acknowledged transfer. A walkaway is modelled by passing
/// `None` for the receiver — the result carries no signatures.
#[must_use]
pub fn make_bilateral_receipt(
    core: ReceiptCore,
    receiver_key: Option<&Keypair>,
    sender_key: &Keypair,
) -> Receipt {
    let content_hash = core.content_hash();
    let mut sigs = BTreeMap::new();
    if let Some(receiver_key) = receiver_key {
        sigs.insert(
            core.receiver_id.clone(),
            receiver_key.sign_message(&content_hash),
        );
        sigs.insert(
            core.sender_id.clone(),
            sender_key.sign_message(&content_hash),
        );
    }
    Receipt::from_parts(core, content_hash, ReceiptMode::Bilateral, sigs)
}

/// Build a unilateral receipt: the provider signs its own-side measurement.
#[must_use]
pub fn make_unilateral_receipt(
    core: ReceiptCore,
    provider_id: &str,
    provider_key: &Keypair,
) -> Receipt {
    let content_hash = core.content_hash();
    let mut sigs = BTreeMap::new();
    sigs.insert(
        provider_id.to_owned(),
        provider_key.sign_message(&content_hash),
    );
    Receipt::from_parts(core, content_hash, ReceiptMode::Unilateral, sigs)
}

#[cfg(test)]
mod tests {
    use super::{
        make_bilateral_receipt, make_unilateral_receipt, AccountMode, Direction, Receipt,
        ReceiptCore, ReceiptMode,
    };
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;
    use ed25519_dalek::VerifyingKey;
    use std::collections::BTreeMap;

    fn parties() -> (
        String,
        crate::crypto::Keypair,
        String,
        crate::crypto::Keypair,
    ) {
        let receiver = derive_keypair("m", "receiver");
        let sender = derive_keypair("m", "sender");
        let rid = derive_id(&receiver.verifying_key());
        let sid = derive_id(&sender.verifying_key());
        (rid, receiver, sid, sender)
    }

    fn ring(entries: &[(&str, &crate::crypto::Keypair)]) -> BTreeMap<String, VerifyingKey> {
        entries
            .iter()
            .map(|(id, kp)| ((*id).to_owned(), kp.verifying_key()))
            .collect()
    }

    #[test]
    fn bilateral_receipt_verifies_and_detects_tampering() {
        let (rid, receiver, sid, sender) = parties();
        let ring = ring(&[(&rid, &receiver), (&sid, &sender)]);
        let core = ReceiptCore::new(Direction::Upload, "cid", (0, 100), 100, 1, AccountMode::Active, &rid, &sid);
        let receipt = make_bilateral_receipt(core, Some(&receiver), &sender);
        assert!(receipt.verify_bilateral(&ring));
        assert!(receipt.is_acknowledged());

        let mut tampered_core = receipt.core().clone();
        tampered_core.bytes += 1;
        let tampered = Receipt::from_parts(
            tampered_core,
            receipt.content_hash().to_owned(),
            receipt.mode(),
            receipt.sigs().clone(),
        );
        assert!(
            !tampered.verify_bilateral(&ring),
            "tamper breaks the content hash"
        );
    }

    #[test]
    fn walkaway_receipt_carries_no_signatures() {
        let (rid, receiver, sid, sender) = parties();
        let core = ReceiptCore::new(Direction::Download, "cid", (0, 100), 100, 1, AccountMode::Active, &rid, &sid);
        let _ = &receiver;
        let receipt = make_bilateral_receipt(core, None, &sender);
        assert!(!receipt.is_acknowledged());
        assert!(receipt.sigs().is_empty());
    }

    // The following are mutation-resistance tests (E86): they pin the boolean
    // structure of the verify predicates that a happy-path suite leaves free.

    #[test]
    fn bilateral_with_one_bad_signature_fails() {
        // Exactly one of the two signatures is invalid — the AND in
        // verify_bilateral must reject (a lone valid sig is not enough).
        let (rid, receiver, sid, sender) = parties();
        let ring = ring(&[(&rid, &receiver), (&sid, &sender)]);
        let core = ReceiptCore::new(Direction::Upload, "cid", (0, 100), 100, 1, AccountMode::Active, &rid, &sid);
        let good = make_bilateral_receipt(core, Some(&receiver), &sender);

        let mut sigs = good.sigs().clone();
        // Overwrite the sender's signature with one over a different message.
        sigs.insert(sid.clone(), sender.sign_message("some other message"));
        let one_bad = Receipt::from_parts(
            good.core().clone(),
            good.content_hash().to_owned(),
            ReceiptMode::Bilateral,
            sigs,
        );
        assert!(
            !one_bad.verify_bilateral(&ring),
            "one valid + one invalid signature must not verify bilaterally",
        );
    }

    #[test]
    fn bilateral_with_only_one_signature_is_not_acknowledged_or_co_attested() {
        let (rid, receiver, sid, sender) = parties();
        let core = ReceiptCore::new(Direction::Upload, "cid", (0, 100), 100, 1, AccountMode::Active, &rid, &sid);
        let good = make_bilateral_receipt(core, Some(&receiver), &sender);

        // Drop the sender's signature — only the receiver's remains.
        let mut sigs = good.sigs().clone();
        sigs.remove(&sid);
        let one_sig = Receipt::from_parts(
            good.core().clone(),
            good.content_hash().to_owned(),
            ReceiptMode::Bilateral,
            sigs,
        );
        assert!(
            !one_sig.is_acknowledged(),
            "one signature is not acknowledged"
        );
        assert!(
            !one_sig.is_co_attested(),
            "one signature is not co-attested"
        );
    }

    #[test]
    fn account_mode_is_signed_into_the_content_hash() {
        // The drawdown-legibility scaffolding (POSTURE B6, ruled 2026-08-11):
        // the account mode a transfer occurred under is part of the SIGNED
        // core, so "this egress was a drawdown drain" is an attested fact a
        // later human billing judgment can rely on — not a mutable annotation.
        let (rid, _, sid, _) = parties();
        let active = ReceiptCore::new(
            Direction::Download,
            "cid",
            (0, 100),
            100,
            1,
            AccountMode::Active,
            &rid,
            &sid,
        );
        let drawdown = ReceiptCore::new(
            Direction::Download,
            "cid",
            (0, 100),
            100,
            1,
            AccountMode::Drawdown,
            &rid,
            &sid,
        );
        assert_ne!(
            active.content_hash(),
            drawdown.content_hash(),
            "the account-mode tag must alter the signed content"
        );
    }

    #[test]
    fn acknowledged_bilateral_receipt_is_co_attested() {
        let (rid, receiver, sid, sender) = parties();
        let core = ReceiptCore::new(Direction::Upload, "cid", (0, 100), 100, 1, AccountMode::Active, &rid, &sid);
        let receipt = make_bilateral_receipt(core, Some(&receiver), &sender);
        assert!(
            receipt.is_co_attested(),
            "a fully-signed bilateral receipt is co-attested",
        );
    }

    #[test]
    fn unilateral_rejection_paths() {
        let (rid, receiver, sid, sender) = parties();
        let ring = ring(&[(&rid, &receiver), (&sid, &sender)]);
        let core = ReceiptCore::new(Direction::Upload, "cid", (0, 100), 100, 1, AccountMode::Active, &rid, &sid);

        // A valid unilateral (provider = sender here) measurement verifies.
        let good = make_unilateral_receipt(core.clone(), &sid, &sender);
        assert!(good.verify_unilateral(&ring));

        // (a) tampered core: the content hash no longer matches -> reject.
        let mut tampered_core = good.core().clone();
        tampered_core.bytes += 1;
        let tampered = Receipt::from_parts(
            tampered_core,
            good.content_hash().to_owned(),
            ReceiptMode::Unilateral,
            good.sigs().clone(),
        );
        assert!(!tampered.verify_unilateral(&ring), "tampered core rejected");

        // (b) no signatures: an unsigned measurement is not valid.
        let empty = Receipt::from_parts(
            good.core().clone(),
            good.content_hash().to_owned(),
            ReceiptMode::Unilateral,
            std::collections::BTreeMap::new(),
        );
        assert!(
            !empty.verify_unilateral(&ring),
            "empty-sig unilateral rejected"
        );

        // (c) wrong mode: a Bilateral-mode receipt is not unilaterally valid.
        let bilateral = make_bilateral_receipt(core, Some(&receiver), &sender);
        assert!(
            !bilateral.verify_unilateral(&ring),
            "bilateral is not unilaterally valid",
        );
    }

    #[test]
    fn a_receipt_persisted_before_the_account_mode_tag_still_verifies() {
        let (rid, receiver, sid, sender) = parties();
        let ring = ring(&[(&rid, &receiver), (&sid, &sender)]);

        // A pre-tag ledger row, byte-for-byte: the canonical bytes this
        // receipt was signed over never contained `account_mode`. Verify-compat
        // (not just parse-compat) is the guarantee — an already-signed receipt
        // must never become "tampered" because the schema grew a field.
        let legacy_core = serde_json::json!({
            "direction": "upload",
            "cid": "cid",
            "byte_start": 0,
            "byte_end": 100,
            "bytes": 100,
            "running_total": 100,
            "day": 1,
            "receiver_id": rid,
            "sender_id": sid,
        });
        let content_hash = crate::crypto::sha256_hex(&crate::canonical::to_canonical_bytes(
            &legacy_core,
        ));
        let mut sigs = BTreeMap::new();
        sigs.insert(sid.clone(), sender.sign_message(&content_hash));
        let row = serde_json::json!({
            "core": legacy_core,
            "content_hash": content_hash,
            "mode": "unilateral",
            "sigs": sigs,
        });

        let receipt: Receipt = serde_json::from_value(row).expect("legacy row deserializes");
        assert_eq!(receipt.core().account_mode, AccountMode::Active);
        assert!(
            receipt.verify_unilateral(&ring),
            "a receipt signed before the account-mode tag existed must stay verifiable"
        );
    }
}
