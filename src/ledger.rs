//! Append-only, hash-linked, signed ledgers — one per actor. Nothing is edited
//! in place; a correction is a new entry. Each entry hash-links to the one
//! before it (`seq` / `prev_hash`), carries a payload (`kind` / `body`), a
//! `hash` over the canonical form of all of that, and one or more signatures
//! over that hash (bilateral entries carry both parties' signatures).
//!
//! [`verify_entries`] re-reads a list of entries, recomputes every hash,
//! re-checks the chain linkage, and re-checks every signature against pinned
//! public keys — so "the books balance" is recomputable, not asserted on trust.
//!
//! Ports `item-storage-protocol-standalone/src/ledger.ts`.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::to_canonical_bytes;
use crate::crypto::{sha256_hex, verify_message, Keypair};

/// The `prev_hash` of the first entry in any ledger (64 hex zeros).
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A party whose signature an appended entry will carry.
pub struct Signer<'a> {
    actor_id: &'a str,
    keypair: &'a Keypair,
}

impl<'a> Signer<'a> {
    /// A signer: the actor id whose key signs, and the keypair to sign with.
    #[must_use]
    pub fn new(actor_id: &'a str, keypair: &'a Keypair) -> Self {
        Self { actor_id, keypair }
    }
}

/// A single append-only ledger entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Position in the chain (0-based).
    pub seq: usize,
    /// The hash of the previous entry (or [`GENESIS_PREV`] for the first).
    pub prev_hash: String,
    /// A timestamp string (opaque to the chain).
    pub ts: String,
    /// The payload kind (e.g. `"receipt"`, `"reputation-event"`).
    pub kind: String,
    /// The payload.
    pub body: Value,
    /// SHA-256 over the canonical `(seq, prev_hash, ts, kind, body)` preimage.
    pub hash: String,
    /// Map of `actor_id` to the hex signature over the entry `hash`.
    pub sigs: BTreeMap<String, String>,
}

/// The payload the entry hash is taken over — everything except the hash and
/// signatures themselves.
#[derive(Serialize)]
struct Preimage<'a> {
    seq: usize,
    prev_hash: &'a str,
    ts: &'a str,
    kind: &'a str,
    body: &'a Value,
}

fn entry_hash(seq: usize, prev_hash: &str, ts: &str, kind: &str, body: &Value) -> String {
    let preimage = Preimage {
        seq,
        prev_hash,
        ts,
        kind,
        body,
    };
    sha256_hex(&to_canonical_bytes(&preimage))
}

/// An actor's append-only ledger.
#[derive(Debug, Default)]
pub struct Ledger {
    owner_id: String,
    entries: Vec<LedgerEntry>,
}

impl Ledger {
    /// A new, empty ledger owned by `owner_id`.
    #[must_use]
    pub fn new(owner_id: &str) -> Self {
        Self {
            owner_id: owner_id.to_owned(),
            entries: Vec::new(),
        }
    }

    /// The owning actor's id.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// The entries, in order.
    #[must_use]
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    fn last_hash(&self) -> String {
        self.entries
            .last()
            .map_or_else(|| GENESIS_PREV.to_owned(), |e| e.hash.clone())
    }

    /// Append a signed entry. `signers` are the parties whose signatures the
    /// entry carries — one for a unilateral note, two for a bilateral entry.
    pub fn append(&mut self, kind: &str, ts: &str, body: Value, signers: &[Signer<'_>]) {
        let seq = self.entries.len();
        let prev_hash = self.last_hash();
        let hash = entry_hash(seq, &prev_hash, ts, kind, &body);
        let sigs = signers
            .iter()
            .map(|s| (s.actor_id.to_owned(), s.keypair.sign_message(&hash)))
            .collect();
        self.entries.push(LedgerEntry {
            seq,
            prev_hash,
            ts: ts.to_owned(),
            kind: kind.to_owned(),
            body,
            hash,
            sigs,
        });
    }
}

/// A problem found while verifying a ledger.
#[derive(Debug, Clone)]
pub struct VerifyIssue {
    /// The `seq` of the offending entry.
    pub seq: usize,
    /// A human-readable description of the problem.
    pub problem: String,
}

/// Verify a list of entries against a keyring (`actor_id -> public key`).
///
/// Returns every problem found; an empty list means the ledger is internally
/// consistent, correctly chained, and every signature is valid under a pinned
/// key.
#[must_use]
pub fn verify_entries(
    entries: &[LedgerEntry],
    keyring: &BTreeMap<String, VerifyingKey>,
) -> Vec<VerifyIssue> {
    let mut issues = Vec::new();
    let mut expected_prev = GENESIS_PREV.to_owned();
    for (idx, entry) in entries.iter().enumerate() {
        if entry.seq != idx {
            issues.push(VerifyIssue {
                seq: entry.seq,
                problem: format!("seq out of order: expected {idx}"),
            });
        }
        if entry.prev_hash != expected_prev {
            issues.push(VerifyIssue {
                seq: entry.seq,
                problem: "prev_hash breaks the chain link".to_owned(),
            });
        }
        let recomputed = entry_hash(
            entry.seq,
            &entry.prev_hash,
            &entry.ts,
            &entry.kind,
            &entry.body,
        );
        if recomputed != entry.hash {
            issues.push(VerifyIssue {
                seq: entry.seq,
                problem: "hash does not match body (entry edited)".to_owned(),
            });
        }
        if entry.sigs.is_empty() {
            issues.push(VerifyIssue {
                seq: entry.seq,
                problem: "entry carries no signature".to_owned(),
            });
        }
        for (signer_id, signature) in &entry.sigs {
            match keyring.get(signer_id) {
                None => issues.push(VerifyIssue {
                    seq: entry.seq,
                    problem: format!("no pinned key for signer {signer_id}"),
                }),
                Some(public_key) => {
                    if !verify_message(public_key, &entry.hash, signature) {
                        issues.push(VerifyIssue {
                            seq: entry.seq,
                            problem: format!("bad signature from {signer_id}"),
                        });
                    }
                }
            }
        }
        expected_prev.clone_from(&entry.hash);
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::{verify_entries, Ledger, Signer, GENESIS_PREV};
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;
    use std::collections::BTreeMap;

    #[test]
    fn chain_links_and_verifies() {
        let kp = derive_keypair("master", "owner");
        let id = derive_id(&kp.verifying_key());
        let mut ledger = Ledger::new(&id);
        ledger.append(
            "a",
            "t",
            serde_json::json!({"n": 1}),
            &[Signer::new(&id, &kp)],
        );
        ledger.append(
            "b",
            "t",
            serde_json::json!({"n": 2}),
            &[Signer::new(&id, &kp)],
        );

        assert_eq!(ledger.entries()[0].prev_hash, GENESIS_PREV);
        assert_eq!(ledger.entries()[1].prev_hash, ledger.entries()[0].hash);

        let ring: BTreeMap<String, _> = [(id.clone(), kp.verifying_key())].into_iter().collect();
        assert!(verify_entries(ledger.entries(), &ring).is_empty());
    }

    #[test]
    fn an_edited_body_breaks_verification() {
        let kp = derive_keypair("master", "owner");
        let id = derive_id(&kp.verifying_key());
        let mut ledger = Ledger::new(&id);
        ledger.append(
            "a",
            "t",
            serde_json::json!({"n": 1}),
            &[Signer::new(&id, &kp)],
        );
        let ring: BTreeMap<String, _> = [(id.clone(), kp.verifying_key())].into_iter().collect();

        let mut entries = ledger.entries().to_vec();
        entries[0].body = serde_json::json!({"n": 999});
        let issues = verify_entries(&entries, &ring);
        assert!(!issues.is_empty(), "an edited body is caught");
    }

    #[test]
    fn a_missing_key_is_reported() {
        let kp = derive_keypair("master", "owner");
        let id = derive_id(&kp.verifying_key());
        let mut ledger = Ledger::new(&id);
        ledger.append("a", "t", serde_json::json!({}), &[Signer::new(&id, &kp)]);
        let empty = BTreeMap::new();
        assert!(!verify_entries(ledger.entries(), &empty).is_empty());
    }
}
