//! The customer's signed manifest: the list of what the provider is supposed to
//! be keeping. It is a sorted list of `(cid, size)` leaves, a Merkle root over
//! that list, a monotonic sequence number, and the customer's signature over a
//! **structured, domain-separated preimage** that binds all of it. Because the
//! customer signs it, "what we owe them" is in their handwriting; and because the
//! byte total and leaf count are bound into the signature, the storage bill
//! (byte-days) is a pure function of a document the customer authored, computable
//! without trusting the provider — and not forgeable after signing.
//!
//! Integrity properties (security review Phase 4):
//! - **I1** — `total_bytes` is bound into the signed preimage and re-derived from
//!   the leaves on verify, so it cannot be altered independently of the leaves.
//! - **I2** — the Merkle tree tags a single (odd) child distinctly from a pair, so
//!   `[A,B,C]` and `[A,B,C,C]` do not collide (CVE-2012-2459); duplicate cids are
//!   rejected outright.
//! - **I5** — a monotonic `seq` is bound in; a stale/replayed manifest is refused
//!   at the boundary.
//! - **I11** — the signature is over a versioned, domain-separated preimage, not a
//!   bare hash, so it cannot be confused with a receipt or ledger signature.
//! - **I12** — leaves are validated (hex content address, bounded size) and the
//!   wire form denies unknown fields.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::blobstore::MAX_OBJECT_BYTES;
use crate::crypto::{sha256_hex, verify_message, Keypair};

/// The domain-separation tag + version for a manifest signature (I11).
const MANIFEST_SIG_DOMAIN: &str = "ciss/v1/manifest";

/// A single manifest leaf: a fingerprint bound to its claimed size.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestLeaf {
    cid: String,
    size: usize,
}

impl ManifestLeaf {
    /// Build a leaf from a content address and its claimed size.
    #[must_use]
    pub fn new(cid: &str, size: usize) -> Self {
        Self {
            cid: cid.to_owned(),
            size,
        }
    }

    /// The content address.
    #[must_use]
    pub fn cid(&self) -> &str {
        &self.cid
    }

    /// The claimed size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Whether the leaf is well-formed: a 64-hex content address and a size within
    /// the per-object ceiling (I12).
    fn is_valid(&self) -> bool {
        let cid_ok = self.cid.len() == 64
            && self
                .cid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        cid_ok && self.size as u64 <= MAX_OBJECT_BYTES
    }
}

/// Hash of a single leaf: binds the fingerprint to its claimed size.
fn leaf_hash(leaf: &ManifestLeaf) -> String {
    sha256_hex(format!("leaf:{}:{}", leaf.cid, leaf.size).as_bytes())
}

/// Merkle root over the leaf set (canonical: leaves are sorted by cid, so the
/// root is a pure function of the set). An odd child is tagged **distinctly** from
/// a pair (`node1:` vs `node:`), so a duplicate-last padding cannot make two
/// different leaf sets collide (I2).
#[must_use]
pub fn merkle_root(leaves: &[ManifestLeaf]) -> String {
    if leaves.is_empty() {
        return sha256_hex(b"empty-manifest");
    }
    let mut ordered = leaves.to_vec();
    ordered.sort_by(|a, b| a.cid.cmp(&b.cid));
    let mut level: Vec<String> = ordered.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair.get(1) {
                Some(right) => sha256_hex(format!("node:{}:{right}", pair[0]).as_bytes()),
                None => sha256_hex(format!("node1:{}", pair[0]).as_bytes()),
            })
            .collect();
    }
    level.into_iter().next().unwrap_or_default()
}

/// Whether the leaf set contains the same cid more than once (an inflation vector
/// even with the padding fix — rejected on verify, I2).
fn has_duplicate_cids(leaves: &[ManifestLeaf]) -> bool {
    let mut seen = HashSet::new();
    leaves.iter().any(|leaf| !seen.insert(leaf.cid.as_str()))
}

/// The domain-separated preimage the customer signs. Binds the signer, the
/// sequence number, the leaf count, the byte total, and the root — so none can be
/// altered without invalidating the signature (I1, I5, I11).
fn signing_preimage(signer_id: &str, seq: u64, leaf_count: usize, total_bytes: usize, root: &str) -> String {
    format!("{MANIFEST_SIG_DOMAIN}:{signer_id}:{seq}:{leaf_count}:{total_bytes}:{root}")
}

/// A built, signed manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    leaves: Vec<ManifestLeaf>,
    root: String,
    total_bytes: usize,
    signer_id: String,
    seq: u64,
    signature: String,
}

impl Manifest {
    /// The Merkle root the customer signed.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Total bytes at rest implied by the list — the rent base.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// The customer identifier that authored/signed the manifest.
    #[must_use]
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// The monotonic sequence number (replay/rollback protection).
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The sorted leaves.
    #[must_use]
    pub fn leaves(&self) -> &[ManifestLeaf] {
        &self.leaves
    }

    /// Verify the manifest fully: leaves are well-formed and unique, the stored
    /// `root`/`total_bytes` reproduce from the leaves, and the customer's
    /// signature over the structured preimage checks out. Any tampering — an
    /// altered leaf, an inflated `total_bytes`, a duplicated cid, a swapped
    /// signature — makes this `false`.
    #[must_use]
    pub fn verify(&self, customer_key: &VerifyingKey) -> bool {
        if self.leaves.iter().any(|leaf| !leaf.is_valid()) || has_duplicate_cids(&self.leaves) {
            return false;
        }
        if merkle_root(&self.leaves) != self.root {
            return false;
        }
        let recomputed: usize = self.leaves.iter().map(ManifestLeaf::size).sum();
        if recomputed != self.total_bytes {
            return false;
        }
        let preimage = signing_preimage(
            &self.signer_id,
            self.seq,
            self.leaves.len(),
            self.total_bytes,
            &self.root,
        );
        verify_message(customer_key, &preimage, &self.signature)
    }
}

/// Build and sign a manifest from a set of `(cid, size)` leaves at sequence `seq`.
#[must_use]
pub fn build_manifest(
    items: &[ManifestLeaf],
    customer_id: &str,
    customer_key: &Keypair,
    seq: u64,
) -> Manifest {
    let mut leaves = items.to_vec();
    leaves.sort_by(|a, b| a.cid.cmp(&b.cid));
    let root = merkle_root(&leaves);
    let total_bytes: usize = leaves.iter().map(ManifestLeaf::size).sum();
    let preimage = signing_preimage(customer_id, seq, leaves.len(), total_bytes, &root);
    let signature = customer_key.sign_message(&preimage);
    Manifest {
        leaves,
        root,
        total_bytes,
        signer_id: customer_id.to_owned(),
        seq,
        signature,
    }
}

/// Expected bytes at rest — a pure function of the manifest, no retrieval needed.
#[must_use]
pub fn expected_bytes(manifest: &Manifest) -> usize {
    manifest.leaves.iter().map(ManifestLeaf::size).sum()
}

#[cfg(test)]
mod tests {
    use super::{build_manifest, expected_bytes, merkle_root, Manifest, ManifestLeaf};
    use crate::crypto::derive_keypair;
    use crate::identity::derive_id;

    fn cid(tag: &str) -> String {
        crate::crypto::sha256_hex(tag.as_bytes())
    }

    fn leaves() -> Vec<ManifestLeaf> {
        vec![
            ManifestLeaf::new(&cid("c"), 3),
            ManifestLeaf::new(&cid("a"), 1),
            ManifestLeaf::new(&cid("b"), 2),
        ]
    }

    #[test]
    fn root_is_order_independent() {
        let mut reversed = leaves();
        reversed.reverse();
        assert_eq!(merkle_root(&leaves()), merkle_root(&reversed));
    }

    #[test]
    fn odd_child_is_not_a_duplicate_padding() {
        // I2 / CVE-2012-2459: [A,B,C] and [A,B,C,C] must NOT collide. (The old
        // duplicate-last padding made them identical.)
        let base = leaves(); // 3 leaves
        let mut padded = leaves();
        // Append a duplicate of one leaf's cid (distinct-tag padding must differ,
        // and the duplicate is itself rejected by verify — see below).
        padded.push(ManifestLeaf::new(base[0].cid(), base[0].size()));
        assert_ne!(
            merkle_root(&base),
            merkle_root(&padded),
            "distinct odd-child tag: a duplicated leaf changes the root",
        );
    }

    #[test]
    fn total_bytes_is_bound_and_cannot_be_forged() {
        // I1: a signed manifest whose total_bytes is altered must not verify.
        let customer = derive_keypair("master", "customer");
        let did = derive_id(&customer.verifying_key());
        let manifest = build_manifest(&leaves(), &did, &customer, 1);
        assert!(manifest.verify(&customer.verifying_key()));
        assert_eq!(manifest.total_bytes(), 6);

        // Forge total_bytes in the serialized form; verify must reject.
        let mut forged: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
        forged["total_bytes"] = serde_json::json!(1);
        let forged: Manifest = serde_json::from_value(forged).unwrap();
        assert!(
            !forged.verify(&customer.verifying_key()),
            "an under-declared total_bytes breaks the signature",
        );
    }

    #[test]
    fn duplicate_cids_are_rejected() {
        // I2: even with the padding fix, a duplicated cid inflates the byte total;
        // verify must reject a leaf set with duplicate cids.
        let customer = derive_keypair("master", "customer");
        let did = derive_id(&customer.verifying_key());
        let dup = vec![
            ManifestLeaf::new(&cid("x"), 10),
            ManifestLeaf::new(&cid("x"), 10),
        ];
        let manifest = build_manifest(&dup, &did, &customer, 1);
        assert!(
            !manifest.verify(&customer.verifying_key()),
            "duplicate cids are rejected",
        );
    }

    #[test]
    fn malformed_leaves_are_rejected() {
        // I12: a non-hex cid or an over-cap size is not a valid leaf.
        let customer = derive_keypair("master", "customer");
        let did = derive_id(&customer.verifying_key());
        let bad_cid = build_manifest(
            &[ManifestLeaf::new("../../etc/passwd", 1)],
            &did,
            &customer,
            1,
        );
        assert!(!bad_cid.verify(&customer.verifying_key()), "non-hex cid rejected");
        let huge = build_manifest(
            &[ManifestLeaf::new(&cid("z"), usize::MAX)],
            &did,
            &customer,
            1,
        );
        assert!(!huge.verify(&customer.verifying_key()), "absurd size rejected");
    }

    #[test]
    fn signed_manifest_verifies_only_under_the_signing_key() {
        let customer = derive_keypair("master", "customer");
        let other = derive_keypair("master", "other");
        let did = derive_id(&customer.verifying_key());
        let manifest = build_manifest(&leaves(), &did, &customer, 1);
        assert!(manifest.verify(&customer.verifying_key()));
        assert!(!manifest.verify(&other.verifying_key()));
    }

    #[test]
    fn total_bytes_sums_leaf_sizes() {
        let customer = derive_keypair("master", "customer");
        let manifest = build_manifest(&leaves(), "id:customer", &customer, 1);
        assert_eq!(manifest.total_bytes(), 6);
        assert_eq!(expected_bytes(&manifest), 6);
    }

    #[test]
    fn seq_is_bound_into_the_signature() {
        // I5: changing seq after signing breaks the signature (the boundary uses
        // seq to reject a replayed/rolled-back manifest).
        let customer = derive_keypair("master", "customer");
        let did = derive_id(&customer.verifying_key());
        let manifest = build_manifest(&leaves(), &did, &customer, 5);
        assert_eq!(manifest.seq(), 5);
        let mut forged: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
        forged["seq"] = serde_json::json!(1);
        let forged: Manifest = serde_json::from_value(forged).unwrap();
        assert!(!forged.verify(&customer.verifying_key()), "seq is bound");
    }

    #[test]
    fn empty_manifest_has_a_fixed_sentinel_root() {
        use crate::crypto::sha256_hex;
        assert_eq!(merkle_root(&[]), sha256_hex(b"empty-manifest"));
    }
}
