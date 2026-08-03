//! The customer's signed manifest: the list of what the provider is supposed to
//! be keeping. It is a sorted list of `(cid, size)` leaves, a Merkle root over
//! that list, and the customer's signature over the root. Because the customer
//! signs it, "what we owe them" is in their handwriting; and because the sizes
//! are in it, the storage bill (byte-days) is a pure function of a document the
//! customer authored, computable without trusting the provider.
//!
//! Ports `item-storage-protocol-standalone/src/manifest.ts`. The Merkle root is
//! canonical for a given *set*: leaves are sorted by cid, so root == f(set),
//! independent of insertion order. (Object grouping / index structure — this
//! flat sorted root vs an MST — is tracked as `ROADMAP_TODO` E85; v0 is flat.)

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{sha256_hex, verify_message, Keypair};

/// A single manifest leaf: a fingerprint bound to its claimed size.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Hash of a single leaf: binds the fingerprint to its claimed size.
fn leaf_hash(leaf: &ManifestLeaf) -> String {
    sha256_hex(format!("leaf:{}:{}", leaf.cid, leaf.size).as_bytes())
}

/// Merkle root over the leaf set (canonical: leaves are sorted by cid, so the
/// root is a pure function of the set; duplicate-last padding for odd levels).
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
            .map(|pair| {
                let left = &pair[0];
                let right = pair.get(1).unwrap_or(left);
                sha256_hex(format!("node:{left}:{right}").as_bytes())
            })
            .collect();
    }
    level.into_iter().next().unwrap_or_default()
}

/// A built, signed manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    leaves: Vec<ManifestLeaf>,
    root: String,
    total_bytes: usize,
    signer_id: String,
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

    /// The sorted leaves.
    #[must_use]
    pub fn leaves(&self) -> &[ManifestLeaf] {
        &self.leaves
    }

    /// Verify the customer's signature over the root *and* that the stored
    /// leaves still reproduce that root — a manifest whose leaves were altered,
    /// or whose signature is from another key, does not verify.
    #[must_use]
    pub fn verify(&self, customer_key: &VerifyingKey) -> bool {
        if merkle_root(&self.leaves) != self.root {
            return false;
        }
        verify_message(customer_key, &self.root, &self.signature)
    }
}

/// Build and sign a manifest from a set of `(cid, size)` leaves.
#[must_use]
pub fn build_manifest(
    items: &[ManifestLeaf],
    customer_id: &str,
    customer_key: &Keypair,
) -> Manifest {
    let mut leaves = items.to_vec();
    leaves.sort_by(|a, b| a.cid.cmp(&b.cid));
    let root = merkle_root(&leaves);
    let total_bytes: usize = leaves.iter().map(ManifestLeaf::size).sum();
    let signature = customer_key.sign_message(&root);
    Manifest {
        leaves,
        root,
        total_bytes,
        signer_id: customer_id.to_owned(),
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
    use super::{build_manifest, expected_bytes, merkle_root, ManifestLeaf};
    use crate::crypto::derive_keypair;

    fn leaves() -> Vec<ManifestLeaf> {
        vec![
            ManifestLeaf::new("cccc", 3),
            ManifestLeaf::new("aaaa", 1),
            ManifestLeaf::new("bbbb", 2),
        ]
    }

    #[test]
    fn empty_manifest_has_a_fixed_sentinel_root() {
        use crate::crypto::sha256_hex;
        assert_eq!(merkle_root(&[]), sha256_hex(b"empty-manifest"));
    }

    #[test]
    fn root_is_order_independent() {
        let mut reversed = leaves();
        reversed.reverse();
        assert_eq!(merkle_root(&leaves()), merkle_root(&reversed));
    }

    #[test]
    fn dropping_a_leaf_changes_the_root() {
        let full = leaves();
        let missing = &full[1..];
        assert_ne!(merkle_root(&full), merkle_root(missing));
    }

    #[test]
    fn total_bytes_sums_leaf_sizes() {
        let customer = derive_keypair("master", "customer");
        let manifest = build_manifest(&leaves(), "id:customer", &customer);
        assert_eq!(manifest.total_bytes(), 6);
        assert_eq!(expected_bytes(&manifest), 6);
    }

    #[test]
    fn signed_manifest_verifies_only_under_the_signing_key() {
        let customer = derive_keypair("master", "customer");
        let other = derive_keypair("master", "other");
        let manifest = build_manifest(&leaves(), "id:customer", &customer);
        assert!(manifest.verify(&customer.verifying_key()));
        assert!(!manifest.verify(&other.verifying_key()));
    }

    #[test]
    fn root_binds_each_leaf_cid_and_size() {
        // The root must bind (cid, size) per leaf: changing one leaf's size or
        // cid (same leaf count) changes the root — otherwise a size-forgery
        // would go undetected and rent could be forged. (E86 mutation-resistance:
        // kills a `leaf_hash` that ignores its input.)
        let base = leaves();

        let mut size_changed = leaves();
        size_changed[0] = ManifestLeaf::new(size_changed[0].cid(), size_changed[0].size() + 1);
        assert_ne!(
            merkle_root(&base),
            merkle_root(&size_changed),
            "root binds each leaf's size",
        );

        let mut cid_changed = leaves();
        cid_changed[0] = ManifestLeaf::new("dddd", cid_changed[0].size());
        assert_ne!(
            merkle_root(&base),
            merkle_root(&cid_changed),
            "root binds each leaf's cid",
        );
    }
}
