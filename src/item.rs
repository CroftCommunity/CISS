//! Content-addressed items and the in-memory content store.
//!
//! An item is any bytes a person asked us to keep. Its name IS its fingerprint,
//! so an item cannot quietly become a different item: change one byte and the
//! fingerprint changes, and the store is keyed by that fingerprint.
//!
//! Ports `item-storage-protocol-standalone/src/item.ts`.

use std::collections::HashMap;

use crate::crypto::sha256_hex;

/// A content-addressed item. Its identity is its `cid` (the fingerprint of its
/// bytes), computed on construction — never assigned — so identity and content
/// are the same fact.
#[derive(Debug, Clone)]
pub struct Item {
    label: String,
    bytes: Vec<u8>,
    cid: String,
    size: usize,
}

impl Item {
    /// Make an item from raw bytes; its `cid` is computed, not assigned.
    ///
    /// `SEAM:` `cid` is a hex SHA-256 standing in for a `CIDv1` over `DAG-CBOR`
    /// (Phase 2 closes this with the in-corpus `serde_ipld_dagcbor` path).
    #[must_use]
    pub fn from_bytes(label: &str, bytes: Vec<u8>) -> Self {
        let cid = sha256_hex(&bytes);
        let size = bytes.len();
        Self {
            label: label.to_owned(),
            bytes,
            cid,
            size,
        }
    }

    /// A human label, purely for narration; identity is the [`Item::cid`].
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The raw bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The content address (hex SHA-256 fingerprint).
    #[must_use]
    pub fn cid(&self) -> &str {
        &self.cid
    }

    /// The size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Why a verified retrieval failed.
#[derive(Debug, thiserror::Error)]
pub enum RetrieveError {
    /// No bytes are stored under the requested cid — loss, not tamper.
    #[error("missing item {cid}")]
    Missing {
        /// The requested content address.
        cid: String,
    },
    /// The stored bytes no longer fingerprint to the requested cid.
    #[error("tampered item {cid} (now fingerprints as {actual})")]
    Tampered {
        /// The requested content address.
        cid: String,
        /// The fingerprint the stored bytes actually produce now.
        actual: String,
    },
}

/// An in-memory, content-addressed store: a map keyed by fingerprint. Retrieval
/// re-fingerprints the stored bytes, so a byte-flip at rest is caught on the way
/// out and named to exactly the item that failed.
///
/// `SEAM:` Phase 7 introduces the pluggable `BlobStore` trait; this is the
/// reference in-memory backend — the dumb Layer-1 store (the boundary computes
/// the cid, the backend just holds bytes under a key). The object grouping /
/// index structure (flat keyspace vs MST) is tracked as `ROADMAP_TODO` E85; v0
/// is a flat keyspace.
#[derive(Debug, Default)]
pub struct ContentStore {
    blobs: HashMap<String, Vec<u8>>,
}

impl ContentStore {
    /// A new, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store bytes under a key — the dumb Layer-1 primitive (no cid check; the
    /// content-addressing is the boundary's job).
    pub fn write(&mut self, key: &str, bytes: &[u8]) {
        self.blobs.insert(key.to_owned(), bytes.to_vec());
    }

    /// Store an item under its own content address.
    pub fn put(&mut self, item: &Item) {
        self.write(item.cid(), item.bytes());
    }

    /// Whether any bytes are stored under `cid`.
    #[must_use]
    pub fn has(&self, cid: &str) -> bool {
        self.blobs.contains_key(cid)
    }

    /// Total bytes actually held, summed from the stored blobs.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.blobs.values().map(Vec::len).sum()
    }

    /// Retrieve by fingerprint and verify: returns the bytes only if the stored
    /// bytes still fingerprint to `cid`.
    ///
    /// # Errors
    ///
    /// [`RetrieveError::Missing`] if nothing is stored under `cid`;
    /// [`RetrieveError::Tampered`] if the stored bytes no longer match `cid`.
    pub fn retrieve_verified(&self, cid: &str) -> Result<&[u8], RetrieveError> {
        let stored = self.blobs.get(cid).ok_or_else(|| RetrieveError::Missing {
            cid: cid.to_owned(),
        })?;
        let actual = sha256_hex(stored);
        if actual != cid {
            return Err(RetrieveError::Tampered {
                cid: cid.to_owned(),
                actual,
            });
        }
        Ok(stored.as_slice())
    }

    /// Remove an item entirely — loss, not tamper.
    pub fn remove(&mut self, cid: &str) {
        self.blobs.remove(cid);
    }

    /// Bytes actually read to retrieve a set of cids — an audit's true cost.
    /// Only cids present contribute (a dropped item reads zero bytes), so the
    /// cost tracks `k * item size`, independent of the corpus size.
    ///
    /// # Panics
    ///
    /// Panics only if a stored blob's length exceeds `u64` — impossible on any
    /// real machine, so this is an unreachable path.
    #[must_use]
    pub fn audit_read_cost(&self, cids: &[String]) -> u64 {
        cids.iter()
            .filter_map(|cid| self.blobs.get(cid))
            .map(|bytes| u64::try_from(bytes.len()).expect("blob length fits u64"))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentStore, Item};
    use crate::crypto::sha256_hex;

    #[test]
    fn item_cid_is_the_fingerprint_of_its_bytes() {
        let bytes = b"hello".to_vec();
        let item = Item::from_bytes("greeting", bytes.clone());
        assert_eq!(item.cid(), sha256_hex(&bytes));
        assert_eq!(item.size(), 5);
        assert_eq!(item.label(), "greeting");
    }

    #[test]
    fn store_holds_and_totals_bytes() {
        let mut store = ContentStore::new();
        let a = Item::from_bytes("a", vec![0u8; 10]);
        let b = Item::from_bytes("b", vec![1u8; 20]);
        store.put(&a);
        store.put(&b);
        assert!(store.has(a.cid()));
        assert!(
            !store.has("a-cid-that-was-never-stored"),
            "absent cid is not present"
        );
        assert_eq!(store.stored_bytes(), 30);
    }

    #[test]
    fn audit_read_cost_counts_only_present_items() {
        let mut store = ContentStore::new();
        let a = Item::from_bytes("a", vec![0u8; 10]);
        let b = Item::from_bytes("b", vec![1u8; 20]);
        store.put(&a);
        store.put(&b);
        let present = vec![a.cid().to_owned(), b.cid().to_owned()];
        assert_eq!(store.audit_read_cost(&present), 30, "sums the read bytes");
        // A dropped/absent item reads zero bytes (cost tracks k*size, not corpus).
        let mut with_missing = present.clone();
        with_missing.push("a-cid-never-stored".to_owned());
        assert_eq!(
            store.audit_read_cost(&with_missing),
            30,
            "an absent cid contributes zero",
        );
    }

    #[test]
    fn identical_bytes_collapse_to_one_key() {
        let mut store = ContentStore::new();
        let a = Item::from_bytes("a", vec![7u8; 8]);
        let b = Item::from_bytes("b-same-bytes", vec![7u8; 8]);
        assert_eq!(a.cid(), b.cid(), "same bytes -> same content address");
        store.put(&a);
        store.put(&b);
        assert_eq!(store.stored_bytes(), 8, "content-addressed storage dedups");
    }
}
