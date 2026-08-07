//! Content-defined chunking (`FastCDC`) with dual-hash chunk references.
//!
//! One pass over the bytes yields both names for every chunk: **sha-256**
//! (CISS's native content address) and **blake3** (iroh's, for the later
//! peer-fetch transport) — the store is transport-ready without a re-hash.
//!
//! Tuning (documented in the M1 plan): avg 256 KiB balances dedup granularity
//! against per-chunk overhead — and on CISS that overhead is *economic*, since
//! every chunk transfer emits a metered receipt. Max 1 MiB keeps headroom
//! under the server's hard 2 MiB object cap; min 64 KiB avoids pathological
//! tiny chunks. These are tuning constants, not a structural choice.

use std::ops::Range;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SyncError;

/// Minimum chunk size handed to the cutter (64 KiB).
pub const CHUNK_MIN_BYTES: usize = 64 * 1024;
/// Target average chunk size (256 KiB).
pub const CHUNK_AVG_BYTES: usize = 256 * 1024;
/// Maximum chunk size (1 MiB) — headroom under the server's 2 MiB object cap.
pub const CHUNK_MAX_BYTES: usize = 1024 * 1024;

/// The server's hard per-object cap; a [`ChunkRef`] may never reach it.
/// Mirrors `ciss::blobstore::MAX_OBJECT_BYTES` (guarded by test).
const MAX_OBJECT_BYTES: u64 = 2 * 1024 * 1024;

/// A 32-byte hash carried as a CBOR/JSON byte string, rendered as lowercase hex.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Lowercase hex rendering (the wire form CISS uses for cids).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use std::fmt::Write as _;
            write!(s, "{b:02x}").expect("writing hex to a String cannot fail");
        }
        s
    }
}

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Hash32;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("exactly 32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Hash32, E> {
                let arr: [u8; 32] =
                    v.try_into().map_err(|_| E::invalid_length(v.len(), &self))?;
                Ok(Hash32(arr))
            }
            // JSON has no byte-string type; serde_json round-trips bytes as a
            // number sequence — accepted here so the inspect view can decode.
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Hash32, A::Error> {
                let mut arr = [0u8; 32];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(33, &self));
                }
                Ok(Hash32(arr))
            }
        }
        deserializer.deserialize_bytes(V)
    }
}

/// A chunk's identity: both content addresses plus its length.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkRef {
    /// sha-256 of the chunk bytes — the CISS-native address.
    pub sha256: Hash32,
    /// blake3 of the same bytes — the iroh-native address (M4).
    pub blake3: Hash32,
    /// Chunk length in bytes; always `0 < len < MAX_OBJECT_BYTES`.
    pub len: u32,
}

impl ChunkRef {
    /// Build a validated reference.
    ///
    /// # Errors
    ///
    /// [`SyncError::InvalidChunkLen`] if `len` is zero or would reach the
    /// server's per-object cap.
    pub fn new(sha256: [u8; 32], blake3: [u8; 32], len: u32) -> Result<Self, SyncError> {
        if len == 0 || u64::from(len) >= MAX_OBJECT_BYTES {
            return Err(SyncError::InvalidChunkLen { len: u64::from(len), max: MAX_OBJECT_BYTES });
        }
        Ok(Self { sha256: Hash32(sha256), blake3: Hash32(blake3), len })
    }

    /// The CISS cid this chunk will be stored under (lowercase 64-hex).
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256.to_hex()
    }

    /// The blake3 address (lowercase 64-hex).
    #[must_use]
    pub fn blake3_hex(&self) -> String {
        self.blake3.to_hex()
    }
}

/// One chunk of a file: its identity plus where it sits in the source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// The dual-hash identity.
    pub chunk_ref: ChunkRef,
    /// The half-open byte range in the source the chunk covers.
    pub range: Range<usize>,
}

/// Split `bytes` at content-defined boundaries and hash each chunk both ways
/// in one pass. Deterministic: the same bytes always produce the same list.
/// Empty input yields no chunks.
///
/// # Panics
///
/// Never in practice: the internal `expect`s guard invariants `FastCDC`
/// upholds by construction (chunk length bounded by the 1 MiB max).
#[must_use]
pub fn chunk_file(bytes: &[u8]) -> Vec<Chunk> {
    if bytes.is_empty() {
        return Vec::new();
    }
    fastcdc::v2020::FastCDC::new(bytes, CHUNK_MIN_BYTES, CHUNK_AVG_BYTES, CHUNK_MAX_BYTES)
        .map(|cut| {
            let range = cut.offset..cut.offset + cut.length;
            let piece = &bytes[range.clone()];
            let sha256: [u8; 32] = Sha256::digest(piece).into();
            let blake3 = *blake3::hash(piece).as_bytes();
            let len = u32::try_from(cut.length)
                .expect("not possible: FastCDC max chunk size is 1 MiB");
            let chunk_ref = ChunkRef::new(sha256, blake3, len)
                .expect("not possible: FastCDC bounds chunk length below the cap");
            Chunk { chunk_ref, range }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_ref_rejects_zero_and_cap() {
        assert!(matches!(
            ChunkRef::new([0; 32], [0; 32], 0),
            Err(SyncError::InvalidChunkLen { len: 0, .. })
        ));
        let cap = u32::try_from(MAX_OBJECT_BYTES).expect("cap fits u32");
        assert!(ChunkRef::new([0; 32], [0; 32], cap).is_err());
        assert!(ChunkRef::new([0; 32], [0; 32], cap - 1).is_ok());
    }

    #[test]
    fn local_cap_mirrors_server_cap() {
        // If the server cap ever moves, this must fail rather than drift.
        assert_eq!(MAX_OBJECT_BYTES, ciss::blobstore::MAX_OBJECT_BYTES);
    }

    #[test]
    fn hash32_hex_is_lowercase_64() {
        let h = Hash32([0xAB; 32]);
        assert_eq!(h.to_hex().len(), 64);
        assert_eq!(&h.to_hex()[..2], "ab");
        // Debug must show the hex, not opaque bytes (diagnostic contract).
        assert!(format!("{h:?}").contains("abab"));
    }

    #[test]
    fn hash32_wrong_length_names_the_expectation() {
        // The deserialize error message is a diagnostic contract too: a
        // truncated hash must say what was expected, not fail opaquely.
        let err = serde_json::from_str::<Hash32>("[1,2,3]").expect_err("must refuse 3 bytes");
        assert!(err.to_string().contains("exactly 32 bytes"), "got: {err}");
    }
}
