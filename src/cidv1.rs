//! Real atproto blob CIDs — closing the Phase-2 `item.rs` hex-SHA-256 `SEAM:`.
//!
//! An atproto blob reference (`blob.ref.$link`) is a **CIDv1** with the `raw`
//! codec (`0x55`) over a **sha-256** multihash. The rest of the codebase content-
//! addresses with a bare hex SHA-256 (the backend key); this module bridges the
//! two so the atproto boundary can speak real CIDs while the metered byte-path
//! (backend + ledger) stays keyed by the same digest.
//!
//! The construction is byte-identical to the in-corpus verified path
//! (`hist-atproto-spike/src/record.rs::blob_cid`, `ipld-core` + `sha2`), which
//! Phase-0 D1-internal confirmed is CID-identical to real PDS records.
//!
//! Because a blob CID *is* a CIDv1-raw over sha-256, the hex digest and the CID
//! string are losslessly interconvertible: the digest lives inside the multihash.

use ipld_core::cid::multihash::Multihash;
use ipld_core::cid::{Cid, Version};
use sha2::{Digest, Sha256};

/// The IPLD `raw` codec — atproto blobs are raw bytes, not DAG-CBOR.
const RAW_CODEC: u64 = 0x55;
/// The multihash code for sha2-256.
const SHA2_256: u64 = 0x12;
/// The length in bytes of a sha-256 digest.
const DIGEST_LEN: usize = 32;

/// A failure converting between a hex digest and a blob CID.
#[derive(Debug, thiserror::Error)]
pub enum CidError {
    /// The supplied digest string was not valid hexadecimal.
    #[error("digest is not valid hexadecimal")]
    BadHex,
    /// The decoded digest was not exactly [`DIGEST_LEN`] bytes.
    #[error("digest must be {DIGEST_LEN} bytes, got {got}")]
    BadDigestLen {
        /// The number of bytes actually decoded.
        got: usize,
    },
    /// The CID string could not be parsed as a CID at all.
    #[error("value is not a parseable CID")]
    Unparseable,
    /// The CID parsed, but is not a CIDv1 `raw` + sha-256 blob CID (the only
    /// shape v0 addresses). No silent acceptance of other codecs/hashes.
    #[error("not a CIDv1 raw+sha-256 blob CID")]
    NotRawSha256,
}

/// The CIDv1 (`raw` + sha-256) string for a blob's raw bytes.
#[must_use]
pub fn blob_cid_string(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    cid_from_digest(&digest).to_string()
}

/// The CIDv1 string for a precomputed hex SHA-256 (the backend's content key).
///
/// # Errors
///
/// [`CidError::BadHex`] if the input is not hex; [`CidError::BadDigestLen`] if
/// it does not decode to a 32-byte digest.
pub fn from_sha256_hex(hex_digest: &str) -> Result<String, CidError> {
    let bytes = hex::decode(hex_digest).map_err(|_| CidError::BadHex)?;
    let digest: [u8; DIGEST_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CidError::BadDigestLen { got: bytes.len() })?;
    Ok(cid_from_digest(&digest).to_string())
}

/// The backend key (hex SHA-256) for a blob CID string, verifying it is a
/// CIDv1 `raw` + sha-256 CID first.
///
/// # Errors
///
/// [`CidError::Unparseable`] if the string is not a CID; [`CidError::NotRawSha256`]
/// if it is a CID but not the CIDv1 `raw` + sha-256 shape v0 addresses.
pub fn to_sha256_hex(cid_str: &str) -> Result<String, CidError> {
    let cid: Cid = cid_str.parse().map_err(|_| CidError::Unparseable)?;
    if cid.version() != Version::V1 || cid.codec() != RAW_CODEC {
        return Err(CidError::NotRawSha256);
    }
    let mh = cid.hash();
    if mh.code() != SHA2_256 || mh.size() as usize != DIGEST_LEN {
        return Err(CidError::NotRawSha256);
    }
    Ok(hex::encode(mh.digest()))
}

/// Wrap a 32-byte sha-256 digest as a CIDv1 `raw` CID.
fn cid_from_digest(digest: &[u8]) -> Cid {
    let mh = Multihash::<64>::wrap(SHA2_256, digest)
        .expect("a 32-byte sha-256 digest fits a 64-byte multihash");
    Cid::new_v1(RAW_CODEC, mh)
}

#[cfg(test)]
mod tests {
    use super::{blob_cid_string, from_sha256_hex, to_sha256_hex, CidError, DIGEST_LEN};
    use crate::crypto::sha256_hex;

    #[test]
    fn blob_cid_is_a_cidv1_raw_sha256_on_the_wire() {
        // Spec-anchored golden check: the binary CID must be exactly
        // varint(0x01) varint(0x55) varint(0x12) varint(0x20) || sha256(bytes).
        // Each prefix byte is < 0x80, so each is a single-byte varint. This
        // pins the wire format independent of the crate's internal assembly.
        let bytes = b"the quick brown fox";
        let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
        let cid: ipld_core::cid::Cid = blob_cid_string(bytes).parse().expect("our own CID parses");
        let mut expected = vec![0x01u8, 0x55, 0x12, 0x20];
        expected.extend_from_slice(&digest);
        assert_eq!(cid.to_bytes(), expected, "CIDv1 raw + sha-256 binary form");
        // Multibase base32-lower of that prefix is always the `bafkrei` header.
        assert!(
            blob_cid_string(bytes).starts_with("bafkrei"),
            "CIDv1 raw+sha-256 string always begins bafkrei",
        );
    }

    #[test]
    fn hex_and_cid_round_trip_losslessly() {
        let bytes = b"round trip me";
        let hex = sha256_hex(bytes);
        let cid = blob_cid_string(bytes);
        assert_eq!(
            from_sha256_hex(&hex).expect("hex -> cid"),
            cid,
            "the hex digest reconstructs the same CID as the bytes",
        );
        assert_eq!(
            to_sha256_hex(&cid).expect("cid -> hex"),
            hex,
            "the CID yields back the backend's hex key",
        );
    }

    #[test]
    fn cid_is_deterministic_and_content_addressed() {
        assert_eq!(blob_cid_string(b"same"), blob_cid_string(b"same"));
        assert_ne!(blob_cid_string(b"a"), blob_cid_string(b"b"));
    }

    #[test]
    fn from_hex_rejects_malformed_digests() {
        assert!(matches!(from_sha256_hex("not-hex"), Err(CidError::BadHex)));
        assert!(matches!(
            from_sha256_hex("00ff"),
            Err(CidError::BadDigestLen { got: 2 })
        ));
    }

    #[test]
    fn to_hex_rejects_non_blob_cids() {
        // Garbage is unparseable.
        assert!(matches!(
            to_sha256_hex("not-a-cid"),
            Err(CidError::Unparseable)
        ));
        // A DAG-CBOR CID (codec 0x71) is a valid CID but not a raw blob CID —
        // rejected loudly, never silently coerced to a hex key.
        let digest = <sha2::Sha256 as sha2::Digest>::digest(b"x");
        let mh = ipld_core::cid::multihash::Multihash::<64>::wrap(0x12, &digest).expect("wrap");
        let dag_cbor = ipld_core::cid::Cid::new_v1(0x71, mh).to_string();
        assert!(matches!(
            to_sha256_hex(&dag_cbor),
            Err(CidError::NotRawSha256)
        ));
    }

    #[test]
    fn to_hex_rejects_a_raw_cid_with_a_non_sha256_hash() {
        // A `raw`-codec CIDv1 (passes the codec check) but hashed with blake3
        // (code 0x1e), 32 bytes: the codec operand is FALSE while the hash-code
        // operand is TRUE, so only an OR of the two rejects it. Pins that the
        // hash check is independent of the codec check (kills `|| -> &&`).
        let mh = ipld_core::cid::multihash::Multihash::<64>::wrap(0x1e, &[0u8; DIGEST_LEN])
            .expect("wrap blake3-sized digest");
        let raw_blake3 = ipld_core::cid::Cid::new_v1(0x55, mh).to_string();
        assert!(
            matches!(to_sha256_hex(&raw_blake3), Err(CidError::NotRawSha256)),
            "a raw CID that is not sha-256 must not be coerced to a hex key",
        );
    }

    #[test]
    fn digest_len_constant_matches_sha256() {
        assert_eq!(DIGEST_LEN, 32);
    }
}
