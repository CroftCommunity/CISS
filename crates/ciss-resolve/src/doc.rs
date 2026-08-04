//! DID-document parsing: extract the atproto **signing key** from a resolved DID
//! document and return it in `did:key:` form.
//!
//! Pure and network-free — the security-critical translation from an untrusted
//! JSON document to the key a JWT signature is verified against. Kept separate
//! from the fetch so it is exhaustively unit-tested against frozen fixtures.
//!
//! atproto publishes the signing key as the `#atproto` verification method. For
//! the modern `Multikey` type the `publicKeyMultibase` value **is** the `did:key`
//! suffix (multicodec-prefixed), so the `did:key` is `did:key:` + that value
//! (confirmed against `rsky-identity`'s `get_did_key_from_multibase`).

use ciss_auth::ResolvedKeys;
use serde::Deserialize;

use crate::ResolveError;

/// The subset of a DID document CISS reads: the id and the verification methods.
#[derive(Debug, Clone, Deserialize)]
pub struct DidDocument {
    /// The document subject — must equal the DID that was resolved.
    pub id: String,
    /// The verification methods; CISS uses the one whose id ends in `#atproto`.
    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
}

/// One verification method entry.
#[derive(Debug, Clone, Deserialize)]
pub struct VerificationMethod {
    /// The method id, e.g. `did:plc:…#atproto`.
    pub id: String,
    /// The key type, e.g. `Multikey`.
    #[serde(rename = "type")]
    pub key_type: String,
    /// The multibase-encoded public key.
    #[serde(default, rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Extract the atproto signing key from `doc`, checking it is the document for
/// `did`, and return it as a `did:key:` string.
///
/// # Errors
///
/// - [`ResolveError::BadDocument`] if `doc.id` ≠ `did`, there is no `#atproto`
///   method, or its multibase value is not a base58btc multikey.
/// - [`ResolveError::UnsupportedKeyType`] if the `#atproto` method is not a
///   `Multikey` (legacy `…VerificationKey2019` types are a tracked follow-up).
pub fn signing_key_from_doc(did: &str, doc: &DidDocument) -> Result<ResolvedKeys, ResolveError> {
    // A fetched document must be the one we asked for — a substituted document
    // for a different DID is a rejection, not a silent accept.
    if doc.id != did {
        return Err(ResolveError::BadDocument);
    }
    let method = doc
        .verification_method
        .iter()
        .find(|m| m.id.ends_with("#atproto"))
        .ok_or(ResolveError::BadDocument)?;

    match method.key_type.as_str() {
        // `Multikey`: publicKeyMultibase is the multicodec-prefixed key; the
        // did:key form is the same string behind the `did:key:` prefix. We do a
        // structural check only (base58btc `z` + non-empty); the curve/point is
        // validated at verify time (ciss-auth, Phase 3), which fails closed on an
        // unsupported or malformed key.
        "Multikey" => {
            let mb = &method.public_key_multibase;
            if mb.len() < 2 || !mb.starts_with('z') {
                return Err(ResolveError::BadDocument);
            }
            Ok(ResolvedKeys::new(format!("did:key:{mb}")))
        }
        // SEAM: the legacy `EcdsaSecp256k1/r1VerificationKey2019` types carry the
        // bare key (no multicodec prefix) and need re-encoding. atproto DIDs
        // publish `Multikey`; reject the legacy shapes (fail closed) until a real
        // one forces the work.
        _ => Err(ResolveError::UnsupportedKeyType),
    }
}

#[cfg(test)]
mod tests {
    use super::{signing_key_from_doc, DidDocument};
    use crate::ResolveError;

    /// The frozen real `did:plc` document (Phase-0 capture).
    const PLC_DOC: &str = include_str!("../../../tests/fixtures/did/did-plc-bsky-app.json");
    const PLC_DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const EXPECTED_DID_KEY: &str = "did:key:zQ3shQo6TF2moaqMTrUZEM1jeuYRQXeHEx4evX9751y2qPqRA";

    fn parse(json: &str) -> DidDocument {
        serde_json::from_str(json).expect("valid DID document JSON")
    }

    #[test]
    fn extracts_the_atproto_signing_key_from_a_real_plc_doc() {
        let doc = parse(PLC_DOC);
        let keys = signing_key_from_doc(PLC_DID, &doc).expect("resolves");
        assert_eq!(keys.signing_key(), EXPECTED_DID_KEY);
    }

    #[test]
    fn rejects_a_document_for_a_different_did() {
        // A substituted document (right shape, wrong subject) must not resolve.
        let doc = parse(PLC_DOC);
        assert_eq!(
            signing_key_from_doc("did:plc:someoneelse", &doc),
            Err(ResolveError::BadDocument),
        );
    }

    #[test]
    fn rejects_a_document_with_no_atproto_method() {
        let doc = parse(
            r#"{"id":"did:web:example.com","verificationMethod":[
                {"id":"did:web:example.com#keys-1","type":"Multikey","publicKeyMultibase":"zQ3sabc"}]}"#,
        );
        assert_eq!(
            signing_key_from_doc("did:web:example.com", &doc),
            Err(ResolveError::BadDocument),
        );
    }

    #[test]
    fn rejects_an_unsupported_key_type() {
        let doc = parse(
            r#"{"id":"did:web:example.com","verificationMethod":[
                {"id":"did:web:example.com#atproto","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6Mkabc"}]}"#,
        );
        assert_eq!(
            signing_key_from_doc("did:web:example.com", &doc),
            Err(ResolveError::UnsupportedKeyType),
        );
    }

    #[test]
    fn rejects_a_non_multibase_key_value() {
        let doc = parse(
            r#"{"id":"did:web:example.com","verificationMethod":[
                {"id":"did:web:example.com#atproto","type":"Multikey","publicKeyMultibase":"Qbadbase"}]}"#,
        );
        assert_eq!(
            signing_key_from_doc("did:web:example.com", &doc),
            Err(ResolveError::BadDocument),
        );
    }

    #[test]
    fn a_did_web_multikey_doc_resolves() {
        let doc = parse(
            r#"{"id":"did:web:example.com","verificationMethod":[
                {"id":"did:web:example.com#atproto","type":"Multikey","publicKeyMultibase":"zQ3shWebKeyExample"}]}"#,
        );
        let keys = signing_key_from_doc("did:web:example.com", &doc).expect("resolves");
        assert_eq!(keys.signing_key(), "did:key:zQ3shWebKeyExample");
    }
}
