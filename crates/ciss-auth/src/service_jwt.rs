//! atproto **service-auth JWT** verification (Model R, ADR 0001 §3 amended).
//!
//! A caller authenticates by presenting a short-lived compact-JWS token minted by
//! `com.atproto.server.getServiceAuth`, signed by the caller's repo key: `iss` =
//! the caller DID, `aud` = this service's DID, `lxm` = the called method, `exp` a
//! ~60s bound. This module verifies it against the **DID-resolved** key
//! ([`crate::ResolvedKeys`], produced by `ciss-resolve`) and the request's
//! expected `aud`/`lxm`.
//!
//! The verification algorithm is taken from the **resolved key's curve**, never
//! from the JWT header — so a forged `alg` (`none`/`HS256`) cannot downgrade the
//! check. The signature is verified **before** any claim is trusted.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use crate::did_key::AtprotoKey;
use crate::{JwtError, Principal, ResolvedKeys};

/// What the request requires of the token, checked after the signature verifies.
#[derive(Debug, Clone, Copy)]
pub struct ServiceAuthParams<'a> {
    /// The DID the key was resolved for; must equal the token `iss`.
    pub expected_iss: &'a str,
    /// This service's DID; must equal the token `aud`.
    pub expected_aud: &'a str,
    /// The XRPC method being called; must equal the token `lxm`.
    pub expected_lxm: &'a str,
    /// The current time in unix seconds (for `exp`).
    pub now_unix_s: u64,
}

/// A verified token: the authenticated DID plus the fields a replay guard needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The verified caller DID (the token `iss`).
    pub did: String,
    /// The token id, if present (for replay defense).
    pub jti: Option<String>,
    /// The token expiry in unix seconds (for the replay window).
    pub exp_unix_s: u64,
}

impl Verified {
    /// The authenticated [`Principal`].
    #[must_use]
    pub fn principal(&self) -> Principal {
        Principal::Authenticated(self.did.clone())
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    #[serde(default)]
    lxm: Option<String>,
    exp: u64,
    #[serde(default)]
    jti: Option<String>,
}

/// Verify a service-auth JWT against `keys` (the resolved signing key) and the
/// request's `params`.
///
/// Verifies the signature first, then the `iss`/`aud`/`lxm`/`exp` bindings. A
/// missing or mismatched `lxm` is refused — an unbound token would be replayable
/// across methods.
///
/// # Errors
///
/// Returns the specific [`JwtError`] for a structural, signature, or claim failure.
pub fn verify_service_auth_jwt(
    jwt: &str,
    keys: &ResolvedKeys,
    params: &ServiceAuthParams,
) -> Result<Verified, JwtError> {
    // Exactly three segments: header.payload.signature.
    let mut parts = jwt.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::BadJwtStructure);
    };

    // Header: a known ECDSA alg. The verification curve comes from the resolved
    // key, not this field, so a forged alg cannot downgrade — this is a sanity gate.
    let header: Header = decode_json(h).map_err(|()| JwtError::BadHeader)?;
    if header.alg != "ES256K" && header.alg != "ES256" {
        return Err(JwtError::BadHeader);
    }

    // Verify the signature over "header.payload" BEFORE trusting any claim.
    let signature = URL_SAFE_NO_PAD.decode(s).map_err(|_| JwtError::BadSignature)?;
    let signing_input = &jwt[..h.len() + 1 + p.len()];
    let key = AtprotoKey::from_did_key(keys.signing_key())?;
    key.verify(signing_input.as_bytes(), &signature)?;

    // Signature is good — now the claims are trustworthy.
    let claims: Claims = decode_json(p).map_err(|()| JwtError::BadClaims)?;
    if claims.iss != params.expected_iss {
        return Err(JwtError::WrongIssuer);
    }
    if claims.aud != params.expected_aud {
        return Err(JwtError::WrongAudience);
    }
    if claims.lxm.as_deref() != Some(params.expected_lxm) {
        return Err(JwtError::WrongMethod);
    }
    if claims.exp <= params.now_unix_s {
        return Err(JwtError::Expired);
    }

    Ok(Verified {
        did: claims.iss,
        jti: claims.jti,
        exp_unix_s: claims.exp,
    })
}

/// base64url-decode a JWS segment and parse it as JSON.
fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, ()> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{verify_service_auth_jwt, ServiceAuthParams};
    use crate::{JwtError, Principal, ResolvedKeys};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};

    const ISS: &str = "did:plc:alice0000000000000000000000";
    const AUD: &str = "did:web:ciss.croft.ing";
    const LXM: &str = "com.atproto.repo.uploadBlob";
    const NOW: u64 = 1_000_000;

    fn signer() -> SigningKey {
        SigningKey::from_slice(&[0x11u8; 32]).unwrap()
    }

    fn did_key_of(sk: &SigningKey) -> String {
        let point = sk.verifying_key().to_encoded_point(true);
        let bytes = [&[0xe7u8, 0x01], point.as_bytes()].concat();
        format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, bytes))
    }

    /// Mint a compact JWS with the given header/claims JSON, signed by `sk`.
    fn mint(sk: &SigningKey, header_json: &str, claims_json: &str) -> String {
        let h = URL_SAFE_NO_PAD.encode(header_json);
        let p = URL_SAFE_NO_PAD.encode(claims_json);
        let signing_input = format!("{h}.{p}");
        let sig: Signature = sk.sign(signing_input.as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{s}")
    }

    /// A valid token for the default params.
    fn valid_token(sk: &SigningKey) -> String {
        mint(
            sk,
            r#"{"typ":"JWT","alg":"ES256K"}"#,
            &format!(r#"{{"iss":"{ISS}","aud":"{AUD}","lxm":"{LXM}","exp":{},"jti":"n1"}}"#, NOW + 60),
        )
    }

    fn params() -> ServiceAuthParams<'static> {
        ServiceAuthParams {
            expected_iss: ISS,
            expected_aud: AUD,
            expected_lxm: LXM,
            now_unix_s: NOW,
        }
    }

    fn verify(jwt: &str, sk: &SigningKey) -> Result<super::Verified, JwtError> {
        let keys = ResolvedKeys::new(did_key_of(sk));
        verify_service_auth_jwt(jwt, &keys, &params())
    }

    #[test]
    fn a_valid_service_auth_jwt_authenticates_the_issuer() {
        let sk = signer();
        let verified = verify(&valid_token(&sk), &sk).expect("valid");
        assert_eq!(verified.principal(), Principal::Authenticated(ISS.to_owned()));
        assert_eq!(verified.jti.as_deref(), Some("n1"));
    }

    #[test]
    fn a_token_for_another_service_is_refused() {
        let sk = signer();
        let jwt = mint(
            &sk,
            r#"{"typ":"JWT","alg":"ES256K"}"#,
            &format!(r#"{{"iss":"{ISS}","aud":"did:web:evil.example","lxm":"{LXM}","exp":{}}}"#, NOW + 60),
        );
        assert_eq!(verify(&jwt, &sk), Err(JwtError::WrongAudience));
    }

    #[test]
    fn a_token_bound_to_a_different_method_is_refused() {
        let sk = signer();
        let jwt = mint(
            &sk,
            r#"{"typ":"JWT","alg":"ES256K"}"#,
            &format!(r#"{{"iss":"{ISS}","aud":"{AUD}","lxm":"com.atproto.sync.getBlob","exp":{}}}"#, NOW + 60),
        );
        assert_eq!(verify(&jwt, &sk), Err(JwtError::WrongMethod));
    }

    #[test]
    fn a_method_less_token_is_refused() {
        // An lxm-less token is replayable across methods — CISS requires the bind.
        let sk = signer();
        let jwt = mint(
            &sk,
            r#"{"typ":"JWT","alg":"ES256K"}"#,
            &format!(r#"{{"iss":"{ISS}","aud":"{AUD}","exp":{}}}"#, NOW + 60),
        );
        assert_eq!(verify(&jwt, &sk), Err(JwtError::WrongMethod));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let sk = signer();
        let jwt = mint(
            &sk,
            r#"{"typ":"JWT","alg":"ES256K"}"#,
            &format!(r#"{{"iss":"{ISS}","aud":"{AUD}","lxm":"{LXM}","exp":{}}}"#, NOW - 1),
        );
        assert_eq!(verify(&jwt, &sk), Err(JwtError::Expired));
    }

    #[test]
    fn a_forged_token_naming_a_victim_iss_but_signed_by_the_attacker_is_refused() {
        // The attacker names the victim DID but signs with their own key; resolved
        // against the victim's key, the signature cannot verify (the A2 invariant
        // for the did: space).
        let attacker = SigningKey::from_slice(&[0x99u8; 32]).unwrap();
        let victim = signer();
        let jwt = mint(
            &attacker,
            r#"{"typ":"JWT","alg":"ES256K"}"#,
            &format!(r#"{{"iss":"{ISS}","aud":"{AUD}","lxm":"{LXM}","exp":{}}}"#, NOW + 60),
        );
        // Resolve against the VICTIM's key (iss claims to be the victim).
        assert_eq!(verify(&jwt, &victim), Err(JwtError::SignatureInvalid));
    }

    #[test]
    fn a_token_whose_iss_does_not_match_the_resolved_did_is_refused() {
        let sk = signer();
        let jwt = mint(
            &sk,
            r#"{"typ":"JWT","alg":"ES256K"}"#,
            &format!(r#"{{"iss":"did:plc:someoneelse","aud":"{AUD}","lxm":"{LXM}","exp":{}}}"#, NOW + 60),
        );
        // Signed correctly by sk, but the caller resolved iss=ISS's key.
        assert_eq!(verify(&jwt, &sk), Err(JwtError::WrongIssuer));
    }

    #[test]
    fn a_forged_alg_none_header_is_refused() {
        let sk = signer();
        let jwt = mint(
            &sk,
            r#"{"typ":"JWT","alg":"none"}"#,
            &format!(r#"{{"iss":"{ISS}","aud":"{AUD}","lxm":"{LXM}","exp":{}}}"#, NOW + 60),
        );
        assert_eq!(verify(&jwt, &sk), Err(JwtError::BadHeader));
    }

    #[test]
    fn a_structurally_broken_jwt_is_refused() {
        let sk = signer();
        assert_eq!(verify("not.a.jwt.at.all", &sk), Err(JwtError::BadJwtStructure));
        assert_eq!(verify("onlyonesegment", &sk), Err(JwtError::BadJwtStructure));
    }
}
