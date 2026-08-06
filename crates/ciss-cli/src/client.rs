//! HTTP client for the CISS server: signed-session auth, the S3 plane
//! (`put`/`get`/`meter`), and the actionable error-code mapping every command
//! shares. Reads are re-verified against their content address before they are
//! trusted, so a corrupted or substituted body never reaches the user.

use anyhow::{anyhow, bail, Context, Result};

use ciss::crypto::{sha256_hex, Keypair};

/// The domain-separated session-challenge prefix. Mirrors the server's private
/// `SESSION_CHALLENGE_PREFIX` (`src/server.rs:66`); the wiring tests keep it in
/// sync — a drift here makes every authenticated call 401.
const SESSION_CHALLENGE_PREFIX: &str = "ciss-session/v1/";

/// A signed session credential for the `id:` plane: the public key plus a
/// signature over `ciss-session/v1/<did>`, proving key possession for `did`.
pub struct Session {
    /// The DID this session acts as (`derive_id` over the key).
    pub did: String,
    pubkey: String,
    signature: String,
}

impl Session {
    /// Construct a session from explicit parts (used by tests to forge a bad
    /// signature; production builds one via [`session_for`]).
    #[must_use]
    pub fn from_parts(did: String, pubkey: String, signature: String) -> Self {
        Self { did, pubkey, signature }
    }
}

/// Build a signed session for `keypair` acting as its derived `id:` DID.
#[must_use]
pub fn session_for(keypair: &Keypair) -> Session {
    let did = ciss::identity::derive_id(&keypair.verifying_key());
    let challenge = format!("{SESSION_CHALLENGE_PREFIX}{did}");
    Session {
        signature: keypair.sign_message(&challenge),
        pubkey: keypair.public_key_hex(),
        did,
    }
}

/// The result of an S3 `PUT`: the content address, the metered byte count, the
/// receipt mode, and the echoed ETag.
#[derive(Debug, Clone)]
pub struct PutResult {
    /// Content id (sha256 hex) the server assigned.
    pub cid: String,
    /// Bytes the server metered for this transfer.
    pub bytes: u64,
    /// `unilateral` (provider-signed) or `bilateral`.
    pub receipt_mode: String,
    /// The `etag` response header, if present.
    pub etag: Option<String>,
}

/// The result of an S3 `GET`: the bytes (already verified against the requested
/// cid) and the echoed ETag.
#[derive(Debug, Clone)]
pub struct GetResult {
    /// The object bytes, content-verified against the requested cid.
    pub bytes: Vec<u8>,
    /// The `etag` response header, if present.
    pub etag: Option<String>,
}

/// The billing meter for a namespace.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Meter {
    /// Number of signed transfer receipts recorded.
    pub receipt_count: u64,
    /// Total bytes uploaded.
    pub upload_bytes: u64,
    /// Total bytes downloaded.
    pub download_bytes: u64,
    /// Upload + download bytes.
    pub running_total_bytes: u64,
    /// Postage owed, in cents.
    pub postage_cents: u64,
}

/// A client bound to one CISS server base URL.
pub struct Client {
    base: String,
    http: reqwest::Client,
}

impl Client {
    /// A client for `base` (a trailing slash is trimmed).
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_owned(),
            http: reqwest::Client::new(),
        }
    }

    /// `PUT /{did}/objects/{key}` under a signed session.
    ///
    /// # Errors
    ///
    /// Fails on a connect error (server unreachable) or a non-2xx status, mapped
    /// to an actionable message.
    pub async fn put_s3(&self, session: &Session, key: &str, body: &[u8]) -> Result<PutResult> {
        let url = format!("{}/{}/objects/{}", self.base, session.did, key);
        let resp = self
            .send(
                self.http
                    .put(&url)
                    .header("x-croft-pubkey", &session.pubkey)
                    .header("x-croft-session", &session.signature)
                    .body(body.to_vec()),
                "upload",
            )
            .await?;
        let resp = self.ensure_success(resp, "upload").await?;
        let etag = header_owned(&resp, "etag");
        let v: serde_json::Value = resp.json().await.context("parse upload response")?;
        Ok(PutResult {
            cid: v["cid"].as_str().context("upload response missing cid")?.to_owned(),
            bytes: v["bytes"].as_u64().context("upload response missing bytes")?,
            receipt_mode: v["receipt_mode"].as_str().unwrap_or_default().to_owned(),
            etag,
        })
    }

    /// `GET /{did}/objects/{cid}` (public read). The returned bytes are verified
    /// to content-address to `cid` before this returns — a mismatch is an error,
    /// never a trusted body.
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx status, or a cid mismatch.
    pub async fn get_s3(&self, did: &str, cid: &str) -> Result<GetResult> {
        let url = format!("{}/{}/objects/{}", self.base, did, cid);
        let resp = self.send(self.http.get(&url), "download").await?;
        let resp = self.ensure_success(resp, "download").await?;
        let etag = header_owned(&resp, "etag");
        let bytes = resp.bytes().await.context("read download body")?.to_vec();
        verify_cid(cid, &bytes)?;
        Ok(GetResult { bytes, etag })
    }

    /// `GET /{did}/meter` under a signed session.
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status.
    pub async fn get_meter(&self, session: &Session) -> Result<Meter> {
        let url = format!("{}/{}/meter", self.base, session.did);
        let resp = self
            .send(
                self.http
                    .get(&url)
                    .header("x-croft-pubkey", &session.pubkey)
                    .header("x-croft-session", &session.signature),
                "meter",
            )
            .await?;
        let resp = self.ensure_success(resp, "meter").await?;
        resp.json::<Meter>().await.context("parse meter response")
    }

    /// Send a request, translating a connect/timeout failure into an actionable
    /// "server unreachable" error rather than a raw reqwest string.
    async fn send(
        &self,
        builder: reqwest::RequestBuilder,
        action: &str,
    ) -> Result<reqwest::Response> {
        builder.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                anyhow!("{action} failed: server unreachable at {}", self.base)
            } else {
                anyhow!("{action} failed: {e}")
            }
        })
    }

    /// Turn a non-2xx response into an actionable error; pass a 2xx through.
    async fn ensure_success(
        &self,
        resp: reqwest::Response,
        action: &str,
    ) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        let trimmed = body.trim();
        let detail = if trimmed.is_empty() {
            String::new()
        } else {
            format!(" ({trimmed})")
        };
        bail!("{action} failed: HTTP {code} — {}{detail}", status_hint(code));
    }
}

fn header_owned(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// An actionable, human hint for a server error status (the Observability note).
/// The 404 hint names the oracle-free ambiguity: a gated object denies reads by
/// returning 404, so "not found" and "not visible to you" are indistinguishable.
fn status_hint(code: u16) -> &'static str {
    match code {
        401 => "no or invalid session — run under an authenticated profile (ciss-ctl key gen)",
        403 => "forbidden — bad signature or wrong signer for this namespace",
        404 => "not found, or not visible to you — a gated object denies reads without disclosing whether it exists",
        409 => "conflict — the policy seq is not newer than the stored one",
        _ => "the server rejected the request",
    }
}

/// Verify that `bytes` content-address to `expected_cid` (sha256 hex). This is
/// the guard that a downloaded body was not corrupted or substituted in transit.
///
/// # Errors
///
/// Returns an error if the sha256 of `bytes` does not equal `expected_cid`.
pub fn verify_cid(expected_cid: &str, bytes: &[u8]) -> Result<()> {
    let actual = sha256_hex(bytes);
    if actual == expected_cid {
        Ok(())
    } else {
        bail!("content mismatch: requested {expected_cid}, but the {} bytes received hash to {actual} (corrupt or substituted body — not written)", bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::{status_hint, verify_cid};
    use ciss::crypto::sha256_hex;

    #[test]
    fn verify_cid_accepts_matching_bytes_and_rejects_a_flipped_byte() {
        let bytes = b"the quick brown fox".to_vec();
        let cid = sha256_hex(&bytes);
        assert!(verify_cid(&cid, &bytes).is_ok(), "the exact bytes verify");

        let mut corrupt = bytes.clone();
        corrupt[0] ^= 0x01;
        assert!(
            verify_cid(&cid, &corrupt).is_err(),
            "a single flipped byte must fail cid verification",
        );
        // A truncated body must also fail (a mutation dropping the length check).
        assert!(verify_cid(&cid, &bytes[..bytes.len() - 1]).is_err(), "truncation fails");
    }

    #[test]
    fn status_hint_is_actionable_per_code() {
        assert!(status_hint(401).contains("session"), "401 points at the session");
        let h403 = status_hint(403);
        assert!(
            h403.contains("forbidden") || h403.contains("signer"),
            "403 names a signature/signer problem",
        );
        let h404 = status_hint(404);
        assert!(
            h404.contains("not found") && (h404.contains("not visible") || h404.contains("gated")),
            "404 must name the oracle-free ambiguity, got {h404:?}",
        );
        assert!(status_hint(409).contains("seq"), "409 names the policy seq conflict");
    }
}
