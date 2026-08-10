//! HTTP client for the CISS server: signed-session auth, the S3 plane
//! (`put`/`get`/`meter`), and the actionable error-code mapping every command
//! shares. Reads are re-verified against their content address before they are
//! trusted, so a corrupted or substituted body never reaches the user.

use anyhow::{anyhow, bail, Context, Result};

use ciss::crypto::{sha256_hex, Keypair};

/// The domain-separated session-challenge prefix. Mirrors the server's private
/// `SESSION_CHALLENGE_PREFIX`; the wiring tests keep it in sync — a drift here
/// makes every authenticated call 401.
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

/// Attach a signed `id:` session (`x-croft-*`) to a request if one is given; an
/// absent session is an anonymous caller (world reads only, no grantee identity).
fn with_session(builder: reqwest::RequestBuilder, session: Option<&Session>) -> reqwest::RequestBuilder {
    match session {
        Some(s) => builder
            .header("x-croft-pubkey", &s.pubkey)
            .header("x-croft-session", &s.signature),
        None => builder,
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
    /// The receipt's content hash (countersign target when bilateral).
    pub receipt_hash: Option<String>,
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

/// Which byte-path a transfer uses. Both land at the same backend digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Plane {
    /// S3-compatible metered plane (`PUT/GET /{did}/objects/{key}`).
    S3,
    /// atproto blob plane (`uploadBlob`/`getBlob`).
    Pds,
}

/// The result of an atproto `uploadBlob`: the content address (bridged to the
/// same sha256 hex the S3 plane uses) plus the raw CIDv1 the network speaks.
#[derive(Debug, Clone)]
pub struct BlobUpload {
    /// Content id as sha256 hex — identical to the S3 plane's `cid`.
    pub cid: String,
    /// The CIDv1 (`ref.$link`) the atproto network addresses the blob by.
    pub cidv1: String,
    /// The blob size in bytes.
    pub bytes: u64,
}

/// One object in a usage (`du`) report: its content id and stored size.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UsageObject {
    /// Content id (sha256 hex).
    pub cid: String,
    /// Stored size in bytes.
    pub bytes: u64,
}

/// A usage (`du`) report for a namespace: per-object sizes + total.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Usage {
    /// The objects and their sizes.
    pub objects: Vec<UsageObject>,
    /// Total bytes across the listed objects.
    pub total_bytes: u64,
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
    verbose: u8,
}

impl Client {
    /// A client for `base` (a trailing slash is trimmed).
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            verbose: 0,
            base: base.into().trim_end_matches('/').to_owned(),
            http: reqwest::Client::new(),
        }
    }

    /// Set the verbosity level (from `-v`): at ≥1, each request's outcome is
    /// logged to stderr. Secrets are never logged.
    #[must_use]
    pub fn with_verbose(mut self, verbose: u8) -> Self {
        self.verbose = verbose;
        self
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
            receipt_hash: v["receipt_hash"].as_str().map(str::to_owned),
            etag,
        })
    }

    /// `GET /{did}/objects/{cid}`. Pass a `session` so a gated object recognizes
    /// the caller as owner/grantee; `None` is an anonymous world read. The bytes
    /// are verified to content-address to `cid` before returning — a mismatch is
    /// an error, never a trusted body.
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx status (a gated denial is 404), or a
    /// cid mismatch.
    pub async fn get_s3(
        &self,
        session: Option<&Session>,
        did: &str,
        cid: &str,
    ) -> Result<GetResult> {
        let url = format!("{}/{}/objects/{}", self.base, did, cid);
        let resp = self.send(with_session(self.http.get(&url), session), "download").await?;
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

    /// `POST /xrpc/com.atproto.repo.uploadBlob` under a signed session (the
    /// `x-croft-*` session is accepted as the atproto-plane credential). Returns
    /// the CIDv1 bridged back to the sha256 hex the S3 plane uses.
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx status, or a malformed blob ref.
    pub async fn upload_blob(&self, session: &Session, body: &[u8]) -> Result<BlobUpload> {
        let url = format!("{}/xrpc/com.atproto.repo.uploadBlob", self.base);
        let resp = self
            .send(
                self.http
                    .post(&url)
                    .header("x-croft-pubkey", &session.pubkey)
                    .header("x-croft-session", &session.signature)
                    .body(body.to_vec()),
                "upload",
            )
            .await?;
        let resp = self.ensure_success(resp, "upload").await?;
        Self::parse_blob_upload(resp, body.len() as u64).await
    }

    /// `POST /xrpc/com.atproto.repo.uploadBlob` presenting a **service-auth JWT**
    /// as the bearer (Model R, the `did:` plane). The token is relayed from the
    /// caller's PDS (`getServiceAuth`); CISS resolves its `iss` and verifies it.
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx status (a rejected token is 401), or a
    /// malformed blob ref.
    pub async fn upload_blob_bearer(&self, token: &str, body: &[u8]) -> Result<BlobUpload> {
        let url = format!("{}/xrpc/com.atproto.repo.uploadBlob", self.base);
        let resp = self
            .send(
                self.http.post(&url).bearer_auth(token).body(body.to_vec()),
                "upload",
            )
            .await?;
        let resp = self.ensure_success(resp, "upload").await?;
        Self::parse_blob_upload(resp, body.len() as u64).await
    }

    /// The service DID this server advertises at `/.well-known/did.json` — the
    /// `aud` a `did:` caller must target when minting a service-auth JWT.
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx status, or a missing `id`.
    pub async fn discover_service_did(&self) -> Result<String> {
        let url = format!("{}/.well-known/did.json", self.base);
        let resp = self.send(self.http.get(&url), "discover service DID").await?;
        let resp = self.ensure_success(resp, "discover service DID").await?;
        let v: serde_json::Value = resp.json().await.context("parse did.json")?;
        v["id"]
            .as_str()
            .context("did.json missing id")
            .map(str::to_owned)
    }

    /// Parse a `uploadBlob` response into a [`BlobUpload`], bridging its CIDv1 to
    /// the sha256 hex the S3 plane uses.
    async fn parse_blob_upload(resp: reqwest::Response, fallback_len: u64) -> Result<BlobUpload> {
        let v: serde_json::Value = resp.json().await.context("parse uploadBlob response")?;
        let cidv1 = v["blob"]["ref"]["$link"]
            .as_str()
            .context("uploadBlob response missing blob.ref.$link")?
            .to_owned();
        let bytes = v["blob"]["size"].as_u64().unwrap_or(fallback_len);
        let cid = ciss::cidv1::to_sha256_hex(&cidv1)
            .map_err(|e| anyhow!("bridge CIDv1 -> sha256 hex failed for {cidv1:?}: {e}"))?;
        Ok(BlobUpload { cid, cidv1, bytes })
    }

    /// `GET /xrpc/com.atproto.sync.getBlob?did=&cid=`. Pass a `session` so a
    /// gated blob recognizes the caller as owner/grantee (`getBlob` authenticates
    /// an `id:` session server-side); `None` is an anonymous world read. Takes the
    /// sha256 hex `cid`, bridges it to the CIDv1 the network speaks, and verifies
    /// the returned bytes against the hex cid before trusting.
    ///
    /// # Errors
    ///
    /// Fails on a bad cid, a connect error, a non-2xx status (a gated denial is
    /// 404), or a cid mismatch.
    pub async fn get_blob(
        &self,
        session: Option<&Session>,
        did: &str,
        cid: &str,
    ) -> Result<GetResult> {
        let cidv1 = ciss::cidv1::from_sha256_hex(cid)
            .map_err(|e| anyhow!("bridge sha256 hex -> CIDv1 failed for {cid:?}: {e}"))?;
        let url = format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            self.base,
            enc(did),
            enc(&cidv1),
        );
        let resp = self.send(with_session(self.http.get(&url), session), "download").await?;
        let resp = self.ensure_success(resp, "download").await?;
        let bytes = resp.bytes().await.context("read getBlob body")?.to_vec();
        verify_cid(cid, &bytes)?;
        Ok(GetResult { bytes, etag: None })
    }

    /// `GET /xrpc/com.atproto.sync.listBlobs?did=`. Pass a `session` so gated
    /// objects the caller may read are included; a non-grantee sees them omitted
    /// (omission, not a 403 — `listBlobs` is not an enumeration oracle). Returns
    /// the visible cids as sha256 hex (bridged from CIDv1).
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx status, or a malformed cid entry.
    pub async fn list_blobs(&self, session: Option<&Session>, did: &str) -> Result<Vec<String>> {
        let url = self.list_blobs_url(did);
        let resp = self.send(with_session(self.http.get(&url), session), "list").await?;
        Self::parse_cid_list(self.ensure_success(resp, "list").await?).await
    }

    /// `GET /xrpc/com.atproto.sync.listBlobs?did=` as a `did:` caller, presenting a
    /// service-auth JWT (`lxm=com.atproto.sync.listBlobs`) so the caller lists its
    /// own (or granted) blobs. Returns the visible cids as sha256 hex.
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx status, or a malformed cid entry.
    pub async fn list_blobs_bearer(&self, token: &str, did: &str) -> Result<Vec<String>> {
        let url = self.list_blobs_url(did);
        let resp = self.send(self.http.get(&url).bearer_auth(token), "list").await?;
        Self::parse_cid_list(self.ensure_success(resp, "list").await?).await
    }

    fn list_blobs_url(&self, did: &str) -> String {
        format!("{}/xrpc/com.atproto.sync.listBlobs?did={}", self.base, enc(did))
    }

    /// Parse a `listBlobs` response body (`{cids:[CIDv1,…]}`) into sha256-hex cids.
    async fn parse_cid_list(resp: reqwest::Response) -> Result<Vec<String>> {
        let v: serde_json::Value = resp.json().await.context("parse listBlobs response")?;
        v["cids"]
            .as_array()
            .context("listBlobs response missing cids array")?
            .iter()
            .map(|c| {
                let link = c.as_str().context("cid entry is not a string")?;
                ciss::cidv1::to_sha256_hex(link)
                    .map_err(|e| anyhow!("bridge CIDv1 -> sha256 hex failed for {link:?}: {e}"))
            })
            .collect()
    }

    /// `POST /{did}/receipt/{hash}/countersign` — complete a bilateral
    /// receipt with the customer's countersignature over its content hash.
    /// Returns the completed (doubly-signed) receipt.
    ///
    /// # Errors
    ///
    /// Connection failures, 403 (forged/wrong-signer), or 404 (no such
    /// receipt).
    pub async fn countersign_receipt(
        &self,
        session: &Session,
        did: &str,
        content_hash: &str,
        sig: &str,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/{}/receipt/{}/countersign", self.base, did, content_hash);
        let body = serde_json::json!({ "signer": session.pubkey, "sig": sig }).to_string();
        let resp = self.send(self.http.post(&url).body(body), "countersign receipt").await?;
        let resp = self.ensure_success(resp, "countersign receipt").await?;
        resp.json().await.context("parse countersigned receipt")
    }

    /// `PUT /{did}/assertion/{kind}[/{subkey}]` with a self-signed
    /// `SignedAssertion` body (Model A). Returns `(seq, ack)` — the ack is
    /// the provider's countersignature proving the assertion took effect.
    ///
    /// # Errors
    ///
    /// Connection failures or a non-2xx status (400 malformed/over-bound,
    /// 403 unauthorized, 409 stale seq).
    pub async fn put_assertion(
        &self,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
        record_json: &[u8],
    ) -> Result<(u64, serde_json::Value)> {
        let url = match subkey {
            None => format!("{}/{}/assertion/{}", self.base, did, kind),
            Some(sk) => format!("{}/{}/assertion/{}/{}", self.base, did, kind, sk),
        };
        let resp = self
            .send(self.http.put(&url).body(record_json.to_vec()), "put assertion")
            .await?;
        let resp = self.ensure_success(resp, "put assertion").await?;
        let v: serde_json::Value = resp.json().await.context("parse assertion response")?;
        let seq = v["seq"].as_u64().context("assertion response missing seq")?;
        Ok((seq, v["ack"].clone()))
    }

    /// `GET /{did}/assertion/{kind}[/{subkey}]` with the caller's session —
    /// the owner's read-back: `{assertion, ack}`; `None` on 404.
    ///
    /// # Errors
    ///
    /// Connection failures or a non-2xx, non-404 status.
    pub async fn get_assertion(
        &self,
        session: Option<&Session>,
        did: &str,
        kind: &str,
        subkey: Option<&str>,
    ) -> Result<Option<serde_json::Value>> {
        let url = match subkey {
            None => format!("{}/{}/assertion/{}", self.base, did, kind),
            Some(sk) => format!("{}/{}/assertion/{}/{}", self.base, did, kind, sk),
        };
        let req = with_session(self.http.get(&url), session);
        let resp = self.send(req, "get assertion").await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let resp = self.ensure_success(resp, "get assertion").await?;
        Ok(Some(resp.json().await.context("parse assertion body")?))
    }

    /// `PUT /{did}/assertion/policy/{cid}` with a self-signed `SignedAssertion` body
    /// (Model A — the record self-authorizes, so no session header is needed).
    /// Returns the stored `seq`.
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status (a stale `seq` is 409).
    pub async fn put_object_policy(&self, did: &str, cid: &str, record_json: &[u8]) -> Result<u64> {
        let url = format!("{}/{}/assertion/policy/{}", self.base, did, cid);
        let resp = self
            .send(self.http.put(&url).body(record_json.to_vec()), "set policy")
            .await?;
        let resp = self.ensure_success(resp, "set policy").await?;
        let v: serde_json::Value = resp.json().await.context("parse policy response")?;
        v["seq"].as_u64().context("policy response missing seq")
    }

    /// `PUT /{did}/assertion/policy/{cid}` as a **Model-C** `did:` owner: a
    /// `PolicyIntent` body plus a service-auth JWT bearer (`lxm=setPolicy`). CISS
    /// verifies the token, then builds and provider-attests the record. Returns
    /// the stored `seq`.
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status (a bad/absent token is 403, a
    /// stale `seq` is 409).
    pub async fn put_object_policy_intent(
        &self,
        did: &str,
        cid: &str,
        intent_json: &[u8],
        token: &str,
    ) -> Result<u64> {
        let url = format!("{}/{}/assertion/policy/{}", self.base, did, cid);
        let resp = self
            .send(
                self.http.put(&url).bearer_auth(token).body(intent_json.to_vec()),
                "set policy",
            )
            .await?;
        let resp = self.ensure_success(resp, "set policy").await?;
        let v: serde_json::Value = resp.json().await.context("parse policy response")?;
        v["seq"].as_u64().context("policy response missing seq")
    }

    /// `GET /xrpc/com.atproto.sync.getBlob` as a `did:` reader, presenting a
    /// service-auth JWT (`lxm=getBlob`) so a gated blob recognizes the caller as a
    /// grantee. Bytes are verified against `cid` before returning.
    ///
    /// # Errors
    ///
    /// Fails on a bad cid, a connect error, a non-2xx status (a gated denial is
    /// 404), or a cid mismatch.
    pub async fn get_blob_bearer(&self, did: &str, cid: &str, token: &str) -> Result<GetResult> {
        let cidv1 = ciss::cidv1::from_sha256_hex(cid)
            .map_err(|e| anyhow!("bridge sha256 hex -> CIDv1 failed for {cid:?}: {e}"))?;
        let url = format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            self.base,
            enc(did),
            enc(&cidv1),
        );
        let resp = self.send(self.http.get(&url).bearer_auth(token), "download").await?;
        let resp = self.ensure_success(resp, "download").await?;
        let bytes = resp.bytes().await.context("read getBlob body")?.to_vec();
        verify_cid(cid, &bytes)?;
        Ok(GetResult { bytes, etag: None })
    }

    /// `GET /{did}/assertion/policy/{cid}` with the caller's `session`. Returns the
    /// policy body the caller is allowed to see (the owner's full record, or a
    /// grantee's `{read_class, may_read}` view), or `None` when the gate returns
    /// 404 (no policy, or not visible to the caller — the oracle-free denial).
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status other than 404.
    pub async fn get_object_policy(
        &self,
        session: Option<&Session>,
        did: &str,
        cid: &str,
    ) -> Result<Option<serde_json::Value>> {
        let url = format!("{}/{}/assertion/policy/{}", self.base, did, cid);
        let resp = self
            .send(with_session(self.http.get(&url), session), "get policy")
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let resp = self.ensure_success(resp, "get policy").await?;
        Ok(Some(resp.json().await.context("parse policy body")?))
    }

    /// `GET /{did}/objects/{cid}/policy` as a **Model-C** `did:` owner, presenting
    /// a service-auth JWT (`lxm=getPolicy`). Returns the policy body, or `None` on
    /// a 404 (no policy, or not visible).
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status other than 404.
    pub async fn get_object_policy_bearer(
        &self,
        did: &str,
        cid: &str,
        token: &str,
    ) -> Result<Option<serde_json::Value>> {
        let url = format!("{}/{}/assertion/policy/{}", self.base, did, cid);
        let resp = self
            .send(self.http.get(&url).bearer_auth(token), "get policy")
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let resp = self.ensure_success(resp, "get policy").await?;
        Ok(Some(resp.json().await.context("parse policy body")?))
    }

    /// `GET /{did}/du` under an `id:` session — per-object sizes + total. Self
    /// usage (querying your own DID) always works; a cross-DID query needs the
    /// server's admin flag + admin membership, else 403.
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status (cross-DID unauthorized is 403).
    pub async fn du(&self, session: Option<&Session>, did: &str) -> Result<Usage> {
        let url = format!("{}/{}/du", self.base, did);
        let resp = self.send(with_session(self.http.get(&url), session), "du").await?;
        let resp = self.ensure_success(resp, "du").await?;
        resp.json::<Usage>().await.context("parse du response")
    }

    /// `GET /{did}/du` as a `did:` caller, presenting a service-auth JWT
    /// (`lxm=ing.croft.ciss.du`). Self usage for your account; cross-DID only if
    /// you are an admin and the server's flag is on.
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status.
    pub async fn du_bearer(&self, token: &str, did: &str) -> Result<Usage> {
        let url = format!("{}/{}/du", self.base, did);
        let resp = self.send(self.http.get(&url).bearer_auth(token), "du").await?;
        let resp = self.ensure_success(resp, "du").await?;
        resp.json::<Usage>().await.context("parse du response")
    }

    /// `PUT /{did}/manifest` — commit a signed keep-set manifest. The manifest
    /// is self-authorizing (the presented pubkey must derive the DID and have
    /// signed it), so only `x-croft-pubkey` is sent — no session header. The
    /// server refuses a seq that is not strictly newer than the stored one (I5).
    ///
    /// # Errors
    ///
    /// Fails on a connect error or a non-2xx status (a stale seq is a 4xx whose
    /// body names the seq conflict).
    pub async fn put_manifest(
        &self,
        session: &Session,
        manifest: &ciss::manifest::Manifest,
    ) -> Result<()> {
        let url = format!("{}/{}/manifest", self.base, session.did);
        let body = serde_json::to_vec(manifest).context("serialize manifest")?;
        let resp = self
            .send(
                self.http.put(&url).header("x-croft-pubkey", &session.pubkey).body(body),
                "manifest commit",
            )
            .await?;
        self.ensure_success(resp, "manifest commit").await?;
        Ok(())
    }

    /// `GET /{did}/manifest` — the committed keep-set manifest, if one exists
    /// (`None` on 404: a cold namespace). Anonymous: the manifest is a signed,
    /// world-readable record.
    ///
    /// # Errors
    ///
    /// Fails on a connect error, a non-2xx/404 status, or an unparseable body.
    pub async fn get_manifest(&self, did: &str) -> Result<Option<ciss::manifest::Manifest>> {
        let url = format!("{}/{}/manifest", self.base, did);
        let resp = self.send(self.http.get(&url), "manifest fetch").await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let resp = self.ensure_success(resp, "manifest fetch").await?;
        let manifest: ciss::manifest::Manifest =
            resp.json().await.context("parse manifest response")?;
        Ok(Some(manifest))
    }

    /// Send a request, translating a connect/timeout failure into an actionable
    /// "server unreachable" error rather than a raw reqwest string.
    async fn send(
        &self,
        builder: reqwest::RequestBuilder,
        action: &str,
    ) -> Result<reqwest::Response> {
        let resp = builder.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                anyhow!("{action} failed: server unreachable at {}", self.base)
            } else {
                anyhow!("{action} failed: {e}")
            }
        })?;
        if self.verbose > 0 {
            // Outcome only — never a header, body, or credential.
            eprintln!("[ciss-ctl] {action}: HTTP {}", resp.status().as_u16());
        }
        Ok(resp)
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

/// Percent-encode a query-string *value* (path segments interpolate `id:`/`did:`
/// directly against the server's routes, so only query values need this — e.g.
/// the `did`/`cid` params of getBlob/listBlobs, and the atproto relay's
/// `aud`/`lxm`). Mirrors the test harness's `enc`.
pub(crate) fn enc(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
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
        401 => "no or invalid credential — check your id: key (`ciss-ctl key gen`) or your did: credential/token",
        403 => "forbidden — bad signature or wrong signer for this namespace",
        404 => "not found, or not visible to you — a gated object denies reads without disclosing whether it exists",
        409 => "conflict — stale seq: the record does not supersede the stored one",
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
        // 401 is plane-neutral (an id: session or a did: token can both be missing
        // or invalid), so it points at the credential, not specifically `key gen`.
        assert!(status_hint(401).contains("credential"), "401 points at the credential");
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
