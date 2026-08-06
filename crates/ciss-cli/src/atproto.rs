//! The `did:` relay (Model R): log in to the user's PDS with an app password and
//! fetch a short-lived, `aud`/`lxm`-scoped service-auth JWT that the **PDS** signs
//! with the user's repo key. The CLI holds a *credential*, never a signing key;
//! CISS is verify-only. Wire shapes confirmed by the D4 live probe against
//! `bsky.social`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::client::enc;
use crate::config::Config;

/// XRPC methods on the PDS.
const CREATE_SESSION: &str = "com.atproto.server.createSession";
const GET_SERVICE_AUTH: &str = "com.atproto.server.getServiceAuth";

/// A PDS credential for the `did:` plane. No signing key — the repo key stays at
/// the PDS. `Debug` deliberately redacts the app password.
#[derive(Clone, Serialize, Deserialize)]
pub struct PdsCredential {
    /// The PDS base URL, e.g. `https://bsky.social`.
    pub pds_host: String,
    /// The account handle or DID used to log in.
    pub identifier: String,
    /// A bsky **app password** (revocable), not the account password.
    pub app_password: String,
}

impl std::fmt::Debug for PdsCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdsCredential")
            .field("pds_host", &self.pds_host)
            .field("identifier", &self.identifier)
            .field("app_password", &"<redacted>")
            .finish()
    }
}

/// Load the `did:` credential: environment
/// (`CISS_PDS_HOST`/`CISS_PDS_IDENTIFIER`/`CISS_PDS_APP_PASSWORD`) wins — the form
/// the D4 probe and the Phase 9 demo use — else the profile credential file.
///
/// # Errors
///
/// Fails if neither the env triple nor the credential file is present/parseable.
pub fn load_credential(config: &Config) -> Result<PdsCredential> {
    if let (Ok(pds_host), Ok(identifier), Ok(app_password)) = (
        std::env::var("CISS_PDS_HOST"),
        std::env::var("CISS_PDS_IDENTIFIER"),
        std::env::var("CISS_PDS_APP_PASSWORD"),
    ) {
        return Ok(PdsCredential {
            pds_host,
            identifier,
            app_password,
        });
    }
    let path = config.credential_path();
    let text = std::fs::read_to_string(&path).map_err(|e| {
        anyhow::anyhow!(
            "no did: credential ({}: {e}). set CISS_PDS_HOST / CISS_PDS_IDENTIFIER / \
             CISS_PDS_APP_PASSWORD, or write {}",
            path.display(),
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

/// A logged-in PDS session: the access token plus the resolved account DID.
pub struct PdsSession {
    /// The PDS-issued access JWT (bearer for `getServiceAuth`).
    pub access_jwt: String,
    /// The account's DID (a `did:plc`), learned from the login response.
    pub did: String,
}

/// `POST /xrpc/com.atproto.server.createSession` — log in with the app password.
///
/// # Errors
///
/// Fails on a transport error or a non-2xx status (never logs the password).
pub async fn create_session(
    http: &reqwest::Client,
    cred: &PdsCredential,
) -> Result<PdsSession> {
    let url = format!(
        "{}/xrpc/{CREATE_SESSION}",
        cred.pds_host.trim_end_matches('/')
    );
    let resp = http
        .post(&url)
        .json(&serde_json::json!({
            "identifier": cred.identifier,
            "password": cred.app_password,
        }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("PDS login failed (connect): {e}"))?;
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        bail!("PDS login failed: HTTP {code} ({})", body.trim());
    }
    let v: serde_json::Value = resp.json().await.context("parse createSession response")?;
    Ok(PdsSession {
        access_jwt: v["accessJwt"]
            .as_str()
            .context("createSession response missing accessJwt")?
            .to_owned(),
        did: v["did"]
            .as_str()
            .context("createSession response missing did")?
            .to_owned(),
    })
}

/// `GET /xrpc/com.atproto.server.getServiceAuth?aud=&lxm=&exp=` — have the PDS
/// mint a service-auth JWT (signed by the account's repo key) scoped to `aud`
/// (the CISS service DID) and `lxm` (the method), expiring at `exp_unix_s`.
///
/// # Errors
///
/// Fails on a transport error, a non-2xx status, or a missing `token`.
pub async fn get_service_auth(
    http: &reqwest::Client,
    pds_host: &str,
    access_jwt: &str,
    aud: &str,
    lxm: &str,
    exp_unix_s: u64,
) -> Result<String> {
    let url = format!(
        "{}/xrpc/{GET_SERVICE_AUTH}?aud={}&lxm={}&exp={}",
        pds_host.trim_end_matches('/'),
        enc(aud),
        enc(lxm),
        exp_unix_s,
    );
    let resp = http
        .get(&url)
        .bearer_auth(access_jwt)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("getServiceAuth failed (connect): {e}"))?;
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        bail!("getServiceAuth failed: HTTP {code} ({})", body.trim());
    }
    let v: serde_json::Value = resp.json().await.context("parse getServiceAuth response")?;
    v["token"]
        .as_str()
        .context("getServiceAuth response missing token")
        .map(str::to_owned)
}

/// Log in and mint a service-auth JWT for `lxm` against `aud` — the full relay a
/// `did:` command runs before talking to CISS. Returns the token and the account
/// DID (the namespace CISS will store under). `exp` is `now + 60s` (a short window).
///
/// # Errors
///
/// Fails if login or minting fails, or the system clock is before the epoch.
pub async fn mint_service_auth(
    http: &reqwest::Client,
    cred: &PdsCredential,
    aud: &str,
    lxm: &str,
) -> Result<(String, String)> {
    let session = create_session(http, cred).await?;
    let exp = now_unix_s()? + 60;
    let token = get_service_auth(http, &cred.pds_host, &session.access_jwt, aud, lxm, exp).await?;
    Ok((token, session.did))
}

fn now_unix_s() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs())
}
