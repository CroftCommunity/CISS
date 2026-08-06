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

/// A transport failure, phrased like the CISS client's (`server unreachable at
/// <host>` for a connect/timeout, else the raw cause).
fn transport_error(action: &str, host: &str, e: &reqwest::Error) -> anyhow::Error {
    if e.is_connect() || e.is_timeout() {
        anyhow::anyhow!("{action} failed: server unreachable at {host}")
    } else {
        anyhow::anyhow!("{action} failed: {e}")
    }
}

/// The `HTTP <code> — <body>` detail for a non-2xx PDS response (consumes it).
async fn http_error_detail(resp: reqwest::Response) -> String {
    let code = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let trimmed = body.trim();
    if trimmed.is_empty() {
        format!("HTTP {code}")
    } else {
        format!("HTTP {code} — {trimmed}")
    }
}

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

/// Persist a `did:` credential to the profile's `pds.json` at mode 0600 (the
/// profile dir is tightened to 0700). Overwrites an existing credential — a
/// re-login simply replaces it.
///
/// # Errors
///
/// Fails if the profile directory or file cannot be created/written.
pub fn save_credential(config: &Config, cred: &PdsCredential) -> Result<()> {
    let dir = config.profile_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    tighten_dir(&dir)?;
    let json = serde_json::to_vec_pretty(cred).context("serialize credential")?;
    write_secret_file(&config.credential_path(), &json)
}

/// Write `bytes` to `path` at mode 0600, replacing any existing file (re-login).
#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    // Truncate-or-create with 0600; a pre-existing file keeps whatever mode it
    // had, so reset it explicitly after.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create credential file {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write credential file {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

#[cfg(not(unix))]
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("write credential file {}", path.display()))
}

#[cfg(unix)]
fn tighten_dir(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))
}

#[cfg(not(unix))]
fn tighten_dir(_dir: &std::path::Path) -> Result<()> {
    Ok(())
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
        .map_err(|e| transport_error("PDS login", &cred.pds_host, &e))?;
    if !resp.status().is_success() {
        bail!("PDS login failed: {}", http_error_detail(resp).await);
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
        .map_err(|e| transport_error("getServiceAuth", pds_host, &e))?;
    if !resp.status().is_success() {
        bail!("getServiceAuth failed: {}", http_error_detail(resp).await);
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

/// Log in once and mint a service-auth token for each `lxm` (all against `aud`,
/// `exp = now + 60s`). Returns the account DID and the tokens in `lxms` order —
/// for a command that needs several method-scoped tokens (e.g. getPolicy +
/// setPolicy) without repeating the login.
///
/// # Errors
///
/// Fails if login or any mint fails.
pub async fn service_auth_tokens(
    http: &reqwest::Client,
    cred: &PdsCredential,
    aud: &str,
    lxms: &[&str],
) -> Result<(String, Vec<String>)> {
    let session = create_session(http, cred).await?;
    let exp = now_unix_s()? + 60;
    let mut tokens = Vec::with_capacity(lxms.len());
    for lxm in lxms {
        tokens.push(get_service_auth(http, &cred.pds_host, &session.access_jwt, aud, lxm, exp).await?);
    }
    Ok((session.did, tokens))
}

fn now_unix_s() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::{load_credential, save_credential, PdsCredential};
    use crate::config::Config;

    /// `save_credential` persists a `did:` credential at mode 0600 and it reads
    /// back intact via `load_credential` (the file path, with env unset).
    #[test]
    fn save_credential_round_trips_at_0600() {
        let tmp = std::env::temp_dir().join(format!("ciss-cred-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // SAFETY (edition 2021): this is the only lib test that touches these vars.
        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        std::env::remove_var("CISS_PDS_HOST");
        std::env::remove_var("CISS_PDS_IDENTIFIER");
        std::env::remove_var("CISS_PDS_APP_PASSWORD");

        let config = Config::new("default").expect("config");
        let cred = PdsCredential {
            pds_host: "https://bsky.social".to_owned(),
            identifier: "you.bsky.social".to_owned(),
            app_password: "abcd-efgh-ijkl-mnop".to_owned(),
        };
        save_credential(&config, &cred).expect("save credential");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(config.credential_path())
                .expect("stat")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "credential file must be 0600, got {mode:o}");
        }

        let loaded = load_credential(&config).expect("load credential");
        assert_eq!(loaded.pds_host, cred.pds_host);
        assert_eq!(loaded.identifier, cred.identifier);
        assert_eq!(loaded.app_password, cred.app_password);

        let _ = std::fs::remove_dir_all(&tmp);
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
