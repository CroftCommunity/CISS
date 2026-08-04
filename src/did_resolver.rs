//! Production DID-resolver composition (deploy wiring).
//!
//! Assembles the `ciss-resolve` layers into the resolver `AppState` holds, and
//! provides the one real network adapter ([`ReqwestFetcher`]) behind the
//! `DidDocFetcher` port. The composition order is load-bearing:
//!
//! ```text
//!   PinnedResolver(admin)  → answered locally, never network (break-glass)
//!     └─ CachingResolver   → a hit skips the timeout + fetch entirely
//!          └─ TimeoutResolver → bounds the network call (no hang)
//!               └─ PlcWebResolver(ReqwestFetcher) → the actual fetch
//! ```
//!
//! Configuration comes from the environment; a malformed admin-pin file **fails
//! the startup loudly** rather than silently running with an unpinned admin set.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ciss_auth::ResolvedKeys;
use ciss_resolve::{
    CachingResolver, DidDocFetcher, DidResolver, PinnedResolver, PlcWebResolver, ResolveError,
    SystemClock, TimeoutResolver, DEFAULT_PLC_DIRECTORY_URL,
};

/// The default service DID (the `aud` a service-auth JWT must name).
const DEFAULT_SERVICE_DID: &str = "did:web:ciss.croft.ing";
/// The default hard resolve timeout.
const DEFAULT_TIMEOUT_MS: u64 = 3_000;
/// The default resolution cache TTL.
const DEFAULT_CACHE_TTL_S: u64 = 300;

/// A `reqwest`-backed DID-document fetcher — the single network line, behind the
/// `DidDocFetcher` port so the resolver logic stays unit-testable without it.
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    /// Build a fetcher whose requests are bounded by `timeout`.
    ///
    /// # Panics
    ///
    /// Panics only if the platform TLS backend cannot initialize — unreachable in
    /// a normal deployment, and a startup-time failure if it ever were.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("ciss-resolve/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client builds with a default TLS backend");
        Self { client }
    }
}

#[async_trait::async_trait]
impl DidDocFetcher for ReqwestFetcher {
    async fn fetch(&self, url: &str) -> Result<String, ResolveError> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| ResolveError::Transport)?;
        match resp.status().as_u16() {
            200 => resp.text().await.map_err(|_| ResolveError::Transport),
            404 => Err(ResolveError::NotFound),
            _ => Err(ResolveError::Transport),
        }
    }
}

/// Resolved configuration for the DID resolver.
pub struct ResolveConfig {
    /// This service's atproto DID (the JWT `aud`).
    pub service_did: String,
    /// The `did:plc` directory base URL.
    pub plc_url: String,
    /// The hard resolve timeout.
    pub timeout: Duration,
    /// The resolution cache TTL in milliseconds.
    pub cache_ttl_ms: u64,
    /// The pinned admin set (resolved locally, never network).
    pub admin_pins: HashMap<String, ResolvedKeys>,
}

impl ResolveConfig {
    /// Read the resolver configuration from the environment.
    ///
    /// - `CISS_SERVICE_DID` (default `did:web:ciss.croft.ing`)
    /// - `CISS_PLC_DIRECTORY_URL` (default `https://plc.directory`)
    /// - `CISS_DID_RESOLVE_TIMEOUT_MS` (default 3000)
    /// - `CISS_DID_CACHE_TTL_S` (default 300)
    /// - `CISS_ADMIN_PINS_FILE` (optional path; lines `<did> <did:key>`)
    ///
    /// # Errors
    ///
    /// Returns a message if a numeric variable is non-numeric or the admin-pin
    /// file cannot be read or is malformed — a loud startup failure, not a silent
    /// mis-config.
    pub fn from_env() -> Result<Self, String> {
        let service_did = env_or(CISS_SERVICE_DID, DEFAULT_SERVICE_DID);
        let plc_url = env_or("CISS_PLC_DIRECTORY_URL", DEFAULT_PLC_DIRECTORY_URL);
        let timeout = Duration::from_millis(env_u64("CISS_DID_RESOLVE_TIMEOUT_MS", DEFAULT_TIMEOUT_MS)?);
        let cache_ttl_ms = env_u64("CISS_DID_CACHE_TTL_S", DEFAULT_CACHE_TTL_S)? * 1_000;
        let admin_pins = match std::env::var("CISS_ADMIN_PINS_FILE") {
            Ok(path) => {
                let text =
                    std::fs::read_to_string(&path).map_err(|e| format!("reading {path}: {e}"))?;
                parse_admin_pins(&text)?
            }
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            service_did,
            plc_url,
            timeout,
            cache_ttl_ms,
            admin_pins,
        })
    }
}

/// The `CISS_SERVICE_DID` env key (shared with the server's fallback default).
const CISS_SERVICE_DID: &str = "CISS_SERVICE_DID";

/// Compose the production resolver from `cfg` (see the module diagram).
#[must_use]
pub fn build_resolver(cfg: &ResolveConfig) -> Arc<dyn DidResolver> {
    let plc = PlcWebResolver::new(ReqwestFetcher::new(cfg.timeout), cfg.plc_url.clone());
    let timed = TimeoutResolver::new(plc, cfg.timeout);
    let cached = CachingResolver::new(timed, SystemClock, cfg.cache_ttl_ms);
    Arc::new(PinnedResolver::new(cached, cfg.admin_pins.clone()))
}

/// Parse an admin-pin file: non-empty, non-`#` lines of `<did> <did:key>`.
///
/// # Errors
///
/// Returns a message on any line that is not exactly a `did:*` and a `did:key:*`.
pub fn parse_admin_pins(text: &str) -> Result<HashMap<String, ResolvedKeys>, String> {
    let mut pins = HashMap::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next(), fields.next()) {
            (Some(did), Some(key), None)
                if did.starts_with("did:") && key.starts_with("did:key:") =>
            {
                pins.insert(did.to_owned(), ResolvedKeys::new(key.to_owned()));
            }
            _ => return Err(format!("malformed admin pin at line {}: {line:?}", n + 1)),
        }
    }
    Ok(pins)
}

/// An environment string with a default.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// A `u64` environment value with a default; a non-numeric value is a loud error.
fn env_u64(key: &str, default: u64) -> Result<u64, String> {
    match std::env::var(key) {
        Ok(v) => v.parse().map_err(|_| format!("{key} must be a number, got {v:?}")),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_admin_pins;

    #[test]
    fn parses_pins_ignoring_comments_and_blanks() {
        let text = "\
# admin break-glass pins
did:plc:admin1  did:key:zQ3shAdminOne

did:web:ops.example   did:key:zQ3shOps
";
        let pins = parse_admin_pins(text).expect("valid");
        assert_eq!(pins.len(), 2);
        assert_eq!(
            pins.get("did:plc:admin1").map(|k| k.signing_key().to_owned()),
            Some("did:key:zQ3shAdminOne".to_owned()),
        );
        assert_eq!(
            pins.get("did:web:ops.example").map(|k| k.signing_key().to_owned()),
            Some("did:key:zQ3shOps".to_owned()),
        );
    }

    #[test]
    fn an_empty_file_yields_no_pins() {
        assert!(parse_admin_pins("\n\n# just comments\n").expect("ok").is_empty());
    }

    #[test]
    fn a_malformed_line_fails_loudly() {
        // Missing the key.
        assert!(parse_admin_pins("did:plc:admin1").is_err());
        // A non-did:key value.
        assert!(parse_admin_pins("did:plc:admin1 not-a-key").is_err());
        // A non-did subject.
        assert!(parse_admin_pins("admin1 did:key:zQ3sh").is_err());
        // Extra field.
        assert!(parse_admin_pins("did:plc:a did:key:zQ3sh extra").is_err());
    }
}
