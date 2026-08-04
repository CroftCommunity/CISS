//! [`PlcWebResolver`] — the network resolver: route a DID to its document URL,
//! fetch it, and extract the signing key.
//!
//! The raw HTTP GET is abstracted behind [`DidDocFetcher`] so the routing and
//! parsing logic is unit-tested against fixtures with no socket. The real fetcher
//! (a `reqwest` client) is wired at the request-path layer; here we own the
//! did:plc/did:web routing and the fail-closed document handling.

use ciss_auth::ResolvedKeys;

use crate::doc::{signing_key_from_doc, DidDocument};
use crate::{DidResolver, ResolveError};

/// Fetches the body at a URL. The one impure seam; everything else is testable.
#[async_trait::async_trait]
pub trait DidDocFetcher: Send + Sync {
    /// GET `url` and return the response body.
    ///
    /// # Errors
    ///
    /// [`ResolveError::NotFound`] for a 404, [`ResolveError::Transport`] for any
    /// other transport failure.
    async fn fetch(&self, url: &str) -> Result<String, ResolveError>;
}

/// Build the DID-document URL for a DID: `did:plc` via the directory, `did:web`
/// via the host's `/.well-known/did.json`.
fn doc_url(plc_base_url: &str, did: &str) -> Result<String, ResolveError> {
    if did.starts_with("did:plc:") {
        return Ok(format!("{plc_base_url}/{did}"));
    }
    if let Some(host) = did.strip_prefix("did:web:") {
        // SEAM: the `did:web:<host>:<path>` (colon-separated port/path) form is a
        // follow-up; the common atproto shape is host-only. A colon here (port or
        // path) is refused rather than mis-routed (fail closed).
        if host.is_empty() || host.contains(':') || host.contains('/') {
            return Err(ResolveError::UnsupportedMethod);
        }
        return Ok(format!("https://{host}/.well-known/did.json"));
    }
    Err(ResolveError::UnsupportedMethod)
}

/// Resolves a DID by fetching its document over `F` and extracting the key.
pub struct PlcWebResolver<F> {
    fetcher: F,
    plc_base_url: String,
}

impl<F> PlcWebResolver<F> {
    /// Wrap `fetcher`, resolving `did:plc` against `plc_base_url`.
    pub fn new(fetcher: F, plc_base_url: impl Into<String>) -> Self {
        Self {
            fetcher,
            plc_base_url: plc_base_url.into(),
        }
    }
}

#[async_trait::async_trait]
impl<F: DidDocFetcher> DidResolver for PlcWebResolver<F> {
    async fn resolve(&self, did: &str, _force_refresh: bool) -> Result<ResolvedKeys, ResolveError> {
        let url = doc_url(&self.plc_base_url, did)?;
        let body = self.fetcher.fetch(&url).await?;
        let doc: DidDocument = serde_json::from_str(&body).map_err(|_| ResolveError::BadDocument)?;
        signing_key_from_doc(did, &doc)
    }
}

#[cfg(test)]
mod tests {
    use super::{DidDocFetcher, PlcWebResolver};
    use crate::{DidResolver, ResolveError};
    use std::sync::Mutex;

    const PLC_DOC: &str = include_str!("../../../tests/fixtures/did/did-plc-bsky-app.json");
    const PLC_DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const EXPECTED_DID_KEY: &str = "did:key:zQ3shQo6TF2moaqMTrUZEM1jeuYRQXeHEx4evX9751y2qPqRA";

    /// A fetcher that records the URL it was asked for and returns a fixed result.
    struct FakeFetcher {
        seen_url: Mutex<Option<String>>,
        outcome: Result<String, ResolveError>,
    }
    impl FakeFetcher {
        fn returning(body: &str) -> Self {
            Self {
                seen_url: Mutex::new(None),
                outcome: Ok(body.to_owned()),
            }
        }
        fn failing(err: ResolveError) -> Self {
            Self {
                seen_url: Mutex::new(None),
                outcome: Err(err),
            }
        }
        fn seen(&self) -> Option<String> {
            self.seen_url.lock().unwrap().clone()
        }
    }
    #[async_trait::async_trait]
    impl DidDocFetcher for FakeFetcher {
        async fn fetch(&self, url: &str) -> Result<String, ResolveError> {
            *self.seen_url.lock().unwrap() = Some(url.to_owned());
            self.outcome.clone()
        }
    }

    #[tokio::test]
    async fn resolves_a_did_plc_via_the_directory_url() {
        let fetcher = FakeFetcher::returning(PLC_DOC);
        let resolver = PlcWebResolver::new(fetcher, "https://plc.directory");
        let keys = resolver.resolve(PLC_DID, false).await.expect("resolves");
        assert_eq!(keys.signing_key(), EXPECTED_DID_KEY);
    }

    #[tokio::test]
    async fn a_did_plc_is_fetched_from_the_configured_directory() {
        let resolver = PlcWebResolver::new(FakeFetcher::returning(PLC_DOC), "https://plc.example");
        resolver.resolve(PLC_DID, false).await.expect("resolves");
        assert_eq!(
            resolver.into_fetcher().seen().as_deref(),
            Some("https://plc.example/did:plc:z72i7hdynmk6r22z27h6tvur"),
        );
    }

    #[tokio::test]
    async fn a_did_web_is_fetched_from_well_known() {
        let fetcher = FakeFetcher::returning(
            r#"{"id":"did:web:example.com","verificationMethod":[
                {"id":"did:web:example.com#atproto","type":"Multikey","publicKeyMultibase":"zQ3shWeb"}]}"#,
        );
        let resolver = PlcWebResolver::new(fetcher, "https://plc.directory");
        let keys = resolver
            .resolve("did:web:example.com", false)
            .await
            .expect("resolves");
        assert_eq!(keys.signing_key(), "did:key:zQ3shWeb");
        assert_eq!(
            resolver.into_fetcher().seen().as_deref(),
            Some("https://example.com/.well-known/did.json"),
        );
    }

    #[tokio::test]
    async fn an_unsupported_method_is_refused_before_any_fetch() {
        let fetcher = FakeFetcher::returning(PLC_DOC);
        let resolver = PlcWebResolver::new(fetcher, "https://plc.directory");
        assert_eq!(
            resolver.resolve("did:key:zabc", false).await,
            Err(ResolveError::UnsupportedMethod),
        );
        assert_eq!(resolver.into_fetcher().seen(), None, "no fetch attempted");
    }

    #[tokio::test]
    async fn a_fetch_failure_fails_closed() {
        let fetcher = FakeFetcher::failing(ResolveError::NotFound);
        let resolver = PlcWebResolver::new(fetcher, "https://plc.directory");
        assert_eq!(
            resolver.resolve(PLC_DID, false).await,
            Err(ResolveError::NotFound),
        );
    }

    #[tokio::test]
    async fn a_non_json_body_is_a_bad_document() {
        let fetcher = FakeFetcher::returning("<html>not json</html>");
        let resolver = PlcWebResolver::new(fetcher, "https://plc.directory");
        assert_eq!(
            resolver.resolve(PLC_DID, false).await,
            Err(ResolveError::BadDocument),
        );
    }

    // Test-only accessor to read the fetcher back after resolution.
    impl<F> PlcWebResolver<F> {
        fn into_fetcher(self) -> F {
            self.fetcher
        }
    }
}
