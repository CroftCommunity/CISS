//! [`StaticResolver`] — resolves DIDs from a fixed in-memory map; unknown DIDs
//! fail closed.
//!
//! Two uses: config-pinned keys (a small set resolved with no network at all), and
//! a hermetic test resolver so the request-path and flow suites verify Model-R auth
//! without reaching `plc.directory`.

use std::collections::HashMap;

use ciss_auth::ResolvedKeys;

use crate::{DidResolver, ResolveError};

/// Resolves DIDs from a fixed map; an unknown DID is [`ResolveError::NotFound`].
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    keys: HashMap<String, ResolvedKeys>,
}

impl StaticResolver {
    /// A resolver backed by `keys`.
    #[must_use]
    pub fn new(keys: HashMap<String, ResolvedKeys>) -> Self {
        Self { keys }
    }

    /// Add or replace one DID's key, builder-style.
    #[must_use]
    pub fn with(mut self, did: impl Into<String>, signing_key: impl Into<String>) -> Self {
        self.keys
            .insert(did.into(), ResolvedKeys::new(signing_key.into()));
        self
    }
}

#[async_trait::async_trait]
impl DidResolver for StaticResolver {
    async fn resolve(&self, did: &str, _force_refresh: bool) -> Result<ResolvedKeys, ResolveError> {
        self.keys.get(did).cloned().ok_or(ResolveError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::StaticResolver;
    use crate::{DidResolver, ResolveError};

    #[tokio::test]
    async fn resolves_a_known_did_from_the_map() {
        let resolver = StaticResolver::default().with("did:plc:alice", "did:key:zQ3shAlice");
        let keys = resolver.resolve("did:plc:alice", false).await.expect("known");
        assert_eq!(keys.signing_key(), "did:key:zQ3shAlice");
    }

    #[tokio::test]
    async fn an_unknown_did_fails_closed() {
        let resolver = StaticResolver::default().with("did:plc:alice", "did:key:zQ3shAlice");
        assert_eq!(
            resolver.resolve("did:plc:bob", false).await,
            Err(ResolveError::NotFound),
        );
    }
}
