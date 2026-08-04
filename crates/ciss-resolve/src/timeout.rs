//! [`TimeoutResolver`] — a hard wall-clock bound on resolution.
//!
//! An unresolvable or slow DID must never park the request path (an availability
//! sink — the atproto-identity increment's motivating hazard). This wrapper bounds
//! the inner resolve and turns an overrun into [`ResolveError::Timeout`] (fail
//! closed), never a hang.

use std::time::Duration;

use ciss_auth::ResolvedKeys;

use crate::{DidResolver, ResolveError};

/// Bounds `inner.resolve` to `timeout`; an overrun is [`ResolveError::Timeout`].
pub struct TimeoutResolver<R> {
    inner: R,
    timeout: Duration,
}

impl<R> TimeoutResolver<R> {
    /// Wrap `inner` with a hard `timeout`.
    #[must_use]
    pub fn new(inner: R, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

#[async_trait::async_trait]
impl<R: DidResolver> DidResolver for TimeoutResolver<R> {
    async fn resolve(&self, did: &str, force_refresh: bool) -> Result<ResolvedKeys, ResolveError> {
        match tokio::time::timeout(self.timeout, self.inner.resolve(did, force_refresh)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ResolveError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TimeoutResolver;
    use crate::testutil::FakeResolver;
    use crate::{DidResolver, ResolveError};
    use ciss_auth::ResolvedKeys;
    use std::time::Duration;

    /// An inner resolver that sleeps past any reasonable timeout before answering.
    struct SlowResolver;
    #[async_trait::async_trait]
    impl DidResolver for SlowResolver {
        async fn resolve(&self, _did: &str, _force: bool) -> Result<ResolvedKeys, ResolveError> {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(ResolvedKeys::new("did:key:zNeverReached".to_owned()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_resolve_that_exceeds_the_timeout_fails_closed() {
        let resolver = TimeoutResolver::new(SlowResolver, Duration::from_secs(2));
        assert_eq!(
            resolver.resolve("did:plc:slow", false).await,
            Err(ResolveError::Timeout),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_resolve_passes_through_unchanged() {
        let inner = FakeResolver::returning("did:key:zQ3shFast");
        let resolver = TimeoutResolver::new(inner, Duration::from_secs(2));
        let keys = resolver.resolve("did:plc:fast", false).await.expect("resolves");
        assert_eq!(keys.signing_key(), "did:key:zQ3shFast");
    }
}
