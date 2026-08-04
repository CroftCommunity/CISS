//! [`PinnedResolver`] — the poisoning-resistant break-glass layer.
//!
//! A hard-coded set of privileged DIDs whose verification keys are baked in and
//! **always resolved locally**, never delegated to the network arm. A poisoned or
//! unreachable `plc.directory`/DNS therefore cannot rotate an admin key underneath
//! us, and admin auth keeps working when the resolver is down (ADR 0001 §5).

use std::collections::HashMap;

use ciss_auth::ResolvedKeys;

use crate::{DidResolver, ResolveError};

/// Resolves a pinned set of DIDs locally; delegates everything else to `inner`.
pub struct PinnedResolver<R> {
    inner: R,
    pinned: HashMap<String, ResolvedKeys>,
}

impl<R> PinnedResolver<R> {
    /// Wrap `inner`, resolving each DID in `pinned` from the baked-in key instead.
    #[must_use]
    pub fn new(inner: R, pinned: HashMap<String, ResolvedKeys>) -> Self {
        Self { inner, pinned }
    }
}

#[async_trait::async_trait]
impl<R: DidResolver> DidResolver for PinnedResolver<R> {
    async fn resolve(&self, did: &str, force_refresh: bool) -> Result<ResolvedKeys, ResolveError> {
        // A pinned DID is always answered from the baked-in key — never delegated,
        // regardless of force_refresh — so a poisoned directory cannot rotate it.
        if let Some(keys) = self.pinned.get(did) {
            return Ok(keys.clone());
        }
        self.inner.resolve(did, force_refresh).await
    }
}

#[cfg(test)]
mod tests {
    use super::PinnedResolver;
    use crate::testutil::FakeResolver;
    use crate::{DidResolver, ResolveError};
    use ciss_auth::ResolvedKeys;
    use std::collections::HashMap;

    const ADMIN: &str = "did:plc:admin000000000000000000000";
    const ADMIN_KEY: &str = "did:key:zQ3shAdminPinnedKey";

    fn pinned_admin() -> HashMap<String, ResolvedKeys> {
        HashMap::from([(ADMIN.to_owned(), ResolvedKeys::new(ADMIN_KEY.to_owned()))])
    }

    #[tokio::test]
    async fn a_pinned_admin_resolves_locally_never_touching_the_network_arm() {
        // The inner resolver panics if called — passing proves the admin key came
        // from the pin, not the (poisonable) network.
        let resolver = PinnedResolver::new(FakeResolver::never_called(), pinned_admin());
        let keys = resolver.resolve(ADMIN, false).await.expect("pinned");
        assert_eq!(keys.signing_key(), ADMIN_KEY);
    }

    #[tokio::test]
    async fn a_pinned_admin_stays_local_even_under_force_refresh() {
        // force_refresh must not be a way to push an admin onto the network arm.
        let resolver = PinnedResolver::new(FakeResolver::never_called(), pinned_admin());
        let keys = resolver.resolve(ADMIN, true).await.expect("pinned");
        assert_eq!(keys.signing_key(), ADMIN_KEY);
    }

    #[tokio::test]
    async fn a_non_pinned_did_delegates_to_the_inner_resolver() {
        let inner = FakeResolver::returning("did:key:zQ3shDelegated");
        let resolver = PinnedResolver::new(inner, pinned_admin());
        let keys = resolver
            .resolve("did:plc:someoneelse", false)
            .await
            .expect("delegated");
        assert_eq!(keys.signing_key(), "did:key:zQ3shDelegated");
    }

    #[tokio::test]
    async fn a_non_pinned_did_that_the_inner_cannot_resolve_fails_closed() {
        let inner = FakeResolver::failing(ResolveError::NotFound);
        let resolver = PinnedResolver::new(inner, pinned_admin());
        assert_eq!(
            resolver.resolve("did:plc:unknown", false).await,
            Err(ResolveError::NotFound),
        );
    }
}
