//! Shared test doubles for the composition layers — a fake inner [`DidResolver`]
//! that counts calls, so cache/pin behavior is testable without a network.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ciss_auth::ResolvedKeys;

use crate::{DidResolver, ResolveError};

/// A fake inner resolver: counts calls and returns a fixed key or a fixed error.
/// [`FakeResolver::never_called`] panics if resolved — proof a wrapper resolved
/// locally.
pub struct FakeResolver {
    calls: Arc<AtomicUsize>,
    outcome: Result<ResolvedKeys, ResolveError>,
    panic_if_called: bool,
}

impl FakeResolver {
    /// A resolver that returns `did_key` for every DID.
    pub fn returning(did_key: &str) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            outcome: Ok(ResolvedKeys::new(did_key.to_owned())),
            panic_if_called: false,
        }
    }

    /// A resolver that always fails with `err`.
    pub fn failing(err: ResolveError) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            outcome: Err(err),
            panic_if_called: false,
        }
    }

    /// A resolver that must never be called (panics if it is).
    pub fn never_called() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            outcome: Err(ResolveError::NotFound),
            panic_if_called: true,
        }
    }

    /// How many times `resolve` has been invoked.
    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl DidResolver for FakeResolver {
    async fn resolve(&self, _did: &str, _force_refresh: bool) -> Result<ResolvedKeys, ResolveError> {
        assert!(!self.panic_if_called, "inner resolver must not be called");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcome.clone()
    }
}
