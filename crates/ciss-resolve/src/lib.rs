//! `ciss-resolve` — atproto DID resolution for CISS.
//!
//! Resolves an atproto DID (`did:plc:…` via `plc.directory`, `did:web:…` via
//! HTTPS) to its **signing key** in `did:key:` form — the material a service-auth
//! JWT signature is verified against (`ciss_auth::verify_service_auth_jwt`, Phase 3).
//!
//! This is the network/cache/timeout half of CISS auth, kept out of `ciss-auth`
//! (which stays pure crypto, no TLS) behind the [`DidResolver`] trait. Every
//! implementation **fails closed**: any error is a rejection, never a fallthrough
//! to an unverified key. The production stack composes three layers (ADR 0001 §5):
//!
//! ```text
//!   PinnedResolver(admin set, always local)     ← poisoning-resistant break-glass
//!     └─ CachingResolver(TTL)                    ← bounds latency + staleness
//!          └─ PlcWebResolver(fetch + hard timeout)
//! ```

#![warn(missing_docs)]
#![warn(clippy::pedantic)]

mod cache;
mod doc;
mod fetch;
mod pinned;
mod static_resolver;
#[cfg(test)]
mod testutil;
mod timeout;

pub use cache::{CacheStats, CachingResolver, Clock, SystemClock};
pub use doc::{signing_key_from_doc, DidDocument};
pub use fetch::{DidDocFetcher, PlcWebResolver};
pub use pinned::PinnedResolver;
pub use static_resolver::StaticResolver;
pub use timeout::TimeoutResolver;

/// The default `did:plc` directory base URL.
pub const DEFAULT_PLC_DIRECTORY_URL: &str = "https://plc.directory";

use ciss_auth::ResolvedKeys;

/// Why DID resolution failed. Every variant is a hard failure: the caller treats
/// a resolution failure as an authentication failure (fail closed), never a
/// fallthrough to an unverified key.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The DID could not be found (unknown, or the directory returned 404).
    #[error("DID not found")]
    NotFound,
    /// Resolution exceeded the hard timeout.
    #[error("DID resolution timed out")]
    Timeout,
    /// The DID document was fetched but is malformed, is for the wrong DID, or
    /// carries no atproto signing key.
    #[error("DID document is malformed")]
    BadDocument,
    /// The DID document's atproto key uses an unsupported type/curve.
    #[error("unsupported atproto key type")]
    UnsupportedKeyType,
    /// The DID method is not one this resolver handles.
    #[error("unsupported DID method")]
    UnsupportedMethod,
    /// A transport/network error reaching the directory.
    #[error("resolver transport error")]
    Transport,
}

/// Resolve an atproto DID to its verification material.
///
/// Implementations MUST fail closed — return a [`ResolveError`] rather than any
/// key — on timeout, transport failure, an unresolvable DID, or a malformed
/// document. `force_refresh` bypasses any cache (used to survive a key rotation
/// on a first-verify failure).
#[async_trait::async_trait]
pub trait DidResolver: Send + Sync {
    /// Resolve `did` to its signing key, optionally bypassing the cache.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError`] for any failure; never returns an unverified key.
    async fn resolve(&self, did: &str, force_refresh: bool) -> Result<ResolvedKeys, ResolveError>;
}
