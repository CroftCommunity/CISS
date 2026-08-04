//! [`CachingResolver`] — a TTL cache over an inner resolver.
//!
//! Bounds both per-request latency and staleness (ADR 0001 §5). Only successful
//! resolutions are cached; a failure is never cached, so a transient outage does
//! not pin a DID as unresolvable. `force_refresh` bypasses the cache to survive a
//! key rotation on a first-verify failure. Time is injected via [`Clock`] so the
//! TTL is testable without sleeping.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ciss_auth::ResolvedKeys;

use crate::{DidResolver, ResolveError};

/// A monotonic-enough millisecond clock, injected so TTL expiry is deterministic
/// in tests.
pub trait Clock: Send + Sync {
    /// The current time in unix milliseconds.
    fn now_ms(&self) -> u64;
}

/// The production clock, reading wall time.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}

/// A cheap snapshot of resolver-cache operational condition. `hits`/`misses` are
/// relaxed atomic counters (no allocation, no extra locking); `size` is the live
/// entry count. Surfaced for operator visibility (logged on each network resolve;
/// available to a future metrics/`usage` surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    /// Live cached-entry count.
    pub size: usize,
    /// Resolutions served from cache.
    pub hits: u64,
    /// Resolutions that went to the inner resolver (cache miss or force-refresh).
    pub misses: u64,
}

impl CacheStats {
    /// Cache hit rate in `[0, 1]`; `0.0` with no activity.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            // Precision loss on huge counts is irrelevant for an operational rate.
            #[allow(clippy::cast_precision_loss)]
            {
                self.hits as f64 / total as f64
            }
        }
    }
}

/// Wraps `inner` with a TTL cache keyed by DID.
pub struct CachingResolver<R, C> {
    inner: R,
    clock: C,
    ttl_ms: u64,
    cache: Mutex<HashMap<String, CacheEntry>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

struct CacheEntry {
    expires_at_ms: u64,
    keys: ResolvedKeys,
}

impl<R, C> CachingResolver<R, C> {
    /// Wrap `inner`, caching successful resolutions for `ttl_ms` per `clock`.
    #[must_use]
    pub fn new(inner: R, clock: C, ttl_ms: u64) -> Self {
        Self {
            inner,
            clock,
            ttl_ms,
            cache: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// A cheap operational snapshot of the resolver cache.
    ///
    /// # Panics
    ///
    /// Panics only if the cache mutex is poisoned (a prior panic while held) —
    /// unreachable, as no code panics inside the critical section.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let size = self.cache.lock().expect("cache mutex not poisoned").len();
        CacheStats {
            size,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

#[async_trait::async_trait]
impl<R: DidResolver, C: Clock> DidResolver for CachingResolver<R, C> {
    async fn resolve(&self, did: &str, force_refresh: bool) -> Result<ResolvedKeys, ResolveError> {
        let now = self.clock.now_ms();
        // Cache read: clone the hit and drop the lock before any await (the std
        // guard is not held across the network call).
        if !force_refresh {
            let hit = {
                let cache = self.cache.lock().expect("cache mutex not poisoned");
                cache
                    .get(did)
                    .filter(|entry| entry.expires_at_ms > now)
                    .map(|entry| entry.keys.clone())
            };
            if let Some(keys) = hit {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(keys);
            }
        }
        // A cache miss (or a deliberate force-refresh): resolve via the inner
        // resolver. Only a success is cached; a failure is returned as-is (fail
        // closed) and never pins the DID as unresolvable.
        self.misses.fetch_add(1, Ordering::Relaxed);
        let keys = self.inner.resolve(did, force_refresh).await?;
        {
            let mut cache = self.cache.lock().expect("cache mutex not poisoned");
            cache.insert(
                did.to_owned(),
                CacheEntry {
                    expires_at_ms: now.saturating_add(self.ttl_ms),
                    keys: keys.clone(),
                },
            );
        }
        // Cheap operational visibility: a compact cache-condition line on each
        // network resolve (DEBUG — off in production, no cost beyond the atomics).
        let stats = self.stats();
        tracing::debug!(
            cache_size = stats.size,
            hits = stats.hits,
            misses = stats.misses,
            hit_rate = stats.hit_rate(),
            "DID resolution cache",
        );
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::{CachingResolver, Clock};
    use crate::testutil::FakeResolver;
    use crate::{DidResolver, ResolveError};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock the test drives by hand.
    struct TestClock(AtomicU64);
    impl TestClock {
        fn at(ms: u64) -> Self {
            Self(AtomicU64::new(ms))
        }
        fn advance(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
    }
    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    const DID: &str = "did:plc:cacheme00000000000000000000";

    #[tokio::test]
    async fn stats_track_hits_misses_and_size_cheaply() {
        let inner = FakeResolver::returning("did:key:zX");
        let resolver = CachingResolver::new(inner, TestClock::at(1_000), 5_000);
        resolver.resolve("did:plc:a", false).await.expect("fill a"); // miss
        resolver.resolve("did:plc:a", false).await.expect("hit a"); // hit
        resolver.resolve("did:plc:b", false).await.expect("fill b"); // miss
        let s = resolver.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 2);
        assert_eq!(s.size, 2);
        assert!((s.hit_rate() - 1.0 / 3.0).abs() < 1e-9, "hit_rate = hits/(hits+misses)");
    }

    #[tokio::test]
    async fn hit_rate_is_zero_with_no_activity() {
        let inner = FakeResolver::returning("did:key:zX");
        let resolver = CachingResolver::new(inner, TestClock::at(1_000), 5_000);
        assert!(resolver.stats().hit_rate() < f64::EPSILON, "no activity => 0.0");
    }

    #[tokio::test]
    async fn a_second_resolve_within_the_ttl_is_served_from_cache() {
        let inner = FakeResolver::returning("did:key:zQ3shCached");
        let resolver = CachingResolver::new(inner, TestClock::at(1_000), 5_000);
        let a = resolver.resolve(DID, false).await.expect("first");
        let b = resolver.resolve(DID, false).await.expect("second");
        assert_eq!(a, b);
        assert_eq!(resolver.inner_calls(), 1, "inner hit once, second was cached");
    }

    #[tokio::test]
    async fn a_resolve_after_the_ttl_expires_re_resolves() {
        let inner = FakeResolver::returning("did:key:zQ3shCached");
        let clock = TestClock::at(1_000);
        // Move the clock into the resolver, but keep resolving across a manual advance.
        let resolver = CachingResolver::new(inner, clock, 5_000);
        resolver.resolve(DID, false).await.expect("first");
        resolver.clock().advance(5_001);
        resolver.resolve(DID, false).await.expect("re-resolve");
        assert_eq!(resolver.inner_calls(), 2, "TTL expired, inner hit again");
    }

    #[tokio::test]
    async fn force_refresh_bypasses_a_fresh_cache_entry() {
        let inner = FakeResolver::returning("did:key:zQ3shCached");
        let resolver = CachingResolver::new(inner, TestClock::at(1_000), 5_000);
        resolver.resolve(DID, false).await.expect("first");
        resolver.resolve(DID, true).await.expect("forced");
        assert_eq!(resolver.inner_calls(), 2, "force_refresh ignored the cache");
    }

    #[tokio::test]
    async fn a_failed_resolution_is_not_cached() {
        let inner = FakeResolver::failing(ResolveError::Timeout);
        let resolver = CachingResolver::new(inner, TestClock::at(1_000), 5_000);
        assert_eq!(resolver.resolve(DID, false).await, Err(ResolveError::Timeout));
        assert_eq!(resolver.resolve(DID, false).await, Err(ResolveError::Timeout));
        assert_eq!(resolver.inner_calls(), 2, "an error is never cached");
    }

    // Test-only accessors into the wrapped fake + clock.
    impl<C> CachingResolver<FakeResolver, C> {
        fn inner_calls(&self) -> usize {
            self.inner.call_count()
        }
    }
    impl<R> CachingResolver<R, TestClock> {
        fn clock(&self) -> &TestClock {
            &self.clock
        }
    }
}
