//! TTL-based in-memory cache wrapping any [`SecretStore`].
//!
//! [`CachingStore`] wraps any backend that implements [`SecretStore`] and adds
//! a simple TTL-based memory cache. Cache entries are stored as
//! [`Zeroizing`] buffers so secret bytes are zeroed on
//! eviction. Setting `ttl` to [`Duration::ZERO`] disables caching entirely,
//! which is appropriate for file and env backends.
//!
//! # Lock discipline
//!
//! The internal [`std::sync::Mutex`] is **never held across an `.await`
//! point**. All cache reads and writes acquire the lock, copy the data they
//! need, then drop the lock before any network call.
//!
//! # Known limitation: thundering herd on TTL expiry
//!
//! When multiple async tasks share a `CachingStore` and a cached entry
//! expires, all tasks that call [`get`](SecretStore::get) concurrently will
//! each independently detect the miss, each call the inner backend, and each
//! write the result back.  For backends with API rate limits (AWS Secrets
//! Manager, AWS SSM Parameter Store) this can cause a brief burst of calls.
//!
//! **Mitigation**: choose a TTL long enough that simultaneous expiry is
//! unlikely in your workload (the default for network backends is 5 minutes).
//! In single-task applications the herd size is always 1 and this does not
//! arise.

use secretx_core::{SecretError, SecretStore, SecretValue, WritableSecretStore};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct CachedEntry {
    bytes: Zeroizing<Vec<u8>>,
    fetched_at: Instant,
}

/// A [`SecretStore`] wrapper that caches the secret value in memory with a TTL.
///
/// Construct with [`CachingStore::new`], passing the inner backend wrapped in
/// an [`Arc`] and the desired TTL. Use [`Duration::ZERO`] to disable caching.
///
/// Each `CachingStore` instance caches exactly one value — the secret
/// identified by the URI passed to the inner backend's `from_uri`. TTL
/// expiry triggers a fresh fetch from the backend on the next `get` call.
pub struct CachingStore<S: SecretStore + ?Sized> {
    inner: Arc<S>,
    ttl: Duration,
    cache: Arc<std::sync::Mutex<Option<CachedEntry>>>,
}

impl<S: SecretStore + ?Sized> std::fmt::Debug for CachingStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingStore")
            .field("ttl", &self.ttl)
            .field("cached", &self.cache.lock().map(|g| g.is_some()).unwrap_or(false))
            .finish_non_exhaustive()
    }
}

impl<S: SecretStore + ?Sized> CachingStore<S> {
    /// Create a new [`CachingStore`] wrapping `inner` with the given `ttl`.
    ///
    /// Pass [`Duration::ZERO`] to bypass caching (all calls go straight to the
    /// inner backend).
    pub fn new(inner: Arc<S>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl<S: SecretStore + ?Sized> SecretStore for CachingStore<S> {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        if self.ttl == Duration::ZERO {
            return self.inner.get().await;
        }

        // Check cache. The block scope releases the lock before the fetch below.
        {
            let cache = self.cache.lock().expect("cache mutex poisoned");
            if let Some(entry) = cache.as_ref() {
                // Use checked_add to avoid panic when ttl is Duration::MAX or
                // close to it — overflow means "never expires".
                let expired = match entry.fetched_at.checked_add(self.ttl) {
                    Some(expiry) => Instant::now() >= expiry,
                    None => false,
                };
                if !expired {
                    return Ok(SecretValue::from_zeroizing(Zeroizing::new(
                        entry.bytes.to_vec(),
                    )));
                }
            }
        }

        // Cache miss or expired — fetch from inner backend.
        let value = self.inner.get().await?;

        // Copy bytes for the cache entry before moving value into return position.
        let cached_bytes = Zeroizing::new(value.as_bytes().to_vec());
        {
            let mut cache = self.cache.lock().expect("cache mutex poisoned");
            *cache = Some(CachedEntry {
                bytes: cached_bytes,
                fetched_at: Instant::now(),
            });
        }

        Ok(value)
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        let value = self.inner.refresh().await?;

        if self.ttl != Duration::ZERO {
            let cached_bytes = Zeroizing::new(value.as_bytes().to_vec());
            let mut cache = self.cache.lock().expect("cache mutex poisoned");
            *cache = Some(CachedEntry {
                bytes: cached_bytes,
                fetched_at: Instant::now(),
            });
        }

        Ok(value)
    }
}

#[async_trait::async_trait]
impl<S: WritableSecretStore + ?Sized> WritableSecretStore for CachingStore<S> {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        // Copy bytes before consuming value (SecretValue has no Clone).
        let cached_bytes = Zeroizing::new(value.as_bytes().to_vec());

        // Write through to inner first; only update cache on success.
        self.inner.put(value).await?;

        if self.ttl != Duration::ZERO {
            let mut cache = self.cache.lock().expect("cache mutex poisoned");
            *cache = Some(CachedEntry {
                bytes: cached_bytes,
                fetched_at: Instant::now(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretx_core::{SecretError, SecretStore, SecretValue, WritableSecretStore};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// A minimal fake backend that counts how many times `get` is called.
    struct FakeStore {
        call_count: Arc<AtomicUsize>,
        value: &'static [u8],
    }

    #[async_trait::async_trait]
    impl SecretStore for FakeStore {
        async fn get(&self) -> Result<SecretValue, SecretError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(SecretValue::new(self.value.to_vec()))
        }

        async fn refresh(&self) -> Result<SecretValue, SecretError> {
            self.get().await
        }
    }

    #[async_trait::async_trait]
    impl WritableSecretStore for FakeStore {
        async fn put(&self, _value: SecretValue) -> Result<(), SecretError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn cache_hit_does_not_call_inner() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let fake = FakeStore {
            call_count: call_count.clone(),
            value: b"s3cr3t",
        };
        let store = CachingStore::new(Arc::new(fake), Duration::from_secs(60));

        let v1 = store.get().await.unwrap();
        assert_eq!(v1.as_bytes(), b"s3cr3t");

        let v2 = store.get().await.unwrap();
        assert_eq!(v2.as_bytes(), b"s3cr3t");

        // Inner should have been called exactly once.
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn zero_ttl_always_calls_inner() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let fake = FakeStore {
            call_count: call_count.clone(),
            value: b"val",
        };
        let store = CachingStore::new(Arc::new(fake), Duration::ZERO);

        store.get().await.unwrap();
        store.get().await.unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn put_populates_cache() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let fake = FakeStore {
            call_count: call_count.clone(),
            value: b"from-inner",
        };
        let store = CachingStore::new(Arc::new(fake), Duration::from_secs(60));

        store
            .put(SecretValue::new(b"from-put".to_vec()))
            .await
            .unwrap();

        // get should be served from cache — inner never called.
        let v = store.get().await.unwrap();
        assert_eq!(v.as_bytes(), b"from-put");
        assert_eq!(call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refresh_updates_cache() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let fake = FakeStore {
            call_count: call_count.clone(),
            value: b"refreshed",
        };
        let store = CachingStore::new(Arc::new(fake), Duration::from_secs(60));

        let v = store.refresh().await.unwrap();
        assert_eq!(v.as_bytes(), b"refreshed");

        // Subsequent get should be served from cache (only 1 inner call total).
        let v2 = store.get().await.unwrap();
        assert_eq!(v2.as_bytes(), b"refreshed");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn max_ttl_does_not_panic() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let fake = FakeStore {
            call_count: call_count.clone(),
            value: b"forever",
        };
        let store = CachingStore::new(Arc::new(fake), Duration::MAX);

        let v1 = store.get().await.unwrap();
        assert_eq!(v1.as_bytes(), b"forever");

        // Second call must be served from cache without panic.
        let v2 = store.get().await.unwrap();
        assert_eq!(v2.as_bytes(), b"forever");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
