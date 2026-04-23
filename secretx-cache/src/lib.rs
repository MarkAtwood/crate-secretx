//! TTL-based in-memory cache wrapping any [`SecretStore`].
//!
//! [`CachingStore`] wraps any backend that implements [`SecretStore`] and adds
//! a simple TTL-based memory cache. Cache entries are stored as
//! [`Zeroizing`](zeroize::Zeroizing) buffers so secret bytes are zeroed on
//! eviction. Setting `ttl` to [`Duration::ZERO`] disables caching entirely,
//! which is appropriate for file and env backends.
//!
//! # Lock discipline
//!
//! The internal [`tokio::sync::Mutex`] is **never held across an `.await`
//! point**. All cache reads and writes acquire the lock, copy the data they
//! need, then drop the lock before any network call.

use secretx_core::{SecretError, SecretStore, SecretValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct CachedEntry {
    bytes: Zeroizing<Vec<u8>>,
    fetched_at: Instant,
}

/// A [`SecretStore`] wrapper that caches secret values in memory with a TTL.
///
/// Construct with [`CachingStore::new`], passing the inner backend wrapped in
/// an [`Arc`] and the desired TTL. Use [`Duration::ZERO`] to disable caching.
pub struct CachingStore<S: SecretStore> {
    inner: Arc<S>,
    ttl: Duration,
    cache: Arc<tokio::sync::Mutex<HashMap<String, CachedEntry>>>,
}

impl<S: SecretStore> CachingStore<S> {
    /// Create a new [`CachingStore`] wrapping `inner` with the given `ttl`.
    ///
    /// Pass [`Duration::ZERO`] to bypass caching (all calls go straight to the
    /// inner backend).
    pub fn new(inner: Arc<S>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl<S: SecretStore> SecretStore for CachingStore<S> {
    async fn get(&self, name: &str) -> Result<SecretValue, SecretError> {
        if self.ttl == Duration::ZERO {
            return self.inner.get(name).await;
        }

        // Check cache — copy bytes out before dropping the lock.
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(name) {
                if entry.fetched_at.elapsed() < self.ttl {
                    let bytes = entry.bytes.to_vec();
                    drop(cache);
                    return Ok(SecretValue::new(bytes));
                }
            }
        } // lock dropped here

        // Cache miss or expired — fetch from inner backend.
        let value = self.inner.get(name).await?;

        // Copy bytes for the cache entry before moving value into return position.
        let cached_bytes = Zeroizing::new(value.as_bytes().to_vec());

        {
            let mut cache = self.cache.lock().await;
            cache.insert(
                name.to_string(),
                CachedEntry {
                    bytes: cached_bytes,
                    fetched_at: Instant::now(),
                },
            );
        } // lock dropped here

        Ok(value)
    }

    async fn put(&self, name: &str, value: SecretValue) -> Result<(), SecretError> {
        // Copy bytes before consuming value (SecretValue has no Clone).
        let cached_bytes = Zeroizing::new(value.as_bytes().to_vec());

        self.inner.put(name, value).await?;

        if self.ttl != Duration::ZERO {
            let mut cache = self.cache.lock().await;
            cache.insert(
                name.to_string(),
                CachedEntry {
                    bytes: cached_bytes,
                    fetched_at: Instant::now(),
                },
            );
        } // lock dropped here

        Ok(())
    }

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        let value = self.inner.refresh(name).await?;

        if self.ttl != Duration::ZERO {
            let cached_bytes = Zeroizing::new(value.as_bytes().to_vec());
            let mut cache = self.cache.lock().await;
            cache.insert(
                name.to_string(),
                CachedEntry {
                    bytes: cached_bytes,
                    fetched_at: Instant::now(),
                },
            );
        } // lock dropped here

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretx_core::{SecretError, SecretStore, SecretValue};
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
        async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(SecretValue::new(self.value.to_vec()))
        }

        async fn put(&self, _name: &str, _value: SecretValue) -> Result<(), SecretError> {
            Ok(())
        }

        async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
            self.get(name).await
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

        let v1 = store.get("key").await.unwrap();
        assert_eq!(v1.as_bytes(), b"s3cr3t");

        let v2 = store.get("key").await.unwrap();
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

        store.get("key").await.unwrap();
        store.get("key").await.unwrap();

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
            .put("key", SecretValue::new(b"from-put".to_vec()))
            .await
            .unwrap();

        // get should be served from cache — inner never called.
        let v = store.get("key").await.unwrap();
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

        let v = store.refresh("key").await.unwrap();
        assert_eq!(v.as_bytes(), b"refreshed");

        // Subsequent get should be served from cache (only 1 inner call total).
        let v2 = store.get("key").await.unwrap();
        assert_eq!(v2.as_bytes(), b"refreshed");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
