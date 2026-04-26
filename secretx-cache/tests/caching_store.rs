use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use secretx_cache::CachingStore;
use secretx_core::{SecretError, SecretStore, SecretValue, WritableSecretStore};

// ── Mock backend ──────────────────────────────────────────────────────────────
//
// Independent oracle: counts calls to get/put/refresh and returns a preset
// value.  Counters are Arc<Mutex<usize>> so the test retains observable handles
// after the mock Arc is moved into CachingStore.
//
// SecretStore is implemented on Arc<MockStore> (not MockStore) because
// CachingStore::new takes Arc<S: SecretStore>.

struct MockStore {
    get_count: Arc<Mutex<usize>>,
    put_count: Arc<Mutex<usize>>,
    refresh_count: Arc<Mutex<usize>>,
    value: String,
}

impl MockStore {
    fn new(value: &str) -> Arc<Self> {
        Arc::new(Self {
            get_count: Arc::new(Mutex::new(0)),
            put_count: Arc::new(Mutex::new(0)),
            refresh_count: Arc::new(Mutex::new(0)),
            value: value.to_string(),
        })
    }

    fn get_count(&self) -> usize {
        *self.get_count.lock().unwrap()
    }

    fn put_count(&self) -> usize {
        *self.put_count.lock().unwrap()
    }

    fn refresh_count(&self) -> usize {
        *self.refresh_count.lock().unwrap()
    }
}

#[async_trait]
impl SecretStore for MockStore {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        *self.get_count.lock().unwrap() += 1;
        Ok(SecretValue::new(self.value.as_bytes().to_vec()))
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        *self.refresh_count.lock().unwrap() += 1;
        // Re-fetch via get so the mock accurately simulates what a real backend
        // does: refresh goes to the source and returns a fresh value.
        self.get().await
    }
}

#[async_trait]
impl WritableSecretStore for MockStore {
    async fn put(&self, _value: SecretValue) -> Result<(), SecretError> {
        *self.put_count.lock().unwrap() += 1;
        Ok(())
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Construct a CachingStore wrapping a MockStore and return it together with
/// the observable mock handle (Arc<MockStore>).
fn make_cache(value: &str, ttl: Duration) -> (CachingStore<MockStore>, Arc<MockStore>) {
    let mock = MockStore::new(value);
    let cache = CachingStore::new(mock.clone(), ttl);
    (cache, mock)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Two gets within TTL: inner get called once; second call served from cache.
#[tokio::test]
async fn cache_hit_within_ttl() {
    let (cache, mock) = make_cache("correct-horse-battery-staple", Duration::from_secs(60));

    let first = cache.get().await.unwrap();
    assert_eq!(first.as_bytes(), b"correct-horse-battery-staple");
    assert_eq!(mock.get_count(), 1, "inner get called once on first fetch");

    let second = cache.get().await.unwrap();
    assert_eq!(second.as_bytes(), b"correct-horse-battery-staple");
    assert_eq!(mock.get_count(), 1, "inner get NOT called again within TTL");
}

/// Two gets with 1 ms TTL, sleeping 5 ms between them: cache expires, inner
/// get called twice.
#[tokio::test]
async fn cache_miss_after_ttl_expiry() {
    let (cache, mock) = make_cache("tr0ub4dor&3", Duration::from_millis(1));

    let first = cache.get().await.unwrap();
    assert_eq!(first.as_bytes(), b"tr0ub4dor&3");
    assert_eq!(mock.get_count(), 1, "inner get called on first fetch");

    std::thread::sleep(Duration::from_millis(5));

    let second = cache.get().await.unwrap();
    assert_eq!(second.as_bytes(), b"tr0ub4dor&3");
    assert_eq!(
        mock.get_count(),
        2,
        "inner get called again after TTL expiry"
    );
}

/// TTL of zero means no caching: every get hits the inner store.
#[tokio::test]
async fn ttl_zero_never_caches() {
    let (cache, mock) = make_cache("s3cr3t", Duration::ZERO);

    cache.get().await.unwrap();
    cache.get().await.unwrap();
    cache.get().await.unwrap();

    assert_eq!(
        mock.get_count(),
        3,
        "inner get called on every request when TTL is zero"
    );
}

/// refresh bypasses the cache, calls the inner store's refresh, then caches
/// the result so a subsequent get within TTL does not call inner get again.
///
/// Sequence:
///   get       → inner get_count = 1, refresh_count = 0  (cache populated)
///   refresh   → inner refresh_count = 1, inner get_count = 2
///               (mock::refresh re-fetches via mock::get; cache updated)
///   get again → inner get_count stays at 2              (served from cache)
#[tokio::test]
async fn refresh_bypasses_cache() {
    let (cache, mock) = make_cache("initial-value", Duration::from_secs(60));

    // Populate cache via get.
    let v = cache.get().await.unwrap();
    assert_eq!(v.as_bytes(), b"initial-value");
    assert_eq!(
        mock.get_count(),
        1,
        "inner get called once to populate cache"
    );
    assert_eq!(mock.refresh_count(), 0, "refresh not yet called");

    // refresh must bypass cache and call inner refresh.
    let refreshed = cache.refresh().await.unwrap();
    assert_eq!(
        refreshed.as_bytes(),
        b"initial-value",
        "refreshed value equals mock preset"
    );
    assert_eq!(mock.refresh_count(), 1, "inner refresh called exactly once");
    // mock::refresh delegates to mock::get, so get_count increments to 2.
    // This is the correct observable behaviour: the inner store was hit.

    // A subsequent get within TTL must be served from the cache that refresh
    // populated; inner get must NOT be called again.
    let get_count_after_refresh = mock.get_count();
    let after = cache.get().await.unwrap();
    assert_eq!(after.as_bytes(), b"initial-value");
    assert_eq!(
        mock.get_count(),
        get_count_after_refresh,
        "get after refresh served from cache; inner get count unchanged"
    );
}

/// put writes to the inner store and populates the cache so a subsequent get
/// within TTL does not call inner get.
#[tokio::test]
async fn put_updates_cache() {
    let (cache, mock) = make_cache("original", Duration::from_secs(60));

    // put a new value — inner get must not be called at all.
    cache
        .put(SecretValue::new(b"updated".to_vec()))
        .await
        .unwrap();
    assert_eq!(mock.put_count(), 1, "inner put called exactly once");
    assert_eq!(mock.get_count(), 0, "inner get not called during put");

    // get within TTL must be served from cache populated by put.
    let v = cache.get().await.unwrap();
    assert_eq!(
        v.as_bytes(),
        b"updated",
        "get returns the value written by put"
    );
    assert_eq!(
        mock.get_count(),
        0,
        "inner get not called after put; served from cache"
    );
}
