//! In-process memory backend for secretx.
//!
//! URI: `secretx:mem:<KEY>`
//!
//! Provides a process-local key–value store backed by a `HashMap` in memory.
//! Useful for testing, ephemeral runtime secrets, and bootstrap/seed scenarios
//! where secrets are injected programmatically.
//!
//! # Standalone use (testing)
//!
//! ```rust
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_mem::MemStore;
//! use secretx_core::{SecretStore, WritableSecretStore, SecretValue};
//!
//! let store = MemStore::new();
//! store.insert("api-key", b"hunter2");
//!
//! let backend = store.backend("api-key");
//! let value = backend.get().await?;
//! assert_eq!(value.as_bytes(), b"hunter2");
//!
//! backend.put(SecretValue::new(b"rotated".to_vec())).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Global store (URI dispatch)
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_mem::MemStore;
//! use secretx_core::SecretStore;
//!
//! MemStore::global().insert("db-password", b"s3cret");
//!
//! let backend = secretx_mem::MemBackend::from_uri("secretx:mem:db-password")?;
//! let value = backend.get().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security note
//!
//! Secrets are held in process memory and zeroed on removal or drop.
//! They are not persisted, encrypted, or protected against memory dumps.
//! For production secrets, prefer backends with at-rest encryption and
//! access control.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};
use zeroize::Zeroizing;

type Map = HashMap<String, Zeroizing<Vec<u8>>>;

/// A process-local in-memory secret store.
///
/// `Clone` is cheap — clones share the same underlying map.
#[derive(Clone, Default)]
pub struct MemStore {
    inner: Arc<RwLock<Map>>,
}

impl std::fmt::Debug for MemStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.inner.read().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("MemStore")
            .field("keys", &count)
            .finish_non_exhaustive()
    }
}

impl MemStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the process-global store used by URI dispatch.
    #[must_use]
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<MemStore> = OnceLock::new();
        GLOBAL.get_or_init(MemStore::new)
    }

    /// Insert a secret, overwriting any existing value for this key.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn insert(&self, key: &str, value: impl Into<Vec<u8>>) {
        let mut map = self.inner.write().expect("MemStore lock poisoned");
        map.insert(key.to_owned(), Zeroizing::new(value.into()));
    }

    /// Remove a secret. Returns `true` if the key existed.
    /// The removed value is zeroed on drop.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn remove(&self, key: &str) -> bool {
        let mut map = self.inner.write().expect("MemStore lock poisoned");
        map.remove(key).is_some()
    }

    /// Get a [`MemBackend`] handle bound to one key in this store.
    #[must_use]
    pub fn backend(&self, key: &str) -> MemBackend {
        MemBackend {
            inner: Arc::clone(&self.inner),
            key: key.to_owned(),
        }
    }
}

/// A handle to a single key in a [`MemStore`].
///
/// Implements [`SecretStore`] and [`WritableSecretStore`].
///
/// # Panics
///
/// `get`, `put`, and `refresh` panic if the internal lock is poisoned.
#[derive(Clone)]
pub struct MemBackend {
    inner: Arc<RwLock<Map>>,
    key: String,
}

impl std::fmt::Debug for MemBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemBackend")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl MemBackend {
    /// Construct from a `secretx:mem:<KEY>` URI string.
    ///
    /// Uses the process-global [`MemStore`].
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        Self::from_parsed_uri(&SecretUri::parse(uri)?)
    }

    /// Construct from a pre-parsed [`SecretUri`].
    ///
    /// Uses the process-global [`MemStore`].
    pub fn from_parsed_uri(parsed: &SecretUri) -> Result<Self, SecretError> {
        if parsed.backend() != "mem" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `mem`, got `{}`",
                parsed.backend()
            )));
        }
        let key = parsed.path();
        if key.is_empty() {
            return Err(SecretError::InvalidUri(
                "mem URI requires a key name: secretx:mem:KEY".into(),
            ));
        }
        Ok(MemStore::global().backend(key))
    }
}

#[async_trait::async_trait]
impl SecretStore for MemBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let map = self.inner.read().expect("MemStore lock poisoned");
        match map.get(&self.key) {
            Some(v) => Ok(SecretValue::new(v.to_vec())),
            None => Err(SecretError::NotFound),
        }
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for MemBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let bytes = value.into_bytes();
        let mut map = self.inner.write().expect("MemStore lock poisoned");
        map.insert(self.key.clone(), bytes);
        Ok(())
    }
}

// ── Inventory registration (URI dispatch) ────────────────────────────────────

inventory::submit!(secretx_core::BackendRegistration::new(
    "mem",
    |uri: &secretx_core::SecretUri| {
        let b = MemBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

inventory::submit!(secretx_core::WritableBackendRegistration::new(
    "mem",
    |uri: &secretx_core::SecretUri| {
        let b = MemBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::WritableSecretStore>)
    },
));

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing ──────────────────────────────────────────────────────────

    #[test]
    fn from_uri_ok() {
        let b = MemBackend::from_uri("secretx:mem:my-key").unwrap();
        assert_eq!(b.key, "my-key");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            MemBackend::from_uri("secretx:file:foo"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        assert!(matches!(
            MemBackend::from_uri("secretx:mem"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // ── Standalone store ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_inserted_value() {
        let store = MemStore::new();
        store.insert("k", b"hello");
        let b = store.backend("k");
        let v = b.get().await.unwrap();
        assert_eq!(v.as_bytes(), b"hello");
    }

    #[tokio::test]
    async fn get_missing_key_returns_not_found() {
        let store = MemStore::new();
        let b = store.backend("missing");
        assert!(matches!(b.get().await, Err(SecretError::NotFound)));
    }

    #[tokio::test]
    async fn put_and_get_roundtrip() {
        let store = MemStore::new();
        let b = store.backend("k");
        b.put(SecretValue::new(b"secret".to_vec())).await.unwrap();
        let v = b.get().await.unwrap();
        assert_eq!(v.as_bytes(), b"secret");
    }

    #[tokio::test]
    async fn put_overwrites_existing() {
        let store = MemStore::new();
        store.insert("k", b"old");
        let b = store.backend("k");
        b.put(SecretValue::new(b"new".to_vec())).await.unwrap();
        let v = b.get().await.unwrap();
        assert_eq!(v.as_bytes(), b"new");
    }

    #[tokio::test]
    async fn refresh_returns_current_value() {
        let store = MemStore::new();
        store.insert("k", b"v1");
        let b = store.backend("k");
        assert_eq!(b.refresh().await.unwrap().as_bytes(), b"v1");
        store.insert("k", b"v2");
        assert_eq!(b.refresh().await.unwrap().as_bytes(), b"v2");
    }

    #[test]
    fn remove_returns_true_then_false() {
        let store = MemStore::new();
        store.insert("k", b"secret");
        assert!(store.remove("k"));
        assert!(!store.remove("k"));
    }

    #[test]
    fn clone_shares_state() {
        let a = MemStore::new();
        let b = a.clone();
        a.insert("k", b"from-a");
        let map = b.inner.read().unwrap();
        assert!(map.contains_key("k"));
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let store = MemStore::new();
        store.insert("k", b"super-secret");
        let b = store.backend("k");
        let dbg = format!("{b:?}");
        assert!(dbg.contains("key"));
        assert!(!dbg.contains("super-secret"));
    }

    // ── Global store ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn global_store_uri_roundtrip() {
        MemStore::global().insert("test-global-key", b"global-value");
        let b = MemBackend::from_uri("secretx:mem:test-global-key").unwrap();
        let v = b.get().await.unwrap();
        assert_eq!(v.as_bytes(), b"global-value");
        MemStore::global().remove("test-global-key");
    }
}
