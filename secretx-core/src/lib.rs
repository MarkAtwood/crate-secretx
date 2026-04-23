//! Core traits and types for the secretx secrets retrieval library.
//!
//! Backend crates depend on this crate and implement [`SecretStore`] and/or
//! [`SigningBackend`]. Use [`SecretUri::parse`] to parse `secretx://` URIs
//! in backend constructors.

use std::collections::HashMap;
use zeroize::Zeroizing;

// ── SecretValue ──────────────────────────────────────────────────────────────

/// A secret value whose memory is zeroed on drop.
///
/// Does not implement `Debug`, `Display`, or `Clone` to prevent accidental
/// leakage. Use [`as_bytes`](SecretValue::as_bytes) for comparisons in tests.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretValue(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// Decode as UTF-8 without copying. Fails if not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, SecretError> {
        std::str::from_utf8(&self.0)
            .map_err(|_| SecretError::DecodeFailed("not valid UTF-8".into()))
    }

    /// Parse as a JSON object and extract a single string field.
    ///
    /// Common for secrets that bundle multiple values as JSON,
    /// e.g. `{"username":"foo","password":"bar"}`.
    pub fn extract_field(&self, field: &str) -> Result<SecretValue, SecretError> {
        let s = self.as_str()?;
        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(s)
            .map_err(|e| SecretError::DecodeFailed(e.to_string()))?;
        match map.get(field) {
            Some(serde_json::Value::String(v)) => Ok(SecretValue::new(v.as_bytes().to_vec())),
            Some(_) => Err(SecretError::DecodeFailed(format!(
                "field `{field}` is not a string"
            ))),
            None => Err(SecretError::DecodeFailed(format!(
                "field `{field}` not found"
            ))),
        }
    }
}

// ── SecretError ───────────────────────────────────────────────────────────────

/// Errors returned by secret store operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// Backend returned no secret for this name/path.
    #[error("secret not found")]
    NotFound,

    /// Backend returned an error.
    #[error("backend `{backend}` error: {source}")]
    Backend {
        backend: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// URI was syntactically invalid or named an unknown/disabled backend.
    #[error("invalid URI: {0}")]
    InvalidUri(String),

    /// Secret was present but could not be decoded as expected.
    #[error("decode failed: {0}")]
    DecodeFailed(String),

    /// Backend is not available (unreachable, token expired, etc.).
    #[error("backend `{backend}` unavailable: {source}")]
    Unavailable {
        backend: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

// ── SecretUri ─────────────────────────────────────────────────────────────────

/// A parsed `secretx://` URI.
///
/// All backend `from_uri` constructors should parse with this type rather than
/// rolling their own string splitting.
///
/// # URI structure
///
/// ```text
/// secretx://<backend>/<path>[?key=val&key2=val2]
/// ```
///
/// Absolute file paths use a double slash after the backend:
///
/// ```text
/// secretx://file//etc/secrets/key   →  backend="file", path="/etc/secrets/key"
/// secretx://file/relative/path      →  backend="file", path="relative/path"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretUri {
    /// Backend name, e.g. `"aws-sm"`, `"file"`, `"env"`.
    pub backend: String,
    /// Backend-specific path, e.g. `"prod/signing-key"` or `"/etc/secrets/key"`.
    pub path: String,
    /// Query parameters, e.g. `?field=password` → `{"field": "password"}`.
    pub params: HashMap<String, String>,
}

impl SecretUri {
    const SCHEME: &'static str = "secretx://";

    /// Parse a `secretx://` URI.
    ///
    /// Returns [`SecretError::InvalidUri`] if the URI does not start with
    /// `secretx://` or has an empty backend component.
    pub fn parse(uri: &str) -> Result<Self, SecretError> {
        let rest = uri.strip_prefix(Self::SCHEME).ok_or_else(|| {
            SecretError::InvalidUri(format!("URI must start with `secretx://`, got: {uri}"))
        })?;

        // Split query string from path.
        let (path_part, query_part) = match rest.find('?') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };

        // Split backend name from the rest of the path on the first '/'.
        let (backend, raw_path) = match path_part.find('/') {
            Some(i) => (&path_part[..i], &path_part[i + 1..]),
            None => (path_part, ""),
        };

        if backend.is_empty() {
            return Err(SecretError::InvalidUri(format!(
                "missing backend name in URI: {uri}"
            )));
        }

        // raw_path starts with '/' for absolute paths (the double-slash encoding):
        //   secretx://file//etc/key  →  raw_path = "/etc/key"   (absolute)
        //   secretx://file/rel/key   →  raw_path = "rel/key"    (relative)
        let path = raw_path.to_string();

        // Parse query parameters.
        let mut params = HashMap::new();
        if let Some(q) = query_part {
            for pair in q.split('&').filter(|s| !s.is_empty()) {
                match pair.find('=') {
                    Some(i) => {
                        params.insert(pair[..i].to_string(), pair[i + 1..].to_string());
                    }
                    None => {
                        params.insert(pair.to_string(), String::new());
                    }
                }
            }
        }

        Ok(SecretUri {
            backend: backend.to_string(),
            path,
            params,
        })
    }

    /// Return a query parameter value by key, or `None` if absent.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }
}

// ── SecretStore ───────────────────────────────────────────────────────────────

/// A backend that retrieves and stores secrets.
///
/// Implement this trait in a backend crate. Provide a `from_uri` constructor
/// as a plain method (not part of this trait) that calls [`SecretUri::parse`]
/// and validates the backend component. URI dispatch is handled by
/// `secretx::from_uri` in the umbrella crate.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Retrieve a secret by name/path. Implementations may serve from cache.
    async fn get(&self, name: &str) -> Result<SecretValue, SecretError>;

    /// Write or update a secret. Not supported by all backends.
    async fn put(&self, name: &str, value: SecretValue) -> Result<(), SecretError>;

    /// Force a cache refresh for this secret and return the refreshed value.
    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError>;
}

// ── SigningBackend ────────────────────────────────────────────────────────────

/// Key algorithm used by a [`SigningBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
    RsaPss2048Sha256,
}

/// A signing backend where the private key never leaves the HSM.
///
/// Implemented by AWS KMS, Azure Key Vault HSM, PKCS#11, wolfHSM, and local
/// key backends. Call sites are identical regardless of backend.
#[async_trait::async_trait]
pub trait SigningBackend: Send + Sync {
    /// Sign `message` using the backend key. Returns raw signature bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError>;

    /// Return the public key as DER-encoded SubjectPublicKeyInfo.
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError>;

    /// Key algorithm identifier.
    fn algorithm(&self) -> SigningAlgorithm;
}

// ── Blocking adapter ─────────────────────────────────────────────────────────

/// Synchronous wrapper for [`SecretStore::get`].
///
/// Works both inside an existing tokio runtime and outside one (creates a
/// single-threaded runtime for the call).  When called from within an existing
/// runtime the call is offloaded to a scoped OS thread with its own runtime so
/// that `block_on` does not panic.
///
/// # Panics
/// Does not panic in normal use.  Panics only if the spawned helper thread
/// itself panics (i.e. if tokio runtime construction fails).
#[cfg(feature = "blocking")]
pub fn get_blocking(store: &dyn SecretStore, name: &str) -> Result<SecretValue, SecretError> {
    // When called from outside any tokio runtime, spin up a one-shot
    // current-thread runtime directly on this thread.
    //
    // When called from inside an existing runtime (current_thread or
    // multi-thread), block_on would panic if called on the same thread.
    // Instead, use std::thread::scope to spawn a scoped thread that borrows
    // `store` and `name` safely. The scope guarantees the thread is joined
    // before it exits, so no lifetime transmutation is needed.
    match tokio::runtime::Handle::try_current() {
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|e| SecretError::Backend {
                backend: "blocking",
                source: e.into(),
            })?
            .block_on(store.get(name)),
        Ok(_) => {
            let mut result: Option<Result<SecretValue, SecretError>> = None;
            std::thread::scope(|s| {
                let join = s.spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .build()
                        .map_err(|e| SecretError::Backend {
                            backend: "blocking",
                            source: e.into(),
                        })?
                        .block_on(store.get(name))
                });
                result = Some(join.join().unwrap_or_else(|_| {
                    Err(SecretError::Backend {
                        backend: "blocking",
                        source: "get_blocking thread panicked".into(),
                    })
                }));
            });
            result.expect("scope always sets result before exiting")
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // SecretValue tests

    #[test]
    fn secret_value_as_bytes() {
        let v = SecretValue::new(b"hello".to_vec());
        assert_eq!(v.as_bytes(), b"hello");
    }

    #[test]
    fn secret_value_as_str() {
        let v = SecretValue::new(b"hello".to_vec());
        assert_eq!(v.as_str().unwrap(), "hello");
    }

    #[test]
    fn secret_value_as_str_invalid_utf8() {
        let v = SecretValue::new(vec![0xff, 0xfe]);
        assert!(matches!(v.as_str(), Err(SecretError::DecodeFailed(_))));
    }

    #[test]
    fn extract_field_ok() {
        let v = SecretValue::new(br#"{"password":"hunter2","user":"alice"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    #[test]
    fn extract_field_missing() {
        let v = SecretValue::new(br#"{"user":"alice"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_field_not_string() {
        let v = SecretValue::new(br#"{"count":42}"#.to_vec());
        assert!(matches!(
            v.extract_field("count"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_field_invalid_json() {
        let v = SecretValue::new(b"not json".to_vec());
        assert!(matches!(
            v.extract_field("x"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // SecretUri tests

    #[test]
    fn uri_env() {
        let u = SecretUri::parse("secretx://env/MY_SECRET").unwrap();
        assert_eq!(u.backend, "env");
        assert_eq!(u.path, "MY_SECRET");
        assert!(u.params.is_empty());
    }

    #[test]
    fn uri_file_relative() {
        let u = SecretUri::parse("secretx://file/relative/path/key").unwrap();
        assert_eq!(u.backend, "file");
        assert_eq!(u.path, "relative/path/key");
    }

    #[test]
    fn uri_file_absolute() {
        let u = SecretUri::parse("secretx://file//etc/secrets/key").unwrap();
        assert_eq!(u.backend, "file");
        assert_eq!(u.path, "/etc/secrets/key");
    }

    #[test]
    fn uri_aws_sm_with_params() {
        let u = SecretUri::parse("secretx://aws-sm/prod/signing-key?field=password&version=AWSCURRENT").unwrap();
        assert_eq!(u.backend, "aws-sm");
        assert_eq!(u.path, "prod/signing-key");
        assert_eq!(u.param("field"), Some("password"));
        assert_eq!(u.param("version"), Some("AWSCURRENT"));
    }

    #[test]
    fn uri_pkcs11_with_lib() {
        let u = SecretUri::parse("secretx://pkcs11/0/my-key?lib=/usr/lib/libsofthsm2.so").unwrap();
        assert_eq!(u.backend, "pkcs11");
        assert_eq!(u.path, "0/my-key");
        assert_eq!(u.param("lib"), Some("/usr/lib/libsofthsm2.so"));
    }

    #[test]
    fn uri_no_path() {
        let u = SecretUri::parse("secretx://wolfhsm/my-key").unwrap();
        assert_eq!(u.backend, "wolfhsm");
        assert_eq!(u.path, "my-key");
    }

    #[test]
    fn uri_wrong_scheme() {
        assert!(matches!(
            SecretUri::parse("https://example.com/secret"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn uri_empty_backend() {
        assert!(matches!(
            SecretUri::parse("secretx:///path"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn uri_missing_param() {
        let u = SecretUri::parse("secretx://aws-sm/my-secret").unwrap();
        assert_eq!(u.param("field"), None);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn get_blocking_outside_runtime() {
        use std::sync::Arc;

        struct FakeStore;

        #[async_trait::async_trait]
        impl SecretStore for FakeStore {
            async fn get(&self, name: &str) -> Result<SecretValue, SecretError> {
                Ok(SecretValue::new(format!("value-for-{name}").into_bytes()))
            }
            async fn put(&self, _: &str, _: SecretValue) -> Result<(), SecretError> {
                Ok(())
            }
            async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
                self.get(name).await
            }
        }

        let store = Arc::new(FakeStore);
        let v = get_blocking(store.as_ref(), "my-key").unwrap();
        assert_eq!(v.as_bytes(), b"value-for-my-key");
    }
}
