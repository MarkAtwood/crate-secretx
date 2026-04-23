//! Backend-agnostic secrets retrieval for Rust.
//!
//! Select a backend at runtime by URI:
//!
//! ```text
//! secretx://env/MY_SECRET
//! secretx://file//etc/keys/signing.key
//! secretx://aws-sm/prod/signing-key
//! secretx://vault/secret/data/myapp/key
//! ```
//!
//! The call site never names a backend. Switching from file-based dev secrets
//! to AWS Secrets Manager in prod is a one-line config change.

use std::sync::Arc;
use zeroize::Zeroizing;

/// A secret value whose memory is zeroed on drop.
///
/// Does not implement `Debug`, `Display`, or `Clone` to prevent accidental leakage.
/// Use [`as_bytes`](SecretValue::as_bytes) for comparisons in tests.
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

    /// URI was syntactically invalid or named an unknown/uncompiled backend.
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

/// A backend that retrieves and stores secrets.
///
/// # URI scheme
///
/// ```text
/// secretx://<backend>/<path>[?field=<name>]
/// ```
///
/// Use [`from_uri`](SecretStore::from_uri) to obtain a backend from a URI string.
/// Construction never makes a network call or file read.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Retrieve a secret by name/path. Implementations may serve from cache.
    async fn get(&self, name: &str) -> Result<SecretValue, SecretError>;

    /// Write or update a secret. Not supported by all backends.
    async fn put(&self, name: &str, value: SecretValue) -> Result<(), SecretError>;

    /// Force a cache refresh for this secret and return the refreshed value.
    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError>;

    /// Parse a URI and return the appropriate backend.
    ///
    /// Does not make any network call or file read — construction only.
    /// Returns [`SecretError::InvalidUri`] for unknown or uncompiled backends.
    fn from_uri(uri: &str) -> Result<Arc<dyn SecretStore>, SecretError>
    where
        Self: Sized;
}

/// Key algorithm used by a [`SigningBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
    RsaPss2048Sha256,
}

/// A signing backend where the private key never leaves the HSM.
///
/// Implemented by AWS KMS, Azure Key Vault HSM, and local key backends.
/// Call sites are identical regardless of backend.
#[async_trait::async_trait]
pub trait SigningBackend: Send + Sync {
    /// Sign `message` using the backend key. Returns raw signature bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError>;

    /// Return the public key as DER-encoded SubjectPublicKeyInfo.
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError>;

    /// Key algorithm identifier.
    fn algorithm(&self) -> SigningAlgorithm;
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
