//! Environment variable backend for secretx.
//!
//! URI: `secretx://env/<VAR_NAME>`
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_env::EnvBackend;
//! use secretx_core::SecretStore;
//!
//! let store = EnvBackend::from_uri("secretx://env/API_KEY")?;
//! let value = store.get("API_KEY").await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};

/// Backend that reads a secret from a single environment variable.
///
/// `put` is not supported — env vars are not writable at runtime.
/// `refresh` re-reads the variable; useful when a process manager rotates it.
pub struct EnvBackend {
    var: String,
}

impl EnvBackend {
    /// Construct from a `secretx://env/<VAR_NAME>` URI.
    ///
    /// Does not read the variable — construction only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "env" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `env`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "env URI requires a variable name: secretx://env/VAR_NAME".into(),
            ));
        }
        Ok(Self { var: parsed.path })
    }
}

#[async_trait::async_trait]
impl SecretStore for EnvBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        std::env::var(&self.var)
            .map(|s| SecretValue::new(s.into_bytes()))
            .map_err(|_| SecretError::NotFound)
    }

    async fn put(&self, _name: &str, _value: SecretValue) -> Result<(), SecretError> {
        Err(SecretError::NotFound)
    }

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_ok() {
        let b = EnvBackend::from_uri("secretx://env/MY_VAR").unwrap();
        assert_eq!(b.var, "MY_VAR");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            EnvBackend::from_uri("secretx://file/foo"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        assert!(matches!(
            EnvBackend::from_uri("secretx://env"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[tokio::test]
    async fn get_present_var() {
        // PATH is set in every sane environment.
        let b = EnvBackend::from_uri("secretx://env/PATH").unwrap();
        let v = b.get("ignored").await.unwrap();
        assert!(!v.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn get_missing_var() {
        let b =
            EnvBackend::from_uri("secretx://env/SECRETX_SURELY_NOT_SET_XYZZY123").unwrap();
        assert!(matches!(
            b.get("ignored").await,
            Err(SecretError::NotFound)
        ));
    }

    #[tokio::test]
    async fn put_returns_not_found() {
        let b = EnvBackend::from_uri("secretx://env/X").unwrap();
        assert!(matches!(
            b.put("x", SecretValue::new(b"v".to_vec())).await,
            Err(SecretError::NotFound)
        ));
    }

    #[tokio::test]
    async fn refresh_rereads() {
        let b = EnvBackend::from_uri("secretx://env/PATH").unwrap();
        let v = b.refresh("ignored").await.unwrap();
        assert!(!v.as_bytes().is_empty());
    }
}
