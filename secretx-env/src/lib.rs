//! Environment variable backend for secretx.
//!
//! URI: `secretx:env:<VAR_NAME>`
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_env::EnvBackend;
//! use secretx_core::SecretStore;
//!
//! let store = EnvBackend::from_uri("secretx:env:API_KEY")?;
//! let value = store.get().await?;
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
    /// Construct from a `secretx:env:<VAR_NAME>` URI.
    ///
    /// Does not read the variable — construction only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "env" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `env`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "env URI requires a variable name: secretx:env:VAR_NAME".into(),
            ));
        }
        Ok(Self {
            var: parsed.path().to_owned(),
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for EnvBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        match std::env::var(&self.var) {
            Ok(s) => Ok(SecretValue::new(s.into_bytes())),
            Err(std::env::VarError::NotPresent) => Err(SecretError::NotFound),
            Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::DecodeFailed(format!(
                "env var `{}` contains non-UTF-8 bytes",
                self.var
            ))),
        }
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "env",
    factory: |uri: &str| {
        EnvBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_ok() {
        let b = EnvBackend::from_uri("secretx:env:MY_VAR").unwrap();
        assert_eq!(b.var, "MY_VAR");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            EnvBackend::from_uri("secretx:file:foo"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        assert!(matches!(
            EnvBackend::from_uri("secretx:env"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[tokio::test]
    async fn get_present_var() {
        // PATH is set in every sane environment.
        let b = EnvBackend::from_uri("secretx:env:PATH").unwrap();
        let v = b.get().await.unwrap();
        assert!(!v.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn get_missing_var() {
        let b = EnvBackend::from_uri("secretx:env:SECRETX_SURELY_NOT_SET_XYZZY123").unwrap();
        assert!(matches!(b.get().await, Err(SecretError::NotFound)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn get_non_utf8_var_returns_decode_failed() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let var_name = "SECRETX_TEST_NON_UTF8_XYZZY9999";
        // 0xFF is never valid in UTF-8.
        std::env::set_var(var_name, OsStr::from_bytes(&[0xFF, 0xFE]));
        let b = EnvBackend::from_uri(&format!("secretx:env:{var_name}")).unwrap();
        let result = b.get().await;
        std::env::remove_var(var_name);

        assert!(
            matches!(result, Err(SecretError::DecodeFailed(_))),
            "non-UTF-8 env var must return DecodeFailed"
        );
    }

    #[tokio::test]
    async fn refresh_rereads() {
        let b = EnvBackend::from_uri("secretx:env:PATH").unwrap();
        let v = b.refresh().await.unwrap();
        assert!(!v.as_bytes().is_empty());
    }
}
