//! Environment variable backend for secretx.
//!
//! URI: `secretx:env:<VAR_NAME>`
//!
//! # Security note
//!
//! The `SecretValue` returned by `get` is wrapped in `Zeroizing` and zeroed on
//! drop.  However, the original environment variable remains in the process's
//! `environ` block for the lifetime of the process.  This copy is visible in
//! `/proc/self/environ`, core dumps, and is inherited by child processes via
//! `fork`/`exec`.  This is inherent to environment-variable-sourced secrets and
//! cannot be mitigated at the application layer.
//!
//! For high-sensitivity secrets, prefer file-backed (`secretx-file`),
//! HSM-backed, or cloud-backed backends where the secret never enters the
//! process environment.
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

use std::sync::Arc;

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};

/// Backend that reads a secret from a single environment variable.
///
/// `put` is not supported — env vars are not writable at runtime.
/// `refresh` re-reads the variable; useful when a process manager rotates it.
///
/// # Security note
///
/// Environment variables are inherently readable by the same user via
/// `/proc/<pid>/environ` on Linux.  This is an OS-level property, not a
/// defect in this backend.  For secrets that must not be visible in the
/// process environment, use a backend that fetches on demand (e.g.
/// `aws-sm`, `gcp-sm`, `vault`).
#[derive(Debug)]
pub struct EnvBackend {
    var: String,
}

impl EnvBackend {
    /// Construct from a `secretx:env:<VAR_NAME>` URI.
    ///
    /// Does not read the variable — construction only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        Self::from_parsed_uri(&SecretUri::parse(uri)?)
    }

    /// Construct from a pre-parsed [`SecretUri`].
    pub fn from_parsed_uri(parsed: &SecretUri) -> Result<Self, SecretError> {
        if parsed.backend() != "env" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `env`, got `{}`",
                parsed.backend()
            )));
        }
        let var_name = parsed.path();
        if var_name.is_empty() {
            return Err(SecretError::InvalidUri(
                "env URI requires a variable name: secretx:env:VAR_NAME".into(),
            ));
        }
        // Reject names that can never resolve as environment variables.
        // POSIX (IEEE Std 1003.1) says env var names must not contain '='
        // and must not be empty.  Embedded NUL bytes would be truncated by
        // the C runtime.  Catch these at construction time rather than
        // letting them silently fail at lookup time.
        if var_name.contains('=') {
            return Err(SecretError::InvalidUri(
                "env var name must not contain '='".into(),
            ));
        }
        if var_name.contains('\0') {
            return Err(SecretError::InvalidUri(
                "env var name must not contain NUL bytes".into(),
            ));
        }
        Ok(Self {
            var: var_name.to_owned(),
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

inventory::submit!(secretx_core::BackendRegistration::new(
    "env",
    |uri: &secretx_core::SecretUri| {
        let b = EnvBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

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

    #[test]
    fn from_uri_rejects_equals_in_name() {
        assert!(matches!(
            EnvBackend::from_uri("secretx:env:FOO=BAR"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_rejects_nul_in_name() {
        assert!(matches!(
            EnvBackend::from_uri("secretx:env:FOO\0BAR"),
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
        // SAFETY: ENV_LOCK (or test serialization) prevents concurrent env access.
        // These become unsafe fn in edition 2024.
        unsafe { std::env::set_var(var_name, OsStr::from_bytes(&[0xFF, 0xFE])) };
        let b = EnvBackend::from_uri(&format!("secretx:env:{var_name}")).unwrap();
        let result = b.get().await;
        unsafe { std::env::remove_var(var_name) };

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
