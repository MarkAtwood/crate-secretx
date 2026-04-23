//! OS keychain backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without a keyring daemon.
//! The integration test (`SECRETX_KEYRING_INTEGRATION_TESTS=1`) requires a
//! running desktop keyring daemon (macOS Keychain, Windows Credential Manager,
//! or `gnome-keyring-daemon` / KWallet on Linux). On a headless Linux server
//! `put` succeeds but `get` returns `NotFound` — **do not run in CI without
//! a keyring daemon**.
//! **Integration-tested on: macOS, Windows (not yet). Linux desktop: not yet.**
//!
//! URI: `secretx://keyring/<service>/<account>`
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_keyring::KeyringBackend;
//! use secretx_core::SecretStore;
//!
//! let store = KeyringBackend::from_uri("secretx://keyring/my-app/api-key")?;
//! let value = store.get("api-key").await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};

/// Backend that reads and writes secrets via the OS keychain (libsecret, Keychain, DPAPI).
///
/// The URI path encodes both a service name and an account name separated by
/// the first `/`:
///
/// ```text
/// secretx://keyring/<service>/<account>
/// ```
///
/// `get` and `refresh` retrieve the stored password string.
/// `put` writes a new password string; the value must be valid UTF-8.
pub struct KeyringBackend {
    service: String,
    account: String,
}

impl KeyringBackend {
    /// Construct from a `secretx://keyring/<service>/<account>` URI.
    ///
    /// Does not open the keychain — construction only.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidUri`] if the backend is not `keyring`,
    /// the path is empty, or the path contains no `/` separator (both
    /// `service` and `account` must be non-empty).
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "keyring" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `keyring`, got `{}`",
                parsed.backend
            )));
        }
        // path must be "<service>/<account>" — split on the first '/'.
        let Some(sep) = parsed.path.find('/') else {
            return Err(SecretError::InvalidUri(
                "keyring URI requires `secretx://keyring/<service>/<account>`".into(),
            ));
        };
        let service = &parsed.path[..sep];
        let account = &parsed.path[sep + 1..];
        if service.is_empty() {
            return Err(SecretError::InvalidUri(
                "keyring URI: service name must not be empty".into(),
            ));
        }
        if account.is_empty() {
            return Err(SecretError::InvalidUri(
                "keyring URI: account name must not be empty".into(),
            ));
        }
        Ok(Self {
            service: service.to_string(),
            account: account.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for KeyringBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        let entry = keyring::Entry::new(&self.service, &self.account).map_err(|e| {
            SecretError::Backend {
                backend: "keyring",
                source: e.into(),
            }
        })?;
        match entry.get_password() {
            Ok(pw) => Ok(SecretValue::new(pw.into_bytes())),
            Err(keyring::Error::NoEntry) => Err(SecretError::NotFound),
            Err(e) => Err(SecretError::Backend {
                backend: "keyring",
                source: e.into(),
            }),
        }
    }

    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        let entry = keyring::Entry::new(&self.service, &self.account).map_err(|e| {
            SecretError::Backend {
                backend: "keyring",
                source: e.into(),
            }
        })?;
        let s = std::str::from_utf8(value.as_bytes())
            .map_err(|_| SecretError::DecodeFailed("keyring requires UTF-8 secret".into()))?;
        entry.set_password(s).map_err(|e| SecretError::Backend {
            backend: "keyring",
            source: e.into(),
        })
    }

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing tests (no OS keychain required) ───────────────────────────

    #[test]
    fn from_uri_ok() {
        let b = KeyringBackend::from_uri("secretx://keyring/my-app/api-key").unwrap();
        assert_eq!(b.service, "my-app");
        assert_eq!(b.account, "api-key");
    }

    #[test]
    fn from_uri_ok_nested_account() {
        // account portion may contain slashes; only the first '/' is the separator.
        let b = KeyringBackend::from_uri("secretx://keyring/svc/user/sub").unwrap();
        assert_eq!(b.service, "svc");
        assert_eq!(b.account, "user/sub");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            KeyringBackend::from_uri("secretx://env/MY_VAR"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_slash() {
        // path has no '/' so account is absent
        assert!(matches!(
            KeyringBackend::from_uri("secretx://keyring/onlyone"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_account() {
        // trailing slash means account is empty
        assert!(matches!(
            KeyringBackend::from_uri("secretx://keyring/svc/"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        // no path component at all
        assert!(matches!(
            KeyringBackend::from_uri("secretx://keyring"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // ── Integration tests (require OS keychain) ───────────────────────────────
    //
    // Gated behind SECRETX_KEYRING_INTEGRATION_TESTS=1.  On headless Linux
    // systems the keychain daemon may not be running; NoStorageAccess and
    // similar are treated as a graceful skip rather than a failure.

    /// Returns true if the error looks like "no storage available" — which
    /// happens on headless servers without a keyring daemon.
    fn is_no_storage(e: &SecretError) -> bool {
        let msg = format!("{e}");
        msg.contains("NoStorageAccess")
            || msg.contains("no storage")
            || msg.contains("No storage")
            || msg.contains("secret service")
            || msg.contains("Secret Service")
    }

    #[tokio::test]
    async fn integration_roundtrip() {
        if std::env::var("SECRETX_KEYRING_INTEGRATION_TESTS").as_deref() != Ok("1") {
            return;
        }

        let svc = "secretx-test";
        let acct = "roundtrip";
        let uri = format!("secretx://keyring/{svc}/{acct}");

        let backend = KeyringBackend::from_uri(&uri).unwrap();

        // Clean up any leftover entry from a previous run.
        if let Ok(entry) = keyring::Entry::new(svc, acct) {
            let _ = entry.delete_credential();
        }

        // Write.
        let put_result = backend
            .put("ignored", SecretValue::new(b"test-secret-value".to_vec()))
            .await;
        match put_result {
            Ok(()) => {}
            Err(ref e) if is_no_storage(e) => {
                eprintln!("keyring: no storage available, skipping integration test");
                return;
            }
            Err(e) => panic!("put failed: {e}"),
        }

        // Read back.
        let got = backend.get("ignored").await.expect("get after put failed");
        assert_eq!(got.as_bytes(), b"test-secret-value");

        // Refresh should also work.
        let refreshed = backend.refresh("ignored").await.expect("refresh failed");
        assert_eq!(refreshed.as_bytes(), b"test-secret-value");

        // Clean up.
        if let Ok(entry) = keyring::Entry::new(svc, acct) {
            let _ = entry.delete_credential();
        }

        // After deletion, get should return NotFound.
        let after = backend.get("ignored").await;
        assert!(
            matches!(after, Err(SecretError::NotFound)),
            "expected NotFound after delete"
        );
    }
}
