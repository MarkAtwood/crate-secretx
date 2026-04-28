//! Linux kernel keyring backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without a keyring daemon.
//! The integration test (`SECRETX_KEYRING_INTEGRATION_TESTS=1`) uses the Linux
//! kernel keyring directly — no daemon required. Run with:
//!
//! ```sh
//! SECRETX_KEYRING_INTEGRATION_TESTS=1 cargo test -p secretx-keyring
//! ```
//!
//! On Linux, secrets are stored in the kernel
//! [persistent keyring](https://www.man7.org/linux/man-pages/man7/persistent-keyring.7.html),
//! which survives reboots for a configurable window (default: a few days). No
//! daemon is needed.
//!
//! **Integration-tested 2026-04-28**: Linux headless (kernel persistent keyring,
//! no daemon).
//!
//! URI: `secretx:keyring:<service>/<account>`
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_keyring::KeyringBackend;
//! use secretx_core::{SecretStore, SecretValue, WritableSecretStore};
//!
//! // Read
//! let store = KeyringBackend::from_uri("secretx:keyring:my-app/api-key")?;
//! let value = store.get().await?;
//!
//! // Write (requires WritableSecretStore in scope)
//! store.put(SecretValue::new(b"new-secret".to_vec())).await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};

/// Backend that reads and writes secrets via the Linux kernel persistent keyring.
///
/// The URI path encodes both a service name and an account name separated by
/// the first `/`:
///
/// ```text
/// secretx:keyring:<service>/<account>
/// ```
///
/// `get` and `refresh` retrieve the stored password string.
/// `put` writes a new password string; the value must be valid UTF-8.
pub struct KeyringBackend {
    service: String,
    account: String,
}

impl KeyringBackend {
    /// Construct from a `secretx:keyring:<service>/<account>` URI.
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
        if parsed.backend() != "keyring" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `keyring`, got `{}`",
                parsed.backend()
            )));
        }
        // path must be "<service>/<account>" — split on the first '/'.
        // account may itself contain slashes (e.g. "svc/user/sub").
        let (service, account) = parsed.path().split_once('/').ok_or_else(|| {
            SecretError::InvalidUri(
                "keyring URI requires `secretx:keyring:<service>/<account>`".into(),
            )
        })?;
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
        // Keyring values are opaque byte strings stored by the OS keychain;
        // ?field= JSON extraction is not supported and would silently return
        // the full stored value, which is confusing.  Reject early.
        if parsed.param("field").is_some() {
            return Err(SecretError::InvalidUri(
                "keyring does not support ?field= (kernel keyring values are opaque strings, not JSON \
                 objects); remove ?field= or use a backend that supports JSON field extraction \
                 (e.g. aws-sm)"
                    .into(),
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
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let service = self.service.clone();
        let account = self.account.clone();
        // Kernel keyring calls (keyctl syscalls) are synchronous.
        // Run them on a blocking thread to avoid stalling the async executor.
        tokio::task::spawn_blocking(move || {
            let entry =
                keyring::Entry::new(&service, &account).map_err(|e| SecretError::Backend {
                    backend: "keyring",
                    source: e.into(),
                })?;
            match entry.get_password() {
                Ok(pw) => Ok(SecretValue::new(pw.into_bytes())),
                Err(keyring::Error::NoEntry) => Err(SecretError::NotFound),
                Err(keyring::Error::NoStorageAccess(e)) => Err(SecretError::Unavailable {
                    backend: "keyring",
                    source: e,
                }),
                Err(e) => Err(SecretError::Backend {
                    backend: "keyring",
                    source: e.into(),
                }),
            }
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "keyring",
            source: e.into(),
        })?
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for KeyringBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        // Decode to UTF-8 before entering spawn_blocking (no I/O needed here).
        let s = std::str::from_utf8(value.as_bytes())
            .map_err(|_| {
                SecretError::DecodeFailed("keyring backend requires UTF-8 secret values".into())
            })?
            .to_owned();
        let service = self.service.clone();
        let account = self.account.clone();
        tokio::task::spawn_blocking(move || {
            let entry =
                keyring::Entry::new(&service, &account).map_err(|e| SecretError::Backend {
                    backend: "keyring",
                    source: e.into(),
                })?;
            entry.set_password(&s).map_err(|e| match e {
                keyring::Error::NoStorageAccess(inner) => SecretError::Unavailable {
                    backend: "keyring",
                    source: inner,
                },
                other => SecretError::Backend {
                    backend: "keyring",
                    source: other.into(),
                },
            })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "keyring",
            source: e.into(),
        })?
    }
}

#[cfg(target_os = "linux")]
inventory::submit!(secretx_core::BackendRegistration {
    name: "keyring",
    factory: |uri: &str| {
        KeyringBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

#[cfg(target_os = "linux")]
inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "keyring",
    factory: |uri: &str| {
        KeyringBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing tests (no OS keychain required) ───────────────────────────

    #[test]
    fn from_uri_ok() {
        let b = KeyringBackend::from_uri("secretx:keyring:my-app/api-key").unwrap();
        assert_eq!(b.service, "my-app");
        assert_eq!(b.account, "api-key");
    }

    #[test]
    fn from_uri_ok_nested_account() {
        // account portion may contain slashes; only the first '/' is the separator.
        let b = KeyringBackend::from_uri("secretx:keyring:svc/user/sub").unwrap();
        assert_eq!(b.service, "svc");
        assert_eq!(b.account, "user/sub");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            KeyringBackend::from_uri("secretx:env:MY_VAR"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_slash() {
        // path has no '/' so account is absent
        assert!(matches!(
            KeyringBackend::from_uri("secretx:keyring:onlyone"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_account() {
        // trailing slash means account is empty
        assert!(matches!(
            KeyringBackend::from_uri("secretx:keyring:svc/"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        // no path component at all
        assert!(matches!(
            KeyringBackend::from_uri("secretx:keyring"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_field_selector_rejected() {
        // Keyring values are opaque strings; ?field= is not supported and must
        // be rejected at construction time.
        let result = KeyringBackend::from_uri("secretx:keyring:my-app/api-key?field=token");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("keyring does not support ?field="),
                    "error must mention the limitation, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    // ── Integration tests (require OS keychain) ───────────────────────────────
    //
    // Gated behind SECRETX_KEYRING_INTEGRATION_TESTS=1.  No daemon required —
    // uses the kernel persistent keyring directly.

    /// Returns true if the kernel keyring is unavailable (e.g. running in a
    /// container that restricts keyrings, or the keyutils subsystem is absent).
    fn is_kernel_keyring_unavailable(e: &SecretError) -> bool {
        matches!(e, SecretError::Unavailable { .. })
    }

    #[tokio::test]
    async fn integration_roundtrip() {
        if std::env::var("SECRETX_KEYRING_INTEGRATION_TESTS").as_deref() != Ok("1") {
            return;
        }

        let svc = "secretx-test";
        let acct = "roundtrip";
        let uri = format!("secretx:keyring:{svc}/{acct}");

        let backend = KeyringBackend::from_uri(&uri).unwrap();

        // Clean up any leftover entry from a previous run.
        if let Ok(entry) = keyring::Entry::new(svc, acct) {
            let _ = entry.delete_credential();
        }

        // Write.
        let put_result = backend
            .put(SecretValue::new(b"test-secret-value".to_vec()))
            .await;
        match put_result {
            Ok(()) => {}
            Err(ref e) if is_kernel_keyring_unavailable(e) => {
                eprintln!("keyring: kernel keyring unavailable, skipping integration test");
                return;
            }
            Err(e) => panic!("put failed: {e}"),
        }

        // Read back.
        let got = backend.get().await.expect("get after put failed");
        assert_eq!(got.as_bytes(), b"test-secret-value");

        // Refresh should also work.
        let refreshed = backend.refresh().await.expect("refresh failed");
        assert_eq!(refreshed.as_bytes(), b"test-secret-value");

        // Clean up.
        if let Ok(entry) = keyring::Entry::new(svc, acct) {
            let _ = entry.delete_credential();
        }

        // After deletion, get should return NotFound.
        let after = backend.get().await;
        assert!(
            matches!(after, Err(SecretError::NotFound)),
            "expected NotFound after delete"
        );
    }
}
