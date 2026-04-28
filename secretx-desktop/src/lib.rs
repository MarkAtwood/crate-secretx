//! Desktop keychain backend for secretx.
//!
//! Reads and writes secrets via the platform desktop keychain:
//! - **macOS** — Keychain Services
//! - **Windows** — Windows Credential Manager
//! - **Linux** — Secret Service protocol (GNOME Keyring, KWallet); requires a
//!   running daemon and an active D-Bus session.
//!
//! For Linux headless daemons that need keyring storage without a desktop
//! session, use `secretx-keyring` (kernel persistent keyring, no daemon) or
//! `secretx-systemd` (TPM2-encrypted tmpfs, no daemon).
//!
//! URI: `secretx:desktop:<service>/<account>`
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_desktop::DesktopKeyringBackend;
//! use secretx_core::{SecretStore, SecretValue, WritableSecretStore};
//!
//! // Read
//! let store = DesktopKeyringBackend::from_uri("secretx:desktop:my-app/api-key")?;
//! let value = store.get().await?;
//!
//! // Write (requires WritableSecretStore in scope)
//! store.put(SecretValue::new(b"new-secret".to_vec())).await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};

/// Backend that reads and writes secrets via the platform desktop keychain.
///
/// ```text
/// secretx:desktop:<service>/<account>
/// ```
///
/// `get` and `refresh` retrieve the stored credential.
/// `put` writes a new credential; the value must be valid UTF-8.
///
/// On Linux this requires a running Secret Service daemon (GNOME Keyring or
/// KWallet). Use `secretx-keyring` or `secretx-systemd` for headless operation.
pub struct DesktopKeyringBackend {
    service: String,
    account: String,
}

impl DesktopKeyringBackend {
    /// Construct from a `secretx:desktop:<service>/<account>` URI.
    ///
    /// Does not open the keychain — construction only.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidUri`] if the backend is not `desktop`,
    /// the path is empty, or the path contains no `/` separator (both
    /// `service` and `account` must be non-empty).
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "desktop" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `desktop`, got `{}`",
                parsed.backend()
            )));
        }
        // path must be "<service>/<account>" — split on the first '/'.
        // account may itself contain slashes (e.g. "svc/user/sub").
        let (service, account) = parsed.path().split_once('/').ok_or_else(|| {
            SecretError::InvalidUri(
                "desktop URI requires `secretx:desktop:<service>/<account>`".into(),
            )
        })?;
        if service.is_empty() {
            return Err(SecretError::InvalidUri(
                "desktop URI: service name must not be empty".into(),
            ));
        }
        if account.is_empty() {
            return Err(SecretError::InvalidUri(
                "desktop URI: account name must not be empty".into(),
            ));
        }
        if parsed.param("field").is_some() {
            return Err(SecretError::InvalidUri(
                "desktop does not support ?field= (keychain values are opaque strings, not JSON \
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
impl SecretStore for DesktopKeyringBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let service = self.service.clone();
        let account = self.account.clone();
        // Keychain calls are synchronous and can block (D-Bus round-trip on Linux,
        // Security.framework on macOS). Run on a blocking thread.
        tokio::task::spawn_blocking(move || {
            let entry =
                keyring::Entry::new(&service, &account).map_err(|e| SecretError::Backend {
                    backend: "desktop",
                    source: e.into(),
                })?;
            match entry.get_password() {
                Ok(pw) => Ok(SecretValue::new(pw.into_bytes())),
                Err(keyring::Error::NoEntry) => Err(SecretError::NotFound),
                Err(keyring::Error::NoStorageAccess(e)) => Err(SecretError::Unavailable {
                    backend: "desktop",
                    source: e,
                }),
                Err(e) => Err(SecretError::Backend {
                    backend: "desktop",
                    source: e.into(),
                }),
            }
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "desktop",
            source: e.into(),
        })?
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for DesktopKeyringBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let s = std::str::from_utf8(value.as_bytes())
            .map_err(|_| {
                SecretError::DecodeFailed(
                    "desktop keychain backend requires UTF-8 secret values".into(),
                )
            })?
            .to_owned();
        let service = self.service.clone();
        let account = self.account.clone();
        tokio::task::spawn_blocking(move || {
            let entry =
                keyring::Entry::new(&service, &account).map_err(|e| SecretError::Backend {
                    backend: "desktop",
                    source: e.into(),
                })?;
            entry.set_password(&s).map_err(|e| match e {
                keyring::Error::NoStorageAccess(inner) => SecretError::Unavailable {
                    backend: "desktop",
                    source: inner,
                },
                other => SecretError::Backend {
                    backend: "desktop",
                    source: other.into(),
                },
            })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "desktop",
            source: e.into(),
        })?
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "desktop",
    factory: |uri: &str| {
        DesktopKeyringBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "desktop",
    factory: |uri: &str| {
        DesktopKeyringBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_ok() {
        let b = DesktopKeyringBackend::from_uri("secretx:desktop:my-app/api-key").unwrap();
        assert_eq!(b.service, "my-app");
        assert_eq!(b.account, "api-key");
    }

    #[test]
    fn from_uri_ok_nested_account() {
        let b = DesktopKeyringBackend::from_uri("secretx:desktop:svc/user/sub").unwrap();
        assert_eq!(b.service, "svc");
        assert_eq!(b.account, "user/sub");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            DesktopKeyringBackend::from_uri("secretx:env:MY_VAR"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_slash() {
        assert!(matches!(
            DesktopKeyringBackend::from_uri("secretx:desktop:onlyone"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_service() {
        assert!(matches!(
            DesktopKeyringBackend::from_uri("secretx:desktop:/account"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_account() {
        assert!(matches!(
            DesktopKeyringBackend::from_uri("secretx:desktop:svc/"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        assert!(matches!(
            DesktopKeyringBackend::from_uri("secretx:desktop"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_field_selector_rejected() {
        let result = DesktopKeyringBackend::from_uri("secretx:desktop:my-app/api-key?field=token");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("desktop does not support ?field="),
                    "error must mention the limitation, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }
}
