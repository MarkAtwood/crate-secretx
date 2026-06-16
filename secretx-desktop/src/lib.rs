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

use std::sync::Arc;

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};
use zeroize::Zeroizing;

const BACKEND: &str = "desktop";

/// Map a [`keyring::Error`] to the appropriate [`SecretError`] variant.
///
/// - `NoEntry` → `NotFound` (expected on `get`, should not occur on `put`).
/// - `NoStorageAccess` / `PlatformFailure` → `Unavailable` (transient; the
///   inner platform error is forwarded directly).
/// - Everything else → `Backend` (permanent).
fn map_keyring_error(e: keyring::Error) -> SecretError {
    match e {
        keyring::Error::NoEntry => SecretError::NotFound,
        keyring::Error::NoStorageAccess(inner) | keyring::Error::PlatformFailure(inner) => {
            SecretError::Unavailable {
                backend: BACKEND,
                source: inner,
            }
        }
        other => SecretError::Backend {
            backend: BACKEND,
            source: other.into(),
        },
    }
}

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
#[derive(Debug)]
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
        Self::from_parsed_uri(&SecretUri::parse(uri)?)
    }

    /// Construct from a pre-parsed [`SecretUri`].
    pub fn from_parsed_uri(parsed: &SecretUri) -> Result<Self, SecretError> {
        if parsed.backend() != BACKEND {
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
        // Reject unknown query parameters to catch typos early.
        // The desktop backend does not support any query parameters.
        for key in parsed.param_keys() {
            if key == "field" {
                return Err(SecretError::InvalidUri(
                    "desktop does not support ?field= (keychain values are opaque strings, not \
                     JSON objects); remove ?field= or use a backend that supports JSON field \
                     extraction (e.g. aws-sm)"
                        .into(),
                ));
            }
            return Err(SecretError::InvalidUri(format!(
                "desktop URI: unknown query parameter `{key}`"
            )));
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
            let entry = keyring::Entry::new(&service, &account).map_err(map_keyring_error)?;
            // ZEROIZATION GAP: keyring crate returns plain String from the OS
            // keychain.  `pw.into_bytes()` is zero-copy (reuses the same heap
            // allocation), so the buffer enters Zeroizing immediately.  The
            // keychain's own internal copy is outside our control.
            entry
                .get_password()
                .map(|pw| SecretValue::new(pw.into_bytes()))
                .map_err(map_keyring_error)
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
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
        // Wrap in Zeroizing so the plaintext copy is zeroed when the closure returns.
        let s = Zeroizing::new(
            std::str::from_utf8(value.as_bytes())
                .map_err(|_| {
                    SecretError::DecodeFailed(
                        "desktop keychain backend requires UTF-8 secret values".into(),
                    )
                })?
                .to_owned(),
        );
        let service = self.service.clone();
        let account = self.account.clone();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(&service, &account).map_err(map_keyring_error)?;
            entry.set_password(&s).map_err(map_keyring_error)
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        })?
    }
}

// Only register on desktop platforms where the keyring crate has a real
// backend (macOS Keychain, Windows Credential Manager, Linux Secret Service).
// On other targets (iOS, Android, embedded) keyring falls back to a mock store.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
inventory::submit!(secretx_core::BackendRegistration::new(
    "desktop",
    |uri: &secretx_core::SecretUri| {
        DesktopKeyringBackend::from_parsed_uri(uri)
            .map(|b| Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
inventory::submit!(secretx_core::WritableBackendRegistration::new(
    "desktop",
    |uri: &secretx_core::SecretUri| {
        DesktopKeyringBackend::from_parsed_uri(uri)
            .map(|b| Arc::new(b) as Arc<dyn secretx_core::WritableSecretStore>)
    },
));

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

    #[test]
    fn from_uri_unknown_query_param_rejected() {
        let result = DesktopKeyringBackend::from_uri("secretx:desktop:my-app/api-key?foo=bar");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("unknown query parameter `foo`"),
                    "error must name the unknown parameter, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }
}
