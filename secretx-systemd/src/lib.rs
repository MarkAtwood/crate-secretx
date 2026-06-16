//! systemd credentials backend for secretx.
//!
//! Reads secrets injected by systemd via `LoadCredential=` or
//! `LoadCredentialEncrypted=` unit-file directives. At service start, systemd
//! decrypts the credential (using TPM2 or a host key) and writes the plaintext
//! into a per-service tmpfs only visible to that unit, available at
//! `$CREDENTIALS_DIRECTORY`.
//!
//! This backend reads `$CREDENTIALS_DIRECTORY/<name>` as raw bytes. No daemon
//! is required at runtime — decryption is done by systemd before exec.
//! Requires systemd v250+ (released January 2022).
//!
//! # URI
//!
//! ```text
//! secretx:systemd:<credential-name>
//! ```
//!
//! # Example unit file
//!
//! ```text
//! [Service]
//! LoadCredentialEncrypted=db-password:/etc/credentials/db-password.cred
//! ```
//!
//! Encrypt a credential with:
//!
//! ```sh
//! systemd-creds encrypt --with-key=tpm2 secret.txt /etc/credentials/db-password.cred
//! ```
//!
//! Then read it:
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_systemd::SystemdCredsBackend;
//! use secretx_core::SecretStore;
//!
//! let store = SystemdCredsBackend::from_uri("secretx:systemd:db-password")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use zeroize::Zeroizing;

/// Read a file into a [`Zeroizing<Vec<u8>>`], pre-sized from metadata to
/// avoid reallocation-induced leaks of partial secret bytes.
fn read_file_zeroizing(path: &std::path::Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let mut buf = Zeroizing::new(Vec::with_capacity(len));
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Validate a systemd credential name per systemd's `credential_name_valid()`.
///
/// Mirrors `filename_is_valid() && fdname_is_valid()` from systemd source:
/// - Must not be empty
/// - Must not be `.` or `..`
/// - Must not contain `/` or `:`
/// - Must not contain bytes < 0x20 (control chars) or >= 0x7F (DEL / non-ASCII)
/// - Must be at most 255 bytes (`NAME_MAX`)
///
/// Reference: systemd `src/shared/creds-util.c`, `src/basic/path-util.c`,
/// `src/basic/fd-util.c`.
fn credential_name_valid(name: &str) -> Result<(), SecretError> {
    if name.is_empty() {
        return Err(SecretError::InvalidUri(
            "systemd URI requires a credential name: `secretx:systemd:<name>`".into(),
        ));
    }
    if name == "." || name == ".." {
        return Err(SecretError::InvalidUri(format!(
            "systemd credential name `{name}` is not allowed (`.` and `..` are reserved)"
        )));
    }
    if name.len() > 255 {
        return Err(SecretError::InvalidUri(format!(
            "systemd credential name is {} bytes; maximum is 255 (NAME_MAX)",
            name.len()
        )));
    }
    for b in name.bytes() {
        if b == b'/' {
            return Err(SecretError::InvalidUri(
                "systemd credential name must not contain `/`".into(),
            ));
        }
        if b == b':' {
            return Err(SecretError::InvalidUri(
                "systemd credential name must not contain `:`".into(),
            ));
        }
        if b < 0x20 || b >= 0x7F {
            return Err(SecretError::InvalidUri(format!(
                "systemd credential name contains invalid byte 0x{b:02X}; \
                 only printable ASCII (0x20–0x7E) is allowed"
            )));
        }
    }
    Ok(())
}

/// Backend that reads systemd service credentials from `$CREDENTIALS_DIRECTORY`.
///
/// ```text
/// secretx:systemd:<credential-name>
/// ```
///
/// `get` and `refresh` read `$CREDENTIALS_DIRECTORY/<name>` as raw bytes.
/// Read-only — credentials are injected by the service manager, not written
/// by the service process itself.
#[derive(Debug)]
pub struct SystemdCredsBackend {
    name: String,
}

impl SystemdCredsBackend {
    /// Construct from a `secretx:systemd:<credential-name>` URI.
    ///
    /// Construction only — does not read `$CREDENTIALS_DIRECTORY`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidUri`] if the backend is not `systemd`
    /// or the credential name fails [`credential_name_valid`].
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "systemd" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `systemd`, got `{}`",
                parsed.backend()
            )));
        }
        let name = parsed.path();
        credential_name_valid(name)?;
        Ok(Self {
            name: name.to_string(),
        })
    }

    fn credential_path(&self) -> Result<PathBuf, SecretError> {
        let dir = std::env::var("CREDENTIALS_DIRECTORY").map_err(|_| SecretError::Unavailable {
            backend: "systemd",
            source: "$CREDENTIALS_DIRECTORY is not set — service must be started by systemd \
                         with LoadCredential= or LoadCredentialEncrypted= configured"
                .into(),
        })?;
        Ok(PathBuf::from(dir).join(&self.name))
    }
}

#[async_trait::async_trait]
impl SecretStore for SystemdCredsBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let path = self.credential_path()?;
        tokio::task::spawn_blocking(move || {
            read_file_zeroizing(&path)
                .map(SecretValue::from_zeroizing)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => SecretError::NotFound,
                    _ => SecretError::Backend {
                        backend: "systemd",
                        source: e.into(),
                    },
                })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "systemd",
            source: e.into(),
        })?
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

inventory::submit!(secretx_core::BackendRegistration::new(
    "systemd",
    |uri: &str| {
        SystemdCredsBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
));

#[cfg(test)]
mod tests {
    use super::*;

    // Serialize env-var mutations across parallel test threads.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── URI parsing ───────────────────────────────────────────────────────────

    #[test]
    fn from_uri_ok() {
        let b = SystemdCredsBackend::from_uri("secretx:systemd:db-password").unwrap();
        assert_eq!(b.name, "db-password");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:env:MY_VAR"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_name() {
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:systemd"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_slash_rejected() {
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:systemd:a/b"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_path_traversal_rejected() {
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:systemd:../etc/passwd"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_dot_rejected() {
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:systemd:."),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_dotdot_rejected() {
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:systemd:.."),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_colon_rejected() {
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:systemd:foo:bar"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_control_char_rejected() {
        // %01 decodes to 0x01 (control character)
        assert!(matches!(
            SystemdCredsBackend::from_uri("secretx:systemd:%01x"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_too_long_rejected() {
        let long_name = "a".repeat(256);
        let uri = format!("secretx:systemd:{long_name}");
        assert!(matches!(
            SystemdCredsBackend::from_uri(&uri),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_max_length_ok() {
        let name = "a".repeat(255);
        let uri = format!("secretx:systemd:{name}");
        SystemdCredsBackend::from_uri(&uri).unwrap();
    }

    // ── Runtime behaviour ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_unavailable_without_credentials_directory() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("CREDENTIALS_DIRECTORY").ok();
        // SAFETY: ENV_LOCK serializes all env-var mutations in this test module.
        unsafe { std::env::remove_var("CREDENTIALS_DIRECTORY") };

        let result = SystemdCredsBackend::from_uri("secretx:systemd:db-password")
            .unwrap()
            .get()
            .await;

        if let Some(v) = saved {
            // SAFETY: restoring previously-set variable under ENV_LOCK.
            unsafe { std::env::set_var("CREDENTIALS_DIRECTORY", v) };
        }

        assert!(
            matches!(result, Err(SecretError::Unavailable { .. })),
            "expected Unavailable without CREDENTIALS_DIRECTORY, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn get_returns_not_found_for_missing_credential() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations in this test module.
        unsafe { std::env::set_var("CREDENTIALS_DIRECTORY", dir.path()) };

        let result = SystemdCredsBackend::from_uri("secretx:systemd:nonexistent")
            .unwrap()
            .get()
            .await;

        // SAFETY: cleanup under ENV_LOCK.
        unsafe { std::env::remove_var("CREDENTIALS_DIRECTORY") };

        assert!(
            matches!(result, Err(SecretError::NotFound)),
            "expected NotFound for missing credential file"
        );
    }

    #[tokio::test]
    async fn get_returns_secret_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("my-secret"), b"hunter2").unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations in this test module.
        unsafe { std::env::set_var("CREDENTIALS_DIRECTORY", dir.path()) };

        let val = SystemdCredsBackend::from_uri("secretx:systemd:my-secret")
            .unwrap()
            .get()
            .await
            .unwrap();

        // SAFETY: cleanup under ENV_LOCK.
        unsafe { std::env::remove_var("CREDENTIALS_DIRECTORY") };

        assert_eq!(val.as_bytes(), b"hunter2");
    }

    #[tokio::test]
    async fn refresh_matches_get() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("my-secret"), b"s3cr3t").unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations in this test module.
        unsafe { std::env::set_var("CREDENTIALS_DIRECTORY", dir.path()) };

        let b = SystemdCredsBackend::from_uri("secretx:systemd:my-secret").unwrap();
        let v1 = b.get().await.unwrap();
        let v2 = b.refresh().await.unwrap();

        // SAFETY: cleanup under ENV_LOCK.
        unsafe { std::env::remove_var("CREDENTIALS_DIRECTORY") };

        assert_eq!(v1.as_bytes(), v2.as_bytes());
    }
}
