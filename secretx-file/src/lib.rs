//! Filesystem backend for secretx.
//!
//! Absolute paths use a double slash after `file`:
//! `secretx://file//etc/secrets/key` → reads `/etc/secrets/key`.
//! Relative paths: `secretx://file/relative/path` → reads `relative/path`.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_file::FileBackend;
//! use secretx_core::SecretStore;
//!
//! let store = FileBackend::from_uri("secretx://file//etc/secrets/api.key")?;
//! let value = store.get("ignored").await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use std::io::Write;
use std::path::PathBuf;

/// Backend that reads a secret from a single file.
///
/// `get` and `refresh` read the entire file. `put` overwrites the file;
/// on Unix the file is created with mode `0600` if it does not exist.
pub struct FileBackend {
    path: PathBuf,
}

impl FileBackend {
    /// Construct from a `secretx://file/<path>` URI.
    ///
    /// Does not read the file — construction only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "file" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `file`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "file URI requires a path: secretx://file/relative or secretx://file//absolute".into(),
            ));
        }
        Ok(Self {
            path: PathBuf::from(&parsed.path),
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for FileBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        std::fs::read(&self.path)
            .map(SecretValue::new)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => SecretError::NotFound,
                _ => SecretError::Backend {
                    backend: "file",
                    source: e.into(),
                },
            })
    }

    /// Overwrite the file with `value`. The parent directory must exist.
    /// On Unix the file is created or truncated with mode `0600`.
    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        write_secret_file(&self.path, value.as_bytes()).map_err(|e| SecretError::Backend {
            backend: "file",
            source: e.into(),
        })
    }

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(data)
}

#[cfg(not(unix))]
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_absolute() {
        let b = FileBackend::from_uri("secretx://file//etc/passwd").unwrap();
        assert_eq!(b.path, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn from_uri_relative() {
        let b = FileBackend::from_uri("secretx://file/relative/path").unwrap();
        assert_eq!(b.path, PathBuf::from("relative/path"));
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            FileBackend::from_uri("secretx://env/X"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_path() {
        assert!(matches!(
            FileBackend::from_uri("secretx://file"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[tokio::test]
    async fn get_missing_file() {
        let b = FileBackend::from_uri(
            "secretx://file//tmp/secretx_test_surely_missing_xyzzy123",
        )
        .unwrap();
        assert!(matches!(b.get("ignored").await, Err(SecretError::NotFound)));
    }

    #[tokio::test]
    async fn put_and_get_roundtrip() {
        let path = std::env::temp_dir().join("secretx_file_test_roundtrip.bin");
        // Absolute path: prepend an extra / to get double-slash encoding.
        let uri = format!("secretx://file/{}", path.display());
        let b = FileBackend::from_uri(&uri).unwrap();

        b.put("ignored", SecretValue::new(b"hello secret".to_vec()))
            .await
            .unwrap();
        let v = b.get("ignored").await.unwrap();
        assert_eq!(v.as_bytes(), b"hello secret");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn refresh_sees_external_write() {
        let path = std::env::temp_dir().join("secretx_file_test_refresh.bin");
        std::fs::write(&path, b"initial").unwrap();

        let uri = format!("secretx://file/{}", path.display());
        let b = FileBackend::from_uri(&uri).unwrap();

        let v1 = b.get("ignored").await.unwrap();
        assert_eq!(v1.as_bytes(), b"initial");

        std::fs::write(&path, b"updated").unwrap();

        let v2 = b.refresh("ignored").await.unwrap();
        assert_eq!(v2.as_bytes(), b"updated");

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn put_creates_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join("secretx_file_test_mode.bin");
        let uri = format!("secretx://file/{}", path.display());
        let b = FileBackend::from_uri(&uri).unwrap();

        b.put("ignored", SecretValue::new(b"secret".to_vec()))
            .await
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let _ = std::fs::remove_file(&path);
    }
}
