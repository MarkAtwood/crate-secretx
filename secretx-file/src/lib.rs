//! Filesystem backend for secretx.
//!
//! Absolute paths use a leading `/` in the path component:
//! `secretx:file:/etc/secrets/key` → reads `/etc/secrets/key`.
//! Relative paths: `secretx:file:relative/path` → reads `relative/path`.
//!
//! # Security
//!
//! URIs for this backend must come from trusted sources (compiled-in
//! configuration, administrator-controlled environment variables). URIs from
//! end-user input are not safe: an attacker who controls a URI string could
//! read any file the process can access. Paths containing `..` components are
//! rejected at construction time as a defense-in-depth measure, but that
//! alone is not sufficient if the path root itself is attacker-controlled.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_file::FileBackend;
//! use secretx_core::{SecretStore, SecretValue, WritableSecretStore};
//!
//! // Read
//! let store = FileBackend::from_uri("secretx:file:/etc/secrets/api.key")?;
//! let value = store.get().await?;
//!
//! // Write (requires WritableSecretStore in scope)
//! store.put(SecretValue::new(b"new-secret".to_vec())).await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};
use std::io::Write;
use std::path::{Component, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Backend that reads a secret from a single file.
///
/// `get` and `refresh` read the entire file. `put` overwrites the file;
/// on Unix the file is created with mode `0600` if it does not exist.
pub struct FileBackend {
    path: PathBuf,
}

impl FileBackend {
    /// Construct from a `secretx:file:<path>` URI.
    ///
    /// Does not read the file — construction only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "file" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `file`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "file URI requires a path: secretx:file:relative or secretx:file:/absolute".into(),
            ));
        }
        let path = PathBuf::from(parsed.path());
        // Reject .. components as a defense-in-depth measure against accidental
        // path traversal. Legitimate secret paths never need to go up the tree.
        if path.components().any(|c| c == Component::ParentDir) {
            return Err(SecretError::InvalidUri(
                "file URI path must not contain '..' components".into(),
            ));
        }
        Ok(Self { path })
    }
}

#[async_trait::async_trait]
impl SecretStore for FileBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::read(&path)
                .map(SecretValue::new)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => SecretError::NotFound,
                    _ => SecretError::Backend {
                        backend: "file",
                        source: e.into(),
                    },
                })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "file",
            source: e.into(),
        })?
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for FileBackend {
    /// Overwrite the file with `value`. The parent directory must exist.
    ///
    /// On Unix the file is created or truncated with mode `0600` (owner
    /// read/write only). On non-Unix platforms (e.g. Windows) the file is
    /// written with default permissions, which may be world-readable depending
    /// on the system configuration. If you need restrictive ACLs on Windows,
    /// set them separately after construction.
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let path = self.path.clone();
        // into_bytes() consumes value and returns Zeroizing<Vec<u8>>, keeping
        // secret bytes in a Zeroizing allocation until the closure drops it.
        let bytes = value.into_bytes();
        tokio::task::spawn_blocking(move || {
            write_secret_file(&path, &bytes).map_err(|e| SecretError::Backend {
                backend: "file",
                source: e.into(),
            })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "file",
            source: e.into(),
        })?
    }
}

/// Counter used to make temp file names unique across concurrent `put()` calls
/// on the same path within a single process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` atomically using a temp-file-then-rename pattern.
///
/// Directly writing with `O_TRUNC` is not atomic: if the process is killed or
/// the disk fills up after truncation but before `write_all` completes, `path`
/// is left empty — the original secret is irrecoverably lost.
///
/// Instead, we write to a hidden temp file **in the same directory** as `path`
/// (guaranteeing they are on the same filesystem), then call `rename()`.
/// POSIX `rename()` is atomic: the old `path` contents are visible until the
/// instant the rename commits, and the new contents appear all-at-once.
///
/// If any step fails the temp file is removed (best-effort) and `path` is
/// left unchanged.
#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        counter
    );
    let tmp_path = parent.join(&tmp_name);

    // Write secret bytes to the temp file.  Use create_new so the open fails
    // atomically if the temp path somehow already exists — guaranteeing that
    // 0o600 is always the file's creation mode, not inherited from a stale file.
    let write_result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .and_then(|mut f| f.write_all(data));

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Atomic rename: the target is replaced in a single syscall.
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    // Same temp-then-rename pattern for atomicity on non-Unix platforms.
    // File permissions are not set here (Windows uses ACLs; configure them
    // separately if restrictive access is required).
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        counter
    );
    let tmp_path = parent.join(&tmp_name);

    if let Err(e) = std::fs::write(&tmp_path, data) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    Ok(())
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "file",
    factory: |uri: &str| {
        FileBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "file",
    factory: |uri: &str| {
        FileBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_absolute() {
        let b = FileBackend::from_uri("secretx:file:/etc/passwd").unwrap();
        assert_eq!(b.path, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn from_uri_relative() {
        let b = FileBackend::from_uri("secretx:file:relative/path").unwrap();
        assert_eq!(b.path, PathBuf::from("relative/path"));
    }

    #[test]
    fn from_uri_rejects_dotdot_relative() {
        // ../etc/passwd — must not be accepted
        assert!(matches!(
            FileBackend::from_uri("secretx:file:../etc/passwd"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_rejects_dotdot_embedded() {
        // config/../../etc/passwd — traversal in the middle of a path
        assert!(matches!(
            FileBackend::from_uri("secretx:file:config/../../etc/passwd"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_rejects_dotdot_absolute() {
        // //etc/secrets/../passwd — traversal in absolute path
        assert!(matches!(
            FileBackend::from_uri("secretx:file:/etc/secrets/../passwd"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            FileBackend::from_uri("secretx:env:X"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_path() {
        assert!(matches!(
            FileBackend::from_uri("secretx:file"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[tokio::test]
    async fn get_missing_file() {
        let b = FileBackend::from_uri("secretx:file:/tmp/secretx_test_surely_missing_xyzzy123")
            .unwrap();
        assert!(matches!(b.get().await, Err(SecretError::NotFound)));
    }

    #[tokio::test]
    async fn put_and_get_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "secretx_file_test_roundtrip_{}.bin",
            std::process::id()
        ));
        // Absolute path: path.display() starts with '/' on Unix.
        let uri = format!("secretx:file:{}", path.display());
        let b = FileBackend::from_uri(&uri).unwrap();

        b.put(SecretValue::new(b"hello secret".to_vec()))
            .await
            .unwrap();
        let v = b.get().await.unwrap();
        assert_eq!(v.as_bytes(), b"hello secret");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn refresh_sees_external_write() {
        let path = std::env::temp_dir().join(format!(
            "secretx_file_test_refresh_{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, b"initial").unwrap();

        let uri = format!("secretx:file:{}", path.display());
        let b = FileBackend::from_uri(&uri).unwrap();

        let v1 = b.get().await.unwrap();
        assert_eq!(v1.as_bytes(), b"initial");

        std::fs::write(&path, b"updated").unwrap();

        let v2 = b.refresh().await.unwrap();
        assert_eq!(v2.as_bytes(), b"updated");

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn put_creates_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("secretx_file_test_mode_{}.bin", std::process::id()));
        let uri = format!("secretx:file:{}", path.display());
        let b = FileBackend::from_uri(&uri).unwrap();

        b.put(SecretValue::new(b"secret".to_vec())).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let _ = std::fs::remove_file(&path);
    }
}
