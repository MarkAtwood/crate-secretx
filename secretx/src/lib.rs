//! Backend-agnostic secrets retrieval for Rust.
//!
//! Re-exports [`secretx_core`] types and provides [`from_uri`] for URI-driven backend selection.
//!
//! # Usage
//!
//! ```toml
//! [dependencies]
//! secretx = { version = "0.1", features = ["aws-sm", "file"] }
//! ```
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! let store = secretx::from_uri("secretx://file//etc/secrets/key")?;
//! let value = store.get("key").await?;
//! # Ok(())
//! # }
//! ```

pub use secretx_core::{SecretError, SecretStore, SecretValue, SigningAlgorithm, SigningBackend};

use std::sync::Arc;

/// Parse a `secretx://` URI and return the appropriate backend.
///
/// Does not make any network call or file read — construction only.
/// Returns [`SecretError::InvalidUri`] for unknown or disabled backends.
pub fn from_uri(_uri: &str) -> Result<Arc<dyn SecretStore>, SecretError> {
    // TODO: dispatch to backend crates based on URI scheme
    Err(SecretError::InvalidUri("no backends compiled in yet".into()))
}
