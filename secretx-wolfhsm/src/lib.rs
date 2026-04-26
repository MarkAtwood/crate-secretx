//! wolfHSM secure element backend for secretx.
//!
//! # Integration test status
//!
//! This backend is a **stub**. All operations return [`SecretError::Unavailable`]
//! until the wolfHSM native library (`libwolfhsm`) is linked. Provide a
//! `build.rs` that links the library, or set `WOLFHSM_LIB` to the path of
//! `libwolfhsm.a` / `libwolfhsm.so`. Real hardware testing requires a
//! wolfHSM device or the wolfHSM simulator.
//! **Not yet integration-tested (native library not available in this environment).**
//!
//! Implements both [`SecretStore`] (NVM data objects) and [`SigningBackend`]
//! (private keys resident on the wolfHSM device) over the wolfHSM C library.
//!
//! # URI format
//!
//! ```text
//! secretx:wolfhsm:<label>
//! ```
//!
//! Where `<label>` is the object label stored in wolfHSM NVM.
//!
//! # Requirements
//!
//! This crate requires the wolfHSM native library. Link it by either:
//!
//! - Setting `WOLFHSM_LIB` to the path to `libwolfhsm.a` / `libwolfhsm.so`
//! - Providing a `build.rs` that links the library
//!
//! Until the native library is linked, all operations return
//! [`SecretError::Unavailable`].

use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
};

// ── Backend ───────────────────────────────────────────────────────────────────

/// Backend that accesses a wolfHSM secure element over the wolfHSM C API.
///
/// Construct with [`WolfHsmBackend::from_uri`].
pub struct WolfHsmBackend {
    label: String,
}

impl WolfHsmBackend {
    /// Construct from a `secretx:wolfhsm:<label>` URI.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "wolfhsm" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `wolfhsm`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "wolfhsm URI requires a label: secretx:wolfhsm:<label>".into(),
            ));
        }
        Ok(Self {
            label: parsed.path().to_owned(),
        })
    }
}

// ── SecretStore ───────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SecretStore for WolfHsmBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        Err(unavailable(&self.label))
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        Err(unavailable(&self.label))
    }
}

// ── SigningBackend ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SigningBackend for WolfHsmBackend {
    async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SecretError> {
        Err(unavailable(&self.label))
    }

    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        Err(unavailable(&self.label))
    }

    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        // The native library is not linked; return Unavailable consistent with all other methods.
        Err(unavailable(&self.label))
    }
}

fn unavailable(label: &str) -> SecretError {
    SecretError::Unavailable {
        backend: "wolfhsm",
        source: format!(
            "wolfHSM native library not linked (label: {label}); \
             provide a build.rs that links libwolfhsm"
        )
        .into(),
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "wolfhsm",
    factory: |uri: &str| {
        WolfHsmBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::SigningBackendRegistration {
    name: "wolfhsm",
    factory: |uri: &str| {
        WolfHsmBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SigningBackend>)
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_ok() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:my-key").unwrap();
        assert_eq!(b.label, "my-key");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:file:foo"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_label() {
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:wolfhsm"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[tokio::test]
    async fn get_returns_unavailable() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:test-key").unwrap();
        assert!(matches!(
            b.get().await,
            Err(SecretError::Unavailable {
                backend: "wolfhsm",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn sign_returns_unavailable() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:test-key").unwrap();
        assert!(matches!(
            b.sign(b"data").await,
            Err(SecretError::Unavailable {
                backend: "wolfhsm",
                ..
            })
        ));
    }

    #[test]
    fn algorithm_returns_unavailable() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:test-key").unwrap();
        assert!(matches!(
            b.algorithm(),
            Err(SecretError::Unavailable {
                backend: "wolfhsm",
                ..
            })
        ));
    }
}
