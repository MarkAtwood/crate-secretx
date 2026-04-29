//! Backend-agnostic secrets retrieval for Rust.
//!
//! Re-exports [`secretx_core`] types and provides [`from_uri`] for URI-driven
//! backend selection.
//!
//! # Usage
//!
//! ```toml
//! [dependencies]
//! secretx = { version = "0.3", features = ["aws-sm", "file"] }
//! ```
//!
//! ## Read a secret
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! let store = secretx::from_uri("secretx:file:/etc/secrets/key")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Read and write a secret
//!
//! Use [`from_uri_writable`] for backends that support writes (`file`, `aws-sm`, `aws-ssm`,
//! `azure-kv`, `doppler`, `gcp-sm`, `hashicorp-vault`, `keyring`, `pkcs11`).
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx::{WritableSecretStore, SecretValue};
//!
//! let store = secretx::from_uri_writable("secretx:file:/etc/secrets/key")?;
//! store.put(SecretValue::new(b"new-value".to_vec())).await?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "cache")]
pub use secretx_cache::CachingStore;
#[cfg(feature = "blocking")]
pub use secretx_core::get_blocking;
pub use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
    WritableSecretStore,
};

// Force the linker to include each backend crate so that its inventory::submit!
// registrations are emitted. Without an explicit symbol reference the linker
// may exclude the rlib entirely, leaving the registry empty.
#[cfg(feature = "aws-kms")]
use secretx_aws_kms as _;
#[cfg(feature = "aws-sm")]
use secretx_aws_sm as _;
#[cfg(feature = "aws-ssm")]
use secretx_aws_ssm as _;
#[cfg(feature = "azure-kv")]
use secretx_azure_kv as _;
#[cfg(feature = "bitwarden")]
use secretx_bitwarden as _;
#[cfg(feature = "desktop")]
use secretx_desktop as _;
#[cfg(feature = "doppler")]
use secretx_doppler as _;
#[cfg(feature = "env")]
use secretx_env as _;
#[cfg(feature = "file")]
use secretx_file as _;
#[cfg(feature = "gcp-sm")]
use secretx_gcp_sm as _;
#[cfg(feature = "hashicorp-vault")]
use secretx_hashicorp_vault as _;
#[cfg(feature = "k8s")]
use secretx_k8s as _;
#[cfg(feature = "keyring")]
use secretx_keyring as _;
#[cfg(feature = "local-signing")]
use secretx_local_signing as _;
#[cfg(feature = "pkcs11")]
use secretx_pkcs11 as _;
#[cfg(feature = "systemd")]
use secretx_systemd as _;
#[cfg(feature = "wolfhsm")]
use secretx_wolfhsm as _;

use std::sync::Arc;

/// Parse a `secretx:` URI and return the appropriate backend.
///
/// Does not make any network call or file read — construction only.
/// Returns [`SecretError::InvalidUri`] for unknown or disabled backends.
///
/// Backend selection is driven by inventory registration in each backend crate —
/// no `#[cfg(feature)]` guards appear in this function.
pub fn from_uri(uri: &str) -> Result<Arc<dyn SecretStore>, SecretError> {
    let parsed = SecretUri::parse(uri)?;
    let backend = parsed.backend();
    for reg in inventory::iter::<secretx_core::BackendRegistration>() {
        if reg.name == backend {
            return (reg.factory)(uri);
        }
    }
    for reg in inventory::iter::<secretx_core::SigningBackendRegistration>() {
        if reg.name == backend {
            return Err(SecretError::InvalidUri(format!(
                "{backend} is a signing-only backend; use secretx::from_signing_uri instead"
            )));
        }
    }
    Err(SecretError::InvalidUri(format!(
        "unknown or disabled backend `{backend}` — enable the corresponding feature flag"
    )))
}

/// Parse a `secretx:` URI and return a writable backend.
///
/// Like [`from_uri`], this is construction-only — no network call or file read.
/// Returns [`SecretError::InvalidUri`] for backends that are read-only (`env`,
/// `bitwarden`, `wolfhsm`), signing-only (`aws-kms`, `local-signing`), unknown,
/// or whose feature flag is not enabled.
///
/// # Trait upcasting and MSRV
///
/// The return type is `Arc<dyn WritableSecretStore>`. On Rust 1.86 and later,
/// this coerces automatically to `Arc<dyn SecretStore>` via trait upcasting.
/// On Rust 1.75–1.85 (the current MSRV), the coercion does not exist. If you
/// need both a writable handle and a read-only `Arc<dyn SecretStore>` for the
/// same backend, call [`from_uri`] separately with the same URI string.
///
/// Calling `get` and `refresh` directly on the `Arc<dyn WritableSecretStore>`
/// works on all supported toolchains — only the `Arc<dyn SecretStore>` coercion
/// requires 1.86.
pub fn from_uri_writable(uri: &str) -> Result<Arc<dyn WritableSecretStore>, SecretError> {
    let parsed = SecretUri::parse(uri)?;
    let backend = parsed.backend();
    for reg in inventory::iter::<secretx_core::WritableBackendRegistration>() {
        if reg.name == backend {
            return (reg.factory)(uri);
        }
    }
    for reg in inventory::iter::<secretx_core::BackendRegistration>() {
        if reg.name == backend {
            return Err(SecretError::InvalidUri(format!(
                "{backend} backend is read-only; use secretx::from_uri for read access"
            )));
        }
    }
    for reg in inventory::iter::<secretx_core::SigningBackendRegistration>() {
        if reg.name == backend {
            return Err(SecretError::InvalidUri(format!(
                "{backend} is a signing-only backend; use secretx::from_signing_uri instead"
            )));
        }
    }
    Err(SecretError::InvalidUri(format!(
        "unknown or disabled backend `{backend}` — enable the corresponding feature flag"
    )))
}

/// Parse a `secretx:` URI and return a signing backend.
///
/// Use this for keys that must never leave hardware: AWS KMS, PKCS#11 HSMs,
/// wolfHSM, or the local software signing backend (dev/test only).
///
/// Like [`from_uri`], this function makes no network calls — construction only.
/// Returns [`SecretError::InvalidUri`] for unknown, disabled, or non-signing
/// backends.
pub fn from_signing_uri(uri: &str) -> Result<Arc<dyn SigningBackend>, SecretError> {
    let parsed = SecretUri::parse(uri)?;
    let backend = parsed.backend();
    for reg in inventory::iter::<secretx_core::SigningBackendRegistration>() {
        if reg.name == backend {
            return (reg.factory)(uri);
        }
    }
    // Give a helpful error for backends that exist but don't support signing.
    for reg in inventory::iter::<secretx_core::BackendRegistration>() {
        if reg.name == backend {
            return Err(SecretError::InvalidUri(format!(
                "{backend} is not a signing backend; use secretx::from_uri instead"
            )));
        }
    }
    Err(SecretError::InvalidUri(format!(
        "unknown or disabled signing backend `{backend}` — enable the corresponding feature flag"
    )))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── from_uri dispatch ─────────────────────────────────────────────────────

    #[test]
    fn from_uri_unknown_backend_returns_invalid_uri() {
        let result = from_uri("secretx:no-such-backend:key");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "unknown backend must return InvalidUri"
        );
    }

    #[test]
    fn from_uri_bad_scheme_returns_invalid_uri() {
        let result = from_uri("https://example.com/secret");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    // env and file are default features; these tests always run.
    #[test]
    fn from_uri_env_dispatches_correctly() {
        assert!(from_uri("secretx:env:MY_VAR").is_ok());
    }

    #[test]
    fn from_uri_file_dispatches_correctly() {
        // from_uri performs construction only — no file read.
        assert!(from_uri("secretx:file:relative/path/key").is_ok());
    }

    // Signing-only backends routed through from_uri must return InvalidUri.
    #[cfg(feature = "aws-kms")]
    #[test]
    fn from_uri_aws_kms_signing_only_returns_invalid_uri() {
        let result = from_uri("secretx:aws-kms:alias/my-key");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("signing-only"),
                    "error must mention 'signing-only', got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got error: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    #[cfg(feature = "local-signing")]
    #[test]
    fn from_uri_local_signing_signing_only_returns_invalid_uri() {
        let result = from_uri("secretx:local-signing:/tmp/key.der?algorithm=ed25519");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("signing-only"),
                    "error must mention 'signing-only', got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got error: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    #[cfg(feature = "k8s")]
    #[test]
    fn from_uri_k8s_dispatches_correctly() {
        // from_uri is construction-only — no network call. A valid k8s URI must
        // return Ok(backend), not InvalidUri (which would mean dispatch failed).
        assert!(
            from_uri("secretx:k8s:default/my-secret").is_ok(),
            "k8s URI must dispatch successfully (construction-only, no network)"
        );
    }

    #[cfg(feature = "wolfhsm")]
    #[test]
    fn from_uri_wolfhsm_dispatches_correctly() {
        // wolfhsm registers as both SecretStore and SigningBackend; from_uri
        // must succeed (the backend returns Unavailable at runtime when the
        // native library is not linked — that is not a URI error).
        assert!(
            from_uri("secretx:wolfhsm:my-label").is_ok(),
            "wolfhsm must be reachable via from_uri"
        );
    }

    // ── from_signing_uri dispatch ─────────────────────────────────────────────

    #[test]
    fn from_signing_uri_unknown_backend_returns_invalid_uri() {
        let result = from_signing_uri("secretx:no-such-backend:key");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "unknown signing backend must return InvalidUri"
        );
    }

    // Non-signing backends routed through from_signing_uri must return InvalidUri.
    // env is always enabled (default feature) so this test always runs.
    #[test]
    fn from_signing_uri_non_signing_backend_returns_invalid_uri() {
        let result = from_signing_uri("secretx:env:MY_VAR");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "non-signing backend via from_signing_uri must return InvalidUri"
        );
    }

    // ── from_uri_writable dispatch ────────────────────────────────────────────

    #[test]
    fn from_uri_writable_unknown_backend_returns_invalid_uri() {
        assert!(matches!(
            from_uri_writable("secretx:no-such-backend:key"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // file is a default feature; always runs.
    #[test]
    fn from_uri_writable_file_dispatches_correctly() {
        assert!(from_uri_writable("secretx:file:relative/path/key").is_ok());
    }

    // env is read-only; from_uri_writable must reject it.
    #[test]
    fn from_uri_writable_env_returns_read_only_error() {
        let result = from_uri_writable("secretx:env:MY_VAR");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("read-only"),
                    "error must mention 'read-only', got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got error: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    #[cfg(feature = "aws-kms")]
    #[test]
    fn from_uri_writable_aws_kms_returns_signing_only_error() {
        let result = from_uri_writable("secretx:aws-kms:alias/my-key");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("signing-only"),
                    "error must mention 'signing-only', got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got error: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    // ── inventory registration ────────────────────────────────────────────────

    #[test]
    fn inventory_backend_registrations_include_defaults() {
        let names: Vec<_> = inventory::iter::<secretx_core::BackendRegistration>()
            .map(|r| r.name)
            .collect();
        assert!(
            names.contains(&"env"),
            "env BackendRegistration not found in inventory"
        );
        assert!(
            names.contains(&"file"),
            "file BackendRegistration not found in inventory"
        );
    }

    #[test]
    fn inventory_writable_registrations_include_file() {
        let names: Vec<_> = inventory::iter::<secretx_core::WritableBackendRegistration>()
            .map(|r| r.name)
            .collect();
        assert!(
            names.contains(&"file"),
            "file WritableBackendRegistration not found in inventory"
        );
        // env must NOT be in writable — it's read-only
        assert!(
            !names.contains(&"env"),
            "env incorrectly registered as WritableBackendRegistration"
        );
    }

    #[cfg(feature = "local-signing")]
    #[test]
    fn inventory_signing_registrations_include_local_signing() {
        let names: Vec<_> = inventory::iter::<secretx_core::SigningBackendRegistration>()
            .map(|r| r.name)
            .collect();
        assert!(
            names.contains(&"local-signing"),
            "local-signing SigningBackendRegistration not found in inventory"
        );
        // local-signing must NOT be in BackendRegistration — it's signing-only
        let backend_names: Vec<_> = inventory::iter::<secretx_core::BackendRegistration>()
            .map(|r| r.name)
            .collect();
        assert!(
            !backend_names.contains(&"local-signing"),
            "local-signing incorrectly registered as BackendRegistration"
        );
    }
}
