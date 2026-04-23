//! Backend-agnostic secrets retrieval for Rust.
//!
//! Re-exports [`secretx_core`] types and provides [`from_uri`] for URI-driven
//! backend selection.
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

pub use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
};

use std::sync::Arc;

/// Parse a `secretx://` URI and return the appropriate backend.
///
/// This is the only function in the workspace that contains `#[cfg(feature)]`
/// guards. Does not make any network call or file read — construction only.
/// Returns [`SecretError::InvalidUri`] for unknown or disabled backends.
pub fn from_uri(uri: &str) -> Result<Arc<dyn SecretStore>, SecretError> {
    let parsed = SecretUri::parse(uri)?;
    match parsed.backend.as_str() {
        #[cfg(feature = "env")]
        "env" => secretx_env::EnvBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "file")]
        "file" => secretx_file::FileBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "aws-kms")]
        "aws-kms" => secretx_aws_kms::AwsKmsBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "aws-sm")]
        "aws-sm" => secretx_aws_sm::AwsSmBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "aws-ssm")]
        "aws-ssm" => secretx_aws_ssm::AwsSsmBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "azure-kv")]
        "azure-kv" => secretx_azure_kv::AzureKvBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "bitwarden")]
        "bitwarden" => secretx_bitwarden::BitwardenBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "doppler")]
        "doppler" => secretx_doppler::DopplerBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "gcp-sm")]
        "gcp-sm" => secretx_gcp_sm::GcpSmBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "hashicorp-vault")]
        "vault" => secretx_hashicorp_vault::VaultBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "keyring")]
        "keyring" => secretx_keyring::KeyringBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "pkcs11")]
        "pkcs11" => secretx_pkcs11::Pkcs11Backend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        #[cfg(feature = "wolfhsm")]
        "wolfhsm" => secretx_wolfhsm::WolfHsmBackend::from_uri(uri).map(|b| Arc::new(b) as Arc<dyn SecretStore>),
        other => Err(SecretError::InvalidUri(format!(
            "unknown or disabled backend `{other}` — enable the corresponding feature flag"
        ))),
    }
}
