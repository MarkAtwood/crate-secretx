//! Azure Key Vault backend for secretx.
//!
//! URI: `secretx://azure-kv/<vault-name>/<secret-name>[?field=<json_field>]`
//!
//! - `vault-name` is the Azure Key Vault name (the subdomain part before `.vault.azure.net`)
//! - `secret-name` is the name of the secret stored in the vault
//!
//! Authentication uses a chain: managed identity first (for Azure-hosted workloads),
//! then Azure CLI / Azure Developer CLI (for developer workstations and CI).
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_azure_kv::AzureKvBackend;
//! use secretx_core::SecretStore;
//!
//! let store = AzureKvBackend::from_uri("secretx://azure-kv/my-vault/my-secret")?;
//! let value = store.get("my-secret").await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use azure_core::{credentials::TokenCredential, error::ErrorKind};
use azure_identity::{DeveloperToolsCredential, ManagedIdentityCredential};
use azure_security_keyvault_secrets::{models::SetSecretParameters, SecretClient};
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};

const BACKEND: &str = "azure-kv";

/// Backend that reads and writes secrets in Azure Key Vault.
///
/// Construct with [`from_uri`](AzureKvBackend::from_uri). The Azure client is
/// built at construction time using a credential chain (managed identity, then
/// Azure CLI / AzureDeveloperCLI).
pub struct AzureKvBackend {
    client: Arc<SecretClient>,
    /// Secret name as stored in Key Vault.
    secret_name: String,
    /// Optional JSON field to extract from the secret string value.
    field: Option<String>,
}

impl AzureKvBackend {
    /// Construct from a `secretx://azure-kv/<vault-name>/<secret-name>[?field=<json_field>]` URI.
    ///
    /// Builds the Azure Key Vault client synchronously. Credential discovery
    /// is deferred to the first actual network call.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend
            )));
        }

        // URI path is "<vault-name>/<secret-name>".
        let (vault_name, secret_name) = split_path(&parsed.path).ok_or_else(|| {
            SecretError::InvalidUri(
                "azure-kv URI requires vault name and secret name: \
                 secretx://azure-kv/<vault-name>/<secret-name>"
                    .into(),
            )
        })?;

        let field = parsed.param("field").map(str::to_owned);
        let client = build_client(&vault_name)?;

        Ok(Self {
            client: Arc::new(client),
            secret_name,
            field,
        })
    }
}

/// Split `"<vault-name>/<secret-name>"` into `(vault_name, secret_name)`.
///
/// Returns `None` if either component is empty.
fn split_path(path: &str) -> Option<(String, String)> {
    let slash = path.find('/')?;
    let vault = &path[..slash];
    let secret = &path[slash + 1..];
    if vault.is_empty() || secret.is_empty() {
        return None;
    }
    Some((vault.to_string(), secret.to_string()))
}

/// Build an Azure Key Vault `SecretClient` using a credential chain.
///
/// Tries managed identity first (succeeds on Azure-hosted workloads), then
/// developer tools credentials (Azure CLI / Azure Developer CLI) for local
/// development. `SecretClient::new` is synchronous so no runtime is needed.
fn build_client(vault_name: &str) -> Result<SecretClient, SecretError> {
    let credential: Arc<dyn TokenCredential> = build_credential()?;
    let vault_url = format!("https://{vault_name}.vault.azure.net");
    SecretClient::new(&vault_url, credential, None).map_err(|e| SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    })
}

/// Build a chained credential: managed identity → developer tools.
///
/// Both credential types are constructed synchronously; actual token fetches
/// are deferred until the first network call.
fn build_credential() -> Result<Arc<dyn TokenCredential>, SecretError> {
    // Prefer managed identity (IMDS) on Azure-hosted workloads.
    // If that succeeds, it will be the active credential at token-fetch time.
    // On a developer workstation IMDS is unreachable, so managed identity will
    // simply fail at get_token() time and the SDK does NOT automatically
    // fall back — so we build a manual chain here.
    //
    // The chain: ManagedIdentityCredential → DeveloperToolsCredential.
    // We wrap both in a simple Arc<ChainedCredential> that tries each in order.

    let mi = ManagedIdentityCredential::new(None).map_err(|e| SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    })?;

    let dt = DeveloperToolsCredential::new(None).map_err(|e| SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    })?;

    Ok(Arc::new(ChainedCredential {
        sources: vec![mi, dt],
    }))
}

/// A simple credential chain that tries each source in order, stopping at the
/// first that returns a token.
struct ChainedCredential {
    sources: Vec<Arc<dyn TokenCredential>>,
}

impl std::fmt::Debug for ChainedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChainedCredential")
    }
}

#[async_trait::async_trait]
impl TokenCredential for ChainedCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<azure_core::credentials::AccessToken> {
        let mut last_err: Option<azure_core::Error> = None;
        for source in &self.sources {
            match source.get_token(scopes, options.clone()).await {
                Ok(token) => return Ok(token),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            azure_core::Error::with_message(
                azure_core::error::ErrorKind::Credential,
                "no credentials available",
            )
        }))
    }
}

/// Return `true` if this Azure error represents a "secret not found" (HTTP 404).
fn is_not_found(e: &azure_core::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::HttpResponse { status, .. } if *status == azure_core::http::StatusCode::NotFound
    )
}

/// Fetch the current value of a secret from Key Vault.
async fn fetch(
    client: &SecretClient,
    secret_name: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    let resp = client.get_secret(secret_name, None).await.map_err(|e| {
        if is_not_found(&e) {
            SecretError::NotFound
        } else {
            SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            }
        }
    })?;

    let secret = resp.into_model().map_err(|e| SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    })?;

    let raw = secret.value.ok_or(SecretError::NotFound)?;
    let value = SecretValue::new(raw.into_bytes());

    match field {
        Some(f) => value.extract_field(f),
        None => Ok(value),
    }
}

#[async_trait::async_trait]
impl SecretStore for AzureKvBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        fetch(&self.client, &self.secret_name, self.field.as_deref()).await
    }

    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        let raw = std::str::from_utf8(value.as_bytes())
            .map(str::to_owned)
            .map_err(|_| {
                SecretError::DecodeFailed(
                    "Azure Key Vault secrets must be valid UTF-8 strings".into(),
                )
            })?;

        let params = SetSecretParameters {
            value: Some(raw),
            ..Default::default()
        };

        let request_content =
            params
                .try_into()
                .map_err(|e: azure_core::Error| SecretError::Backend {
                    backend: BACKEND,
                    source: e.into(),
                })?;

        self.client
            .set_secret(&self.secret_name, request_content, None)
            .await
            .map_err(|e| {
                if is_not_found(&e) {
                    SecretError::NotFound
                } else {
                    SecretError::Backend {
                        backend: BACKEND,
                        source: e.into(),
                    }
                }
            })?;

        Ok(())
    }

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // URI parsing tests — no Azure connection required.

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            AzureKvBackend::from_uri("secretx://env/FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        assert!(matches!(
            AzureKvBackend::from_uri("https://azure-kv/my-vault/my-secret"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_secret_name() {
        assert!(matches!(
            AzureKvBackend::from_uri("secretx://azure-kv/my-vault"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_vault_name() {
        assert!(matches!(
            AzureKvBackend::from_uri("secretx://azure-kv//my-secret"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn split_path_ok() {
        let (vault, secret) = split_path("my-vault/my-secret").unwrap();
        assert_eq!(vault, "my-vault");
        assert_eq!(secret, "my-secret");
    }

    #[test]
    fn split_path_nested_secret() {
        // Secret names may not contain '/' in Azure KV, but the URI parser
        // may present path components separated by '/'. We take only the
        // first segment as vault name and the rest as secret name, so a
        // secret name like "prod/my-secret" becomes path="prod/my-secret"
        // with vault="prod" and secret="my-secret" — this is the intended
        // URI design.
        let (vault, secret) = split_path("my-vault/nested/path").unwrap();
        assert_eq!(vault, "my-vault");
        assert_eq!(secret, "nested/path");
    }

    #[test]
    fn split_path_no_slash() {
        assert!(split_path("my-vault").is_none());
    }

    #[test]
    fn split_path_empty_vault() {
        assert!(split_path("/my-secret").is_none());
    }

    #[test]
    fn split_path_empty_secret() {
        assert!(split_path("my-vault/").is_none());
    }

    // Integration tests — skipped unless SECRETX_AZURE_TEST=1 and Azure env vars are set.

    #[tokio::test]
    async fn integration_get() {
        if std::env::var("SECRETX_AZURE_TEST").as_deref() != Ok("1") {
            return;
        }
        let vault = match std::env::var("SECRETX_AZURE_VAULT") {
            Ok(v) => v,
            Err(_) => return,
        };
        let secret = match std::env::var("SECRETX_AZURE_SECRET") {
            Ok(s) => s,
            Err(_) => return,
        };
        let uri = format!("secretx://azure-kv/{vault}/{secret}");
        let store = AzureKvBackend::from_uri(&uri).unwrap();
        let value = store.get(&secret).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_refresh() {
        if std::env::var("SECRETX_AZURE_TEST").as_deref() != Ok("1") {
            return;
        }
        let vault = match std::env::var("SECRETX_AZURE_VAULT") {
            Ok(v) => v,
            Err(_) => return,
        };
        let secret = match std::env::var("SECRETX_AZURE_SECRET") {
            Ok(s) => s,
            Err(_) => return,
        };
        let uri = format!("secretx://azure-kv/{vault}/{secret}");
        let store = AzureKvBackend::from_uri(&uri).unwrap();
        let value = store.refresh(&secret).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_field_extraction() {
        if std::env::var("SECRETX_AZURE_TEST").as_deref() != Ok("1") {
            return;
        }
        let vault = match std::env::var("SECRETX_AZURE_VAULT") {
            Ok(v) => v,
            Err(_) => return,
        };
        let secret = match std::env::var("SECRETX_AZURE_SECRET_JSON") {
            Ok(s) => s,
            Err(_) => return,
        };
        let field = match std::env::var("SECRETX_AZURE_FIELD") {
            Ok(f) => f,
            Err(_) => return,
        };
        let uri = format!("secretx://azure-kv/{vault}/{secret}?field={field}");
        let store = AzureKvBackend::from_uri(&uri).unwrap();
        let value = store.get(&secret).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}
