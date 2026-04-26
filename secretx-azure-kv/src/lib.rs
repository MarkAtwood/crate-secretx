//! Azure Key Vault backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without credentials.
//! Live integration tests require an Azure subscription with a Key Vault
//! instance. Set `SECRETX_AZURE_TEST=1`, `SECRETX_AZURE_VAULT`, and
//! `SECRETX_AZURE_SECRET` env vars to enable them.
//! **Not yet integration-tested.**
//!
//! URI: `secretx:azure-kv:<vault-name>/<secret-name>[?field=<json_field>&credential=<mode>]`
//!
//! - `vault-name` is the Azure Key Vault name (the subdomain part before `.vault.azure.net`)
//! - `secret-name` is the name of the secret stored in the vault
//! - `credential` controls which Azure credential is used:
//!   - `managed-identity` — use only managed identity; recommended in production to
//!     prevent silent fallback to developer credentials on transient MI failures
//!   - `developer` — use only Azure CLI / Azure Developer CLI; for local development
//!   - `chained` or absent (default) — try managed identity first, then developer tools
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_azure_kv::AzureKvBackend;
//! use secretx_core::SecretStore;
//!
//! let store = AzureKvBackend::from_uri("secretx:azure-kv:my-vault/my-secret")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Zeroization
//!
//! The Azure SDK deserializes the HTTP response internally and returns the secret as a plain
//! `String` (`secret.value`).  That `String` is in non-Zeroizing heap memory before our code
//! sees it — there is no way to zero it from outside the SDK.  Because the secret is already
//! leaked at the SDK layer, using `serde_json` for `?field=` extraction adds no additional
//! unzeroed copies.  Only the final `SecretValue` returned to the caller is zeroed on drop.
//!
//! In `put`, the secret bytes are decoded to a plain `String` before being passed to
//! `SetSecretParameters`. That intermediate `String` is moved into the Azure SDK struct and is
//! not zeroed on drop; the Azure SDK does not use `Zeroizing` for its fields. This is an SDK
//! limitation. The `SecretValue` passed to `put` is zeroed on drop as usual.

use std::sync::Arc;

use azure_core::{credentials::TokenCredential, error::ErrorKind};
use azure_identity::{DeveloperToolsCredential, ManagedIdentityCredential};
use azure_security_keyvault_secrets::{models::SetSecretParameters, SecretClient};
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};

const BACKEND: &str = "azure-kv";

/// Which Azure credential to use for authenticating to Key Vault.
#[derive(Clone, Copy)]
enum CredentialMode {
    /// Managed identity only. Recommended for production to prevent silent fallback
    /// to developer credentials on transient managed-identity failures.
    ManagedIdentity,
    /// Developer tools (Azure CLI / Azure Developer CLI) only. For local development.
    Developer,
    /// Try managed identity first; fall back to developer tools. The default.
    Chained,
}

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
    /// Construct from a `secretx:azure-kv:<vault-name>/<secret-name>[?field=<json_field>]` URI.
    ///
    /// Builds the Azure Key Vault client synchronously. Credential discovery
    /// is deferred to the first actual network call.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend()
            )));
        }

        // URI path is "<vault-name>/<secret-name>".
        let (vault_name, secret_name) = split_path(parsed.path()).ok_or_else(|| {
            // Distinguish the slash-in-secret case: Azure KV secret names
            // cannot contain '/', so give an actionable message rather than
            // just "requires vault name and secret name".
            if parsed.path().bytes().filter(|&b| b == b'/').count() > 1 {
                SecretError::InvalidUri(
                    "azure-kv secret name must not contain '/': Azure Key Vault \
                     does not support nested secret names; \
                     use secretx:azure-kv:<vault-name>/<secret-name>"
                        .into(),
                )
            } else {
                SecretError::InvalidUri(
                    "azure-kv URI requires vault name and secret name: \
                     secretx:azure-kv:<vault-name>/<secret-name>"
                        .into(),
                )
            }
        })?;

        let field = parsed.param("field").map(str::to_owned);
        let credential_mode = match parsed.param("credential") {
            None | Some("chained") => CredentialMode::Chained,
            Some("managed-identity") => CredentialMode::ManagedIdentity,
            Some("developer") => CredentialMode::Developer,
            Some(other) => {
                return Err(SecretError::InvalidUri(format!(
                    "unknown credential mode `{other}`; \
                     supported: managed-identity, developer, chained (default)"
                )))
            }
        };
        let client = build_client(&vault_name, credential_mode)?;

        Ok(Self {
            client: Arc::new(client),
            secret_name,
            field,
        })
    }
}

/// Split `"<vault-name>/<secret-name>"` into `(vault_name, secret_name)`.
///
/// Returns `None` if either component is empty or if `secret-name` contains `/`
/// (Azure Key Vault secret names may not contain slashes).
fn split_path(path: &str) -> Option<(String, String)> {
    let slash = path.find('/')?;
    let vault = &path[..slash];
    let secret = &path[slash + 1..];
    if vault.is_empty() || secret.is_empty() || secret.contains('/') {
        return None;
    }
    Some((vault.to_string(), secret.to_string()))
}

/// Build an Azure Key Vault `SecretClient` using the specified credential mode.
///
/// `SecretClient::new` is synchronous so no runtime is needed.
fn build_client(vault_name: &str, mode: CredentialMode) -> Result<SecretClient, SecretError> {
    let credential: Arc<dyn TokenCredential> = build_credential(mode)?;
    let vault_url = format!("https://{vault_name}.vault.azure.net");
    SecretClient::new(&vault_url, credential, None).map_err(|e| SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    })
}

/// Build an Azure credential according to `mode`.
fn build_credential(mode: CredentialMode) -> Result<Arc<dyn TokenCredential>, SecretError> {
    match mode {
        CredentialMode::ManagedIdentity => {
            let mi = ManagedIdentityCredential::new(None).map_err(|e| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;
            Ok(mi as Arc<dyn TokenCredential>)
        }
        CredentialMode::Developer => {
            let dt = DeveloperToolsCredential::new(None).map_err(|e| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;
            Ok(dt as Arc<dyn TokenCredential>)
        }
        CredentialMode::Chained => {
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
    }
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

/// Returns true for errors that are likely transient (network I/O, server-side 5xx, 429).
/// Callers should use `Unavailable` for these; `Backend` for permanent errors.
fn is_transient(e: &azure_core::Error) -> bool {
    matches!(e.kind(), ErrorKind::Io)
        || matches!(
            e.kind(),
            ErrorKind::HttpResponse { status, .. }
            if status.is_server_error()
                || *status == azure_core::http::StatusCode::TooManyRequests
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
        } else if is_transient(&e) {
            SecretError::Unavailable {
                backend: BACKEND,
                source: e.into(),
            }
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

    match field {
        Some(f) => {
            let json: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                SecretError::DecodeFailed(format!(
                    "azure-kv: ?field= requires a JSON string secret: {e}"
                ))
            })?;
            let val = json.get(f).and_then(|v| v.as_str()).ok_or_else(|| {
                SecretError::DecodeFailed(format!(
                    "azure-kv: field '{f}' not found or not a string"
                ))
            })?;
            Ok(SecretValue::new(val.as_bytes().to_vec()))
        }
        None => Ok(SecretValue::new(raw.into_bytes())),
    }
}

#[async_trait::async_trait]
impl SecretStore for AzureKvBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        fetch(&self.client, &self.secret_name, self.field.as_deref()).await
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for AzureKvBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        if self.field.is_some() {
            return Err(SecretError::InvalidUri(
                "put() requires a URI without a field selector (?field=); \
                 to update the whole secret omit ?field=, or implement read-modify-write \
                 at the call site"
                    .into(),
            ));
        }
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
                } else if is_transient(&e) {
                    SecretError::Unavailable {
                        backend: BACKEND,
                        source: e.into(),
                    }
                } else {
                    SecretError::Backend {
                        backend: BACKEND,
                        source: e.into(),
                    }
                }
            })?;

        Ok(())
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "azure-kv",
    factory: |uri: &str| {
        AzureKvBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "azure-kv",
    factory: |uri: &str| {
        AzureKvBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // URI parsing tests — no Azure connection required.

    #[test]
    fn from_uri_unknown_credential_mode() {
        assert!(matches!(
            AzureKvBackend::from_uri("secretx:azure-kv:my-vault/my-secret?credential=saml"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            AzureKvBackend::from_uri("secretx:env:FOO"),
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
            AzureKvBackend::from_uri("secretx:azure-kv:my-vault"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_vault_name() {
        assert!(matches!(
            AzureKvBackend::from_uri("secretx:azure-kv:/my-secret"),
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
    fn split_path_nested_secret_rejected() {
        // Azure Key Vault secret names may not contain '/'. A URI like
        // secretx:azure-kv:my-vault/nested/path is ambiguous and would
        // produce a confusing Azure API error. Reject it at parse time so
        // callers get InvalidUri instead.
        assert!(split_path("my-vault/nested/path").is_none());
    }

    #[test]
    fn from_uri_slash_in_secret_name_gives_actionable_error() {
        let result = AzureKvBackend::from_uri("secretx:azure-kv:my-vault/nested/path");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "expected InvalidUri"
        );
        if let Err(SecretError::InvalidUri(msg)) = result {
            assert!(
                msg.contains("must not contain '/'"),
                "error message should explain the slash constraint, got: {msg}"
            );
        }
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

    // put() field-selector guard — no Azure connection needed.
    #[tokio::test]
    async fn put_with_field_selector_returns_invalid_uri() {
        let store =
            AzureKvBackend::from_uri("secretx:azure-kv:my-vault/my-secret?field=password").unwrap();
        let result = store.put(SecretValue::new(b"new-value".to_vec())).await;
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "put with field selector must return InvalidUri (got: {:?})",
            result.err()
        );
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
        let uri = format!("secretx:azure-kv:{vault}/{secret}");
        let store = AzureKvBackend::from_uri(&uri).unwrap();
        let value = store.get().await.unwrap();
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
        let uri = format!("secretx:azure-kv:{vault}/{secret}");
        let store = AzureKvBackend::from_uri(&uri).unwrap();
        let value = store.refresh().await.unwrap();
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
        let uri = format!("secretx:azure-kv:{vault}/{secret}?field={field}");
        let store = AzureKvBackend::from_uri(&uri).unwrap();
        let value = store.get().await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}
