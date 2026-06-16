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
use std::time::Duration;

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
        Self::from_parsed_uri(&SecretUri::parse(uri)?)
    }

    /// Construct from a pre-parsed [`SecretUri`].
    pub fn from_parsed_uri(parsed: &SecretUri) -> Result<Self, SecretError> {
        if parsed.backend() != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend()
            )));
        }

        // URI path is "<vault-name>/<secret-name>".
        let (vault_name, secret_name) = split_path(parsed.path()).map_err(|e| match e {
            SplitPathError::NestedSlash => SecretError::InvalidUri(
                "azure-kv secret name must not contain '/': Azure Key Vault \
                 does not support nested secret names; \
                 use secretx:azure-kv:<vault-name>/<secret-name>"
                    .into(),
            ),
            SplitPathError::Invalid => SecretError::InvalidUri(
                "azure-kv URI requires vault name and secret name: \
                 secretx:azure-kv:<vault-name>/<secret-name>"
                    .into(),
            ),
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
        let client = build_client(vault_name, credential_mode)?;

        Ok(Self {
            client: Arc::new(client),
            secret_name: secret_name.to_owned(),
            field,
        })
    }
}

/// Why `split_path` rejected the input.
#[derive(Debug)]
enum SplitPathError {
    /// The secret-name component contains `/` (Azure KV forbids slashes in
    /// secret names). Stored separately so callers can give an actionable
    /// error message without re-scanning the path.
    NestedSlash,
    /// Any other structural problem: missing slash, empty component, invalid
    /// vault-name characters, etc.
    Invalid,
}

/// Split `"<vault-name>/<secret-name>"` into `(vault_name, secret_name)`.
///
/// Returns borrowed slices into `path`. Fails with [`SplitPathError::NestedSlash`]
/// if `secret-name` contains `/` (Azure Key Vault secret names may not contain
/// slashes), or [`SplitPathError::Invalid`] for any other structural problem
/// (missing slash, empty component, vault-name outside `[a-zA-Z0-9-]`, etc.).
fn split_path(path: &str) -> Result<(&str, &str), SplitPathError> {
    let slash = path.find('/').ok_or(SplitPathError::Invalid)?;
    let vault = &path[..slash];
    let secret = &path[slash + 1..];
    if vault.is_empty() || secret.is_empty() {
        return Err(SplitPathError::Invalid);
    }
    if secret.contains('/') {
        return Err(SplitPathError::NestedSlash);
    }
    // Azure vault names must be 3-24 characters, alphanumeric or hyphens.
    // Rejecting anything else prevents URL injection via the vault name
    // (e.g. "evil.com/x#" would redirect the HTTPS request to a different host).
    if vault.len() < 3 || vault.len() > 24 {
        return Err(SplitPathError::Invalid);
    }
    if !vault
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(SplitPathError::Invalid);
    }
    Ok((vault, secret))
}

/// Build an Azure Key Vault `SecretClient` using the specified credential mode.
///
/// `SecretClient::new` is synchronous so no runtime is needed.
fn build_client(vault_name: &str, mode: CredentialMode) -> Result<SecretClient, SecretError> {
    let credential: Arc<dyn TokenCredential> = build_credential(mode)?;
    let vault_url = format!("https://{vault_name}.vault.azure.net");
    SecretClient::new(&vault_url, credential, None).map_err(map_azure_error)
}

/// Build an Azure credential according to `mode`.
fn build_credential(mode: CredentialMode) -> Result<Arc<dyn TokenCredential>, SecretError> {
    match mode {
        CredentialMode::ManagedIdentity => {
            let mi = ManagedIdentityCredential::new(None).map_err(map_azure_error)?;
            Ok(mi as Arc<dyn TokenCredential>)
        }
        CredentialMode::Developer => {
            let dt = DeveloperToolsCredential::new(None).map_err(map_azure_error)?;
            Ok(dt as Arc<dyn TokenCredential>)
        }
        CredentialMode::Chained => {
            let mi = ManagedIdentityCredential::new(None).map_err(map_azure_error)?;
            let dt = DeveloperToolsCredential::new(None).map_err(map_azure_error)?;
            Ok(Arc::new(ChainedCredential {
                sources: vec![
                    ("ManagedIdentity".to_owned(), mi),
                    ("DeveloperTools".to_owned(), dt),
                ],
            }))
        }
    }
}

/// Per-source timeout for credential acquisition. Prevents IMDS hangs in
/// non-Azure environments from blocking the entire credential chain.
const CREDENTIAL_SOURCE_TIMEOUT: Duration = Duration::from_secs(5);

/// A credential chain that tries each source in order, stopping at the first
/// that returns a token. Each source is subject to [`CREDENTIAL_SOURCE_TIMEOUT`]
/// and all intermediate errors are preserved in the final error message.
struct ChainedCredential {
    sources: Vec<(String, Arc<dyn TokenCredential>)>,
}

impl std::fmt::Debug for ChainedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.sources.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("ChainedCredential")
            .field("sources", &names)
            .finish()
    }
}

/// Returns `true` if this credential error indicates a misconfiguration rather
/// than the credential source simply being unavailable.
///
/// Misconfiguration examples: wrong client_id, identity not assigned to the
/// resource (HTTP 400/403 from IMDS), invalid tenant. These should not be
/// silently swallowed because the operator intended to use this credential
/// source and it is broken.
///
/// Unavailability examples: IMDS not reachable (timeout, connection refused),
/// which just means we are not running in Azure.
fn is_credential_misconfiguration(e: &azure_core::Error) -> bool {
    match e.kind() {
        // HTTP 400 (bad request) or 403 (forbidden) from IMDS = misconfigured identity
        ErrorKind::HttpResponse { status, .. } => {
            *status == azure_core::http::StatusCode::BadRequest
                || *status == azure_core::http::StatusCode::Forbidden
        }
        // Credential errors from the SDK that are not I/O or connection
        // failures are typically configuration problems.
        ErrorKind::Credential => true,
        // I/O and connection errors mean the endpoint is unreachable, not
        // misconfigured.
        ErrorKind::Io | ErrorKind::Connection => false,
        _ => false,
    }
}

#[async_trait::async_trait]
impl TokenCredential for ChainedCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<azure_core::credentials::AccessToken> {
        let mut errors: Vec<String> = Vec::new();
        for (name, source) in &self.sources {
            let result = tokio::time::timeout(
                CREDENTIAL_SOURCE_TIMEOUT,
                source.get_token(scopes, options.clone()),
            )
            .await;

            match result {
                Ok(Ok(token)) => return Ok(token),
                Ok(Err(e)) => {
                    let is_misconfig = is_credential_misconfiguration(&e);
                    errors.push(format!("{name}: {e}"));
                    // If a source fails due to misconfiguration (not just
                    // unavailability), stop the chain immediately. The
                    // operator selected this source and it is broken;
                    // falling through to developer credentials would mask
                    // a production problem.
                    if is_misconfig {
                        let msg = format!(
                            "credential source '{name}' is misconfigured \
                             (not just unavailable); stopping chain. \
                             All errors: [{}]",
                            errors.join("; ")
                        );
                        return Err(azure_core::Error::with_message(
                            azure_core::error::ErrorKind::Credential,
                            msg,
                        ));
                    }
                }
                Err(_elapsed) => {
                    errors.push(format!(
                        "{name}: timed out after {}s",
                        CREDENTIAL_SOURCE_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        let msg = if errors.is_empty() {
            "no credential sources configured".to_owned()
        } else {
            format!(
                "all credential sources failed: [{}]",
                errors.join("; ")
            )
        };
        Err(azure_core::Error::with_message(
            azure_core::error::ErrorKind::Credential,
            msg,
        ))
    }
}

/// Map an `azure_core::Error` to a `SecretError`, classifying transient vs permanent.
///
/// Transient errors (network I/O, 5xx, 429) map to [`SecretError::Unavailable`];
/// everything else maps to [`SecretError::Backend`].
///
/// Both `azure_core::Error` and `SecretError` are foreign types, so `impl From`
/// is blocked by orphan rules.
fn map_azure_error(e: azure_core::Error) -> SecretError {
    if is_transient(&e) {
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
}

/// Map an Azure API error, distinguishing not-found, transient, and permanent.
///
/// Used for Azure Key Vault API calls where a 404 should map to
/// [`SecretError::NotFound`] rather than a backend error.
fn map_azure_api_error(e: azure_core::Error) -> SecretError {
    if is_not_found(&e) {
        SecretError::NotFound
    } else {
        map_azure_error(e)
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
    matches!(e.kind(), ErrorKind::Io | ErrorKind::Connection)
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
    let resp = client
        .get_secret(secret_name, None)
        .await
        .map_err(map_azure_api_error)?;

    let secret = resp.into_model().map_err(map_azure_error)?;

    let raw = secret.value.ok_or_else(|| SecretError::Backend {
        backend: BACKEND,
        source: "azure-kv returned 200 with no secret value field; SDK or service anomaly".into(),
    })?;

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
        let raw = String::from_utf8(value.as_bytes().to_vec()).map_err(|e| {
            SecretError::DecodeFailed(format!(
                "Azure Key Vault secrets must be valid UTF-8 strings \
                 (invalid byte at position {})",
                e.utf8_error().valid_up_to()
            ))
        })?;

        let params = SetSecretParameters {
            value: Some(raw),
            ..Default::default()
        };

        let request_content =
            params
                .try_into()
                .map_err(|e: azure_core::Error| map_azure_error(e))?;

        self.client
            .set_secret(&self.secret_name, request_content, None)
            .await
            .map_err(map_azure_api_error)?;

        Ok(())
    }
}

inventory::submit!(secretx_core::BackendRegistration::new(
    "azure-kv",
    |uri: &secretx_core::SecretUri| {
        let b = AzureKvBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

inventory::submit!(secretx_core::WritableBackendRegistration::new(
    "azure-kv",
    |uri: &secretx_core::SecretUri| {
        // Reject ?field= at construction time: put() cannot write a single
        // JSON field without a read-modify-write race.  Fail early rather than
        // returning InvalidUri from put() at rotation time.
        if uri.param("field").is_some() {
            return Err(secretx_core::SecretError::InvalidUri(
                "azure-kv writable backend does not support ?field=; \
                 put() requires the full secret URI without a field selector"
                    .into(),
            ));
        }
        let b = AzureKvBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::WritableSecretStore>)
    },
));

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
        assert!(matches!(
            split_path("my-vault/nested/path"),
            Err(SplitPathError::NestedSlash)
        ));
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
        assert!(split_path("my-vault").is_err());
    }

    #[test]
    fn split_path_empty_vault() {
        assert!(split_path("/my-secret").is_err());
    }

    #[test]
    fn split_path_empty_secret() {
        assert!(split_path("my-vault/").is_err());
    }

    #[test]
    fn split_path_vault_name_url_injection() {
        // Vault names must be DNS-safe; special chars would cause URL injection
        // in the "https://{vault_name}.vault.azure.net" endpoint.
        assert!(split_path("evil.com/secret").is_err());
        assert!(split_path("evil#fragment/secret").is_err());
        assert!(split_path("evil:8080/secret").is_err());
        assert!(split_path("evil@host/secret").is_err());
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

    // ── is_not_found / is_transient unit tests ───────────────────────────────

    fn make_http_error(status: u16) -> azure_core::Error {
        azure_core::Error::with_message(
            ErrorKind::HttpResponse {
                status: azure_core::http::StatusCode::try_from(status).unwrap(),
                error_code: None,
                raw_response: None,
            },
            format!("test HTTP {status}"),
        )
    }

    #[test]
    fn is_not_found_404() {
        assert!(is_not_found(&make_http_error(404)));
    }

    #[test]
    fn is_not_found_200_is_false() {
        assert!(!is_not_found(&make_http_error(200)));
    }

    #[test]
    fn is_not_found_500_is_false() {
        assert!(!is_not_found(&make_http_error(500)));
    }

    #[test]
    fn is_transient_500() {
        assert!(is_transient(&make_http_error(500)));
    }

    #[test]
    fn is_transient_503() {
        assert!(is_transient(&make_http_error(503)));
    }

    #[test]
    fn is_transient_429() {
        assert!(is_transient(&make_http_error(429)));
    }

    #[test]
    fn is_transient_403_is_false() {
        assert!(!is_transient(&make_http_error(403)));
    }

    #[test]
    fn is_transient_io_error() {
        let e = azure_core::Error::with_message(ErrorKind::Io, "network down");
        assert!(is_transient(&e));
    }

    #[test]
    fn is_transient_connection_error() {
        let e = azure_core::Error::with_message(ErrorKind::Connection, "DNS failed");
        assert!(is_transient(&e));
    }
}
