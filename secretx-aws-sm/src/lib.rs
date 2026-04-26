//! AWS Secrets Manager backend for secretx.
//!
//! URI: `secretx:aws-sm:<name>[?field=<json_field>]`
//!
//! # Zeroization
//!
//! The AWS SDK deserializes the HTTP response internally using serde and returns the secret
//! as a plain `String` (`secret_string()`).  That `String` is in non-Zeroizing heap memory
//! before our code sees it — there is no way to zero it from outside the SDK.  Because the
//! secret is already leaked at the SDK layer, using `serde_json` for `?field=` extraction
//! adds no additional unzeroed copies.  Only the final `SecretValue` returned to the caller
//! is zeroed on drop.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_aws_sm::AwsSmBackend;
//! use secretx_core::SecretStore;
//!
//! let store = AwsSmBackend::from_uri("secretx:aws-sm:prod/my-secret")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use aws_sdk_secretsmanager::error::SdkError;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use aws_sdk_secretsmanager::operation::put_secret_value::PutSecretValueError;
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};

const BACKEND: &str = "aws-sm";

/// Backend that reads and writes secrets in AWS Secrets Manager.
///
/// Construct with [`from_uri`](AwsSmBackend::from_uri). The AWS client is
/// built eagerly at construction time using `aws_config::load_from_env`.
pub struct AwsSmBackend {
    client: Arc<aws_sdk_secretsmanager::Client>,
    /// Secret name or ARN as stored in Secrets Manager.
    name: String,
    /// Optional JSON field to extract from a string secret.
    field: Option<String>,
}

impl AwsSmBackend {
    /// Construct from a `secretx:aws-sm:<name>[?field=<json_field>]` URI.
    ///
    /// Loads AWS configuration from the environment (region, credentials) at
    /// construction time. This is a synchronous call that internally spins up a
    /// short-lived tokio runtime on a scoped thread so it is safe to call from
    /// both inside and outside an existing tokio runtime.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "aws-sm URI requires a secret name: secretx:aws-sm:<name>".into(),
            ));
        }
        let name = parsed.path().to_owned();
        let field = parsed.param("field").map(str::to_owned);
        let client = build_client()?;
        Ok(Self {
            client: Arc::new(client),
            name,
            field,
        })
    }
}

/// Build an AWS Secrets Manager client by loading config from the environment.
///
/// Uses [`secretx_core::run_on_new_thread`] so this works whether or not the
/// caller is already inside a tokio runtime.
fn build_client() -> Result<aws_sdk_secretsmanager::Client, SecretError> {
    secretx_core::run_on_new_thread(
        || async {
            let config = aws_config::load_from_env().await;
            Ok(aws_sdk_secretsmanager::Client::new(&config))
        },
        BACKEND,
    )
}

/// Map a `GetSecretValueError` to `SecretError`.
fn map_get_error(e: SdkError<GetSecretValueError>) -> SecretError {
    if let Some(svc) = e.as_service_error() {
        if svc.is_resource_not_found_exception() {
            return SecretError::NotFound;
        }
        // ThrottlingException and InternalServiceError are transient; retry may succeed.
        // All other service errors (InvalidParameterException, InvalidRequestException,
        // DecryptionFailure, auth failures) are permanent.
        let code = svc.meta().code().unwrap_or("");
        if code == "ThrottlingException"
            || code == "RequestThrottledException"
            || svc.is_internal_service_error()
        {
            return SecretError::Unavailable {
                backend: BACKEND,
                source: format!("{svc}").into(),
            };
        }
        return SecretError::Backend {
            backend: BACKEND,
            source: format!("{svc}").into(),
        };
    }
    // Network failure, timeout, dispatch error — transient; retry is appropriate.
    SecretError::Unavailable {
        backend: BACKEND,
        source: e.into(),
    }
}

/// Map a `PutSecretValueError` to `SecretError`.
fn map_put_error(e: SdkError<PutSecretValueError>) -> SecretError {
    if let Some(svc) = e.as_service_error() {
        if svc.is_resource_not_found_exception() {
            return SecretError::NotFound;
        }
        // ThrottlingException and InternalServiceError are transient; retry may succeed.
        // All other service errors are permanent.
        let code = svc.meta().code().unwrap_or("");
        if code == "ThrottlingException"
            || code == "RequestThrottledException"
            || svc.is_internal_service_error()
        {
            return SecretError::Unavailable {
                backend: BACKEND,
                source: format!("{svc}").into(),
            };
        }
        return SecretError::Backend {
            backend: BACKEND,
            source: format!("{svc}").into(),
        };
    }
    // Network failure, timeout, dispatch error — transient; retry is appropriate.
    SecretError::Unavailable {
        backend: BACKEND,
        source: e.into(),
    }
}

/// Fetch a secret value from Secrets Manager and return it as `SecretValue`.
///
/// Handles both `secret_string` and `secret_binary` responses. If `field` is
/// set, extracts that JSON string field from the secret string.
async fn fetch(
    client: &aws_sdk_secretsmanager::Client,
    name: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    let resp = client
        .get_secret_value()
        .secret_id(name)
        .send()
        .await
        .map_err(map_get_error)?;

    if let Some(s) = resp.secret_string() {
        match field {
            Some(f) => {
                let json: serde_json::Value = serde_json::from_str(s).map_err(|e| {
                    SecretError::DecodeFailed(format!(
                        "aws-sm: ?field= requires a JSON string secret: {e}"
                    ))
                })?;
                let val = json.get(f).and_then(|v| v.as_str()).ok_or_else(|| {
                    SecretError::DecodeFailed(format!(
                        "aws-sm: field '{f}' not found or not a string"
                    ))
                })?;
                Ok(SecretValue::new(val.as_bytes().to_vec()))
            }
            None => Ok(SecretValue::new(s.as_bytes().to_vec())),
        }
    } else if let Some(blob) = resp.secret_binary() {
        Ok(SecretValue::new(blob.as_ref().to_vec()))
    } else {
        Err(SecretError::Backend {
            backend: BACKEND,
            source: "response contained neither secret_string nor secret_binary".into(),
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for AwsSmBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        fetch(&self.client, &self.name, self.field.as_deref()).await
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for AwsSmBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        // A field selector (?field=name) tells get() to extract one JSON field from
        // the full secret.  put() would need to read-modify-write the whole secret
        // to update just that field — risking races with concurrent writers and
        // corrupting other fields on any error.  Return an explicit error so callers
        // discover the limitation immediately rather than silently corrupting secrets.
        if self.field.is_some() {
            return Err(SecretError::InvalidUri(
                "put() requires a URI without a field selector (?field=); \
                 to update the whole secret omit ?field=, or implement read-modify-write \
                 at the call site"
                    .into(),
            ));
        }
        // Prefer secret_string for valid UTF-8 so the AWS console shows
        // the value in plaintext; fall back to secret_binary for arbitrary bytes.
        let bytes: &[u8] = value.as_bytes();
        match std::str::from_utf8(bytes) {
            Ok(s) => {
                self.client
                    .put_secret_value()
                    .secret_id(&self.name)
                    .secret_string(s)
                    .send()
                    .await
                    .map_err(map_put_error)?;
            }
            Err(_) => {
                // ZEROIZATION GAP: Blob::new copies bytes into SDK-owned heap
                // without Zeroizing. The secretx SecretValue is zeroed on drop
                // but the Blob copy is not. Full protection requires the AWS SDK
                // to support Zeroizing buffers, which it currently does not.
                let blob = aws_sdk_secretsmanager::primitives::Blob::new(bytes.to_vec());
                self.client
                    .put_secret_value()
                    .secret_id(&self.name)
                    .secret_binary(blob)
                    .send()
                    .await
                    .map_err(map_put_error)?;
            }
        }
        Ok(())
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "aws-sm",
    factory: |uri: &str| {
        AwsSmBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "aws-sm",
    factory: |uri: &str| {
        AwsSmBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // URI parsing tests — no AWS connection required.

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            AwsSmBackend::from_uri("secretx:env:FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        // "secretx:aws-sm" has no path component.
        assert!(matches!(
            AwsSmBackend::from_uri("secretx:aws-sm"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        assert!(matches!(
            AwsSmBackend::from_uri("https://aws-sm/foo"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // put() field-selector guard — no AWS connection needed (returns before any network call).
    #[tokio::test]
    async fn put_with_field_selector_returns_invalid_uri_unit() {
        let store = AwsSmBackend::from_uri("secretx:aws-sm:my-secret?field=password").unwrap();
        let result = store.put(SecretValue::new(b"new-value".to_vec())).await;
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "put with field selector must return InvalidUri (got: {:?})",
            result.err()
        );
    }

    // Integration tests — skipped unless SECRETX_AWS_SM_TEST_SECRET is set.

    #[tokio::test]
    async fn integration_get() {
        let name = match std::env::var("SECRETX_AWS_SM_TEST_SECRET") {
            Ok(n) => n,
            Err(_) => return,
        };
        let store = AwsSmBackend::from_uri(&format!("secretx:aws-sm:{name}")).unwrap();
        let value = store.get().await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_refresh() {
        let name = match std::env::var("SECRETX_AWS_SM_TEST_SECRET") {
            Ok(n) => n,
            Err(_) => return,
        };
        let store = AwsSmBackend::from_uri(&format!("secretx:aws-sm:{name}")).unwrap();
        let value = store.refresh().await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_field_extraction() {
        let name = match std::env::var("SECRETX_AWS_SM_TEST_SECRET_JSON") {
            Ok(n) => n,
            Err(_) => return,
        };
        let field = match std::env::var("SECRETX_AWS_SM_TEST_FIELD") {
            Ok(f) => f,
            Err(_) => return,
        };
        let store =
            AwsSmBackend::from_uri(&format!("secretx:aws-sm:{name}?field={field}")).unwrap();
        let value = store.get().await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn put_with_field_selector_returns_invalid_uri() {
        let name = match std::env::var("SECRETX_AWS_SM_TEST_SECRET_JSON") {
            Ok(n) => n,
            Err(_) => return,
        };
        let field = match std::env::var("SECRETX_AWS_SM_TEST_FIELD") {
            Ok(f) => f,
            Err(_) => return,
        };
        let store =
            AwsSmBackend::from_uri(&format!("secretx:aws-sm:{name}?field={field}")).unwrap();
        let result = store.put(SecretValue::new(b"new-value".to_vec())).await;
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "put with field selector must return InvalidUri"
        );
    }
}
