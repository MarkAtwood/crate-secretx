//! AWS Secrets Manager backend for secretx.
//!
//! URI: `secretx://aws-sm/<name>[?field=<json_field>]`
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_aws_sm::AwsSmBackend;
//! use secretx_core::SecretStore;
//!
//! let store = AwsSmBackend::from_uri("secretx://aws-sm/prod/my-secret")?;
//! let value = store.get("prod/my-secret").await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use aws_sdk_secretsmanager::error::SdkError;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use aws_sdk_secretsmanager::operation::put_secret_value::PutSecretValueError;
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use zeroize::Zeroizing;

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
    /// Construct from a `secretx://aws-sm/<name>[?field=<json_field>]` URI.
    ///
    /// Loads AWS configuration from the environment (region, credentials) at
    /// construction time. This is a synchronous call that internally spins up a
    /// short-lived tokio runtime on a scoped thread so it is safe to call from
    /// both inside and outside an existing tokio runtime.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "aws-sm URI requires a secret name: secretx://aws-sm/<name>".into(),
            ));
        }
        let name = parsed.path.clone();
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
/// Uses a scoped thread with its own single-threaded tokio runtime so this
/// works correctly whether or not the caller is already inside a tokio runtime.
fn build_client() -> Result<aws_sdk_secretsmanager::Client, SecretError> {
    let mut result: Option<Result<aws_sdk_secretsmanager::Client, SecretError>> = None;
    std::thread::scope(|s| {
        let join = s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| SecretError::Backend {
                    backend: BACKEND,
                    source: e.into(),
                })
                .map(|rt| {
                    rt.block_on(async {
                        let config = aws_config::load_from_env().await;
                        aws_sdk_secretsmanager::Client::new(&config)
                    })
                })
        });
        result = Some(join.join().unwrap_or_else(|_| {
            Err(SecretError::Backend {
                backend: BACKEND,
                source: "client init thread panicked".into(),
            })
        }));
    });
    result.expect("scope always sets result before exiting")
}

/// Map a `GetSecretValueError` to `SecretError`.
fn map_get_error(e: SdkError<GetSecretValueError>) -> SecretError {
    if let SdkError::ServiceError(ref se) = e {
        if se.err().is_resource_not_found_exception() {
            return SecretError::NotFound;
        }
    }
    SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    }
}

/// Map a `PutSecretValueError` to `SecretError`.
fn map_put_error(e: SdkError<PutSecretValueError>) -> SecretError {
    if let SdkError::ServiceError(ref se) = e {
        if se.err().is_resource_not_found_exception() {
            return SecretError::NotFound;
        }
    }
    SecretError::Backend {
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

    let value = if let Some(s) = resp.secret_string() {
        SecretValue::new(s.as_bytes().to_vec())
    } else if let Some(blob) = resp.secret_binary() {
        SecretValue::new(blob.as_ref().to_vec())
    } else {
        return Err(SecretError::Backend {
            backend: BACKEND,
            source: "response contained neither secret_string nor secret_binary".into(),
        });
    };

    match field {
        Some(f) => value.extract_field(f),
        None => Ok(value),
    }
}

#[async_trait::async_trait]
impl SecretStore for AwsSmBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        fetch(&self.client, &self.name, self.field.as_deref()).await
    }

    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
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
                let zv = Zeroizing::new(bytes.to_vec());
                let blob = aws_sdk_secretsmanager::primitives::Blob::new(zv.as_slice());
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

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // URI parsing tests — no AWS connection required.

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            AwsSmBackend::from_uri("secretx://env/FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        // "secretx://aws-sm" has no path component.
        assert!(matches!(
            AwsSmBackend::from_uri("secretx://aws-sm"),
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

    // Integration tests — skipped unless SECRETX_AWS_SM_TEST_SECRET is set.

    #[tokio::test]
    async fn integration_get() {
        let name = match std::env::var("SECRETX_AWS_SM_TEST_SECRET") {
            Ok(n) => n,
            Err(_) => return,
        };
        let store = AwsSmBackend::from_uri(&format!("secretx://aws-sm/{name}")).unwrap();
        let value = store.get(&name).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_refresh() {
        let name = match std::env::var("SECRETX_AWS_SM_TEST_SECRET") {
            Ok(n) => n,
            Err(_) => return,
        };
        let store = AwsSmBackend::from_uri(&format!("secretx://aws-sm/{name}")).unwrap();
        let value = store.refresh(&name).await.unwrap();
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
            AwsSmBackend::from_uri(&format!("secretx://aws-sm/{name}?field={field}")).unwrap();
        let value = store.get(&name).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}
