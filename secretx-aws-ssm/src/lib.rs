//! AWS Systems Manager Parameter Store backend for secretx.
//!
//! URI: `secretx://aws-ssm/<parameter_name>`
//!
//! For absolute SSM paths (starting with `/`), use the double-slash encoding:
//!
//! ```text
//! secretx://aws-ssm//prod/db/password   →  SSM parameter "/prod/db/password"
//! secretx://aws-ssm/my-param            →  SSM parameter "my-param"
//! ```
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_aws_ssm::AwsSsmBackend;
//! use secretx_core::SecretStore;
//!
//! let store = AwsSsmBackend::from_uri("secretx://aws-ssm//prod/db/password").await?;
//! let value = store.get("ignored").await?;
//! # Ok(())
//! # }
//! ```

use aws_sdk_ssm::types::ParameterType;
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};

/// Backend that reads and writes AWS SSM Parameter Store parameters.
///
/// Parameters are fetched with decryption enabled (`SecureString` type).
/// `put` writes a `SecureString` parameter (requires `ssm:PutParameter` permission).
pub struct AwsSsmBackend {
    client: aws_sdk_ssm::Client,
    path: String,
}

/// Build an SSM client by loading AWS config from the environment.
///
/// Spawns a scoped thread with its own single-threaded tokio runtime so this
/// function is safe to call from both inside and outside an existing runtime.
fn build_ssm_client() -> Result<aws_sdk_ssm::Client, SecretError> {
    let mut result = None;
    std::thread::scope(|s| {
        let r = s.spawn(|| -> Result<aws_sdk_ssm::Client, SecretError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| SecretError::Backend {
                    backend: "aws-ssm",
                    source: e.into(),
                })?;
            let cfg = rt.block_on(aws_config::load_from_env());
            Ok(aws_sdk_ssm::Client::new(&cfg))
        });
        result = Some(r.join().unwrap_or_else(|_| {
            Err(SecretError::Backend {
                backend: "aws-ssm",
                source: "client init thread panicked".into(),
            })
        }));
    });
    result.unwrap()
}

impl AwsSsmBackend {
    /// Construct from a `secretx://aws-ssm/<path>` URI.
    ///
    /// Validates the URI and builds the AWS SSM client by loading credentials
    /// from the environment. No network calls are made beyond credential
    /// loading.
    pub async fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "aws-ssm" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `aws-ssm`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "aws-ssm URI requires a parameter name: secretx://aws-ssm/<name>".into(),
            ));
        }
        let client = build_ssm_client()?;
        Ok(Self {
            client,
            path: parsed.path,
        })
    }

    /// Construct synchronously (useful in non-async contexts or tests).
    ///
    /// Identical to [`from_uri`](Self::from_uri) but callable outside of an
    /// async runtime.
    pub fn from_uri_sync(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "aws-ssm" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `aws-ssm`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "aws-ssm URI requires a parameter name: secretx://aws-ssm/<name>".into(),
            ));
        }
        let client = build_ssm_client()?;
        Ok(Self {
            client,
            path: parsed.path,
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for AwsSsmBackend {
    /// Retrieve the SSM parameter, decrypting `SecureString` values.
    ///
    /// The `name` argument is ignored; the parameter path comes from the URI.
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        let resp = self
            .client
            .get_parameter()
            .name(&self.path)
            .with_decryption(true)
            .send()
            .await
            .map_err(|e| {
                if e.as_service_error()
                    .map(|se| se.is_parameter_not_found())
                    .unwrap_or(false)
                {
                    SecretError::NotFound
                } else {
                    SecretError::Unavailable {
                        backend: "aws-ssm",
                        source: e.into(),
                    }
                }
            })?;

        let value = resp
            .parameter
            .and_then(|p| p.value)
            .ok_or(SecretError::NotFound)?;

        Ok(SecretValue::new(value.into_bytes()))
    }

    /// Write or update the SSM parameter as a `SecureString`.
    ///
    /// The `name` argument is ignored; the parameter path comes from the URI.
    /// Returns `SecretError::Backend` if `value` is not valid UTF-8, since SSM
    /// parameter values are always strings.
    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        let s = std::str::from_utf8(value.as_bytes()).map_err(|_| SecretError::Backend {
            backend: "aws-ssm",
            source: "SSM parameter values must be valid UTF-8".into(),
        })?;

        self.client
            .put_parameter()
            .name(&self.path)
            .value(s)
            .r#type(ParameterType::SecureString)
            .overwrite(true)
            .send()
            .await
            .map_err(|e| SecretError::Unavailable {
                backend: "aws-ssm",
                source: e.into(),
            })?;

        Ok(())
    }

    /// Force re-fetch of the SSM parameter (bypasses any caller-side cache).
    ///
    /// The `name` argument is ignored; the parameter path comes from the URI.
    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing tests (no AWS credentials needed) ────────────────────────

    #[test]
    fn from_uri_sync_simple_name() {
        let b = AwsSsmBackend::from_uri_sync("secretx://aws-ssm/my-param").unwrap();
        assert_eq!(b.path, "my-param");
    }

    #[test]
    fn from_uri_sync_absolute_path() {
        let b =
            AwsSsmBackend::from_uri_sync("secretx://aws-ssm//prod/db/password").unwrap();
        assert_eq!(b.path, "/prod/db/password");
    }

    #[test]
    fn from_uri_sync_wrong_backend() {
        assert!(matches!(
            AwsSsmBackend::from_uri_sync("secretx://aws-sm/my-param"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_sync_wrong_scheme() {
        assert!(matches!(
            AwsSsmBackend::from_uri_sync("https://ssm.amazonaws.com/my-param"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_sync_empty_path() {
        assert!(matches!(
            AwsSsmBackend::from_uri_sync("secretx://aws-ssm"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_sync_hierarchical_relative() {
        let b =
            AwsSsmBackend::from_uri_sync("secretx://aws-ssm/team/service/api-key").unwrap();
        assert_eq!(b.path, "team/service/api-key");
    }

    // ── Integration tests (require live AWS credentials + env var) ───────────

    fn integration_param() -> Option<String> {
        std::env::var("SECRETX_AWS_SSM_TEST_PARAM").ok()
    }

    #[tokio::test]
    async fn integration_get_existing_param() {
        let Some(param) = integration_param() else {
            return;
        };
        let uri = format!("secretx://aws-ssm/{param}");
        let store = AwsSsmBackend::from_uri(&uri).await.expect("from_uri");
        let value = store.get("ignored").await.expect("get");
        assert!(!value.as_bytes().is_empty(), "returned value should be non-empty");
    }

    #[tokio::test]
    async fn integration_get_missing_param() {
        if integration_param().is_none() {
            return;
        }
        let store = AwsSsmBackend::from_uri(
            "secretx://aws-ssm/secretx-test-surely-does-not-exist-xyzzy99",
        )
        .await
        .expect("from_uri");
        assert!(
            matches!(store.get("ignored").await, Err(SecretError::NotFound)),
            "expected NotFound for a nonexistent parameter"
        );
    }

    #[tokio::test]
    async fn integration_refresh_returns_value() {
        let Some(param) = integration_param() else {
            return;
        };
        let uri = format!("secretx://aws-ssm/{param}");
        let store = AwsSsmBackend::from_uri(&uri).await.expect("from_uri");
        let value = store.refresh("ignored").await.expect("refresh");
        assert!(!value.as_bytes().is_empty());
    }
}
