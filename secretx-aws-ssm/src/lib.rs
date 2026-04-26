//! AWS Systems Manager Parameter Store backend for secretx.
//!
//! URI: `secretx:aws-ssm:<parameter_name>`
//!
//! Absolute SSM paths (starting with `/`) use a leading `/` in the path component:
//!
//! ```text
//! secretx:aws-ssm:/prod/db/password   →  SSM parameter "/prod/db/password"
//! secretx:aws-ssm:my-param            →  SSM parameter "my-param"
//! ```
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_aws_ssm::AwsSsmBackend;
//! use secretx_core::SecretStore;
//!
//! let store = AwsSsmBackend::from_uri("secretx:aws-ssm:/prod/db/password")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```

use aws_sdk_ssm::{
    error::SdkError,
    operation::{get_parameter::GetParameterError, put_parameter::PutParameterError},
    types::ParameterType,
};
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};

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
///
/// DO NOT replace this with `tokio::task::block_in_place` or `Handle::block_on`.
/// `block_in_place` panics when called from a `current_thread` runtime (the default
/// in `#[tokio::test]` and common in single-threaded services).  The scoped-thread
/// pattern works in every runtime configuration because the new thread owns its own
/// runtime — it never interacts with the caller's runtime at all.
fn build_ssm_client() -> Result<aws_sdk_ssm::Client, SecretError> {
    secretx_core::run_on_new_thread(
        || async {
            let cfg = aws_config::load_from_env().await;
            Ok(aws_sdk_ssm::Client::new(&cfg))
        },
        "aws-ssm",
    )
}

/// Map a `GetParameterError` to [`SecretError`].
fn map_get_error(e: SdkError<GetParameterError>) -> SecretError {
    let se = e.as_service_error();
    if se.map(|s| s.is_parameter_not_found()).unwrap_or(false) {
        // Parameter does not exist — the caller may create it.
        return SecretError::NotFound;
    }
    if se
        .map(|s| s.is_parameter_version_not_found())
        .unwrap_or(false)
    {
        // Parameter exists but the requested version was deleted.
        // The parameter itself is still there; NotFound would be a lie.
        return SecretError::Backend {
            backend: "aws-ssm",
            source: e.into(),
        };
    }
    if se.map(|s| s.is_invalid_key_id()).unwrap_or(false) {
        // KMS key ID in the parameter config is wrong — permanent.
        return SecretError::Backend {
            backend: "aws-ssm",
            source: e.into(),
        };
    }
    if se
        .and_then(|s| s.meta().code())
        .map(|c| c == "AccessDeniedException")
        .unwrap_or(false)
    {
        // IAM permission denied — permanent until IAM policy changes.
        return SecretError::Backend {
            backend: "aws-ssm",
            source: e.into(),
        };
    }
    // InternalServerError, throttling, network failures — transient.
    SecretError::Unavailable {
        backend: "aws-ssm",
        source: e.into(),
    }
}

/// Map a `PutParameterError` to [`SecretError`].
fn map_put_error(e: SdkError<PutParameterError>) -> SecretError {
    let se = e.as_service_error();
    if se
        .and_then(|s| s.meta().code())
        .map(|c| c == "ParameterNotFound")
        .unwrap_or(false)
    {
        // put_parameter with overwrite=true creates the parameter if absent, so
        // ParameterNotFound should not occur in practice.  Map defensively to
        // Backend (permanent — retrying will not create the parameter).
        return SecretError::Backend {
            backend: "aws-ssm",
            source: e.into(),
        };
    }
    if se.map(|s| s.is_invalid_key_id()).unwrap_or(false) {
        // KMS key ID in the parameter config is wrong — permanent.
        return SecretError::Backend {
            backend: "aws-ssm",
            source: e.into(),
        };
    }
    if se
        .and_then(|s| s.meta().code())
        .map(|c| c == "AccessDeniedException")
        .unwrap_or(false)
    {
        // IAM permission denied — permanent until IAM policy changes.
        return SecretError::Backend {
            backend: "aws-ssm",
            source: e.into(),
        };
    }
    if se
        .and_then(|s| s.meta().code())
        .map(|c| c == "ValidationException")
        .unwrap_or(false)
    {
        // Validation failure (e.g. value > 4096 bytes for SecureString) — permanent.
        return SecretError::Backend {
            backend: "aws-ssm",
            source: e.into(),
        };
    }
    // InternalServerError, throttling, network failures — transient.
    SecretError::Unavailable {
        backend: "aws-ssm",
        source: e.into(),
    }
}

impl AwsSsmBackend {
    /// Construct from a `secretx:aws-ssm:<path>` URI.
    ///
    /// Validates the URI and builds the AWS SSM client by loading credentials
    /// from the environment. No network calls are made beyond credential
    /// loading.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "aws-ssm" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `aws-ssm`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "aws-ssm URI requires a parameter name: secretx:aws-ssm:<name>".into(),
            ));
        }
        // SSM parameters are raw strings, not JSON objects — field extraction is
        // not supported.  Reject ?field= at construction time so callers get a
        // clear error instead of silently receiving the full raw value.
        if parsed.param("field").is_some() {
            return Err(SecretError::InvalidUri(
                "aws-ssm does not support ?field= (SSM parameters are raw strings, not JSON \
                 objects); remove ?field= or use a backend that supports field extraction \
                 (e.g. aws-sm)"
                    .into(),
            ));
        }
        let client = build_ssm_client()?;
        Ok(Self {
            client,
            path: parsed.path().to_owned(),
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for AwsSsmBackend {
    /// Retrieve the SSM parameter, decrypting `SecureString` values.
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let resp = self
            .client
            .get_parameter()
            .name(&self.path)
            .with_decryption(true)
            .send()
            .await
            .map_err(map_get_error)?;

        let value = resp
            .parameter
            .and_then(|p| p.value)
            .ok_or(SecretError::NotFound)?;

        Ok(SecretValue::new(value.into_bytes()))
    }

    /// Force re-fetch of the SSM parameter (bypasses any caller-side cache).
    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for AwsSsmBackend {
    /// Write or update the SSM parameter as a `SecureString`.
    ///
    /// Returns `SecretError::DecodeFailed` if `value` is not valid UTF-8, since SSM
    /// parameter values are always strings.
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let s = std::str::from_utf8(value.as_bytes()).map_err(|_| {
            SecretError::DecodeFailed("SSM parameter values must be valid UTF-8".into())
        })?;

        self.client
            .put_parameter()
            .name(&self.path)
            .value(s)
            .r#type(ParameterType::SecureString)
            .overwrite(true)
            .send()
            .await
            .map_err(map_put_error)?;

        Ok(())
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "aws-ssm",
    factory: |uri: &str| {
        AwsSsmBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "aws-ssm",
    factory: |uri: &str| {
        AwsSsmBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing tests (no AWS credentials needed) ────────────────────────

    #[test]
    fn from_uri_simple_name() {
        let b = AwsSsmBackend::from_uri("secretx:aws-ssm:my-param").unwrap();
        assert_eq!(b.path, "my-param");
    }

    #[test]
    fn from_uri_absolute_path() {
        let b = AwsSsmBackend::from_uri("secretx:aws-ssm:/prod/db/password").unwrap();
        assert_eq!(b.path, "/prod/db/password");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            AwsSsmBackend::from_uri("secretx:aws-sm:my-param"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        assert!(matches!(
            AwsSsmBackend::from_uri("https://ssm.amazonaws.com/my-param"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        assert!(matches!(
            AwsSsmBackend::from_uri("secretx:aws-ssm"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_field_selector_rejected() {
        // SSM parameters are raw strings; ?field= is not supported and must
        // be rejected at construction time rather than silently ignored.
        let result = AwsSsmBackend::from_uri("secretx:aws-ssm:my-param?field=password");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("aws-ssm does not support ?field="),
                    "error must mention the limitation, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    #[test]
    fn from_uri_hierarchical_relative() {
        let b = AwsSsmBackend::from_uri("secretx:aws-ssm:team/service/api-key").unwrap();
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
        let uri = format!("secretx:aws-ssm:{param}");
        let store = AwsSsmBackend::from_uri(&uri).expect("from_uri");
        let value = store.get().await.expect("get");
        assert!(
            !value.as_bytes().is_empty(),
            "returned value should be non-empty"
        );
    }

    #[tokio::test]
    async fn integration_get_missing_param() {
        if integration_param().is_none() {
            return;
        }
        let store =
            AwsSsmBackend::from_uri("secretx:aws-ssm:secretx-test-surely-does-not-exist-xyzzy99")
                .expect("from_uri");
        assert!(
            matches!(store.get().await, Err(SecretError::NotFound)),
            "expected NotFound for a nonexistent parameter"
        );
    }

    #[tokio::test]
    async fn integration_refresh_returns_value() {
        let Some(param) = integration_param() else {
            return;
        };
        let uri = format!("secretx:aws-ssm:{param}");
        let store = AwsSsmBackend::from_uri(&uri).expect("from_uri");
        let value = store.refresh().await.expect("refresh");
        assert!(!value.as_bytes().is_empty());
    }
}
