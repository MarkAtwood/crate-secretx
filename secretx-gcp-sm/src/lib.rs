//! GCP Secret Manager backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without credentials.
//! Live integration tests require a GCP project with the Secret Manager API
//! enabled. Set `SECRETX_GCP_TEST=1` and `GCP_ACCESS_TOKEN` to enable them.
//! **Not yet integration-tested.**
//!
//! URI: `secretx://gcp-sm/<project>/<secret>[?version=<version>]`
//!
//! - `project` — GCP project ID
//! - `secret`  — secret name in Secret Manager
//! - `version` — secret version (default: `latest`)
//!
//! Requires `GCP_ACCESS_TOKEN` to be set in the environment at construction
//! time. Obtain a token with `gcloud auth print-access-token` or by another
//! OAuth2 flow appropriate to your environment.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_gcp_sm::GcpSmBackend;
//! use secretx_core::SecretStore;
//!
//! let store = GcpSmBackend::from_uri("secretx://gcp-sm/my-project/my-secret")?;
//! let value = store.get("my-secret").await?;
//! # Ok(())
//! # }
//! ```

use base64::Engine as _;
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use zeroize::Zeroizing;

const BACKEND: &str = "gcp-sm";
const BASE_URL: &str = "https://secretmanager.googleapis.com/v1";

/// Backend that reads and writes secrets in GCP Secret Manager via REST.
///
/// Construct with [`from_uri`](GcpSmBackend::from_uri). Reads the GCP access
/// token from `GCP_ACCESS_TOKEN` at construction time.
pub struct GcpSmBackend {
    client: reqwest::Client,
    project: String,
    secret: String,
    version: String,
    access_token: Zeroizing<String>,
}

impl GcpSmBackend {
    /// Construct from a `secretx://gcp-sm/<project>/<secret>[?version=<ver>]` URI.
    ///
    /// Reads `GCP_ACCESS_TOKEN` from the environment. Does not contact GCP —
    /// construction validates the URI and token presence only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend
            )));
        }

        let (project, secret) = split_project_secret(&parsed.path).ok_or_else(|| {
            SecretError::InvalidUri("gcp-sm URI must be secretx://gcp-sm/<project>/<secret>".into())
        })?;

        let version = parsed.param("version").unwrap_or("latest").to_string();

        let access_token =
            std::env::var("GCP_ACCESS_TOKEN").map_err(|_| SecretError::Unavailable {
                backend: BACKEND,
                source: "GCP_ACCESS_TOKEN env var not set".into(),
            })?;

        Ok(Self {
            client: reqwest::Client::new(),
            project,
            secret,
            version,
            access_token: Zeroizing::new(access_token),
        })
    }
}

/// Split `"<project>/<secret>"` into `(project, secret)`.
///
/// Returns `None` if either component is empty.
fn split_project_secret(path: &str) -> Option<(String, String)> {
    let slash = path.find('/')?;
    let project = &path[..slash];
    let secret = &path[slash + 1..];
    if project.is_empty() || secret.is_empty() {
        return None;
    }
    // secret must not contain a '/' (only one slash allowed in path)
    if secret.contains('/') {
        return None;
    }
    Some((project.to_string(), secret.to_string()))
}

/// Build the REST URL for accessing a secret version.
fn access_url(project: &str, secret: &str, version: &str) -> String {
    format!("{BASE_URL}/projects/{project}/secrets/{secret}/versions/{version}:access")
}

/// Build the REST URL for adding a new secret version.
fn add_version_url(project: &str, secret: &str) -> String {
    format!("{BASE_URL}/projects/{project}/secrets/{secret}:addSecretVersion")
}

#[async_trait::async_trait]
impl SecretStore for GcpSmBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        let url = access_url(&self.project, &self.secret, &self.version);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(self.access_token.as_str())
            .send()
            .await
            .map_err(|e| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;

        if resp.status() == 404 {
            return Err(SecretError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: format!("HTTP {}", resp.status()).into(),
            });
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        })?;

        let data_b64 = json["payload"]["data"]
            .as_str()
            .ok_or_else(|| SecretError::DecodeFailed("gcp-sm: missing payload.data".into()))?;

        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| SecretError::DecodeFailed(format!("gcp-sm: base64 decode: {e}")))?;

        Ok(SecretValue::new(data))
    }

    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        let body = serde_json::json!({
            "payload": {
                "data": encoded,
            }
        });

        let url = add_version_url(&self.project, &self.secret);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(self.access_token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;

        if resp.status() == 404 {
            return Err(SecretError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: format!("HTTP {}", resp.status()).into(),
            });
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

    // URI parsing unit tests — no GCP connection required.

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            GcpSmBackend::from_uri("secretx://env/FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        assert!(matches!(
            GcpSmBackend::from_uri("https://gcp-sm/proj/secret"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        assert!(matches!(
            GcpSmBackend::from_uri("secretx://gcp-sm"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_secret() {
        // Only project, no secret.
        assert!(matches!(
            GcpSmBackend::from_uri("secretx://gcp-sm/myproject"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_token() {
        // Only run this test when GCP_ACCESS_TOKEN is not set.
        if std::env::var("GCP_ACCESS_TOKEN").is_ok() {
            return;
        }
        assert!(matches!(
            GcpSmBackend::from_uri("secretx://gcp-sm/my-project/my-secret"),
            Err(SecretError::Unavailable { .. })
        ));
    }

    #[test]
    fn split_project_secret_ok() {
        let (p, s) = split_project_secret("my-project/my-secret").unwrap();
        assert_eq!(p, "my-project");
        assert_eq!(s, "my-secret");
    }

    #[test]
    fn split_project_secret_no_slash() {
        assert!(split_project_secret("onlyone").is_none());
    }

    #[test]
    fn split_project_secret_empty_secret() {
        assert!(split_project_secret("project/").is_none());
    }

    #[test]
    fn split_project_secret_extra_slash() {
        // More than one slash is not allowed.
        assert!(split_project_secret("project/secret/extra").is_none());
    }

    #[test]
    fn access_url_default_version() {
        let url = access_url("my-project", "my-secret", "latest");
        assert_eq!(
            url,
            "https://secretmanager.googleapis.com/v1/projects/my-project/secrets/my-secret/versions/latest:access"
        );
    }

    #[test]
    fn access_url_explicit_version() {
        let url = access_url("my-project", "my-secret", "3");
        assert_eq!(
            url,
            "https://secretmanager.googleapis.com/v1/projects/my-project/secrets/my-secret/versions/3:access"
        );
    }

    // Integration tests — skipped unless both GCP_ACCESS_TOKEN and
    // SECRETX_GCP_TEST=1 are set.

    #[tokio::test]
    async fn integration_get() {
        if std::env::var("SECRETX_GCP_TEST").is_err() || std::env::var("GCP_ACCESS_TOKEN").is_err()
        {
            return;
        }
        let project = std::env::var("GCP_PROJECT").unwrap_or_else(|_| "my-project".into());
        let secret = std::env::var("GCP_SECRET_NAME").unwrap_or_else(|_| "my-secret".into());
        let uri = format!("secretx://gcp-sm/{project}/{secret}");
        let store = GcpSmBackend::from_uri(&uri).unwrap();
        let value = store.get(&secret).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_refresh() {
        if std::env::var("SECRETX_GCP_TEST").is_err() || std::env::var("GCP_ACCESS_TOKEN").is_err()
        {
            return;
        }
        let project = std::env::var("GCP_PROJECT").unwrap_or_else(|_| "my-project".into());
        let secret = std::env::var("GCP_SECRET_NAME").unwrap_or_else(|_| "my-secret".into());
        let uri = format!("secretx://gcp-sm/{project}/{secret}");
        let store = GcpSmBackend::from_uri(&uri).unwrap();
        let value = store.refresh(&secret).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_get_explicit_version() {
        if std::env::var("SECRETX_GCP_TEST").is_err() || std::env::var("GCP_ACCESS_TOKEN").is_err()
        {
            return;
        }
        let project = std::env::var("GCP_PROJECT").unwrap_or_else(|_| "my-project".into());
        let secret = std::env::var("GCP_SECRET_NAME").unwrap_or_else(|_| "my-secret".into());
        let uri = format!("secretx://gcp-sm/{project}/{secret}?version=1");
        let store = GcpSmBackend::from_uri(&uri).unwrap();
        let value = store.get(&secret).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}
