//! Doppler backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without credentials.
//! Live integration tests require a Doppler account and service token.
//! Set `SECRETX_DOPPLER_TEST=1` and `DOPPLER_TOKEN` to enable them.
//! **Not yet integration-tested.**
//!
//! URI: `secretx://doppler/<project>/<config>/<secret-name>`
//!
//! - `project` — Doppler project name
//! - `config`  — Doppler config name (e.g. `prd`, `dev`)
//! - `secret-name` — the secret key name
//!
//! Requires `DOPPLER_TOKEN` to be set in the environment at construction time.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_doppler::DopplerBackend;
//! use secretx_core::SecretStore;
//!
//! let store = DopplerBackend::from_uri("secretx://doppler/myproject/prd/DB_PASSWORD")?;
//! let value = store.get("DB_PASSWORD").await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};

const BACKEND: &str = "doppler";

/// Backend that reads and writes secrets in Doppler via the REST API.
///
/// Construct with [`from_uri`](DopplerBackend::from_uri). The Doppler token is
/// read from `DOPPLER_TOKEN` at construction time.
pub struct DopplerBackend {
    client: reqwest::Client,
    project: String,
    config: String,
    name: String,
    token: String,
}

impl DopplerBackend {
    /// Construct from a `secretx://doppler/<project>/<config>/<name>` URI.
    ///
    /// Reads `DOPPLER_TOKEN` from the environment. Does not contact Doppler —
    /// construction only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend
            )));
        }

        let parts: Vec<&str> = parsed.path.splitn(3, '/').collect();
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            return Err(SecretError::InvalidUri(
                "doppler URI must be secretx://doppler/<project>/<config>/<name>".into(),
            ));
        }

        let token = std::env::var("DOPPLER_TOKEN").map_err(|_| SecretError::Unavailable {
            backend: BACKEND,
            source: "DOPPLER_TOKEN env var not set".into(),
        })?;

        let client = reqwest::Client::new();
        Ok(Self {
            client,
            project: parts[0].to_string(),
            config: parts[1].to_string(),
            name: parts[2].to_string(),
            token,
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for DopplerBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        let resp = self
            .client
            .get("https://api.doppler.com/v3/configs/config/secret")
            .bearer_auth(&self.token)
            .query(&[
                ("project", &self.project),
                ("config", &self.config),
                ("name", &self.name),
            ])
            .send()
            .await
            .map_err(|e: reqwest::Error| SecretError::Backend {
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

        let json: serde_json::Value =
            resp.json().await.map_err(|e: reqwest::Error| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;

        let value = json["secret"]["computed"]
            .as_str()
            .ok_or_else(|| SecretError::DecodeFailed("doppler: missing secret.computed".into()))?;

        Ok(SecretValue::new(value.as_bytes().to_vec()))
    }

    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        let v = std::str::from_utf8(value.as_bytes())
            .map_err(|_| SecretError::DecodeFailed("doppler requires UTF-8 secret value".into()))?;

        let body = serde_json::json!({
            "project": self.project,
            "config": self.config,
            "name": self.name,
            "value": v,
        });

        let resp = self
            .client
            .post("https://api.doppler.com/v3/configs/config/secret")
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e: reqwest::Error| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;

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

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            DopplerBackend::from_uri("secretx://env/FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        assert!(matches!(
            DopplerBackend::from_uri("https://doppler/proj/cfg/name"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_path_parts() {
        // Only project and config, no name.
        if std::env::var("DOPPLER_TOKEN").is_err() {
            return;
        }
        assert!(matches!(
            DopplerBackend::from_uri("secretx://doppler/myproject/prd"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        // No path at all.
        if std::env::var("DOPPLER_TOKEN").is_err() {
            return;
        }
        assert!(matches!(
            DopplerBackend::from_uri("secretx://doppler"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_token() {
        if std::env::var("DOPPLER_TOKEN").is_ok() {
            return;
        }
        assert!(matches!(
            DopplerBackend::from_uri("secretx://doppler/myproject/prd/DB_PASSWORD"),
            Err(SecretError::Unavailable { .. })
        ));
    }

    #[tokio::test]
    async fn integration_get() {
        if std::env::var("SECRETX_DOPPLER_TEST").is_err() {
            return;
        }
        let project = std::env::var("DOPPLER_PROJECT").unwrap_or_else(|_| "myproject".into());
        let config = std::env::var("DOPPLER_CONFIG").unwrap_or_else(|_| "prd".into());
        let name = std::env::var("DOPPLER_SECRET_NAME").unwrap_or_else(|_| "DB_PASSWORD".into());
        let uri = format!("secretx://doppler/{project}/{config}/{name}");
        let store = DopplerBackend::from_uri(&uri).unwrap();
        let value = store.get(&name).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn integration_refresh() {
        if std::env::var("SECRETX_DOPPLER_TEST").is_err() {
            return;
        }
        let project = std::env::var("DOPPLER_PROJECT").unwrap_or_else(|_| "myproject".into());
        let config = std::env::var("DOPPLER_CONFIG").unwrap_or_else(|_| "prd".into());
        let name = std::env::var("DOPPLER_SECRET_NAME").unwrap_or_else(|_| "DB_PASSWORD".into());
        let uri = format!("secretx://doppler/{project}/{config}/{name}");
        let store = DopplerBackend::from_uri(&uri).unwrap();
        let value = store.refresh(&name).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}
