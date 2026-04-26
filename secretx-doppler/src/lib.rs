//! Doppler backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without credentials.
//! Live integration tests require a Doppler account and service token.
//! Set `SECRETX_DOPPLER_TEST=1` and `DOPPLER_TOKEN` to enable them.
//! **Not yet integration-tested.**
//!
//! URI: `secretx:doppler:<project>/<config>/<secret-name>`
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
//! let store = DopplerBackend::from_uri("secretx:doppler:myproject/prd/DB_PASSWORD")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Zeroization
//!
//! `DOPPLER_TOKEN` is stored as `Zeroizing<String>` and zeroed when this backend is dropped.
//! The raw HTTP response buffer from reqwest (`bytes::Bytes`) is **not** zeroed on drop —
//! this is unavoidable at the reqwest layer, and the secret content lands there before any
//! parsing begins.  Because the secret is already in non-Zeroizing heap memory at that point,
//! using `serde_json` to extract the value adds no additional unzeroed copies.  Only the final
//! `SecretValue` produced by `get` is zeroed on drop.
//! In `put`, the secret value is serialized into a `serde_json::Value` for the request body;
//! that intermediate allocation is not zeroed (unavoidable — the value must go over the wire).

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};
use zeroize::Zeroizing;

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
    // Zeroizing ensures the token is cleared from memory when the backend drops.
    token: Zeroizing<String>,
}

impl DopplerBackend {
    /// Construct from a `secretx:doppler:<project>/<config>/<name>` URI.
    ///
    /// Reads `DOPPLER_TOKEN` from the environment. Does not contact Doppler —
    /// construction only.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend()
            )));
        }

        let parts: Vec<&str> = parsed.path().splitn(3, '/').collect();
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            return Err(SecretError::InvalidUri(
                "doppler URI must be secretx:doppler:<project>/<config>/<name>".into(),
            ));
        }

        // Doppler secret values are raw strings fetched via the
        // `secrets.get` API — the response is always a single string, not a
        // JSON object.  ?field= extraction is not supported and would silently
        // return the full raw value, which is confusing.  Reject early.
        if parsed.param("field").is_some() {
            return Err(SecretError::InvalidUri(
                "doppler does not support ?field= (Doppler secret values are raw strings, not \
                 JSON objects); remove ?field= or use a backend that supports JSON field \
                 extraction (e.g. aws-sm)"
                    .into(),
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
            token: Zeroizing::new(token),
        })
    }
}

/// Map a non-successful HTTP status to the appropriate [`SecretError`].
///
/// 5xx codes and HTTP 429 Too Many Requests are transient (→ `Unavailable`);
/// all other non-2xx codes are permanent configuration/request errors (→ `Backend`).
fn map_http_status(status: reqwest::StatusCode, detail: &str) -> SecretError {
    let msg = if detail.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {detail}")
    };
    if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        SecretError::Unavailable {
            backend: BACKEND,
            source: msg.into(),
        }
    } else {
        SecretError::Backend {
            backend: BACKEND,
            source: msg.into(),
        }
    }
}

#[async_trait::async_trait]
impl SecretStore for DopplerBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let resp = self
            .client
            .get("https://api.doppler.com/v3/configs/config/secret")
            .bearer_auth(self.token.as_str())
            .query(&[
                ("project", &self.project),
                ("config", &self.config),
                ("name", &self.name),
            ])
            .send()
            .await
            .map_err(|e: reqwest::Error| {
                // Network-level failures (timeout, DNS, connection refused) are
                // transient — a retry may succeed after the network recovers.
                SecretError::Unavailable {
                    backend: BACKEND,
                    source: e.into(),
                }
            })?;

        let status = resp.status();
        if status == 404 {
            return Err(SecretError::NotFound);
        }
        if status == 401 || status == 403 {
            // Authentication/authorization failure — permanent until token or
            // permissions are fixed. Use Backend (not Unavailable) so callers
            // know that retrying will not help.
            let detail = resp.text().await.unwrap_or_default();
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: format!(
                    "HTTP {status} (check DOPPLER_TOKEN and project permissions){}",
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {detail}")
                    }
                )
                .into(),
            });
        }
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(map_http_status(status, &detail));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e: reqwest::Error| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;

        let json: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            SecretError::DecodeFailed(format!("doppler: invalid JSON response: {e}"))
        })?;
        let computed = json
            .get("secret")
            .and_then(|s| s.get("computed"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| {
                SecretError::DecodeFailed("doppler: missing secret.computed in response".into())
            })?;
        Ok(SecretValue::new(computed.as_bytes().to_vec()))
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for DopplerBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
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
            .bearer_auth(self.token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e: reqwest::Error| {
                // Network-level failures (timeout, DNS, connection refused) are
                // transient — a retry may succeed after the network recovers.
                SecretError::Unavailable {
                    backend: BACKEND,
                    source: e.into(),
                }
            })?;

        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(map_http_status(status, &detail));
        }
        Ok(())
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "doppler",
    factory: |uri: &str| {
        DopplerBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "doppler",
    factory: |uri: &str| {
        DopplerBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            DopplerBackend::from_uri("secretx:env:FOO"),
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
        // Path validation fires before DOPPLER_TOKEN is read, so this must
        // return InvalidUri regardless of whether the token is present.
        assert!(matches!(
            DopplerBackend::from_uri("secretx:doppler:myproject/prd"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        // No path at all.
        // Path validation fires before DOPPLER_TOKEN is read, so this must
        // return InvalidUri regardless of whether the token is present.
        assert!(matches!(
            DopplerBackend::from_uri("secretx:doppler"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_token() {
        if std::env::var("DOPPLER_TOKEN").is_ok() {
            return;
        }
        assert!(matches!(
            DopplerBackend::from_uri("secretx:doppler:myproject/prd/DB_PASSWORD"),
            Err(SecretError::Unavailable { .. })
        ));
    }

    #[test]
    fn map_http_status_429_is_unavailable() {
        let err = map_http_status(reqwest::StatusCode::TOO_MANY_REQUESTS, "rate limited");
        assert!(
            matches!(err, SecretError::Unavailable { .. }),
            "HTTP 429 must map to Unavailable (transient); got: {err:?}"
        );
    }

    #[test]
    fn from_uri_field_selector_rejected() {
        // Doppler values are raw strings; ?field= is not supported and must be
        // rejected before the token is read (so no DOPPLER_TOKEN needed).
        let result = DopplerBackend::from_uri("secretx:doppler:myproject/prd/DB_PASSWORD?field=pw");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("doppler does not support ?field="),
                    "error must mention the limitation, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    #[tokio::test]
    async fn integration_get() {
        if std::env::var("SECRETX_DOPPLER_TEST").is_err() {
            return;
        }
        let project = std::env::var("DOPPLER_PROJECT").unwrap_or_else(|_| "myproject".into());
        let config = std::env::var("DOPPLER_CONFIG").unwrap_or_else(|_| "prd".into());
        let name = std::env::var("DOPPLER_SECRET_NAME").unwrap_or_else(|_| "DB_PASSWORD".into());
        let uri = format!("secretx:doppler:{project}/{config}/{name}");
        let store = DopplerBackend::from_uri(&uri).unwrap();
        let value = store.get().await.unwrap();
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
        let uri = format!("secretx:doppler:{project}/{config}/{name}");
        let store = DopplerBackend::from_uri(&uri).unwrap();
        let value = store.refresh().await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}
