//! HashiCorp Vault KV v2 backend for secretx.
//!
//! URI: `secretx://vault/<mount>/<secret-path>[?field=<json_field>&addr=<vault_addr>]`
//!
//! - `mount` — KV v2 mount point, e.g. `secret`
//! - `secret-path` — path within the mount, e.g. `prod/api-key`
//! - `field` — (optional) extract a single JSON string field from the secret data
//! - `addr` — (optional) Vault server address; defaults to `VAULT_ADDR` env var,
//!   then `http://127.0.0.1:8200`
//!
//! `VAULT_TOKEN` must be set in the environment; `from_uri` returns
//! [`SecretError::Unavailable`] if it is absent.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_hashicorp_vault::VaultBackend;
//! use secretx_core::SecretStore;
//!
//! let store = VaultBackend::from_uri("secretx://vault/secret/prod/api-key?field=token")?;
//! let value = store.get("ignored").await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;

/// Backend that reads and writes secrets in a HashiCorp Vault KV v2 engine.
pub struct VaultBackend {
    client: VaultClient,
    mount: String,
    secret_path: String,
    /// When set, extract this JSON string field from the KV data map.
    field: Option<String>,
}

fn build_vault_client(addr: &str, token: &str) -> Result<VaultClient, SecretError> {
    VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(addr)
            .token(token)
            .build()
            .map_err(|e| SecretError::InvalidUri(format!("vault client config: {e}")))?,
    )
    .map_err(|e| SecretError::Backend {
        backend: "vault",
        source: e.into(),
    })
}

fn map_client_error(e: ClientError) -> SecretError {
    if let ClientError::APIError { code: 404, .. } = e {
        return SecretError::NotFound;
    }
    SecretError::Backend {
        backend: "vault",
        source: e.into(),
    }
}

impl VaultBackend {
    /// Construct from a `secretx://vault/<mount>/<path>` URI.
    ///
    /// Reads `VAULT_TOKEN` from the environment — returns
    /// [`SecretError::Unavailable`] if absent.
    ///
    /// No network calls are made during construction.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "vault" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `vault`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "vault URI requires a path: secretx://vault/<mount>/<path>".into(),
            ));
        }

        let (mount, secret_path) = match parsed.path.find('/') {
            Some(i) => (
                parsed.path[..i].to_string(),
                parsed.path[i + 1..].to_string(),
            ),
            None => {
                return Err(SecretError::InvalidUri(
                    "vault URI must be secretx://vault/<mount>/<path>".into(),
                ))
            }
        };

        if secret_path.is_empty() {
            return Err(SecretError::InvalidUri(
                "vault secret path cannot be empty".into(),
            ));
        }

        let addr = parsed
            .param("addr")
            .map(|s| s.to_string())
            .or_else(|| std::env::var("VAULT_ADDR").ok())
            .unwrap_or_else(|| "http://127.0.0.1:8200".to_string());

        let token = std::env::var("VAULT_TOKEN").map_err(|_| SecretError::Unavailable {
            backend: "vault",
            source: "VAULT_TOKEN env var not set".into(),
        })?;

        let field = parsed.param("field").map(|s| s.to_string());
        let client = build_vault_client(&addr, &token)?;

        Ok(Self {
            client,
            mount,
            secret_path,
            field,
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for VaultBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        let data: serde_json::Map<String, serde_json::Value> =
            vaultrs::kv2::read(&self.client, &self.mount, &self.secret_path)
                .await
                .map_err(map_client_error)?;

        let value = if let Some(field) = &self.field {
            match data.get(field) {
                Some(serde_json::Value::String(s)) => SecretValue::new(s.as_bytes().to_vec()),
                Some(_) => {
                    return Err(SecretError::DecodeFailed(format!(
                        "field `{field}` is not a string"
                    )))
                }
                None => {
                    return Err(SecretError::DecodeFailed(format!(
                        "field `{field}` not found in secret"
                    )))
                }
            }
        } else {
            SecretValue::new(
                serde_json::to_string(&data)
                    .map_err(|e| SecretError::Backend {
                        backend: "vault",
                        source: e.into(),
                    })?
                    .into_bytes(),
            )
        };
        Ok(value)
    }

    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        let s = std::str::from_utf8(value.as_bytes()).map_err(|_| {
            SecretError::DecodeFailed("secret value is not valid UTF-8".into())
        })?;

        let key = self.field.as_deref().unwrap_or("value");
        let data: HashMap<&str, &str> = HashMap::from([(key, s)]);

        vaultrs::kv2::set(&self.client, &self.mount, &self.secret_path, &data)
            .await
            .map_err(map_client_error)?;

        Ok(())
    }

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing (no Vault server required) ────────────────────────────────

    #[test]
    fn from_uri_wrong_backend() {
        // Ensure VAULT_TOKEN is set so the only failure is backend mismatch.
        // If VAULT_TOKEN is absent we still get an error, just a different one —
        // both outcomes satisfy the assertion.
        let result = VaultBackend::from_uri("secretx://aws-sm/secret/foo");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_missing_mount_slash() {
        // No slash means no mount/path split — invalid.
        // VAULT_TOKEN absence would return Unavailable before reaching this
        // check, so gate the test.
        if std::env::var("VAULT_TOKEN").is_err() {
            return;
        }
        let result = VaultBackend::from_uri("secretx://vault/nosuchpath");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_empty_secret_path() {
        if std::env::var("VAULT_TOKEN").is_err() {
            return;
        }
        let result = VaultBackend::from_uri("secretx://vault/secret/");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_missing_vault_token() {
        if std::env::var("VAULT_TOKEN").is_ok() {
            return; // skip if token is present
        }
        let result = VaultBackend::from_uri("secretx://vault/secret/foo");
        assert!(matches!(result, Err(SecretError::Unavailable { .. })));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        let result = VaultBackend::from_uri("https://vault.example.com/secret/foo");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_empty_path() {
        let result = VaultBackend::from_uri("secretx://vault");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    // ── Integration tests (require live Vault + env vars) ────────────────────

    fn integration_enabled() -> bool {
        std::env::var("SECRETX_VAULT_TEST").is_ok()
            && std::env::var("VAULT_TOKEN").is_ok()
    }

    #[tokio::test]
    async fn integration_put_and_get() {
        if !integration_enabled() {
            return;
        }
        let backend =
            VaultBackend::from_uri("secretx://vault/secret/secretx-test/simple?field=val")
                .expect("from_uri failed");

        let written = b"hello-vault";
        backend
            .put("ignored", SecretValue::new(written.to_vec()))
            .await
            .expect("put failed");

        let read = backend.get("ignored").await.expect("get failed");
        assert_eq!(read.as_bytes(), written);
    }

    #[tokio::test]
    async fn integration_get_full_json() {
        if !integration_enabled() {
            return;
        }
        // Write a secret with multiple fields first.
        let setup =
            VaultBackend::from_uri("secretx://vault/secret/secretx-test/json?field=alpha")
                .expect("from_uri failed");
        setup
            .put("ignored", SecretValue::new(b"aaa".to_vec()))
            .await
            .expect("setup put failed");

        // Read without field — expect JSON.
        let backend = VaultBackend::from_uri("secretx://vault/secret/secretx-test/json")
            .expect("from_uri failed");
        let raw = backend.get("ignored").await.expect("get failed");
        let json: serde_json::Value =
            serde_json::from_slice(raw.as_bytes()).expect("not valid JSON");
        assert!(json.is_object(), "expected JSON object");
    }

    #[tokio::test]
    async fn integration_get_not_found() {
        if !integration_enabled() {
            return;
        }
        let backend =
            VaultBackend::from_uri("secretx://vault/secret/secretx-test/does-not-exist-xyzzy")
                .expect("from_uri failed");
        let result = backend.get("ignored").await;
        assert!(
            matches!(result, Err(SecretError::NotFound)),
            "expected NotFound"
        );
    }

    #[tokio::test]
    async fn integration_refresh_same_as_get() {
        if !integration_enabled() {
            return;
        }
        let backend =
            VaultBackend::from_uri("secretx://vault/secret/secretx-test/simple?field=val")
                .expect("from_uri failed");

        backend
            .put("ignored", SecretValue::new(b"refresh-test".to_vec()))
            .await
            .expect("put failed");

        let v1 = backend.get("ignored").await.expect("get failed");
        let v2 = backend.refresh("ignored").await.expect("refresh failed");
        assert_eq!(v1.as_bytes(), v2.as_bytes());
    }
}
