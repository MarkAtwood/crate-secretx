//! HashiCorp Vault KV v2 backend for secretx.
//!
//! URI: `secretx:vault:<mount>/<secret-path>[?field=<json_field>&addr=<vault_addr>]`
//!
//! - `mount` — KV v2 mount point, e.g. `secret`
//! - `secret-path` — path within the mount, e.g. `prod/api-key`
//! - `field` — optional. When set, `get` extracts a single JSON string field and `put`
//!   writes `{field: value}` as the KV data map (KV v2 creates a new version containing
//!   only that field — other fields in the previous version are not carried forward).
//!   Without `?field=`, `get` returns the full KV data map serialized as JSON and `put`
//!   accepts a JSON object string and writes it as the complete data map.
//! - `addr` — (optional) Vault server address; defaults to `VAULT_ADDR` env var,
//!   then `http://127.0.0.1:8200`
//!
//! # URI trust assumption
//!
//! `from_uri` trusts the URI, including the `addr=` parameter, completely.
//! **Do not construct URIs from untrusted input.** If `addr=` is attacker-
//! controlled, requests (including the `VAULT_TOKEN`) are sent to the attacker's
//! server (SSRF). URIs should come from admin-controlled configuration, not from
//! user input, database rows, or any other partially-trusted source.
//!
//! # Partial-update footgun
//!
//! `put` with `?field=` writes a **new KV v2 version** containing *only* the named
//! field. Vault has no field-level update operation; any other fields in the previous
//! version are not preserved. To update a multi-field secret atomically, omit `?field=`
//! and supply the complete JSON object to `put`.
//!
//! `VAULT_TOKEN` must be set in the environment; `from_uri` returns
//! [`SecretError::Unavailable`] if it is absent.
//!
//! # Token lifecycle
//!
//! `VAULT_TOKEN` is read once at construction time and cached for the lifetime
//! of the `VaultBackend` instance. Vault tokens expire (default TTL varies by
//! auth method; root tokens created with `vault token create` default to 32
//! days, service tokens are typically shorter). When the token expires, Vault
//! returns HTTP 403, which this backend maps to `SecretError::Backend`
//! (permanent — retrying will not help until a fresh token is provided).
//!
//! To rotate credentials: drop the existing `VaultBackend` and construct a new
//! one with the updated `VAULT_TOKEN`. Rotation is transparent to callers that
//! use URI-based construction — update the env var and re-call `from_uri`.
//!
//! # Zeroization
//!
//! Both `get` and `put` make raw HTTP calls using `reqwest`. The auth token is stored
//! as `Zeroizing<String>` and zeroed when this backend is dropped.
//!
//! The HTTP response buffer from `reqwest` (`bytes::Bytes`) is not zeroed on drop —
//! unavoidable at the reqwest layer.  The secret content lands in that buffer before any
//! parsing begins, so using `serde_json` to navigate the response adds no additional
//! unzeroed copies; the secret was already in non-Zeroizing heap memory.  Only the final
//! `SecretValue` produced by `get` is zeroed on drop.
//! The `put` request body is a plain `Vec<u8>` and is not zeroed after the HTTP call —
//! this is unavoidable since `put` must write secret bytes over the network.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_hashicorp_vault::VaultBackend;
//! use secretx_core::SecretStore;
//!
//! let store = VaultBackend::from_uri("secretx:vault:secret/prod/api-key?field=token")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};
use zeroize::Zeroizing;

const BACKEND: &str = "vault";

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

/// Backend that reads and writes secrets in a HashiCorp Vault KV v2 engine.
pub struct VaultBackend {
    /// HTTP client for raw Vault API calls (used by `get`).
    http_client: reqwest::Client,
    /// Vault server base URL (no trailing slash), e.g. `http://127.0.0.1:8200`.
    addr: String,
    /// Vault auth token — zeroed when this backend is dropped.
    token: Zeroizing<String>,
    /// KV v2 mount name, e.g. `secret`.
    mount: String,
    /// Secret path within the mount, e.g. `prod/api-key`.
    secret_path: String,
    /// When set, extract this JSON string field from the KV data map.
    field: Option<String>,
}

impl VaultBackend {
    /// Construct from a `secretx:vault:<mount>/<path>` URI.
    ///
    /// Reads `VAULT_TOKEN` from the environment — returns
    /// [`SecretError::Unavailable`] if absent.
    ///
    /// No network calls are made during construction.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "vault" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `vault`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "vault URI requires a path: secretx:vault:<mount>/<path>".into(),
            ));
        }

        let (mount, secret_path) = match parsed.path().find('/') {
            Some(i) => (
                parsed.path()[..i].to_string(),
                parsed.path()[i + 1..].to_string(),
            ),
            None => {
                return Err(SecretError::InvalidUri(
                    "vault URI must be secretx:vault:<mount>/<path>".into(),
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
        // Trim trailing slashes so URL construction is not sensitive to whether
        // VAULT_ADDR was set as "http://host:8200" or "http://host:8200/".
        let addr = addr.trim_end_matches('/').to_string();

        let token =
            Zeroizing::new(
                std::env::var("VAULT_TOKEN").map_err(|_| SecretError::Unavailable {
                    backend: "vault",
                    source: "VAULT_TOKEN env var not set".into(),
                })?,
            );

        let field = parsed.param("field").map(|s| s.to_string());
        let http_client = reqwest::Client::new();

        Ok(Self {
            http_client,
            addr,
            token,
            mount,
            secret_path,
            field,
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for VaultBackend {
    /// Retrieve the Vault secret.
    ///
    /// Makes a raw HTTP `GET /v1/<mount>/data/<path>` call to the Vault KV v2
    /// API. When no `?field=` parameter is set, the KV v2 data map is returned
    /// serialized as a JSON object.
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let url = format!("{}/v1/{}/data/{}", self.addr, self.mount, self.secret_path);

        let resp = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", self.token.as_str())
            .send()
            .await
            .map_err(|e| SecretError::Unavailable {
                backend: "vault",
                source: e.into(),
            })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound);
        }
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(map_http_status(status, &detail));
        }

        let body = resp.bytes().await.map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        })?;

        // KV v2 response: {"data": {"data": {<secret-map>}, "metadata": {...}}, ...}
        let json: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| SecretError::DecodeFailed(format!("vault: invalid JSON response: {e}")))?;
        let data_map = json
            .get("data")
            .and_then(|d| d.get("data"))
            .ok_or_else(|| {
                SecretError::DecodeFailed("vault: missing data.data in response".into())
            })?;

        if let Some(field) = &self.field {
            let val = data_map
                .get(field.as_str())
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SecretError::DecodeFailed(format!(
                        "vault: field '{field}' not found or not a string"
                    ))
                })?;
            Ok(SecretValue::new(val.as_bytes().to_vec()))
        } else {
            // Reject an empty data map — returning b"{}" would silently give
            // callers an unusable secret; fail loudly instead.
            if data_map.as_object().map(|m| m.is_empty()).unwrap_or(false) {
                return Err(SecretError::DecodeFailed(
                    "vault secret has no fields; use ?field=<name> to request a specific field"
                        .into(),
                ));
            }
            let data_bytes = serde_json::to_vec(data_map).map_err(|e| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            })?;
            Ok(SecretValue::new(data_bytes))
        }
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for VaultBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let s = std::str::from_utf8(value.as_bytes())
            .map_err(|_| SecretError::DecodeFailed("secret value is not valid UTF-8".into()))?;

        // Build the KV v2 write body: {"data": {<map>}}.
        let body_bytes: Vec<u8> = if let Some(field) = &self.field {
            // Use serde_json to JSON-encode field and value, since either may
            // contain characters that require escaping (e.g. quotes, backslash).
            let body = serde_json::json!({"data": {field: s}});
            serde_json::to_vec(&body).map_err(|e| SecretError::Backend {
                backend: "vault",
                source: e.into(),
            })?
        } else {
            // No ?field= — value must be a valid, non-empty JSON object.
            let data: serde_json::Map<String, serde_json::Value> = serde_json::from_str(s)
                .map_err(|e| {
                    SecretError::DecodeFailed(format!(
                        "put without ?field= requires a JSON object \
                         (e.g. {{\"key\": \"value\"}}): {e}"
                    ))
                })?;
            if data.is_empty() {
                return Err(SecretError::DecodeFailed(
                    "put without ?field= requires a non-empty JSON object".into(),
                ));
            }
            // `s` is a validated JSON object — wrap it directly to avoid
            // re-serializing through serde_json::Value (which would create
            // extra non-Zeroizing allocations of the secret map content).
            format!("{{\"data\":{s}}}").into_bytes()
        };

        let url = format!("{}/v1/{}/data/{}", self.addr, self.mount, self.secret_path);

        let resp = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", self.token.as_str())
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|e| SecretError::Unavailable {
                backend: "vault",
                source: e.into(),
            })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: format!("KV mount '{}' not found (HTTP 404)", self.mount).into(),
            });
        }
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(map_http_status(status, &detail));
        }

        Ok(())
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "vault",
    factory: |uri: &str| {
        VaultBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "vault",
    factory: |uri: &str| {
        VaultBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing (no Vault server required) ────────────────────────────────

    #[test]
    fn from_uri_wrong_backend() {
        // Backend mismatch is checked before VAULT_TOKEN, so this always returns
        // InvalidUri regardless of whether the env var is set.
        let result = VaultBackend::from_uri("secretx:aws-sm:secret/foo");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_missing_mount_slash() {
        // No slash means no mount/path split — invalid.
        // The path check returns InvalidUri before from_uri reaches the
        // VAULT_TOKEN retrieval, so this test runs regardless of whether the
        // env var is set.
        let result = VaultBackend::from_uri("secretx:vault:nosuchpath");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_empty_secret_path() {
        // The empty-secret-path check returns InvalidUri before from_uri
        // reaches the VAULT_TOKEN retrieval, so no token is needed.
        let result = VaultBackend::from_uri("secretx:vault:secret/");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_missing_vault_token() {
        if std::env::var("VAULT_TOKEN").is_ok() {
            return; // skip if token is present
        }
        let result = VaultBackend::from_uri("secretx:vault:secret/foo");
        assert!(matches!(result, Err(SecretError::Unavailable { .. })));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        let result = VaultBackend::from_uri("https://vault.example.com/secret/foo");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn from_uri_empty_path() {
        let result = VaultBackend::from_uri("secretx:vault");
        assert!(matches!(result, Err(SecretError::InvalidUri(_))));
    }

    // ── error mapping (no Vault server required) ──────────────────────────────

    #[test]
    fn map_http_status_429_is_unavailable() {
        let err = map_http_status(reqwest::StatusCode::TOO_MANY_REQUESTS, "rate limited");
        assert!(
            matches!(err, SecretError::Unavailable { .. }),
            "HTTP 429 must map to Unavailable (transient); got: {err:?}"
        );
    }

    // ── put without ?field= (no live Vault required) ─────────────────────────

    #[tokio::test]
    async fn put_without_field_rejects_invalid_json() {
        if std::env::var("VAULT_TOKEN").is_err() {
            return; // need a token to construct the backend
        }
        // No ?field= — put must parse the value as a JSON object.
        // The parse fails before any network call, so no live Vault is needed.
        let backend = VaultBackend::from_uri("secretx:vault:secret/test/nofieldput")
            .expect("from_uri should succeed");
        let result = backend
            .put(SecretValue::new(b"not-valid-json".to_vec()))
            .await;
        assert!(
            matches!(result, Err(SecretError::DecodeFailed(_))),
            "put without ?field= must reject non-JSON input, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn put_without_field_rejects_empty_object() {
        if std::env::var("VAULT_TOKEN").is_err() {
            return; // need a token to construct the backend
        }
        // {} is valid JSON but writing an empty data map would make the
        // subsequent get fail with DecodeFailed (the is_empty guard in get
        // rejects empty maps). Reject at put time so the error is immediate
        // rather than deferred to the next get call.
        let backend = VaultBackend::from_uri("secretx:vault:secret/test/nofieldput-empty")
            .expect("from_uri should succeed");
        let result = backend.put(SecretValue::new(b"{}".to_vec())).await;
        assert!(
            matches!(result, Err(SecretError::DecodeFailed(_))),
            "put without ?field= must reject empty JSON object, got: {result:?}"
        );
    }

    // ── Integration tests (require live Vault + env vars) ────────────────────

    fn integration_enabled() -> bool {
        std::env::var("SECRETX_VAULT_TEST").is_ok() && std::env::var("VAULT_TOKEN").is_ok()
    }

    #[tokio::test]
    async fn integration_put_and_get() {
        if !integration_enabled() {
            return;
        }
        // Use a path unique to this test so parallel test runs cannot race with
        // integration_refresh_same_as_get, which also writes a field secret.
        let backend =
            VaultBackend::from_uri("secretx:vault:secret/secretx-test/put-and-get?field=val")
                .expect("from_uri failed");

        let written = b"hello-vault";
        backend
            .put(SecretValue::new(written.to_vec()))
            .await
            .expect("put failed");

        let read = backend.get().await.expect("get failed");
        assert_eq!(read.as_bytes(), written);
    }

    #[tokio::test]
    async fn integration_get_full_json() {
        if !integration_enabled() {
            return;
        }
        // Write a secret with multiple fields first.
        let setup = VaultBackend::from_uri("secretx:vault:secret/secretx-test/json?field=alpha")
            .expect("from_uri failed");
        setup
            .put(SecretValue::new(b"aaa".to_vec()))
            .await
            .expect("setup put failed");

        // Read without field — expect JSON.
        let backend = VaultBackend::from_uri("secretx:vault:secret/secretx-test/json")
            .expect("from_uri failed");
        let raw = backend.get().await.expect("get failed");
        let json: serde_json::Value =
            serde_json::from_slice(raw.as_bytes()).expect("not valid JSON");
        assert!(json.is_object(), "expected JSON object");
        assert_eq!(
            json["alpha"].as_str(),
            Some("aaa"),
            "field 'alpha' should round-trip through get-without-field"
        );
    }

    #[tokio::test]
    async fn integration_get_not_found() {
        if !integration_enabled() {
            return;
        }
        let backend =
            VaultBackend::from_uri("secretx:vault:secret/secretx-test/does-not-exist-xyzzy")
                .expect("from_uri failed");
        let result = backend.get().await;
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
        // Use a path unique to this test so parallel test runs cannot race with
        // integration_put_and_get, which also writes a field secret.
        let backend = VaultBackend::from_uri(
            "secretx:vault:secret/secretx-test/refresh-same-as-get?field=val",
        )
        .expect("from_uri failed");

        backend
            .put(SecretValue::new(b"refresh-test".to_vec()))
            .await
            .expect("put failed");

        let v1 = backend.get().await.expect("get failed");
        let v2 = backend.refresh().await.expect("refresh failed");
        assert_eq!(v1.as_bytes(), v2.as_bytes());
    }

    #[tokio::test]
    async fn integration_field_put_drops_other_fields() {
        if !integration_enabled() {
            return;
        }
        // Demonstrate the partial-update footgun: put with ?field= creates a new
        // KV v2 version containing ONLY the named field. Other fields from the
        // previous version are not carried forward.
        //
        // Step 1: write a two-field secret without ?field=.
        let full_backend = VaultBackend::from_uri("secretx:vault:secret/secretx-test/footgun-test")
            .expect("from_uri failed");
        full_backend
            .put(SecretValue::new(
                br#"{"a":"alpha-val","b":"beta-val"}"#.to_vec(),
            ))
            .await
            .expect("initial full-object put failed");

        // Step 2: overwrite only field "a" using ?field=a.
        let field_backend =
            VaultBackend::from_uri("secretx:vault:secret/secretx-test/footgun-test?field=a")
                .expect("from_uri failed");
        field_backend
            .put(SecretValue::new(b"new-alpha".to_vec()))
            .await
            .expect("field put failed");

        // Step 3: read back the full JSON. The new version must contain only
        // {"a": "new-alpha"} — "b" is gone because KV v2 has no field-level
        // update; set always replaces the entire data map.
        let read = full_backend.get().await.expect("get failed");
        let parsed: serde_json::Value =
            serde_json::from_slice(read.as_bytes()).expect("get did not return valid JSON");
        assert_eq!(
            parsed.get("a").and_then(|v| v.as_str()),
            Some("new-alpha"),
            "field 'a' should have the new value"
        );
        assert!(
            parsed.get("b").is_none(),
            "field 'b' must be absent after a field-only put — field put drops all other fields"
        );
    }

    #[tokio::test]
    async fn integration_put_full_json_and_get() {
        if !integration_enabled() {
            return;
        }
        // put without ?field= writes the caller-supplied JSON object as the full KV
        // data map. get without ?field= reads it back as JSON. Verify the round-trip.
        let backend = VaultBackend::from_uri("secretx:vault:secret/secretx-test/jsonput")
            .expect("from_uri failed");

        backend
            .put(SecretValue::new(br#"{"key":"hello-json-put"}"#.to_vec()))
            .await
            .expect("put failed");

        let read = backend.get().await.expect("get failed");
        let parsed: serde_json::Value =
            serde_json::from_slice(read.as_bytes()).expect("get did not return valid JSON");
        assert_eq!(
            parsed.get("key").and_then(|v| v.as_str()),
            Some("hello-json-put"),
            "round-tripped value mismatch"
        );
    }

    #[tokio::test]
    async fn integration_trailing_slash_addr_works() {
        if !integration_enabled() {
            return;
        }
        // A trailing slash in the addr (common when VAULT_ADDR=http://host:8200/)
        // must not produce a double-slash URL that causes a 404.
        let addr = std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
        let uri_with_slash =
            format!("secretx:vault:secret/secretx-test/trailing-slash?addr={addr}/&field=v");
        let backend = VaultBackend::from_uri(&uri_with_slash)
            .expect("from_uri with trailing-slash addr failed");

        backend
            .put(SecretValue::new(b"ok".to_vec()))
            .await
            .expect("put with trailing-slash addr failed");
        let val = backend
            .get()
            .await
            .expect("get with trailing-slash addr failed");
        assert_eq!(val.as_bytes(), b"ok");
    }
}
