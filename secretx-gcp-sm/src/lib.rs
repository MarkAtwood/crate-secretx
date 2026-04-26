//! GCP Secret Manager backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without credentials.
//! Live integration tests require a GCP project with the Secret Manager API
//! enabled. Set `SECRETX_GCP_TEST=1` and `GCP_ACCESS_TOKEN` to enable them.
//! **Not yet integration-tested.**
//!
//! URI: `secretx:gcp-sm:<project>/<secret>[?version=<version>]`
//!
//! - `project` — GCP project ID
//! - `secret`  — secret name in Secret Manager
//! - `version` — secret version (default: `latest`)
//!
//! Requires `GCP_ACCESS_TOKEN` to be set in the environment at construction
//! time. Obtain a token with `gcloud auth print-access-token` or by another
//! OAuth2 flow appropriate to your environment.
//!
//! # Write behavior
//!
//! GCP Secret Manager always creates a **new version** on write.  The
//! [`WritableSecretStore::put`] method enforces this invariant: if the URI
//! includes a pinned `?version=` (e.g. `?version=3`), `put()` returns
//! [`SecretError::InvalidUri`] immediately — a pinned backend's `get()` would
//! continue reading the old version and never see the newly written data.
//! Omit `?version=` (or use `?version=latest`) when you need both `get` and
//! `put` to work on the same backend instance.
//!
//! # Token lifetime
//!
//! Tokens obtained from `gcloud auth print-access-token` (and most OAuth2
//! flows) expire after **1 hour**. The backend reads the token once at
//! construction time and reuses it for all subsequent calls. In a
//! long-running process, calls made after the token expires will fail with
//! HTTP 401.
//!
//! **Workaround for short-lived workloads:** reconstruct the backend before
//! each use to pick up a fresh token.
//!
//! **Production workloads:** use [Workload Identity] or a service account
//! key with an SDK that refreshes credentials automatically (e.g. the
//! [Google Cloud Rust client library]).
//!
//! [Workload Identity]: https://cloud.google.com/iam/docs/workload-identity-federation
//! [Google Cloud Rust client library]: https://github.com/googleapis/google-cloud-rust
//!
//! # Zeroization
//!
//! The access token is stored as `Zeroizing<String>` and zeroed when the backend
//! is dropped.  The raw HTTP response buffer from reqwest (`bytes::Bytes`) is not
//! zeroed on drop (unavoidable at the reqwest layer); the base64-encoded secret
//! content lands there before any parsing begins.  Because the secret is already
//! in non-Zeroizing heap memory at that point, using `serde_json` to extract the
//! value adds no additional unzeroed copies.  Only the final `SecretValue` produced
//! by `get` is zeroed on drop.  For `put`, the assembled request body is not
//! zeroed after the HTTP call — the secret bytes must be written over the network.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_gcp_sm::GcpSmBackend;
//! use secretx_core::SecretStore;
//!
//! let store = GcpSmBackend::from_uri("secretx:gcp-sm:my-project/my-secret")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```

use base64::Engine as _;
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, WritableSecretStore};
use zeroize::Zeroizing;

const BACKEND: &str = "gcp-sm";
const BASE_URL: &str = "https://secretmanager.googleapis.com/v1";

/// Backend that reads and writes secrets in GCP Secret Manager via REST.
///
/// Construct with [`from_uri`](GcpSmBackend::from_uri). Reads the GCP access
/// token from `GCP_ACCESS_TOKEN` at construction time.
///
/// # Token expiry — important for long-running processes
///
/// The token is read **once** at construction and reused for the lifetime of
/// this object.  Tokens from `gcloud auth print-access-token` expire after
/// **1 hour**.  In a long-running process, calls made after expiry will fail
/// with `SecretError::Unavailable` (HTTP 401 with an expiry hint message).
/// There is no automatic refresh.
///
/// Workaround for daemons: handle `SecretError::Unavailable` by dropping this
/// backend and constructing a fresh one with an updated `GCP_ACCESS_TOKEN`, or
/// store a factory closure and reconstruct on each use.  For production workloads, prefer [Workload Identity] or a
/// service account key with the [Google Cloud Rust client library], which
/// handles token refresh automatically.
///
/// [Workload Identity]: https://cloud.google.com/iam/docs/workload-identity-federation
/// [Google Cloud Rust client library]: https://github.com/googleapis/google-cloud-rust
pub struct GcpSmBackend {
    client: reqwest::Client,
    project: String,
    secret: String,
    version: String,
    access_token: Zeroizing<String>,
}

impl GcpSmBackend {
    /// Construct from a `secretx:gcp-sm:<project>/<secret>[?version=<ver>]` URI.
    ///
    /// Reads `GCP_ACCESS_TOKEN` from the environment at the time of this call.
    /// Does not contact GCP — construction validates the URI and token
    /// presence only.
    ///
    /// **The token is stored for the lifetime of this object and never
    /// refreshed.**  For long-running processes, see the token expiry
    /// warning in the struct documentation.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend()
            )));
        }

        let (project, secret) = split_project_secret(parsed.path()).ok_or_else(|| {
            SecretError::InvalidUri("gcp-sm URI must be secretx:gcp-sm:<project>/<secret>".into())
        })?;

        let version = parsed.param("version").unwrap_or("latest").to_string();

        validate_gcp_resource_name_component(&project, "project")?;
        validate_gcp_resource_name_component(&secret, "secret")?;
        validate_gcp_resource_name_component(&version, "version")?;

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

/// Reject characters that are not valid in GCP resource name components.
///
/// GCP project IDs allow `[a-z0-9-]`, secret names allow `[A-Za-z0-9_-]`,
/// and version labels are `[A-Za-z0-9]+` or `"latest"`.  Any other character
/// (spaces, `#`, `%`, `/`, etc.) would corrupt the REST URL path or produce a
/// confusing HTTP 400 from GCP rather than a clear `InvalidUri` at construction
/// time.
fn validate_gcp_resource_name_component(value: &str, label: &str) -> Result<(), SecretError> {
    if value.is_empty() {
        return Err(SecretError::InvalidUri(format!(
            "gcp-sm {label} must not be empty"
        )));
    }
    let ok = value
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'));
    if !ok {
        return Err(SecretError::InvalidUri(format!(
            "gcp-sm {label} contains invalid characters; \
             allowed: [A-Za-z0-9_-] (got: {value:?})"
        )));
    }
    Ok(())
}

/// Build the REST URL for accessing a secret version.
fn access_url(project: &str, secret: &str, version: &str) -> String {
    format!("{BASE_URL}/projects/{project}/secrets/{secret}/versions/{version}:access")
}

/// Build the REST URL for adding a new secret version.
fn add_version_url(project: &str, secret: &str) -> String {
    format!("{BASE_URL}/projects/{project}/secrets/{secret}:addSecretVersion")
}

/// Map a non-successful HTTP status to the appropriate [`SecretError`].
///
/// - 5xx and 429 codes are transient (→ `Unavailable`).
/// - 401 is mapped to `Unavailable` with an explanatory message: `GCP_ACCESS_TOKEN` is captured
///   at construction and never refreshed.  When the token expires the API returns 401; callers
///   who handle `Unavailable` can drop the backend and reconstruct with a fresh token.
/// - All other non-2xx codes are permanent configuration/request errors (→ `Backend`).
fn map_http_status(status: reqwest::StatusCode, detail: &str) -> SecretError {
    let msg = if detail.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {detail}")
    };
    if status.is_server_error() || status == 429 {
        SecretError::Unavailable {
            backend: BACKEND,
            source: msg.into(),
        }
    } else if status == 401 {
        // The GCP access token is stored at construction time and never refreshed.
        // A 401 most likely means the token has expired.  Signal Unavailable so
        // callers know to reconstruct the backend with a fresh GCP_ACCESS_TOKEN.
        SecretError::Unavailable {
            backend: BACKEND,
            source: format!(
                "{msg} — GCP_ACCESS_TOKEN may have expired; \
                 reconstruct the backend with a fresh token"
            )
            .into(),
        }
    } else {
        SecretError::Backend {
            backend: BACKEND,
            source: msg.into(),
        }
    }
}

#[async_trait::async_trait]
impl SecretStore for GcpSmBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let url = access_url(&self.project, &self.secret, &self.version);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(self.access_token.as_str())
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
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(map_http_status(status, &detail));
        }

        let body = resp.bytes().await.map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        })?;
        // GCP SM response: {"payload": {"data": "<base64>", "dataCrc32c": ...}, ...}
        let json: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            SecretError::DecodeFailed(format!("gcp-sm: invalid JSON response: {e}"))
        })?;
        let data_b64 = json
            .get("payload")
            .and_then(|p| p.get("data"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| {
                SecretError::DecodeFailed("gcp-sm: missing payload.data in response".into())
            })?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| SecretError::DecodeFailed(format!("gcp-sm: base64 decode: {e}")))?;
        Ok(SecretValue::new(data))
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for GcpSmBackend {
    /// Add a new version of the secret in GCP Secret Manager.
    ///
    /// # Pinned version
    ///
    /// Returns [`SecretError::InvalidUri`] if this backend was constructed with
    /// a pinned `?version=` parameter.  GCP Secret Manager creates a **new**
    /// version on every write; a pinned backend's `get()` would continue
    /// reading the old version and could never observe the written data.
    /// Construct the backend without `?version=` (or with `?version=latest`)
    /// when you need both `get` and `put`.
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        // GCP Secret Manager always creates a new version on write.  If this
        // backend was constructed with a pinned ?version= (e.g. ?version=3),
        // the new version would be unreachable by this instance's get() call,
        // which would continue reading the pinned version.  That silently
        // violates the WritableSecretStore contract.  Reject early so callers
        // discover the misconfiguration immediately.
        if self.version != "latest" {
            return Err(SecretError::InvalidUri(
                "gcp-sm: put() requires a URI without a pinned ?version= (omit ?version= or \
                 use ?version=latest); GCP Secret Manager always creates a new version and \
                 a pinned version would prevent get() from reading it"
                    .into(),
            ));
        }

        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        let body = serde_json::to_vec(&serde_json::json!({"payload": {"data": encoded}})).map_err(
            |e| SecretError::Backend {
                backend: BACKEND,
                source: e.into(),
            },
        )?;

        let url = add_version_url(&self.project, &self.secret);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(self.access_token.as_str())
            .header("Content-Type", "application/json")
            .body(body)
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
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(map_http_status(status, &detail));
        }
        Ok(())
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "gcp-sm",
    factory: |uri: &str| {
        GcpSmBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "gcp-sm",
    factory: |uri: &str| {
        GcpSmBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that read or write GCP_ACCESS_TOKEN to prevent races.
    // from_uri_missing_token skips when the var is set; put_with_pinned_version
    // sets it to a dummy value.  Without serialization they would race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // URI parsing unit tests — no GCP connection required.

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            GcpSmBackend::from_uri("secretx:env:FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // validate_gcp_resource_name_component: '#' and '%' in project/secret/version must
    // return InvalidUri rather than silently corrupting the REST URL.
    // Oracle: '#' is a URI fragment delimiter; if interpolated raw into the URL
    // path string it truncates the path and sends the request to the wrong endpoint.
    // These tests do NOT require GCP_ACCESS_TOKEN — the path validation fires
    // before the token check in from_uri.

    #[test]
    fn from_uri_project_with_hash_rejected() {
        // %23 decodes to '#', which would corrupt the REST URL path.
        let result = GcpSmBackend::from_uri("secretx:gcp-sm:my-project%23test/my-secret");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "project containing '#' (decoded from %23) must return InvalidUri"
        );
    }

    #[test]
    fn from_uri_secret_with_percent_rejected() {
        // %25 decodes to '%'; not a valid GCP secret name character.
        let result = GcpSmBackend::from_uri("secretx:gcp-sm:my-project/my%25secret");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "secret containing '%' (decoded from %25) must return InvalidUri"
        );
    }

    #[test]
    fn from_uri_version_with_hash_rejected() {
        // %23 in the version query param decodes to '#', corrupting the URL.
        let result = GcpSmBackend::from_uri("secretx:gcp-sm:my-project/my-secret?version=1%232");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "version containing '#' (decoded from %23) must return InvalidUri"
        );
    }

    #[test]
    fn from_uri_empty_version_rejected() {
        // ?version= (empty string) passes the character check vacuously;
        // the explicit empty-string guard must reject it before it generates
        // a malformed REST URL (.../versions/:access).
        let result = GcpSmBackend::from_uri("secretx:gcp-sm:my-project/my-secret?version=");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "empty version param must return InvalidUri"
        );
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
            GcpSmBackend::from_uri("secretx:gcp-sm"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_secret() {
        // Only project, no secret.
        assert!(matches!(
            GcpSmBackend::from_uri("secretx:gcp-sm:myproject"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_token() {
        let _g = ENV_LOCK.lock().unwrap();
        // Only run this test when GCP_ACCESS_TOKEN is not set.
        if std::env::var("GCP_ACCESS_TOKEN").is_ok() {
            return;
        }
        assert!(matches!(
            GcpSmBackend::from_uri("secretx:gcp-sm:my-project/my-secret"),
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

    #[tokio::test]
    async fn put_with_pinned_version_returns_invalid_uri() {
        let _g = ENV_LOCK.lock().unwrap();
        // put() with a pinned ?version= would create a new GCP SM version that
        // get() (which reads self.version) can never see — WritableSecretStore
        // contract violation.  The guard fires before any network call.
        // Use a dummy token so from_uri succeeds; no network is contacted.
        unsafe { std::env::set_var("GCP_ACCESS_TOKEN", "dummy-token") };
        let store =
            GcpSmBackend::from_uri("secretx:gcp-sm:my-project/my-secret?version=3").unwrap();
        let result = store.put(SecretValue::new(b"value".to_vec())).await;
        unsafe { std::env::remove_var("GCP_ACCESS_TOKEN") };
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("pinned ?version="),
                    "error must mention the limitation, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(()) => panic!("expected InvalidUri, got Ok"),
        }
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
        let uri = format!("secretx:gcp-sm:{project}/{secret}");
        let store = GcpSmBackend::from_uri(&uri).unwrap();
        let value = store.get().await.unwrap();
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
        let uri = format!("secretx:gcp-sm:{project}/{secret}");
        let store = GcpSmBackend::from_uri(&uri).unwrap();
        let value = store.refresh().await.unwrap();
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
        let uri = format!("secretx:gcp-sm:{project}/{secret}?version=1");
        let store = GcpSmBackend::from_uri(&uri).unwrap();
        let value = store.get().await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }

    #[test]
    fn map_http_status_401_is_unavailable() {
        let err = map_http_status(reqwest::StatusCode::UNAUTHORIZED, "token expired");
        assert!(
            matches!(err, SecretError::Unavailable { .. }),
            "HTTP 401 must map to Unavailable so callers can refresh token, got: {err:?}"
        );
    }

    #[test]
    fn map_http_status_403_is_backend() {
        let err = map_http_status(reqwest::StatusCode::FORBIDDEN, "permission denied");
        assert!(
            matches!(err, SecretError::Backend { .. }),
            "HTTP 403 must map to Backend (permanent), got: {err:?}"
        );
    }

    #[test]
    fn map_http_status_500_is_unavailable() {
        let err = map_http_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "server error");
        assert!(
            matches!(err, SecretError::Unavailable { .. }),
            "HTTP 500 must map to Unavailable, got: {err:?}"
        );
    }

    #[test]
    fn map_http_status_429_is_unavailable() {
        let err = map_http_status(reqwest::StatusCode::TOO_MANY_REQUESTS, "rate limited");
        assert!(
            matches!(err, SecretError::Unavailable { .. }),
            "HTTP 429 must map to Unavailable, got: {err:?}"
        );
    }
}
