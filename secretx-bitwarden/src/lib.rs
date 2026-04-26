//! Bitwarden Secrets Manager backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without credentials.
//! Live integration tests require a Bitwarden Secrets Manager account
//! (available on Teams/Enterprise plans) and a machine account access token.
//! Set `SECRETX_BWS_TEST=1` and `BWS_ACCESS_TOKEN` to enable them.
//! **Not yet integration-tested.**
//!
//! URI: `secretx:bitwarden:<project-name>/<secret-name>`
//!
//! Authentication is via the `BWS_ACCESS_TOKEN` environment variable, which
//! must hold a Bitwarden Secrets Manager machine account access token.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_bitwarden::BitwardenBackend;
//! use secretx_core::SecretStore;
//!
//! // BWS_ACCESS_TOKEN must be set in the environment.
//! let store = BitwardenBackend::from_uri("secretx:bitwarden:my-project/my-secret")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Zeroization
//!
//! `BWS_ACCESS_TOKEN` is stored as `Zeroizing<String>` and zeroed when this backend is dropped.
//! However, the Bitwarden SDK's `SecretResponse::value` field is a plain `String`; the secret
//! value returned by the SDK is not zeroed when the SDK response object is dropped. This is an
//! SDK limitation. The `SecretValue` returned to the caller is zeroed on drop as usual.

use bitwarden::{
    auth::login::AccessTokenLoginRequest,
    secrets_manager::{
        projects::ProjectsListRequest,
        secrets::{SecretGetRequest, SecretIdentifiersByProjectRequest},
        ClientProjectsExt, ClientSecretsExt,
    },
    Client,
};
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use zeroize::Zeroizing;

const BACKEND: &str = "bitwarden";

/// Backend that reads secrets from Bitwarden Secrets Manager.
///
/// Construct with [`from_uri`](BitwardenBackend::from_uri). Authenticates
/// lazily on the first [`get`](SecretStore::get) call using the
/// `BWS_ACCESS_TOKEN` environment variable.
///
/// After the first successful `get`, the authenticated client, organization
/// UUID, project UUID, and secret UUID are all cached.  Subsequent calls make
/// exactly one API call (`secrets().get(secret_id)`) instead of three
/// (list_projects + list_secrets + get).
///
/// # Session lifetime
///
/// The session state is cached for the **lifetime of this object**.
/// If the access token is rotated or expires after the first successful `get`,
/// all subsequent calls will fail with an auth error from the Bitwarden API.
/// To force re-authentication, drop the existing backend and construct a new
/// one with the updated `BWS_ACCESS_TOKEN`.
pub struct BitwardenBackend {
    access_token: Zeroizing<String>,
    project_name: String,
    secret_name: String,
    /// Lazily-initialized session state: authenticated client, organization
    /// UUID, project UUID, and secret UUID.  Populated on the first successful
    /// get().  Caches project_id and secret_id to avoid N+2 API calls on every
    /// subsequent get (list_projects + list_secrets + get → just get).
    session: tokio::sync::OnceCell<(Client, uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
}

impl BitwardenBackend {
    /// Construct from a `secretx:bitwarden:<project-name>/<secret-name>` URI.
    ///
    /// Reads the `BWS_ACCESS_TOKEN` environment variable at construction time.
    /// No network call is made until [`get`](SecretStore::get) is called.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidUri`] if the URI does not match the
    /// expected format or does not name the `bitwarden` backend.
    ///
    /// Returns [`SecretError::Unavailable`] if `BWS_ACCESS_TOKEN` is not set.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend()
            )));
        }

        // path is "<project-name>/<secret-name>"
        let (project_name, secret_name) = parsed.path().split_once('/').ok_or_else(|| {
            SecretError::InvalidUri(format!(
                "bitwarden URI requires `<project-name>/<secret-name>`, got path: `{}`",
                parsed.path()
            ))
        })?;

        if project_name.is_empty() || secret_name.is_empty() {
            return Err(SecretError::InvalidUri(
                "bitwarden URI: project-name and secret-name must not be empty".into(),
            ));
        }

        // Bitwarden Secrets Manager returns the secret value as a plain string;
        // ?field= JSON extraction is not supported and would silently return the
        // full raw value, which is confusing.  Reject early.
        if parsed.param("field").is_some() {
            return Err(SecretError::InvalidUri(
                "bitwarden does not support ?field= (Bitwarden secret values are plain strings, \
                 not JSON objects); remove ?field= or use a backend that supports JSON field \
                 extraction (e.g. aws-sm)"
                    .into(),
            ));
        }

        let access_token =
            std::env::var("BWS_ACCESS_TOKEN").map_err(|_| SecretError::Unavailable {
                backend: BACKEND,
                source: "BWS_ACCESS_TOKEN environment variable is not set".into(),
            })?;

        Ok(Self {
            access_token: Zeroizing::new(access_token),
            project_name: project_name.to_owned(),
            secret_name: secret_name.to_owned(),
            session: tokio::sync::OnceCell::new(),
        })
    }
}

/// Create an authenticated Bitwarden client using the given access token.
///
/// Returns the client and the organization UUID extracted from the JWT token
/// embedded in the access token.
async fn build_authed_client(access_token: &str) -> Result<(Client, uuid::Uuid), SecretError> {
    let client = Client::new(None);

    let auth_resp = client
        .auth()
        .login_access_token(&AccessTokenLoginRequest {
            access_token: access_token.to_string(),
            state_file: None,
        })
        .await
        .map_err(|e| SecretError::Unavailable {
            backend: BACKEND,
            source: e.into(),
        })?;

    if !auth_resp.authenticated {
        return Err(SecretError::Unavailable {
            backend: BACKEND,
            source: "access token login did not authenticate".into(),
        });
    }

    // `client.internal` is a `#[doc(hidden)]` pub field of `bitwarden::Client`
    // (bitwarden-core 2.0.0, bitwarden-core/src/client/client.rs).  There is no
    // other public API in bitwarden 2.0.0 to retrieve the organization UUID after
    // `login_access_token` — the `AccessTokenLoginResponse` struct does not expose it
    // and it is not returned via any other pub method on `Client`.
    //
    // NOTE: The org UUID is NOT embedded in the access token JWT string.  The token
    // format is `0.<access_token_id_uuid>.<client_secret>:<encryption_key_base64>`;
    // the org UUID is stored in the SDK's internal `login_method` state after auth.
    // There is therefore no JWT-parsing fallback if `client.internal` is removed.
    //
    // Verified against bitwarden = "2.0.0". When upgrading bitwarden, check:
    //   bitwarden-core/src/client/client.rs — `pub internal` field still present
    //   bitwarden-core/src/client/internal.rs — `get_access_token_organization` still present
    // If the internal field is removed, file an issue with bitwarden-core to expose
    // the org ID via a stable public API.
    let org_id: uuid::Uuid = client
        .internal
        .get_access_token_organization()
        .ok_or_else(|| SecretError::Unavailable {
            backend: BACKEND,
            source: "could not determine organization ID from access token".into(),
        })?
        .into();

    Ok((client, org_id))
}

/// Classify a `SecretsManagerError` into `Backend` (permanent) or `Unavailable` (transient).
///
/// `SecretsManagerError` is a private type in `bitwarden-sm` so we cannot pattern-match on it
/// from outside the crate.  Both `SecretsManagerError` and its inner `ApiError` use
/// `#[error(transparent)]`, which makes `Display` delegate all the way down and `source()`
/// skip intermediate types.  As a result:
///
/// - `ApiError::ResponseContent { status, .. }` formats as
///   `"Received error message from server: [NNN] ..."` — we detect 5xx this way.
/// - `ApiError::Reqwest(e)` formats as the reqwest error message (e.g., "error sending request
///   for url (...): connection refused") — we detect network errors by known substrings.
/// - `ApiError::Io(e)` formats similarly.
///
/// Everything else (Validation, Crypto, Serde, 4xx) is a permanent caller/config error → Backend.
///
/// If a future version of bitwarden-core changes the `ResponseContent` Display format, update
/// the `"[5"` / `"[429]"` checks here.
fn classify_bitwarden_sdk_error(e: impl std::error::Error + Send + Sync + 'static) -> SecretError {
    let msg = e.to_string();
    // 5xx responses: "Received error message from server: [5XX] ..."
    // 429 (rate limit): transient, the caller should back off and retry.
    let transient_response =
        msg.starts_with("Received error message from server: [5") || msg.contains("[429]");
    // reqwest / IO network failures (these bubble up through the transparent chain).
    let transient_network = msg.contains("error sending request")
        || msg.contains("connection refused")
        || msg.contains("connection reset")
        || msg.contains("timed out")
        || msg.contains("dns error")
        || msg.contains("No such host");
    if transient_response || transient_network {
        SecretError::Unavailable {
            backend: BACKEND,
            source: e.into(),
        }
    } else {
        SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        }
    }
}

/// Resolve `project_name` to its UUID by listing all projects in the org.
async fn resolve_project_id(
    client: &Client,
    org_id: uuid::Uuid,
    project_name: &str,
) -> Result<uuid::Uuid, SecretError> {
    let resp = client
        .projects()
        .list(&ProjectsListRequest {
            organization_id: org_id,
        })
        .await
        .map_err(classify_bitwarden_sdk_error)?;

    resp.data
        .into_iter()
        .find(|p| p.name == project_name)
        .map(|p| p.id)
        .ok_or(SecretError::NotFound)
}

/// Find the secret UUID within a project by secret name.
async fn resolve_secret_id(
    client: &Client,
    project_id: uuid::Uuid,
    secret_name: &str,
) -> Result<uuid::Uuid, SecretError> {
    let resp = client
        .secrets()
        .list_by_project(&SecretIdentifiersByProjectRequest { project_id })
        .await
        .map_err(classify_bitwarden_sdk_error)?;

    resp.data
        .into_iter()
        .find(|s| s.key == secret_name)
        .map(|s| s.id)
        .ok_or(SecretError::NotFound)
}

/// Fetch the secret value using cached session state.
///
/// On the first call: authenticates, resolves project_name → project_id and
/// secret_name → secret_id, then fetches the secret.  All intermediate IDs
/// are stored in `backend.session` so subsequent calls skip the two list
/// operations and make exactly one API call (`secrets().get`).
async fn fetch(backend: &BitwardenBackend) -> Result<SecretValue, SecretError> {
    // Initialize once: auth + name-resolution + ID caching.
    // On error the OnceCell stays uninitialized so the next call retries.
    let (client, _org_id, _project_id, secret_id) = backend
        .session
        .get_or_try_init(|| async {
            let (client, org_id) = build_authed_client(&backend.access_token).await?;
            let project_id = resolve_project_id(&client, org_id, &backend.project_name).await?;
            let secret_id = resolve_secret_id(&client, project_id, &backend.secret_name).await?;
            Ok::<_, SecretError>((client, org_id, project_id, secret_id))
        })
        .await?;

    let secret_resp = client
        .secrets()
        .get(&SecretGetRequest { id: *secret_id })
        .await
        .map_err(classify_bitwarden_sdk_error)?;

    Ok(SecretValue::new(secret_resp.value.into_bytes()))
}

#[async_trait::async_trait]
impl SecretStore for BitwardenBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        fetch(self).await
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "bitwarden",
    factory: |uri: &str| {
        BitwardenBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize all tests that read or write BWS_ACCESS_TOKEN to prevent races
    // within this test binary.
    //
    // Scope limitation: ENV_LOCK only coordinates threads inside this test
    // binary.  If a future integration-test harness or workspace-level test
    // binary also mutates BWS_ACCESS_TOKEN in a separate thread, it will not
    // be covered by this lock.  Keep env-var mutation confined to this crate's
    // tests.  If cross-crate coordination is ever needed, move to a
    // per-process lock file or a dedicated test environment variable.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn from_uri_wrong_backend() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:env:FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("https://bitwarden/proj/sec"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_secret_name() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:bitwarden:only-project"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_project() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:bitwarden:/secret-name"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_token() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("BWS_ACCESS_TOKEN") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:bitwarden:proj/sec"),
            Err(SecretError::Unavailable { .. })
        ));
    }

    #[test]
    fn from_uri_valid() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy-token") };
        let backend = BitwardenBackend::from_uri("secretx:bitwarden:my-project/my-secret");
        assert!(backend.is_ok());
        let b = backend.unwrap();
        assert_eq!(b.project_name, "my-project");
        assert_eq!(b.secret_name, "my-secret");
    }

    #[test]
    fn from_uri_field_selector_rejected() {
        // Bitwarden values are plain strings; ?field= is not supported and must
        // be rejected before BWS_ACCESS_TOKEN is read.  Use a dummy token to
        // get past path validation so the ?field= guard is exercised.
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy-token") };
        let result =
            BitwardenBackend::from_uri("secretx:bitwarden:my-project/my-secret?field=password");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("bitwarden does not support ?field="),
                    "error must mention the limitation, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(_) => panic!("expected InvalidUri, got Ok"),
        }
    }

    // Integration tests — skipped unless BWS_ACCESS_TOKEN is set AND
    // SECRETX_BWS_TEST=1.

    #[tokio::test]
    async fn integration_get() {
        if std::env::var("SECRETX_BWS_TEST").as_deref() != Ok("1") {
            return;
        }
        let project = match std::env::var("SECRETX_BWS_TEST_PROJECT") {
            Ok(p) => p,
            Err(_) => return,
        };
        let secret = match std::env::var("SECRETX_BWS_TEST_SECRET") {
            Ok(s) => s,
            Err(_) => return,
        };
        let uri = format!("secretx:bitwarden:{project}/{secret}");
        let store = BitwardenBackend::from_uri(&uri).unwrap();
        let value = store.get().await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}
