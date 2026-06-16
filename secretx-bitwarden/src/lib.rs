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
use std::sync::Arc;

use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use zeroize::Zeroizing;

const BACKEND: &str = "bitwarden";

/// Construct a [`SecretError::Backend`] (permanent) for this backend.
fn backend_error(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> SecretError {
    SecretError::Backend {
        backend: BACKEND,
        source: source.into(),
    }
}

/// Construct a [`SecretError::Unavailable`] (transient) for this backend.
fn unavailable_error(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> SecretError {
    SecretError::Unavailable {
        backend: BACKEND,
        source: source.into(),
    }
}

/// Convert a `SecretResponse` value into a [`SecretValue`], rejecting empty
/// responses.  An empty `value` field typically indicates a server-side issue
/// or a secret that was created without a value; returning it silently could
/// cause hard-to-diagnose failures downstream.
fn secret_value_from_response(value: String) -> Result<SecretValue, SecretError> {
    if value.is_empty() {
        return Err(backend_error(
            "Bitwarden returned an empty secret value",
        ));
    }
    Ok(SecretValue::new(value.into_bytes()))
}

/// Per-SDK-call timeout.  Each individual Bitwarden SDK network call
/// (login, list-projects, list-secrets, get-secret) is wrapped with this
/// timeout so that a hung connection does not block the caller indefinitely.
const SDK_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Cached session state produced by the first successful `get()`.
///
/// Stores the authenticated client together with the three UUIDs resolved
/// during the initial handshake so that subsequent `get()` calls can skip
/// the list-projects and list-secrets round-trips.
struct BitwardenSession {
    client: Client,
    /// Stored for diagnostics and potential future per-org operations;
    /// not read on the hot path today.
    #[allow(dead_code)]
    org_id: uuid::Uuid,
    /// Stored so a future `list_secrets` refresh does not need to
    /// re-resolve the project; not read on the hot path today.
    #[allow(dead_code)]
    project_id: uuid::Uuid,
    secret_id: uuid::Uuid,
}

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
/// If the access token expires after the first successful `get`,
/// call [`refresh`](SecretStore::refresh) to re-authenticate and update
/// the cached session.  Subsequent `get` calls will then use the new client.
pub struct BitwardenBackend {
    access_token: Zeroizing<String>,
    project_name: String,
    secret_name: String,
    /// Lazily-initialized session state.  Populated on the first successful
    /// `get()`.  Caches project_id and secret_id to avoid N+2 API calls on
    /// every subsequent `get()` (list_projects + list_secrets + get → just get).
    ///
    /// Uses `RwLock<Option<…>>` instead of `OnceCell` so that `refresh()` can
    /// replace the session with a re-authenticated client.
    session: tokio::sync::RwLock<Option<BitwardenSession>>,
}

impl std::fmt::Debug for BitwardenBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitwardenBackend")
            .field("project_name", &self.project_name)
            .field("secret_name", &self.secret_name)
            .finish_non_exhaustive()
    }
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
        Self::from_parsed_uri(&SecretUri::parse(uri)?)
    }

    /// Construct from a pre-parsed [`SecretUri`].
    pub fn from_parsed_uri(parsed: &SecretUri) -> Result<Self, SecretError> {
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
        // Bitwarden does not allow '/' in project or secret names.  After
        // percent-decoding, a slash in either component would mean the URI
        // encoded a literal '/' (%2F) which we cannot reliably distinguish
        // from the project/secret separator.  Reject to avoid silent mismatch.
        if secret_name.contains('/') {
            return Err(SecretError::InvalidUri(
                "bitwarden URI: secret-name must not contain '/' \
                 (only one '/' separator between project-name and secret-name is allowed)"
                    .into(),
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

        let access_token = std::env::var("BWS_ACCESS_TOKEN").map_err(|e| match e {
            std::env::VarError::NotPresent => {
                unavailable_error("BWS_ACCESS_TOKEN environment variable is not set")
            }
            std::env::VarError::NotUnicode(_) => {
                unavailable_error("BWS_ACCESS_TOKEN environment variable contains non-UTF-8 bytes")
            }
        })?;
        if access_token.is_empty() {
            return Err(unavailable_error(
                "BWS_ACCESS_TOKEN environment variable is set but empty",
            ));
        }

        Ok(Self {
            access_token: Zeroizing::new(access_token),
            project_name: project_name.to_owned(),
            secret_name: secret_name.to_owned(),
            session: tokio::sync::RwLock::new(None),
        })
    }
}

/// Wrap a future with [`SDK_CALL_TIMEOUT`], converting `Elapsed` into
/// [`SecretError::Unavailable`].
async fn with_timeout<F, T>(fut: F) -> Result<T, SecretError>
where
    F: std::future::Future<Output = Result<T, SecretError>>,
{
    tokio::time::timeout(SDK_CALL_TIMEOUT, fut)
        .await
        .map_err(|_elapsed| {
            unavailable_error(format!(
                "SDK call timed out after {}s",
                SDK_CALL_TIMEOUT.as_secs()
            ))
        })?
}

/// Create an authenticated Bitwarden client using the given access token.
///
/// Returns the client and the organization UUID extracted from the JWT token
/// embedded in the access token.
async fn build_authed_client(access_token: &str) -> Result<(Client, uuid::Uuid), SecretError> {
    let client = Client::new(None);

    let auth_resp = with_timeout(async {
        client
            .auth()
            // NOTE: access_token is copied into a plain String here because the
            // Bitwarden SDK's AccessTokenLoginRequest requires an owned String —
            // there is no Zeroizing-aware alternative.  This is an SDK limitation
            // documented in the module-level zeroization note.
            .login_access_token(&AccessTokenLoginRequest {
                access_token: access_token.to_string(),
                state_file: None,
            })
            .await
            .map_err(unavailable_error)
    })
    .await?;

    if !auth_resp.authenticated {
        return Err(unavailable_error(
            "access token login did not authenticate",
        ));
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
        .ok_or_else(|| {
            unavailable_error("could not determine organization ID from access token")
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
        || msg.contains("No such host")
        || msg.contains("Name or service not known");
    if transient_response || transient_network {
        unavailable_error(e)
    } else {
        backend_error(e)
    }
}

/// Resolve `project_name` to its UUID by listing all projects in the org.
async fn resolve_project_id(
    client: &Client,
    org_id: uuid::Uuid,
    project_name: &str,
) -> Result<uuid::Uuid, SecretError> {
    let resp = with_timeout(async {
        client
            .projects()
            .list(&ProjectsListRequest {
                organization_id: org_id,
            })
            .await
            .map_err(classify_bitwarden_sdk_error)
    })
    .await?;

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
    let resp = with_timeout(async {
        client
            .secrets()
            .list_by_project(&SecretIdentifiersByProjectRequest { project_id })
            .await
            .map_err(classify_bitwarden_sdk_error)
    })
    .await?;

    resp.data
        .into_iter()
        .find(|s| s.key == secret_name)
        .map(|s| s.id)
        .ok_or(SecretError::NotFound)
}

impl BitwardenBackend {
    /// Fetch the secret value using cached session state.
    ///
    /// On the first call: authenticates, resolves project_name → project_id and
    /// secret_name → secret_id, then fetches the secret.  All intermediate IDs
    /// are stored in `self.session` so subsequent calls skip the two list
    /// operations and make exactly one API call (`secrets().get`).
    async fn fetch(&self) -> Result<SecretValue, SecretError> {
        // Fast path: session already initialized — read lock allows concurrent gets.
        {
            let guard = self.session.read().await;
            if let Some(session) = &*guard {
                let secret_resp = with_timeout(async {
                    session
                        .client
                        .secrets()
                        .get(&SecretGetRequest {
                            id: session.secret_id,
                        })
                        .await
                        .map_err(classify_bitwarden_sdk_error)
                })
                .await?;
                return secret_value_from_response(secret_resp.value);
            }
        }

        // Slow path: first call — take write lock and initialize.
        let mut guard = self.session.write().await;
        // Double-check: another task may have initialized while we waited.
        if guard.is_none() {
            let (client, org_id) = build_authed_client(&self.access_token).await?;
            let project_id =
                resolve_project_id(&client, org_id, &self.project_name).await?;
            let secret_id =
                resolve_secret_id(&client, project_id, &self.secret_name).await?;
            *guard = Some(BitwardenSession {
                client,
                org_id,
                project_id,
                secret_id,
            });
        }
        let session = guard.as_ref().unwrap();
        let secret_resp = with_timeout(async {
            session
                .client
                .secrets()
                .get(&SecretGetRequest {
                    id: session.secret_id,
                })
                .await
                .map_err(classify_bitwarden_sdk_error)
        })
        .await?;
        secret_value_from_response(secret_resp.value)
    }
}

#[async_trait::async_trait]
impl SecretStore for BitwardenBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        self.fetch().await
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        // Re-authenticate and re-resolve IDs outside the lock.
        let (client, org_id) = build_authed_client(&self.access_token).await?;
        let project_id = resolve_project_id(&client, org_id, &self.project_name).await?;
        let secret_id = resolve_secret_id(&client, project_id, &self.secret_name).await?;

        // Fetch the secret before updating the cache so a fetch failure
        // does not discard a previously-working session.
        let secret_resp = with_timeout(async {
            client
                .secrets()
                .get(&SecretGetRequest { id: secret_id })
                .await
                .map_err(classify_bitwarden_sdk_error)
        })
        .await?;

        // Update the cached session so subsequent get() calls use the
        // refreshed client.
        *self.session.write().await = Some(BitwardenSession {
            client,
            org_id,
            project_id,
            secret_id,
        });

        secret_value_from_response(secret_resp.value)
    }
}

inventory::submit!(secretx_core::BackendRegistration::new(
    "bitwarden",
    |uri: &secretx_core::SecretUri| {
        let b = BitwardenBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

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
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:env:FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("https://bitwarden/proj/sec"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_secret_name() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:bitwarden:only-project"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_project() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:bitwarden:/secret-name"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_token() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
        unsafe { std::env::remove_var("BWS_ACCESS_TOKEN") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:bitwarden:proj/sec"),
            Err(SecretError::Unavailable { .. })
        ));
    }

    #[test]
    fn from_uri_empty_token() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx:bitwarden:proj/sec"),
            Err(SecretError::Unavailable { .. })
        ));
    }

    #[test]
    fn from_uri_valid() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
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
        // SAFETY: ENV_LOCK serializes all env-var mutations within this
        // test binary; no other thread reads BWS_ACCESS_TOKEN concurrently.
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

    // ── classify_bitwarden_sdk_error tests ──────────────────────────────────

    /// Minimal error type used as an oracle-independent input to
    /// `classify_bitwarden_sdk_error`.  Each test constructs one with a known
    /// message string and asserts the returned `SecretError` variant.
    #[derive(Debug)]
    struct FakeError(String);

    impl std::fmt::Display for FakeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for FakeError {}

    /// Helper: returns `true` when the error is the transient `Unavailable` variant.
    fn is_unavailable(e: &SecretError) -> bool {
        matches!(e, SecretError::Unavailable { .. })
    }

    /// Helper: returns `true` when the error is the permanent `Backend` variant.
    fn is_backend(e: &SecretError) -> bool {
        matches!(e, SecretError::Backend { .. })
    }

    #[test]
    fn classify_5xx_server_error() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "Received error message from server: [500] Internal Server Error".into(),
        ));
        assert!(is_unavailable(&e), "5xx should be transient: {e:?}");
    }

    #[test]
    fn classify_503_server_error() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "Received error message from server: [503] Service Unavailable".into(),
        ));
        assert!(is_unavailable(&e), "503 should be transient: {e:?}");
    }

    #[test]
    fn classify_429_rate_limit() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "Received error message from server: [429] Too Many Requests".into(),
        ));
        assert!(is_unavailable(&e), "429 should be transient: {e:?}");
    }

    #[test]
    fn classify_4xx_permanent() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "Received error message from server: [401] Unauthorized".into(),
        ));
        assert!(is_backend(&e), "401 should be permanent: {e:?}");
    }

    #[test]
    fn classify_error_sending_request() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "error sending request for url (https://example.com): connection refused".into(),
        ));
        assert!(is_unavailable(&e), "network send error should be transient: {e:?}");
    }

    #[test]
    fn classify_connection_refused() {
        let e = classify_bitwarden_sdk_error(FakeError("connection refused".into()));
        assert!(is_unavailable(&e), "connection refused should be transient: {e:?}");
    }

    #[test]
    fn classify_connection_reset() {
        let e = classify_bitwarden_sdk_error(FakeError("connection reset by peer".into()));
        assert!(is_unavailable(&e), "connection reset should be transient: {e:?}");
    }

    #[test]
    fn classify_timed_out() {
        let e = classify_bitwarden_sdk_error(FakeError("operation timed out".into()));
        assert!(is_unavailable(&e), "timed out should be transient: {e:?}");
    }

    #[test]
    fn classify_dns_error() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "dns error: failed to lookup address information".into(),
        ));
        assert!(is_unavailable(&e), "dns error should be transient: {e:?}");
    }

    #[test]
    fn classify_no_such_host() {
        let e = classify_bitwarden_sdk_error(FakeError("No such host is known".into()));
        assert!(is_unavailable(&e), "No such host should be transient: {e:?}");
    }

    #[test]
    fn classify_name_or_service_not_known() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "Name or service not known".into(),
        ));
        assert!(is_unavailable(&e), "Name or service not known should be transient: {e:?}");
    }

    #[test]
    fn classify_unknown_error_is_permanent() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "some unknown SDK error message".into(),
        ));
        assert!(is_backend(&e), "unrecognised error should be permanent: {e:?}");
    }

    #[test]
    fn classify_validation_error_is_permanent() {
        let e = classify_bitwarden_sdk_error(FakeError(
            "Validation failed: field X is required".into(),
        ));
        assert!(is_backend(&e), "validation error should be permanent: {e:?}");
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
