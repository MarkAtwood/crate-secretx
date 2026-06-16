//! Kubernetes Secret backend for secretx.
//!
//! URI: `secretx:k8s:<namespace>/<secret-name>[?key=<data-key>]`

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::{api::core::v1::Secret as K8sSecret, ByteString};
use kube::api::{Patch, PatchParams, PostParams};
use kube::Api;
use secretx_core::{SecretError, SecretUri};
use std::collections::BTreeMap;
use std::sync::Arc;

const BACKEND: &str = "k8s";
const FIELD_MANAGER: &str = "secretx-k8s";
/// Default data key used when no `?key=` parameter is specified in the URI.
const DEFAULT_DATA_KEY: &str = "value";

/// Validate a Kubernetes name as a DNS-1123 subdomain (RFC 1123 §2.1).
///
/// Rules: lowercase alphanumeric or `-`/`.`, max 253 chars, must start and
/// end with an alphanumeric character.
fn validate_dns1123(label: &str, value: &str) -> Result<(), SecretError> {
    if value.is_empty() {
        return Err(SecretError::InvalidUri(format!(
            "k8s {label} must not be empty"
        )));
    }
    if value.len() > 253 {
        return Err(SecretError::InvalidUri(format!(
            "k8s {label} `{value}` exceeds 253 characters"
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(SecretError::InvalidUri(format!(
            "k8s {label} `{value}` contains invalid characters; \
             must be lowercase alphanumeric, '-', or '.'"
        )));
    }
    let first = value.as_bytes()[0];
    let last = value.as_bytes()[value.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(SecretError::InvalidUri(format!(
            "k8s {label} `{value}` must start and end with an alphanumeric character"
        )));
    }
    Ok(())
}

/// Backend that reads and writes Kubernetes Secrets.
///
/// Construct with [`K8sBackend::from_uri`]. The Kubernetes client is
/// initialized lazily on first use, so construction never makes a network call.
pub struct K8sBackend {
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) key: Option<String>,
    client: tokio::sync::OnceCell<kube::Client>,
}

impl std::fmt::Debug for K8sBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sBackend")
            .field("namespace", &self.namespace)
            .field("name", &self.name)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl K8sBackend {
    /// Lazily initialize the Kubernetes client, returning a reference.
    ///
    /// The client is created on first use via [`kube::Client::try_default()`].
    /// Subsequent calls return the cached instance.
    async fn ensure_client(&self) -> Result<kube::Client, SecretError> {
        self.client
            .get_or_try_init(|| async {
                kube::Client::try_default()
                    .await
                    .map_err(|e| SecretError::Unavailable {
                        backend: BACKEND,
                        source: Box::new(e),
                    })
            })
            .await
            .cloned()
    }

    /// Construct from a `secretx:k8s:<namespace>/<secret-name>[?key=<data-key>]` URI.
    ///
    /// Validates URI syntax only — no network call is made at construction time.
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

        let path = parsed.path();
        let (namespace, name) = path.split_once('/').ok_or_else(|| {
            SecretError::InvalidUri("k8s URI must be secretx:k8s:<namespace>/<secret-name>".into())
        })?;

        validate_dns1123("namespace", namespace)?;
        validate_dns1123("secret name", name)?;

        let key = parsed.param("key").map(str::to_owned);
        // K8s Secret data keys must match [-._a-zA-Z0-9]+; reject invalid
        // keys at construction rather than surfacing confusing runtime errors.
        if let Some(ref k) = key {
            if k.is_empty() {
                return Err(SecretError::InvalidUri(
                    "k8s URI `?key=` value must not be empty".into(),
                ));
            }
            if !k
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            {
                return Err(SecretError::InvalidUri(format!(
                    "k8s URI `?key={k}` contains invalid characters; \
                     data keys must match [-._a-zA-Z0-9]+"
                )));
            }
        }

        Ok(Self {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            key,
            client: tokio::sync::OnceCell::new(),
        })
    }
}

/// Classify a kube error as transient ([`SecretError::Unavailable`]) or
/// permanent ([`SecretError::Backend`]).
///
/// Transient (retry may succeed): network errors, transport failures,
/// token-refresh failures, API 429/5xx.
/// Permanent (retry will not help): RBAC denials, bad requests, config errors.
fn map_kube_error(e: kube::Error) -> SecretError {
    let is_transient = match &e {
        // API errors: 429 and 5xx are transient server-side conditions.
        kube::Error::Api(s) => s.code == 429 || (500..600).contains(&s.code),
        // Network / transport / tower middleware — server may still be healthy.
        kube::Error::HyperError(_) | kube::Error::Service(_) | kube::Error::ReadEvents(_) => true,
        // Auth token refresh failure — may succeed after credential rotation.
        kube::Error::Auth(_) => true,
        // Everything else (bad config, serialization, build errors) is permanent.
        _ => false,
    };
    if is_transient {
        SecretError::Unavailable {
            backend: BACKEND,
            source: Box::new(e),
        }
    } else {
        SecretError::Backend {
            backend: BACKEND,
            source: Box::new(e),
        }
    }
}

#[async_trait::async_trait]
impl secretx_core::SecretStore for K8sBackend {
    async fn get(&self) -> Result<secretx_core::SecretValue, SecretError> {
        let client = self.ensure_client().await?;

        let api: Api<K8sSecret> = Api::namespaced(client, &self.namespace);

        let secret = api.get_opt(&self.name).await.map_err(map_kube_error)?;

        let secret = secret.ok_or(SecretError::NotFound)?;
        let mut data = secret.data.ok_or(SecretError::NotFound)?;

        if let Some(k) = &self.key {
            let bs = data.remove(k.as_str()).ok_or(SecretError::NotFound)?;
            Ok(secretx_core::SecretValue::new(bs.0))
        } else {
            match data.len() {
                0 => Err(SecretError::NotFound),
                1 => {
                    // len==1 is proven by the match arm above; into_values() skips the key.
                    let bs = data
                        .into_values()
                        .next()
                        .expect("len==1 guarantees one entry");
                    Ok(secretx_core::SecretValue::new(bs.0))
                }
                _ => Err(SecretError::InvalidUri(
                    "Secret has multiple keys; add ?key=<name> to the URI to select one".into(),
                )),
            }
        }
    }
    async fn refresh(&self) -> Result<secretx_core::SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl secretx_core::WritableSecretStore for K8sBackend {
    async fn put(&self, value: secretx_core::SecretValue) -> Result<(), SecretError> {
        let client = self.ensure_client().await?;

        let api: Api<K8sSecret> = Api::namespaced(client, &self.namespace);
        // When ?key= is absent, store under DEFAULT_DATA_KEY.  This is documented
        // behaviour: a no-key Secret created by secretx-k8s will always have
        // exactly one entry in .data named DEFAULT_DATA_KEY.
        let key_name = self.key.as_deref().unwrap_or(DEFAULT_DATA_KEY);
        let bytes = value.into_bytes();

        // ZEROIZATION GAP: ByteString wraps a plain Vec<u8> (not Zeroizing).
        // The copy here is unavoidable — k8s-openapi does not provide a
        // Zeroizing-compatible ByteString.  The original SecretValue is zeroed
        // on drop; the copy lives until the HTTP request is serialised and sent.
        let mut data: BTreeMap<String, ByteString> = BTreeMap::new();
        data.insert(key_name.to_owned(), ByteString(bytes.to_vec()));

        if self.key.is_some() {
            // JSON merge patch: adds/updates the target key while preserving all
            // other keys in the Secret.  We use merge patch (not SSA) here because
            // per-key writes do not require field-ownership tracking.
            // On 404 (Secret does not exist yet), fall through to create.
            let patch_secret = K8sSecret {
                data: Some(data),
                ..Default::default()
            };
            match api
                .patch(
                    &self.name,
                    &PatchParams::default(),
                    &Patch::Merge(patch_secret),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(ref s)) if s.is_not_found() => {
                    // Secret doesn't exist — fall through to create.
                    // Rebuild data from the original bytes (avoids clone above).
                    data = BTreeMap::new();
                    data.insert(key_name.to_owned(), ByteString(bytes.to_vec()));
                }
                Err(e) => return Err(map_kube_error(e)),
            }
        } else {
            // Server-side apply (SSA): create-or-update in a single API call.
            // SSA gives field manager FIELD_MANAGER ownership of the DEFAULT_DATA_KEY key.
            // Subsequent no-key puts update "value" in-place; keys owned by other
            // managers (e.g. set via ?key=) are left untouched by SSA.
            //
            // We use SSA here (not merge patch) because SSA is an atomic
            // create-or-update that does not require knowing the current
            // resourceVersion, making it safe to call from multiple replicas.
            let apply_secret = K8sSecret {
                data: Some(data),
                ..Default::default()
            };
            match api
                .patch(
                    &self.name,
                    &PatchParams::apply(FIELD_MANAGER),
                    &Patch::Apply(apply_secret),
                )
                .await
            {
                Ok(_) => return Ok(()),
                // SSA creates-or-updates in one call. A 404 here means the
                // namespace itself is missing or the API group is unreachable —
                // falling through to POST would also fail. Surface the error.
                Err(e) => return Err(map_kube_error(e)),
            }
        }

        // Create path: Secret does not exist yet (merge-patch 404 with ?key=).
        let new_secret = K8sSecret {
            metadata: ObjectMeta {
                name: Some(self.name.clone()),
                namespace: Some(self.namespace.clone()),
                ..Default::default()
            },
            data: Some(data),
            type_: Some("Opaque".to_owned()),
            ..Default::default()
        };
        match api.create(&PostParams::default(), &new_secret).await {
            Ok(_) => Ok(()),
            // Race: another writer created the Secret between our PATCH 404
            // and this POST.  Retry the PATCH once — the Secret now exists.
            Err(kube::Error::Api(ref s)) if s.is_already_exists() => {
                let retry_data = {
                    let mut m = BTreeMap::new();
                    m.insert(key_name.to_owned(), ByteString(bytes.to_vec()));
                    m
                };
                let retry_secret = K8sSecret {
                    data: Some(retry_data),
                    ..Default::default()
                };
                api.patch(
                    &self.name,
                    &PatchParams::default(),
                    &Patch::Merge(retry_secret),
                )
                .await
                .map(|_| ())
                .map_err(map_kube_error)
            }
            Err(e) => Err(map_kube_error(e)),
        }
    }
}

inventory::submit!(secretx_core::BackendRegistration::new(
    BACKEND,
    |uri: &secretx_core::SecretUri| {
        let b = K8sBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

inventory::submit!(secretx_core::WritableBackendRegistration::new(
    BACKEND,
    |uri: &secretx_core::SecretUri| {
        let b = K8sBackend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::WritableSecretStore>)
    },
));

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use secretx_core::SecretError;

    // ── valid URI: no key ──────────────────────────────────────────────────

    /// `secretx:k8s:default/my-secret` — no `?key=` param.
    /// Expect: Ok; namespace == "default", name == "my-secret", key == None.
    #[test]
    fn test_from_uri_valid_no_key() {
        let backend = K8sBackend::from_uri("secretx:k8s:default/my-secret")
            .expect("valid URI must parse successfully");
        assert_eq!(backend.namespace, "default");
        assert_eq!(backend.name, "my-secret");
        assert_eq!(backend.key, None);
    }

    // ── valid URI: with key ────────────────────────────────────────────────

    /// `secretx:k8s:prod/db-creds?key=password` — `?key=` param present.
    /// Expect: Ok; key == Some("password").
    #[test]
    fn test_from_uri_valid_with_key() {
        let backend = K8sBackend::from_uri("secretx:k8s:prod/db-creds?key=password")
            .expect("valid URI with key must parse successfully");
        assert_eq!(backend.namespace, "prod");
        assert_eq!(backend.name, "db-creds");
        assert_eq!(backend.key, Some("password".to_string()));
    }

    // ── wrong backend ──────────────────────────────────────────────────────

    /// URI names a different backend (`aws-sm`).
    /// Expect: Err(InvalidUri).
    #[test]
    fn test_from_uri_wrong_backend() {
        let result = K8sBackend::from_uri("secretx:aws-sm:foo");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "wrong backend must return InvalidUri, got: {result:?}"
        );
    }

    // ── empty namespace ────────────────────────────────────────────────────

    /// `secretx:k8s:/my-secret` — namespace is empty (leading slash).
    /// Expect: Err(InvalidUri).
    #[test]
    fn test_from_uri_empty_namespace() {
        let result = K8sBackend::from_uri("secretx:k8s:/my-secret");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "empty namespace must return InvalidUri, got: {result:?}"
        );
    }

    // ── empty name ─────────────────────────────────────────────────────────

    /// `secretx:k8s:default/` — secret name is empty (trailing slash).
    /// Expect: Err(InvalidUri).
    #[test]
    fn test_from_uri_empty_name() {
        let result = K8sBackend::from_uri("secretx:k8s:default/");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "empty name must return InvalidUri, got: {result:?}"
        );
    }

    // ── no slash ───────────────────────────────────────────────────────────

    /// `secretx:k8s:default` — no slash separating namespace and name.
    /// Expect: Err(InvalidUri).
    #[test]
    fn test_from_uri_no_slash() {
        let result = K8sBackend::from_uri("secretx:k8s:default");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "missing slash must return InvalidUri, got: {result:?}"
        );
    }

    // ── extra slash in name ────────────────────────────────────────────────

    /// `secretx:k8s:default/a/b` — more than one slash; `a/b` is not a
    /// valid Kubernetes secret name.
    /// Expect: Err(InvalidUri).
    #[test]
    fn test_from_uri_slash_in_name() {
        let result = K8sBackend::from_uri("secretx:k8s:default/a/b");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "slash in name must return InvalidUri, got: {result:?}"
        );
    }

    #[test]
    fn test_from_uri_empty_key_rejected() {
        let result = K8sBackend::from_uri("secretx:k8s:default/my-secret?key=");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "empty ?key= must return InvalidUri, got: {result:?}"
        );
    }

    #[test]
    fn test_from_uri_invalid_key_chars_rejected() {
        let result = K8sBackend::from_uri("secretx:k8s:default/my-secret?key=foo/bar");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "key with '/' must return InvalidUri, got: {result:?}"
        );
    }
}

// ── Shared mock helpers for get and put tests ─────────────────────────────────

#[cfg(test)]
mod mock_helpers {
    use super::*;
    use http::{Request, Response};
    use kube::client::Body;
    use serde_json::json;

    pub type Handle = tower_test::mock::Handle<Request<Body>, Response<Body>>;

    pub fn make_pair() -> (kube::Client, Handle) {
        let (svc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = kube::Client::new(svc, "default");
        (client, handle)
    }

    pub fn make_backend(uri: &str, client: kube::Client) -> K8sBackend {
        let backend = K8sBackend::from_uri(uri).unwrap();
        backend.client.set(client).ok();
        backend
    }

    pub async fn respond(
        handle: &mut Handle,
        status: u16,
        body: serde_json::Value,
    ) -> Request<Body> {
        let (req, send) = handle.next_request().await.expect("expected mock request");
        let bytes = serde_json::to_vec(&body).unwrap();
        send.send_response(
            Response::builder()
                .status(status)
                .body(Body::from(bytes))
                .unwrap(),
        );
        req
    }

    pub fn secret_json(
        namespace: &str,
        name: &str,
        data: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": name, "namespace": namespace, "resourceVersion": "1" },
            "data": data,
            "type": "Opaque"
        })
    }

    pub fn not_found_json(name: &str) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "NotFound",
            "code": 404,
            "message": format!("secrets \"{}\" not found", name)
        })
    }

    pub fn forbidden_json() -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "Forbidden",
            "code": 403,
            "message": "secrets is forbidden"
        })
    }
}

// ── Mock HTTP tests: SecretStore::get() ───────────────────────────────────────

#[cfg(test)]
mod get_mock_tests {
    use super::mock_helpers::*;
    use serde_json::json;

    /// Single-key Secret, no `?key=`: returns that key's bytes.
    #[tokio::test]
    async fn test_get_single_key_returns_bytes() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret", client);

        // "aGVsbG8=" == base64("hello")
        let resp = secret_json("default", "my-secret", json!({ "value": "aGVsbG8=" }));
        let mock = tokio::spawn(async move { respond(&mut handle, 200, resp).await });

        let result = secretx_core::SecretStore::get(&backend).await.unwrap();
        assert_eq!(result.as_bytes(), b"hello");
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
        assert!(
            req.uri().path().contains("/namespaces/default/secrets/my-secret"),
            "GET path must target the correct namespace/secret, got: {}",
            req.uri()
        );
    }

    /// Multi-key Secret with `?key=db-pass`: returns that specific key's bytes.
    #[tokio::test]
    async fn test_get_specific_key_with_key_param() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret?key=db-pass", client);

        // "aGVsbG8=" == base64("hello"), "d29ybGQ=" == base64("world")
        let resp = secret_json(
            "default",
            "my-secret",
            json!({ "db-pass": "aGVsbG8=", "db-user": "d29ybGQ=" }),
        );
        let mock = tokio::spawn(async move { respond(&mut handle, 200, resp).await });

        let result = secretx_core::SecretStore::get(&backend).await.unwrap();
        assert_eq!(result.as_bytes(), b"hello");
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
        assert!(
            req.uri().path().contains("/namespaces/default/secrets/my-secret"),
            "GET path must target the correct namespace/secret, got: {}",
            req.uri()
        );
    }

    /// Multi-key Secret, no `?key=`: must return `InvalidUri`.
    #[tokio::test]
    async fn test_get_multi_key_no_key_param_err() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret", client);

        let resp = secret_json(
            "default",
            "my-secret",
            json!({ "db-pass": "aGVsbG8=", "db-user": "d29ybGQ=" }),
        );
        let mock = tokio::spawn(async move { respond(&mut handle, 200, resp).await });

        let Err(err) = secretx_core::SecretStore::get(&backend).await else {
            panic!("expected Err(InvalidUri)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::InvalidUri(_)),
            "expected InvalidUri, got: {err:?}"
        );
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
    }

    /// Secret not found (404): must return `NotFound`.
    #[tokio::test]
    async fn test_get_not_found() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/missing", client);

        let resp = not_found_json("missing");
        let mock = tokio::spawn(async move { respond(&mut handle, 404, resp).await });

        let Err(err) = secretx_core::SecretStore::get(&backend).await else {
            panic!("expected Err(NotFound)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::NotFound),
            "expected NotFound, got: {err:?}"
        );
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
        assert!(
            req.uri().path().contains("/namespaces/default/secrets/missing"),
            "GET path must target the correct secret, got: {}",
            req.uri()
        );
    }

    /// Secret exists but `.data` is absent: must return `NotFound`.
    #[tokio::test]
    async fn test_get_data_none_is_not_found() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/empty", client);

        // Secret with no "data" field
        let resp = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "empty", "namespace": "default", "resourceVersion": "1" },
            "type": "Opaque"
        });
        let mock = tokio::spawn(async move { respond(&mut handle, 200, resp).await });

        let Err(err) = secretx_core::SecretStore::get(&backend).await else {
            panic!("expected Err(NotFound)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::NotFound),
            "expected NotFound for absent .data, got: {err:?}"
        );
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
    }

    /// 403 Forbidden response: must return `Backend` (permanent RBAC error).
    #[tokio::test]
    async fn test_get_forbidden_is_backend() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret", client);

        let resp = forbidden_json();
        let mock = tokio::spawn(async move { respond(&mut handle, 403, resp).await });

        let Err(err) = secretx_core::SecretStore::get(&backend).await else {
            panic!("expected Err(Backend)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::Backend { .. }),
            "expected Backend for 403, got: {err:?}"
        );
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
    }

    fn server_error_json() -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "InternalError",
            "code": 500,
            "message": "Internal error occurred"
        })
    }

    fn too_many_requests_json() -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "TooManyRequests",
            "code": 429,
            "message": "Too many requests"
        })
    }

    /// 500 Internal Server Error: must return `Unavailable` (transient).
    #[tokio::test]
    async fn test_get_500_is_unavailable() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret", client);

        let resp = server_error_json();
        let mock = tokio::spawn(async move { respond(&mut handle, 500, resp).await });

        let Err(err) = secretx_core::SecretStore::get(&backend).await else {
            panic!("expected Err(Unavailable)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::Unavailable { .. }),
            "expected Unavailable for 500, got: {err:?}"
        );
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
    }

    /// 429 Too Many Requests: must return `Unavailable` (transient).
    #[tokio::test]
    async fn test_get_429_is_unavailable() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret", client);

        let resp = too_many_requests_json();
        let mock = tokio::spawn(async move { respond(&mut handle, 429, resp).await });

        let Err(err) = secretx_core::SecretStore::get(&backend).await else {
            panic!("expected Err(Unavailable)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::Unavailable { .. }),
            "expected Unavailable for 429, got: {err:?}"
        );
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::GET);
    }
}

// ── Mock HTTP tests: WritableSecretStore::put() ───────────────────────────────

#[cfg(test)]
mod put_mock_tests {
    use super::mock_helpers::*;
    use serde_json::json;

    /// `?key=` specified, PATCH succeeds (200): `put()` returns Ok(()).
    #[tokio::test]
    async fn test_put_with_key_patch_succeeds() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret?key=password", client);

        let resp = secret_json("default", "my-secret", json!({ "password": "aGVsbG8=" }));
        let mock = tokio::spawn(async move { respond(&mut handle, 200, resp).await });

        let value = secretx_core::SecretValue::new(b"hello".to_vec());
        secretx_core::WritableSecretStore::put(&backend, value)
            .await
            .unwrap();
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::PATCH);
        assert!(
            req.uri()
                .path()
                .contains("/namespaces/default/secrets/my-secret"),
            "PATCH path must target the correct namespace/secret, got: {}",
            req.uri()
        );
        assert_eq!(
            req.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/merge-patch+json"),
            "merge-patch with ?key= must use application/merge-patch+json"
        );
    }

    /// `?key=` specified, PATCH returns 404 → falls through to POST create (201): Ok(()).
    #[tokio::test]
    async fn test_put_with_key_creates_on_404() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/new-secret?key=password", client);

        let mock = tokio::spawn(async move {
            // First request: PATCH → 404
            let req1 = respond(&mut handle, 404, not_found_json("new-secret")).await;
            // Second request: POST create → 201
            let req2 = respond(
                &mut handle,
                201,
                secret_json("default", "new-secret", json!({ "password": "aGVsbG8=" })),
            )
            .await;
            (req1, req2)
        });

        let value = secretx_core::SecretValue::new(b"hello".to_vec());
        secretx_core::WritableSecretStore::put(&backend, value)
            .await
            .unwrap();
        let (req1, req2) = mock.await.unwrap();

        // First request: merge-patch attempt
        assert_eq!(req1.method(), http::Method::PATCH);
        assert!(
            req1.uri()
                .path()
                .contains("/namespaces/default/secrets/new-secret"),
            "PATCH path must target the correct secret, got: {}",
            req1.uri()
        );
        assert_eq!(
            req1.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/merge-patch+json"),
            "merge-patch with ?key= must use application/merge-patch+json"
        );

        // Second request: POST create fallback
        assert_eq!(req2.method(), http::Method::POST);
        assert!(
            req2.uri().path().contains("/namespaces/default/secrets"),
            "POST path must target the secrets collection, got: {}",
            req2.uri()
        );
    }

    /// No `?key=`, SSA PATCH succeeds (200): `put()` returns Ok(()).
    #[tokio::test]
    async fn test_put_no_key_ssa_succeeds() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret", client);

        let resp = secret_json("default", "my-secret", json!({ "value": "aGVsbG8=" }));
        let mock = tokio::spawn(async move { respond(&mut handle, 200, resp).await });

        let value = secretx_core::SecretValue::new(b"hello".to_vec());
        secretx_core::WritableSecretStore::put(&backend, value)
            .await
            .unwrap();
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::PATCH);
        assert!(
            req.uri()
                .path()
                .contains("/namespaces/default/secrets/my-secret"),
            "SSA PATCH path must target the correct namespace/secret, got: {}",
            req.uri()
        );
        // SSA (server-side apply) uses application/apply-patch+yaml content type.
        assert_eq!(
            req.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/apply-patch+yaml"),
            "SSA without ?key= must use application/apply-patch+yaml"
        );
        // SSA must include the fieldManager query parameter.
        let query = req.uri().query().unwrap_or("");
        assert!(
            query.contains("fieldManager=secretx-k8s"),
            "SSA must set fieldManager=secretx-k8s, got query: {query}"
        );
    }

    /// 403 Forbidden response to PATCH: `put()` returns `Backend` (permanent RBAC error).
    #[tokio::test]
    async fn test_put_forbidden_is_backend() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret?key=password", client);

        let resp = forbidden_json();
        let mock = tokio::spawn(async move { respond(&mut handle, 403, resp).await });

        let value = secretx_core::SecretValue::new(b"hello".to_vec());
        let Err(err) = secretx_core::WritableSecretStore::put(&backend, value).await else {
            panic!("expected Err(Backend)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::Backend { .. }),
            "expected Backend for 403, got: {err:?}"
        );
        let req = mock.await.unwrap();
        assert_eq!(req.method(), http::Method::PATCH);
        assert_eq!(
            req.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/merge-patch+json"),
            "merge-patch with ?key= must use application/merge-patch+json"
        );
    }
}
