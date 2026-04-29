//! Kubernetes Secret backend for secretx.
//!
//! URI: `secretx:k8s:<namespace>/<secret-name>[?key=<data-key>]`

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::{api::core::v1::Secret as K8sSecret, ByteString};
use kube::api::{Patch, PatchParams, PostParams};
use kube::Api;
use secretx_core::{SecretError, SecretUri};
use std::collections::BTreeMap;

const BACKEND: &str = "k8s";

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
    /// Construct from a `secretx:k8s:<namespace>/<secret-name>[?key=<data-key>]` URI.
    ///
    /// Validates URI syntax only — no network call is made at construction time.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
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

        if namespace.is_empty() {
            return Err(SecretError::InvalidUri(
                "k8s namespace must not be empty".into(),
            ));
        }
        if name.is_empty() {
            return Err(SecretError::InvalidUri(
                "k8s secret name must not be empty".into(),
            ));
        }
        if name.contains('/') {
            return Err(SecretError::InvalidUri(
                "k8s secret name must not contain '/'".into(),
            ));
        }

        let key = parsed.param("key").map(str::to_owned);

        Ok(Self {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            key,
            client: tokio::sync::OnceCell::new(),
        })
    }
}

fn map_kube_error(e: kube::Error) -> SecretError {
    match &e {
        kube::Error::Api(s) if s.is_forbidden() => SecretError::Unavailable {
            backend: BACKEND,
            source: Box::new(e),
        },
        _ => SecretError::Backend {
            backend: BACKEND,
            source: Box::new(e),
        },
    }
}

#[async_trait::async_trait]
impl secretx_core::SecretStore for K8sBackend {
    async fn get(&self) -> Result<secretx_core::SecretValue, SecretError> {
        let client = self
            .client
            .get_or_try_init(|| async {
                kube::Client::try_default()
                    .await
                    .map_err(|e| SecretError::Unavailable {
                        backend: BACKEND,
                        source: Box::new(e),
                    })
            })
            .await?
            .clone();

        let api: Api<K8sSecret> = Api::namespaced(client, &self.namespace);

        let secret = api.get_opt(&self.name).await.map_err(map_kube_error)?;

        let secret = secret.ok_or(SecretError::NotFound)?;
        let data = secret.data.ok_or(SecretError::NotFound)?;

        if let Some(k) = &self.key {
            let bs = data.get(k.as_str()).ok_or(SecretError::NotFound)?;
            Ok(secretx_core::SecretValue::new(bs.0.clone()))
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
        let client = self
            .client
            .get_or_try_init(|| async {
                kube::Client::try_default()
                    .await
                    .map_err(|e| SecretError::Unavailable {
                        backend: BACKEND,
                        source: Box::new(e),
                    })
            })
            .await?
            .clone();

        let api: Api<K8sSecret> = Api::namespaced(client, &self.namespace);
        // When ?key= is absent, store under the literal key name "value".  This is
        // documented behaviour: a no-key Secret created by secretx-k8s will always
        // have exactly one entry in .data named "value".
        let key_name = self.key.as_deref().unwrap_or("value");
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
            //
            // Note: data.clone() is necessary because K8sSecret takes ownership of
            // the map, but we need data again if the patch returns 404 and we must
            // fall through to the create path.  Both copies are non-Zeroizing (see
            // ZEROIZATION GAP above).
            let patch_secret = K8sSecret {
                data: Some(data.clone()),
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
                    // Secret doesn't exist — fall through to create
                }
                Err(e) => return Err(map_kube_error(e)),
            }
        } else {
            // Server-side apply (SSA): create-or-update in a single API call.
            // SSA gives field manager "secretx-k8s" ownership of the "value" key.
            // Subsequent no-key puts update "value" in-place; keys owned by other
            // managers (e.g. set via ?key=) are left untouched by SSA.
            //
            // We use SSA here (not merge patch) because SSA is an atomic
            // create-or-update that does not require knowing the current
            // resourceVersion, making it safe to call from multiple replicas.
            let apply_secret = K8sSecret {
                data: Some(data.clone()),
                ..Default::default()
            };
            match api
                .patch(
                    &self.name,
                    &PatchParams::apply("secretx-k8s"),
                    &Patch::Apply(apply_secret),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(ref s)) if s.is_not_found() => {
                    // SSA is supposed to create-or-update; a 404 here would mean
                    // the API group itself is unavailable rather than the resource
                    // being absent.  Fall through to an explicit POST as a last resort.
                }
                Err(e) => return Err(map_kube_error(e)),
            }
        }

        // Create path: Secret does not exist yet (merge-patch 404) or SSA
        // unexpectedly returned 404.
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
        api.create(&PostParams::default(), &new_secret)
            .await
            .map(|_| ())
            .map_err(map_kube_error)
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: BACKEND,
    factory: |uri: &str| {
        K8sBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: BACKEND,
    factory: |uri: &str| {
        K8sBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// These tests are written TDD-style: the K8sBackend struct and from_uri()
// do not exist yet.  The tests will fail to compile until the implementer
// adds:
//
//   pub(crate) struct K8sBackend {
//       pub(crate) namespace: String,
//       pub(crate) name: String,
//       pub(crate) key: Option<String>,
//       // ... additional fields (e.g. kube::Client) as needed
//   }
//
//   impl K8sBackend {
//       pub fn from_uri(uri: &str) -> Result<Self, SecretError> { ... }
//   }
//
// Once those exist, all tests below must pass without modification.

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
}

// ── Mock HTTP tests: SecretStore::get() ───────────────────────────────────────

#[cfg(test)]
mod get_mock_tests {
    use super::*;
    use http::{Request, Response};
    use kube::client::Body;
    use serde_json::json;

    type Handle = tower_test::mock::Handle<Request<Body>, Response<Body>>;

    fn make_pair() -> (kube::Client, Handle) {
        let (svc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = kube::Client::new(svc, "default");
        (client, handle)
    }

    fn make_backend(uri: &str, client: kube::Client) -> K8sBackend {
        let backend = K8sBackend::from_uri(uri).unwrap();
        backend.client.set(client).ok();
        backend
    }

    async fn respond(handle: &mut Handle, status: u16, body: serde_json::Value) {
        let (_, send) = handle.next_request().await.expect("expected mock request");
        let bytes = serde_json::to_vec(&body).unwrap();
        send.send_response(
            Response::builder()
                .status(status)
                .body(Body::from(bytes))
                .unwrap(),
        );
    }

    fn secret_json(namespace: &str, name: &str, data: serde_json::Value) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": name, "namespace": namespace, "resourceVersion": "1" },
            "data": data,
            "type": "Opaque"
        })
    }

    fn not_found_json(name: &str) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "NotFound",
            "code": 404,
            "message": format!("secrets \"{}\" not found", name)
        })
    }

    fn forbidden_json() -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "Forbidden",
            "code": 403,
            "message": "secrets is forbidden"
        })
    }

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
        mock.await.unwrap();
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
        mock.await.unwrap();
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
        mock.await.unwrap();
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
        mock.await.unwrap();
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
        mock.await.unwrap();
    }

    /// 403 Forbidden response: must return `Unavailable`.
    #[tokio::test]
    async fn test_get_forbidden_is_unavailable() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret", client);

        let resp = forbidden_json();
        let mock = tokio::spawn(async move { respond(&mut handle, 403, resp).await });

        let Err(err) = secretx_core::SecretStore::get(&backend).await else {
            panic!("expected Err(Unavailable)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::Unavailable { .. }),
            "expected Unavailable for 403, got: {err:?}"
        );
        mock.await.unwrap();
    }
}

// ── Mock HTTP tests: WritableSecretStore::put() ───────────────────────────────

#[cfg(test)]
mod put_mock_tests {
    use super::*;
    use http::{Request, Response};
    use kube::client::Body;
    use serde_json::json;

    type Handle = tower_test::mock::Handle<Request<Body>, Response<Body>>;

    fn make_pair() -> (kube::Client, Handle) {
        let (svc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = kube::Client::new(svc, "default");
        (client, handle)
    }

    fn make_backend(uri: &str, client: kube::Client) -> K8sBackend {
        let backend = K8sBackend::from_uri(uri).unwrap();
        backend.client.set(client).ok();
        backend
    }

    async fn respond(handle: &mut Handle, status: u16, body: serde_json::Value) {
        let (_, send) = handle.next_request().await.expect("expected mock request");
        let bytes = serde_json::to_vec(&body).unwrap();
        send.send_response(
            Response::builder()
                .status(status)
                .body(Body::from(bytes))
                .unwrap(),
        );
    }

    fn secret_json(namespace: &str, name: &str, data: serde_json::Value) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": name, "namespace": namespace, "resourceVersion": "2" },
            "data": data,
            "type": "Opaque"
        })
    }

    fn not_found_json(name: &str) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "NotFound",
            "code": 404,
            "message": format!("secrets \"{}\" not found", name)
        })
    }

    fn forbidden_json() -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "Forbidden",
            "code": 403,
            "message": "secrets is forbidden"
        })
    }

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
        mock.await.unwrap();
    }

    /// `?key=` specified, PATCH returns 404 → falls through to POST create (201): Ok(()).
    #[tokio::test]
    async fn test_put_with_key_creates_on_404() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/new-secret?key=password", client);

        let mock = tokio::spawn(async move {
            // First request: PATCH → 404
            respond(&mut handle, 404, not_found_json("new-secret")).await;
            // Second request: POST create → 201
            respond(
                &mut handle,
                201,
                secret_json("default", "new-secret", json!({ "password": "aGVsbG8=" })),
            )
            .await;
        });

        let value = secretx_core::SecretValue::new(b"hello".to_vec());
        secretx_core::WritableSecretStore::put(&backend, value)
            .await
            .unwrap();
        mock.await.unwrap();
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
        mock.await.unwrap();
    }

    /// 403 Forbidden response to PATCH: `put()` returns `Unavailable`.
    #[tokio::test]
    async fn test_put_forbidden_is_unavailable() {
        let (client, mut handle) = make_pair();
        let backend = make_backend("secretx:k8s:default/my-secret?key=password", client);

        let resp = forbidden_json();
        let mock = tokio::spawn(async move { respond(&mut handle, 403, resp).await });

        let value = secretx_core::SecretValue::new(b"hello".to_vec());
        let Err(err) = secretx_core::WritableSecretStore::put(&backend, value).await else {
            panic!("expected Err(Unavailable)");
        };
        assert!(
            matches!(err, secretx_core::SecretError::Unavailable { .. }),
            "expected Unavailable for 403, got: {err:?}"
        );
        mock.await.unwrap();
    }
}
