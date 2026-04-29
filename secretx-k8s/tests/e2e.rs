//! End-to-end integration test for secretx-k8s.
//!
//! Requires `SECRETX_K8S_KUBECONFIG` to point to a valid kubeconfig file
//! (e.g. a kind cluster). Silently skipped when the env var is absent.
//!
//! Run with:
//!   SECRETX_K8S_KUBECONFIG=~/.kube/kind-config cargo test -p secretx-k8s -- --test-threads=1
//!
//! The `--test-threads=1` flag is required because this test mutates the KUBECONFIG
//! environment variable, which is a process-global resource.  Running in a single
//! thread prevents races with other tests that also call kube::Client::try_default().

use k8s_openapi::api::core::v1::Secret as K8sSecret;
use kube::api::DeleteParams;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Api, Client, Config};
use secretx_core::{SecretError, SecretValue};
use secretx_k8s::K8sBackend;

fn unique_name(base: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{base}-{ts}")
}

#[tokio::test]
async fn k8s_round_trip() {
    let kubeconfig_path = match std::env::var("SECRETX_K8S_KUBECONFIG") {
        Ok(v) => v,
        Err(_) => return, // skip when not configured
    };

    // Point the kube client at the test cluster by setting KUBECONFIG.
    // This is a process-global mutation; run with --test-threads=1 (see module doc).
    // SAFETY: this test requires --test-threads=1, so no other thread reads KUBECONFIG
    // concurrently.  set_var is unsafe on Rust ≥ 1.81; the allow suppresses the
    // unused-unsafe lint on earlier toolchains where it is still safe.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("KUBECONFIG", &kubeconfig_path);
    }

    let ns = "default";
    let secret_name = unique_name("secretx-k8s-test");
    let multi_name = unique_name("secretx-k8s-multi");

    // ── a) round-trip without ?key= ───────────────────────────────────────

    let uri = format!("secretx:k8s:{ns}/{secret_name}");

    secretx_core::WritableSecretStore::put(
        &K8sBackend::from_uri(&uri).unwrap(),
        SecretValue::new(b"hello-world".to_vec()),
    )
    .await
    .expect("put (no key) should succeed");

    let value = secretx_core::SecretStore::get(&K8sBackend::from_uri(&uri).unwrap())
        .await
        .expect("get (no key) should succeed");
    assert_eq!(value.as_bytes(), b"hello-world");

    // ── b) round-trip with ?key=: two keys coexist ────────────────────────

    let uri_pw = format!("secretx:k8s:{ns}/{multi_name}?key=password");
    let uri_usr = format!("secretx:k8s:{ns}/{multi_name}?key=username");

    secretx_core::WritableSecretStore::put(
        &K8sBackend::from_uri(&uri_pw).unwrap(),
        SecretValue::new(b"pass123".to_vec()),
    )
    .await
    .expect("put ?key=password should succeed");

    secretx_core::WritableSecretStore::put(
        &K8sBackend::from_uri(&uri_usr).unwrap(),
        SecretValue::new(b"admin".to_vec()),
    )
    .await
    .expect("put ?key=username should succeed");

    let pw_val = secretx_core::SecretStore::get(&K8sBackend::from_uri(&uri_pw).unwrap())
        .await
        .expect("get ?key=password");
    assert_eq!(pw_val.as_bytes(), b"pass123");

    let usr_val = secretx_core::SecretStore::get(&K8sBackend::from_uri(&uri_usr).unwrap())
        .await
        .expect("get ?key=username");
    assert_eq!(usr_val.as_bytes(), b"admin");

    // ── c) update existing secret ─────────────────────────────────────────

    secretx_core::WritableSecretStore::put(
        &K8sBackend::from_uri(&uri).unwrap(),
        SecretValue::new(b"v2".to_vec()),
    )
    .await
    .expect("update should succeed");

    let v2_val = secretx_core::SecretStore::get(&K8sBackend::from_uri(&uri).unwrap())
        .await
        .expect("get after update");
    assert_eq!(v2_val.as_bytes(), b"v2");

    // ── d) key absent in secret → NotFound ───────────────────────────────

    let uri_missing_key = format!("secretx:k8s:{ns}/{secret_name}?key=nonexistent");
    let Err(err) =
        secretx_core::SecretStore::get(&K8sBackend::from_uri(&uri_missing_key).unwrap()).await
    else {
        panic!("expected Err(NotFound) for missing key");
    };
    assert!(
        matches!(err, SecretError::NotFound),
        "missing key must return NotFound, got: {err:?}"
    );

    // ── e) secret does not exist → NotFound ──────────────────────────────

    let uri_missing = format!("secretx:k8s:{ns}/does-not-exist-xyzzy-secretx");
    let Err(err2) =
        secretx_core::SecretStore::get(&K8sBackend::from_uri(&uri_missing).unwrap()).await
    else {
        panic!("expected Err(NotFound) for absent secret");
    };
    assert!(
        matches!(err2, SecretError::NotFound),
        "missing secret must return NotFound, got: {err2:?}"
    );

    // ── cleanup (best-effort) ─────────────────────────────────────────────

    let kc = Kubeconfig::read_from(&kubeconfig_path).expect("read kubeconfig for cleanup");
    let cfg = Config::from_custom_kubeconfig(kc, &KubeConfigOptions::default())
        .await
        .expect("parse kubeconfig for cleanup");
    let cleanup_client = Client::try_from(cfg).expect("build cleanup client");
    let api: Api<K8sSecret> = Api::namespaced(cleanup_client, ns);
    let _ = api.delete(&secret_name, &DeleteParams::default()).await;
    let _ = api.delete(&multi_name, &DeleteParams::default()).await;
}
