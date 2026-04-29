# secretx-k8s

Kubernetes Secret backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:k8s:<namespace>/<secret-name>[?key=<data-key>]
```

- `namespace` — Kubernetes namespace containing the Secret
- `secret-name` — name of the `Secret` object
- `key` — optional: the key within `.data` to return; required if the Secret contains more
  than one key

Without `?key=`, `get` succeeds only if the Secret contains exactly one key and returns that
key's value. For Secrets with more than one key, `?key=<name>` is required; `get` returns
`SecretError::InvalidUri` at read time if it is absent.

## Write behaviour (`put`)

`put` uses two strategies depending on whether `?key=` is present:

- **With `?key=`** (e.g. `secretx:k8s:prod/db?key=password`): JSON merge-patch.
  Adds or updates the named key; all other keys in the Secret are preserved.
  If the Secret does not exist it is created.

- **Without `?key=`**: Server-side apply (SSA) with field manager `secretx-k8s`.
  The value is stored under the literal key name `"value"` (i.e. `.data.value`).
  SSA is an atomic create-or-update: you do not need a pre-existing Secret, and
  no `resourceVersion` is required.  Keys owned by other field managers are left
  untouched.

## Auth

Auth is resolved in order:

1. **In-cluster** — ServiceAccount token mounted at
   `/var/run/secrets/kubernetes.io/serviceaccount/token`, with the API server address read from
   `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT`. This is the default inside a pod.
2. **Kubeconfig** — `KUBECONFIG` env var, then `~/.kube/config`. Used for out-of-cluster
   processes (local dev, batch jobs).

## Relationship to ESO and Secrets Store CSI Driver

This backend reads native Kubernetes `Secret` objects. It does not bypass your existing secrets
management tooling — it consumes what that tooling already produced:

- **External Secrets Operator (ESO)** materializes secrets from a real secrets manager (AWS SM,
  Vault, etc.) into `Secret` objects. `secretx-k8s` reads those objects.
- **Secrets Store CSI Driver** can also sync its payload into `Secret` objects via
  `secretObjects:` config. `secretx-k8s` reads those too.
- If CSI mounts the secret as a **file** instead, use `secretx-file:` directly.
- If the orchestrator injects it as an **env var**, use `secretx-env:` directly.

The value of this backend is dynamic lookup at runtime without pre-declaring every secret as a
pod volume mount or env var entry.

## Usage

```toml
[dependencies]
secretx-k8s = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_k8s::K8sBackend;
use secretx_core::SecretStore;

let store = K8sBackend::from_uri("secretx:k8s:prod/db-credentials?key=password")?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`k8s` feature on the `secretx` umbrella crate to use it via URI dispatch.
