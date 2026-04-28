# secretx-gcp-sm

GCP Secret Manager backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:gcp-sm:<project>/<secret>[?version=<version>]
```

- `project` — GCP project ID
- `secret` — secret name in Secret Manager
- `version` — secret version (default: `latest`)

Requires `GCP_ACCESS_TOKEN` to be set in the environment at construction time. Obtain a token with `gcloud auth print-access-token`.

**Token lifetime**: access tokens expire after one hour. The backend reads the token once at construction and reuses it. For long-running processes, reconstruct the backend before each use, or use a service account with automatic token refresh via the [Google Cloud Rust client library](https://github.com/googleapis/google-cloud-rust).

## Usage

```toml
[dependencies]
secretx-gcp-sm = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_gcp_sm::GcpSmBackend;
use secretx_core::SecretStore;

let store = GcpSmBackend::from_uri("secretx:gcp-sm:my-project/my-secret")?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `gcp-sm` feature on the `secretx` umbrella crate to use it via URI dispatch.
