# secretx-scaleway-sm

Scaleway Secret Manager backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:scaleway-sm:<project-id>/<secret-name>[?field=<json_field>&revision=<n>&region=<region>]
```

- `project-id` — Scaleway project ID (UUID)
- `secret-name` — human-readable secret name within the project
- `field` — optional: extract a single field from a JSON string secret
- `revision` — secret revision number (default: latest)
- `region` — Scaleway region (default: `fr-par`; also `nl-ams`, `pl-waw`)

`SCW_SECRET_KEY` must be set in the environment. `SCW_DEFAULT_PROJECT_ID` and
`SCW_DEFAULT_REGION` are used as defaults if not specified in the URI.

## Usage

```toml
[dependencies]
secretx-scaleway-sm = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_scaleway_sm::ScalewaySmBackend;
use secretx_core::SecretStore;

let store = ScalewaySmBackend::from_uri(
    "secretx:scaleway-sm:a3244b8d-1e30-4c5d-8e7a-abcdef012345/prod-api-key"
)?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`scaleway-sm` feature on the `secretx` umbrella crate to use it via URI dispatch.
