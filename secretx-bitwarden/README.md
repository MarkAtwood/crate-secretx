# secretx-bitwarden

Bitwarden Secrets Manager backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:bitwarden:<project-id>/<secret-name>
```

- `project-id` — Bitwarden project UUID
- `secret-name` — secret name within the project

Requires `BWS_ACCESS_TOKEN` to be set in the environment at construction time. Obtain a machine account access token from the Bitwarden Secrets Manager console.

## Usage

```toml
[dependencies]
secretx-bitwarden = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_bitwarden::BitwardenBackend;
use secretx_core::SecretStore;

let store = BitwardenBackend::from_uri(
    "secretx:bitwarden:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/DB_PASSWORD",
)?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `bitwarden` feature on the `secretx` umbrella crate to use it via URI dispatch.
