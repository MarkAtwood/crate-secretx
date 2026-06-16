# secretx-bitwarden

Bitwarden Secrets Manager backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:bitwarden:<project-name>/<secret-name>
```

- `project-name` — Bitwarden project name (looked up by name, not UUID)
- `secret-name` — secret name within the project

Requires `BWS_ACCESS_TOKEN` to be set in the environment at construction time. Obtain a machine account access token from the Bitwarden Secrets Manager console.

## Usage

```toml
[dependencies]
secretx-bitwarden = "0.4"
secretx-core = "0.4"
```

```rust
use secretx_bitwarden::BitwardenBackend;
use secretx_core::SecretStore;

let store = BitwardenBackend::from_uri(
    "secretx:bitwarden:my-project/DB_PASSWORD",
)?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `bitwarden` feature on the `secretx` umbrella crate to use it via URI dispatch.
