# secretx-env

Environment variable backend for [secretx](https://crates.io/crates/secretx).

Reads a secret from a single environment variable. Useful for local development and CI environments where secrets are injected into the process environment.

## URI

```text
secretx:env:<VAR_NAME>
```

## Usage

```toml
[dependencies]
secretx-env = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_env::EnvBackend;
use secretx_core::SecretStore;

let store = EnvBackend::from_uri("secretx:env:API_KEY")?;
let value = store.get().await?;
```

`put` is not supported — environment variables cannot be written at runtime. `refresh` re-reads the variable, useful when a process manager rotates it in place.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enabled by the `env` feature flag on the `secretx` umbrella crate (included in the default feature set).
