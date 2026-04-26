# secretx-doppler

Doppler backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:doppler:<project>/<config>/<secret-name>
```

- `project` — Doppler project name
- `config` — Doppler config name (e.g. `prd`, `dev`)
- `secret-name` — the secret key name

Requires `DOPPLER_TOKEN` to be set in the environment at construction time.

## Usage

```toml
[dependencies]
secretx-doppler = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_doppler::DopplerBackend;
use secretx_core::SecretStore;

let store = DopplerBackend::from_uri("secretx:doppler:myproject/prd/DB_PASSWORD")?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `doppler` feature on the `secretx` umbrella crate to use it via URI dispatch.
