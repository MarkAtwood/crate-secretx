# secretx-hashicorp-vault

HashiCorp Vault KV v2 backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:vault:<mount>/<secret-path>[?field=<json_field>&addr=<vault_addr>]
```

- `mount` — KV v2 mount point (e.g. `secret`)
- `secret-path` — path within the mount (e.g. `prod/api-key`)
- `field` — optional: extract a single field from the KV data map on `get`; write `{field: value}` on `put`
- `addr` — Vault server address; defaults to `VAULT_ADDR` env var, then `http://127.0.0.1:8200`

`VAULT_TOKEN` must be set in the environment.

## Usage

```toml
[dependencies]
secretx-hashicorp-vault = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_hashicorp_vault::VaultBackend;
use secretx_core::SecretStore;

let store = VaultBackend::from_uri("secretx:vault:secret/prod/api-key?field=value")?;
let value = store.get().await?;
```

## Partial-update note

`put` with `?field=` writes a **new KV v2 version** containing only the named field. Other fields from the previous version are not preserved. To update a multi-field secret atomically, omit `?field=` and pass the complete JSON object to `put`.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `hashicorp-vault` feature on the `secretx` umbrella crate to use it via URI dispatch.
