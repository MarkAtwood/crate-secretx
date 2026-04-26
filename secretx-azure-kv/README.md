# secretx-azure-kv

Azure Key Vault backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:azure-kv:<vault-name>/<secret-name>[?field=<json_field>&credential=<mode>]
```

- `vault-name` — Key Vault name (the subdomain before `.vault.azure.net`)
- `secret-name` — secret name in Key Vault (may not contain `/`)
- `field` — optional: extract a single field from a JSON string secret
- `credential` — `managed-identity`, `developer`, or `chained` (default)

Credential modes:
- **`managed-identity`** — use only managed identity; recommended in production to prevent silent fallback on transient MI failures
- **`developer`** — use only Azure CLI / Azure Developer CLI; for local development
- **`chained`** (default) — try managed identity first, then developer tools

## Usage

```toml
[dependencies]
secretx-azure-kv = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_azure_kv::AzureKvBackend;
use secretx_core::SecretStore;

let store = AzureKvBackend::from_uri("secretx:azure-kv:my-vault/my-secret")?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `azure-kv` feature on the `secretx` umbrella crate to use it via URI dispatch.
