# secretx-barbican

OpenStack Barbican (Key Manager Service) backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:barbican:<secret-uuid>[?field=<json_field>]
```

- `secret-uuid` — Barbican secret UUID (the final path component of the secret `href`,
  e.g. `b4a14b62-e3fe-4e28-a47b-12345678abcd`)
- `field` — optional: extract a single field from a JSON string secret

The Barbican endpoint and OpenStack credentials are read from standard OpenStack environment
variables at construction time.

## OpenStack auth

Set the standard OpenStack cloud environment variables:

```sh
export OS_AUTH_URL=https://identity.example.com/v3
export OS_PROJECT_NAME=my-project
export OS_USER_DOMAIN_NAME=Default
export OS_USERNAME=myuser
export OS_PASSWORD=mypassword
```

Or use a pre-obtained token:

```sh
export OS_AUTH_URL=https://identity.example.com/v3
export OS_TOKEN=gAAAAABhxx...
export OS_BARBICAN_ENDPOINT=https://key-manager.example.com
```

`OS_BARBICAN_ENDPOINT` overrides the endpoint discovered from the Keystone service catalog.
This is useful for clouds that do not advertise Barbican in their catalog.

## Covered providers

A single `secretx-barbican` crate works with any provider that runs an unmodified Barbican
installation:

| Provider | Notes |
|----------|-------|
| OVHcloud (FR) | OpenStack KMS exposes Barbican API |
| Open Telekom Cloud / T-Systems (DE) | DEW service |
| Cleura / City Network (SE) | standard OpenStack |
| STACKIT (DE) | standard OpenStack base |
| VK Cloud / Cloud.ru (RU) | standard OpenStack |
| Any private OpenStack deployment | same API |

## Usage

```toml
[dependencies]
secretx-barbican = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_barbican::BarbicanBackend;
use secretx_core::SecretStore;

let store = BarbicanBackend::from_uri(
    "secretx:barbican:b4a14b62-e3fe-4e28-a47b-12345678abcd"
)?;
let value = store.get().await?;
```

## PKCS#11 plugin note

Some OpenStack operators wire Barbican to a hardware HSM via its PKCS#11 plugin (Thales or
Utimaco). This backend does not expose that HSM for signing — it retrieves secret payloads
only. For direct PKCS#11 HSM access on the same hardware, use `secretx-pkcs11`.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`barbican` feature on the `secretx` umbrella crate to use it via URI dispatch.
