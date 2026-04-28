# secretx-alibaba-sm

Alibaba Cloud KMS Secrets Manager backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:alibaba-sm:<region>/<secret-name>[?field=<json_field>&version=<version-id>]
```

- `region` — Alibaba Cloud region ID (e.g. `cn-hangzhou`, `ap-southeast-1`)
- `secret-name` — secret name in KMS Secrets Manager
- `field` — optional: extract a single field from a JSON string secret
- `version` — secret version ID (default: `ACSCurrent`)

`ALIBABA_CLOUD_ACCESS_KEY_ID` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET` must be set in the
environment. RAM role credentials (ECS metadata service) are supported as a fallback.

## Crypto note

Alibaba Cloud KMS Secrets Manager wraps secrets using AES-256 by default. For deployments
subject to China data-residency regulations, the `kms-instance` parameter selects a dedicated
KMS instance that can be backed by GM/T (Guomi) SM4 encryption. The underlying SM2/SM4 crypto
is an OSCCA standard, not FIPS. FIPS 140 certification is not available on this backend.

## Usage

```toml
[dependencies]
secretx-alibaba-sm = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_alibaba_sm::AlibabaSmBackend;
use secretx_core::SecretStore;

let store = AlibabaSmBackend::from_uri("secretx:alibaba-sm:ap-southeast-1/prod-db-password")?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`alibaba-sm` feature on the `secretx` umbrella crate to use it via URI dispatch.
