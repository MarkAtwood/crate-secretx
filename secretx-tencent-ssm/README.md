# secretx-tencent-ssm

Tencent Cloud Secrets Manager (SSM) backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:tencent-ssm:<region>/<secret-name>[?field=<json_field>&version=<version-id>]
```

- `region` — Tencent Cloud region (e.g. `ap-guangzhou`, `eu-frankfurt`)
- `secret-name` — secret name in SSM
- `field` — optional: extract a single field from a JSON string secret
- `version` — secret version (default: `$LATEST`)

`TENCENTCLOUD_SECRET_ID` and `TENCENTCLOUD_SECRET_KEY` must be set in the environment. CAM
role credentials (CVM metadata service) are supported as a fallback.

## Crypto note

Tencent SSM encrypts secrets using their KMS service. For deployments in China regions subject
to data-residency requirements, HSM-backed instances using SM4 (OSCCA standard) are available.
FIPS 140 certification is not available on this backend.

## Usage

```toml
[dependencies]
secretx-tencent-ssm = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_tencent_ssm::TencentSsmBackend;
use secretx_core::SecretStore;

let store = TencentSsmBackend::from_uri("secretx:tencent-ssm:ap-guangzhou/prod-db-password")?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`tencent-ssm` feature on the `secretx` umbrella crate to use it via URI dispatch.
