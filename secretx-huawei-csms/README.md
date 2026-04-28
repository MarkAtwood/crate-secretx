# secretx-huawei-csms

Huawei Cloud CSMS (Cloud Secret Management Service) backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:huawei-csms:<region>/<secret-name>[?field=<json_field>&version=<version-id>]
```

- `region` — Huawei Cloud region ID (e.g. `cn-north-4`, `eu-west-101`)
- `secret-name` — secret name in CSMS
- `field` — optional: extract a single field from a JSON string secret
- `version` — secret version (default: latest)

`HUAWEI_CLOUD_ACCESS_KEY` and `HUAWEI_CLOUD_SECRET_KEY` must be set in the environment.
ECS agency credentials (metadata service) are supported as a fallback.

CSMS is part of the **DEW** (Data Encryption Workshop) umbrella service. The API endpoint is
`csms.<region>.myhuaweicloud.com`.

## Dedicated HSM

Huawei Cloud also offers **Dedicated HSM** (separate product) for keys that must never leave
hardware. CSMS itself encrypts secrets using the shared KMS service. For HSM-backed key
operations, the Dedicated HSM exposes a PKCS#11 interface — use `secretx-pkcs11` for those.

## Crypto note

Huawei Cloud KMS supports both AES-256 and SM4 (OSCCA). For China-region deployments with
GM/T compliance requirements, SM4-encrypted secrets are available. FIPS 140 certification is
not available on this backend.

## Usage

```toml
[dependencies]
secretx-huawei-csms = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_huawei_csms::HuaweiCsmsBackend;
use secretx_core::SecretStore;

let store = HuaweiCsmsBackend::from_uri("secretx:huawei-csms:eu-west-101/prod-api-key")?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`huawei-csms` feature on the `secretx` umbrella crate to use it via URI dispatch.
