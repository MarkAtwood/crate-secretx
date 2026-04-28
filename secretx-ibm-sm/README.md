# secretx-ibm-sm

IBM Cloud Secrets Manager backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:ibm-sm:<region>/<instance-id>/<secret-id>[?field=<json_field>]
```

- `region` — IBM Cloud region (e.g. `us-south`, `eu-de`)
- `instance-id` — Secrets Manager service instance GUID
- `secret-id` — UUID of the secret within the instance
- `field` — optional: extract a single field from a JSON string secret

`IBMCLOUD_API_KEY` must be set in the environment. The backend exchanges it for an IAM access
token at construction time.

## Background

IBM Cloud Secrets Manager is HashiCorp Vault Enterprise, operated and hosted by IBM. It exposes
the IBM Secrets Manager v2 REST API (not the Vault API directly). For the underlying Vault
API — when running your own Vault — use `secretx-hashicorp-vault` instead.

IBM also offers **Hyper Protect Crypto Services** (HPCS), an HSM service rooted in IBM Z
mainframe silicon at FIPS 140-2 Level 4. HPCS is a separate product and a separate backend
(not this one). HPCS implements the PKCS#11 interface; use `secretx-pkcs11` against an HPCS
endpoint today.

## Usage

```toml
[dependencies]
secretx-ibm-sm = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_ibm_sm::IbmSmBackend;
use secretx_core::SecretStore;

let store = IbmSmBackend::from_uri(
    "secretx:ibm-sm:us-south/a1b2c3d4-e5f6-7890-abcd-ef1234567890/a1b2c3d4-5678-90ab-cdef-1234567890ab"
)?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`ibm-sm` feature on the `secretx` umbrella crate to use it via URI dispatch.
