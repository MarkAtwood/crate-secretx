# secretx-oci-vault

Oracle Cloud Infrastructure (OCI) Vault backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:oci-vault:<compartment-id>/<secret-name>[?field=<json_field>&version=<n>]
```

- `compartment-id` — OCID of the compartment containing the secret
- `secret-name` — secret name within the vault
- `field` — optional: extract a single field from a JSON string secret
- `version` — secret version number (default: current)

`OCI_VAULT_ID` must be set to the OCID of the OCI Vault. `OCI_REGION` must be set (or the
region must be present in `~/.oci/config`). Authentication uses the OCI config file
(`~/.oci/config`) or instance principal (when running inside OCI compute).

## Signing

OCI Vault HSM-backed keys are accessible via `SigningBackend`. Use a key URI:

```text
secretx:oci-vault-key:<compartment-id>/<key-name>
```

This maps to the OCI Vault Cryptographic Operations service. The private key never leaves the HSM.

## Usage

```toml
[dependencies]
secretx-oci-vault = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_oci_vault::OciVaultBackend;
use secretx_core::SecretStore;

let store = OciVaultBackend::from_uri(
    "secretx:oci-vault:ocid1.compartment.oc1..xxxx/my-secret"
)?;
let value = store.get().await?;
```

## Auth

OCI authentication chain (same order as the OCI SDK):

1. `~/.oci/config` profile (key file or session token)
2. Instance principal (running inside OCI compute; no config file required)
3. Resource principal (running inside OCI Functions / OKE pod)

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`oci-vault` feature on the `secretx` umbrella crate to use it via URI dispatch.
