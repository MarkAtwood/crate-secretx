# secretx-tpm2

TPM 2.0 backend for [secretx](https://crates.io/crates/secretx).

Read and write secrets in TPM non-volatile storage, or sign with persistent TPM-resident keys. The private key never leaves the TPM chip.

## URIs

```text
secretx:tpm2:nv/<index>                              # NV index (read/write)
secretx:tpm2:key/<handle>[?algorithm=ecdsa-p256]      # signing key
```

## Usage

```rust
use secretx_tpm2::Tpm2Backend;
use secretx_core::SecretStore;

// Read a secret from NV index
let store = Tpm2Backend::from_uri("secretx:tpm2:nv/0x01000001")?;
let value = store.get().await?;
```

```rust
use secretx_tpm2::Tpm2Backend;
use secretx_core::SigningBackend;

// Sign with a persistent ECC key
let signer = Tpm2Backend::from_uri("secretx:tpm2:key/0x81000001")?;
let sig = signer.sign(b"message").await?;
```

## TCTI configuration

The TPM transport is configured via `?tcti=` or the `TPM2TOOLS_TCTI` environment variable:

- `device:/dev/tpmrm0` — kernel resource manager (default)
- `swtpm:host=127.0.0.1,port=2321` — software TPM simulator
- `tabrmd` — TPM2 access broker daemon

## System requirements

Requires `libtss2-esys` installed on the system.

- Debian/Ubuntu: `apt install libtss2-dev`
- Fedora: `dnf install tpm2-tss-devel`

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enabled by the `tpm2` feature flag on the `secretx` umbrella crate.
