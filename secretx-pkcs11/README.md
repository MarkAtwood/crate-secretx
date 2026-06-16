# secretx-pkcs11

PKCS#11 HSM backend for [secretx](https://crates.io/crates/secretx).

Implements both `SecretStore` (for reading/writing data objects in the HSM token) and `SigningBackend` (for private keys resident in the HSM) via PKCS#11. Tested with SoftHSM2; compatible with any PKCS#11 v2.40-compliant token.

## URI

```text
secretx:pkcs11:<slot>/<label>[?lib=<path>]
```

- `slot` — PKCS#11 slot number (integer)
- `label` — object label in the token
- `lib` — path to the PKCS#11 shared library (e.g. `/usr/lib/libsofthsm2.so`); defaults to `PKCS11_LIB` env var

The token PIN is read from the `PKCS11_PIN` environment variable if set.

## Usage

```toml
[dependencies]
secretx-pkcs11 = "0.4"
secretx-core = "0.4"
```

```rust
use secretx_pkcs11::Pkcs11Backend;
use secretx_core::SigningBackend;

let backend = Pkcs11Backend::from_uri(
    "secretx:pkcs11:0/my-ec-key?lib=/usr/lib/libsofthsm2.so",
)?;
let sig = backend.sign(b"hello world").await?;
let pubkey_der = backend.public_key_der().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `pkcs11` feature on the `secretx` umbrella crate to use it via URI dispatch.
