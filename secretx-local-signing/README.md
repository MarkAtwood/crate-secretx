# secretx-local-signing

Local file-based signing backend for [secretx](https://crates.io/crates/secretx).

Loads a PKCS#8 DER-encoded private key from a file and implements `SigningBackend` for Ed25519, ECDSA P-256/SHA-256, and RSA-PSS-2048/SHA-256. The key is loaded into memory at construction time and zeroed on drop.

## URI

```text
secretx:local-signing:<key_path>?algorithm=<algo>

secretx:local-signing:/etc/secrets/ed25519.der?algorithm=ed25519
secretx:local-signing:relative/key.der?algorithm=p256
secretx:local-signing:/etc/secrets/rsa.der?algorithm=rsa-pss-2048
```

- `key_path` — path to a PKCS#8 DER-encoded private key file (use a leading `/` for absolute paths)
- `algorithm` — `ed25519`, `p256`, or `rsa-pss-2048`

## Usage

```toml
[dependencies]
secretx-local-signing = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_local_signing::LocalSigningBackend;
use secretx_core::SigningBackend;

let backend = LocalSigningBackend::from_uri(
    "secretx:local-signing:/etc/secrets/ed25519.der?algorithm=ed25519",
)?;
let sig = backend.sign(b"hello world").await?;
let pubkey_der = backend.public_key_der().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `local-signing` feature on the `secretx` umbrella crate to use it via URI dispatch.
