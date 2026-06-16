# secretx-signature

Adapter bridging [`secretx_core::SigningBackend`](https://crates.io/crates/secretx-core) to RustCrypto's [`signature::Signer`](https://crates.io/crates/signature).

`SigningBackend` is async and returns raw bytes. `Signer<S>` is sync and returns typed signatures. This crate bridges the gap with per-algorithm adapter types that validate the algorithm at construction and run the async signing operation synchronously.

## Features

| Feature | Adapter type | Signature type |
|---------|-------------|----------------|
| `ed25519` | `Ed25519Signer` | `ed25519::Signature` |
| `ecdsa-p256` | `EcdsaP256Signer` | `p256::ecdsa::Signature` |
| `rsa-pss` | `RsaPss2048Signer` | `rsa::pss::Signature` (2048-bit only) |

## Usage

```toml
[dependencies]
secretx-signature = { version = "0.5", features = ["ed25519"] }
secretx-core = "0.5"
```

```rust
use secretx_signature::Ed25519Signer;
use signature::Signer;

// backend: Arc<dyn SigningBackend> from secretx::from_signing_uri
let signer = Ed25519Signer::new(backend)?;
let sig: ed25519::Signature = signer.try_sign(b"hello")?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Unlike backend crates (`secretx-aws-kms`, `secretx-file`, etc.), it is not included in the `secretx` umbrella crate — add it as a direct dependency. The umbrella handles backend dispatch via `from_signing_uri()`; this crate is a downstream consumer that wraps the resulting backend for use with the RustCrypto `signature` ecosystem.
