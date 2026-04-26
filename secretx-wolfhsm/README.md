# secretx-wolfhsm

wolfHSM secure element backend for [secretx](https://crates.io/crates/secretx).

Implements both `SecretStore` (NVM data objects) and `SigningBackend` (HSM-resident private keys) over the wolfHSM C library.

**Status**: stub implementation — all operations return `Unavailable` until the wolfHSM native library is linked. See requirements below.

## URI

```text
secretx:wolfhsm:<label>
```

- `label` — object label in wolfHSM NVM

## Usage

```toml
[dependencies]
secretx-wolfhsm = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_wolfhsm::WolfHsmBackend;
use secretx_core::SigningBackend;

let backend = WolfHsmBackend::from_uri("secretx:wolfhsm:my-key")?;
let sig = backend.sign(b"hello world").await?;
```

## Requirements

Link the wolfHSM native library by either:

- Setting `WOLFHSM_LIB` to the path to `libwolfhsm.a` or `libwolfhsm.so`
- Providing a `build.rs` that links the library

Until the native library is linked, all operations return `SecretError::Unavailable`. Real hardware testing requires a wolfHSM device or the wolfHSM simulator.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `wolfhsm` feature on the `secretx` umbrella crate to use it via URI dispatch.
