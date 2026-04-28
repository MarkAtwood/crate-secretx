# secretx-wolfhsm

wolfHSM secure element backend for [secretx](https://crates.io/crates/secretx).

Implements `SecretStore` and `WritableSecretStore` (NVM data objects) over the
wolfHSM C library. `SigningBackend` is declared but returns `Unavailable` until
`EccP256Key::load_from_nvm` is exposed by the `wolfhsm` crate.

## URI

```text
secretx:wolfhsm:<label>[?server=<addr>][?client_id=<n>]
```

- `label` — NVM object label (1–24 bytes, UTF-8)
- `server` — wolfHSM server address. Format: `host:port` for TCP
  (e.g. `127.0.0.1:8080`), `[ip]:port` for IPv6, or `/path` for Unix domain
  socket. TCP port must be ≤ 32767 (wolfhsm C transport uses `i16` for port).
  Falls back to `WOLFHSM_SERVER` environment variable if absent.
- `client_id` — wolfHSM client ID (0–255, default 1). Controls the NVM
  namespace on the server; two clients with the same ID share the same objects.

The `?server=` address is validated at construction time (syntax only, no
connection). `WOLFHSM_SERVER` is validated at first use.

## Usage

### Reading a secret

```toml
[dependencies]
secretx-wolfhsm = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_wolfhsm::WolfHsmBackend;
use secretx_core::SecretStore;

let store = WolfHsmBackend::from_uri("secretx:wolfhsm:my-secret?server=127.0.0.1:8080")?;
let value = store.get().await?;
```

### Writing a secret

```rust
use secretx_wolfhsm::WolfHsmBackend;
use secretx_core::{SecretValue, WritableSecretStore};

let store = WolfHsmBackend::from_uri("secretx:wolfhsm:my-secret?server=127.0.0.1:8080")?;
store.put(SecretValue::new(b"my-password".to_vec())).await?;
```

**Note**: `put()` is non-atomic. Overwriting an existing object deletes the old
object before adding the new one. If the add fails after the delete,
`SecretError::Backend` is returned and the data is lost.

### Using the umbrella crate

```toml
[dependencies]
secretx = { version = "0.3", features = ["wolfhsm"] }
```

```rust
use secretx::SecretStore;

let store = secretx::from_uri("secretx:wolfhsm:my-secret")?;
let value = store.get().await?;
```

## Environment variable

Set `WOLFHSM_SERVER` to the server address when not using the `?server=` query
parameter:

```sh
export WOLFHSM_SERVER=127.0.0.1:8080
```

## SigningBackend status

`sign()` and `public_key_der()` return `SecretError::Unavailable`. The
`wolfhsm` crate does not yet expose an API to load a committed ECC key from NVM
by label (`EccP256Key::load_from_nvm`). When that API is available, signing will
be implemented.

## Integration test status

Requires a running wolfHSM server or simulator. Set `WOLFHSM_SERVER` before
running integration tests:

```sh
WOLFHSM_SERVER=127.0.0.1:8080 cargo test -p secretx-wolfhsm
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace.
Enable the `wolfhsm` feature on the `secretx` umbrella crate to use it via URI
dispatch.
