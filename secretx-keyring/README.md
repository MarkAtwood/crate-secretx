# secretx-keyring

OS keychain backend for [secretx](https://crates.io/crates/secretx).

Reads and writes secrets via the platform keychain: macOS Keychain Services, Windows Credential Manager, or `libsecret` / KWallet on Linux.

## URI

```text
secretx:keyring:<service>/<account>
```

- `service` — keychain service name (groups credentials by application)
- `account` — account name within the service

## Usage

```toml
[dependencies]
secretx-keyring = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_keyring::KeyringBackend;
use secretx_core::SecretStore;

let store = KeyringBackend::from_uri("secretx:keyring:my-app/api-key")?;
let value = store.get().await?;
```

## Platform notes

- **macOS** — uses Keychain Services; works in both GUI and server contexts.
- **Windows** — uses Windows Credential Manager.
- **Linux** — requires a running keyring daemon (`gnome-keyring-daemon`, KWallet). On headless servers `put` may succeed but `get` returns `NotFound` without a daemon. Do not use in headless CI without a keyring daemon.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `keyring` feature on the `secretx` umbrella crate to use it via URI dispatch.
