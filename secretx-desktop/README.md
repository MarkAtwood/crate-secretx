# secretx-desktop

Desktop keychain backend for [secretx](https://crates.io/crates/secretx).

Reads and writes secrets via the platform desktop keychain:

- **macOS** — Keychain Services
- **Windows** — Windows Credential Manager
- **Linux** — Secret Service protocol (GNOME Keyring, KWallet); requires a running daemon

For Linux headless services, use `secretx-keyring` (kernel persistent keyring, no daemon) or `secretx-systemd` (TPM2-encrypted tmpfs, no daemon) instead.

## URI

```text
secretx:desktop:<service>/<account>
```

- `service` — keychain service name (groups credentials by application)
- `account` — account name within the service

## Usage

```toml
[dependencies]
secretx-desktop = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_desktop::DesktopKeyringBackend;
use secretx_core::SecretStore;

let store = DesktopKeyringBackend::from_uri("secretx:desktop:my-app/api-key")?;
let value = store.get().await?;
```

## Platform notes

- **macOS** — uses Keychain Services; requires user session.
- **Windows** — uses Windows Credential Manager; requires user session.
- **Linux** — requires a running Secret Service daemon (`gnome-keyring-daemon`, KWallet). Returns `SecretError::Unavailable` if no daemon is accessible.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `desktop` feature on the `secretx` umbrella crate to use it via URI dispatch.
