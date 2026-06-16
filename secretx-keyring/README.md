# secretx-keyring

Linux kernel keyring backend for [secretx](https://crates.io/crates/secretx).

Reads and writes secrets via the Linux kernel [persistent keyring](https://www.man7.org/linux/man-pages/man7/persistent-keyring.7.html). No daemon required — secrets are stored in kernel memory, survive across logout/login sessions for a configurable window (default: a few days), and are access-controlled by the kernel. Secrets do **not** survive reboots.

## URI

```text
secretx:keyring:<service>/<account>
```

- `service` — keyring description prefix (groups credentials by application)
- `account` — credential identifier within the service

## Requirements

Linux only. Requires kernel keyutils support (standard on all modern Linux distributions).

## Usage

```toml
[dependencies]
secretx-keyring = "0.4"
secretx-core = "0.4"
```

```rust
use secretx_keyring::KeyringBackend;
use secretx_core::SecretStore;

let store = KeyringBackend::from_uri("secretx:keyring:my-app/api-key")?;
let value = store.get().await?;
```

## Security notes

- Secrets are stored in kernel memory — never written to disk as plaintext.
- Access is controlled by the kernel's UID-based keyring permissions.
- The persistent keyring survives across logouts but expires after a configurable window (default: a few days). It does **not** survive reboots.
- For encrypted-at-rest storage, consider `secretx-systemd` (TPM2-encrypted, tmpfs-backed) or a cloud backend.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `keyring` feature on the `secretx` umbrella crate to use it via URI dispatch.
