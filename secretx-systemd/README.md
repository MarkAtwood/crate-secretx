# secretx-systemd

systemd credentials backend for [secretx](https://crates.io/crates/secretx).

Reads secrets injected by systemd via `LoadCredential=` or `LoadCredentialEncrypted=` unit-file directives. At service start, systemd decrypts the credential (using TPM2 or a host key) and exposes the plaintext in a per-service tmpfs at `$CREDENTIALS_DIRECTORY`. No daemon is required at runtime.

Requires systemd v250+ (released January 2022).

## URI

```text
secretx:systemd:<credential-name>
```

## Unit file configuration

```ini
[Service]
LoadCredentialEncrypted=db-password:/etc/credentials/db-password.cred
```

Encrypt a credential:

```sh
systemd-creds encrypt --with-key=tpm2 secret.txt /etc/credentials/db-password.cred
```

## Usage

```toml
[dependencies]
secretx-systemd = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_systemd::SystemdCredsBackend;
use secretx_core::SecretStore;

let store = SystemdCredsBackend::from_uri("secretx:systemd:db-password")?;
let value = store.get().await?;
```

## Security notes

- Credentials are decrypted by systemd before exec — the service sees only plaintext.
- The `$CREDENTIALS_DIRECTORY` tmpfs is only visible to that specific service unit.
- Encrypted at rest on disk (TPM2-bound or host-key-bound via `systemd-creds encrypt`).
- Read-only — credentials are injected by the service manager, not written by the service.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `systemd` feature on the `secretx` umbrella crate to use it via URI dispatch.
