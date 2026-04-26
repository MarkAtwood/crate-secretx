# Changelog

## [0.3.0] - 2026-04-24

### Breaking changes

- **`put()` removed from `SecretStore`** — callers using `store.put(value).await` must now depend on
  `WritableSecretStore` and call `from_uri_writable` to obtain a writable handle. `from_uri` still
  works for read-only access; the call site is unchanged.

### New

- **`WritableSecretStore` subtrait** — `pub trait WritableSecretStore: SecretStore`. Adds `put()`.
  Implemented by all backends that support writes: `file`, `keyring`, `aws-sm`, `aws-ssm`,
  `azure-kv`, `doppler`, `gcp-sm`, `hashicorp-vault`, `pkcs11`. Read-only backends (`env`,
  `bitwarden`) implement only `SecretStore`.

- **`from_uri_writable(uri)`** in the `secretx` umbrella crate — returns
  `Arc<dyn WritableSecretStore>`. Rejects read-only backends (`env`, `bitwarden`) and signing-only
  backends (`aws-kms`, `local-signing`, `wolfhsm`) with `SecretError::InvalidUri` at construction
  time.

- **`WritableSecretStore` re-exported** from the `secretx` umbrella crate.

### Migration guide

**Before (0.2):**

```rust
use secretx::{SecretStore, SecretValue};

let store = secretx::from_uri(&uri)?;
store.put(SecretValue::new(b"value".to_vec())).await?;  // put was on SecretStore
```

**After (0.3):**

```rust
use secretx::{WritableSecretStore, SecretValue};

let store = secretx::from_uri_writable(&uri)?;
store.put(SecretValue::new(b"value".to_vec())).await?;  // put is on WritableSecretStore
```

Read-only usage is unchanged:

```rust
use secretx::SecretStore;

let store = secretx::from_uri(&uri)?;       // unchanged
let value = store.get().await?;             // unchanged
```

### Note on trait upcasting (MSRV 1.75)

`Arc<dyn WritableSecretStore>` does not automatically coerce to `Arc<dyn SecretStore>` on Rust
1.75–1.85 (current MSRV). If you need both handles for the same backend, call `from_uri` and
`from_uri_writable` separately with the same URI string. Calling `.get()` and `.refresh()` directly
on an `Arc<dyn WritableSecretStore>` works on all supported toolchains via supertrait method
dispatch.

## [0.2.0] - 2026-04-23

Initial public release.
