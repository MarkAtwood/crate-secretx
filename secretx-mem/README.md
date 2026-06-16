# secretx-mem

In-process memory backend for [secretx](https://crates.io/crates/secretx).

Provides a process-local key–value store backed by a `HashMap` in memory. Useful for testing, ephemeral runtime secrets, and bootstrap/seed scenarios where secrets are injected programmatically.

## URI

```text
secretx:mem:<KEY>
```

## Usage

### Standalone (testing)

```rust
use secretx_mem::MemStore;
use secretx_core::{SecretStore, WritableSecretStore, SecretValue};

let store = MemStore::new();
store.insert("api-key", b"hunter2");

let backend = store.backend("api-key");
let value = backend.get().await?;

backend.put(SecretValue::new(b"rotated".to_vec())).await?;
```

### Global store (URI dispatch)

```rust
use secretx_mem::MemStore;

// Pre-populate at startup
MemStore::global().insert("db-password", b"s3cret");

// Later, via URI dispatch
let store = secretx::from_uri("secretx:mem:db-password")?;
let value = store.get().await?;
```

## Security note

Secrets are held in process memory and zeroed on removal or drop. They are not persisted, encrypted, or protected against memory dumps. For production secrets, prefer backends with at-rest encryption and access control.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enabled by the `mem` feature flag on the `secretx` umbrella crate (included in the default feature set).
