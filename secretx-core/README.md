# secretx-core

Core traits and types for the [secretx](https://crates.io/crates/secretx) secrets library.

`secretx-core` defines the shared interfaces that all secretx backends implement.

## Key types

**`SecretStore`** — the main async trait: `get`, `put`, `refresh`. All backends implement this.

**`SigningBackend`** — for HSM-resident keys that must never leave hardware: `sign`, `public_key_der`, `algorithm`.

**`SecretValue`** — wraps `Zeroizing<Vec<u8>>`. Memory is zeroed on drop. Does not implement `Debug`, `Display`, or `Clone` — cannot appear in log output by accident.

**`SecretError`** — `#[non_exhaustive]` enum: `NotFound`, `Backend`, `InvalidUri`, `DecodeFailed`, `Unavailable`.

**`SecretUri`** — parser for `secretx:` URIs used by backend constructors.

## Usage

Application code depends on `secretx-core` for trait methods and error handling. Backend crate authors implement `SecretStore` or `SigningBackend` against it.

```toml
[dependencies]
secretx-core = "0.2"
```

```rust
use secretx_core::{SecretStore, SecretError, SecretValue};

async fn load(store: &dyn SecretStore) -> Result<SecretValue, SecretError> {
    store.get().await
}
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace — a
backend-agnostic secrets retrieval library for Rust. Use the `secretx` umbrella crate
to select a backend at runtime from a URI, or depend on a backend crate directly if
you only need one backend.
