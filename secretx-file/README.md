# secretx-file

Filesystem backend for [secretx](https://crates.io/crates/secretx).

Reads a secret from a file. Absolute paths use a leading `/` in the path component; relative paths are supported as-is. Paths containing `..` are rejected at construction time.

## URI

```text
secretx:file:<path>

secretx:file:/etc/secrets/api.key   →  reads /etc/secrets/api.key
secretx:file:relative/path          →  reads relative/path
```

## Usage

```toml
[dependencies]
secretx-file = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_file::FileBackend;
use secretx_core::SecretStore;

let store = FileBackend::from_uri("secretx:file:/etc/secrets/api.key")?;
let value = store.get().await?;
```

`put` overwrites the file atomically; on Unix the file is created with mode `0600` if it does not exist.

## Security note

URIs for this backend must come from trusted sources (compiled-in configuration or administrator-controlled environment variables). Do not construct URIs from end-user input — an attacker who controls the URI could read any file the process can access.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enabled by the `file` feature flag on the `secretx` umbrella crate (included in the default feature set).
