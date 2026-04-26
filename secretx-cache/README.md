# secretx-cache

TTL-based in-memory cache wrapping any `SecretStore` — part of the [secretx](https://crates.io/crates/secretx) workspace.

`CachingStore<S>` caches the value returned by any `SecretStore` backend in memory for a configurable TTL. Cache entries are stored in `Zeroizing` buffers so secret bytes are zeroed on eviction or drop.

## Usage

```toml
[dependencies]
secretx-cache = "0.2"
secretx-aws-sm = "0.2"  # or any other backend
secretx-core = "0.2"
```

```rust
use secretx_cache::CachingStore;
use secretx_aws_sm::AwsSmBackend;
use secretx_core::SecretStore;
use std::sync::Arc;
use std::time::Duration;

let backend = AwsSmBackend::from_uri("secretx:aws-sm:prod/my-secret")?;
let store = CachingStore::new(Arc::new(backend), Duration::from_secs(300));

let value = store.get().await?;  // fetches from AWS on first call
let value = store.get().await?;  // returns cached value for up to 5 minutes
```

Use `Duration::ZERO` to disable caching entirely, which is appropriate for `env` and `file` backends where reads are cheap.

## Thundering herd note

When multiple async tasks share a `CachingStore` and a cached entry expires simultaneously, each task independently fetches from the backend. For rate-limited backends (AWS SM, SSM) choose a TTL long enough to make simultaneous expiry unlikely in your workload.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `cache` feature on the `secretx` umbrella crate to use `CachingStore` there.
