# secretx-yandex-lockbox

Yandex Cloud Lockbox backend for [secretx](https://crates.io/crates/secretx).

> **Status: Planned.** This crate does not exist yet. See the roadmap issue for implementation status.

## URI

```text
secretx:yandex-lockbox:<secret-id>[?field=<json_field>&version=<version-id>]
```

- `secret-id` — Yandex Cloud Lockbox secret identifier (e.g. `e6q942tvc1gm469xtgmn`)
- `field` — optional: extract a single entry key from the secret's key-value payload
- `version` — secret version ID (default: current)

Auth uses a Yandex Cloud IAM token. Set one of:
- `YANDEX_CLOUD_IAM_TOKEN` — short-lived token (expires in ~12h); obtain with `yc iam create-token`
- `YANDEX_CLOUD_SA_KEY_FILE` — path to a service account key JSON file; the backend exchanges
  it for an IAM token automatically

## Lockbox data model

Lockbox secrets have a key-value payload (multiple entries per version). The `?field=` query
parameter selects a single entry. Without `?field=`, `get` returns the first entry value; for
multi-entry secrets, use `?field=` to be explicit.

## Usage

```toml
[dependencies]
secretx-yandex-lockbox = "0.3"
secretx-core = "0.3"
```

```rust
use secretx_yandex_lockbox::YandexLockboxBackend;
use secretx_core::SecretStore;

let store = YandexLockboxBackend::from_uri(
    "secretx:yandex-lockbox:e6q942tvc1gm469xtgmn?field=password"
)?;
let value = store.get().await?;
```

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the
`yandex-lockbox` feature on the `secretx` umbrella crate to use it via URI dispatch.
