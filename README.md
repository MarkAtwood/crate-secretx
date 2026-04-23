# secretx

Backend-agnostic secrets retrieval for Rust. One trait, many stores.

```toml
[dependencies]
secretx = { version = "0.1", features = ["aws-sm", "file"] }
```

---

## The problem

Every Rust service that needs secrets from a managed store writes the same boilerplate: pick a
cloud SDK, call the API, handle errors, inject the value. Do it again for the next environment,
the next vendor, the next project.

There is no standard abstraction. Code is coupled to a specific SDK at the call site. Switching
from HashiCorp Vault to AWS Secrets Manager — or from real credentials to a local file in dev —
requires changes throughout the codebase.

`secretx` is the `sqlx` of secrets retrieval. Write your code against one trait. Switch backends
by changing a URI in config.

---

## How it works

Backends are selected by URI at runtime. The call site never names a backend.

```
secretx://<backend>/<path>[?options]
```

| URI | Backend |
|-----|---------|
| `secretx://env/MY_SECRET` | Environment variable |
| `secretx://file//etc/secrets/key` | File (absolute path) |
| `secretx://aws-kms/alias/my-key` | AWS KMS (signing only) |
| `secretx://aws-sm/prod/my-secret` | AWS Secrets Manager |
| `secretx://aws-ssm/prod/my-param` | AWS SSM Parameter Store |
| `secretx://azure-kv/myvault/mysecret` | Azure Key Vault |
| `secretx://bitwarden/myproject/MY_SECRET` | Bitwarden Secrets Manager |
| `secretx://doppler/myproject/prd/MY_SECRET` | Doppler |
| `secretx://gcp-sm/my-project/my-secret` | GCP Secret Manager |
| `secretx://keyring/myapp/my-key` | OS keychain |
| `secretx://pkcs11/0/my-key?lib=/usr/lib/libsofthsm2.so` | PKCS#11 HSM |
| `secretx://vault/secret/data/myapp/key` | HashiCorp Vault |
| `secretx://wolfhsm/my-key` | wolfHSM secure element |

The `from_uri` call constructs the backend and validates the URI syntax. It does not make any
network call or file read. Fetch happens on first `get`.

---

## Usage

### URI-driven (umbrella crate)

The `secretx` umbrella crate provides `from_uri` dispatch. Enable the backends you need as
features.

```toml
[dependencies]
secretx = { version = "0.1", features = ["aws-sm", "file"] }
```

```rust
use secretx::{SecretStore, SecretValue};

// Configured per-environment. No code change to switch backends.
let uri = std::env::var("SIGNING_KEY_URI")
    .unwrap_or_else(|_| "secretx://file//etc/dev-secrets/signing.key".into());

let store = secretx::from_uri(&uri)?;
let key: SecretValue = store.get("signing-key").await?;

// key is zeroed from memory when it drops.
```

### Direct (single backend crate)

If you only ever use one backend and don't need URI dispatch, depend on the backend crate
directly. No umbrella, no feature flags, no compile guards in your dependency tree.

```toml
[dependencies]
secretx-aws-sm = "0.1"
```

```rust
use secretx_aws_sm::AwsSmBackend;
use secretx_core::SecretStore;

let store = AwsSmBackend::from_uri("secretx://aws-sm/prod/signing-key")?;
let key = store.get("prod/signing-key").await?;
```

### Signing with an HSM-resident key

For keys that must never leave the hardware (AWS KMS, Azure Key Vault HSM, PKCS#11, wolfHSM),
use `SigningBackend`. Call sites are identical regardless of which HSM is underneath.

```rust
use secretx_aws_kms::AwsKmsBackend;
use secretx_core::SigningBackend;

let backend = AwsKmsBackend::from_uri("secretx://aws-kms/alias/my-signing-key")?;
let signature = backend.sign(&message).await?;
let pubkey_der = backend.public_key_der().await?;
```

---

## Core types

**`SecretValue`** — wraps `Zeroizing<Vec<u8>>`. Memory is zeroed on drop. Does not implement
`Debug`, `Display`, or `Clone`. Cannot appear in log output by accident.

**`SecretStore`** — the main trait: `get`, `put`, `refresh`, `from_uri`.

**`SigningBackend`** — for HSM-resident keys: `sign`, `public_key_der`, `algorithm`. The
private key never leaves the hardware.

**`SecretError`** — `#[non_exhaustive]` enum: `NotFound`, `Backend`, `InvalidUri`,
`DecodeFailed`, `Unavailable`. Unavailability is always a hard error — no silent fallback to
empty string or default value.

---

## Crate structure

The library is a Cargo workspace. Each backend is its own crate with no compile-time feature
guards. The only `#[cfg(feature)]` in the entire workspace is in the thin `secretx` umbrella
crate's URI dispatch function.

| Crate | Contents |
|-------|----------|
| `secretx-core` | Traits, `SecretValue`, `SecretError` |
| `secretx-cache` | `CachingStore<S>` — TTL-based in-memory cache over any `SecretStore` |
| `secretx-env` | Environment variable backend |
| `secretx-file` | Filesystem backend |
| `secretx-aws-kms` | AWS KMS backend (signing only) |
| `secretx-aws-sm` | AWS Secrets Manager backend |
| `secretx-aws-ssm` | AWS SSM Parameter Store backend |
| `secretx-azure-kv` | Azure Key Vault backend |
| `secretx-bitwarden` | Bitwarden Secrets Manager backend |
| `secretx-doppler` | Doppler backend |
| `secretx-gcp-sm` | GCP Secret Manager backend |
| `secretx-hashicorp-vault` | HashiCorp Vault backend |
| `secretx-keyring` | OS keychain backend (macOS, Linux, Windows) |
| `secretx-pkcs11` | PKCS#11 HSM backend |
| `secretx-wolfhsm` | wolfHSM secure element backend |
| `secretx` | Umbrella: re-exports `secretx-core` + `from_uri` dispatch |

---

## Status

Early development. The API may change before 1.0.

All backends are implemented. Integration test coverage as of 2026-04-23:

| Backend | Integration tested | Notes |
|---------|-------------------|-------|
| `env` | ✅ real I/O | reads live env vars |
| `file` | ✅ real I/O | reads/writes real files |
| `local-signing` | ✅ real crypto | sign + verify round-trip |
| `cache` | ✅ real TTL logic | in-memory, no external service |
| `aws-sm` | ✅ real AWS | tested against AWS Secrets Manager |
| `aws-ssm` | ✅ real AWS | tested against AWS SSM Parameter Store |
| `aws-kms` | ✅ real AWS | ECDSA P-256 and RSA-PSS 2048 sign/verify |
| `hashicorp-vault` | ✅ local Vault | tested against Vault dev server |
| `pkcs11` | ✅ SoftHSM2 | EC P-256 sign + data object get/put |
| `azure-kv` | ⚠️ unit tests only | needs Azure subscription + Key Vault |
| `gcp-sm` | ⚠️ unit tests only | needs GCP project + Secret Manager API |
| `doppler` | ⚠️ unit tests only | needs Doppler account + service token |
| `bitwarden` | ⚠️ unit tests only | needs Bitwarden Secrets Manager account |
| `keyring` | ❌ headless fails | requires desktop keyring daemon; `put` succeeds but `get` returns `NotFound` on a headless server |
| `wolfhsm` | ➖ stub only | returns `Unavailable`; requires wolfHSM native library + device |

Unit tests (URI parsing, error mapping) pass for all backends regardless of credentials.

---

## License

MIT — Copyright (c) 2026 WolfSSL Inc.

See [LICENSE](LICENSE).
