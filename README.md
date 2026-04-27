# secretx

Backend-agnostic secrets retrieval for Rust services and daemons. One trait, many stores.

```toml
[dependencies]
secretx = { version = "0.3", features = ["aws-sm", "file"] }
```

---

## The problem

Daemons and services have no interactive session and no OS keychain to unlock. Credentials are
injected by an orchestrator or platform — from Vault, AWS Secrets Manager, encrypted files on
disk, or environment variables set by the container runtime. Every project that touches two of
these backends writes the same boilerplate twice: pick an SDK, call the API, handle errors,
inject the value.

There is no standard abstraction. Code is coupled to a specific SDK at the call site. Switching
from HashiCorp Vault to AWS Secrets Manager — or from real credentials to a local file in dev —
requires changes throughout the codebase.

`secretx` is the `sqlx` of secrets retrieval. Write your code against one trait. Switch backends
by changing a URI in config.

**vs. `keyring`:** The [`keyring`](https://crates.io/crates/keyring) crate is excellent for
interactive desktop apps that store user-entered credentials in OS-native keychains (macOS
Keychain, GNOME Keyring, Windows Credential Manager). Those backends require a logged-in user
session and a running keychain daemon — conditions that don't hold on a headless server.
`secretx` targets the daemon case. The two are complementary: `secretx-keyring` wraps `keyring`
as one backend option for the rare service that runs inside a user session.

---

## What this is not

- **Not a secrets manager.** Does not store, encrypt, or audit secrets — that is the backend's job.
- **Not a key management system.** Does not generate keys or rotate credentials autonomously.
  Exception: the HSM backends (`aws-kms`, `azure-kv`, `pkcs11`, `wolfhsm`) expose `SigningBackend`
  for keys that must never leave the hardware.
- **Not a configuration loader.** Loads secrets (sensitive values that must be zeroed on drop),
  not config (non-sensitive structured data). Use `config-rs` or `figment` for the rest.
- **Not async-only.** A sync `get_blocking` adapter wraps `get` for callers that cannot be async.
- **Not a secrets scanner.** Does not audit code for hardcoded secrets.

---

## How it works

Backends are selected by URI at runtime. The call site never names a backend.

```
secretx:<backend>:<path>[?options]
```

| URI | Backend | Notes |
|-----|---------|-------|
| `secretx:env:MY_SECRET` | Environment variable | |
| `secretx:file:/etc/secrets/key` | File (absolute path) | |
| `secretx:file:relative/path` | File (relative to CWD) | |
| `secretx:aws-kms:alias/my-key` | AWS KMS | signing only |
| `secretx:aws-sm:prod/my-secret` | AWS Secrets Manager | |
| `secretx:aws-sm:prod/my-secret?field=password` | AWS Secrets Manager | extract one JSON field |
| `secretx:aws-ssm:prod/my-param` | AWS SSM Parameter Store | `SecureString` decrypted automatically |
| `secretx:aws-ssm:prod/my-param?version=3` | AWS SSM Parameter Store | specific version |
| `secretx:azure-kv:myvault/mysecret` | Azure Key Vault | also `SigningBackend` for HSM vaults |
| `secretx:bitwarden:myproject/MY_SECRET` | Bitwarden Secrets Manager | auth via `BWS_ACCESS_TOKEN` |
| `secretx:doppler:myproject/prd/MY_SECRET` | Doppler | auth via `DOPPLER_TOKEN` |
| `secretx:gcp-sm:my-project/my-secret` | GCP Secret Manager | |
| `secretx:keyring:myapp/my-key` | OS keychain | desktop sessions only |
| `secretx:local-signing:<path>` | Local key file | signing only; Ed25519, P-256, RSA-PSS |
| `secretx:pkcs11:0/my-key?lib=/usr/lib/libsofthsm2.so` | PKCS#11 HSM | also `SigningBackend`; `lib` from `PKCS11_LIB` env var |
| `secretx:vault:secret/myapp/key` | HashiCorp Vault | auth via `VAULT_TOKEN` or AppRole |
| `secretx:wolfhsm:my-key` | wolfHSM secure element | also `SigningBackend`; transport via `WOLFHSM_SERVER` |

The `from_uri` call constructs the backend and validates the URI syntax. It does not make any
network call or file read. Fetch happens on first `get`.

---

## Usage

### URI-driven (umbrella crate)

The `secretx` umbrella crate provides `from_uri` dispatch. Enable the backends you need as
features.

```toml
[dependencies]
secretx = { version = "0.3", features = ["aws-sm", "file"] }
```

Feature flags match backend names: `aws-kms`, `aws-sm`, `aws-ssm`, `azure-kv`, `bitwarden`,
`cache`, `doppler`, `env` (default), `file` (default), `gcp-sm`, `hashicorp-vault`, `keyring`,
`local-signing`, `pkcs11`, `wolfhsm`.

```rust
use secretx::{SecretStore, SecretValue};

// Configured per-environment. No code change to switch backends.
let uri = std::env::var("SIGNING_KEY_URI")
    .unwrap_or_else(|_| "secretx:file:/etc/dev-secrets/signing.key".into());

let store = secretx::from_uri(&uri)?;
let key: SecretValue = store.get().await?;

// key is zeroed from memory when it drops.
```

### Direct (single backend crate)

If you only ever use one backend and don't need URI dispatch, depend on the backend crate
directly. No umbrella, no feature flags, no compile guards in your dependency tree.

```toml
[dependencies]
secretx-aws-sm = "0.3"
```

```rust
use secretx_aws_sm::AwsSmBackend;
use secretx_core::SecretStore;

let store = AwsSmBackend::from_uri("secretx:aws-sm:prod/signing-key")?;
let key = store.get().await?;
```

### Signing with an HSM-resident key

For keys that must never leave the hardware (AWS KMS, Azure Key Vault HSM, PKCS#11, wolfHSM),
use `SigningBackend`. Call sites are identical regardless of which HSM is underneath.

```rust
use secretx_aws_kms::AwsKmsBackend;
use secretx_core::SigningBackend;

let backend = AwsKmsBackend::from_uri("secretx:aws-kms:alias/my-signing-key")?;
let signature = backend.sign(&message).await?;
let pubkey_der = backend.public_key_der().await?;
```

---

## Core types

**`SecretValue`** — wraps `Zeroizing<Vec<u8>>`. Memory is zeroed on drop. Does not implement
`Debug`, `Display`, or `Clone`. Cannot appear in log output by accident.

**`SecretStore`** — the main trait: `get` and `refresh`. All backends implement this.

**`WritableSecretStore`** — subtrait that adds `put`. Implemented by backends that support
writes (file, keyring, cloud stores). Read-only backends (`env`, `bitwarden`) implement only
`SecretStore`.

**`SigningBackend`** — for HSM-resident keys: `sign`, `public_key_der`, `algorithm`. The
private key never leaves the hardware.

**`SecretError`** — `#[non_exhaustive]` enum: `NotFound`, `Backend`, `InvalidUri`,
`DecodeFailed`, `Unavailable`. Unavailability is always a hard error — no silent fallback to
empty string or default value.

---

## Crate structure

The library is a Cargo workspace. Each backend is its own crate with no compile-time feature
guards. All `#[cfg(feature)]` guards are confined to the `secretx` umbrella crate's three
dispatch functions. Backend crates have no compile-time feature guards.

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
| `secretx-local-signing` | Local key file signing backend (Ed25519, P-256, RSA-PSS) |
| `secretx-pkcs11` | PKCS#11 HSM backend |
| `secretx-wolfhsm` | wolfHSM secure element backend |
| `secretx` | Umbrella: re-exports `secretx-core` + `from_uri` dispatch |

---

## Security guarantees

1. **`SecretValue` memory is zeroed on drop.** `Zeroizing<Vec<u8>>` ensures this. Backends never
   copy secret bytes into non-`Zeroizing` buffers.

2. **No `Debug` or `Display`.** `SecretValue` does not implement these traits. Tracing spans and
   log lines cannot accidentally format a secret.

3. **No logging of secret content.** Backends log the secret name and backend; never the bytes.

4. **URI parsing does not fetch.** `from_uri` validates URI syntax only — no network call, no
   file read. Secrets that are never requested are never fetched.

5. **Unavailability is a hard error.** If the backend is unreachable and the cache has no entry,
   `get` returns `SecretError::Unavailable`. There is no silent fallback to an empty string.

6. **`put` access is controlled at the backend.** This crate does not enforce IAM or ACLs; it
   relies on the backend to reject unauthorized writes.

---

## Comparison

| | `secretx` | Roll-your-own | Direct SDK | `config-rs` |
|---|---|---|---|---|
| Backend-agnostic | Yes | No | No | No |
| Memory zeroed on drop | Yes | Varies | No | No |
| URI-driven backend selection | Yes | No | No | No |
| TTL caching | Yes | Varies | No | No |
| HSM signing support | Yes | Rarely | Separate SDK | No |
| `cargo test` without cloud creds | Yes (file/env) | Varies | No | Yes |

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

## Versioning

All crates in the workspace share a single version number.

- **Patch** (`0.x.Y`): bug fixes and documentation; no API change.
- **Minor** (`0.X.0`): new backends, new optional methods, additive features.
- **Major** (`X.0.0`): breaking changes to `SecretStore`, `SecretValue`, or `SecretError`.

Commits that remove or incompatibly change a public item use the `!` breaking-change marker
(`feat!:`, `fix!:`) or a `BREAKING CHANGE:` footer, even on 0.x releases.

---

## Releasing

All crates must be published in dependency order. A crate cannot be published until all of its
workspace dependencies are already on crates.io.

```
1. secretx-core
2. secretx-cache
3. All backend crates (any order — each depends only on secretx-core)
4. secretx  (depends on all of the above)
```

Pre-flight checks before publishing:

```bash
cargo fmt --all -- --check
cargo clippy --all-features --workspace -- -D warnings
cargo test --workspace --all-features
cargo audit
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features --workspace
cargo hack check --feature-powerset --depth 2 -p secretx
```

Publish each crate with `cargo publish -p <crate>`, waiting ~30 s between each for the
crates.io index to update. After publishing, tag the release (`git tag vX.Y.Z`) and create a
GitHub release with the relevant CHANGELOG entry.

---

## License

MIT — Copyright (c) 2026 WolfSSL Inc.

See [LICENSE](LICENSE).
