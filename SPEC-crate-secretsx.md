# SPEC: secretx

A backend-agnostic secrets retrieval library for Rust. One trait, many stores.

**Status:** In progress. Core traits and types implemented and published (`secretx-core 0.1.0`). Backend implementations pending.

---

## The Problem

Every Rust project that needs secrets from a managed store (AWS Secrets Manager, Azure Key Vault,
HashiCorp Vault, GCP Secret Manager, etc.) writes the same boilerplate: pick a cloud SDK, call the
API, unwrap the value, inject it somewhere. There is no `sqlx`-equivalent — no single trait that
lets you write code once and switch backends via config.

The consequences:

- Code is coupled to a specific cloud vendor's SDK at the call site.
- Testing requires either real credentials or elaborate mocks per SDK.
- Rotation, caching, and memory safety (zeroing secrets on drop) are re-implemented in every project.
- The "just read from an env var in dev, Secrets Manager in prod" pattern requires `if cfg!(...)` noise throughout the codebase.

The gap is not "we need a better AWS SDK wrapper." The gap is "we need a secrets abstraction that
treats the retrieval backend as a swappable driver, the same way `sqlx` treats the database."

**The invariant this crate upholds:** the call site never names a backend. A URI in config selects
the backend at runtime. Switching from file-based dev secrets to AWS Secrets Manager in prod is a
one-line config change.

---

## What This Is Not

- Not a secrets manager itself. Does not store, encrypt, or audit secrets — that is the backend's job.
- Not a key management system. Does not generate keys, sign data, or rotate credentials autonomously.
  Exception: the `aws-kms` backend exposes a `SigningBackend` for keys that must never leave KMS.
- Not a configuration loader. Loads secrets (sensitive values that must be zeroed) not config
  (non-sensitive structured data). Use `config-rs` or `figment` for the rest.
- Not async-only. A sync `get_blocking` adapter is provided for code that cannot be async.
- Not a secrets scanner. Does not audit code for hardcoded secrets.

---

## URI Scheme

Backends are selected by URI. This keeps the call site backend-agnostic and makes config-file
driven deployment trivial.

```
secretx://<backend>/<path>[?key=val&key2=val2]
```

Absolute file paths use a double slash after the backend: `secretx://file//etc/keys/signing.key`.

| URI | Backend | Notes |
|-----|---------|-------|
| `secretx://aws-kms/alias/my-signing-key` | AWS KMS | Key ARN or alias; signing only |
| `secretx://aws-sm/prod/signing-key` | AWS Secrets Manager | Secret name `prod/signing-key` |
| `secretx://aws-sm/prod/signing-key?field=password` | AWS Secrets Manager | JSON field extraction |
| `secretx://aws-ssm/prod/signing-key` | AWS SSM Parameter Store | Parameter name `prod/signing-key`; SecureString decrypted automatically |
| `secretx://aws-ssm/prod/signing-key?version=3` | AWS SSM Parameter Store | Specific parameter version |
| `secretx://azure-kv/myvault/mysecret` | Azure Key Vault | Vault name + secret name |
| `secretx://bitwarden/myproject/SIGNING_KEY` | Bitwarden Secrets Manager | Project name + secret name |
| `secretx://doppler/myproject/prd/SIGNING_KEY` | Doppler | Project + config + secret name |
| `secretx://env/MY_SECRET` | Environment variable | `MY_SECRET` env var |
| `secretx://file//etc/keys/signing.key` | Filesystem | Absolute path (double slash) |
| `secretx://file/relative/path` | Filesystem | Relative to CWD |
| `secretx://gcp-sm/my-project/my-secret` | GCP Secret Manager | Project + secret name |
| `secretx://keyring/myapp/signing-key` | OS keychain | Service + account |
| `secretx://pkcs11/0/my-signing-key?lib=/usr/lib/libsofthsm2.so` | PKCS#11 HSM | Slot index + object label; `lib` path from URI or `PKCS11_LIB` env var |
| `secretx://vault/secret/data/myapp/key` | HashiCorp Vault | KV v2 path |
| `secretx://wolfhsm/my-signing-key` | wolfHSM | Object label; server transport configured via `WOLFHSM_SERVER` env var |

Each backend's `from_uri` constructor calls `SecretUri::parse` from `secretx-core` to parse the
URI and validate the backend component. Backends not compiled in return a clear error at parse
time, not at runtime. URI parsing does not make any network call or file read.

---

## Core Types

### `SecretValue`

The primary value type. Wraps a `Vec<u8>` and zeroes memory on drop via the `zeroize` crate.
Never implements `Debug`, `Display`, or `Clone` to prevent accidental leakage.

```rust
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self
    pub fn as_bytes(&self) -> &[u8]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>>

    /// Decode as UTF-8 string without copying. Fails if not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, SecretError>

    /// Parse as a JSON object and extract a single string field.
    /// Common for Secrets Manager secrets that store multiple values as JSON.
    pub fn extract_field(&self, field: &str) -> Result<SecretValue, SecretError>
}
```

`SecretValue` does not implement `Serialize` or `Deserialize`. It must never appear in log
output, tracing spans, or serialized structs.

### `SecretError`

```rust
#[non_exhaustive]
pub enum SecretError {
    /// Backend returned no secret for this name/path.
    NotFound,
    /// Backend returned an error (wrapped, with backend name for context).
    Backend { backend: &'static str, source: Box<dyn std::error::Error + Send + Sync> },
    /// URI was syntactically invalid or named an unknown/uncompiled backend.
    InvalidUri(String),
    /// Secret was present but could not be decoded as expected (e.g. not valid UTF-8, not valid JSON).
    DecodeFailed(String),
    /// Backend is not available (e.g. Secrets Manager unreachable, token expired).
    Unavailable { backend: &'static str, source: Box<dyn std::error::Error + Send + Sync> },
}
```

### `SecretUri`

All backends parse URIs using this shared type from `secretx-core`. Backend constructors call
`SecretUri::parse` rather than rolling their own string splitting, so URI parsing is consistent
across the entire workspace.

```rust
pub struct SecretUri {
    /// Backend name, e.g. `"aws-sm"`, `"file"`, `"env"`.
    pub backend: String,
    /// Backend-specific path, e.g. `"prod/signing-key"` or `"/etc/secrets/key"`.
    pub path: String,
    /// Query parameters, e.g. `?field=password` → `{"field": "password"}`.
    pub params: HashMap<String, String>,
}

impl SecretUri {
    pub fn parse(uri: &str) -> Result<Self, SecretError>;
    pub fn param(&self, key: &str) -> Option<&str>;
}
```

`parse` returns `SecretError::InvalidUri` if the URI does not start with `secretx://` or has an
empty backend component. The `path` field preserves a leading `/` for absolute file paths
(encoded with double slash: `secretx://file//etc/key` → `path = "/etc/key"`).

Backend `from_uri` constructors are plain methods (not part of any trait). They call
`SecretUri::parse`, validate the backend field matches their own name, then extract path and
params to configure the struct.

### `SecretStore` trait

```rust
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Retrieve a secret by name/path. Implementations may serve from cache.
    async fn get(&self, name: &str) -> Result<SecretValue, SecretError>;

    /// Write or update a secret. Not supported by all backends (e.g. env, KMS).
    async fn put(&self, name: &str, value: SecretValue) -> Result<(), SecretError>;

    /// Force a cache refresh for this secret. Returns the refreshed value.
    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError>;
}
```

`from_uri` is **not** part of this trait. Construction is not behavior. Each backend exposes its
own `from_uri(uri: &str) -> Result<Self, SecretError>` as a plain associated function. URI
dispatch across all backends is handled by `secretx::from_uri` in the umbrella crate — the only
place in the workspace that contains `#[cfg(feature)]` guards.

### `SigningBackend` trait

For backends where signing must happen inside the HSM and key material never leaves (AWS KMS,
Azure Key Vault HSM, GCP Cloud KMS).

```rust
#[async_trait]
pub trait SigningBackend: Send + Sync {
    /// Sign `message` using the backend key. Returns the raw signature bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError>;

    /// Return the public key as DER-encoded SubjectPublicKeyInfo.
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError>;

    /// Key algorithm. Used by callers to construct the right verifier.
    fn algorithm(&self) -> SigningAlgorithm;
}

pub enum SigningAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
    RsaPss2048Sha256,
}
```

`SigningBackend` is implemented by `AwsKmsBackend` and `AzureKeyVaultHsmBackend`. For the
`LocalKey` backend (key loaded from file or env), a `LocalSigningBackend` wraps `ed25519-dalek`
and implements the same trait, so call sites are identical.

---

## Backends

### `aws-kms` (feature `aws-kms`)

AWS KMS asymmetric keys. Only `SigningBackend` is implemented — `SecretStore::get` and `put`
return `SecretError::NotFound` since KMS does not expose key material.

`sign` calls `kms:Sign` with the configured signing algorithm. The private key never leaves KMS.
`public_key_der` calls `kms:GetPublicKey`.

Supported key specs: `ECC_NIST_P256`, `RSA_2048`. Ed25519 (`ECC_NIST_P25519`) where available
(not all regions; detected at runtime and error returned clearly if unsupported).

### `aws-sm` (feature `aws-secrets-manager`)

AWS Secrets Manager via `aws-sdk-secretsmanager`. Uses the ambient credential chain
(`AWS_PROFILE`, `AWS_ROLE_ARN`, instance metadata, ECS task role). Region defaults to
`AWS_DEFAULT_REGION` or the SDK's region provider chain.

`put` calls `PutSecretValue`. `refresh` bypasses cache and calls `GetSecretValue` directly.

Optional `?field=<name>` query parameter: if the secret value is a JSON object, extracts a
single string field and returns it as the `SecretValue`. Useful for Secrets Manager secrets that
bundle multiple values (e.g. `{"username":"foo","password":"bar"}`).

Optional `?version=<stage>` to retrieve a specific staging label (default: `AWSCURRENT`).

### `aws-ssm` (feature `aws-ssm`)

AWS SSM Parameter Store via `aws-sdk-ssm`. Uses the same ambient credential chain as `aws-sm`
(`AWS_PROFILE`, `AWS_ROLE_ARN`, instance metadata, ECS task role). Region defaults to
`AWS_DEFAULT_REGION` or the SDK's region provider chain.

`SecureString` parameters are decrypted automatically using the parameter's associated KMS key;
the caller never handles the encrypted form. `String` and `StringList` parameters are also
supported (StringList is returned as raw comma-separated bytes — callers that need splitting
should use `as_str()` and split themselves).

`put` calls `PutParameter` with `Overwrite: true`. `refresh` bypasses cache and calls
`GetParameter` with `WithDecryption: true` directly.

Optional `?version=<n>` query parameter to retrieve a specific parameter version (default:
current). Optional `?label=<name>` to retrieve by parameter label.

Note: SSM has lower per-request cost than Secrets Manager and is commonly used for
non-rotating secrets and configuration in AWS environments. Many shops use SSM for secrets
and Secrets Manager only for secrets that require automatic rotation — both backends are
important to support.

### `azure-kv` (feature `azure-keyvault`)

Azure Key Vault secrets via `azure_security_keyvault_secrets`. Credential chain via `azure_identity`
(environment, managed identity, Azure CLI). Vault name from the URI host component.

`put` calls `SetSecret`. `refresh` calls `GetSecret` with a cache bypass.

`AzureKeyVaultHsmBackend` implements `SigningBackend` for keys in a Key Vault HSM-backed vault.

### `bitwarden` (feature `bitwarden`)

Bitwarden Secrets Manager via the official `bitwarden-sm` Rust SDK. Authentication via
`BWS_ACCESS_TOKEN` environment variable (a machine account access token, not a user password).

URI path is `<project-name>/<secret-name>`. Secrets are stored by name within a project;
the backend resolves names to UUIDs internally on first access and caches the mapping. If
two secrets in the same project share a name, `get` returns `SecretError::Backend` with a
message describing the ambiguity — callers must ensure names are unique within a project.

`put` creates or updates a secret by name within the project. `refresh` bypasses cache,
re-resolves the name-to-UUID mapping, and re-fetches the value.

Does not implement `SigningBackend` — Bitwarden Secrets Manager stores secret values only,
not HSM-resident keys.

### `doppler` (feature `doppler`)

Doppler via its REST API (`https://api.doppler.com/v3`). Authentication via `DOPPLER_TOKEN`
environment variable or `?token=` query parameter (environment variable preferred — never
put tokens in URIs stored in code).

URI path is `<project>/<config>/<secret-name>`. Config typically corresponds to an environment
(e.g. `prd`, `stg`, `dev`).

`put` calls the Doppler secrets update API. `refresh` bypasses cache and re-fetches from the
API directly.

No official Rust SDK exists; this backend uses `reqwest` for HTTP. Requires the `cache` feature
to be practical — Doppler has aggressive rate limits on the per-secret fetch API.

### `env` (default, no extra deps)

Reads the named environment variable. `put` returns `SecretError::NotFound` (env vars are not
writable at runtime in a meaningful way). `refresh` re-reads the env var (value may have changed
if the process manager rotated it).

### `file` (default, no extra deps)

Reads the entire file at the given path. No caching — file is re-read on each `get` unless
wrapped in `CachingStore`. Useful for Docker secrets (`/run/secrets/...`), Kubernetes secret
volume mounts, and development.

`put` overwrites the file with mode `0600`. `refresh` re-reads from disk.

### `gcp-sm` (feature `gcp-secretmanager`)

GCP Secret Manager via `google-cloud-secretmanager`. Project and secret name from the URI path.
Credential chain via Application Default Credentials.

`put` adds a new version (`AddSecretVersion`). `refresh` fetches `latest`.

### `hashicorp-vault` (feature `hashicorp-vault`)

HashiCorp Vault KV v2 via `vaultrs`. Address from `VAULT_ADDR` env var or `?addr=` query
parameter. Token from `VAULT_TOKEN` or via AppRole auth (configurable).

`put` calls `kv2::set`. `refresh` bypasses cache and calls `kv2::read` directly.

### `keyring` (feature `keyring`)

OS keychain via the `keyring` crate. macOS Keychain, Linux Secret Service (GNOME Keyring /
KWallet), Windows Credential Manager. Service name from the URI host, account name from the path.

Development and desktop use only. Not suitable for server deployments.

### `pkcs11` (feature `pkcs11`)

PKCS#11 HSM interface via the `cryptoki` crate. Covers any hardware or software token that
exposes a PKCS#11 library: Thales Luna, Entrust nShield, YubiKey (with `ykcs11`), SoftHSM2,
AWS CloudHSM, and others.

URI path is `<slot-id>/<object-label>`. The slot index selects the PKCS#11 token; the label
identifies the object on that token. The shared library path is taken from the `?lib=` query
parameter or the `PKCS11_LIB` environment variable (env var preferred — library paths must
not be hardcoded into URIs stored in config).

`SecretStore::get` reads a `CKO_DATA` object with the given label and returns its value.
`put` creates or overwrites a `CKO_DATA` object. Not all tokens support `put` on data objects;
`SecretError::Backend` is returned for tokens that reject the write.

`SigningBackend` is also implemented: `sign` calls `C_Sign` with the `CKO_PRIVATE_KEY` object
matching the label; `public_key_der` reads the corresponding `CKO_PUBLIC_KEY` and encodes it
as DER SubjectPublicKeyInfo. The private key never leaves the token. Supported mechanisms:
`CKM_ECDSA` (P-256), `CKM_RSA_PKCS_PSS` (RSA-2048), `CKM_EDDSA` (Ed25519, where supported).

PIN authentication: if the token requires a user PIN, supply it via `PKCS11_PIN` environment
variable or `?pin=` query parameter (`PKCS11_PIN` preferred). If no PIN is set and the token
requires one, `get` returns `SecretError::Unavailable`.

For CI testing, use SoftHSM2 (`softhsm2-util --init-token`). SoftHSM2 is available in most
Linux package managers and supports all three signing mechanisms.

### `wolfhsm` (feature `wolfhsm`)

wolfHSM secure element interface via the `wolfhsm` Rust crate (FFI bindings to the wolfHSM
client library). Targets embedded and automotive hardware where a secure core runs the wolfHSM
server and the application core runs the wolfHSM client — the private key and stored objects
never cross the core boundary.

URI path is the NVM object label. The server transport is configured outside the URI:

- `WOLFHSM_SERVER` — transport address. Format is transport-specific:
  - TCP: `tcp://127.0.0.1:8080`
  - POSIX shared memory: `posix://wh_server`
  - Embedded transports (UART, SPI, custom) are configured at compile time via the wolfHSM
    client library; `WOLFHSM_SERVER` is ignored in those builds.
- `WOLFHSM_CLIENT_ID` — numeric client identity (default: `1`).
- `WOLFHSM_AUTH_KEY` — path to the client authentication key file, or raw hex via
  `WOLFHSM_AUTH_KEY_HEX`.

`SecretStore::get` reads a `WH_OBJ_TYPE_DATA` NVM object with the given label.
`put` creates or overwrites the NVM object.

`SigningBackend` is also implemented: `sign` calls `wh_Client_Sign` with the
`WH_OBJ_TYPE_KEY` object matching the label; the private key never leaves the secure element.
`public_key_der` reads the corresponding public key and encodes it as DER SubjectPublicKeyInfo.
Supported algorithms: ECC P-256 (`CTC_SHA256wECDSA`), RSA-PSS 2048, Ed25519 (where the
target hardware supports it).

For CI testing, use the wolfHSM simulator server (`wh_server_sim`) included in the wolfHSM
source tree. The simulator runs as a local process and communicates over POSIX shared memory,
requiring no hardware.

---

## Caching Layer

The `CachingStore` wrapper adds a TTL-based in-memory cache over any `SecretStore`. It is not
mandatory — backends that benefit from caching (Secrets Manager, Vault) are typically wrapped
automatically by their constructors; backends that are cheap to read (file, env) are not.

```rust
pub struct CachingStore<S: SecretStore> {
    inner: Arc<S>,
    ttl: Duration,
    cache: Arc<Mutex<HashMap<String, CachedEntry>>>,
}

struct CachedEntry {
    value: SecretValue,          // zeroed on eviction
    fetched_at: Instant,
}
```

`get` returns the cached value if `fetched_at + ttl > now`. `refresh` bypasses the cache,
fetches from the inner store, and updates the cache entry. On TTL expiry, the old value is
zeroed and the new value fetched lazily on next `get`.

Default TTL: 5 minutes for Secrets Manager / Vault / Key Vault; 0 (no caching) for file / env.

---

## Security Invariants

1. **`SecretValue` memory is zeroed on drop.** `Zeroizing<Vec<u8>>` from the `zeroize` crate
   ensures this. Implementations must not copy the inner bytes into non-`Zeroizing` buffers.

2. **No `Debug` or `Display` for `SecretValue`.** The type does not implement these traits.
   Tracing spans and log lines cannot accidentally format a `SecretValue`.

3. **No logging of secret content.** Implementations must not log secret bytes, even at `TRACE`.
   Log the secret name and backend only.

4. **`put` is access-controlled at the backend level.** This crate does not enforce IAM; it
   relies on the backend to reject unauthorized writes. Callers should not assume `put` is safe
   to expose without authorization checks.

5. **URI parsing does not fetch.** `from_uri` constructs the backend object and validates the
   URI syntax but does not make any network call or file read. Fetch happens on first `get`.
   This ensures startup does not block on secret availability, and secrets that are not needed
   are never fetched.

6. **Unavailability is a hard error.** If the backend is unreachable and the cache has no
   entry, `get` returns `SecretError::Unavailable`. There is no silent fallback to a default
   value or empty string. Callers must decide explicitly how to handle unavailability.

---

## Crate Structure

The library is a Cargo workspace. Each backend is its own crate with no compile-time feature
guards. The only `#[cfg(feature = "...")]` in the entire workspace lives in the thin `secretx`
umbrella crate's URI dispatch function — a few match arms, nothing else.

```
secretx-core/            — SecretValue, SecretError, SecretUri, SecretStore trait, SigningBackend trait
secretx-cache/           — CachingStore<S: SecretStore>  (dep: secretx-core, tokio)
secretx-aws-kms/         — AWS KMS backend               (dep: secretx-core, aws-sdk-kms, aws-config)
secretx-aws-sm/          — AWS Secrets Manager           (dep: secretx-core, aws-sdk-secretsmanager, aws-config)
secretx-aws-ssm/         — AWS SSM Parameter Store       (dep: secretx-core, aws-sdk-ssm, aws-config)
secretx-azure-kv/        — Azure Key Vault               (dep: secretx-core, azure_security_keyvault_secrets, azure_identity)
secretx-bitwarden/       — Bitwarden Secrets Manager     (dep: secretx-core, secretx-cache, bitwarden-sm)
secretx-doppler/         — Doppler                       (dep: secretx-core, secretx-cache, reqwest)
secretx-env/             — environment variable          (dep: secretx-core)
secretx-file/            — filesystem                    (dep: secretx-core)
secretx-gcp-sm/          — GCP Secret Manager            (dep: secretx-core, google-cloud-secretmanager)
secretx-hashicorp-vault/ — HashiCorp Vault               (dep: secretx-core, vaultrs)
secretx-keyring/         — OS keychain                   (dep: secretx-core, keyring)
secretx-pkcs11/          — PKCS#11 HSM                   (dep: secretx-core, cryptoki)
secretx-wolfhsm/         — wolfHSM secure element        (dep: secretx-core, wolfhsm)
secretx/                 — umbrella: re-exports + URI dispatch  (optional deps on all backend crates)
```

### The umbrella crate (`secretx`)

`secretx` is the entry point for callers who want URI-driven backend selection. It re-exports
`secretx_core::{SecretValue, SecretError, SecretUri, SecretStore, SigningBackend, SigningAlgorithm}`
and provides a free function:

```rust
pub fn from_uri(uri: &str) -> Result<Arc<dyn SecretStore>, SecretError>
```

This function is the **only** place in the workspace that contains `#[cfg(feature = "...")]`
guards. Feature flags in `secretx/Cargo.toml` gate optional dependencies on the backend crates:

```toml
[features]
default = ["env", "file"]
aws-kms = ["dep:secretx-aws-kms"]
aws-sm  = ["dep:secretx-aws-sm"]
aws-ssm = ["dep:secretx-aws-ssm"]
azure-kv = ["dep:secretx-azure-kv"]
bitwarden = ["dep:secretx-bitwarden"]
cache = ["dep:secretx-cache"]
doppler = ["dep:secretx-doppler"]
env = ["dep:secretx-env"]
file = ["dep:secretx-file"]
gcp-sm = ["dep:secretx-gcp-sm"]
hashicorp-vault = ["dep:secretx-hashicorp-vault"]
keyring = ["dep:secretx-keyring"]
pkcs11 = ["dep:secretx-pkcs11"]
wolfhsm = ["dep:secretx-wolfhsm"]
```

Callers who want only one backend and don't need URI dispatch can depend on the backend crate
directly (e.g. `secretx-aws-sm`) without pulling in `secretx` or any other backend.

### `secretx-core`

No optional dependencies. No `#[cfg]`. Dependencies: `zeroize`, `thiserror`, `async-trait`,
`serde_json`. This is what backend crate authors depend on. Exports: `SecretValue`, `SecretError`,
`SecretUri`, `SecretStore`, `SigningBackend`, `SigningAlgorithm`.

### `secretx-cache`

`CachingStore<S: SecretStore>` with TTL-based eviction. Depends on `secretx-core` + `tokio`
(async `Mutex`). Backend crates that require caching (`secretx-bitwarden`, `secretx-doppler`)
depend on this crate directly, not on `tokio` themselves.

---

## Testing

### Unit tests

Each crate has its own `#[cfg(test)]` module. No cross-crate test fixtures.

`secretx-core`:
- `SecretValue` zeroes memory on drop (use `valgrind` or check the `zeroize` drop path directly).
- `extract_field` on valid and malformed JSON.

`secretx-cache`:
- `CachingStore` serves from cache on second call within TTL.
- `CachingStore` re-fetches after TTL expiry.
- `CachingStore` zeroes old cached value on eviction.

`secretx` (umbrella):
- `from_uri` correctly identifies each backend type from its URI scheme.
- `from_uri` returns `InvalidUri` for unknown scheme and for backend crate not enabled.

### Integration tests (require real or mocked backends)

- `aws-kms` backend: use LocalStack or real KMS. Sign a known message, verify signature with
  the public key returned by `public_key_der`.
- `aws-sm` backend: use LocalStack or a real AWS account with a test secret. Verify `get`,
  `put` (new version), `refresh`, `extract_field`, expiry of cached value.
- `aws-ssm` backend: use LocalStack or a real AWS account. Verify `get` on `String` and
  `SecureString` parameter types, `put` (overwrite), `refresh`, version pinning via `?version=`.
- `bitwarden` backend: use a real Bitwarden Secrets Manager account. Gate behind
  `BWS_ACCESS_TOKEN` env var check; skip if absent.
- `doppler` backend: use a real Doppler account with a test project/config (no LocalStack
  equivalent exists). Gate these tests behind a `DOPPLER_TOKEN` env var check; skip if absent.
- `env` backend: set env var, read it, verify.
- `file` backend: write a temp file, read it back, verify bytes match, overwrite with `put`.
- `hashicorp-vault` backend: use the official `vault` Docker image in CI. KV v2 get/put.
- `pkcs11` backend: use SoftHSM2 (`softhsm2-util --init-token`). Test `get`/`put` on
  `CKO_DATA` objects and `SigningBackend` for all three supported mechanisms. SoftHSM2 is
  available in CI via `apt-get install softhsm2`.
- `wolfhsm` backend: use the wolfHSM simulator server (`wh_server_sim` over POSIX shared
  memory). Test `get`/`put` on NVM data objects and `SigningBackend` for ECC P-256 and RSA-PSS.
  Gate behind a `WOLFHSM_SIMULATOR` env var check; skip if absent.

### `SecretValue` must never appear in test output

All test assertions compare `as_bytes()` return values, not the `SecretValue` itself. Test
failure output must not print secret content. Use `assert_eq!(actual.as_bytes(), expected)` not
`assert_eq!(actual, expected_secretvalue)`.

---

## Usage Example

Via the umbrella crate (URI dispatch, feature `aws-sm` + `file` enabled):

```rust
use secretx::{SecretStore, SecretValue};
use std::sync::Arc;

// In dev: secretx://file//etc/dev-secrets/signing.key
// In prod: secretx://aws-sm/prod/usenet-ipfs/signing-key
let uri = std::env::var("SIGNING_KEY_URI")
    .unwrap_or_else(|_| "secretx://file//etc/dev-secrets/signing.key".into());

let store: Arc<dyn SecretStore> = secretx::from_uri(&uri)?;
let key_bytes: SecretValue = store.get("signing-key").await?;

// key_bytes is zeroed when it goes out of scope.
// The call site has no knowledge of which backend was used.
```

Via a backend crate directly (no umbrella, no URI dispatch):

```rust
use secretx_aws_sm::AwsSmBackend;
use secretx_core::SecretStore;

let store = AwsSmBackend::from_uri("secretx://aws-sm/prod/signing-key")?;
let key_bytes = store.get("prod/signing-key").await?;
```

For signing with AWS KMS directly:

```rust
use secretx_aws_kms::AwsKmsBackend;
use secretx_core::SigningBackend;

let backend = AwsKmsBackend::from_uri("secretx://aws-kms/alias/usenet-ipfs-signing-key")?;
let signature = backend.sign(&message_bytes).await?;
let pubkey_der = backend.public_key_der().await?;
```

---

## Comparison with Alternatives

| | secretx | Roll-your-own | aws-sdk-secretsmanager directly | config-rs |
|---|---|---|---|---|
| Backend-agnostic | Yes | No | No | No |
| SecretValue zeroing | Yes | Varies | No | No |
| URI-driven backend selection | Yes | No | No | No |
| Caching with TTL | Yes | Varies | No | No |
| SigningBackend (HSM) | Yes | Rarely | Separate SDK | No |
| `cargo test` without cloud creds | Yes (file/env) | Varies | No | Yes |

---

## Open Questions

1. **Rotation callbacks.** Should `SecretStore` have an `on_rotate` callback so long-running
   servers can re-fetch and re-inject a rotated secret without restart? AWS Secrets Manager
   supports Lambda rotation; Vault supports lease renewal. Deferred — callers can poll `refresh`
   on a timer for now.

2. **Structured secrets.** Secrets Manager commonly stores JSON objects with multiple fields.
   Should there be a `SecretMap` type (a map from field name to `SecretValue`) in addition to
   bare `SecretValue`? Or is `extract_field` sufficient?

3. **Sync API.** `get_blocking` wraps `get` in a `tokio::task::block_in_place`. Is this
   sufficient, or should there be a separate sync-only trait for non-async callers? The `keyring`
   crate is sync; the adapter is currently `spawn_blocking`.

4. **Multiple URIs / fallback chain.** Should `from_uri` accept a comma-separated list of URIs
   and try each in order (primary → fallback)? Useful for "try Secrets Manager, fall back to
   env var." Or is this complexity the caller's problem?

5. **Audit logging.** Some compliance regimes require every secret access to be logged to an
   audit trail (separate from the application log). Should `CachingStore` support an optional
   `AuditSink` trait, or is that always the backend's job (CloudTrail, Vault audit log)?

6. **Windows DPAPI backend.** For Windows-native deployments (not containers), DPAPI is the
   natural secrets store. The `keyring` crate covers this partially; a dedicated backend may
   be cleaner.

7. **Crate name.** Resolved: `secretx` is published on crates.io. URI scheme is `secretx://`.
