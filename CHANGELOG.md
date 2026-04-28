# Changelog

## [secretx-wolfhsm 0.3.1] - 2026-04-27

### Fixed (`secretx-wolfhsm` only — other crates unchanged at 0.3.0)

- **Port > 32767 in server address now returns `InvalidUri` at construction
  time** instead of `Unavailable` at first use. wolfhsm's C TCP transport
  stores port as `i16`; the limit is now enforced in `make_transport` and
  the `?server=` address is validated eagerly in `from_uri()` (pure parsing,
  no I/O). `WOLFHSM_SERVER` from the environment is still validated lazily
  since its value is not known at construction time.

- **`put()` new-object path now makes one `nvm_list` round-trip instead of
  two.** The ID list fetched during the label scan is threaded through a new
  `FindResult` enum to `find_free_id_from_list`, avoiding a redundant call
  to the wolfHSM server.

- **TOCTOU gap in `find_free_id` documented.** The window between the
  ID-list snapshot and `nvm_add` is inherent to the wolfHSM protocol (no
  atomic allocate API); callers should propagate `Backend` on conflict rather
  than retrying automatically.

---

## [0.3.0] - 2026-04-24

### Breaking changes

- **URI scheme changed from `secretx://` to `secretx:`** — the old `secretx://backend/path`
  format abused RFC 3986 authority syntax and required an awkward double-slash for absolute paths
  (`secretx://file//etc/key`). The new `secretx:backend:path` format is a proper RFC 3986 opaque
  URI. Query parameters are unchanged.

  Find all old-format URIs in a project:

  ```sh
  grep -r 'secretx://' . --include="*.toml" --include="*.yaml" --include="*.yml" \
    --include="*.env" --include="*.json" --include="*.rs" --include="*.md"
  ```

  Migrate with sed (Linux):

  ```sh
  find . -type f \( -name "*.toml" -o -name "*.yaml" -o -name "*.yml" \
    -o -name "*.env" -o -name "*.json" -o -name "*.rs" -o -name "*.md" \) \
    -exec sed -i -E 's|secretx://([^/?]+)/|secretx:\1:|g' {} \;
  ```

  Migrate with sed (macOS):

  ```sh
  find . -type f \( -name "*.toml" -o -name "*.yaml" -o -name "*.yml" \
    -o -name "*.env" -o -name "*.json" -o -name "*.rs" -o -name "*.md" \) \
    -exec sed -i '' -E 's|secretx://([^/?]+)/|secretx:\1:|g' {} \;
  ```

  | Before (v0.2) | After (v0.3) |
  |---------------|--------------|
  | `secretx://env/MY_VAR` | `secretx:env:MY_VAR` |
  | `secretx://file/relative/path` | `secretx:file:relative/path` |
  | `secretx://file//etc/secrets/key` | `secretx:file:/etc/secrets/key` |
  | `secretx://aws-sm/prod/db-password` | `secretx:aws-sm:prod/db-password` |
  | `secretx://aws-sm/prod/db-password?field=pw` | `secretx:aws-sm:prod/db-password?field=pw` |
  | `secretx://aws-ssm/prod/db/password` | `secretx:aws-ssm:prod/db/password` |
  | `secretx://aws-kms/alias/my-key` | `secretx:aws-kms:alias/my-key` |
  | `secretx://azure-kv/myvault/mysecret` | `secretx:azure-kv:myvault/mysecret` |
  | `secretx://vault/secret/myapp` | `secretx:vault:secret/myapp` |
  | `secretx://pkcs11/0/my-key` | `secretx:pkcs11:0/my-key` |
  | `secretx://wolfhsm/my-label` | `secretx:wolfhsm:my-label` |

  Passing an old-format URI at runtime returns a clear error pointing to this changelog.

- **`put()` removed from `SecretStore`** — callers using `store.put(value).await` must now
  depend on `WritableSecretStore` and call `from_uri_writable` to obtain a writable handle.
  `from_uri` still works for read-only access; the call site is unchanged.

### New

- **`WritableSecretStore` subtrait** — `pub trait WritableSecretStore: SecretStore`. Adds
  `put()`. Implemented by all backends that support writes: `file`, `keyring`, `aws-sm`,
  `aws-ssm`, `azure-kv`, `doppler`, `gcp-sm`, `hashicorp-vault`, `pkcs11`. Read-only backends
  (`env`, `bitwarden`) implement only `SecretStore`.

- **`from_uri_writable(uri)`** in the `secretx` umbrella crate — returns
  `Arc<dyn WritableSecretStore>`. Rejects read-only backends (`env`, `bitwarden`) and
  signing-only backends (`aws-kms`, `local-signing`, `wolfhsm`) with `SecretError::InvalidUri`
  at construction time.

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
`from_uri_writable` separately with the same URI string. Calling `.get()` and `.refresh()`
directly on an `Arc<dyn WritableSecretStore>` works on all supported toolchains via supertrait
method dispatch.

## [0.2.0] - 2026-04-23

Initial public release. Workspace restructured: the single-crate `secretx` 0.1.0 was split into
`secretx-core` plus per-backend crates. The `secretx` umbrella crate re-exports everything from
`secretx-core` at the same public paths — a `cargo update` is sufficient for users who depended
only on the `secretx` umbrella crate.

| 0.1.0 path | 0.2.0 path | Status |
|------------|------------|--------|
| `secretx::SecretValue` | `secretx::SecretValue` (re-export) | compatible |
| `secretx::SecretError` | `secretx::SecretError` (re-export) | compatible |
| `secretx::SecretStore` | `secretx::SecretStore` (re-export) | compatible |
| `secretx::SigningBackend` | `secretx::SigningBackend` (re-export) | compatible |
| `secretx::SigningAlgorithm` | `secretx::SigningAlgorithm` (re-export) | compatible |
| `secretx::get_blocking` | `secretx::get_blocking` (feature `blocking`) | compatible |
