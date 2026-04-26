# Migration Guide

## v0.2 → v0.3: URI scheme change

The URI format changed in v0.3. All `secretx://` URIs must be updated.

### What changed and why

The old format `secretx://backend/path` abused RFC 3986 authority syntax: the thing after `://` is
supposed to be a hostname, not a backend name. Absolute file paths required an awkward double-slash
hack (`secretx://file//etc/key`). This was flagged in code review as confusing and fragile.

The new format `secretx:backend:path` is a proper RFC 3986 opaque URI. The scheme is `secretx`,
the opaque part is parsed internally as `backend:path`. Absolute paths work naturally.

### Find old URIs

```sh
grep -r 'secretx://' . --include="*.toml" --include="*.yaml" --include="*.yml" \
  --include="*.env" --include="*.json" --include="*.rs" --include="*.md"
```

### Transformation rule

```sh
# Linux (GNU sed):
find . -type f \( -name "*.toml" -o -name "*.yaml" -o -name "*.yml" \
  -o -name "*.env" -o -name "*.json" -o -name "*.rs" -o -name "*.md" \) \
  -exec sed -i -E 's|secretx://([^/?]+)/|secretx:\1:|g' {} \;

# macOS (BSD sed):
find . -type f \( -name "*.toml" -o -name "*.yaml" -o -name "*.yml" \
  -o -name "*.env" -o -name "*.json" -o -name "*.rs" -o -name "*.md" \) \
  -exec sed -i '' -E 's|secretx://([^/?]+)/|secretx:\1:|g' {} \;
```

Apply to all URI strings in config files, source code, and documentation.

### Before / after examples

| Before (v0.2) | After (v0.3) |
|---------------|--------------|
| `secretx://env/MY_VAR` | `secretx:env:MY_VAR` |
| `secretx://file/relative/path` | `secretx:file:relative/path` |
| `secretx://file//etc/secrets/key` | `secretx:file:/etc/secrets/key` |
| `secretx://aws-sm/prod/db-password` | `secretx:aws-sm:prod/db-password` |
| `secretx://aws-sm/prod/db-password?field=pw` | `secretx:aws-sm:prod/db-password?field=pw` |
| `secretx://aws-ssm/prod/db/password` | `secretx:aws-ssm:prod/db/password` |
| `secretx://aws-ssm//prod/db/password` | `secretx:aws-ssm:/prod/db/password` |
| `secretx://aws-kms/alias/my-key` | `secretx:aws-kms:alias/my-key` |
| `secretx://azure-kv/myvault/mysecret` | `secretx:azure-kv:myvault/mysecret` |
| `secretx://bitwarden/myproject/SIGNING_KEY` | `secretx:bitwarden:myproject/SIGNING_KEY` |
| `secretx://doppler/myproject/prd/SIGNING_KEY` | `secretx:doppler:myproject/prd/SIGNING_KEY` |
| `secretx://gcp-sm/my-project/my-secret` | `secretx:gcp-sm:my-project/my-secret` |
| `secretx://vault/secret/myapp` | `secretx:vault:secret/myapp` |
| `secretx://vault/secret/myapp?field=pw` | `secretx:vault:secret/myapp?field=pw` |
| `secretx://keyring/myapp/signing-key` | `secretx:keyring:myapp/signing-key` |
| `secretx://pkcs11/0/my-key` | `secretx:pkcs11:0/my-key` |
| `secretx://local-signing//tmp/key.der?algorithm=ed25519` | `secretx:local-signing:/tmp/key.der?algorithm=ed25519` |
| `secretx://wolfhsm/my-label` | `secretx:wolfhsm:my-label` |

### Helpful error on old URIs

If you pass an old-format URI at runtime, `SecretUri::parse` returns a clear error:

```
URI uses the old `secretx://backend/path` format; use `secretx:backend:path` instead (see MIGRATION.md): secretx://env/MY_VAR
```
