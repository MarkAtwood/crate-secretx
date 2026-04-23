# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **SYNC BEADS DATA**:
   ```bash
   git pull --rebase
   bd dolt push
   git status
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Report to user** - State what is staged/unstaged; ask for approval before committing or pushing
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- git commit and git push require explicit user approval — never run them without asking
- Stage changes and report what is ready; wait for the user to say "commit" or "push"
<!-- END BEADS INTEGRATION -->


## Build & Test

```bash
# Default features (file + env backends only)
cargo build
cargo test

# All features
cargo test --all-features

# Feature-powerset check (requires cargo-hack)
cargo hack check --feature-powerset --no-dev-deps

# Specific backend combos
cargo test --features aws-secrets-manager,cache
cargo test --features hashicorp-vault,signing

# Linting
cargo fmt --all
cargo clippy --all-features -- -D warnings

# Docs (nightly, with docsrs attributes)
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features

# MSRV check (see Cargo.toml rust-version)
cargo +<msrv> test --all-features
```

**Pre-commit gate** (run all before staging):
```bash
cargo fmt --all
typos src/
cargo clippy --all-features -- -D warnings
cargo hack check --feature-powerset --no-dev-deps
cargo test --all-features
```


## Architecture Overview

`secretsx` is a backend-agnostic secrets retrieval crate. The design invariant: **call sites never name a backend**. A URI in config selects the backend at runtime.

```
secretsx://<backend>/<path>[?field=<name>]
```

### Workspace layout

Cargo workspace. Each backend is its own crate — no `#[cfg(feature)]` guards anywhere except
the 15-line dispatch function in `secretx/src/lib.rs`.

```
secretx-core/       src/lib.rs  — SecretValue, SecretError, SecretStore, SigningBackend
secretx-cache/      src/lib.rs  — CachingStore<S: SecretStore>
secretx-aws-kms/    src/lib.rs  — secretx://aws-kms/<id>                (SigningBackend only)
secretx-aws-sm/     src/lib.rs  — secretx://aws-sm/<name>
secretx-aws-ssm/    src/lib.rs  — secretx://aws-ssm/<name>
secretx-azure-kv/   src/lib.rs  — secretx://azure-kv/<vault>/<secret>
secretx-bitwarden/  src/lib.rs  — secretx://bitwarden/<proj>/<name>
secretx-doppler/    src/lib.rs  — secretx://doppler/<proj>/<cfg>/<name>
secretx-env/        src/lib.rs  — secretx://env/<VAR>
secretx-file/       src/lib.rs  — secretx://file/<path>
secretx-gcp-sm/     src/lib.rs  — secretx://gcp-sm/<project>/<secret>
secretx-hashicorp-vault/ src/lib.rs — secretx://vault/<path>
secretx-keyring/    src/lib.rs  — secretx://keyring/<svc>/<acct>
secretx-pkcs11/     src/lib.rs  — secretx://pkcs11/<slot>/<label>       (also SigningBackend)
secretx-wolfhsm/    src/lib.rs  — secretx://wolfhsm/<label>             (also SigningBackend)
secretx/            src/lib.rs  — re-exports secretx-core + from_uri dispatch (feature-gated)
```

### Key types

- **`SecretValue`** — `Zeroizing<Vec<u8>>` wrapper. No `Debug`, `Display`, or `Clone`. Memory zeroed on drop.
- **`SecretError`** — `#[non_exhaustive]` enum: `NotFound`, `Backend`, `InvalidUri`, `DecodeFailed`, `Unavailable`.
- **`SecretStore`** — async trait: `get`, `put`, `refresh`, `from_uri`.
- **`SigningBackend`** — async trait for HSM-resident keys (AWS KMS, Azure KV HSM, local): `sign`, `public_key_der`, `algorithm`.
- **`CachingStore<S>`** — TTL-based in-memory wrapper over any `SecretStore`. Default TTL: 5 min for network backends, 0 for file/env.


## Conventions & Patterns

### SecretValue rules
- Never implement `Debug`, `Display`, `Clone`, `Serialize`, or `Deserialize` for `SecretValue`.
- Never copy inner bytes into a non-`Zeroizing` buffer inside any backend.
- Test assertions compare `actual.as_bytes()` against a `&[u8]` literal — never compare `SecretValue` directly.
- Test output must never print secret content. Use `assert_eq!(actual.as_bytes(), b"expected")`.

### URI parsing contract
- `from_uri` constructs the backend object and validates URI syntax only — no network call, no file read.
- `from_uri` for a backend whose feature flag is not compiled in must return `SecretError::InvalidUri` with a message naming the missing feature.

### Feature flag discipline
- Features are additive; `default = ["file", "env"]` only.
- `tokio` is only a dependency when the `cache` feature is enabled.
- `cargo hack check --feature-powerset` must pass before any PR.

### Error handling
- `SecretError::Unavailable` is a hard error — no silent fallback to empty string or default value.
- Log the secret name and backend name; never log secret bytes, even at `TRACE`.

### Crate names
`secretx` (umbrella) is published on crates.io. Backend crates are `secretx-core`,
`secretx-cache`, `secretx-aws-sm`, `secretx-aws-kms`, `secretx-aws-ssm`, `secretx-azure-kv`,
`secretx-bitwarden`, `secretx-doppler`, `secretx-env`, `secretx-file`, `secretx-gcp-sm`,
`secretx-hashicorp-vault`, `secretx-keyring`, `secretx-pkcs11`, `secretx-wolfhsm`.
The URI scheme `secretx://` matches the umbrella crate name.

### No git remote (local-only)
This repo has no git remote configured. `git push` is not possible. Use `bd dolt push` for beads sync.
