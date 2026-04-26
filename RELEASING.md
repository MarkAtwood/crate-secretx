# Releasing secretx

This workspace publishes all crates together in a coordinated release. All crates
share the same `version` (set in `[workspace.package]`).

---

## 0.1.0 → 0.2.0 migration notes

`secretx` 0.1.0 was published as a single crate (`secretx`) with all traits and
types defined in one `lib.rs`. Starting with 0.2.0 the workspace splits into a
core crate (`secretx-core`) plus per-backend crates, with the `secretx` umbrella
re-exporting everything from `secretx-core` at the same public paths.

**Public API compatibility**: all types that existed in `secretx` 0.1.0 are
re-exported from `secretx` 0.2.0 at the same path:

| 0.1.0 path | 0.2.0 path | Status |
|------------|------------|--------|
| `secretx::SecretValue` | `secretx::SecretValue` (re-export) | ✓ compatible |
| `secretx::SecretError` | `secretx::SecretError` (re-export) | ✓ compatible |
| `secretx::SecretStore` | `secretx::SecretStore` (re-export) | ✓ compatible |
| `secretx::SigningBackend` | `secretx::SigningBackend` (re-export) | ✓ compatible |
| `secretx::SigningAlgorithm` | `secretx::SigningAlgorithm` (re-export) | ✓ compatible |
| `secretx::get_blocking` | `secretx::get_blocking` (re-export, feature `blocking`) | ✓ compatible |

Users who depended only on `secretx` (not the internal crates) and who compile
with the same feature set will see no breakage. A `cargo update` is sufficient.

**Yanking 0.1.0**: do **not** yank 0.1.0 automatically. Only yank if a security
issue or serious soundness bug is found in the old version.

---

## Publish order

Path dependencies within the workspace must be resolved in the following order.
A crate cannot be published until all of its non-optional dependencies are
already on crates.io.

```
1. secretx-core
2. secretx-cache          (depends on secretx-core)
3. [all backend crates]   (each depends on secretx-core; publish in any order or in parallel)
   secretx-aws-kms
   secretx-aws-sm
   secretx-aws-ssm
   secretx-azure-kv
   secretx-bitwarden
   secretx-doppler
   secretx-env
   secretx-file
   secretx-gcp-sm
   secretx-hashicorp-vault
   secretx-keyring
   secretx-local-signing
   secretx-pkcs11
   secretx-wolfhsm
4. secretx                (depends on all of the above)
```

---

## Release procedure

### 0. Pre-flight checks

Run all of the following before bumping the version. Do not proceed to step 1
until every check passes.

```bash
cargo fmt --all -- --check
cargo clippy --all-features --workspace -- -D warnings
cargo test --workspace --all-features
cargo audit                          # install once: cargo install cargo-audit
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features --workspace
cargo hack check --feature-powerset --no-dev-deps -p secretx
```

If `cargo audit` reports any advisories, resolve them before publishing — do
not publish a release with known vulnerabilities.

### 1. Bump version

Edit `Cargo.toml` (workspace root) `[workspace.package]` `version`:

```toml
[workspace.package]
version = "0.2.0"
```

Run `cargo check --workspace` to make sure the lock file regenerates cleanly.
Commit: `chore: bump version to 0.2.0`.

### 2. Dry-run in publish order

Run for each crate in publish order:

```bash
cargo publish --dry-run -p secretx-core
cargo publish --dry-run -p secretx-cache
cargo publish --dry-run -p secretx-aws-kms
# ... all backend crates ...
cargo publish --dry-run -p secretx
```

Fix any packaging issues (missing `include`, wrong `readme` path, etc.).

### 3. Publish

```bash
cargo publish -p secretx-core
# wait ~30 s for crates.io index to update
cargo publish -p secretx-cache
# wait ~30 s
cargo publish -p secretx-aws-kms
cargo publish -p secretx-aws-sm
# ... remaining backends (can be done back-to-back with ~30 s between each) ...
# wait for all backends to appear in the index
cargo publish -p secretx
```

If a publish step fails mid-sequence, you have two choices depending on how
far the sequence got:

- **No crates published yet**: fix and retry from step 3.
- **Some crates already published**: you cannot un-publish them. Fix the
  problem, do another dry-run on the affected crate and all that follow it,
  then resume from the failed crate. If the fix requires a source change,
  bump the patch version (e.g. `0.2.0` → `0.2.1`), bump all crates together,
  and publish a new release. Only yank the incomplete release if it is broken
  enough to cause harm to users who already picked it up.

### 4. Tag

```bash
git tag v0.2.0
```

This repository has no configured git remote — `git push` is not available.
Create the GitHub release manually from the tag, or push the tag from
a machine that has the remote configured:

```bash
git push origin v0.2.0
```

Create a GitHub release from the tag with the changelog.

---

## Version bump policy

- **Patch** (0.x.Y): bug fixes, documentation changes, no API change.
- **Minor** (0.X.0): new backends, new optional methods, additive features.
- **Major** (X.0.0): breaking changes to `SecretStore`, `SecretValue`, or `SecretError`.

All crates in the workspace are bumped together — they share a single version.

### Conventional commit discipline for breaking changes

Any commit that removes or incompatibly changes a public item **must** use the
breaking-change marker in the conventional commit subject:

```
fix!: remove with_max_entries from CachingStore
feat!: cache_key parameter removed from SecretStore methods
```

Or use a `BREAKING CHANGE:` footer on a multi-line commit message. Using plain
`fix:` or `feat:` for a breaking commit gives no signal to tooling
(release-please, changelog generators, dependabot) that a version bump is
required. This applies even on 0.x crates — `fix!:` still correctly signals
that a minor version bump is needed under 0.x semver.
