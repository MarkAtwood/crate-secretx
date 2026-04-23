# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data (no git remote on this repo)
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode,
causing the agent to hang indefinitely waiting for y/n input.

```bash
cp -f source dest       # NOT: cp source dest
mv -f source dest       # NOT: mv source dest
rm -f file              # NOT: rm file
rm -rf directory        # NOT: rm -r directory
```

Other commands that may prompt:
- `scp` — use `-o BatchMode=yes`
- `ssh` — use `-o BatchMode=yes`
- `apt-get` — use `-y`

## Rust / Cargo Notes

- `cargo fmt --all` must be clean before any commit.
- `cargo clippy --all-features -- -D warnings` must pass.
- `cargo hack check --feature-powerset --no-dev-deps` must pass (installs via `cargo install cargo-hack`).
- Features are additive; default is `file` + `env` only. Do not add `tokio` to the default feature set.
- Docs build: `RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features`
- Spell-check: `typos src/` (installs via `cargo install typos-cli`). Spaced hex bytes in comments trigger false positives — rewrite as `0xdeadbeef` (one token, no spaces).

## Security Constraints (enforced in code, not just convention)

- `SecretValue` must not implement `Debug`, `Display`, `Clone`, `Serialize`, or `Deserialize`.
- Never copy secret bytes into a non-`Zeroizing` buffer.
- `from_uri` must not make any network call or file read — construction only.
- Backends not compiled in must return `SecretError::InvalidUri` (naming the missing feature), not panic.
- Tests must compare `actual.as_bytes()` against `&[u8]` literals. Never print `SecretValue` in test output.

## No Git Remote

This repository has no git remote. `git push` will fail. Do not attempt it.
Use `bd dolt push` to sync beads issue data across sessions.

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
   bd dolt push
   git status
   ```
5. **Report to user** - State what is staged/unstaged; ask for approval before committing
6. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- git commit requires explicit user approval — never run it without asking
- git push is NOT possible (no remote) — do not attempt it
- Stage changes and report what is ready; wait for the user to say "commit"
<!-- END BEADS INTEGRATION -->
