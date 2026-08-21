# eri

`eri` is the dedicated Rust Auth service source repository. Its public hostname
is `auth.shocker.cl`; do not rename the hostname to match the service.

Before working here, read the workspace Governance `AGENTS.md` and `STACK.md`,
then use the INF-008 task branch and worktree.

## Standard commands

- `make dev`
- `make test`
- `make build`

Run `cargo fmt` and `cargo clippy -- -D warnings` before committing. The local
pre-commit hook formats Rust files automatically.
