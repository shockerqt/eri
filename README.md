# eri

Eri is the dedicated Rust Auth service for `auth.shocker.cl`.

The name **eri** is inspired by the name of the creator's cat.

This delivery is an executable foundation, not a complete authorization server.
It provides typed startup configuration, Google identity persistence,
liveness/readiness, and public JWKS. It does not expose OIDC or authorization
server discovery because conforming metadata would require capabilities this
stage does not implement. Authorization, token, login, federation, refresh,
revocation, UserInfo, and logout remain unavailable. `docs/design.md` describes
the planned server, not the current endpoint surface. Do not route OAuth clients
or production traffic to this stage.

## Run locally

Copy `docs/config.example.toml` to an ignored path such as `config/eri.toml`,
create a key manifest as described in `docs/operations.md`, and provide the
database URL without committing it:

```sh
export ERI_DATABASE_URL='postgres://eri:password@127.0.0.1:5432/eri'
make dev CONFIG=config/eri.toml
```

The binary requires `--config PATH` or `ERI_CONFIG=PATH`; there is no implicit
configuration path, issuer, port, or bind address. Production requires an HTTPS
issuer. Development HTTP is accepted only for a literal loopback IP, and the
issuer currently requires the origin root path. The listener always requires an
explicit loopback socket address and nonzero port.

## Verify

```sh
make lint
make test
make build
```

PostgreSQL-backed tests are mandatory and fail when `DATABASE_URL` cannot create
isolated test databases. In the INF-008 worktree, run commands through the
task-owned launcher, for example `/tmp/eri-inf008-tests/run make test`; the
launcher supplies only isolated test database credentials.

CI runs the full check on GitHub's native Ubuntu 24.04 ARM runner and packages
the deployable `aarch64-unknown-linux-gnu` release binary with its exact source
SHA, Rust target identity, and SHA-256 checksum. It does not deploy the artifact.
