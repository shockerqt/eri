# eri

Eri is the dedicated Rust Auth service for `auth.shocker.cl`.

The name **eri** is inspired by the name of the creator's cat.

This delivery provides the executable foundation plus internal OAuth policy and
PostgreSQL credential/session lifecycle libraries. The library validates explicit
public clients, exact redirect/resource/scope bindings and S256 PKCE, then supports
one-time authorization codes, strict refresh rotation/replay revocation, token
revocation and provider-session logout. Credentials are opaque and stored only as
SHA-256 hashes.

It also includes a Google upstream library with fixed production endpoints,
bounded code exchange and JWKS fetching, cached RSA verification keys, and a
verified identity type. Only that verified type can cross the database boundary
into an authenticated Eri user. The adapter is not connected to an HTTP callback
in this delivery, and local tests use synthetic signed identities rather than
live Google credentials.

Persistent browser authorization transactions now retain validated downstream
requests across process restarts, bind Google callbacks to hashed state and
browser secrets, and issue authorization codes only after session-bound consent
and current client-policy checks. Verified Google logins replace a persisted
profile snapshot and retain optional upstream authentication-time provenance.
First-party client configuration includes distinct callback, browser-origin,
resource, scope, and post-logout redirect allowlists.

When authorization configuration is present, Eri exposes discovery,
authorization and Google callback, server-rendered consent, token and revocation,
UserInfo, and confirmed local logout. Foundation-only configuration continues to
expose health and JWKS and withholds provider discovery. RP-Initiated Logout hint
conformance remains deferred, so metadata withholds `end_session_endpoint` and
`/logout` rejects `id_token_hint`. CIMD/DCR remains deferred. Synthetic tests do
not replace real Google and application compatibility checks in staging.

Expired authorization codes may be removed after their expiry once any linked
refresh family has also expired. Provider sessions, refresh families and retained
refresh-token members may be removed after the family/session absolute expiry.
Expiry indexes support a future bounded cleanup job; this package does not run one.

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
