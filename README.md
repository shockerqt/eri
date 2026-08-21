# eri

Dedicated Rust source repository for the Auth service at `auth.shocker.cl`.

The name **eri** is inspired by the name of the creator's cat.

## Naming contract

- Repository, Cargo crate, binary, and systemd unit: `eri`
- Public hostname: `auth.shocker.cl`

## Commands

```sh
make dev
make test
make build
```

This repository currently contains only the Rust service bootstrap. OIDC and
OAuth implementation work belongs to the subsequent INF-008 implementation.
