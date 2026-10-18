# Provider logout evidence

`scripts/provider-logout-proof.sql` checks the provider database lifecycle for
one BAL-033 diagnostic operation. The input is a public 32-character lowercase
hexadecimal operation reference, never a token, cookie, URL, or secret. The query
returns one JSON object containing only booleans and counts.

Run the query against the reviewed staging database **after** the client has
attempted to refresh family B following logout. Use an already approved, read-only
`psql` connection with credentials supplied by the operator's normal private
connection method. For example, within that connection:

```psql
\set operation_id 0123456789abcdef0123456789abcdef
\i scripts/provider-logout-proof.sql
```

The query starts a read-only transaction and rolls it back. Its reference filter
must match exactly two authorization codes, one A family, one B family, and one
consumed logout challenge. It checks the first-party client, resource and logout
callback, binds both families and the challenge to the same provider session,
requires a prior rotation member in each family, and checks that B and the
session were revoked at the challenge consumption time. A must have been revoked
earlier. B and the session must still be unexpired when the query captures database
time, so expiry cannot explain the later B refresh rejection.

Keep the client result and provider result as separate evidence. A client refresh
that is accepted after logout is a failure even if client cleanup then fails. A
client `invalid_grant` response remains unconfirmed until it is paired with a
complete provider result for the same operation. The SQL establishes that A was
revoked before logout, but cannot establish what caused A's revocation; pair it
with the client SDK `revokeAsync` result. It also cannot prove the HTTP response,
Google identity flow, or live end-to-end acceptance by itself. Missing or pruned
rows, an invalid reference, mismatched cardinality, or an expired B/session yield
an incomplete result; do not interpret that as successful logout.

`make test-provider-proof` runs 18 synthetic cases against a fresh local
PostgreSQL 17 cluster on a private Unix socket and removes it afterward. The
fixture uses only temporary tables in each connection. CI supplies its existing
PostgreSQL 17 service container ID through `ERI_PROVIDER_PROOF_CONTAINER`; the
runner accepts only a 12–64 character lowercase hexadecimal container ID and
executes a fixed `docker exec ... psql` argument list. For a nonstandard local
PostgreSQL installation, pass `--postgres-bin /path/to/postgresql/17/bin` to the
Python runner. These minimal fixtures test the query's decision rules, not the
full provider schema constraints or endpoint acceptance.
