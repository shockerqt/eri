# Foundation operations

Keep configuration and key files outside the repository. The service loads and
validates them once at startup. It never generates keys during requests and
publishes only RSA public parameters at `/jwks`.

## Create an operator key set

Generate at least 2048-bit RSA keys in a private directory. The following uses
3072 bits and creates an unencrypted PKCS#8 service key; protect the directory
and private file through host access controls:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out eri-2026-09-private.pem
openssl pkey -in eri-2026-09-private.pem -pubout \
  -out eri-2026-09-public.pem
chmod 600 eri-2026-09-private.pem
```

Copy `docs/keys.example.json` beside the keys and point the TOML signing
manifest at it. Every `kid` must be unique and stable. Exactly one active entry
has a private key. Previous and next entries are public-only. Eri rejects an
active public key that does not match its private key, malformed keys, RSA keys
under 2048 bits, duplicate or invalid key IDs, and (on Unix) private files with
group or other permissions. It also requires the private-key path to be a regular
file. Operators must restrict ownership and permissions on the containing key
directory; file-mode validation does not replace directory access controls.

## Rotate keys

1. Generate the next key pair offline and add only its public key under `next`.
2. Restart Eri to prepublish the next JWK.
3. After cache propagation, make that pair `active`, move the old active public
   key to `previous`, and restart Eri.
4. Keep the previous public key through the maximum token lifetime plus clock
   skew and JWKS cache overlap, then remove it and restart.

Manifest changes take effect only on restart. A compromised key requires a
separate emergency removal decision.

Token verification permits 30 seconds of clock skew when evaluating `exp`.
Resource servers should keep their clocks synchronized and use the same reviewed
skew rather than silently widening it.

## Health and startup

`/health/live` reports only process liveness. `/health/ready` runs a bounded
`SELECT 1` using the configured pool and returns 503 on failure without database
details. Startup loads keys, connects a bounded pool, applies embedded migrations,
binds the configured loopback socket, and shuts down gracefully on SIGINT or
SIGTERM. Database URLs and key material must never be passed as command arguments
or written to logs.

The foundation serves `/health/live`, `/health/ready`, and `/jwks` only. OIDC and
OAuth authorization-server discovery are added with their conforming metadata
only when the corresponding authorization and token capabilities exist.

Identity persistence is closed to Google for this stage. The two issuer values
documented by Google, `accounts.google.com` and `https://accounts.google.com`,
map to the stored canonical value `https://accounts.google.com`. Other issuer
strings and empty subjects are rejected; arbitrary issuer URLs are never
lowercased, trimmed, or otherwise normalized.
