# Foundation operations

## Provider activation

The OAuth/OIDC HTTP surface is enabled only when `[authorization]` includes a
Google declaration and reviewed first-party clients. The environment variable
named by `client_secret_env` must resolve to a nonempty value at startup. Without
that section Eri serves health and JWKS only and withholds discovery.

Local `/logout` uses a confirmed session and CSRF challenge with an exact
registered post-logout destination. It is not advertised as an OIDC
`end_session_endpoint` until ID-token hint conformance is implemented.

## Persistence cleanup

Run cleanup only after taking a database backup and in bounded batches. Delete
expired `browser_authorizations` and consumed or expired `logout_challenges`
first. Delete expired `refresh_families` next; their members cascade only after
the family can no longer be renewed, preserving refresh replay detection for the
whole family lifetime. Delete expired authorization codes only after any linked
refresh family is gone, then delete expired provider sessions. Never delete
individual consumed refresh members from a live family or authorization codes
still referenced by `refresh_families`. PostgreSQL foreign keys enforce the
remaining source-code/session relationships; monitor expiry indexes and table
sizes before and after each batch.

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

## Browser flow regression

The ignored browser regression starts Eri, a signed synthetic Google upstream,
and a separate callback origin on ephemeral loopback listeners. It uses Chromium
to submit the real consent and logout forms at a narrow viewport and verifies
that their bound cross-origin redirects complete without CSP violations. Supply
an installed Playwright module and browser/runtime paths explicitly:

```sh
ERI_PLAYWRIGHT_MODULE=/path/to/node_modules/playwright \
PLAYWRIGHT_BROWSERS_PATH=/path/to/playwright-browsers \
LD_LIBRARY_PATH=/path/to/chromium-runtime-libs \
DATABASE_URL=postgres://user:password@loopback/isolated_test_database \
ERI_TEST_DATABASE_URL=postgres://user:password@loopback/isolated_test_database \
cargo test --locked \
  web::tests::chromium_follows_bound_consent_and_logout_redirects \
  -- --ignored --nocapture
```

The test has a 60-second child-process timeout. It uses only synthetic identities
and credentials and does not establish real Google, mobile, or MCP acceptance.
Optionally set `ERI_BROWSER_ARTIFACT_DIR` to save consent and logout screenshots
from this synthetic fixture. The browser also checks POST origins and referrers
on form, stylesheet, and client callback requests.
Consent and logout form documents use `Referrer-Policy: strict-origin`: Chromium
therefore supplies the same-origin `Origin` needed by the CSRF check while any
subsequent client navigation receives at most Eri's origin, never the callback,
state, code, or CSRF query. Other sensitive responses retain `no-referrer`. This
behavior follows the Fetch request-Origin algorithm and the Referrer Policy
`strict-origin` definition:

- <https://fetch.spec.whatwg.org/#append-a-request-origin-header>
- <https://w3c.github.io/webappsec-referrer-policy/#referrer-policy-strict-origin>
