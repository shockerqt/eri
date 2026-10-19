# Generic MCP client metadata

Owned by INF-008/Eri. CIMD is disabled when `authorization.cimd` is absent.
First-party declarations keep precedence, including a first-party ID that is an
HTTPS URL. Enabling CIMD requires an explicit reviewed local policy:

```toml
[authorization.cimd]
scopes = ["openid", "offline_access"]
resources = ["https://api.example/mcp"]
allow_refresh = true
```

There is no generic default resource. Generic authorization must select an
explicit resource in this local allowlist; remote metadata cannot authorize a
scope, resource, browser origin, post-logout redirect or custom app scheme.
`allow_refresh` defaults to false. Refresh additionally requires the document's
`refresh_token` grant and explicit consent for `offline_access`. The existing
provider SSO cookie never skips consent for CIMD; `prompt=none` cannot approve a
generic grant. Static clients can separately opt into operator preauthorization.

A public client uses an HTTPS metadata URL as its exact `client_id`. For example:

```json
{
  "client_id": "https://client.example.org/metadata.json",
  "client_name": "Declared public client",
  "redirect_uris": ["https://client.example.org/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

The fetcher requires public DNS destinations, pinned validated addresses and TLS
for the original host, no proxy/redirect, a five-second total timeout, at most
eight concurrent fetches and a 5KiB document. Metadata extras are inert; secrets
and remote key declarations are rejected. HTTPS callbacks and literal native
HTTP loopback-IP callbacks are supported. Native authorization may vary only the
declared loopback port; exchange must match the actual authorized URI exactly,
including port, path and query. All clients require S256 PKCE.

The consent UI shows the escaped metadata URL and labels the display name as
declared. Metadata URL possession establishes a declaration, not public-client
authentication or first-party trust. Generic token/UserInfo/revoke CORS remains
denied; a backend/native client can use the standard endpoints without Origin.
Revocation does not fetch metadata, so renewable credentials can be revoked during
a metadata outage. Generic clients use local confirmed logout without introducing
remote post-logout redirects.

Browser transactions, codes and refresh families persist one versioned JSONB
security binding in their existing tables. It includes the exact client URL, full
sorted registered redirect set and redirect kinds, and effective refresh
permission. Any redirect addition/removal or effective refresh permission change
requires new authorization, even when the current callback remains listed.
Cosmetic display-name changes and redirect ordering do not invalidate grants.
Current local scope/resource policy is still revalidated. NULL records remain
first-party and cannot be reinterpreted as dynamic, or the reverse; a dynamic
client later added as first-party must reauthorize.

Cache entries retain their original monotonic freshness deadline, at most five
minutes and reduced by HTTP Age. Expired cache fetch failures have no stale
fallback. Non-cacheable documents receive a five-second operation lease from
validation completion and are never cached. Same-client concurrent cache misses
fail promptly with Busy while one fetch is active; this bounded availability
tradeoff prevents older responses overwriting newer metadata. Cancellation releases
the reservation. Metadata resolution happens outside database transactions.
After lock waits and before mutation/commit, expiry completes rollback and allows
at most one fresh resolution outside locks. A repeated expiry or fetch failure
fails closed without consuming credentials. This bounds local snapshot freshness;
it does not make remote metadata changes atomic with a local commit.

Discovery advertises `client_id_metadata_document_supported` only when this
optional policy is enabled. DCR and `registration_endpoint` are not implemented.
Synthetic tests exercise generic resource discovery through signed Google fixtures,
consent, code exchange, JWKS verification, refresh/replay and logout, plus metadata
changes, outages, lock waits and binding persistence. They do not establish real
Google, Balance or Spark acceptance. Runtime activation belongs to Infrastructure;
Spark remains a separate deferred pre-retirement gate.
