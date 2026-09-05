# Eri authorization server design

Status: initial design critiqued and coordinator dispositions applied. Owned by INF-008,
run INF-008-20260905-075417-implement-authorization-server in Governance.

## Boundary and delivery

Eri is a standalone Axum/Tokio service backed by PostgreSQL through SQLx. It
owns OAuth/OIDC authorization, Google federation and provider sessions. Balance
owns protected-resource metadata, application data, API authorization and
WebSocket transport. Staging uses a separate reviewed issuer/environment and
test data; the production Keycloak route remains unchanged during this goal.

Implement in serial deliveries: executable foundation; credential lifecycle;
Google adapter; browser/code flow; MCP interoperability; measured staging/handoff. Each
delivery includes meaningful tests and CI. No successful mock flow will be
reported as a real Google or MCP-client login.

## Configuration and signing

Use a typed file configuration plus narrowly named environment variables for
database credentials and Google client secret. Never print secret-bearing
configuration, bearer tokens, request bodies, cookies or query strings in logs.
Issuer is an explicit absolute HTTPS URL without credentials, query or fragment,
not reconstructed from Host or forwarded headers. A separately explicit local
development mode permits loopback HTTP only. Bind only to loopback; exposure is
an Infrastructure decision. Require configured port rather than silently choosing
an unreviewed staging port. Bound request bodies and DB connections.

Load a reviewed key manifest at startup: exactly one active RSA signing key,
stable unique kid, and public-only previous/next verification keys. Private PEM
files are outside Git, owned by the service with restricted permissions. Use
established RSA/JWT library primitives, RS256 only and RSA >= 2048 bits. Reject
duplicate kid, malformed keys, mismatched public/private material and missing
active key. Cache public JWKS bytes and parsed crypto keys in memory; no per-request
key reads or generation. Persist keys outside the process so restarts preserve kid.

Rotation is an explicit operator action: prepublish the next public key, activate
its private key through the reviewed manifest and restart, retain previous public
keys for at least the maximum issued token lifetime plus clock skew/cache overlap,
then retire. Emergency compromise removal is a separate operational action. No
public key-management endpoint or private key in PostgreSQL. Tests exercise old/new
keys and restart reload, not merely random key generation.

## Endpoint and token contract

| Endpoint | Behavior |
| --- | --- |
| GET /health/live | Process liveness; no secret or environment details. |
| GET /health/ready | Bounded database readiness; generic unavailable response on failure. |
| GET /.well-known/openid-configuration | OIDC issuer and implemented endpoint/feature metadata. |
| GET /.well-known/oauth-authorization-server | OAuth metadata including S256 and issuer-response support. |
| GET /jwks | Only public RSA verification keys; bounded cache lifetime. |
| GET /authorize, POST /authorize | Validate client/redirect/scope/resource/PKCE, then interactive login/consent. |
| GET /federation/google/callback | Consume browser-bound Google transaction, verify upstream identity. |
| POST /consent | CSRF-protected approval/denial for a validated authorization transaction. |
| POST /token | Authorization-code exchange or one-time refresh. |
| POST /revoke | Revoke renewable grant; unknown tokens are indistinguishable. |
| GET /userinfo, POST /userinfo | Valid OIDC access token and scope; expose only granted profile claims. |
| GET /logout, POST /logout | Confirmation then CSRF-protected SSO/grant invalidation; exact reviewed redirect only. |

Unsupported features are not advertised. Sensitive responses are no-store, use
Referrer-Policy: no-referrer, clickjacking protection and restrictive CSP; UI
escapes all client/user strings. Public metadata/JWKS may support credential-free
CORS; token/revoke/userinfo CORS uses reviewed browser origins. Authorization,
consent and logout are browser navigations/forms, not permissive CORS APIs.

JWT access tokens: typ=at+jwt, iss, UUID sub, aud, exp, iat, jti, client_id and
space-separated scope; default lifetime 5 minutes. Allow one client-selected
resource per grant. For an openid grant, also include the explicit configured
Eri UserInfo endpoint audience so the same access token can retrieve identity
claims. UserInfo validates that audience and openid, not arbitrary resource tokens.
ID tokens are distinct JWTs addressed to client_id,
issued only for openid, with nonce when requested and auth_time only when verified
upstream evidence exists; never accepted
as API access tokens. Profile/email claims follow scope and verified upstream
data. Resource audience and ID-token audience are not interchangeable.

## Identity, client and authorization policy

Users have internal UUIDs. External identities are unique by canonical upstream
issuer plus subject; never automatically link accounts by email. Google subject
and verified identity claims establish the account, not a user-supplied profile.
Any mapping from existing Keycloak users to Eri identities needs separate reviewed
evidence; staging uses isolated test identities/data and does not rewrite users.

First-party clients are explicit public declarations: exact redirect strings,
allowed scopes, allowed resources, optional default resource and reviewed browser
origins. No embedded client secrets. Require response_type=code and S256 PKCE;
reject duplicate singleton parameters and malformed/oversized values. No implicit
or password grants. Validate client and exact redirect before redirecting any
error; invalid/untrusted redirects produce a local error. Authorization responses
carry the configured iss and original state. Reject redirect fragments/userinfo.
Custom app schemes require explicit first-party registration. Generic CIMD clients
may declare HTTPS or native HTTP loopback-IP redirects. The sole matching exception
is the port of an explicitly native loopback-IP redirect (127.0.0.1 or [::1]): all
other bytes, including path and query, must match. Bind the actual requested URI
into the code; token exchange must match it exactly, including its port. No generic
host wildcards, DNS-name loopback exceptions or silent URI normalization.

Requested scope and resource must be within client and server policy. Bind the
selected resource, scopes, client_id, exact redirect and challenge into the stored
authorization grant. Token requests must preserve that binding; refresh cannot
expand it. Explicitly reject unsupported multiple-resource requests rather than
silently choosing one. OIDC-only userinfo uses only the Eri UserInfo audience;
combined grants include it alongside the authorized resource audience.
Requesting offline_access requires explicit consent before refresh
issuance. Generic MCP clients always require user consent showing verified client
identity, scope and resource; an SSO cookie alone does not imply authorization.

## Browser federation and session persistence

Use separate high-entropy upstream state, upstream nonce, PKCE verifier and browser
binding cookie for the Google authorization transaction. Persist a hashed browser
binding and state with the validated downstream request, expiry and one-time
consumption. The upstream callback requires both state and the matching browser;
it cannot be replayed or supplied with an arbitrary downstream redirect. Google
HTTP requests use fixed trusted endpoints, TLS, bounded responses and timeouts.
Offline tests inject an upstream adapter through the library test construction
path; the production binary has no alternate-provider or test-login bypass switch.
Validate the upstream ID-token signature, allowed issuer, audience/azp, expiry,
nonce and required identity claims. Do not persist Google tokens after identity
verification. Failed callbacks do not establish an Eri session.

Use opaque random provider-session cookies, HttpOnly, Secure, SameSite=Lax,
host-only Path=/ (__Host- prefix in HTTPS mode); rotate at authentication and
store hashes server-side. Consent/logout use separate CSRF tokens bound to the
session and transaction and validate Origin when supplied. Never trust forwarded
headers to relax cookie/security policy. The provider session has a bounded
absolute lifetime (initial proposal: 30 days); refresh does not silently extend it
forever. Keep local session creation time separate from verified upstream auth_time.
Follow docs/browser-flow-plan.md for prompt=none/consent and conservative handling
of prompt=login/max_age when Google's verified reauthentication evidence is absent.

Authorization codes are 256-bit opaque random values, stored only as hashes,
expire within 60 seconds, and are consumed atomically after all bindings/PKCE
checks. Successful exchange creates the renewable grant and token response in
one committed DB transaction. Do not return credentials from rolled-back state.

Refresh tokens are opaque 256-bit random values, hashed at rest and bound to a
grant family, user, client, scopes, resource and absolute expiry (30 days maximum).
Track every consumed member until family expiry. Rotation locks the family row,
checks session/grant state, consumes one token and inserts its successor atomically.
Every path takes locks in session-then-family-then-token order. Reuse of a consumed
token after proving its original client/resource bindings revokes the family in a transaction that commits even though the HTTP result
is invalid_grant. Concurrent refresh has one winner; the losing replay revokes
the family, so the winner's new refresh cannot be used afterward. No grace window:
clients serialize refresh and must reauthorize after an ambiguous/lost response.
This is an explicit availability tradeoff preserving replay detection; PKCE does
not prove the sender of a refresh retry and cannot justify returning the successor.

Logout revokes the current provider session and its renewable grants and clears
cookies. Revocation of a refresh family does not need per-request access-token
introspection. Already-issued access tokens expire naturally within their short
lifetime. Bound persistence growth with expiry indexes and documented cleanup.

## Generic MCP client metadata

Implement CIMD against MCP authorization 2026-07-28 and its referenced CIMD draft.
Recheck the pinned contract when implementing the compatibility package.
Bind client_id to the fetched document's identity and
exact redirect declarations; treat metadata as untrusted. Support HTTPS only,
no credentials/fragment, deny private/loopback/link-local/reserved destinations,
DNS-rebinding-safe address pinning, no redirects/proxies, short timeout and bounded
response size/cache. Do not fetch arbitrary URLs from metadata or resource values.
No remote metadata can grant server scopes/resources or first-party trust.
Preserve validated metadata bindings through authorization/token exchange and
revalidate policy before issuing renewable credentials. Add DCR only when a real
target client demonstrates it is needed and its bounded policy is reviewed.

## Verification and operations

Pure tests cover config, exact redirects, PKCE, claim/type/audience/issuer checks,
keys and expiry. PostgreSQL tests cover unique identities, transaction consumption,
restart persistence, code replay, refresh concurrency/reuse, logout and revocation.
A headless client exercises discovery through logout using an explicitly injected
test identity provider (never a production login bypass). Real Google and real
MCP-client smoke tests are separate staging acceptance evidence.

CI runs fmt/clippy with warnings denied, tests with an isolated PostgreSQL service
and release build against the exact PR SHA; publish versioned artifacts for later
reviewed delivery. Staging uses isolated credentials/database, systemd, reviewed
HTTPS ingress, healthchecks and rollback. Measure release RSS and server-side
discovery/JWT-verification p95; preserve the workload and raw numeric aggregates
needed to reproduce results without retaining credentials or user data.

## Primary references checked

- OAuth security BCP: https://www.rfc-editor.org/rfc/rfc9700.html
- OIDC Core: https://openid.net/specs/openid-connect-core-1_0.html
- Google identity validation: https://developers.google.com/identity/openid-connect/openid-connect
- MCP authorization version to verify before the compatibility package:
  https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
