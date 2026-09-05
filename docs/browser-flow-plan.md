# Google and browser flow implementation plan

INF-008, implementation run 20260905-075417. Proposed next deliveries; this is
not evidence that the endpoints or a real Google login currently work.

## Delivery boundaries

1. Implement the Google upstream adapter and verified identity boundary, with
   fixed production endpoints, bounded HTTP/JWKS caching and independent signed
   fixtures. No HTTP callback or session can authenticate from raw profile input.
2. Implement persistent browser transactions, first-party client configuration,
   authorization/callback/consent, distinct token responses and UserInfo. Preserve
   published migrations and credential locking/replay behavior.
3. Finish logout, metadata/CORS, browser and negative/concurrent HTTP tests; then
   separately implement bounded CIMD and real-client compatibility.

Each package gets settled-diff review, coordinator checks and exact-SHA CI. Only
one writer uses the Eri worktree. Google mocks establish local behavior, while
real Google/mobile/MCP and performance measurements remain staging gates.

## Upstream adapter

Production URLs are fixed: accounts.google.com/o/oauth2/v2/auth,
oauth2.googleapis.com/token, and www.googleapis.com/oauth2/v3/certs, all HTTPS.
There is no runtime endpoint override, proxy inheritance, redirect following,
test-user flag or arbitrary URL derived from token headers. Use an established
HTTP and JWT library with TLS verification, 5-second total requests, 2-second
connect timeout, bounded concurrency, at most 64 KiB token responses and 256 KiB
JWKS. Cache parsed RS256 keys for a bounded freshness period respecting shorter
upstream max-age. Serialize refresh; throttle unknown-kid refreshes to prevent
unbounded fetches, and fail closed after cached keys expire. Do not negatively
cache a key forever after a fetch failure. Reject duplicate kid and malformed or
non-signing RSA keys; require at least 2048-bit RSA.

Exchange a code using configured Google web client ID and a secret resolved from
an explicit environment-variable name; redirect URI comes from configured Eri
issuer plus the fixed callback path. Send the browser transaction's upstream
PKCE verifier. Do not retain or log Google's access/refresh/ID tokens. Sanitize
network, JSON and validation errors and redact any secret-bearing Debug output.

Verify signature/RS256/kid, the two documented Google issuers, configured client
audience, azp when present (required for multiple audiences), exp/iat with a
30-second skew, nonempty subject and exact transaction nonce. Reject unsupported
critical JWT headers; never use jku/x5u as fetch targets. A privately constructed
VerifiedGoogleIdentity carries subject and optional scope-safe profile/email
claims. Missing or false email_verified never establishes a verified email.
Identity creation is by canonical issuer/subject, never email. Only accepting
this verified type may create an AuthenticatedUser for session issuance.

Tests inject transport and keys through private library/unit-test construction,
not a production configuration switch. Test real HTTP response bounds, redirects,
timeouts, cache refresh/coalescing and malformed responses; signed fixtures test
wrong key/algorithm/issuer/audience/azp/nonce, expiry, future iat and missing claims.

## Browser state and consent

Parse bounded GET query or POST form parameters and reject duplicate singletons,
multiple resources and unsupported response types. Validate client and raw exact
redirect before any redirect response. Persist the validated request (including
downstream state and nonce) independently of upstream state, nonce and verifier.
Use a 10-minute transaction, random opaque browser binding and hashed
state/binding at rest. Give each transaction a distinct cookie name derived from
its state hash, with a maximum of four pending transaction cookies per browser;
reject excess starts with a local retry/cancel instruction. Never overwrite
another transaction's binding. The temporary upstream verifier must be recoverable for
code exchange; erase it on consume and expire abandoned records. Consume a
callback only after matching both state and browser binding, before contacting
Google. Use separate states: awaiting_google -> callback_claimed -> awaiting_consent
-> approved/denied, with failed/expired terminal paths. Consuming upstream state
does not consume downstream consent. A failed or replayed callback cannot create
a provider session. Clear the transaction cookie after callback consumption.

Rotate provider cookies at authentication: Secure, HttpOnly, SameSite=Lax,
host-only, Path=/ and __Host- prefix for HTTPS. Configured development loopback
HTTP has a different explicit cookie name. Host/forwarded headers never decide
security settings. Support multiple browser transactions without sharing a
single mutable downstream request. Persist verified profiles in a user_profiles
table keyed by internal user UUID, so UserInfo can resolve them from token sub.
Replace the snapshot on verified login, clearing withheld optional claims. Expose
only authorized claims. Distinguish local session creation time from optional
verified upstream auth_time, which must never be fabricated from iat or now.

Always display consent for a new grant in this first implementation. Do not yet
persist remembered approvals. Thus prompt=none returns login_required if no
eligible session and consent_required otherwise; it never renders UI. consent
forces consent. Google's documented prompts are none/consent/select_account;
select_account does not prove reauthentication and max_age is not documented.
Its optional auth_time requires a claims request and Google configuration support.
For now prompt=login returns login_required because verified fresh upstream
authentication cannot be guaranteed. max_age may succeed only with a verified
upstream auth_time meeting the bound; missing/stale evidence returns login_required.
Request auth_time from Google when configured and validate it if returned. Do not
advertise stronger reauthentication guarantees. Unsupported prompt combinations
fail locally or through an already verified redirect as appropriate.

Consent is an explicit CSRF-protected POST. A separate random CSRF token is
hashed and bound to transaction and authenticated session; verify Origin when
present. Pending-request validation must not grant offline_access. Derive final
offline consent exclusively from the stored approved request, never from a query
boolean. Denial consumes the transaction and returns access_denied with original
state and configured iss. Approval issues a 60-second code once under consistent
transaction/session locks. Avoid holding DB locks during upstream network calls.

## Tokens, logout and surface

Keep the existing session -> family -> member lock order and binding-first
replay policy. Add immutable nonce/auth_time provenance to code exchanges with
an additive migration. auth_time is included only when upstream evidence exists;
never substitute local session creation time. Sign access JWTs with typ at+jwt, resource audience and
explicit UserInfo audience for openid. ID JWTs use typ JWT, client audience,
auth_time and requested nonce; issue only for openid. UserInfo accepts access
tokens with its audience and openid, filters profile/email claims by scopes,
and cannot accept an ID token. OIDC-only grants default to UserInfo resource;
the server derives and explicitly allows this internal resource from its configured
issuer when openid is granted, including clients without a resource default.
Refresh preserves grants and cannot expand scope/resource. Token signing failure
after committed consumption requires reauthorization; never return an uncommitted
refresh token or undo replay evidence to make retry appear successful.

Logout GET confirms; POST requires session-bound CSRF, revokes the session and
all its refresh families, then clears cookies. Only exact registered post-logout
redirects from a separate post_logout_redirects client declaration are allowed;
authorization callback registration alone is insufficient. Existing access JWTs expire within five minutes. Revoke
remains client-bound and indistinguishable for unknown credentials.

Metadata advertises only implemented capabilities. Authorization and UserInfo
support GET/POST. Sensitive responses use no-store, no-referrer, frame protection
and restrictive CSP. Client/user strings are escaped. Browser-origin CORS for
token/revoke/UserInfo is explicit; navigations/consent/logout have no wildcard
credentialed CORS. Public discovery/JWKS may use credential-free wildcard CORS.

## Small authentication interface

Subject: Eri granting access to a named application; audience: Balance and MCP
users; one job: understand the requested access and approve or cancel it. Use a
single narrow, responsive column with a prominent application name and a compact
permission list. The signature element is a quiet connection line from the
signed-in account to the requesting application, not a decorative dashboard.

Palette: ink #111918, panel #1B2926, paper #F1F2E9, muted #AEBDB5, mint #BDE6CC,
danger #F0AAA0. Use locally available system sans for body and serif for the
application heading, avoiding external font requests on authentication pages.
Use plain Spanish actions: Continuar con Google, Permitir acceso, Cancelar and
Cerrar sesión. Visible focus, usable narrow-screen layout and reduced motion;
no JavaScript requirement. Review: authentication clarity takes precedence over
visual novelty; omit the connection motif if it obscures account/application
identity. No untrusted remote client logos or profile pictures are fetched.

## Primary references

- https://developers.google.com/identity/openid-connect/openid-connect
- https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
- https://www.rfc-editor.org/rfc/rfc9700.html
- https://www.rfc-editor.org/rfc/rfc8252.html
