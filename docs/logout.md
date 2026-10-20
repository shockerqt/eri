# Logout policy

This bounded extension leaves discovery advertisement unchanged;
`end_session_endpoint` remains withheld.

`/logout` accepts RP parameters through GET or an
`application/x-www-form-urlencoded` POST body: `client_id`,
`post_logout_redirect_uri`, `state` and `id_token_hint`. The return URI must be
an exact registered static-client destination; a signed hint can supply the
client ID through its audience. If both client ID and hint are supplied they
must agree. State requires a return URI. Missing return URI uses the provider
landing page and confirmation. Duplicate, mixed challenge/RP, malformed or
unsupported parameters fail closed. Confirmation POST remains a separate mode
with a same-origin check and a one-use session-bound CSRF challenge.

The default client policy is `logout_flow = 'interactive'`, independently of
`authorization_flow`. Only an explicitly reviewed static client declaration may
set `logout_flow = 'id_token_hint'`. CIMD metadata never grants this permission.
The exception is a deliberate departure from the OIDC RP-Initiated Logout
recommendation to confirm even with a valid hint. A valid signed hint is a
bearer artifact: replay with the same active browser cookie can trigger logout;
it is not fresh evidence of user intent. Review this tradeoff before opting in.
Missing hints always require confirmation.

The exception requires an Eri RS256 ID token with known `kid`, `typ=JWT`, no
unsupported critical headers, correct issuer, client audience, required identity
and time claims, and the exact active provider session `sid` and subject. An
expired ID token is accepted only with that active matching session, a valid
`exp > iat` interval, no future issuance beyond 30 seconds of clock skew, and
issuance no earlier than the provider session authentication time minus that
skew. Valid hints with an old/missing SID or different subject remain interactive.
Invalid signatures, keys, algorithms, token classes, issuer or client mismatch
reject without revocation. Old ID tokens without SID remain usable for confirmed
logout. Refreshed grants still issue no new ID token.

The existing logout challenge and locked finish transaction recheck active
session, client policy and exact destination before consuming the challenge and
revoking the provider session and every renewable refresh family under it.
The hint's originating refresh family need not remain active. Cookie deletion,
state return and no-store response semantics are shared with confirmed logout.
Issued access tokens retain their short remaining lifetime. Eri does not log out
of Google or create another session/revocation engine.

ID tokens now include a signed `sid` from the existing authorization code's
provider session. This needs no database migration. Client opt-in is configuration
only; rollback must restore the older config if the older binary does not
recognize `logout_flow`. Use POST where practical: GET hints can enter browser
history and URL/access logs. Never log query strings containing hints; apply the
same restriction to reverse proxies and diagnostic tooling. Response referrer
policy and no-store caching reduce disclosure but cannot erase a logged URL.

Normative reference: [OpenID Connect RP-Initiated Logout 1.0, section 2](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout).
