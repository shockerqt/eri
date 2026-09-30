# Real staging OAuth diagnostic

This public client uses Node 24 built-ins and a human browser to exercise Eri's
real Google login and consent. It is owned by INF-008; staging routes, Google
credentials and reviewed client configuration remain Infrastructure/INF-015 work.
It does not deploy or configure Eri and never contacts a Balance production API.
The existing synthetic Rust/browser regressions remain separate evidence.

Use an explicitly reviewed HTTPS staging issuer, for example the hostname from
the INF-015 staging declaration. The issuer argument must exactly match discovery
(with no trailing slash). The client refuses the production hostname
`auth.shocker.cl`. Confirm the staging hostname and its routing before running;
the script cannot independently establish infrastructure ownership from a URL.
It also refuses insecure, cross-origin, credential-bearing, query-bearing or
fragment-bearing metadata endpoints, redirects, mismatched issuers, unsupported
PKCE and missing public-client authentication metadata.

The reviewed public client is `eri-staging-cli`, with registered callback
`http://127.0.0.1:8765/callback`, no client secret, the discovered UserInfo endpoint as the
OAuth resource, and scopes `openid profile email offline_access`. Do not change server registration
as part of running this diagnostic. Its empty declared resource list permits
Eri's UserInfo resource with `openid`, rather than the issuer root. Resolve any registration mismatch through the
owning Infrastructure task first.

Run on a workstation with Node 24:

```sh
node scripts/staging-oauth-smoke.mjs --help
node scripts/staging-oauth-smoke.mjs --issuer https://REVIEWED-STAGING-HOST
```

Use an interactive terminal and browser. Alternatively run the client on the VPS
through an SSH connection from the workstation:

```sh
ssh -L 8765:127.0.0.1:8765 YOUR-REVIEWED-VPS
# In that SSH terminal, from the Eri task worktree:
node scripts/staging-oauth-smoke.mjs --issuer https://REVIEWED-STAGING-HOST
```

The SSH tunnel makes the workstation browser's loopback callback reach the VPS
listener. Both the workstation forwarding port and VPS listener port must be
available; stop an unrelated local listener through its own workflow before
trying again. The client binds only `127.0.0.1`, establishes the listener before
printing the authorization URL, and closes it after each transaction. Never open
port 8765 publicly or change OCI/Nginx/firewall rules for this callback.

1. Open the transient authorization URL printed in the terminal. Sign in with
   Google and approve Eri consent. Callback parsing requires an exact path and
   Host, singleton parameters, the generated state and the expected response
   issuer. A malformed request does not consume the transaction; twenty rejected
   requests or a five-minute deadline ends it.
2. The client exchanges the code with S256 PKCE and public `none` authentication.
   It verifies RS256 access and ID tokens against the discovered public JWKS,
   issuer, audience, client identity, expiry and nonce, then compares token and
   UserInfo subjects in memory. Refresh responses must omit the ID token.
3. The first family proves refresh rotation, replays the original refresh token
   and proves the rotated successor is also revoked. Each rejection must be
   exactly HTTP 400 with OAuth `invalid_grant`; network failures and unrelated
   errors fail the diagnostic.
4. Open the second authorization URL in the **same browser** to create a fresh
   family. The client proves that family's latest refresh token is live before
   logout. Open the printed plain `https://REVIEWED-STAGING-HOST/logout` URL in
   that browser and confirm Eri logout. Once the browser confirms completion,
   press Enter in the terminal. The client proves the latest refresh token is
   rejected with HTTP 400 `invalid_grant`.

Use plain `/logout` without post-logout redirects. `/logout?client_id=eri-staging-cli`
alone is invalid because Eri requires a registered destination with that form of
logout. The diagnostic relies on the real browser's provider session cookie and
Eri's logout confirmation/CSRF flow; it does not export or replay browser cookies.
If the browser is using a different session, the final rejection will fail.

Authorization URLs contain transient state, nonce and challenge. They are the only
sensitive browser instructions printed; do not share them, capture the terminal
or redirect the entire output into an evidence file. Codes, tokens, cookies,
profiles, subjects and server response bodies are never printed or written to
disk by this client. Credentials live only in process memory. Browser history
and the browser's normal Google/Eri storage are outside this process; use an
appropriate staging browser profile and close it after the run. The callback
page has no query echo, `no-store`, `no-referrer` and restrictive CSP headers.
Each network request has a fifteen-second deadline through body consumption and
a one-MiB response limit. The script never emits caught exception details.

Record only the final JSON summary and deterministic `PASS`/`FAIL` stage names as
durable evidence, together with the reviewed source SHA, runtime version and
staging run reference. A passing summary proves the stages listed above for that
human run. A failing summary identifies the stage without exposing credentials;
inspect the authorized staging service through its operational runbook if needed.
An interrupted or expired run is incomplete and must not be recorded as a pass.
After an ambiguous refresh transport failure, start a new run rather than manually
retrying a token: the server may already have rotated it.

This diagnostic does not prove restart persistence, key rotation, RAM or latency
targets, native/mobile login, or a real Gemini Spark MCP connection. Those remain
separate acceptance gates. It does not revoke already-issued self-contained
access tokens; Eri's documented short access-token lifetime still applies.

Run the synthetic client security regressions without Google or external traffic:

```sh
make test-oauth-smoke
```

`make test` includes these Node tests before the Rust suite. CI installs Node major
24. The fixtures cover metadata/endpoint policy, callback transaction binding and
non-consumption, signed-token claim/key failures, response boundaries and exact
refresh-replay error assertions. They do not establish real staging acceptance.
