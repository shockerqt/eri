# Explicit production identity enrollment

This operator CLI performs one Authorization Code + S256 PKCE login against
exactly `https://auth.shocker.cl` using the pre-provisioned static public client
`eri-production-enrollment` and exact redirect
`http://127.0.0.1:8765/callback`. It requests only `openid`, uses the discovered
same-origin UserInfo endpoint as resource, verifies signed access/ID tokens,
issuer, audience, client, nonce and matching subjects, then calls UserInfo once.
It never calls Balance or links a Balance identity. Provisioning and runtime
activation remain Infrastructure-owned and require their separate reviewed plan.

Use Node 24 in an interactive SSH terminal. From your local computer establish
loopback forwarding (keep local port 8765 free):

```sh
ssh -L8765:127.0.0.1:8765 USER@HOST
```

From the governed Eri checkout in that SSH terminal run:

```sh
node scripts/production-enrollment.mjs --production-enrollment
```

Open the transient authorization URL printed to **stderr** in your local browser.
Keep it inside the terminal/browser; never paste it into chat, a ticket, a log or
a transcript. Do not redirect or capture terminal output or use a recording SSH
session. The CLI requires TTY input/stderr and an SSH session. The callback binds
only VPS loopback port 8765 with the existing five-minute callback deadline.
Stdout contains only generic PASS/FAIL status; errors never print response bodies,
profiles, email, subjects, codes or tokens. No enrollment is started by `--help`.

By default identity and credentials stay in memory. To retain an explicit private
identity-association receipt, supply an absolute normalized destination inside an
existing directory owned by your current user with mode 0700 and no symlinked
path components:

```sh
node scripts/production-enrollment.mjs --production-enrollment --receipt /PRIVATE-DIRECTORY/enrollment.json
```

The receipt is created exclusively with `O_EXCL`, `O_NOFOLLOW` and mode 0600.
Existing files and symlinks are rejected; no overwrite occurs. Only issuer,
client, subject and timestamp are stored. Treat this receipt as private identity
data; do not paste it into chat or commit it. No token or profile is persisted.
A receipt failure returns generic FAIL even if provider enrollment already
succeeded; it does not roll back the provider identity. Parent directories must
remain private and stable throughout execution.

No refresh token is requested or accepted. The short-lived access token is kept
in memory and expires within five minutes. This CLI does not claim token
revocation or provider-browser logout; `/revoke` does not support access-token
revocation. The browser may retain its Eri/Google SSO session. This script neither
activates production configuration nor provides consumer migration acceptance.

Synthetic coverage runs with `make test-oauth-smoke`, also included by `make test`.
