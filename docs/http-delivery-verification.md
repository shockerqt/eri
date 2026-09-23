# First-party HTTP delivery verification

Date: 2026-09-10. Task: INF-008. Execution:
INF-008-20260905-075417-implement-authorization-server.
Integrated starting revision: `290cf4ae781ae183e72b51e3c71538e2c6c0dc97`.
This records a delivery phase, not completion of INF-008 or its staging goal.

## Review and corrections

The recovered local HTTP implementation passed 54 tests before review. Coordinator
and independent Sol review nevertheless identified browser and security defects:

- HTTPS accepted development session/transaction cookies. Readers now enforce
  the selected mode and exact host-cookie names; duplicate transaction names
  fail closed.
- Preflight expected a custom header value absent from browser OPTIONS requests.
  It now checks the union of reviewed static origins; actual requests retain
  their client-specific origin checks.
- Claimed callback failures retained transaction cookies. Every terminal path
  now clears the matched cookie, and pending cookies expire after 600 seconds.
- Revocation concealed persistence failures behind HTTP 200. It now returns 503
  for storage failures while keeping unknown-token results indistinguishable.
- The initiating document's CSP blocked the registered client redirect after
  consent/logout POST. Its form policy now allows only self and the source
  derived from the persisted, validated destination.
- Real Chromium execution exposed `Origin: null` under `no-referrer`. Form-only
  `strict-origin` preserves same-origin POST validation without forwarding
  callback paths or parameters. Other sensitive responses retain `no-referrer`.
- Consent now identifies the actual session's verified account. Local logout has
  a confirmation destination, and the compact UI follows the documented palette.

The HTTP regression now separately proves that replay invalidates a live refresh
successor and that logout invalidates a fresh live renewable family. Previously
both checks followed explicit revocation and could mask missing behavior.

Coordinator verification passed `make check`: 56 standard tests, formatting,
Clippy with warnings denied, and release build. The ignored Chromium test was
also invoked explicitly and passed against actual Eri routes, synthetic signed
Google identity, and a separate callback origin. See [operations](operations.md)
for its portable command. This is browser interoperability evidence for the
fixture, not real Google authentication or real mobile/MCP acceptance.

Independent Sol review found no unresolved substantive blocker after corrections.
Gemini Flash 3.8 High then reviewed the bounded consent/logout policy and account
binding; it returned no substantive defect. Its optional suggestion to reject
every absent Origin header was not adopted: the existing contract requires
session-bound CSRF and validates Origin when supplied. Browser tests additionally
assert the actual exact Origin; `Origin: null` remains rejected.

## Workflow observations and usage

Sol implemented and independently reviewed; Luna audited HTTP coverage, staging
contracts, and official Spark documentation. The coordinator reproduced browser
failures, resolved contracts, and independently reran verification.

Gemini invocation `614c0247-bc0b-49d0-85b4-dd2b23df97d1` completed read-only:
304022 input tokens, 46122 output tokens, 350144 total, 251.468 seconds. The
`inf-008` group totals 629740 observed tokens over three completed calls, with
complete accounting and no unknown or in-flight calls at that observation.
Native coordinator/Sol/Luna token counters are unavailable and are not estimated.

Retrospective inputs: exercise real browser headers before treating a synthetic
HTTP success as UI readiness; test each revocation cause against a still-live
credential; compare delegated findings with observed total usage. One AGY execution
contained substantial provider usage despite bounded scope and output. This pass
added no new substantive finding after Sol review. These observations support a
later routing discussion, not an automatic policy change or a measured comparison
with native-agent costs. User retrospective feedback is still pending.

## Remaining goal evidence

The 2026-09-23 login UI package adds a server-rendered landing page for validated
first-party authorization requests. It shows the reviewed application, scopes,
and resource before a user chooses Google. A one-use, browser-bound POST starts
Google federation; a separate cancel action atomically denies the pending request
and returns `access_denied` to its validated redirect. The additive migration
preserves callbacks that were already awaiting Google before this package.
Coordinator verification passed `make check` (56 standard tests, formatting,
Clippy and release build) and the explicitly invoked Chromium login, consent,
logout, and cancel flow at a 390px viewport. Independent Sol review found no
substantive issue. Chromium evidence uses a signed synthetic Google fixture,
not a real Google account.

The user selected Gemini Spark. Its [official custom-app guide](https://support.google.com/gemini/answer/17209137)
documents an MCP URL and manual credentials when DCR is unavailable. It does not
establish the concrete callback, authentication method, or CIMD behavior needed
for this integration. Do not substitute Gemini CLI assumptions for a real Spark
connection.

Still pending: verified generic-client registration/interoperability, real Google
credentials and staging login,
Infrastructure staging activation, restart/key-rotation smoke tests, RAM/latency
measurements, and BAL-033 mobile/API/MCP integration. Production Keycloak cutover
remains outside the active staging goal. No completion claim follows from this
HTTP package or its green tests alone.
