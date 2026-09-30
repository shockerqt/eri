# Reproducible staging measurements

INF-008 owns these diagnostics. INF-015 owns staging activation, release artifact
installation and operational execution. Run them only after the reviewed staging
release and secret/config contracts are installed through the Infrastructure
runbook. They do not deploy, migrate, restart, change keys or authenticate users.
No measurements have been established merely by building or testing the tools.

CI builds the release example `staging-benchmark`, packages it as `eri-benchmark`
beside `eri`, and covers both binaries in `SHA256SUMS`. `SOURCE_SHA` and
`RUST_TARGET` identify the artifact. Before running, record the successful exact
merge-SHA CI artifact reference and verify its package-relative checksums through
the Infrastructure release procedure. The benchmark accepts only a lowercase
40-hex `SOURCE_SHA` marker adjacent to its executable. It never invokes Git. A
marker alone is not proof of a verified artifact: preserve the checksum and CI
reference with the measurement, and compare its source SHA with the installed
Eri release before assessing results.

The latency binary reads only `/etc/eri-staging/config.toml` with production mode,
issuer `https://auth-staging.shocker.cl`, bind `127.0.0.1:8092` and signing manifest
`/etc/eri-staging/keys/manifest.json`. Config and manifest paths must canonicalize
to those exact paths. Before key loading or database connection it requires the
`ERI_DATABASE_URL` environment variable, no inline database URI, explicit literal
loopback host (`127.0.0.1` or `::1`), username `eri_staging` and database
`eri_staging`. URL queries/fragments are rejected, including connection options
that could override identity. Credentials belong in the root-owned staging
EnvironmentFile, never command arguments or a shell-sourced service-user file.

The binary uses the public Eri config, keys, pool, AppState and router APIs. Pool
connection and Google adapter construction happen at setup; neither migrations,
Google requests nor identity/session/data writes are performed. A random synthetic
UUID and signed access JWT are generated only in memory before timing. A separate
SigningKeys verification object loads the same manifest before timing. It does
not inspect browser credentials or print tokens, private keys, claims, config,
URLs with credentials or caught errors.

The transient unit must receive its own restrictions: it does **not** inherit
`eri-staging.service`. After the artifact has been verified and installed under
the exact reviewed release directory, use this template through the authorized
Infrastructure operational workflow. Replace the SHA with the verified artifact
SHA; do not copy secret values into this command:

```sh
sudo systemd-run --unit=eri-staging-benchmark --wait --pipe --collect \
  --property=Type=exec \
  --property=User=eri_staging --property=Group=eri_staging \
  --property=EnvironmentFile=/etc/eri-staging/secrets.env \
  --property=WorkingDirectory=/opt/eri-staging/releases/VERIFIED_40_HEX_SHA \
  --property=RuntimeMaxSec=185 --property=TimeoutStopSec=5 \
  --property=NoNewPrivileges=yes --property=PrivateTmp=yes \
  --property=ProtectSystem=strict --property=ProtectHome=yes \
  --property=ProtectKernelTunables=yes --property=ProtectKernelModules=yes \
  --property=ProtectControlGroups=yes --property=RestrictSUIDSGID=yes \
  --property=LockPersonality=yes --property=UMask=0077 \
  --property=CapabilityBoundingSet= \
  --property=RestrictAddressFamilies='AF_UNIX AF_INET AF_INET6' \
  --property=IPAddressDeny=any --property=IPAddressAllow=localhost \
  --property=ReadOnlyPaths=/etc/eri-staging \
  /opt/eri-staging/releases/VERIFIED_40_HEX_SHA/eri-benchmark \
  --warmup 1000 --samples 10000
```

systemd reads the root-only EnvironmentFile before dropping privileges. The
service UID must already have the reviewed read permissions for config and keys.
Do not widen permissions for this command. The transient unit's loopback network
restriction permits the staging PostgreSQL connection and blocks remote Google
traffic. Verify support/enforcement of these unit properties on the VPS before
execution. Failure must be resolved in the owning Infrastructure workflow.
`RuntimeMaxSec` supplies the external hard bound for synchronous file/key work;
the binary also bounds the async setup/run to 180 seconds and the entire post-setup
warmup/measurement window to 120 seconds. Setup time is excluded from statistics.

Defaults are 1,000 warmup iterations per phase and 10,000 measured samples per
phase, concurrency one. Bounds are 100–10,000 warmups and 100–100,000 samples.
Warmups run both operations; measured discovery and verification phases then run
serially. Monotonic `Instant` timestamps measure nanoseconds. Any failed sample
or expired window fails the whole diagnostic, with only generic stderr.
The summary reports nearest-rank p50/p95/p99: sort observed durations and select
index `ceil(p * N / 100) - 1`. No samples or errors are silently discarded.

Discovery measures in-process `Router.clone().oneshot` dispatch (clone occurs
outside timing), bounded complete response body (64 KiB). The timer stops before JSON parsing
and exact issuer/UserInfo/S256/response-issuer metadata checks; a failed validation
still rejects the entire measurement. It excludes TCP, Nginx,
Cloudflare and network latency. Verification measures the actual public
`SigningKeys::verify<serde_json::Value>` path: JOSE parsing, cached kid-map lookup,
RS256 verification, issuer/audience/expiry validation and JSON claims decoding.
It excludes signing, key loading, remote JWKS fetching, HTTP authentication
handlers, database work and network latency. Do not label that narrower primitive
as complete HTTP UserInfo or resource-server authentication latency.

For a separate service RSS window, run Node 24 on the VPS after staged Eri is
healthy, using an identity allowed to read the service's `/proc` entries:

```sh
node scripts/staging-rss.mjs --help
node scripts/staging-rss.mjs --duration-seconds 30
```

Only `eri-staging.service` is accepted. Every snapshot reads MainPID through
`systemctl`, resolves `/proc/PID/exe` to
`/opt/eri-staging/releases/<lowercase-40-hex>/eri`, and checks start-time ticks
around the VmRSS read. Initial, periodic and final identities must match. Missing
or changed processes, restart, deleted executables or other release paths fail
the window. This measures the **running Eri service process**, not Node or the
latency benchmark process. Read permissions vary by `/proc` policy; resolve that
through the authorized operating procedure instead of widening host access.

The default finite workload lasts 30 seconds (CLI bounds 1–120 seconds), targets
10 total requests/second alternating discovery and JWKS on literal
`http://127.0.0.1:8092`, and samples VmRSS every 100 ms. Requests are serial,
redirects forbidden, HTTP 200 and bounded JSON required; discovery must contain
exact staging issuer/JWKS/UserInfo URLs and JWKS must contain public signing keys.
Each request has at most two seconds, further limited by the remaining window,
including body consumption, and each body has a one-MiB bound. No authorization,
Google or token endpoint is called. On the deployed staging service discovery and
JWKS are read-only cached endpoints.

Scheduling follows a monotonic cadence and skips missed slots instead of bursting
to catch up. The summary reports configured and actual duration, request rate,
sampling mean/max interval, successful request count, zero request errors,
nearest-rank p95 and maximum RSS bytes, PID/start ticks and canonical release SHA.
Slow snapshots or requests therefore remain visible in observed rates. A request
or periodic snapshot crossing the window end invalidates the window. Initial and
final process checks occur outside its reported workload duration; `systemctl`
calls have two-second timeouts. Any HTTP/process failure aborts without a partial
passing summary. Sampling itself and systemctl checks add observer overhead; record
the tool/runtime versions and host workload when interpreting results.

Record only sanitized summary JSON, exact artifact/checksum/source identity,
Node version, host/environment and workload context in the Governance run. Compare
discovery and verification p95 to the <1 ms target and service maximum RSS to the
<30 MB target (report bytes and conversion explicitly). A failed threshold remains
a failed acceptance gate; do not change targets or discard warm/hot/slow windows
without a declared rerun rationale. RSS represents this finite discovery/JWKS
workload, not all real login traffic. These measurements do not prove Google,
mobile or Spark interoperability, restart persistence or signing-key rotation.

Local regression commands do not read the staging service or staging secrets:

```sh
make test-rss
cargo check --locked --example staging-benchmark
```

`make test` includes synthetic OAuth and RSS Node regressions plus Rust tests.
`make build` builds both release Eri and the benchmark; CI packages both. Full
repository checks remain required for the exact implementation SHA.
