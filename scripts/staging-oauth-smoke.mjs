#!/usr/bin/env node
// Diagnostic public OAuth client. All credentials remain in this process.
import { createHash, randomBytes, createPublicKey, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

const LIMIT = 1024 * 1024;
const CALLBACK = 'http://127.0.0.1:8765/callback';
const CLIENT = 'eri-staging-cli';
const fail = () => { throw new Error('diagnostic check failed'); };
const requireThat = (condition) => { if (!condition) fail(); };
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const nonempty = (v) => typeof v === 'string' && v.length > 0;

export function issuerPolicy(value) {
  const url = new URL(value);
  requireThat(url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash);
  requireThat(url.pathname === '/' && url.hostname.toLowerCase().replace(/\.+$/, '') !== 'auth.shocker.cl');
  // Require the exact issuer spelling; discovery must not normalize it for us.
  requireThat(value === url.origin);
  return value;
}

export function endpointPolicy(value, issuer) {
  const url = new URL(value);
  requireThat(url.protocol === 'https:' && url.origin === issuer && !url.username && !url.password && !url.hash && !url.search);
  return url.href;
}

export async function readJson(response) {
  requireThat(!response.redirected && ((response.status >= 200 && response.status < 300) || (response.status >= 400 && response.status < 500)));
  requireThat((response.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase() === 'application/json');
  const length = response.headers.get('content-length');
  if (length !== null) requireThat(/^\d+$/.test(length) && Number(length) <= LIMIT);
  requireThat(response.body !== null);
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      requireThat(size <= LIMIT);
      chunks.push(value);
    }
    const result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    requireThat(object(result));
    return result;
  } catch {
    await reader.cancel().catch(() => {});
    fail();
  } finally {
    reader.releaseLock();
  }
}

export async function requestJson(url, options = {}, fetcher = fetch) {
  // The timeout remains active through body consumption, not just the headers.
  const response = await fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(15_000) });
  const data = await readJson(response);
  return { status: response.status, data };
}

export function validateMetadata(metadata, issuer) {
  requireThat(object(metadata) && metadata.issuer === issuer);
  requireThat(Array.isArray(metadata.code_challenge_methods_supported) && metadata.code_challenge_methods_supported.includes('S256'));
  requireThat(Array.isArray(metadata.token_endpoint_auth_methods_supported) && metadata.token_endpoint_auth_methods_supported.includes('none'));
  requireThat(metadata.authorization_response_iss_parameter_supported === true);
  const endpoints = {};
  for (const name of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint']) {
    endpoints[name] = endpointPolicy(metadata[name], issuer);
  }
  return endpoints;
}

export function transaction() {
  const verifier = randomBytes(32).toString('base64url');
  return {
    state: randomBytes(32).toString('base64url'),
    nonce: randomBytes(32).toString('base64url'),
    verifier,
    challenge: createHash('sha256').update(verifier).digest('base64url'),
  };
}

// Use the discovered UserInfo resource: the diagnostic registration has no
// separately declared API resources. Eri grants this resource with openid.
export function oauthRequestBuilder(endpoints) {
  const resource = endpoints.userinfo_endpoint;
  return {
    authorization(pending) {
      const url = new URL(endpoints.authorization_endpoint);
      url.search = new URLSearchParams({ client_id: CLIENT, redirect_uri: CALLBACK, response_type: 'code',
        scope: 'openid profile email offline_access', resource, state: pending.state,
        nonce: pending.nonce, code_challenge: pending.challenge, code_challenge_method: 'S256' }).toString();
      return url;
    },
    token(fields) {
      return new URLSearchParams({ client_id: CLIENT, ...fields, resource });
    },
  };
}

export function parseCallback(method, host, target, pending, issuer) {
  requireThat(method === 'GET' && host === '127.0.0.1:8765');
  requireThat(typeof target === 'string' && target.startsWith('/callback?') && target.length <= 8192);
  const url = new URL(target, CALLBACK);
  requireThat(url.origin === 'http://127.0.0.1:8765' && url.pathname === '/callback' && !url.hash);
  const q = url.searchParams;
  const allowed = new Set(['state', 'iss', 'code', 'error', 'error_description', 'error_uri']);
  for (const name of q.keys()) requireThat(allowed.has(name) && q.getAll(name).length === 1);
  requireThat(q.get('state') === pending.state && q.get('iss') === issuer);
  const code = q.get('code');
  const error = q.get('error');
  requireThat((nonempty(code) && !q.has('error')) || (nonempty(error) && !q.has('code')));
  requireThat(!code || (!q.has('error_description') && !q.has('error_uri')));
  return error ? { error: true } : { code };
}

export async function listenForCallback(pending, issuer, onListening, deadlineMs = 300_000) {
  let attempts = 0;
  let settled = false;
  let timer;
  const server = createServer({ maxHeaderSize: 8192 }, (req, res) => {
    if (settled) { res.writeHead(410).end(); return; }
    let result;
    try { result = parseCallback(req.method, req.headers.host, req.url, pending, issuer); } catch { /* generic rejection below */ }
    res.writeHead(result ? 200 : 400, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      'x-content-type-options': 'nosniff',
      'connection': 'close',
    });
    res.end('<!doctype html><title>OAuth diagnostic</title><p>Return to the diagnostic terminal.</p>');
    if (result) finish(result.error ? new Error('authorization declined') : null, result);
    else if (++attempts >= 20) finish(new Error('callback limit reached'));
  });
  server.headersTimeout = 5000;
  server.requestTimeout = 5000;
  let resolveResult, rejectResult;
  const completion = new Promise((resolve, reject) => { resolveResult = resolve; rejectResult = reject; });
  function finish(error, result) {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    server.close();
    server.closeAllConnections();
    if (error) rejectResult(error); else resolveResult(result);
  }
  server.on('error', () => finish(new Error('callback listener unavailable')));
  timer = setTimeout(() => finish(new Error('callback deadline reached')), deadlineMs);
  server.listen(8765, '127.0.0.1', () => {
    try { onListening(); } catch { finish(new Error('authorization display failed')); }
  });
  return completion;
}

function decodePart(part) {
  requireThat(nonempty(part) && /^[A-Za-z0-9_-]+$/.test(part));
  const bytes = Buffer.from(part, 'base64url');
  requireThat(bytes.toString('base64url') === part);
  const v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  requireThat(object(v));
  return v;
}

export function verifyJwt(token, jwks, expected, now = Math.floor(Date.now() / 1000)) {
  requireThat(nonempty(token) && token.length <= 32768);
  const parts = token.split('.');
  requireThat(parts.length === 3);
  const header = decodePart(parts[0]);
  const claims = decodePart(parts[1]);
  requireThat(header.alg === 'RS256' && header.typ === expected.typ && nonempty(header.kid));
  requireThat(!('crit' in header) && !('b64' in header));
  requireThat(object(jwks) && Array.isArray(jwks.keys) && jwks.keys.length > 0 && jwks.keys.length <= 32);
  const seen = new Set();
  for (const key of jwks.keys) {
    requireThat(object(key) && nonempty(key.kid) && !seen.has(key.kid));
    seen.add(key.kid);
    requireThat(!['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some((field) => field in key));
  }
  const key = jwks.keys.find((candidate) => candidate.kid === header.kid);
  requireThat(key?.kty === 'RSA' && key.alg === 'RS256' && key.use === 'sig');
  if ('key_ops' in key) requireThat(Array.isArray(key.key_ops) && key.key_ops.length === 1 && key.key_ops[0] === 'verify');
  const publicKey = createPublicKey({ key, format: 'jwk' });
  requireThat(publicKey.asymmetricKeyDetails?.modulusLength >= 2048);
  requireThat(/^[A-Za-z0-9_-]+$/.test(parts[2]) && Buffer.from(parts[2], 'base64url').toString('base64url') === parts[2]);
  requireThat(verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], 'base64url')));
  requireThat(claims.iss === expected.issuer && nonempty(claims.sub));
  requireThat(Number.isSafeInteger(claims.exp) && Number.isSafeInteger(claims.iat));
  requireThat(claims.iat >= 0 && claims.exp > claims.iat && claims.iat <= now + 30 && claims.exp > now - 30);
  if ('nbf' in claims) requireThat(Number.isSafeInteger(claims.nbf) && claims.nbf >= 0 && claims.nbf <= now + 30 && claims.nbf < claims.exp);
  const aud = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  requireThat(Array.isArray(aud) && aud.length > 0 && aud.every(nonempty) && new Set(aud).size === aud.length);
  requireThat(expected.audiences.every((value) => aud.includes(value)));
  if (expected.typ === 'JWT') {
    requireThat(aud.length === 1 && aud[0] === expected.client && claims.nonce === expected.nonce);
    if ('azp' in claims) requireThat(claims.azp === expected.client);
  } else requireThat(claims.client_id === expected.client);
  return claims;
}

export function assertInvalidGrant(result) {
  requireThat(result.status === 400 && result.data.error === 'invalid_grant');
}

async function main(args) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/staging-oauth-smoke.mjs --issuer https://STAGING-HOST');
    console.log('Requires Node 24 and interactive browser login. Callback: 127.0.0.1:8765.');
    return;
  }
  requireThat(args.length === 2 && args[0] === '--issuer' && process.stdin.isTTY);
  const issuer = issuerPolicy(args[1]);
  const stages = [];
  let stage = 'discovery';
  const pass = (name) => { stages.push(name); console.log(`PASS ${name}`); };
  try {
    const oidc = await requestJson(`${issuer}/.well-known/openid-configuration`);
    const as = await requestJson(`${issuer}/.well-known/oauth-authorization-server`);
    requireThat(oidc.status === 200 && as.status === 200);
    const endpoints = validateMetadata(oidc.data, issuer);
    const other = validateMetadata(as.data, issuer);
    requireThat(Object.keys(endpoints).every((name) => endpoints[name] === other[name]));
    const jwksResult = await requestJson(endpoints.jwks_uri);
    requireThat(jwksResult.status === 200);
    const jwks = jwksResult.data;
    pass(stage);
    const requests = oauthRequestBuilder(endpoints);
    const post = (fields) => requestJson(endpoints.token_endpoint, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: requests.token(fields),
    });
    async function checkTokens(result, nonce, priorSubject) {
      requireThat(result.status === 200 && result.data.token_type === 'Bearer');
      requireThat(nonempty(result.data.access_token) && nonempty(result.data.refresh_token));
      requireThat(Number.isSafeInteger(result.data.expires_in) && result.data.expires_in > 0);
      const access = verifyJwt(result.data.access_token, jwks, {
        typ: 'at+jwt', issuer, client: CLIENT, audiences: [endpoints.userinfo_endpoint],
      });
      if (nonce !== undefined) {
        const id = verifyJwt(result.data.id_token, jwks, { typ: 'JWT', issuer, client: CLIENT, audiences: [CLIENT], nonce });
        requireThat(id.sub === access.sub);
      } else requireThat(!('id_token' in result.data));
      if (priorSubject !== undefined) requireThat(access.sub === priorSubject);
      const info = await requestJson(endpoints.userinfo_endpoint, {
        headers: { authorization: `Bearer ${result.data.access_token}`, accept: 'application/json' },
      });
      requireThat(info.status === 200 && info.data.sub === access.sub);
      return { refresh: result.data.refresh_token, subject: access.sub };
    }
    async function authorize(label) {
      const pending = transaction();
      const url = requests.authorization(pending);
      const callback = await listenForCallback(pending, issuer, () => {
        console.log(`Open this transient authorization URL in your browser (${label}). Do not save or share it:`);
        console.log(url.href);
      });
      return checkTokens(await post({ grant_type: 'authorization_code', code: callback.code,
        redirect_uri: CALLBACK, code_verifier: pending.verifier }), pending.nonce);
    }
    stage = 'login-token-userinfo';
    const first = await authorize('refresh replay family');
    pass(stage);
    stage = 'refresh-rotation';
    const rotated = await checkTokens(await post({ grant_type: 'refresh_token', refresh_token: first.refresh }), undefined, first.subject);
    requireThat(rotated.refresh !== first.refresh);
    pass(stage);
    stage = 'refresh-replay-family-revocation';
    assertInvalidGrant(await post({ grant_type: 'refresh_token', refresh_token: first.refresh }));
    assertInvalidGrant(await post({ grant_type: 'refresh_token', refresh_token: rotated.refresh }));
    pass(stage);
    stage = 'logout-family-live';
    const second = await authorize('fresh logout family; use the same browser');
    const live = await checkTokens(await post({ grant_type: 'refresh_token', refresh_token: second.refresh }), undefined, second.subject);
    requireThat(live.refresh !== second.refresh);
    pass(stage);
    stage = 'logout-revocation';
    console.log(`In the SAME browser, open ${issuer}/logout and confirm Eri logout.`);
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try { await rl.question('After the browser confirms logout, press Enter here: ', { signal: AbortSignal.timeout(300_000) }); }
    finally { rl.close(); }
    assertInvalidGrant(await post({ grant_type: 'refresh_token', refresh_token: live.refresh }));
    pass(stage);
    console.log(JSON.stringify({ diagnostic: 'eri-staging-oauth', result: 'pass', stages }));
  } catch {
    // Never emit server bodies, exceptions, claims, codes or credentials.
    console.error(`FAIL ${stage}`);
    console.log(JSON.stringify({ diagnostic: 'eri-staging-oauth', result: 'fail', stage, stages }));
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(() => {
    console.error('FAIL invocation (use --help)');
    process.exitCode = 1;
  });
}
