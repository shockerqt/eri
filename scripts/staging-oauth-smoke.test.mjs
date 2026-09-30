import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { issuerPolicy, endpointPolicy, validateMetadata, parseCallback, transaction, verifyJwt,
  readJson, requestJson, assertInvalidGrant, listenForCallback, oauthRequestBuilder } from './staging-oauth-smoke.mjs';

const issuer = 'https://auth-staging.example';
const client = 'eri-staging-cli';
const pending = { state: 'secret-state' };
const callback = (query) => parseCallback('GET', '127.0.0.1:8765', `/callback?${query}`, pending, issuer);
const bound = `state=secret-state&iss=${encodeURIComponent(issuer)}`;
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'fixture-key', alg: 'RS256', use: 'sig' };
const jwks = { keys: [jwk] };
const now = 2000000000;
const accessClaims = { iss: issuer, sub: 'synthetic-subject', aud: [`${issuer}/userinfo`],
  client_id: client, iat: now - 10, exp: now + 300 };
const accessExpected = { typ: 'at+jwt', issuer, client, audiences: [`${issuer}/userinfo`] };
function jwt(claims = accessClaims, header = {}) {
  const data = [Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'at+jwt', kid: jwk.kid, ...header })).toString('base64url'),
    Buffer.from(JSON.stringify(claims)).toString('base64url')].join('.');
  return `${data}.${sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url')}`;
}

test('issuer and endpoints refuse production, insecure and credential-bearing destinations', () => {
  assert.equal(issuerPolicy(issuer), issuer);
  assert.equal(endpointPolicy(`${issuer}/token`, issuer), `${issuer}/token`);
  for (const value of ['https://auth.shocker.cl', 'https://AUTH.SHOCKER.CL', 'https://auth.shocker.cl.', 'https://AUTH.SHOCKER.CL.', 'http://auth-staging.example',
    `${issuer}/`, `${issuer}/other`, `${issuer}?secret=x`, `${issuer}#x`, 'https://u:p@auth-staging.example']) {
    assert.throws(() => issuerPolicy(value));
  }
  for (const value of ['http://auth-staging.example/token', 'https://other.example/token',
    'https://u:p@auth-staging.example/token', `${issuer}/token#fragment`, `${issuer}/token?credential=x`]) {
    assert.throws(() => endpointPolicy(value, issuer));
  }
});

test('metadata demands exact issuer, public none, S256, response issuer and safe endpoints', () => {
  const metadata = { issuer, code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
    authorization_response_iss_parameter_supported: true, authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`, userinfo_endpoint: `${issuer}/userinfo` };
  assert.equal(validateMetadata(metadata, issuer).token_endpoint, `${issuer}/token`);
  for (const change of [{ issuer: `${issuer}/` }, { code_challenge_methods_supported: ['plain'] },
    { token_endpoint_auth_methods_supported: ['client_secret_basic'] }, { authorization_response_iss_parameter_supported: false },
    { jwks_uri: 'https://attacker.example/jwks' }]) {
    assert.throws(() => validateMetadata({ ...metadata, ...change }, issuer));
  }
});

test('PKCE transaction uses fresh cryptographic state, nonce and S256 verifier', () => {
  const a = transaction(), b = transaction();
  for (const key of ['state', 'nonce', 'verifier', 'challenge']) {
    assert.match(a[key], /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(a[key], b[key]);
  }
});

test('outbound authorization, code and refresh forms bind the discovered UserInfo resource', () => {
  // Use a distinct discovered path to catch substitution of the issuer root or
  // reconstruction of /userinfo instead of the validated metadata endpoint.
  const userinfo = `${issuer}/discovered-userinfo`;
  const requests = oauthRequestBuilder({ authorization_endpoint: `${issuer}/authorize`, userinfo_endpoint: userinfo });
  const authorization = requests.authorization(transaction());
  assert.deepEqual(authorization.searchParams.getAll('resource'), [userinfo]);
  assert.match(authorization.searchParams.get('scope'), /(?:^| )openid(?: |$)/);
  for (const fields of [{ grant_type: 'authorization_code', code: 'synthetic', redirect_uri: 'http://127.0.0.1:8765/callback', code_verifier: 'synthetic' },
    { grant_type: 'refresh_token', refresh_token: 'synthetic' },
    { grant_type: 'refresh_token', refresh_token: 'synthetic', resource: issuer }]) {
    const form = requests.token(fields);
    assert.deepEqual(form.getAll('resource'), [userinfo]);
    assert.equal(form.get('client_id'), client);
    assert.equal(form.get('grant_type'), fields.grant_type);
  }
});

test('callback accepts only bound unambiguous singleton responses', () => {
  assert.deepEqual(callback(`${bound}&code=synthetic-code`), { code: 'synthetic-code' });
  assert.deepEqual(callback(`${bound}&error=access_denied&error_description=private`), { error: true });
  for (const query of [`${bound}&code=a&code=b`, `${bound}&state=other&code=a`,
    `${bound}&iss=${encodeURIComponent(issuer)}&code=a`, `${bound}&code=a&error=access_denied`,
    `${bound}&code=a&error=`, `${bound}&error=access_denied&code=`, `${bound}&code=`,
    'state=other&iss=https%3A%2F%2Fauth-staging.example&code=a', `${bound}&code=a&extra=1`,
    `${bound}&code=a&error_description=private`, `state=secret-state&iss=https%3A%2F%2Fevil.example&code=a`]) {
    assert.throws(() => callback(query));
  }
  for (const [method, host, target] of [['POST', '127.0.0.1:8765', `/callback?${bound}&code=a`],
    ['GET', 'localhost:8765', `/callback?${bound}&code=a`], ['GET', '127.0.0.1:8765', `/other?${bound}&code=a`],
    ['GET', '127.0.0.1:8765', `http://127.0.0.1:8765/callback?${bound}&code=a`]]) {
    assert.throws(() => parseCallback(method, host, target, pending, issuer));
  }
});

test('listener rejects malformed request without consuming pending transaction', async () => {
  let start;
  const listening = new Promise((resolve) => { start = resolve; });
  const result = listenForCallback(pending, issuer, start, 2000);
  await listening;
  const rejected = await fetch(`http://127.0.0.1:8765/callback?${bound}&code=a&code=b`);
  assert.equal(rejected.status, 400);
  assert.equal(rejected.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(rejected.headers.get('cache-control'), 'no-store');
  assert.match(rejected.headers.get('content-security-policy'), /default-src 'none'/);
  assert.doesNotMatch(await rejected.text(), /secret-state|code=a/);
  const accepted = await fetch(`http://127.0.0.1:8765/callback?${bound}&code=synthetic-code`);
  assert.equal(accepted.status, 200);
  assert.deepEqual(await result, { code: 'synthetic-code' });
});

test('signed access and ID fixtures verify with separate claims contracts', () => {
  assert.equal(verifyJwt(jwt(), jwks, accessExpected, now).sub, 'synthetic-subject');
  const idClaims = { ...accessClaims, aud: client, nonce: 'synthetic-nonce' };
  assert.equal(verifyJwt(jwt(idClaims, { typ: 'JWT' }), jwks,
    { typ: 'JWT', issuer, client, audiences: [client], nonce: 'synthetic-nonce' }, now).sub, accessClaims.sub);
  assert.throws(() => verifyJwt(jwt(idClaims, { typ: 'JWT' }), jwks,
    { typ: 'JWT', issuer, client, audiences: [client], nonce: 'wrong' }, now));
  assert.throws(() => verifyJwt(jwt({ ...idClaims, aud: [client, 'other'] }, { typ: 'JWT' }), jwks,
    { typ: 'JWT', issuer, client, audiences: [client], nonce: 'synthetic-nonce' }, now));
});

test('valid signatures cannot excuse wrong issuer, audience, times, subject or client', () => {
  for (const change of [{ iss: 'https://other.example' }, { aud: [issuer] }, { aud: [issuer, issuer] },
    { sub: '' }, { client_id: 'other' }, { exp: now - 30 }, { exp: '2000000300' },
    { iat: now + 31 }, { iat: -1 }, { exp: now - 10 }, { nbf: now + 31 }, { nbf: '2000000000' }]) {
    assert.throws(() => verifyJwt(jwt({ ...accessClaims, ...change }), jwks, accessExpected, now));
  }
  assert.equal(verifyJwt(jwt({ ...accessClaims, exp: now - 29, iat: now - 60 }), jwks, accessExpected, now).iss, issuer);
});

test('algorithm/type extensions, unknown/duplicate kid, weak/private/non-signing keys and tampering fail', () => {
  for (const header of [{ alg: 'HS256' }, { typ: 'JWT' }, { kid: 'unknown' }, { crit: [] }, { b64: true }]) {
    assert.throws(() => verifyJwt(jwt(accessClaims, header), jwks, accessExpected, now));
  }
  for (const keys of [[jwk, jwk], [{ ...jwk, d: 'private' }], [{ ...jwk, alg: 'RS512' }],
    [{ ...jwk, use: 'enc' }], [{ ...jwk, key_ops: ['sign'] }], [{ ...jwk, kty: 'EC' }]]) {
    assert.throws(() => verifyJwt(jwt(), { keys }, accessExpected, now));
  }
  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' });
  assert.throws(() => verifyJwt(jwt(), { keys: [{ ...jwk, ...weak }] }, accessExpected, now));
  const token = jwt();
  const parts = token.split('.');
  parts[1] = Buffer.from(JSON.stringify({ ...accessClaims, sub: 'tampered' })).toString('base64url');
  assert.throws(() => verifyJwt(parts.join('.'), jwks, accessExpected, now));
});

test('response boundaries reject oversized, malformed, redirected and non-JSON bodies', async () => {
  assert.deepEqual(await readJson(new Response('{"ok":true}', { headers: { 'content-type': 'application/json' } })), { ok: true });
  for (const response of [new Response('{}', { headers: { 'content-type': 'text/html' } }),
    new Response('[]', { headers: { 'content-type': 'application/json' } }),
    new Response('{broken', { headers: { 'content-type': 'application/json' } }),
    new Response('{}', { status: 302, headers: { 'content-type': 'application/json' } }),
    new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': '1048577' } }),
    new Response(' '.repeat(1048577), { headers: { 'content-type': 'application/json' } })]) {
    await assert.rejects(readJson(response));
  }
  let observed;
  const result = await requestJson(`${issuer}/token`, {}, async (_url, options) => {
    observed = options;
    return new Response('{}', { headers: { 'content-type': 'application/json' } });
  });
  assert.equal(result.status, 200);
  assert.equal(observed.redirect, 'error');
  assert.ok(observed.signal instanceof AbortSignal);
});

test('replay success requires exact HTTP 400 invalid_grant, never arbitrary failure', () => {
  assert.doesNotThrow(() => assertInvalidGrant({ status: 400, data: { error: 'invalid_grant' } }));
  for (const result of [{ status: 200, data: { error: 'invalid_grant' } },
    { status: 503, data: { error: 'invalid_grant' } }, { status: 400, data: { error: 'invalid_request' } },
    { status: 401, data: { error: 'invalid_grant' } }, { status: 400, data: {} }]) {
    assert.throws(() => assertInvalidGrant(result));
  }
});
