import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, chmod, readFile, stat, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { enroll, enrollmentInvocation, writeEnrollmentReceipt } from './production-enrollment.mjs';

const issuer = 'https://auth.shocker.cl', client = 'eri-production-enrollment';
const callbackUri = 'http://127.0.0.1:8765/callback';
const metadata = { issuer, code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
  authorization_response_iss_parameter_supported: true, authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`, userinfo_endpoint: `${issuer}/discovered-userinfo` };
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const key = { ...publicKey.export({ format: 'jwk' }), kid: 'synthetic-key', alg: 'RS256', use: 'sig' };
const sensitiveSubject = 'synthetic-sensitive-subject';
function jwt(claims, typ) {
  const data = [Buffer.from(JSON.stringify({ alg: 'RS256', typ, kid: key.kid })).toString('base64url'),
    Buffer.from(JSON.stringify(claims)).toString('base64url')].join('.');
  return `${data}.${sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url')}`;
}
function fixture(change = {}) {
  let pending, authorization, calls = [];
  return {
    calls,
    async callback(transaction, expectedIssuer, show) {
      pending = transaction;
      assert.equal(expectedIssuer, issuer);
      show();
      assert.equal(authorization.searchParams.get('state'), pending.state);
      assert.equal(authorization.searchParams.get('nonce'), pending.nonce);
      assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
      assert.equal(authorization.searchParams.get('code_challenge'), createHash('sha256').update(pending.verifier).digest('base64url'));
      assert.equal(authorization.searchParams.get('client_id'), client);
      assert.equal(authorization.searchParams.get('redirect_uri'), callbackUri);
      assert.equal(authorization.searchParams.get('scope'), 'openid');
      assert.equal(authorization.searchParams.get('resource'), metadata.userinfo_endpoint);
      return { code: 'synthetic-code' };
    },
    showAuthorization(url) { authorization = new URL(url); },
    async request(url, options) {
      calls.push(url);
      if (url.endsWith('/.well-known/openid-configuration') || url.endsWith('/.well-known/oauth-authorization-server')) return { status: 200, data: { ...metadata, ...change.metadata } };
      if (url === metadata.jwks_uri) return { status: 200, data: { keys: [key] } };
      if (url === metadata.token_endpoint) {
        assert.equal(options.method, 'POST');
        assert.equal(options.body.get('code_verifier'), pending.verifier);
        assert.equal(options.body.get('code'), 'synthetic-code');
        assert.equal(options.body.get('grant_type'), 'authorization_code');
        assert.equal(options.body.get('client_id'), client);
        assert.equal(options.body.get('redirect_uri'), callbackUri);
        assert.equal(options.body.get('resource'), metadata.userinfo_endpoint);
        const now = Math.floor(Date.now() / 1000);
        const claims = { iss: issuer, sub: sensitiveSubject, iat: now, exp: now + 300 };
        return { status: 200, data: { token_type: 'Bearer', expires_in: 300,
          access_token: jwt({ ...claims, client_id: client, aud: metadata.userinfo_endpoint, ...change.access }, 'at+jwt'),
          id_token: jwt({ ...claims, aud: client, nonce: pending.nonce, ...change.id }, 'JWT'), ...change.tokens } };
      }
      if (url === metadata.userinfo_endpoint) {
        assert.match(options.headers.authorization, /^Bearer /);
        return { status: 200, data: { sub: sensitiveSubject, ...change.info } };
      }
      throw new Error('unexpected network destination');
    },
  };
}

test('one production code/PKCE exchange and UserInfo call use only exact discovered issuer endpoints', async () => {
  const io = fixture();
  const output = [];
  const originalLog = console.log, originalError = console.error;
  console.log = (...values) => output.push(values.join(' '));
  console.error = (...values) => output.push(values.join(' '));
  try { assert.equal(await enroll(io), undefined); }
  finally { console.log = originalLog; console.error = originalError; }
  assert.deepEqual(output, []);
  assert.deepEqual(io.calls, [`${issuer}/.well-known/openid-configuration`, `${issuer}/.well-known/oauth-authorization-server`,
    metadata.jwks_uri, metadata.token_endpoint, metadata.userinfo_endpoint]);
});

test('production flow fails closed on foreign metadata, token identity, audience, nonce, and renewable credentials', async () => {
  for (const change of [
    { metadata: { issuer: 'https://auth-staging.shocker.cl' } },
    { metadata: { userinfo_endpoint: 'https://balance.shocker.cl/api/me' } },
    { metadata: { code_challenge_methods_supported: ['plain'] } },
    { access: { client_id: 'foreign' } }, { access: { iss: 'https://foreign.invalid' } },
    { access: { aud: ['https://balance.shocker.cl/api', metadata.userinfo_endpoint] } },
    { id: { sub: 'different' } }, { id: { nonce: 'wrong' } }, { id: { aud: 'foreign' } },
    { info: { sub: 'different' } }, { tokens: { refresh_token: 'must-not-exist' } },
    { tokens: { expires_in: 301 } }, { tokens: { id_token: 'invalid.signature.token' } },
  ]) {
    let saved = false;
    await assert.rejects(enroll({ ...fixture(change), saveReceipt: () => { saved = true; } }));
    assert.equal(saved, false);
  }
});

test('invocation needs exact opt-in, SSH, interactive input and stderr, and explicit absolute receipt path', () => {
  assert.equal(enrollmentInvocation(['--production-enrollment'], true, true, 'ssh'), undefined);
  assert.equal(enrollmentInvocation(['--production-enrollment', '--receipt', '/private/receipt'], true, true, 'ssh'), '/private/receipt');
  for (const args of [[], ['--issuer', issuer], ['--production-enrollment', '--receipt', 'relative'], ['--production-enrollment', '--receipt'], ['--production-enrollment', '--unknown'], ['--production-enrollment', 'extra']]) assert.throws(() => enrollmentInvocation(args, true, true, 'ssh'));
  for (const [input, stderr, ssh] of [[false,true,'ssh'], [true,false,'ssh'], [true,true,undefined]]) assert.throws(() => enrollmentInvocation(['--production-enrollment'], input, stderr, ssh));
  const cli = spawnSync(process.execPath, ['scripts/production-enrollment.mjs', '--production-enrollment'], { encoding: 'utf8', env: { ...process.env, SSH_CONNECTION: 'synthetic' } });
  assert.equal(cli.status, 1);
  assert.equal(cli.stdout, 'FAIL enrollment\n');
  assert.equal(cli.stderr, '');
});

test('receipt is private, exclusive, rejects symlinks/insecure parent and contains only identity association fields', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'eri-enrollment-test-'));
  try {
    await chmod(directory, 0o700);
    const path = join(directory, 'receipt.json');
    const io = fixture();
    assert.equal(await enroll({ ...io, receipt: path }), undefined);
    const record = JSON.parse(await readFile(path, 'utf8'));
    assert.deepEqual(Object.keys(record).sort(), ['client','issuer','sub','timestamp']);
    assert.equal(record.sub, sensitiveSubject);
    assert.equal(record.issuer, issuer);
    assert.equal(record.client, client);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    const original = await readFile(path, 'utf8');
    await assert.rejects(writeEnrollmentReceipt(path, 'replacement'));
    assert.equal(await readFile(path, 'utf8'), original);
    const link = join(directory, 'link');
    await symlink(path, link);
    await assert.rejects(writeEnrollmentReceipt(link, 'replacement'));
    const alias = directory + '-alias';
    await symlink(directory, alias);
    try { await assert.rejects(writeEnrollmentReceipt(join(alias, 'new'), sensitiveSubject)); }
    finally { await rm(alias); }
    await chmod(directory, 0o755);
    const insecure = fixture();
    await assert.rejects(enroll({ ...insecure, receipt: join(directory, 'insecure') }));
    assert.deepEqual(insecure.calls, []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
