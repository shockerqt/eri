#!/usr/bin/env node
// Explicit operator-only enrollment; no Balance calls or credential persistence.
import { constants } from 'node:fs';
import { open, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateMetadata, transaction, oauthRequestBuilder, requestJson, listenForCallback,
  verifyJwt } from './staging-oauth-smoke.mjs';

const ISSUER = 'https://auth.shocker.cl';
const CLIENT = 'eri-production-enrollment';
const CALLBACK = 'http://127.0.0.1:8765/callback';
const check = value => { if (!value) throw new Error('enrollment check failed'); };

export function enrollmentInvocation(args, inputTTY, errorTTY, sshConnection) {
  check(inputTTY && errorTTY && typeof sshConnection === 'string' && sshConnection.length > 0);
  check(args[0] === '--production-enrollment' && (args.length === 1 ||
    (args.length === 3 && args[1] === '--receipt' && isAbsolute(args[2]))));
  return args[2];
}

export async function validateReceiptPath(path) {
  check(isAbsolute(path) && path === resolve(path));
  const parent = dirname(path);
  check(await realpath(parent) === parent);
  const info = await stat(parent);
  check(info.isDirectory() && (info.mode & 0o777) === 0o700 && info.uid === process.getuid());
}

export async function writeEnrollmentReceipt(path, subject, timestamp = new Date().toISOString()) {
  await validateReceiptPath(path);
  check(typeof subject === 'string' && subject.length > 0 && subject.length <= 255 && subject.trim() === subject);
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(JSON.stringify({ issuer: ISSUER, client: CLIENT, sub: subject, timestamp }) + '\n');
    await file.sync();
  } finally { await file.close(); }
}

// Compose the existing bounded metadata, callback and JWT helpers. Injected I/O
// permits synthetic tests without real enrollment or public network requests.
export async function enroll({ request = requestJson, callback = listenForCallback,
  showAuthorization, receipt, saveReceipt = writeEnrollmentReceipt } = {}) {
  if (receipt !== undefined) await validateReceiptPath(receipt);
  const oidc = await request(`${ISSUER}/.well-known/openid-configuration`);
  const as = await request(`${ISSUER}/.well-known/oauth-authorization-server`);
  check(oidc.status === 200 && as.status === 200);
  const endpoints = validateMetadata(oidc.data, ISSUER);
  const other = validateMetadata(as.data, ISSUER);
  check(Object.keys(endpoints).every(name => endpoints[name] === other[name]));
  const keys = await request(endpoints.jwks_uri);
  check(keys.status === 200);
  const pending = transaction();
  const requests = oauthRequestBuilder(endpoints, { client: CLIENT, callback: CALLBACK, scope: 'openid' });
  const result = await callback(pending, ISSUER, () => showAuthorization(requests.authorization(pending).href));
  check(typeof result.code === 'string' && result.code.length > 0);
  const tokens = await request(endpoints.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: requests.token({ grant_type: 'authorization_code', code: result.code,
      redirect_uri: CALLBACK, code_verifier: pending.verifier }),
  });
  check(tokens.status === 200 && tokens.data.token_type === 'Bearer' &&
    !('refresh_token' in tokens.data) && Number.isSafeInteger(tokens.data.expires_in) &&
    tokens.data.expires_in > 0 && tokens.data.expires_in <= 300);
  const access = verifyJwt(tokens.data.access_token, keys.data, {
    typ: 'at+jwt', issuer: ISSUER, client: CLIENT, audiences: [endpoints.userinfo_endpoint],
  });
  check((Array.isArray(access.aud) ? access.aud : [access.aud]).length === 1 &&
    access.exp - access.iat <= 300);
  const id = verifyJwt(tokens.data.id_token, keys.data, {
    typ: 'JWT', issuer: ISSUER, client: CLIENT, audiences: [CLIENT], nonce: pending.nonce,
  });
  check(id.sub === access.sub);
  const info = await request(endpoints.userinfo_endpoint, {
    headers: { authorization: `Bearer ${tokens.data.access_token}`, accept: 'application/json' },
  });
  check(info.status === 200 && info.data.sub === access.sub);
  if (receipt !== undefined) await saveReceipt(receipt, access.sub);
}

async function main(args) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/production-enrollment.mjs --production-enrollment [--receipt /private/path]');
    console.log('Requires an interactive SSH terminal; see docs/production-enrollment.md.');
    return;
  }
  try {
    const receipt = enrollmentInvocation(args, process.stdin.isTTY, process.stderr.isTTY, process.env.SSH_CONNECTION);
    await enroll({ receipt, showAuthorization: url => {
      process.stderr.write('Open this transient URL in your local browser; do not copy it into chat or logs:\n');
      process.stderr.write(url + '\n');
    } });
    console.log('PASS enrollment');
  } catch {
    // Never print exceptions, response bodies, claims, identity or credentials.
    console.log('FAIL enrollment');
    process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main(process.argv.slice(2));
