#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, realpath } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

const execute = promisify(execFile);
const ISSUER = 'https://auth-staging.shocker.cl';
const ORIGIN = 'http://127.0.0.1:8092';
const requireThat = (ok) => { if (!ok) throw new Error('RSS diagnostic failed'); };

export function parsePid(text) {
  requireThat(typeof text === 'string' && /^[1-9]\d*\n?$/.test(text));
  const pid = Number(text.trim());
  requireThat(Number.isSafeInteger(pid));
  return pid;
}

export function executablePolicy(path) {
  const match = /^\/opt\/eri-staging\/releases\/([0-9a-f]{40})\/eri$/.exec(path);
  requireThat(match !== null);
  return match[1];
}

export function parseStartTime(text, pid) {
  // comm may contain spaces and parentheses. Field 22 follows the last ') '.
  const end = text.lastIndexOf(') ');
  requireThat(text.startsWith(`${pid} (`) && end > 0);
  const fields = text.slice(end + 2).trim().split(/\s+/);
  requireThat(fields.length >= 20 && /^[A-Za-z]$/.test(fields[0]) && /^[1-9]\d*$/.test(fields[19]));
  return fields[19]; // preserve exact ticks without floating-point conversion
}

export function parseRss(text) {
  const matches = [...text.matchAll(/^VmRSS:\s+(\d+) kB\s*$/gm)];
  requireThat(matches.length === 1);
  const bytes = Number(matches[0][1]) * 1024;
  requireThat(Number.isSafeInteger(bytes) && bytes > 0);
  return bytes;
}

export function percentile(values, p) {
  requireThat(values.length > 0 && p > 0 && p <= 100 && values.every((v) => Number.isSafeInteger(v) && v > 0));
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.ceil(sorted.length * p / 100) - 1];
}

function sameIdentity(a, b) {
  requireThat(a.pid === b.pid && a.startTime === b.startTime && a.executable === b.executable);
}

export async function serviceSnapshot() {
  const { stdout } = await execute('systemctl', ['show', '--property=MainPID', '--value', 'eri-staging.service'],
    { timeout: 2000, maxBuffer: 1024, encoding: 'utf8' });
  const pid = parsePid(stdout);
  const executable = await realpath(`/proc/${pid}/exe`);
  const source = executablePolicy(executable);
  const before = parseStartTime(await readFile(`/proc/${pid}/stat`, 'utf8'), pid);
  const rss = parseRss(await readFile(`/proc/${pid}/status`, 'utf8'));
  const after = parseStartTime(await readFile(`/proc/${pid}/stat`, 'utf8'), pid);
  requireThat(before === after);
  return { pid, executable, source, startTime: after, rss };
}

export async function workloadRequest(path, remainingMs, fetcher = fetch) {
  requireThat(['/jwks', '/.well-known/openid-configuration'].includes(path) && remainingMs > 0);
  const response = await fetcher(`${ORIGIN}${path}`, { redirect: 'error',
    signal: AbortSignal.timeout(Math.max(1, Math.floor(Math.min(2000, remainingMs)))), headers: { accept: 'application/json' } });
  requireThat(response.status === 200 && !response.redirected);
  requireThat((response.headers.get('content-type') ?? '').split(';')[0].trim() === 'application/json');
  const length = response.headers.get('content-length');
  if (length !== null) requireThat(/^\d+$/.test(length) && Number(length) <= 1024 * 1024);
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      requireThat(bytes <= 1024 * 1024);
      chunks.push(value);
    }
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    requireThat(data !== null && typeof data === 'object' && !Array.isArray(data));
    if (path === '/.well-known/openid-configuration') {
      requireThat(data.issuer === ISSUER && data.jwks_uri === `${ISSUER}/jwks` && data.userinfo_endpoint === `${ISSUER}/userinfo`);
    } else {
      requireThat(Array.isArray(data.keys) && data.keys.length > 0 && data.keys.length <= 32);
      const seen = new Set();
      for (const key of data.keys) {
        requireThat(key?.kty === 'RSA' && key.alg === 'RS256' && key.use === 'sig' && typeof key.kid === 'string' && key.kid.length > 0 && !seen.has(key.kid));
        requireThat(typeof key.n === 'string' && typeof key.e === 'string');
        requireThat(!['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some((name) => name in key));
        seen.add(key.kid);
      }
    }
  } catch {
    await reader.cancel().catch(() => {});
    throw new Error('RSS workload failed');
  } finally { reader.releaseLock(); }
}

export async function measureWindow({ durationMs = 30000, sampleIntervalMs = 100, requestRate = 10 } = {}, deps = {}) {
  requireThat(Number.isInteger(durationMs) && durationMs >= 1000 && durationMs <= 120000);
  requireThat(Number.isInteger(sampleIntervalMs) && sampleIntervalMs >= 100 && sampleIntervalMs <= 1000);
  requireThat(Number.isInteger(requestRate) && requestRate >= 1 && requestRate <= 20);
  const snapshot = deps.snapshot ?? serviceSnapshot;
  const request = deps.request ?? workloadRequest;
  const now = deps.now ?? (() => performance.now());
  const sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const identity = await snapshot();
  executablePolicy(identity.executable);
  const start = now(), end = start + durationMs;
  let nextSample = start, nextRequest = start, successes = 0;
  const values = [];
  const sampleTimes = [];
  while (now() < end) {
    if (now() >= nextSample) {
      const current = await snapshot();
      sameIdentity(identity, current);
      requireThat(now() < end); // an overrun is incomplete evidence
      values.push(current.rss);
      sampleTimes.push(now() - start);
      nextSample += sampleIntervalMs;
      if (nextSample <= now()) nextSample = now() + sampleIntervalMs;
    }
    if (now() >= nextRequest) {
      await request(successes % 2 === 0 ? '/.well-known/openid-configuration' : '/jwks', end - now());
      requireThat(now() < end);
      successes++;
      nextRequest += 1000 / requestRate;
      if (nextRequest <= now()) nextRequest = now() + 1000 / requestRate;
    }
    const wait = Math.min(nextSample, nextRequest, end) - now();
    if (wait > 0) await sleep(wait);
  }
  const actualDurationMs = now() - start;
  requireThat(successes >= 2 && values.length >= 2);
  sameIdentity(identity, await snapshot()); // MainPID and process start ticks must still match
  const gaps = sampleTimes.slice(1).map((time, index) => time - sampleTimes[index]);
  return { diagnostic: 'eri-staging-rss', result: 'pass', source_sha: identity.source ?? executablePolicy(identity.executable),
    service: 'eri-staging.service', pid: identity.pid, process_start_ticks: identity.startTime,
    identity_stable: true, scope: 'eri_service_process_rss_under_loopback_discovery_jwks_workload',
    configured_duration_ms: durationMs, actual_duration_ms: actualDurationMs,
    configured_request_rate_per_second: requestRate, actual_request_rate_per_second: successes * 1000 / actualDurationMs,
    successful_requests: successes, request_errors: 0, configured_sampling_interval_ms: sampleIntervalMs,
    samples: values.length, actual_sampling_mean_interval_ms: gaps.reduce((a, b) => a + b, 0) / gaps.length,
    actual_sampling_max_interval_ms: Math.max(...gaps), p95_rss_bytes: percentile(values, 95), max_rss_bytes: Math.max(...values) };
}

async function main(args) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/staging-rss.mjs [--duration-seconds 30]');
    console.log('Only eri-staging.service, canonical release executable and loopback 127.0.0.1:8092.');
    return;
  }
  requireThat(args.length === 0 || (args.length === 2 && args[0] === '--duration-seconds' && /^\d+$/.test(args[1])));
  const durationMs = args.length ? Number(args[1]) * 1000 : 30000;
  console.log(JSON.stringify(await measureWindow({ durationMs })));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(() => { console.error('FAIL staging RSS diagnostic'); process.exitCode = 1; });
}
