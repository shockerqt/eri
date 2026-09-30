import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePid, parseStartTime, parseRss, executablePolicy, percentile, measureWindow, workloadRequest } from './staging-rss.mjs';

const executable = `/opt/eri-staging/releases/${'a'.repeat(40)}/eri`;
const identity = { pid: 123, executable, startTime: '987654321', rss: 20 * 1024 * 1024 };
function fixtures(overrides = {}) {
  let clock = 0, calls = 0;
  const paths = [];
  return { paths, deps: { now: () => clock, sleep: async (ms) => { clock += ms; },
    snapshot: async () => ({ ...identity }), request: async (path, remainingMs) => {
      assert.ok(remainingMs > 0 && remainingMs <= 1000);
      paths.push(path); calls++;
      clock += 5;
    }, ...overrides }, advance: (ms) => { clock += ms; }, calls: () => calls };
}

test('process stat handles comm spaces and nested parentheses and preserves exact start ticks', () => {
  const tail = ['S', ...Array(18).fill('0'), '98765432109876543210', '0', '0'];
  assert.equal(parseStartTime(`123 (eri (worker) thread)) ${tail.join(' ')}\n`, 123), '98765432109876543210');
  for (const text of ['123 eri S 0', `124 (eri) ${tail.join(' ')}`, `123 (eri) ${tail.slice(0, 19).join(' ')}`, `123 (eri) ${[...tail.slice(0, 19), '-1'].join(' ')}`]) {
    assert.throws(() => parseStartTime(text, 123));
  }
});

test('only a canonical staging release executable and positive MainPID are accepted', () => {
  assert.equal(executablePolicy(executable), 'a'.repeat(40));
  for (const path of ['/opt/eri/current/eri', '/opt/eri-staging/current/eri', `${executable} (deleted)`,
    executable.replace('a'.repeat(40), 'A'.repeat(40)), executable.replace('/eri', '/eri-benchmark'), '/tmp/eri']) {
    assert.throws(() => executablePolicy(path));
  }
  assert.equal(parsePid('123\n'), 123);
  for (const value of ['0\n', '-1', '123\n456', ' 123', '1.2', '9007199254740993']) assert.throws(() => parsePid(value));
});

test('RSS parses Linux kB into bytes and refuses absent/duplicate/invalid counters', () => {
  assert.equal(parseRss('Name:\teri\nVmRSS:\t1234 kB\nThreads:\t2\n'), 1234 * 1024);
  for (const text of ['VmRSS: 0 kB\n', 'VmRSS: 123 MB\n', 'VmRSS: -1 kB\n',
    'VmRSS: 12 kB\nVmRSS: 13 kB\n', 'Name: eri\n']) assert.throws(() => parseRss(text));
});

test('nearest-rank percentile selects observed values and handles small windows', () => {
  assert.equal(percentile([90, 10, 20, 30], 95), 90);
  assert.equal(percentile(Array.from({ length: 100 }, (_, i) => i + 1), 95), 95);
  assert.throws(() => percentile([], 95));
});

test('window reports service RSS, exact identity, successful workload and observed timing', async () => {
  const f = fixtures();
  const result = await measureWindow({ durationMs: 1000 }, f.deps);
  assert.equal(result.p95_rss_bytes, identity.rss);
  assert.equal(result.max_rss_bytes, identity.rss);
  assert.equal(result.pid, identity.pid);
  assert.equal(result.source_sha, 'a'.repeat(40));
  assert.equal(result.actual_duration_ms, 1000);
  assert.equal(result.successful_requests, 10);
  assert.equal(result.request_errors, 0);
  assert.equal(result.samples, 10);
  assert.equal(result.actual_sampling_mean_interval_ms, 100);
  assert.deepEqual([...new Set(f.paths)], ['/.well-known/openid-configuration', '/jwks']);
});

test('restart or executable replacement invalidates the entire measurement', async () => {
  for (const mutation of [{ pid: 456 }, { startTime: '987654322' }, { executable: executable.replace('a'.repeat(40), 'b'.repeat(40)) }]) {
    let reads = 0;
    const f = fixtures({ snapshot: async () => ({ ...identity, ...(reads++ >= 3 ? mutation : {}) }) });
    await assert.rejects(measureWindow({ durationMs: 1000 }, f.deps));
  }
  // A change detected only by the final MainPID/start-time check also fails.
  let reads = 0;
  const f = fixtures({ snapshot: async () => ({ ...identity, ...(reads++ === 11 ? { pid: 456 } : {}) }) });
  await assert.rejects(measureWindow({ durationMs: 1000 }, f.deps));
});

test('failed HTTP request and deadline overrun cannot become successful partial evidence', async () => {
  const failed = fixtures({ request: async () => { throw new Error('synthetic HTTP failure'); } });
  await assert.rejects(measureWindow({ durationMs: 1000 }, failed.deps));
  const overrun = fixtures();
  overrun.deps.request = async () => { overrun.advance(1001); };
  await assert.rejects(measureWindow({ durationMs: 1000 }, overrun.deps));
  const badBounds = fixtures();
  await assert.rejects(measureWindow({ durationMs: 999 }, badBounds.deps));
});


test('HTTP workload requires exact staging metadata and bounded JSON without redirects', async () => {
  const metadata = { issuer: 'https://auth-staging.shocker.cl', jwks_uri: 'https://auth-staging.shocker.cl/jwks',
    userinfo_endpoint: 'https://auth-staging.shocker.cl/userinfo' };
  let options;
  const fetcher = async (url, given) => {
    assert.equal(url, 'http://127.0.0.1:8092/.well-known/openid-configuration');
    options = given;
    return new Response(JSON.stringify(metadata), { headers: { 'content-type': 'application/json' } });
  };
  await workloadRequest('/.well-known/openid-configuration', 200, fetcher);
  assert.equal(options.redirect, 'error');
  assert.ok(options.signal instanceof AbortSignal);
  for (const response of [new Response(JSON.stringify({ ...metadata, issuer: 'https://auth.shocker.cl' }), { headers: { 'content-type': 'application/json' } }),
    new Response('{}', { status: 503, headers: { 'content-type': 'application/json' } }),
    new Response('{}', { status: 302, headers: { 'content-type': 'application/json' } }),
    new Response('{}', { headers: { 'content-type': 'text/html' } }),
    new Response(' '.repeat(1048577), { headers: { 'content-type': 'application/json' } }),
    new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': '1048577' } })]) {
    await assert.rejects(workloadRequest('/.well-known/openid-configuration', 200, async () => response));
  }
  await assert.rejects(workloadRequest('/userinfo', 200, fetcher));
});
