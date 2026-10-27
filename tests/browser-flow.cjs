const { chromium } = require(process.env.ERI_PLAYWRIGHT_MODULE || 'playwright');
const fs = require('node:fs/promises');
const path = require('node:path');

const [eriOrigin, clientOrigin, finalOrigin, upstreamOrigin] = process.argv.slice(2);
if (!eriOrigin || !clientOrigin || !finalOrigin || !upstreamOrigin) throw new Error('eri and client origins are required');

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 }, javaScriptEnabled: false });
    // All fixture origins, including the synthetic upstream, are loopback-only.
    await page.route('**/*', route => {
      const url = new URL(route.request().url());
      return url.protocol === 'http:' && url.hostname === '127.0.0.1' &&
        [eriOrigin, clientOrigin, finalOrigin, upstreamOrigin].includes(url.origin)
        ? route.continue() : route.abort();
    });
    const cspErrors = [];
    let lastPostStatus;
    let lastPostBody = '';
    let lastPostOrigin = '';
    const clientReferrers = [];
    const finalReferrers = [];
    const consentResponses = [];
    const formReferrers = [];
    const postOrigins = [];
    const capture = async name => {
      const directory = process.env.ERI_BROWSER_ARTIFACT_DIR;
      if (!directory) return;
      await fs.mkdir(directory, { recursive: true });
      await page.screenshot({ path: path.join(directory, `${name}.png`), fullPage: true });
    };
    page.on('console', message => {
      if (message.type() === 'error' && /content security policy/i.test(message.text())) {
        cspErrors.push(message.text());
      }
    });
    page.on('response', async response => {
      if (response.request().method() === 'POST') {
        lastPostStatus = response.status();
        lastPostBody = await response.text().catch(() => '');
        if (new URL(response.url()).pathname === '/consent') {
          const headers = response.headers();
          if (response.status() !== 200 || headers.location || headers['referrer-policy'] !== 'no-referrer' || headers['cache-control'] !== 'no-store') {
            throw new Error('consent completion must be a private 200 document without Location');
          }
          consentResponses.push(response);
        }
      }
    });
    page.on('request', request => {
      if (request.method() === 'POST') {
        lastPostOrigin = request.headers().origin || '';
        postOrigins.push(lastPostOrigin);
        formReferrers.push(request.headers().referer || '');
      }
      if (new URL(request.url()).origin === eriOrigin && new URL(request.url()).pathname === '/auth.css') {
        formReferrers.push(request.headers().referer || '');
      }
      if (new URL(request.url()).origin === finalOrigin) finalReferrers.push(request.headers().referer || '');
      if (new URL(request.url()).origin === clientOrigin) {
        clientReferrers.push(request.headers().referer || '');
      }
    });
    const authorize = new URL('/authorize', eriOrigin);
    authorize.search = new URLSearchParams({
      client_id: 'web',
      redirect_uri: `${clientOrigin}/callback-direct`,
      response_type: 'code',
      code_challenge_method: 'S256',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      scope: 'openid profile email offline_access',
      resource: 'https://api.example/resource',
      state: 'browser-state',
      nonce: 'browser-nonce',
    }).toString();
    await page.goto(authorize.toString());
    await page.getByRole('heading', { name: 'Balance' }).waitFor();
    await page.getByText('Recurso: https://api.example/resource').waitFor();
    const loginFitsMobile = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    if (!loginFitsMobile) throw new Error('login page overflows the mobile viewport');
    await capture('login-mobile');
    await page.getByRole('button', { name: 'Continuar con Google' }).click();
    try {
      await page.getByText('browser@example.test').waitFor({ timeout: 10000 });
    } catch (_) {
      const text = await page.locator('main').innerText().catch(() => 'no Eri page');
      throw new Error(`Google return did not reach consent: ${text.slice(0, 240)}; POST status ${lastPostStatus || 'unknown'}; Origin ${JSON.stringify(lastPostOrigin)}`);
    }
    const fitsMobile = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    if (!fitsMobile) throw new Error('consent page overflows the mobile viewport');
    await capture('consent-mobile');
    const consumedConsent = await page.locator('form').evaluate(form => new URLSearchParams(new FormData(form)).toString());
    try {
      await Promise.all([
        page.waitForURL(url => url.origin === clientOrigin && url.pathname === '/callback-direct', { timeout: 10000 }),
        page.getByRole('button', { name: 'Autorizar' }).click(),
      ]);
    } catch (_) {
      if (cspErrors.length) throw new Error(`CSP browser errors: ${cspErrors.join('\n')}`);
      const known = ['Origen inválido', 'Sesión inválida', 'La solicitud expiró', 'Solicitud inválida']
        .find(message => lastPostBody.includes(message)) || 'unknown response';
      throw new Error(`consent navigation failed after POST status ${lastPostStatus || 'unknown'}: ${known}; observed origin ${JSON.stringify(lastPostOrigin)}`);
    }
    if (!page.url().includes('code=') || !page.url().includes('state=browser-state')) {
      throw new Error('authorization callback omitted bound parameters');
    }

    const replay = await page.request.post(`${eriOrigin}/consent`, {
      headers: { origin: eriOrigin, 'content-type': 'application/x-www-form-urlencoded' },
      data: `${consumedConsent}&action=approve`,
    });
    if (replay.status() !== 400 || replay.headers().location || /http-equiv=refresh|<a href=/.test(await replay.text())) {
      throw new Error('consumed consent must fail locally without a second navigation');
    }

    // Same provider session, new grants: one click must survive callback ->
    // third-origin 303 for both successful consent and an explicit denial.
    authorize.searchParams.set('redirect_uri', `${clientOrigin}/callback`);
    for (const action of ['Autorizar', 'Denegar']) {
      await page.goto(authorize.toString());
      await page.getByText('browser@example.test').waitFor();
      await Promise.all([
        page.waitForURL(url => url.origin === finalOrigin && url.pathname === '/complete', { timeout: 10000 }),
        page.getByRole('button', { name: action, exact: true }).click(),
      ]);
      const params = new URL(page.url()).searchParams;
      if (params.get('state') !== 'browser-state' || params.get('iss') !== eriOrigin ||
          (action === 'Autorizar' ? !params.get('code') || params.has('error') : params.get('error') !== 'access_denied' || params.has('code'))) {
        throw new Error('chained callback lost the exact bound authorization response');
      }
    }
    // Disable only the refresh element in one synthetic response to exercise
    // the same escaped fallback link with page JavaScript still disabled.
    await page.route(`${eriOrigin}/consent`, async route => {
      const response = await route.fetch();
      const body = (await response.text()).replace(/<meta http-equiv=refresh content="[^"]*">/, '');
      await route.fulfill({ response, body });
    }, { times: 1 });
    await page.goto(authorize.toString());
    await page.getByRole('button', { name: 'Autorizar', exact: true }).click();
    await Promise.all([
      page.waitForURL(url => url.origin === finalOrigin && url.pathname === '/complete'),
      page.getByRole('link', { name: 'Volver a la aplicación', exact: true }).click(),
    ]);
    const fallbackParams = new URL(page.url()).searchParams;
    if (!fallbackParams.get('code') || fallbackParams.get('state') !== 'browser-state' || fallbackParams.get('iss') !== eriOrigin) {
      throw new Error('fallback link lost the bound authorization response');
    }
    if (consentResponses.length !== 4 || finalReferrers.length !== 3 || finalReferrers.some(Boolean)) {
      throw new Error('consent did not complete once per click or leaked its referrer');
    }
    authorize.searchParams.set('redirect_uri', `${clientOrigin}/callback-direct`);

    const logout = new URL('/logout', eriOrigin);
    logout.search = new URLSearchParams({
      client_id: 'web',
      post_logout_redirect_uri: `${clientOrigin}/signed-out`,
      state: 'signed-out-state',
    }).toString();
    await page.goto(logout.toString());
    await capture('logout-mobile');
    await Promise.all([
      page.waitForURL(url => url.origin === clientOrigin && url.pathname === '/signed-out'),
      page.getByRole('button', { name: 'Cerrar sesión' }).click(),
    ]);
    if (!page.url().includes('state=signed-out-state')) {
      throw new Error('logout callback omitted state');
    }
    await page.goto(authorize.toString());
    await page.getByRole('heading', { name: 'Balance' }).waitFor();
    await Promise.all([
      page.waitForURL(url => url.origin === clientOrigin && url.pathname === '/callback-direct'),
      page.getByRole('button', { name: 'Cancelar' }).click(),
    ]);
    if (!page.url().includes('error=access_denied') || !page.url().includes('state=browser-state')) {
      throw new Error('cancellation omitted the bound client error or state');
    }
    if (clientReferrers.some(value => value && value !== `${eriOrigin}/`)) {
      throw new Error('cross-origin navigation disclosed more than the Eri origin');
    }
    if (formReferrers.some(value => value && value !== `${eriOrigin}/`)) {
      throw new Error('form or stylesheet request disclosed a sensitive referrer path');
    }
    if (postOrigins.length !== 7 || postOrigins.some(value => value !== eriOrigin)) {
      throw new Error('browser forms did not preserve the exact Eri Origin');
    }
    if (cspErrors.length) throw new Error(`CSP browser errors: ${cspErrors.join('\n')}`);
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
