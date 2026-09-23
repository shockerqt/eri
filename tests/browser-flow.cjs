const { chromium } = require(process.env.ERI_PLAYWRIGHT_MODULE || 'playwright');
const fs = require('node:fs/promises');
const path = require('node:path');

const [eriOrigin, clientOrigin] = process.argv.slice(2);
if (!eriOrigin || !clientOrigin) throw new Error('eri and client origins are required');

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    const cspErrors = [];
    let lastPostStatus;
    let lastPostBody = '';
    let lastPostOrigin = '';
    const clientReferrers = [];
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
      if (new URL(request.url()).origin === clientOrigin) {
        clientReferrers.push(request.headers().referer || '');
      }
    });
    const authorize = new URL('/authorize', eriOrigin);
    authorize.search = new URLSearchParams({
      client_id: 'web',
      redirect_uri: `${clientOrigin}/callback`,
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
    try {
      await Promise.all([
        page.waitForURL(url => url.origin === clientOrigin && url.pathname === '/callback', { timeout: 10000 }),
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
      page.waitForURL(url => url.origin === clientOrigin && url.pathname === '/callback'),
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
    if (postOrigins.length !== 4 || postOrigins.some(value => value !== eriOrigin)) {
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
