// Screenshots the demo console started by serve.py, for the README.
//   npm install puppeteer-core@23      (once, inside docs/demo/)
//   node shoot.js ../assets/screenshots [page names...]
// Uses a locally installed Chromium browser; set BROWSER to override the path.
const puppeteer = require('puppeteer-core');
const fs = require('fs');
const BROWSER = process.env.BROWSER || [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
].find(p => fs.existsSync(p));
const BASE = 'http://127.0.0.1:8765';
const OUT = process.argv[2] || 'shots';
const only = process.argv.slice(3);

const PAGES = [
  { name: 'dashboard', path: '/', wait: 3500, h: 1180 },
  { name: 'device-detail', path: '/devices/3', wait: 3500, h: 1000 },
  { name: 'incidents', path: '/incidents', wait: 2500, h: 760 },
  { name: 'incident-detail', path: '/incidents/7', wait: 2500, h: 1000 },
  { name: 'filtering', path: '/filtering', wait: 3500, h: 900 },
  { name: 'settings', path: '/settings', wait: 2500, h: 700 },
  { name: 'mobile', path: '/', wait: 3500, mobile: true },
  { name: 'dashboard-light', path: '/', wait: 3500, h: 1180, theme: 'light' },
];

(async () => {
  const browser = await puppeteer.launch({
    executablePath: BROWSER,
    headless: 'new',
    args: ['--hide-scrollbars', '--no-first-run', '--disable-features=BraveRewards'],
  });
  for (const p of PAGES) {
    if (only.length && !only.includes(p.name)) continue;
    const page = await browser.newPage();
    // The console remembers its theme in localStorage, which every page in
    // this browser shares - so set it explicitly for each capture.
    await page.evaluateOnNewDocument(t => { try { localStorage.setItem('sp.theme', t); } catch (e) {} }, p.theme || 'dark');
    await page.authenticate({ username: 'securepi', password: 'demo' });
    if (p.mobile) await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 2, isMobile: true });
    else await page.setViewport({ width: 1440, height: p.h || 960, deviceScaleFactor: 2 });
    page.on('pageerror', e => console.log(p.name, 'PAGEERROR', e.message));
    page.on('console', m => { if (m.type() === 'error') console.log(p.name, 'CONSOLE', m.text()); });
    await page.goto(BASE + p.path, { waitUntil: 'networkidle0' });
    await new Promise(r => setTimeout(r, p.wait));
    const full = !!p.full;
    await page.screenshot({ path: `${OUT}/${p.name}.png`, fullPage: full });
    const h = await page.evaluate(() => document.documentElement.scrollHeight);
    console.log(p.name, 'ok height', h);
    await page.close();
  }
  await browser.close();
})();
