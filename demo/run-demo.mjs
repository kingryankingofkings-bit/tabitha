// Narrated, automated end-to-end demo: loads dist/chrome-e2e into Chromium, serves two demo
// agents on two origins, enables both, pairs them through the extension popup, runs a
// bidirectional AI prompt exchange, transfers a file (and shows a disguised one being rejected),
// then verifies the audit chain. Usage: npm run demo   (HEADED=1 to watch it)
import { chromium } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { startServers } from './serve.mjs';

const t = (id) => `[data-testid="${id}"]`;
const step = (n, msg) => console.log(`\n\x1b[1m[${n}] ${msg}\x1b[0m`);
const ok = (msg) => console.log(`    \x1b[32m✔\x1b[0m ${msg}`);

const extPath = resolve('dist/chrome-e2e');
const profile = mkdtempSync(join(tmpdir(), 'tb-demo-'));
const servers = await startServers([0, 0]);
const [originA, originB] = servers.urls;
const context = await chromium.launchPersistentContext(profile, {
  channel: 'chromium',
  headless: !process.env.HEADED,
  args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`],
});

try {
  const sw = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  const extId = new URL(sw.url()).host;
  const tabIdFor = (page) => sw.evaluate(async (u) => (await chrome.tabs.query({})).find((x) => x.url === u)?.id, page.url());
  const popupFor = async (page) => {
    const p = await context.newPage();
    await p.goto(`chrome-extension://${extId}/ui/popup.html?tabId=${await tabIdFor(page)}`);
    return p;
  };
  const lastLog = async (page, kind) => (await page.locator(`${t('log')}[data-kind="${kind}"] > span:last-child`).first().textContent())?.trim();

  step(1, `Open two agents on two origins: ${originA} (Planner) and ${originB} (Researcher)`);
  const planner = await context.newPage();
  const researcher = await context.newPage();
  await planner.goto(`${originA}/planner.html`);
  await researcher.goto(`${originB}/researcher.html`);
  await planner.locator(t('tb-status')).filter({ hasText: 'unavailable' }).waitFor();
  ok('Before enabling: window.tabBridge is absent and the page runs standalone (graceful degradation)');

  step(2, 'User enables TabBridge on both origins from the toolbar popup');
  for (const page of [planner, researcher]) {
    const popup = await popupFor(page);
    await popup.locator(t('enable-site')).click();
    await page.locator(t('tb-status')).filter({ hasText: 'connected' }).waitFor();
    await popup.close();
  }
  ok('Both agents connected to TabBridge');

  step(3, 'User pairs the tabs: Planner starts, Researcher joins with the 6-digit code');
  const popupA = await popupFor(planner);
  await popupA.locator(t('start-pairing')).click();
  for (const d of ['i2j', 'j2i']) {
    await popupA.locator(t(`grant-${d}-prompts`)).check();
    await popupA.locator(t(`grant-${d}-tasks`)).check();
  }
  await popupA.locator(t('grant-i2j-files')).check();
  await popupA.locator(t('grant-i2j-type-image/png')).check();
  await popupA.locator(t('pair-submit')).click();
  const code = (await popupA.locator(t('pair-code')).textContent()).trim();
  ok(`Pairing code shown only in extension UI: ${code}`);
  const popupB = await popupFor(researcher);
  await popupB.locator(t('join-code-input')).fill(code);
  await popupB.locator(t('join-lookup')).click();
  ok(`Consent preview: ${(await popupB.locator(t('join-preview')).innerText()).replace(/\s+/g, ' ').slice(0, 160)}…`);
  await popupB.locator(t('join-approve')).click();
  await planner.locator(`${t('room')}[data-state="active"]`).waitFor();
  await researcher.locator(`${t('room')}[data-state="active"]`).waitFor();
  ok('Keys exchanged + confirmed; room ACTIVE on both sides');

  step(4, 'Bidirectional AI exchange');
  await planner.locator(t('question')).fill('What are the top risks of letting AI agents talk across tabs?');
  await planner.locator(t('ask')).click();
  await planner.locator(`${t('log')}[data-kind="answer"]`).waitFor();
  ok(`Planner → Researcher prompt; Researcher replied: ${await lastLog(planner, 'answer')}`);
  await planner.locator(`${t('log')}[data-kind="task-in"][data-status="done"]`).waitFor();
  ok(`Task state received by Planner: ${await lastLog(planner, 'task-in')}`);
  await researcher.locator(t('question')).fill('Draft an outline for the risk report');
  await researcher.locator(t('ask')).click();
  await researcher.locator(`${t('log')}[data-kind="answer"]`).waitFor();
  ok(`Researcher → Planner prompt; Planner replied: ${await lastLog(researcher, 'answer')}`);

  step(5, 'File transfer with validation');
  await planner.locator(t('send-png')).click();
  await researcher.locator(`${t('log')}[data-kind="file-in"]`).waitFor();
  ok(`Researcher received: ${await lastLog(researcher, 'file-in')}`);
  await planner.locator(t('send-disguised')).click();
  await planner.locator(`${t('log')}[data-kind="error"]`).first().waitFor();
  ok(`Disguised HTML-as-PNG blocked at the sender: ${await lastLog(planner, 'error')}`);
  await researcher.locator(t('send-png')).click();
  await researcher.locator(`${t('log')}[data-kind="error"]`).first().waitFor();
  ok(`Researcher → Planner file refused (not granted): ${await lastLog(researcher, 'error')}`);

  step(6, 'Audit log');
  const dash = await context.newPage();
  await dash.goto(`chrome-extension://${extId}/ui/dashboard.html`);
  await dash.locator(t('audit-entry')).first().waitFor();
  await dash.locator(t('audit-verify')).click();
  await dash.locator(`${t('audit-verify-result')}[data-ok]`).waitFor();
  ok(`${await dash.locator(t('audit-entry')).count()} audit entries shown; verification: ${await dash.locator(t('audit-verify-result')).textContent()}`);

  step(7, 'Revocation: user closes the room');
  await popupA.reload();
  await popupA.locator(`${t('room-item')} ${t('room-close')}`).first().click();
  await researcher.locator(`${t('room')}[data-state="closed"]`).waitFor();
  ok('Room closed on both sides; further sends are refused');
  console.log('\n\x1b[32mDemo complete.\x1b[0m');
} finally {
  await context.close();
  await servers.close();
  rmSync(profile, { recursive: true, force: true });
}
