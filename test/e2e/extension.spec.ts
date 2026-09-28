// End-to-end: two demo agents on two origins pair through extension UI, hold a bidirectional
// conversation, exchange task state and a validated file, and the audit chain verifies.
import { expect, test } from '@playwright/test';
import { launch, tid, type Harness } from './harness';

let h: Harness;

test.beforeAll(async () => {
  h = await launch();
});
test.afterAll(async () => {
  await h?.close();
});

test('pair two tabs, converse both ways, transfer a validated file, verify audit', async () => {
  const { context, urls } = h;
  const planner = await context.newPage();
  const researcher = await context.newPage();
  await planner.goto(`${urls[0]}/planner.html`);
  await researcher.goto(`${urls[1]}/researcher.html`);

  // AC1: not enabled → API absent, page degrades gracefully.
  await expect(planner.locator(tid('tb-status'))).toHaveText('unavailable');
  expect(await planner.evaluate(() => typeof (window as { tabBridge?: unknown }).tabBridge)).toBe('undefined');

  // Enable both origins from the popup (targets the page tab via ?tabId).
  for (const page of [planner, researcher]) {
    const popup = await h.popupFor(page);
    await expect(popup.locator(tid('site-status'))).toHaveText('disabled');
    await popup.locator(tid('enable-site')).click();
    await expect(popup.locator(tid('site-status'))).toHaveText('enabled');
    await expect(page.locator(tid('tb-status'))).toHaveText('connected'); // injected into the open tab
    await expect(popup.locator(tid('endpoint-status'))).toContainText('connected');
    await popup.close();
  }

  // Initiator (planner): choose permissions, get code.
  const popupA = await h.popupFor(planner);
  await popupA.locator(tid('start-pairing')).click();
  for (const dir of ['i2j', 'j2i']) {
    await popupA.locator(tid(`grant-${dir}-prompts`)).check();
    await popupA.locator(tid(`grant-${dir}-tasks`)).check();
  }
  await popupA.locator(tid('grant-i2j-files')).check();
  await popupA.locator(tid('grant-i2j-type-image/png')).check();
  await popupA.locator(tid('pair-submit')).click();
  const code = (await popupA.locator(tid('pair-code')).textContent())?.trim() ?? '';
  expect(code).toMatch(/^\d{6}$/);

  // Joiner (researcher): enter code, review both origins, approve.
  const popupB = await h.popupFor(researcher);
  await popupB.locator(tid('join-code-input')).fill(code);
  await popupB.locator(tid('join-lookup')).click();
  const preview = popupB.locator(tid('join-preview'));
  await expect(preview).toContainText(urls[0]);
  await expect(preview).toContainText(urls[1]);
  await popupB.locator(tid('join-approve')).click();

  // Both agents see an active room.
  await expect(planner.locator(`${tid('room')}[data-state="active"]`)).toHaveCount(1);
  await expect(researcher.locator(`${tid('room')}[data-state="active"]`)).toHaveCount(1);

  // Planner asks → researcher's agent replies (plus task updates) → ask() resolves.
  await planner.locator(tid('question')).fill('Summarize cross-tab agent risks');
  await planner.locator(tid('ask')).click();
  await expect(researcher.locator(`${tid('log')}[data-kind="prompt-in"]`)).toContainText('Summarize cross-tab agent risks');
  await expect(planner.locator(`${tid('log')}[data-kind="answer"]`)).toContainText('Research notes on "Summarize cross-tab agent risks"');
  await expect(planner.locator(`${tid('log')}[data-kind="task-in"][data-status="done"]`)).toHaveCount(1);

  // Reverse direction: researcher asks → planner replies.
  await researcher.locator(tid('question')).fill('Outline the report');
  await researcher.locator(tid('ask')).click();
  await expect(researcher.locator(`${tid('log')}[data-kind="answer"]`)).toContainText('Plan for "Outline the report"');

  // File transfer: planner → researcher PNG accepted with provenance.
  await planner.locator(tid('send-png')).click();
  const fileIn = researcher.locator(`${tid('log')}[data-kind="file-in"]`);
  await expect(fileIn).toContainText('chart.png');
  await expect(fileIn).toHaveAttribute('data-sha256', /^[0-9a-f]{64}$/);

  // Disguised HTML is rejected before it ever leaves the planner tab.
  await planner.locator(tid('send-disguised')).click();
  await expect(planner.locator(`${tid('log')}[data-kind="error"]`).first()).toHaveAttribute('data-code', /FILE_TYPE_(MISMATCH|DENIED)/);

  // Researcher was not granted file sending → NOT_PERMITTED.
  await researcher.locator(tid('send-png')).click();
  await expect(researcher.locator(`${tid('log')}[data-kind="error"]`).first()).toHaveAttribute('data-code', 'NOT_PERMITTED');

  // Audit log: entries present and the hash chain verifies.
  const dash = await context.newPage();
  await dash.goto(`chrome-extension://${h.extId}/ui/dashboard.html`);
  await expect(dash.locator(`${tid('audit-entry')}[data-type="frame.routed"]`).first()).toBeVisible();
  await expect(dash.locator(`${tid('audit-entry')}[data-type="content.received"]`).first()).toBeVisible();
  await dash.locator(tid('audit-verify')).click();
  await expect(dash.locator(tid('audit-verify-result'))).toHaveAttribute('data-ok', 'true');

  // Revocation: closing the room from the popup reaches both agents.
  await popupA.reload();
  await popupA.locator(`${tid('room-item')} ${tid('room-close')}`).first().click();
  await expect(planner.locator(`${tid('room')}[data-state="closed"]`)).toHaveCount(1);
  await expect(researcher.locator(`${tid('room')}[data-state="closed"]`)).toHaveCount(1);
});
