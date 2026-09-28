// Launch Chromium with the unpacked dist/chrome-e2e build and serve the demo agents on two origins.
import { chromium, type BrowserContext, type Page, type Worker } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
// @ts-expect-error — plain ESM helper without type declarations
import { startServers } from '../../demo/serve.mjs';

export interface Harness {
  context: BrowserContext;
  sw: Worker;
  extId: string;
  urls: [string, string];
  tabIdFor(page: Page): Promise<number>;
  popupFor(page: Page): Promise<Page>;
  close(): Promise<void>;
}

export async function launch(): Promise<Harness> {
  const extPath = resolve('dist/chrome-e2e');
  const profile = mkdtempSync(join(tmpdir(), 'tb-e2e-'));
  const servers = await startServers([0, 0]);
  const context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`],
  });
  let sw = context.serviceWorkers()[0];
  if (!sw) sw = await context.waitForEvent('serviceworker');
  const extId = new URL(sw.url()).host;

  async function tabIdFor(page: Page): Promise<number> {
    const url = page.url();
    const id = await sw.evaluate(async (u: string) => {
      const tabs = await chrome.tabs.query({});
      return tabs.find((t) => t.url === u)?.id ?? -1;
    }, url);
    if (id < 0) throw new Error(`no tab for ${url}`);
    return id;
  }

  async function popupFor(page: Page): Promise<Page> {
    const tabId = await tabIdFor(page);
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extId}/ui/popup.html?tabId=${tabId}`);
    return popup;
  }

  return {
    context,
    sw,
    extId,
    urls: servers.urls as [string, string],
    tabIdFor,
    popupFor,
    close: async () => {
      await context.close();
      await servers.close();
      rmSync(profile, { recursive: true, force: true });
    },
  };
}

export const tid = (id: string) => `[data-testid="${id}"]`;
