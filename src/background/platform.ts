// Chrome / Firefox glue implementing RouterPlatform, plus storage adapters. SPEC.md §5, §14, §15.
// Browser-only; not unit tested. Everything here fails soft (logs) except where the router must
// know about a failure (hasHostPermission → false fails closed).

import { ext } from '../platform/ext';
import type { AuditPersisted, AuditStore, KeyValueStore, SenderInfo, Settings } from '../shared/types';
import type { RouterPlatform } from './router';

export const SETTINGS_KEY = 'tb.settings';
export const AUDIT_KEY = 'tb.audit';
export const SCRIPT_ID_ISOLATED = 'tb-isolated';
export const SCRIPT_ID_MAIN = 'tb-main';
export const ISOLATED_JS = 'content/isolated.js';
export const PAGE_API_JS = 'content/page-api.js';

function warn(what: string, e: unknown): void {
  try {
    console.warn(`[tabbridge] ${what}:`, e instanceof Error ? e.message : e);
  } catch {
    /* ignore */
  }
}

/** Normalizes runtime.Port.sender. Identity is only ever taken from here, never from messages. */
export function toSenderInfo(sender: chrome.runtime.MessageSender | undefined): SenderInfo {
  const out: SenderInfo = {};
  if (!sender) return out;
  const tabId = sender.tab?.id;
  if (typeof tabId === 'number') out.tabId = tabId;
  if (typeof sender.frameId === 'number') out.frameId = sender.frameId;
  if (typeof sender.url === 'string') out.url = sender.url;
  const origin = (sender as { origin?: unknown }).origin;
  if (typeof origin === 'string') out.origin = origin;
  if (typeof sender.id === 'string') out.extensionId = sender.id;
  const title = sender.tab?.title;
  if (typeof title === 'string') out.tabTitle = title;
  return out;
}

/**
 * `scheme://host/*` for an http(s) origin. Match patterns cannot express ports, so the router
 * re-checks the exact origin (incl. port) at hello (DECISIONS T1 / OSQ-1).
 */
export function matchPattern(origin: string): string {
  const u = new URL(origin);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new TypeError('matchPattern: http(s) origin required');
  return `${u.protocol}//${u.hostname}/*`;
}

function safeMatchPattern(origin: string): string | null {
  try {
    return matchPattern(origin);
  } catch {
    return null;
  }
}

/** storage.session (or any StorageArea) as a KeyValueStore. */
export class ChromeKV implements KeyValueStore {
  constructor(private readonly area: chrome.storage.StorageArea) {}
  async get<T>(key: string): Promise<T | undefined> {
    const got = (await this.area.get(key)) as Record<string, unknown>;
    return got[key] as T | undefined;
  }
  async set(key: string, value: unknown): Promise<void> {
    await this.area.set({ [key]: value });
  }
}

/** Audit log persistence: storage.local "tb.audit". */
export class ChromeAuditStore implements AuditStore {
  constructor(private readonly area: chrome.storage.StorageArea = ext.storage.local) {}
  async load(): Promise<AuditPersisted | undefined> {
    const got = (await this.area.get(AUDIT_KEY)) as Record<string, unknown>;
    return got[AUDIT_KEY] as AuditPersisted | undefined;
  }
  async save(p: AuditPersisted): Promise<void> {
    await this.area.set({ [AUDIT_KEY]: p });
  }
}

export async function loadSettings(): Promise<Settings | undefined> {
  const got = (await ext.storage.local.get(SETTINGS_KEY)) as Record<string, unknown>;
  return got[SETTINGS_KEY] as Settings | undefined; // router re-validates
}

export async function saveSettings(s: Settings): Promise<void> {
  await ext.storage.local.set({ [SETTINGS_KEY]: s });
}

function scriptDefs(matches: string[]): chrome.scripting.RegisteredContentScript[] {
  return [
    {
      id: SCRIPT_ID_ISOLATED,
      js: [ISOLATED_JS],
      matches,
      runAt: 'document_start',
      allFrames: false,
      persistAcrossSessions: true,
      world: 'ISOLATED',
    },
    {
      id: SCRIPT_ID_MAIN,
      js: [PAGE_API_JS],
      matches,
      runAt: 'document_start',
      allFrames: false,
      persistAcrossSessions: true,
      world: 'MAIN',
    },
  ];
}

/** (Re)registers both content scripts for exactly `sites`; unregisters them when empty. */
export async function syncContentScripts(sites: string[]): Promise<void> {
  const matches = [...new Set(sites.map(safeMatchPattern).filter((m): m is string => m !== null))];
  const ids = [SCRIPT_ID_ISOLATED, SCRIPT_ID_MAIN];
  let existing: string[] = [];
  try {
    existing = (await ext.scripting.getRegisteredContentScripts({ ids })).map((s) => s.id);
  } catch (e) {
    warn('getRegisteredContentScripts failed', e);
  }
  if (matches.length === 0) {
    if (existing.length === 0) return;
    try {
      await ext.scripting.unregisterContentScripts({ ids: existing });
    } catch (e) {
      warn('unregisterContentScripts failed', e);
    }
    return;
  }
  const defs = scriptDefs(matches);
  try {
    const toUpdate = defs.filter((d) => existing.includes(d.id));
    const toRegister = defs.filter((d) => !existing.includes(d.id));
    if (toUpdate.length) await ext.scripting.updateContentScripts(toUpdate);
    if (toRegister.length) await ext.scripting.registerContentScripts(toRegister);
  } catch (e) {
    // Fall back to a clean re-registration (e.g. a stale registration from an older version).
    warn('content script update failed; re-registering', e);
    try {
      await ext.scripting.unregisterContentScripts({ ids });
    } catch {
      /* none registered */
    }
    try {
      await ext.scripting.registerContentScripts(defs);
    } catch (e2) {
      warn('registerContentScripts failed', e2);
    }
  }
}

/** Injects both scripts into already-open top frames whose exact origin is `origin`. */
export async function injectIntoOpenTabs(origin: string): Promise<void> {
  const pattern = safeMatchPattern(origin);
  if (!pattern) return;
  let tabs: chrome.tabs.Tab[] = [];
  try {
    tabs = await ext.tabs.query({ url: pattern });
  } catch (e) {
    warn('tabs.query failed', e);
    return;
  }
  await Promise.all(
    tabs.map(async (tab) => {
      if (typeof tab.id !== 'number' || typeof tab.url !== 'string') return;
      let tabOrigin: string;
      try {
        tabOrigin = new URL(tab.url).origin;
      } catch {
        return;
      }
      if (tabOrigin !== origin) return; // match patterns ignore ports
      const target = { tabId: tab.id, frameIds: [0] };
      try {
        await ext.scripting.executeScript({ target, files: [ISOLATED_JS], world: 'ISOLATED' });
        await ext.scripting.executeScript({ target, files: [PAGE_API_JS], world: 'MAIN' });
      } catch {
        /* tab may be discarded, navigating, or a privileged page: ignore */
      }
    }),
  );
}

export async function hasHostPermission(origin: string): Promise<boolean> {
  const pattern = safeMatchPattern(origin);
  if (!pattern) return false;
  try {
    return await ext.permissions.contains({ origins: [pattern] });
  } catch (e) {
    warn('permissions.contains failed', e);
    return false;
  }
}

export function setBadge(tabId: number, text: string): void {
  try {
    const action = ext.action;
    void action.setBadgeText({ tabId, text }).catch(() => undefined);
    if (text) void action.setBadgeBackgroundColor({ tabId, color: '#B45309' }).catch(() => undefined);
  } catch {
    /* tab gone */
  }
}

/** `chrome-extension://<id>` / `moz-extension://<uuid>` without trailing slash. */
export function extensionOrigin(): string {
  return ext.runtime.getURL('').replace(/\/+$/, '');
}

export function createPlatform(): RouterPlatform {
  return {
    extensionOrigin: extensionOrigin(),
    extensionId: ext.runtime.id,
    hasHostPermission,
    syncContentScripts,
    injectIntoOpenTabs,
    setBadge,
    loadSettings,
    saveSettings,
  };
}
