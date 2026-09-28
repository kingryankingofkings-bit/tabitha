// Background entry (Chrome MV3 service worker / Firefox MV3 event page). SPEC.md §2, §5.1.
// MV3 requirement: every listener is registered synchronously at top level so a waking worker
// receives the event that woke it. The router queues anything that arrives before init() is done.
//
// Deliberately NOT registered: runtime.onConnectExternal / runtime.onMessageExternal (T15).
// storage.session keeps its default access level (TRUSTED_CONTEXTS): content scripts can't read it.

import { ext } from '../platform/ext';
import { randomBytes } from '../shared/encoding';
import { PORT_ENDPOINT, PORT_UI } from '../shared/limits';
import { AuditLog } from './audit';
import { ChromeAuditStore, ChromeKV, createPlatform, toSenderInfo } from './platform';
import { Router } from './router';

const SWEEP_ALARM = 'tb.sweep';

const logError = (e: unknown): void => {
  console.error('[tabbridge]', e instanceof Error ? e.message : e);
};

const platform = createPlatform();
const audit = new AuditLog({ store: new ChromeAuditStore(ext.storage.local), now: () => Date.now() });
const router = new Router({
  session: new ChromeKV(ext.storage.session),
  audit,
  platform,
  now: () => Date.now(),
  randomBytes,
});

ext.runtime.onConnect.addListener((port) => {
  const sender = toSenderInfo(port.sender);
  if (port.name === PORT_ENDPOINT) router.connectEndpoint(port, sender);
  else if (port.name === PORT_UI) router.connectUi(port, sender);
  else port.disconnect();
});

ext.tabs.onRemoved.addListener((tabId) => {
  router.onTabRemoved(tabId).catch(logError);
});

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SWEEP_ALARM) router.sweep().catch(logError);
});

ext.permissions.onAdded.addListener(() => {
  router.onPermissionsAdded().catch(logError);
});

ext.permissions.onRemoved.addListener(() => {
  router.onPermissionsRemoved().catch(logError);
});

ext.runtime.onInstalled.addListener(() => {
  router.resyncContentScripts().catch(logError);
});

ext.runtime.onStartup.addListener(() => {
  router.resyncContentScripts().catch(logError);
});

// Re-creating an alarm with the same name replaces it; cheap on every wake.
void Promise.resolve(ext.alarms.create(SWEEP_ALARM, { periodInMinutes: 1 })).catch(logError);

// Audit log first (so its chain is loaded before the router appends), then router state.
void audit
  .init()
  .catch(logError)
  .then(() => router.init())
  .catch(logError);
