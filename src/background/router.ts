// Router: the policy enforcement point. SPEC.md §4, §5, §5.1–5.3, §7; DECISIONS.md D1, D4, D7.
//
// Invariants:
// - Every inbound event (endpoint message, endpoint disconnect, UI call, tab event, sweep,
//   permission event) runs through ONE FIFO async queue. Ops never interleave.
// - Sender identity comes only from SenderInfo (port.sender), never from message fields.
// - State is written through to storage.session ("tb.router") at the end of each op BEFORE any
//   message produced by that op is posted (outbox pattern), so a worker killed mid-op can never
//   have told a peer about something it has not persisted (e.g. an advanced seq).
// - The router never decrypts. It sees headers, ciphertext lengths and ciphertext hashes only.
// - Pairing codes are secrets: they go to trusted UI only, never into the audit log or to endpoints.

import { TabBridgeError, toErrorPayload, type ErrorCode } from '../shared/errors';
import {
  AUDIT_DEFAULT_MAX_ENTRIES,
  AUDIT_MAX_MAX_ENTRIES,
  AUDIT_MIN_MAX_ENTRIES,
  CLOSED_ROOM_RETENTION_MS,
  HEX32_RE,
  KEYING_TIMEOUT_MS,
  MAX_AGENT_NAME,
  MAX_NOTE_CHARS,
  MAX_ROOMS_PER_ENDPOINT,
  PAIR_REQUEST_TTL_MS,
  PANEL_ORIGIN,
  PANEL_PATH,
  RESUME_GRACE_MS,
} from '../shared/limits';
import { base64ToBytes, randomHex32, randomInt, utf8Encode } from '../shared/encoding';
import { bodyLimit, base64DecodedLength, expectedCtBytes, validateE2R, validateHeader } from '../shared/protocol';
import { constantTimeEqual, sha256Hex } from '../shared/crypto';
import type {
  AuditActor,
  AuditType,
  CloseReason,
  E2R,
  EndpointId,
  EndpointInfo,
  EndpointRecord,
  EndpointSelector,
  FrameHeader,
  FrameId,
  KeyValueStore,
  PairingEndpointRef,
  RoomAdminView,
  RoomId,
  RoomMember,
  RoomRecord,
  RoomView,
  RouterState,
  RuntimePortLike,
  SenderInfo,
  Settings,
  Transcript,
  UiMethod,
  UiMethods,
  UiState,
} from '../shared/types';
import type { AuditLog } from './audit';
import { PairingManager } from './pairing';
import {
  applyNarrowing,
  checkFrame,
  checkRate,
  defaultProposal,
  directionOf,
  grantFromProposal,
  perspective,
  validateProposal,
} from './permissions';
import { emptyRouterState, RouterStateStore } from './state';

// ------------------------------------------------------------------------------------------ API

export interface RouterPlatform {
  extensionOrigin: string; // e.g. 'chrome-extension://abc' (no trailing slash)
  extensionId: string;
  hasHostPermission(origin: string): Promise<boolean>;
  syncContentScripts(sites: string[]): Promise<void>;
  injectIntoOpenTabs(origin: string): Promise<void>;
  setBadge(tabId: number, text: string): void;
  loadSettings(): Promise<Settings | undefined>;
  saveSettings(s: Settings): Promise<void>;
}

export interface RouterDeps {
  session: KeyValueStore;
  audit: AuditLog;
  platform: RouterPlatform;
  now(): number;
  randomBytes(n: number): Uint8Array;
}

/** Max entries kept in RoomRecord.recentFrameIds and RoomRecord.routed (FIFO). */
export const ROUTED_HISTORY = 256;
/** Endpoint-triggered audit records that are not tied to an accepted frame (rejections,
 *  violations, pair requests, rejected hellos) are capped per source per minute so a hostile
 *  endpoint cannot flush the bounded audit log. Suppressed counts are reported on the next entry. */
export const NOISY_AUDIT_PER_MIN = 60;
/** Minimum spacing of UI state pushes per UI port. */
export const UI_PUSH_INTERVAL_MS = 50;

const UI_METHODS: readonly UiMethod[] = [
  'state.get',
  'site.enable',
  'site.disable',
  'pair.start',
  'pair.lookup',
  'pair.approve',
  'pair.cancel',
  'room.close',
  'room.narrow',
  'pause.set',
  'audit.list',
  'audit.verify',
  'audit.clear',
  'audit.export',
  'settings.get',
  'settings.set',
];

const VIOLATION_CLOSES: Partial<Record<ErrorCode, CloseReason>> = {
  DECRYPT_FAILED: 'violation',
  REPLAY: 'violation',
  KEY_CONFIRM_FAILED: 'key-confirm-failed',
};

// -------------------------------------------------------------------------------- helpers

type Obj = Record<string, unknown>;
type AuditInput = { type: AuditType; roomId?: RoomId; actor: AuditActor; data: Record<string, unknown> };

function isObj(x: unknown): x is Obj {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function own<T>(rec: Record<string, T>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(rec, key) ? rec[key] : undefined;
}

function bad(what: string): never {
  throw new TabBridgeError('INVALID_MESSAGE', `Invalid message: ${what}`);
}

/** Strict params object: exactly the allowed keys, required ones present. */
function params(p: unknown, required: readonly string[], optional: readonly string[] = []): Obj {
  if (!isObj(p) || Object.prototype.toString.call(p) !== '[object Object]') bad('params must be an object');
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(p)) if (!allowed.has(k)) bad(`unknown param "${k}"`);
  for (const k of required) if (p[k] === undefined) bad(`param "${k}" is required`);
  return p;
}

/** Methods without params accept an absent value (JSON drops `undefined`), null, or `{}`. */
function noParams(p: unknown): void {
  if (p === undefined || p === null) return;
  if (isObj(p) && Object.keys(p).length === 0) return;
  bad('method takes no params');
}

function intParam(x: unknown, what: string, min: number, max: number): number {
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < min || x > max) bad(`${what} out of range`);
  return x;
}

function hex32Param(x: unknown, what: string): string {
  if (typeof x !== 'string' || !HEX32_RE.test(x)) bad(`${what} invalid`);
  return x;
}

function selectorParam(x: unknown): EndpointSelector {
  if (!isObj(x)) bad('endpoint selector must be an object');
  const keys = Object.keys(x);
  if (keys.length !== 1) bad('endpoint selector must have exactly one key');
  if (keys[0] === 'tabId') return { tabId: intParam(x.tabId, 'endpoint.tabId', 0, Number.MAX_SAFE_INTEGER) };
  if (keys[0] === 'endpointId') return { endpointId: hex32Param(x.endpointId, 'endpoint.endpointId') };
  bad('endpoint selector invalid');
}

/** Removes C0/C1 controls, bidi overrides/isolates/marks and zero-width chars (display spoofing), then trims. */
export function cleanDisplayText(s: string): string {
  return s
    .replace(/[\u0000-\u001f\u007f-\u009f؜​-‏‪-‮⁦-⁩﻿]/g, '')
    .trim();
}

/** Canonical http(s) origin, or null. The input must already BE the canonical origin. */
export function normalizeWebOrigin(o: unknown): string | null {
  if (typeof o !== 'string' || o.length === 0 || o.length > 2048) return null;
  let u: URL;
  try {
    u = new URL(o);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.origin === 'null' || u.origin !== o) return null;
  return u.origin;
}

/** `scheme://host[:port]` of any URL (works for chrome-extension:/moz-extension:, whose WHATWG origin is opaque). */
function schemeHostOf(url: string | undefined): string | null {
  if (typeof url !== 'string') return null;
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function pathOf(url: string | undefined): string | null {
  if (typeof url !== 'string') return null;
  try {
    return new URL(url).pathname;
  } catch {
    return null;
  }
}

export type SenderClass =
  | { kind: 'page'; origin: string; tabId: number; title?: string }
  | { kind: 'panel'; origin: string }
  | { reject: ErrorCode; origin?: string };

function isExtensionContext(sender: SenderInfo, platform: RouterPlatform): boolean {
  return schemeHostOf(sender.url) === platform.extensionOrigin || sender.origin === platform.extensionOrigin;
}

/** A trusted extension page of THIS extension (URL and origin agree, id matches). */
export function isExtensionPageSender(sender: SenderInfo, platform: RouterPlatform): boolean {
  return (
    schemeHostOf(sender.url) === platform.extensionOrigin &&
    (sender.origin === undefined || sender.origin === platform.extensionOrigin) &&
    typeof sender.extensionId === 'string' &&
    sender.extensionId === platform.extensionId
  );
}

/** SPEC §5.1. `sites` are the enabled origins. */
export function classifyEndpointSender(sender: SenderInfo, platform: RouterPlatform, sites: readonly string[]): SenderClass {
  if (isExtensionContext(sender, platform)) {
    if (isExtensionPageSender(sender, platform) && pathOf(sender.url) === PANEL_PATH) return { kind: 'panel', origin: PANEL_ORIGIN };
    return { reject: 'SENDER_REJECTED' };
  }
  const tabId = sender.tabId;
  if (typeof tabId !== 'number' || !Number.isSafeInteger(tabId) || tabId < 0) return { reject: 'SENDER_REJECTED' };
  if (sender.frameId !== 0) return { reject: 'SENDER_REJECTED' };
  if (sender.extensionId !== undefined && sender.extensionId !== platform.extensionId) return { reject: 'SENDER_REJECTED' };
  let raw = sender.origin;
  if (raw === undefined) {
    if (typeof sender.url !== 'string') return { reject: 'SENDER_REJECTED' };
    try {
      raw = new URL(sender.url).origin;
    } catch {
      return { reject: 'SENDER_REJECTED' };
    }
  }
  const origin = normalizeWebOrigin(raw);
  if (!origin) return { reject: 'SENDER_REJECTED' };
  // The document URL (when known) must agree with the origin: about:blank/blob:/data: documents
  // and sandboxed (opaque-origin) documents are rejected.
  if (sender.url !== undefined) {
    let u: URL;
    try {
      u = new URL(sender.url);
    } catch {
      return { reject: 'SENDER_REJECTED' };
    }
    if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.origin !== origin) return { reject: 'SENDER_REJECTED' };
  }
  if (!sites.includes(origin)) return { reject: 'ORIGIN_NOT_ENABLED', origin };
  const out: SenderClass = { kind: 'page', origin, tabId };
  if (typeof sender.tabTitle === 'string') {
    const t = cleanDisplayText(sender.tabTitle).slice(0, 200);
    if (t) out.title = t;
  }
  return out;
}

export function defaultSettings(): Settings {
  return { sites: [], paused: false, auditMaxEntries: AUDIT_DEFAULT_MAX_ENTRIES, defaultProposal: defaultProposal() };
}

function clampAuditMax(n: number): number {
  return Math.min(AUDIT_MAX_MAX_ENTRIES, Math.max(AUDIT_MIN_MAX_ENTRIES, Math.floor(n)));
}

/** Settings from storage are re-validated; anything off falls back to the safe default. */
function sanitizeSettings(raw: unknown): Settings {
  const d = defaultSettings();
  if (!isObj(raw)) return d;
  if (Array.isArray(raw.sites)) {
    const sites: string[] = [];
    for (const s of raw.sites) {
      const o = normalizeWebOrigin(s);
      if (o && !sites.includes(o)) sites.push(o);
    }
    d.sites = sites;
  }
  if (typeof raw.paused === 'boolean') d.paused = raw.paused;
  if (typeof raw.auditMaxEntries === 'number' && Number.isFinite(raw.auditMaxEntries)) d.auditMaxEntries = clampAuditMax(raw.auditMaxEntries);
  if (raw.defaultProposal !== undefined) {
    try {
      d.defaultProposal = validateProposal(raw.defaultProposal);
    } catch {
      /* keep default */
    }
  }
  return d;
}

function copySettings(s: Settings): Settings {
  return JSON.parse(JSON.stringify(s)) as Settings;
}

function unrefTimer(t: unknown): void {
  (t as { unref?: () => void } | undefined)?.unref?.();
}

// ------------------------------------------------------------------------ connections

interface EndpointConn {
  port: RuntimePortLike;
  sender: SenderInfo;
  endpointId?: EndpointId;
  helloSeen: boolean;
  closed: boolean;
}

interface UiConn {
  port: RuntimePortLike;
  closed: boolean;
  lastPush: number;
  timer?: ReturnType<typeof setTimeout>;
}

interface NoisyBucket {
  windowStart: number;
  count: number;
  suppressed: number;
}

const noop = (): void => {};

// ------------------------------------------------------------------------------ Router

export class Router {
  private readonly d: RouterDeps;
  private readonly store: RouterStateStore;
  private state: RouterState = emptyRouterState();
  private settings: Settings = defaultSettings();
  private pairing: PairingManager;

  /** endpointId → live connection (runtime only, never persisted). */
  private readonly live = new Map<EndpointId, EndpointConn>();
  private readonly uiConns = new Set<UiConn>();
  private readonly noisy = new Map<string, NoisyBucket>();

  private tail: Promise<unknown>;
  private openGate: () => void = noop;
  private initP: Promise<void> | undefined;

  // Per-op buffers (only touched inside the queue).
  private dirty = false;
  private uiChanged = false;
  private outbox: (() => void)[] = [];
  private auditQ: AuditInput[] = [];

  constructor(deps: RouterDeps) {
    this.d = deps;
    this.store = new RouterStateStore(deps.session);
    this.pairing = this.makePairing(undefined);
    // Everything queued before init() completes waits behind this gate (nothing is dropped).
    this.tail = new Promise<void>((resolve) => {
      this.openGate = resolve;
    });
  }

  // ------------------------------------------------------------------ public surface

  init(): Promise<void> {
    if (!this.initP) {
      this.initP = this.doInit().finally(() => this.openGate());
    }
    return this.initP;
  }

  connectEndpoint(port: RuntimePortLike, sender: SenderInfo): void {
    const conn: EndpointConn = { port, sender: { ...sender }, helloSeen: false, closed: false };
    port.onMessage.addListener((msg) => {
      if (conn.closed) return;
      this.enqueue(() => this.onEndpointMessage(conn, msg)).catch((e) => this.opFailed(conn, e));
    });
    port.onDisconnect.addListener(() => {
      this.enqueue(() => this.onEndpointDisconnect(conn)).catch(logError);
    });
  }

  connectUi(port: RuntimePortLike, sender: SenderInfo): void {
    if (!isExtensionPageSender(sender, this.d.platform)) {
      try {
        port.disconnect();
      } catch {
        /* ignore */
      }
      return;
    }
    const ui: UiConn = { port, closed: false, lastPush: 0 };
    this.uiConns.add(ui);
    port.onMessage.addListener((raw) => this.onUiMessage(ui, raw));
    port.onDisconnect.addListener(() => {
      ui.closed = true;
      if (ui.timer !== undefined) clearTimeout(ui.timer);
      this.uiConns.delete(ui);
    });
    this.schedulePush(ui);
  }

  handleUi<M extends UiMethod>(m: M, p: UiMethods[M]['p']): Promise<UiMethods[M]['r']> {
    return this.enqueue(() => this.uiOp(m, p)) as Promise<UiMethods[M]['r']>;
  }

  onTabRemoved(tabId: number): Promise<void> {
    return this.enqueue(() => this.tabRemoved(tabId));
  }

  onPermissionsAdded(): Promise<void> {
    return this.enqueue(async () => {
      for (const origin of [...this.state.pendingSites]) {
        if (await this.hasPermission(origin)) await this.enableSite(origin, { kind: 'router' });
      }
    });
  }

  onPermissionsRemoved(): Promise<void> {
    return this.enqueue(async () => {
      for (const origin of [...this.settings.sites]) {
        if (!(await this.hasPermission(origin))) await this.disableSite(origin, { kind: 'router' });
      }
    });
  }

  /** Re-register content scripts for the current sites (runtime.onInstalled / onStartup). */
  resyncContentScripts(): Promise<void> {
    return this.enqueue(async () => {
      await this.syncScripts();
    });
  }

  sweep(): Promise<void> {
    // housekeeping() runs at the start of every op; an empty op is a sweep.
    return this.enqueue(noop);
  }

  async whenIdle(): Promise<void> {
    for (;;) {
      const t = this.tail;
      await t;
      if (t === this.tail) return;
    }
  }

  // ------------------------------------------------------------------ queue & commit

  private enqueue<T>(fn: () => Promise<T> | T): Promise<T> {
    const run = this.tail.then(() => this.runOp(fn));
    this.tail = run.then(noop, noop);
    return run;
  }

  private async runOp<T>(fn: () => Promise<T> | T): Promise<T> {
    try {
      this.housekeeping();
      return await fn();
    } finally {
      await this.commit();
    }
  }

  /** Persist → audit → post messages → schedule UI pushes. */
  private async commit(): Promise<void> {
    if (this.dirty) {
      this.dirty = false;
      this.state.pairing = this.pairing.snapshot();
      try {
        await this.store.save(this.state);
      } catch (e) {
        logError(e);
      }
    }
    const audits = this.auditQ;
    this.auditQ = [];
    for (const a of audits) {
      try {
        await this.d.audit.append(a);
      } catch (e) {
        logError(e);
      }
    }
    const out = this.outbox;
    this.outbox = [];
    for (const f of out) {
      try {
        f();
      } catch {
        /* port already gone */
      }
    }
    if (this.uiChanged) {
      this.uiChanged = false;
      for (const ui of this.uiConns) this.schedulePush(ui);
    }
  }

  private async doInit(): Promise<void> {
    try {
      let raw: Settings | undefined;
      try {
        raw = await this.d.platform.loadSettings();
      } catch (e) {
        logError(e);
      }
      this.settings = sanitizeSettings(raw);
      this.state = await this.store.load();
      this.pairing = this.makePairing(this.state.pairing);
      try {
        this.d.audit.setMaxEntries(this.settings.auditMaxEntries);
      } catch (e) {
        logError(e);
      }
      const now = this.d.now();
      // Fresh worker: no port survived. Keep an older disconnectedAt so grace is not extended.
      for (const rec of Object.values(this.state.endpoints)) {
        if (rec.connected || rec.disconnectedAt === undefined) {
          rec.connected = false;
          rec.disconnectedAt = now;
        }
      }
      const pending: string[] = [];
      for (const s of this.state.pendingSites) {
        const o = normalizeWebOrigin(s);
        if (o && !pending.includes(o) && !this.settings.sites.includes(o)) pending.push(o);
      }
      this.state.pendingSites = pending;
      this.dirty = true;
      await this.runOp(noop);
    } catch (e) {
      // Fail closed: empty state and default settings (no sites enabled).
      logError(e);
      this.state = emptyRouterState();
      this.settings = defaultSettings();
      this.pairing = this.makePairing(undefined);
    }
  }

  private makePairing(snapshot: RouterState['pairing'] | undefined): PairingManager {
    return new PairingManager({
      now: () => this.d.now(),
      randomInt: (n) => randomInt(n, (k) => this.d.randomBytes(k)),
      ...(snapshot ? { snapshot } : {}),
    });
  }

  private opFailed(conn: EndpointConn, e: unknown): void {
    logError(e);
    if (conn.closed) return;
    try {
      conn.port.postMessage({ t: 'error', v: 1, code: 'INTERNAL' });
    } catch {
      /* ignore */
    }
  }

  // ------------------------------------------------------------------ outbox helpers

  private post(conn: { port: RuntimePortLike }, msg: unknown): void {
    const port = conn.port;
    this.outbox.push(() => port.postMessage(msg));
  }

  private postTo(endpointId: EndpointId, msg: unknown): void {
    const c = this.live.get(endpointId);
    if (c) this.post(c, msg);
  }

  private sendError(conn: EndpointConn, code: ErrorCode, message?: string): void {
    const msg: { t: 'error'; v: 1; code: ErrorCode; message?: string } = { t: 'error', v: 1, code };
    if (message) msg.message = message.slice(0, 500);
    this.post(conn, msg);
  }

  private sendErrorFrom(conn: EndpointConn, e: unknown): void {
    const p = toErrorPayload(e);
    this.sendError(conn, p.code, p.message);
  }

  private badge(tabId: number, text: string): void {
    this.outbox.push(() => this.d.platform.setBadge(tabId, text));
  }

  private audit(e: AuditInput): void {
    this.auditQ.push(e);
  }

  /** Throttled audit for records an endpoint can trigger at will. */
  private noisyAudit(key: string, e: AuditInput): void {
    const now = this.d.now();
    let b = this.noisy.get(key);
    if (!b || !(now - b.windowStart < 60_000) || now < b.windowStart) {
      const suppressed = b?.suppressed ?? 0;
      if (!b && this.noisy.size >= 1024) {
        const first = this.noisy.keys().next();
        if (!first.done) this.noisy.delete(first.value);
      }
      b = { windowStart: now, count: 0, suppressed: 0 };
      this.noisy.set(key, b);
      if (suppressed > 0) e.data.suppressedBefore = suppressed;
    }
    if (b.count >= NOISY_AUDIT_PER_MIN) {
      b.suppressed++;
      return;
    }
    b.count++;
    this.auditQ.push(e);
  }

  private mark(): void {
    this.dirty = true;
    this.uiChanged = true;
  }

  private armTimer(ms: number): void {
    const t = setTimeout(() => {
      this.enqueue(noop).catch(logError);
    }, ms);
    unrefTimer(t);
  }

  private actorOf(rec: EndpointRecord): AuditActor {
    return { kind: 'endpoint', endpointId: rec.endpointId, origin: rec.origin };
  }

  // ------------------------------------------------------------------ views

  private isLive(id: EndpointId): boolean {
    return this.live.has(id);
  }

  private roomView(room: RoomRecord, forId: EndpointId): RoomView {
    const me = room.members[0].endpointId === forId ? room.members[0] : room.members[1];
    const peer = me === room.members[0] ? room.members[1] : room.members[0];
    const { outbound, inbound } = perspective(room.grant, me.role);
    const view: RoomView = {
      roomId: room.roomId,
      state: room.state,
      createdAt: room.createdAt,
      expiresAt: room.grant.expiresAt,
      role: me.role,
      peer: { origin: peer.origin, kind: peer.kind, connected: this.isLive(peer.endpointId) },
      outbound,
      inbound,
    };
    const peerRec = own(this.state.endpoints, peer.endpointId);
    if (peerRec?.agent.attached && peerRec.agent.name) view.peer.agentName = peerRec.agent.name;
    if (room.closedReason) view.closedReason = room.closedReason;
    return view;
  }

  private adminView(room: RoomRecord): RoomAdminView {
    const v: RoomAdminView = {
      roomId: room.roomId,
      state: room.state,
      createdAt: room.createdAt,
      members: JSON.parse(JSON.stringify(room.members)) as [RoomMember, RoomMember],
      grant: JSON.parse(JSON.stringify(room.grant)) as RoomRecord['grant'],
      frames: { routed: room.counters.routed, rejected: room.counters.rejected },
    };
    if (room.closedReason) v.closedReason = room.closedReason;
    return v;
  }

  private endpointInfo(rec: EndpointRecord): EndpointInfo {
    const info: EndpointInfo = {
      endpointId: rec.endpointId,
      kind: rec.kind,
      origin: rec.origin,
      agent: { ...rec.agent },
      connected: this.isLive(rec.endpointId),
    };
    if (rec.tabId !== undefined) info.tabId = rec.tabId;
    if (rec.title !== undefined) info.title = rec.title;
    return info;
  }

  private uiState(): UiState {
    return {
      paused: this.settings.paused,
      sites: [...this.settings.sites],
      pendingSites: [...this.state.pendingSites],
      endpoints: Object.values(this.state.endpoints).map((r) => this.endpointInfo(r)),
      rooms: Object.values(this.state.rooms).map((r) => this.adminView(r)),
      pairings: this.pairing.list().map((p) => ({ code: p.code, initiator: p.initiator, expiresAt: p.expiresAt })),
      pairRequests: this.state.pairRequests.map((r) => ({ ...r })),
      lockedUntil: this.pairing.lockedUntil(),
    };
  }

  private sendRoomUpdate(room: RoomRecord, to: EndpointId): void {
    if (!this.isLive(to)) return;
    this.postTo(to, { t: 'room', v: 1, room: this.roomView(room, to) });
  }

  private roomsOf(id: EndpointId, includeClosed = false): RoomRecord[] {
    return Object.values(this.state.rooms).filter(
      (r) => (includeClosed || r.state !== 'closed') && (r.members[0].endpointId === id || r.members[1].endpointId === id),
    );
  }

  private peerOf(room: RoomRecord, id: EndpointId): RoomMember {
    return room.members[0].endpointId === id ? room.members[1] : room.members[0];
  }

  private isMember(room: RoomRecord, id: EndpointId): boolean {
    return room.members[0].endpointId === id || room.members[1].endpointId === id;
  }

  private notifyPeers(id: EndpointId): void {
    for (const room of this.roomsOf(id)) this.sendRoomUpdate(room, this.peerOf(room, id).endpointId);
  }

  // ------------------------------------------------------------------ lifecycle

  private closeRoom(room: RoomRecord, reason: CloseReason, actor: AuditActor = { kind: 'router' }): void {
    if (room.state === 'closed') return;
    room.state = 'closed';
    room.closedReason = reason;
    room.closedAt = this.d.now();
    this.mark();
    for (const m of room.members) this.sendRoomUpdate(room, m.endpointId);
    this.audit({ type: 'room.closed', roomId: room.roomId, actor, data: { reason } });
  }

  /** Time-based transitions. Runs at the start of every op (so expiry is enforced on every event)
   *  and is the body of sweep(). */
  private housekeeping(): void {
    const now = this.d.now();
    for (const room of Object.values(this.state.rooms)) {
      if (room.state === 'closed') {
        if (!(now - (room.closedAt ?? 0) < CLOSED_ROOM_RETENTION_MS)) {
          delete this.state.rooms[room.roomId];
          this.mark();
        }
        continue;
      }
      if (!(now < room.grant.expiresAt)) {
        this.closeRoom(room, 'expired');
        continue;
      }
      if (room.state === 'keying' && !(now - room.createdAt < KEYING_TIMEOUT_MS)) {
        this.closeRoom(room, 'key-confirm-failed');
        continue;
      }
      for (const m of room.members) {
        if (this.isLive(m.endpointId)) continue;
        const rec = own(this.state.endpoints, m.endpointId);
        if (!rec || !(now - (rec.disconnectedAt ?? 0) < RESUME_GRACE_MS)) {
          this.closeRoom(room, 'endpoint-gone');
          break;
        }
      }
    }
    // Endpoints that did not resume within the grace period are forgotten (their rooms are closed above).
    for (const rec of Object.values(this.state.endpoints)) {
      if (this.isLive(rec.endpointId)) continue;
      if (!(now - (rec.disconnectedAt ?? 0) < RESUME_GRACE_MS)) {
        delete this.state.endpoints[rec.endpointId];
        this.pairing.cancelForEndpoint(rec.endpointId);
        this.mark();
      }
    }
    // Pairings whose initiator no longer exists are cancelled; expired ones swept.
    for (const p of this.pairing.list()) {
      if (!own(this.state.endpoints, p.initiator.endpointId)) {
        this.pairing.cancelForEndpoint(p.initiator.endpointId);
        this.mark();
      }
    }
    if (this.pairing.sweep().length > 0) this.mark();
    const keep = this.state.pairRequests.filter((r) => now - r.at < PAIR_REQUEST_TTL_MS && r.at <= now);
    if (keep.length !== this.state.pairRequests.length) {
      for (const r of this.state.pairRequests) if (!keep.includes(r)) this.badge(r.tabId, '');
      this.state.pairRequests = keep;
      this.mark();
    }
  }

  private async tabRemoved(tabId: number): Promise<void> {
    if (typeof tabId !== 'number' || !Number.isSafeInteger(tabId) || tabId < 0) return;
    for (const rec of Object.values(this.state.endpoints)) {
      if (rec.kind !== 'page' || rec.tabId !== tabId) continue;
      for (const room of this.roomsOf(rec.endpointId)) this.closeRoom(room, 'tab-closed');
      this.forgetEndpoint(rec.endpointId);
    }
    const before = this.state.pairRequests.length;
    this.state.pairRequests = this.state.pairRequests.filter((r) => r.tabId !== tabId);
    if (before !== this.state.pairRequests.length) this.mark();
  }

  /** Disconnects (if live) and deletes an endpoint record; its pairings are cancelled. */
  private forgetEndpoint(id: EndpointId): void {
    const conn = this.live.get(id);
    if (conn) this.dropConn(conn);
    if (own(this.state.endpoints, id)) delete this.state.endpoints[id];
    this.pairing.cancelForEndpoint(id);
    this.mark();
  }

  /** Router-initiated disconnect. */
  private dropConn(conn: EndpointConn): void {
    if (conn.closed) return;
    conn.closed = true;
    const port = conn.port;
    this.outbox.push(() => port.disconnect());
    this.detach(conn);
  }

  private detach(conn: EndpointConn): void {
    const id = conn.endpointId;
    if (id === undefined || this.live.get(id) !== conn) return;
    this.live.delete(id);
    const rec = own(this.state.endpoints, id);
    if (rec) {
      rec.connected = false;
      rec.disconnectedAt = this.d.now();
      this.mark();
      this.notifyPeers(id);
      this.armTimer(RESUME_GRACE_MS + 50);
    }
  }

  private async onEndpointDisconnect(conn: EndpointConn): Promise<void> {
    if (conn.closed) return;
    conn.closed = true;
    this.detach(conn);
  }

  // ------------------------------------------------------------------ endpoint messages

  private async onEndpointMessage(conn: EndpointConn, raw: unknown): Promise<void> {
    if (conn.closed) return;
    if (!conn.helloSeen) {
      conn.helloSeen = true;
      await this.onHello(conn, raw);
      return;
    }
    const id = conn.endpointId;
    const rec = id === undefined ? undefined : own(this.state.endpoints, id);
    if (!rec || this.live.get(rec.endpointId) !== conn) {
      // Endpoint was forgotten (site disabled, tab closed) while the port lingered.
      this.dropConn(conn);
      return;
    }
    if (isObj(raw) && raw.t === 'frame') {
      await this.onFrame(conn, rec, raw);
      return;
    }
    let m: E2R;
    try {
      m = validateE2R(raw);
    } catch (e) {
      this.sendErrorFrom(conn, e);
      return;
    }
    switch (m.t) {
      case 'hello':
        this.sendError(conn, 'INVALID_MESSAGE', 'Duplicate hello');
        return;
      case 'agent':
        return this.onAgent(conn, rec, m);
      case 'pair-request':
        return this.onPairRequest(conn, rec, m);
      case 'key-share':
        return this.onKeyShare(conn, rec, m);
      case 'confirmed':
        return this.onConfirmed(conn, rec, m);
      case 'receipt':
        return this.onReceipt(conn, rec, m);
      case 'audit-detail':
        return this.onAuditDetail(conn, rec, m);
      case 'violation':
        return this.onViolation(conn, rec, m);
      case 'leave':
        return this.onLeave(conn, rec, m);
      default:
        this.sendError(conn, 'INVALID_MESSAGE');
    }
  }

  private async onHello(conn: EndpointConn, raw: unknown): Promise<void> {
    let m: E2R;
    try {
      m = validateE2R(raw);
    } catch (e) {
      const code = e instanceof TabBridgeError && e.code === 'UNSUPPORTED_VERSION' ? 'UNSUPPORTED_VERSION' : 'INVALID_MESSAGE';
      this.sendError(conn, code, 'First message must be a valid hello');
      this.dropConn(conn);
      return;
    }
    if (m.t !== 'hello') {
      this.sendError(conn, 'INVALID_MESSAGE', 'First message must be hello');
      this.dropConn(conn);
      return;
    }
    const cls = classifyEndpointSender(conn.sender, this.d.platform, this.settings.sites);
    if ('reject' in cls || cls.kind !== m.kind) {
      const code: ErrorCode = 'reject' in cls ? cls.reject : 'SENDER_REJECTED';
      this.post(conn, { t: 'rejected', v: 1, code });
      const origin = 'origin' in cls && cls.origin ? cls.origin : schemeHostOf(conn.sender.url) ?? 'unknown';
      const data: Record<string, unknown> = { code, origin, kind: m.kind };
      if (typeof conn.sender.tabId === 'number') data.tabId = conn.sender.tabId;
      this.noisyAudit(`rejected|${origin}`, { type: 'endpoint.rejected', actor: { kind: 'router' }, data });
      this.dropConn(conn);
      return;
    }

    const tabId = cls.kind === 'page' ? cls.tabId : undefined;
    const token = randomHex32((n) => this.d.randomBytes(n));
    const tokenHash = await sha256Hex(utf8Encode(token));
    let rec: EndpointRecord | undefined;
    let resumed = false;

    if (m.resume) {
      const old = own(this.state.endpoints, m.resume.endpointId);
      const presented = await sha256Hex(utf8Encode(m.resume.resumeToken));
      const tokenOk = old !== undefined && constantTimeEqual(presented, old.resumeTokenHash);
      if (
        old &&
        tokenOk &&
        old.kind === cls.kind &&
        old.tabId === tabId &&
        old.origin === cls.origin &&
        !old.connected &&
        !this.isLive(old.endpointId)
      ) {
        rec = old;
        resumed = true;
        rec.connected = true;
        delete rec.disconnectedAt;
        rec.resumeTokenHash = tokenHash; // rotate: a token is good for one resume only
        if (cls.kind === 'page') {
          if (cls.title !== undefined) rec.title = cls.title;
          else delete rec.title;
        }
      }
    }
    if (!rec) {
      let id = randomHex32((n) => this.d.randomBytes(n));
      while (own(this.state.endpoints, id)) id = randomHex32((n) => this.d.randomBytes(n));
      rec = {
        endpointId: id,
        kind: cls.kind,
        origin: cls.origin,
        agent: { attached: false },
        resumeTokenHash: tokenHash,
        connected: true,
      };
      if (tabId !== undefined) rec.tabId = tabId;
      if (cls.kind === 'page' && cls.title !== undefined) rec.title = cls.title;
      this.state.endpoints[id] = rec;
    }
    conn.endpointId = rec.endpointId;
    this.live.set(rec.endpointId, conn);
    this.mark();

    const rooms = this.roomsOf(rec.endpointId, true).map((r) => this.roomView(r, rec!.endpointId));
    this.post(conn, {
      t: 'welcome',
      v: 1,
      endpointId: rec.endpointId,
      resumeToken: token,
      origin: rec.origin,
      kind: rec.kind,
      rooms,
      paused: this.settings.paused,
      resumed,
    });
    if (resumed) {
      this.notifyPeers(rec.endpointId);
      // Re-drive keying steps this endpoint may have missed while the worker was down.
      for (const room of this.roomsOf(rec.endpointId)) {
        if (room.state !== 'keying') continue;
        if (!own(room.pubKeys, rec.endpointId)) this.post(conn, { t: 'key-request', v: 1, roomId: room.roomId });
        else if (this.keysComplete(room) && (room.lastSeq[rec.endpointId] ?? 0) === 0)
          this.post(conn, { t: 'room-keys', v: 1, roomId: room.roomId, transcript: this.transcript(room) });
      }
    }
  }

  private onAgent(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'agent' }>): void {
    let name: string | undefined;
    if (m.name !== undefined) {
      name = cleanDisplayText(m.name);
      if (name.length < 1 || name.length > MAX_AGENT_NAME) {
        this.sendError(conn, 'INVALID_MESSAGE', 'agent name must be 1..64 characters');
        return;
      }
    }
    rec.agent = m.attached ? (name ? { attached: true, name } : { attached: true }) : { attached: false };
    this.mark();
    this.notifyPeers(rec.endpointId);
  }

  private onPairRequest(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'pair-request' }>): void {
    if (rec.kind !== 'page' || rec.tabId === undefined) {
      this.sendError(conn, 'NOT_PERMITTED', 'Only page endpoints can request pairing');
      return;
    }
    const tabId = rec.tabId;
    let note: string | undefined;
    if (m.note !== undefined) {
      note = cleanDisplayText(m.note).slice(0, MAX_NOTE_CHARS);
      if (!note) note = undefined;
    }
    const entry: UiState['pairRequests'][number] = { tabId, origin: rec.origin, at: this.d.now() };
    if (note !== undefined) entry.note = note;
    this.state.pairRequests = this.state.pairRequests.filter((r) => r.tabId !== tabId);
    this.state.pairRequests.push(entry);
    this.mark();
    this.badge(tabId, '!');
    const data: Record<string, unknown> = { tabId };
    if (note !== undefined) data.note = note;
    this.noisyAudit(`ep|${rec.endpointId}`, { type: 'pair.requested', actor: this.actorOf(rec), data });
  }

  private getRoomFor(conn: EndpointConn, rec: EndpointRecord, roomId: RoomId): RoomRecord | undefined {
    const room = own(this.state.rooms, roomId);
    if (!room) {
      this.sendError(conn, 'ROOM_NOT_FOUND');
      return undefined;
    }
    if (!this.isMember(room, rec.endpointId)) {
      this.sendError(conn, 'NOT_A_MEMBER');
      return undefined;
    }
    return room;
  }

  private keysComplete(room: RoomRecord): boolean {
    return room.members.every((m) => own(room.pubKeys, m.endpointId) !== undefined);
  }

  private transcript(room: RoomRecord): Transcript {
    const ini = room.members[0].role === 'initiator' ? room.members[0] : room.members[1];
    const joi = ini === room.members[0] ? room.members[1] : room.members[0];
    const party = (m: RoomMember) => ({
      endpointId: m.endpointId,
      origin: m.origin,
      kind: m.kind,
      publicKey: room.pubKeys[m.endpointId] as string,
    });
    return {
      v: 1,
      roomId: room.roomId,
      initiator: party(ini),
      joiner: party(joi),
      grant: JSON.parse(JSON.stringify(room.grant)) as RoomRecord['grant'],
    };
  }

  private async onKeyShare(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'key-share' }>): Promise<void> {
    const room = this.getRoomFor(conn, rec, m.roomId);
    if (!room) return;
    if (room.state !== 'keying') return this.sendError(conn, 'ROOM_NOT_ACTIVE');
    if (own(room.pubKeys, rec.endpointId) !== undefined) return this.sendError(conn, 'INVALID_MESSAGE', 'Key already shared');
    let raw: Uint8Array;
    try {
      raw = base64ToBytes(m.publicKey);
    } catch {
      return this.sendError(conn, 'INVALID_MESSAGE', 'Invalid public key');
    }
    if (raw.length !== 65 || raw[0] !== 0x04) return this.sendError(conn, 'INVALID_MESSAGE', 'Invalid public key');
    if (Object.values(room.pubKeys).includes(m.publicKey)) return this.sendError(conn, 'INVALID_MESSAGE', 'Invalid public key');
    try {
      // Reject points that are not on P-256 before they reach the peer.
      const copy = new Uint8Array(new ArrayBuffer(raw.length));
      copy.set(raw);
      await globalThis.crypto.subtle.importKey('raw', copy, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    } catch {
      return this.sendError(conn, 'INVALID_MESSAGE', 'Invalid public key');
    }
    room.pubKeys[rec.endpointId] = m.publicKey;
    this.mark();
    if (this.keysComplete(room)) {
      const transcript = this.transcript(room);
      for (const mem of room.members) this.postTo(mem.endpointId, { t: 'room-keys', v: 1, roomId: room.roomId, transcript });
    }
  }

  private onConfirmed(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'confirmed' }>): void {
    const room = this.getRoomFor(conn, rec, m.roomId);
    if (!room) return;
    if (room.state !== 'keying' || !this.keysComplete(room)) return this.sendError(conn, 'ROOM_NOT_ACTIVE');
    const peer = this.peerOf(room, rec.endpointId);
    // Only after the peer's confirm frame was routed to this endpoint, and only once.
    if (room.confirmed.includes(rec.endpointId) || (room.lastSeq[peer.endpointId] ?? 0) < 1)
      return this.sendError(conn, 'INVALID_MESSAGE', 'Unexpected confirmed');
    room.confirmed.push(rec.endpointId);
    this.mark();
    if (room.members.every((x) => room.confirmed.includes(x.endpointId))) {
      room.state = 'active';
      for (const mem of room.members) this.sendRoomUpdate(room, mem.endpointId);
      this.audit({
        type: 'room.opened',
        roomId: room.roomId,
        actor: { kind: 'router' },
        data: { members: JSON.parse(JSON.stringify(room.members)), grant: JSON.parse(JSON.stringify(room.grant)) },
      });
    }
  }

  private onReceipt(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'receipt' }>): void {
    const room = own(this.state.rooms, m.roomId);
    const rf = room ? own(room.routed, m.frameId) : undefined;
    if (!room || !rf || rf.to !== rec.endpointId || rf.receipt !== undefined)
      return this.sendError(conn, 'INVALID_MESSAGE', 'Unexpected receipt');
    rf.receipt = m.status;
    this.mark();
    const out: { t: 'receipt'; v: 1; roomId: RoomId; frameId: FrameId; status: typeof m.status; code?: ErrorCode } = {
      t: 'receipt',
      v: 1,
      roomId: m.roomId,
      frameId: m.frameId,
      status: m.status,
    };
    if (m.code !== undefined && m.status !== 'accepted') out.code = m.code;
    this.postTo(rf.from, out);
    const data: Record<string, unknown> = { frameId: m.frameId, status: m.status };
    if (out.code !== undefined) data.code = out.code;
    this.audit({ type: 'frame.receipt', roomId: room.roomId, actor: this.actorOf(rec), data });
  }

  private onAuditDetail(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'audit-detail' }>): void {
    const room = own(this.state.rooms, m.roomId);
    const rf = room ? own(room.routed, m.frameId) : undefined;
    let ok = !!room && !!rf && m.detail.kind === rf.kind;
    if (ok && rf) {
      if (m.direction === 'sent') ok = rf.from === rec.endpointId && !rf.sentDetail;
      else ok = rf.to === rec.endpointId && !rf.recvDetail && rf.receipt === 'accepted';
    }
    if (!ok || !room || !rf) return this.sendError(conn, 'INVALID_MESSAGE', 'Unexpected audit-detail');
    // Content records are endpoint attestations. The router cannot decrypt, but the sender and the
    // receiver each report detail.sha256 over the same plaintext, so an honest exchange yields equal
    // hashes; a divergence proves one side misreported (SECURITY_REVIEW M2). Record both and flag it.
    const sha = m.detail.sha256;
    const other = m.direction === 'sent' ? rf.recvSha : rf.sentSha;
    if (m.direction === 'sent') {
      rf.sentDetail = true;
      rf.sentSha = sha;
    } else {
      rf.recvDetail = true;
      rf.recvSha = sha;
    }
    this.mark();
    this.audit({
      type: m.direction === 'sent' ? 'content.sent' : 'content.received',
      roomId: room.roomId,
      actor: this.actorOf(rec),
      data: { frameId: m.frameId, detail: m.detail },
    });
    if (other !== undefined && other !== sha) {
      this.audit({
        type: 'content.mismatch',
        roomId: room.roomId,
        actor: { kind: 'router' },
        data: { frameId: m.frameId, kind: rf.kind, sentSha: rf.sentSha, recvSha: rf.recvSha },
      });
    }
  }

  private onViolation(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'violation' }>): void {
    const room = this.getRoomFor(conn, rec, m.roomId);
    if (!room) return;
    const data: Record<string, unknown> = { code: m.code };
    if (m.frameId !== undefined) data.frameId = m.frameId;
    if (m.message !== undefined) data.message = cleanDisplayText(m.message).slice(0, 200);
    this.noisyAudit(`ep|${rec.endpointId}`, { type: 'violation', roomId: room.roomId, actor: this.actorOf(rec), data });
    const reason = VIOLATION_CLOSES[m.code];
    if (reason && room.state !== 'closed') this.closeRoom(room, reason, this.actorOf(rec));
  }

  private onLeave(conn: EndpointConn, rec: EndpointRecord, m: Extract<E2R, { t: 'leave' }>): void {
    const room = this.getRoomFor(conn, rec, m.roomId);
    if (!room) return;
    if (room.state !== 'closed') this.closeRoom(room, 'peer-left', this.actorOf(rec));
  }

  // ------------------------------------------------------------------ frame policy (§5.3)

  private async onFrame(conn: EndpointConn, rec: EndpointRecord, raw: Obj): Promise<void> {
    const now = this.d.now();
    const rawHeader = isObj(raw.header) ? raw.header : undefined;
    const echoRoomId = typeof rawHeader?.roomId === 'string' && HEX32_RE.test(rawHeader.roomId) ? rawHeader.roomId : undefined;
    const echoFrameId = typeof rawHeader?.frameId === 'string' && HEX32_RE.test(rawHeader.frameId) ? rawHeader.frameId : undefined;

    const reject = (code: ErrorCode, h?: FrameHeader, room?: RoomRecord): void => {
      if (room && this.isMember(room, rec.endpointId)) {
        room.counters.rejected++;
        this.mark();
      }
      const roomId = h?.roomId ?? echoRoomId;
      const frameId = h?.frameId ?? echoFrameId;
      if (roomId !== undefined && frameId !== undefined) this.post(conn, { t: 'ack', v: 1, roomId, frameId, ok: false, code });
      else this.sendError(conn, code);
      const data: Record<string, unknown> = { code };
      if (frameId !== undefined) data.frameId = frameId;
      if (h) {
        data.kind = h.kind;
        data.size = h.size;
        if (h.mime !== undefined) data.mime = h.mime;
      }
      const entry: AuditInput = { type: 'frame.rejected', actor: this.actorOf(rec), data };
      if (room) entry.roomId = room.roomId;
      this.noisyAudit(`ep|${rec.endpointId}`, entry);
    };

    // 1. global pause
    if (this.settings.paused) return reject('PAUSED');

    // 2. header + ciphertext shape
    let h: FrameHeader;
    try {
      h = validateHeader(raw.header);
    } catch (e) {
      return reject(e instanceof TabBridgeError && e.code === 'UNSUPPORTED_VERSION' ? 'UNSUPPORTED_VERSION' : 'INVALID_MESSAGE');
    }
    const keys = Object.keys(raw);
    if (keys.length !== 4 || !['t', 'v', 'header', 'ct'].every((k) => keys.includes(k))) return reject('INVALID_MESSAGE', h);
    if (raw.v !== 1) return reject('UNSUPPORTED_VERSION', h);
    const ct = raw.ct;
    if (typeof ct !== 'string') return reject('INVALID_MESSAGE', h);
    const expected = expectedCtBytes(h.size);
    if (ct.length > Math.ceil(expected / 3) * 4) return reject('PAYLOAD_TOO_LARGE', h); // no need to scan it
    const ctLen = base64DecodedLength(ct);
    if (ctLen !== expected) return reject(ctLen > expected ? 'PAYLOAD_TOO_LARGE' : 'INVALID_MESSAGE', h);

    // 3. sender identity comes from the port
    if (h.from !== rec.endpointId) return reject('SPOOFED_SENDER', h);

    // 4. room & membership
    const room = own(this.state.rooms, h.roomId);
    if (!room) return reject('ROOM_NOT_FOUND', h);
    if (!this.isMember(room, rec.endpointId)) return reject('NOT_A_MEMBER', h);
    // A room closed by expiry keeps reporting ROOM_EXPIRED (housekeeping may have closed it at the
    // start of this very op).
    if (room.state === 'closed') return reject(room.closedReason === 'expired' ? 'ROOM_EXPIRED' : 'ROOM_CLOSED', h, room);

    // 5. expiry
    if (!(now < room.grant.expiresAt)) {
      this.closeRoom(room, 'expired');
      return reject('ROOM_EXPIRED', h, room);
    }

    // 6. state gating: keying → only one confirm per sender (after room-keys); active → no confirm
    const from = rec.endpointId;
    const last = room.lastSeq[from] ?? 0;
    if (room.state === 'keying') {
      if (h.kind !== 'confirm' || !this.keysComplete(room) || last !== 0) return reject('ROOM_NOT_ACTIVE', h, room);
    } else if (h.kind === 'confirm') {
      return reject('ROOM_NOT_ACTIVE', h, room);
    }

    // 7. per-kind size cap
    if (h.size > bodyLimit(h.kind)) return reject('PAYLOAD_TOO_LARGE', h, room);

    // 8. grant
    const dir = directionOf(room.members, from);
    if (!dir) return reject('NOT_A_MEMBER', h, room);
    const policy = checkFrame(room.grant, dir, h, now);
    if (!policy.ok) return reject(policy.code, h, room);

    // 9. replay
    if (h.seq !== last + 1 || room.recentFrameIds.includes(h.frameId)) return reject('REPLAY', h, room);

    // 10. rate
    const rate = checkRate(own(room.rate, from), now, expected, room.grant.rate);
    if (!rate.ok) return reject('RATE_LIMITED', h, room);

    // 11. peer must be connected (no queuing)
    const peer = this.peerOf(room, from);
    if (!this.isLive(peer.endpointId)) return reject('PEER_UNAVAILABLE', h, room);

    // 12. accept
    room.lastSeq[from] = h.seq;
    room.recentFrameIds.push(h.frameId);
    while (room.recentFrameIds.length > ROUTED_HISTORY) room.recentFrameIds.shift();
    room.routed[h.frameId] = { from, to: peer.endpointId, kind: h.kind, at: now, sentDetail: false, recvDetail: false };
    const routedKeys = Object.keys(room.routed);
    for (let i = 0; i < routedKeys.length - ROUTED_HISTORY; i++) delete room.routed[routedKeys[i] as string];
    room.rate[from] = rate.bucket;
    room.counters.routed++;
    this.mark();
    // ctSha256 = sha256 over the UTF-8 bytes of the base64 ciphertext string as sent on the wire.
    const ctSha256 = await sha256Hex(utf8Encode(ct));
    this.postTo(peer.endpointId, { t: 'frame', v: 1, header: h, ct });
    this.post(conn, { t: 'ack', v: 1, roomId: h.roomId, frameId: h.frameId, ok: true });
    const data: Record<string, unknown> = {
      frameId: h.frameId,
      from,
      to: peer.endpointId,
      kind: h.kind,
      size: h.size,
      seq: h.seq,
      ctSha256,
    };
    if (h.mime !== undefined) data.mime = h.mime;
    this.audit({ type: 'frame.routed', roomId: room.roomId, actor: this.actorOf(rec), data });
  }

  // ------------------------------------------------------------------ UI

  private onUiMessage(ui: UiConn, raw: unknown): void {
    if (ui.closed) return;
    if (!isObj(raw) || typeof raw.id !== 'number' || !Number.isSafeInteger(raw.id) || raw.id < 0) return;
    const id = raw.id;
    const respondErr = (e: unknown) => this.postUi(ui, { t: 'res', id, ok: false, e: toErrorPayload(e) });
    const extra = Object.keys(raw).filter((k) => k !== 'id' && k !== 'm' && k !== 'p');
    if (extra.length > 0 || typeof raw.m !== 'string' || !(UI_METHODS as readonly string[]).includes(raw.m)) {
      // Through the queue so responses keep request order.
      this.enqueue(noop).then(
        () => respondErr(new TabBridgeError('INVALID_MESSAGE', 'Invalid message: unknown method')),
        logError,
      );
      return;
    }
    const m = raw.m as UiMethod;
    (this.handleUi(m, raw.p as never) as Promise<unknown>).then(
      (r) => this.postUi(ui, { t: 'res', id, ok: true, r }),
      (e: unknown) => {
        if (!(e instanceof TabBridgeError)) logError(e);
        respondErr(e);
      },
    );
  }

  private postUi(ui: UiConn, msg: unknown): void {
    if (ui.closed) return;
    try {
      ui.port.postMessage(msg);
    } catch {
      /* ignore */
    }
  }

  private schedulePush(ui: UiConn): void {
    if (ui.closed || ui.timer !== undefined) return;
    const delay = Math.max(0, ui.lastPush + UI_PUSH_INTERVAL_MS - Date.now());
    ui.timer = setTimeout(() => {
      this.enqueue(() => {
        ui.timer = undefined;
        if (ui.closed) return;
        ui.lastPush = Date.now();
        this.postUi(ui, { t: 'ev', ev: 'state', d: this.uiState() });
      }).catch(logError);
    }, delay);
  }

  private resolveConnected(sel: EndpointSelector): EndpointRecord | undefined {
    if ('endpointId' in sel) {
      const rec = own(this.state.endpoints, sel.endpointId);
      return rec && this.isLive(rec.endpointId) ? rec : undefined;
    }
    const matches = Object.values(this.state.endpoints).filter(
      (r) => r.kind === 'page' && r.tabId === sel.tabId && this.isLive(r.endpointId),
    );
    return matches[matches.length - 1];
  }

  private refOf(rec: EndpointRecord): PairingEndpointRef {
    const ref: PairingEndpointRef = { endpointId: rec.endpointId, kind: rec.kind, origin: rec.origin };
    if (rec.tabId !== undefined) ref.tabId = rec.tabId;
    return ref;
  }

  private openRoomCount(id: EndpointId): number {
    return this.roomsOf(id).length;
  }

  private clearPairRequest(tabId: number | undefined): void {
    if (tabId === undefined) return;
    const before = this.state.pairRequests.length;
    this.state.pairRequests = this.state.pairRequests.filter((r) => r.tabId !== tabId);
    if (before !== this.state.pairRequests.length) {
      this.badge(tabId, '');
      this.mark();
    }
  }

  private async hasPermission(origin: string): Promise<boolean> {
    try {
      return (await this.d.platform.hasHostPermission(origin)) === true;
    } catch (e) {
      logError(e);
      return false;
    }
  }

  private async saveSettings(): Promise<void> {
    this.uiChanged = true;
    try {
      await this.d.platform.saveSettings(copySettings(this.settings));
    } catch (e) {
      logError(e);
    }
  }

  private async syncScripts(): Promise<void> {
    try {
      await this.d.platform.syncContentScripts([...this.settings.sites]);
    } catch (e) {
      logError(e);
    }
  }

  private async enableSite(origin: string, actor: AuditActor): Promise<void> {
    this.state.pendingSites = this.state.pendingSites.filter((s) => s !== origin);
    this.mark();
    if (this.settings.sites.includes(origin)) return;
    this.settings.sites.push(origin);
    await this.saveSettings();
    await this.syncScripts();
    // Injection can be slow (many tabs); do it after commit without blocking the queue.
    this.outbox.push(() => {
      this.d.platform.injectIntoOpenTabs(origin).catch(logError);
    });
    this.audit({ type: 'site.enabled', actor, data: { origin } });
  }

  private async disableSite(origin: string, actor: AuditActor): Promise<void> {
    this.state.pendingSites = this.state.pendingSites.filter((s) => s !== origin);
    this.settings.sites = this.settings.sites.filter((s) => s !== origin);
    this.mark();
    await this.saveSettings();
    await this.syncScripts();
    for (const room of Object.values(this.state.rooms)) {
      if (room.state !== 'closed' && room.members.some((m) => m.origin === origin)) this.closeRoom(room, 'site-disabled');
    }
    for (const rec of Object.values(this.state.endpoints)) {
      if (rec.kind === 'page' && rec.origin === origin) this.forgetEndpoint(rec.endpointId);
    }
    for (const r of this.state.pairRequests) if (r.origin === origin) this.badge(r.tabId, '');
    this.state.pairRequests = this.state.pairRequests.filter((r) => r.origin !== origin);
    this.audit({ type: 'site.disabled', actor, data: { origin } });
  }

  private async uiOp(m: UiMethod, p: unknown): Promise<unknown> {
    const ui: AuditActor = { kind: 'ui' };
    switch (m) {
      case 'state.get':
        noParams(p);
        return this.uiState();

      case 'site.enable': {
        const o = params(p, ['origin']);
        const origin = normalizeWebOrigin(o.origin);
        if (!origin) bad('origin must be a canonical http(s) origin');
        if (this.settings.sites.includes(origin)) {
          if (this.state.pendingSites.includes(origin)) {
            this.state.pendingSites = this.state.pendingSites.filter((s) => s !== origin);
            this.mark();
          }
          return { status: 'enabled' };
        }
        if (!(await this.hasPermission(origin))) {
          if (!this.state.pendingSites.includes(origin)) {
            this.state.pendingSites.push(origin);
            this.mark();
          }
          return { status: 'pending-permission' };
        }
        await this.enableSite(origin, ui);
        return { status: 'enabled' };
      }

      case 'site.disable': {
        const o = params(p, ['origin']);
        const origin = normalizeWebOrigin(o.origin);
        if (!origin) bad('origin must be a canonical http(s) origin');
        await this.disableSite(origin, ui);
        return { status: 'disabled' };
      }

      case 'pair.start': {
        const o = params(p, ['endpoint', 'proposal']);
        const sel = selectorParam(o.endpoint);
        const proposal = validateProposal(o.proposal);
        if (this.settings.paused) throw new TabBridgeError('PAUSED');
        const rec = this.resolveConnected(sel);
        if (!rec) throw new TabBridgeError('PEER_UNAVAILABLE');
        if (this.openRoomCount(rec.endpointId) >= MAX_ROOMS_PER_ENDPOINT) throw new TabBridgeError('TOO_MANY_ROOMS');
        const ref = this.refOf(rec);
        this.mark();
        const pr = this.pairing.start(ref, proposal);
        this.clearPairRequest(rec.tabId);
        this.audit({ type: 'pair.started', actor: ui, data: { initiator: ref, proposal: pr.proposal, expiresAt: pr.expiresAt } });
        return { code: pr.code, expiresAt: pr.expiresAt };
      }

      case 'pair.lookup': {
        const o = params(p, ['code', 'endpoint']);
        if (typeof o.code !== 'string' || o.code.length > 32) bad('code must be a string');
        const code = o.code;
        const sel = selectorParam(o.endpoint);
        if (this.settings.paused) throw new TabBridgeError('PAUSED');
        const rec = this.resolveConnected(sel);
        if (!rec) throw new TabBridgeError('PEER_UNAVAILABLE');
        this.mark(); // failure counters may change
        try {
          return this.pairing.lookup(code, this.refOf(rec));
        } catch (e) {
          this.auditPairFailed('lookup', e, rec);
          throw e;
        }
      }

      case 'pair.approve': {
        const o = params(p, ['code', 'endpoint']);
        if (typeof o.code !== 'string' || o.code.length > 32) bad('code must be a string');
        const code = o.code;
        const sel = selectorParam(o.endpoint);
        if (this.settings.paused) throw new TabBridgeError('PAUSED');
        const jrec = this.resolveConnected(sel);
        if (!jrec) throw new TabBridgeError('PEER_UNAVAILABLE');
        const tooMany = (id: EndpointId) => this.openRoomCount(id) >= MAX_ROOMS_PER_ENDPOINT;
        // Room caps are checked before the (single-use) code is consumed.
        if (tooMany(jrec.endpointId)) {
          this.auditPairFailed('approve', new TabBridgeError('TOO_MANY_ROOMS'), jrec);
          throw new TabBridgeError('TOO_MANY_ROOMS');
        }
        if (!(this.d.now() < this.pairing.lockedUntil())) {
          const pending = this.pairing.list().find((r) => r.code === code);
          if (pending && tooMany(pending.initiator.endpointId)) {
            this.auditPairFailed('approve', new TabBridgeError('TOO_MANY_ROOMS'), jrec);
            throw new TabBridgeError('TOO_MANY_ROOMS');
          }
        }
        this.mark();
        let res: ReturnType<PairingManager['approve']>;
        try {
          res = this.pairing.approve(code, this.refOf(jrec));
        } catch (e) {
          this.auditPairFailed('approve', e, jrec);
          throw e;
        }
        const irec = own(this.state.endpoints, res.initiator.endpointId);
        if (!irec || !this.isLive(irec.endpointId) || irec.origin !== res.initiator.origin || irec.kind !== res.initiator.kind) {
          this.auditPairFailed('approve', new TabBridgeError('PEER_UNAVAILABLE'), jrec);
          throw new TabBridgeError('PEER_UNAVAILABLE');
        }
        if (irec.endpointId === jrec.endpointId) throw new TabBridgeError('PAIRING_SELF');
        if (tooMany(irec.endpointId)) {
          this.auditPairFailed('approve', new TabBridgeError('TOO_MANY_ROOMS'), jrec);
          throw new TabBridgeError('TOO_MANY_ROOMS');
        }
        const now = this.d.now();
        let roomId = randomHex32((n) => this.d.randomBytes(n));
        while (own(this.state.rooms, roomId)) roomId = randomHex32((n) => this.d.randomBytes(n));
        const member = (r: EndpointRecord, role: RoomMember['role']): RoomMember => {
          const mem: RoomMember = { endpointId: r.endpointId, kind: r.kind, origin: r.origin, role };
          if (r.tabId !== undefined) mem.tabId = r.tabId;
          return mem;
        };
        const room: RoomRecord = {
          roomId,
          state: 'keying',
          createdAt: now,
          members: [member(irec, 'initiator'), member(jrec, 'joiner')],
          grant: grantFromProposal(res.proposal, now),
          pubKeys: {},
          confirmed: [],
          lastSeq: { [irec.endpointId]: 0, [jrec.endpointId]: 0 },
          rate: {},
          recentFrameIds: [],
          routed: {},
          counters: { routed: 0, rejected: 0 },
        };
        this.state.rooms[roomId] = room;
        this.mark();
        this.clearPairRequest(jrec.tabId);
        for (const mem of room.members) this.postTo(mem.endpointId, { t: 'key-request', v: 1, roomId });
        this.audit({
          type: 'pair.approved',
          roomId,
          actor: ui,
          data: {
            roomId,
            initiator: this.refOf(irec),
            joiner: this.refOf(jrec),
            grant: JSON.parse(JSON.stringify(room.grant)),
          },
        });
        this.armTimer(KEYING_TIMEOUT_MS + 50);
        return { roomId };
      }

      case 'pair.cancel': {
        const o = params(p, ['code']);
        if (typeof o.code !== 'string' || o.code.length > 32) bad('code must be a string');
        const pending = this.pairing.list().find((r) => r.code === o.code);
        const cancelled = this.pairing.cancel(o.code);
        if (cancelled) {
          this.mark();
          const data: Record<string, unknown> = {};
          if (pending) data.initiator = pending.initiator;
          this.audit({ type: 'pair.cancelled', actor: ui, data });
        }
        return { cancelled };
      }

      case 'room.close': {
        const o = params(p, ['roomId']);
        const room = own(this.state.rooms, hex32Param(o.roomId, 'roomId'));
        if (!room) throw new TabBridgeError('ROOM_NOT_FOUND');
        if (room.state === 'closed') return { closed: false };
        this.closeRoom(room, 'user', ui);
        return { closed: true };
      }

      case 'room.narrow': {
        const o = params(p, ['roomId', 'patch']);
        const room = own(this.state.rooms, hex32Param(o.roomId, 'roomId'));
        if (!room) throw new TabBridgeError('ROOM_NOT_FOUND');
        if (room.state === 'closed') throw new TabBridgeError('ROOM_CLOSED');
        const grant = applyNarrowing(room.grant, o.patch as never);
        room.grant = grant;
        this.mark();
        for (const mem of room.members) this.sendRoomUpdate(room, mem.endpointId);
        this.audit({
          type: 'room.narrowed',
          roomId: room.roomId,
          actor: ui,
          data: { patch: JSON.parse(JSON.stringify(o.patch)), grant: JSON.parse(JSON.stringify(grant)) },
        });
        return this.adminView(room);
      }

      case 'pause.set': {
        const o = params(p, ['paused']);
        if (typeof o.paused !== 'boolean') bad('paused must be boolean');
        if (this.settings.paused !== o.paused) {
          this.settings.paused = o.paused;
          await this.saveSettings();
          for (const conn of this.live.values()) this.post(conn, { t: 'paused', v: 1, paused: o.paused });
          this.audit({ type: 'pause.changed', actor: ui, data: { paused: o.paused } });
        }
        return { paused: this.settings.paused };
      }

      case 'audit.list': {
        const q: { limit?: number; beforeSeq?: number; roomId?: RoomId } = {};
        if (p !== undefined && p !== null) {
          const o = params(p, [], ['limit', 'beforeSeq', 'roomId']);
          if (o.limit !== undefined) q.limit = intParam(o.limit, 'limit', 1, 1000);
          if (o.beforeSeq !== undefined) q.beforeSeq = intParam(o.beforeSeq, 'beforeSeq', 0, Number.MAX_SAFE_INTEGER);
          if (o.roomId !== undefined) q.roomId = hex32Param(o.roomId, 'roomId');
        }
        return this.d.audit.list(q);
      }

      case 'audit.verify':
        noParams(p);
        return this.d.audit.verify();

      case 'audit.clear':
        noParams(p);
        return this.d.audit.clear(ui);

      case 'audit.export':
        noParams(p);
        return this.d.audit.export();

      case 'settings.get':
        noParams(p);
        return copySettings(this.settings);

      case 'settings.set': {
        const o = params(p, [], ['auditMaxEntries', 'defaultProposal']);
        let max: number | undefined;
        let proposal: Settings['defaultProposal'] | undefined;
        if (o.auditMaxEntries !== undefined) {
          max = clampAuditMax(intParam(o.auditMaxEntries, 'auditMaxEntries', 0, Number.MAX_SAFE_INTEGER));
        }
        if (o.defaultProposal !== undefined) proposal = validateProposal(o.defaultProposal);
        if (max !== undefined) {
          this.settings.auditMaxEntries = max;
          this.d.audit.setMaxEntries(max);
        }
        if (proposal !== undefined) this.settings.defaultProposal = proposal;
        await this.saveSettings();
        return copySettings(this.settings);
      }

      default:
        bad('unknown method');
    }
  }

  private auditPairFailed(stage: 'lookup' | 'approve', e: unknown, joiner: EndpointRecord): void {
    // Never include the code itself.
    const reason = toErrorPayload(e).code;
    this.audit({ type: 'pair.failed', actor: { kind: 'ui' }, data: { stage, reason, joiner: this.refOf(joiner) } });
  }
}

function logError(e: unknown): void {
  try {
    console.error('[tabbridge]', e instanceof Error ? e.message : e);
  } catch {
    /* ignore */
  }
}
