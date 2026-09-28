// Router unit tests: the test plays raw endpoints over FakePorts (posting E2R messages directly).
// The router never decrypts, so most frames carry a syntactically valid ciphertext of the right
// decoded length (size + 28). Real crypto is only used for key-share public keys.
import { beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/background/audit';
import { Router, classifyEndpointSender, type RouterPlatform } from '../../src/background/router';
import { ROUTER_STATE_KEY } from '../../src/background/state';
import { generateKeyPair } from '../../src/shared/crypto';
import { bytesToBase64, randomBytes, randomHex32 } from '../../src/shared/encoding';
import {
  AUDIT_MAX_MAX_ENTRIES,
  AUDIT_MIN_MAX_ENTRIES,
  DEFAULT_RATE,
  FILE_META_MAX,
  KEYING_TIMEOUT_MS,
  MAX_ROOMS_PER_ENDPOINT,
  PAIR_REQUEST_TTL_MS,
  PORT_ENDPOINT,
  PORT_UI,
  RESUME_GRACE_MS,
} from '../../src/shared/limits';
import type {
  AllowedMime,
  FrameKind,
  GrantProposal,
  RouterState,
  SenderInfo,
  Settings,
  UiState,
} from '../../src/shared/types';
import { FakeClock, FakePort, MemoryAuditStore, MemoryKV, portPair, settle } from '../helpers/fakes';

// ---------------------------------------------------------------------------------- fixtures

const EXT_ID = 'tbtestextensionid';
const EXT = `chrome-extension://${EXT_ID}`;
const A = 'https://a.example';
const B = 'https://b.example';
const C = 'http://127.0.0.1:5300';
const TAB_A = 11;
const TAB_B = 22;
const TAB_C = 33;

/* eslint-disable @typescript-eslint/no-explicit-any */
type Msg = any;

class FakePlatform implements RouterPlatform {
  extensionOrigin = EXT;
  extensionId = EXT_ID;
  granted = new Set<string>([A, B, C]);
  settings: Settings | undefined;
  synced: string[][] = [];
  injected: string[] = [];
  badges: { tabId: number; text: string }[] = [];
  async hasHostPermission(origin: string) {
    return this.granted.has(origin);
  }
  async syncContentScripts(sites: string[]) {
    this.synced.push([...sites]);
  }
  async injectIntoOpenTabs(origin: string) {
    this.injected.push(origin);
  }
  setBadge(tabId: number, text: string) {
    this.badges.push({ tabId, text });
  }
  async loadSettings() {
    return this.settings ? (JSON.parse(JSON.stringify(this.settings)) as Settings) : undefined;
  }
  async saveSettings(s: Settings) {
    this.settings = JSON.parse(JSON.stringify(s)) as Settings;
  }
}

interface Ctx {
  clock: FakeClock;
  kv: MemoryKV;
  store: MemoryAuditStore;
  audit: AuditLog;
  platform: FakePlatform;
  router: Router;
}

async function makeRouter(prev?: Partial<Ctx>): Promise<Ctx> {
  const clock = prev?.clock ?? new FakeClock();
  const kv = prev?.kv ?? new MemoryKV();
  const store = prev?.store ?? new MemoryAuditStore();
  const platform = prev?.platform ?? new FakePlatform();
  const audit = new AuditLog({ store, now: clock.now, flushDelayMs: 1 });
  await audit.init();
  const router = new Router({ session: kv, audit, platform, now: clock.now, randomBytes });
  await router.init();
  return { clock, kv, store, audit, platform, router };
}

async function setup(sites = [A, B, C]): Promise<Ctx> {
  const ctx = await makeRouter();
  for (const s of sites) expect(await ctx.router.handleUi('site.enable', { origin: s })).toEqual({ status: 'enabled' });
  return ctx;
}

async function flush(ctx: Ctx): Promise<void> {
  await settle(3);
  await ctx.router.whenIdle();
  await settle(3);
}

class Client {
  readonly msgs: Msg[] = [];
  endpointId = '';
  resumeToken = '';
  disconnected = false;
  constructor(
    readonly port: FakePort,
    readonly server: FakePort,
    readonly sender: SenderInfo,
  ) {
    port.onMessage.addListener((m) => this.msgs.push(m));
    port.onDisconnect.addListener(() => {
      this.disconnected = true;
    });
  }
  send(m: unknown): void {
    this.port.postMessage(m);
  }
  of(t: string): Msg[] {
    return this.msgs.filter((m) => m.t === t);
  }
  last(t: string): Msg {
    return this.of(t).at(-1);
  }
  clear(): void {
    this.msgs.length = 0;
  }
  acks(): Msg[] {
    return this.of('ack');
  }
  lastAck(): Msg {
    return this.last('ack');
  }
}

const pageSender = (origin: string, tabId: number, extra: Partial<SenderInfo> = {}): SenderInfo => ({
  tabId,
  frameId: 0,
  url: `${origin}/app.html`,
  origin,
  extensionId: EXT_ID,
  tabTitle: `Tab ${tabId}`,
  ...extra,
});
const panelSender = (extra: Partial<SenderInfo> = {}): SenderInfo => ({
  url: `${EXT}/ui/sidepanel.html`,
  origin: EXT,
  extensionId: EXT_ID,
  ...extra,
});

function open(ctx: Ctx, sender: SenderInfo): Client {
  const [c, s] = portPair(PORT_ENDPOINT);
  const client = new Client(c, s, sender);
  ctx.router.connectEndpoint(s, sender);
  return client;
}

async function connect(
  ctx: Ctx,
  sender: SenderInfo,
  kind: 'page' | 'panel' = 'page',
  resume?: { endpointId: string; resumeToken: string },
): Promise<Client> {
  const client = open(ctx, sender);
  client.send(resume ? { t: 'hello', v: 1, kind, resume } : { t: 'hello', v: 1, kind });
  await flush(ctx);
  const w = client.last('welcome');
  if (w) {
    client.endpointId = w.endpointId;
    client.resumeToken = w.resumeToken;
  }
  return client;
}

const ctFor = (size: number): string => bytesToBase64(new Uint8Array(size + 28).fill(7));

function frame(
  from: Client | string,
  roomId: string,
  seq: number,
  kind: FrameKind = 'prompt',
  size = 64,
  opts: { mime?: AllowedMime; frameId?: string; ct?: string } = {},
): Msg {
  const header: Msg = {
    v: 1,
    frameId: opts.frameId ?? randomHex32(),
    roomId,
    from: typeof from === 'string' ? from : from.endpointId,
    seq,
    kind,
    size,
    ts: 1_700_000_000_000,
  };
  if (opts.mime) header.mime = opts.mime;
  return { t: 'frame', v: 1, header, ct: opts.ct ?? ctFor(size) };
}

const dir = (over: Partial<GrantProposal['i2j']> = {}): GrantProposal['i2j'] => ({
  prompts: true,
  tasks: true,
  files: false,
  fileTypes: [],
  maxFileBytes: 1024 * 1024,
  ...over,
});
const proposal = (i2j = dir(), j2i = dir(), ttlMs = 900_000): GrantProposal => ({ i2j, j2i, ttlMs });

async function pubKey(): Promise<string> {
  return bytesToBase64((await generateKeyPair()).publicKeyRaw);
}

/** Pair via UI; returns roomId in keying state (key-requests delivered). */
async function pairKeying(ctx: Ctx, a: Client, b: Client, p = proposal()): Promise<string> {
  const sel = (c: Client) => (c.sender.tabId !== undefined ? { tabId: c.sender.tabId } : { endpointId: c.endpointId });
  const { code } = await ctx.router.handleUi('pair.start', { endpoint: sel(a), proposal: p });
  const { roomId } = await ctx.router.handleUi('pair.approve', { code, endpoint: sel(b) });
  await flush(ctx);
  return roomId;
}

/** Full keying handshake to an active room. */
async function pairActive(ctx: Ctx, a: Client, b: Client, p = proposal()): Promise<string> {
  const roomId = await pairKeying(ctx, a, b, p);
  a.send({ t: 'key-share', v: 1, roomId, publicKey: await pubKey() });
  b.send({ t: 'key-share', v: 1, roomId, publicKey: await pubKey() });
  await flush(ctx);
  a.send(frame(a, roomId, 1, 'confirm', 90));
  b.send(frame(b, roomId, 1, 'confirm', 90));
  await flush(ctx);
  a.send({ t: 'confirmed', v: 1, roomId });
  b.send({ t: 'confirmed', v: 1, roomId });
  await flush(ctx);
  expect(a.last('room')?.room.state).toBe('active');
  expect(b.last('room')?.room.state).toBe('active');
  a.clear();
  b.clear();
  return roomId;
}

async function auditTypes(ctx: Ctx): Promise<string[]> {
  await ctx.router.whenIdle();
  return (await ctx.router.handleUi('audit.list', { limit: 1000 })).map((e) => e.type).reverse();
}

async function auditOf(ctx: Ctx, type: string) {
  await ctx.router.whenIdle();
  return (await ctx.router.handleUi('audit.list', { limit: 1000 })).filter((e) => e.type === type);
}

async function state(ctx: Ctx): Promise<UiState> {
  return ctx.router.handleUi('state.get', undefined);
}

// ----------------------------------------------------------------------- classification

describe('sender classification (§1.2, §5.1)', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await setup([A]);
  });

  const expectRejected = async (sender: SenderInfo, code: string, kind: 'page' | 'panel' = 'page') => {
    const c = await connect(ctx, sender, kind);
    expect(c.of('welcome')).toHaveLength(0);
    expect(c.msgs).toEqual([{ t: 'rejected', v: 1, code }]);
    expect(c.disconnected).toBe(true);
    return c;
  };

  it('admits a top-frame page on an enabled origin', async () => {
    const c = await connect(ctx, pageSender(A, TAB_A));
    const w = c.last('welcome');
    expect(w).toMatchObject({ t: 'welcome', v: 1, origin: A, kind: 'page', rooms: [], paused: false, resumed: false });
    expect(w.endpointId).toMatch(/^[0-9a-f]{32}$/);
    expect(w.resumeToken).toMatch(/^[0-9a-f]{32}$/);
    expect(c.disconnected).toBe(false);
  });

  it('rejects a non-enabled origin with ORIGIN_NOT_ENABLED and audits it', async () => {
    await expectRejected(pageSender('https://evil.example', 5), 'ORIGIN_NOT_ENABLED');
    await expectRejected(pageSender('https://a.example:8443', 5), 'ORIGIN_NOT_ENABLED'); // same host, other port
    const rej = await auditOf(ctx, 'endpoint.rejected');
    expect(rej[1]?.data).toMatchObject({ code: 'ORIGIN_NOT_ENABLED', origin: 'https://evil.example' });
  });

  it('rejects non-top frames, missing tabs, non-http schemes and opaque origins', async () => {
    await expectRejected(pageSender(A, TAB_A, { frameId: 2 }), 'SENDER_REJECTED');
    await expectRejected(pageSender(A, TAB_A, { tabId: undefined }), 'SENDER_REJECTED');
    await expectRejected(pageSender(A, -1), 'SENDER_REJECTED');
    await expectRejected({ tabId: 1, frameId: 0, url: 'file:///etc/passwd', origin: 'file://' }, 'SENDER_REJECTED');
    await expectRejected({ tabId: 1, frameId: 0, url: 'ftp://a.example/x' }, 'SENDER_REJECTED');
    await expectRejected({ tabId: 1, frameId: 0, url: `${A}/sandboxed`, origin: 'null' }, 'SENDER_REJECTED');
    await expectRejected({ tabId: 1, frameId: 0, url: 'about:blank', origin: A }, 'SENDER_REJECTED');
    await expectRejected({ tabId: 1, frameId: 0, url: `data:text/html,hi` }, 'SENDER_REJECTED');
    await expectRejected({ tabId: 1, frameId: 0, url: `blob:${A}/1234` }, 'SENDER_REJECTED');
    await expectRejected(pageSender(A, TAB_A, { extensionId: 'otherextension' }), 'SENDER_REJECTED');
  });

  it('falls back to the URL origin when sender.origin is absent (Firefox)', async () => {
    const c = await connect(ctx, { tabId: TAB_A, frameId: 0, url: `${A}/x?y#z` });
    expect(c.last('welcome')?.origin).toBe(A);
  });

  it('admits the side panel only at the exact panel URL of this extension', async () => {
    const p = await connect(ctx, panelSender({ url: `${EXT}/ui/sidepanel.html?x=1#h` }), 'panel');
    expect(p.last('welcome')).toMatchObject({ kind: 'panel', origin: 'tabbridge://console' });
    await expectRejected(panelSender({ url: `${EXT}/ui/dashboard.html` }), 'SENDER_REJECTED', 'panel');
    await expectRejected(panelSender({ url: `${EXT}/ui/sidepanel.html`, extensionId: 'nope' }), 'SENDER_REJECTED', 'panel');
    await expectRejected(panelSender({ url: `chrome-extension://otherext/ui/sidepanel.html`, origin: 'chrome-extension://otherext' }), 'SENDER_REJECTED', 'panel');
    // kind in hello must match classification
    await expectRejected(panelSender(), 'SENDER_REJECTED', 'page');
    await expectRejected(pageSender(A, TAB_A), 'SENDER_REJECTED', 'panel');
  });

  it('classifyEndpointSender never trusts message fields and handles bad URLs', () => {
    const p = ctx.platform;
    expect(classifyEndpointSender({ tabId: 1, frameId: 0, url: 'not a url' }, p, [A])).toEqual({ reject: 'SENDER_REJECTED' });
    expect(classifyEndpointSender({ tabId: 1, frameId: 0, url: `${A}/`, origin: 'https://b.example' }, p, [A, B])).toEqual({
      reject: 'SENDER_REJECTED',
    });
    expect(classifyEndpointSender({ tabId: 1, frameId: 0, origin: 'HTTPS://A.EXAMPLE' }, p, [A])).toEqual({ reject: 'SENDER_REJECTED' });
  });

  it('requires hello first: anything else → error INVALID_MESSAGE + disconnect', async () => {
    const c = open(ctx, pageSender(A, TAB_A));
    c.send({ t: 'agent', v: 1, attached: true, name: 'x' });
    c.send({ t: 'hello', v: 1, kind: 'page' });
    await flush(ctx);
    expect(c.msgs).toHaveLength(1);
    expect(c.msgs[0]).toMatchObject({ t: 'error', code: 'INVALID_MESSAGE' });
    expect(c.disconnected).toBe(true);

    const g = open(ctx, pageSender(A, TAB_A));
    g.send('garbage');
    await flush(ctx);
    expect(g.msgs[0]).toMatchObject({ t: 'error', code: 'INVALID_MESSAGE' });
    expect(g.disconnected).toBe(true);

    const n = open(ctx, pageSender(A, TAB_A));
    n.send({ t: 'hello', v: 1, kind: 'native' }); // 'native' can never register
    await flush(ctx);
    expect(n.msgs[0]).toMatchObject({ t: 'error', code: 'INVALID_MESSAGE' });
    expect(n.disconnected).toBe(true);
    expect((await state(ctx)).endpoints).toHaveLength(0);
  });

  it('a bad frame after hello → error, connection stays up', async () => {
    const c = await connect(ctx, pageSender(A, TAB_A));
    c.send({ t: 'key-share', v: 1, roomId: 'xyz', publicKey: 'AAAA' });
    c.send({ t: 'hello', v: 1, kind: 'page' });
    c.send({ t: 'bogus', v: 1 });
    await flush(ctx);
    expect(c.of('error').map((e) => e.code)).toEqual(['INVALID_MESSAGE', 'INVALID_MESSAGE', 'INVALID_MESSAGE']);
    expect(c.disconnected).toBe(false);
  });

  it('queues connections that arrive before init() completes', async () => {
    const clock = new FakeClock();
    const platform = new FakePlatform();
    platform.settings = { sites: [A], paused: false, auditMaxEntries: 5000, defaultProposal: proposal() };
    const audit = new AuditLog({ store: new MemoryAuditStore(), now: clock.now, flushDelayMs: 1 });
    const router = new Router({ session: new MemoryKV(), audit, platform, now: clock.now, randomBytes });
    const [c, s] = portPair(PORT_ENDPOINT);
    const got: Msg[] = [];
    c.onMessage.addListener((m) => got.push(m));
    router.connectEndpoint(s, pageSender(A, TAB_A));
    c.postMessage({ t: 'hello', v: 1, kind: 'page' });
    await settle();
    expect(got).toHaveLength(0);
    await audit.init();
    await router.init();
    await settle();
    await router.whenIdle();
    await settle();
    expect(got[0]).toMatchObject({ t: 'welcome', origin: A });
  });
});

// ------------------------------------------------------------------------------ resume

describe('resume (§4 hello, D7)', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await setup();
  });

  it('resumes the same endpoint with the right token, tab and origin; rotates the token', async () => {
    const a = await connect(ctx, pageSender(A, TAB_A));
    const b = await connect(ctx, pageSender(B, TAB_B));
    const roomId = await pairActive(ctx, a, b);
    a.port.disconnect();
    await flush(ctx);
    expect(b.last('room').room.peer.connected).toBe(false);

    const a2 = await connect(ctx, pageSender(A, TAB_A), 'page', { endpointId: a.endpointId, resumeToken: a.resumeToken });
    const w = a2.last('welcome');
    expect(w).toMatchObject({ endpointId: a.endpointId, resumed: true });
    expect(w.resumeToken).not.toBe(a.resumeToken);
    expect(w.rooms.map((r: Msg) => r.roomId)).toEqual([roomId]);
    expect(w.rooms[0]).toMatchObject({ state: 'active', role: 'initiator', peer: { origin: B, connected: true } });
    expect(b.last('room').room.peer.connected).toBe(true);

    // The old token is single-use.
    a2.port.disconnect();
    await flush(ctx);
    const a3 = await connect(ctx, pageSender(A, TAB_A), 'page', { endpointId: a.endpointId, resumeToken: a.resumeToken });
    expect(a3.last('welcome')).toMatchObject({ resumed: false });
    expect(a3.endpointId).not.toBe(a.endpointId);
  });

  it('refuses resume with a wrong token, from another tab, another origin, or while connected', async () => {
    const a = await connect(ctx, pageSender(A, TAB_A));
    const resume = { endpointId: a.endpointId, resumeToken: a.resumeToken };
    // still connected
    const dup = await connect(ctx, pageSender(A, TAB_A), 'page', resume);
    expect(dup.last('welcome')).toMatchObject({ resumed: false });
    expect(dup.endpointId).not.toBe(a.endpointId);

    a.port.disconnect();
    await flush(ctx);
    const wrong = await connect(ctx, pageSender(A, TAB_A), 'page', { ...resume, resumeToken: randomHex32() });
    expect(wrong.last('welcome')).toMatchObject({ resumed: false });
    const otherTab = await connect(ctx, pageSender(A, 99), 'page', resume);
    expect(otherTab.last('welcome')).toMatchObject({ resumed: false });
    const otherOrigin = await connect(ctx, pageSender(B, TAB_A), 'page', resume);
    expect(otherOrigin.last('welcome')).toMatchObject({ resumed: false });
    // After all those failures the genuine resume still works.
    const ok = await connect(ctx, pageSender(A, TAB_A), 'page', resume);
    expect(ok.last('welcome')).toMatchObject({ resumed: true, endpointId: a.endpointId });
  });

  it('survives a worker restart: endpoints come back disconnected and can resume', async () => {
    const a = await connect(ctx, pageSender(A, TAB_A));
    const b = await connect(ctx, pageSender(B, TAB_B));
    const roomId = await pairActive(ctx, a, b);
    // New router instance over the same session storage (worker restart; old ports are dead).
    const ctx2 = await makeRouter({ clock: ctx.clock, kv: ctx.kv, store: ctx.store, platform: ctx.platform });
    const persisted = (await ctx.kv.get<RouterState>(ROUTER_STATE_KEY))!;
    expect(Object.values(persisted.endpoints).every((e) => !e.connected && e.disconnectedAt === ctx.clock.t)).toBe(true);
    const a2 = await connect(ctx2, pageSender(A, TAB_A), 'page', { endpointId: a.endpointId, resumeToken: a.resumeToken });
    const b2 = await connect(ctx2, pageSender(B, TAB_B), 'page', { endpointId: b.endpointId, resumeToken: b.resumeToken });
    expect(a2.last('welcome').resumed).toBe(true);
    expect(b2.last('welcome').resumed).toBe(true);
    // seq state survived: next frame is seq 2
    a2.send(frame(a2, roomId, 2));
    await flush(ctx2);
    expect(a2.lastAck()).toMatchObject({ ok: true });
    expect(b2.last('frame').header.seq).toBe(2);
  });

  it('closes rooms when the endpoint does not resume within RESUME_GRACE_MS', async () => {
    const a = await connect(ctx, pageSender(A, TAB_A));
    const b = await connect(ctx, pageSender(B, TAB_B));
    const roomId = await pairActive(ctx, a, b);
    a.port.disconnect();
    await flush(ctx);
    ctx.clock.advance(RESUME_GRACE_MS - 1);
    await ctx.router.sweep();
    await flush(ctx);
    expect(b.last('room').room.state).toBe('active');
    ctx.clock.advance(2);
    await ctx.router.sweep();
    await flush(ctx);
    expect(b.last('room').room).toMatchObject({ roomId, state: 'closed', closedReason: 'endpoint-gone' });
    const s = await state(ctx);
    expect(s.endpoints.map((e) => e.endpointId)).not.toContain(a.endpointId);
    const late = await connect(ctx, pageSender(A, TAB_A), 'page', { endpointId: a.endpointId, resumeToken: a.resumeToken });
    expect(late.last('welcome').resumed).toBe(false);
  });
});

// ----------------------------------------------------------------------------- pairing

describe('pairing → keying → active (§1.3)', () => {
  let ctx: Ctx;
  let a: Client;
  let b: Client;
  beforeEach(async () => {
    ctx = await setup();
    a = await connect(ctx, pageSender(A, TAB_A));
    b = await connect(ctx, pageSender(B, TAB_B));
    a.send({ t: 'agent', v: 1, attached: true, name: ' Planner‮\u0007 ' });
    await flush(ctx);
  });

  it('runs the full handshake with a transcript built from router records', async () => {
    const p = proposal(dir({ files: true, fileTypes: ['image/png'] }), dir({ tasks: false }));
    const { code, expiresAt } = await ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_A }, proposal: p });
    expect(code).toMatch(/^\d{6}$/);
    expect(expiresAt).toBeGreaterThan(ctx.clock.t);
    const preview = await ctx.router.handleUi('pair.lookup', { code, endpoint: { tabId: TAB_B } });
    expect(preview).toMatchObject({ initiator: { origin: A, kind: 'page' }, joiner: { origin: B, kind: 'page' }, proposal: p });
    const { roomId } = await ctx.router.handleUi('pair.approve', { code, endpoint: { tabId: TAB_B } });
    await flush(ctx);
    expect(a.last('key-request')).toEqual({ t: 'key-request', v: 1, roomId });
    expect(b.last('key-request')).toEqual({ t: 'key-request', v: 1, roomId });
    expect((await state(ctx)).rooms[0]).toMatchObject({ roomId, state: 'keying' });

    // Prompt frames are not allowed while keying.
    a.send(frame(a, roomId, 1, 'prompt'));
    // Confirm before room-keys is not allowed either.
    b.send(frame(b, roomId, 1, 'confirm', 90));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: false, code: 'ROOM_NOT_ACTIVE' });
    expect(b.lastAck()).toMatchObject({ ok: false, code: 'ROOM_NOT_ACTIVE' });

    const pa = await pubKey();
    const pb = await pubKey();
    a.send({ t: 'key-share', v: 1, roomId, publicKey: pa });
    await flush(ctx);
    expect(a.of('room-keys')).toHaveLength(0);
    a.send({ t: 'key-share', v: 1, roomId, publicKey: await pubKey() }); // second share
    b.send({ t: 'key-share', v: 1, roomId, publicKey: pa }); // reflected key
    await flush(ctx);
    expect(a.last('error')).toMatchObject({ code: 'INVALID_MESSAGE' });
    expect(b.last('error')).toMatchObject({ code: 'INVALID_MESSAGE' });
    b.send({ t: 'key-share', v: 1, roomId, publicKey: pb });
    await flush(ctx);

    const rk = a.last('room-keys');
    expect(rk).toEqual(b.last('room-keys'));
    expect(rk.transcript).toEqual({
      v: 1,
      roomId,
      initiator: { endpointId: a.endpointId, origin: A, kind: 'page', publicKey: pa },
      joiner: { endpointId: b.endpointId, origin: B, kind: 'page', publicKey: pb },
      grant: { i2j: p.i2j, j2i: p.j2i, expiresAt: ctx.clock.t + p.ttlMs, rate: { ...DEFAULT_RATE } },
    });

    // confirm frames: seq 1, once per sender, forwarded unchanged
    const fa = frame(a, roomId, 1, 'confirm', 90);
    a.send(fa);
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true, frameId: fa.header.frameId });
    expect(b.last('frame')).toEqual(fa);
    a.send(frame(a, roomId, 2, 'confirm', 90));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: false, code: 'ROOM_NOT_ACTIVE' });

    // A cannot claim 'confirmed' before B's confirm reached it.
    a.send({ t: 'confirmed', v: 1, roomId });
    await flush(ctx);
    expect(a.last('error')).toMatchObject({ code: 'INVALID_MESSAGE' });

    b.send(frame(b, roomId, 1, 'confirm', 90));
    await flush(ctx);
    a.send({ t: 'confirmed', v: 1, roomId });
    await flush(ctx);
    expect((await state(ctx)).rooms[0]!.state).toBe('keying');
    b.send({ t: 'confirmed', v: 1, roomId });
    await flush(ctx);

    const va = a.last('room').room;
    const vb = b.last('room').room;
    expect(va).toMatchObject({ roomId, state: 'active', role: 'initiator', outbound: p.i2j, inbound: p.j2i, peer: { origin: B, kind: 'page', connected: true } });
    expect(vb).toMatchObject({ roomId, state: 'active', role: 'joiner', outbound: p.j2i, inbound: p.i2j });
    expect(vb.peer).toEqual({ origin: A, kind: 'page', connected: true, agentName: 'Planner' }); // control & bidi chars stripped
    expect(await auditTypes(ctx)).toEqual(
      expect.arrayContaining(['site.enabled', 'pair.started', 'pair.approved', 'frame.routed', 'room.opened']),
    );
    // 'confirm' after active is refused
    b.send(frame(b, roomId, 2, 'confirm', 90));
    await flush(ctx);
    expect(b.lastAck()).toMatchObject({ ok: false, code: 'ROOM_NOT_ACTIVE' });
  });

  it('rejects key-share from non-members, bad keys, and outside keying', async () => {
    const c = await connect(ctx, pageSender(C, TAB_C));
    const roomId = await pairKeying(ctx, a, b);
    c.send({ t: 'key-share', v: 1, roomId, publicKey: await pubKey() });
    c.send({ t: 'key-share', v: 1, roomId: randomHex32(), publicKey: await pubKey() });
    // 65 bytes, 0x04 prefix, but not a curve point
    const bogus = new Uint8Array(65);
    bogus[0] = 4;
    a.send({ t: 'key-share', v: 1, roomId, publicKey: bytesToBase64(bogus) });
    // 0x05 prefix (validator only sees the base64 'B' prefix)
    const k = (await generateKeyPair()).publicKeyRaw;
    k[0] = 5;
    a.send({ t: 'key-share', v: 1, roomId, publicKey: bytesToBase64(k) });
    await flush(ctx);
    expect(c.of('error').map((e) => e.code)).toEqual(['NOT_A_MEMBER', 'ROOM_NOT_FOUND']);
    expect(a.of('error').map((e) => e.code)).toEqual(['INVALID_MESSAGE', 'INVALID_MESSAGE']);
  });

  it('closes keying rooms after KEYING_TIMEOUT_MS', async () => {
    const roomId = await pairKeying(ctx, a, b);
    ctx.clock.advance(KEYING_TIMEOUT_MS);
    await ctx.router.sweep();
    await flush(ctx);
    expect(a.last('room').room).toMatchObject({ roomId, state: 'closed', closedReason: 'key-confirm-failed' });
    expect(b.last('room').room).toMatchObject({ roomId, state: 'closed', closedReason: 'key-confirm-failed' });
  });

  it('pair.start requires a connected endpoint; lookup/approve failures are audited without the code', async () => {
    await expect(ctx.router.handleUi('pair.start', { endpoint: { tabId: 404 }, proposal: proposal() })).rejects.toMatchObject({
      code: 'PEER_UNAVAILABLE',
    });
    await expect(
      ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_A }, proposal: { ...proposal(), ttlMs: 5 } }),
    ).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    const { code } = await ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_A }, proposal: proposal() });
    await expect(ctx.router.handleUi('pair.lookup', { code, endpoint: { tabId: TAB_A } })).rejects.toMatchObject({ code: 'PAIRING_SELF' });
    const wrong = code === '000000' ? '000001' : '000000';
    await expect(ctx.router.handleUi('pair.approve', { code: wrong, endpoint: { tabId: TAB_B } })).rejects.toMatchObject({
      code: 'PAIRING_CODE_INVALID',
    });
    const failed = await auditOf(ctx, 'pair.failed');
    expect(failed.map((e) => e.data.reason).sort()).toEqual(['PAIRING_CODE_INVALID', 'PAIRING_SELF']);
    const all = JSON.stringify(ctx.router ? await ctx.router.handleUi('audit.export', undefined) : '');
    expect(all).not.toContain(`"${code}"`);
    expect(all).not.toContain(`"${wrong}"`);
    // cancel
    expect(await ctx.router.handleUi('pair.cancel', { code })).toEqual({ cancelled: true });
    expect(await ctx.router.handleUi('pair.cancel', { code })).toEqual({ cancelled: false });
  });

  it('pairs a page with the side panel (panel selected by endpointId)', async () => {
    const panel = await connect(ctx, panelSender(), 'panel');
    const roomId = await pairActive(ctx, a, panel);
    const s = await state(ctx);
    const room = s.rooms.find((r) => r.roomId === roomId)!;
    expect(room.members[1]).toMatchObject({ kind: 'panel', origin: 'tabbridge://console', role: 'joiner' });
    expect(room.members[1].tabId).toBeUndefined();
  });

  it('pair-request: page only, badge + UiState entry, deduped per tab, cleared by pair.start and TTL', async () => {
    a.send({ t: 'pair-request', v: 1, note: 'please pair' });
    a.send({ t: 'pair-request', v: 1, note: 'again' });
    await flush(ctx);
    let s = await state(ctx);
    expect(s.pairRequests).toEqual([{ tabId: TAB_A, origin: A, note: 'again', at: ctx.clock.t }]);
    expect(ctx.platform.badges.at(-1)).toEqual({ tabId: TAB_A, text: '!' });
    expect((await auditOf(ctx, 'pair.requested')).length).toBe(2);
    await ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_A }, proposal: proposal() });
    await flush(ctx);
    expect((await state(ctx)).pairRequests).toEqual([]);
    expect(ctx.platform.badges.at(-1)).toEqual({ tabId: TAB_A, text: '' });

    b.send({ t: 'pair-request', v: 1 });
    await flush(ctx);
    ctx.clock.advance(PAIR_REQUEST_TTL_MS);
    await ctx.router.sweep();
    await flush(ctx);
    s = await state(ctx);
    expect(s.pairRequests).toEqual([]);
    expect(ctx.platform.badges.at(-1)).toEqual({ tabId: TAB_B, text: '' });

    const panel = await connect(ctx, panelSender(), 'panel');
    panel.send({ t: 'pair-request', v: 1 });
    await flush(ctx);
    expect(panel.last('error')).toMatchObject({ code: 'NOT_PERMITTED' });
  });

  it('agent: validates the name and pushes room updates to peers', async () => {
    const roomId = await pairActive(ctx, a, b);
    b.send({ t: 'agent', v: 1, attached: true, name: '\u0000​' });
    await flush(ctx);
    expect(b.last('error')).toMatchObject({ code: 'INVALID_MESSAGE' });
    b.send({ t: 'agent', v: 1, attached: true, name: 'Researcher' });
    await flush(ctx);
    expect(a.last('room').room).toMatchObject({ roomId, peer: { agentName: 'Researcher' } });
    b.send({ t: 'agent', v: 1, attached: false });
    await flush(ctx);
    expect(a.last('room').room.peer.agentName).toBeUndefined();
  });

  it('enforces MAX_ROOMS_PER_ENDPOINT for both parties without consuming the code', async () => {
    const c = await connect(ctx, pageSender(C, TAB_C));
    for (let i = 0; i < MAX_ROOMS_PER_ENDPOINT; i++) await pairKeying(ctx, a, b);
    // Joiner (B) at the cap
    const { code } = await ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_C }, proposal: proposal() });
    await expect(ctx.router.handleUi('pair.approve', { code, endpoint: { tabId: TAB_B } })).rejects.toMatchObject({ code: 'TOO_MANY_ROOMS' });
    // Initiator (A) at the cap
    await expect(ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_A }, proposal: proposal() })).rejects.toMatchObject({
      code: 'TOO_MANY_ROOMS',
    });
    // Code survived the refusal: once one room closes, B can join.
    const firstRoom = (await state(ctx)).rooms[0]!.roomId;
    await ctx.router.handleUi('room.close', { roomId: firstRoom });
    await expect(ctx.router.handleUi('pair.approve', { code, endpoint: { tabId: TAB_B } })).resolves.toMatchObject({
      roomId: expect.stringMatching(/^[0-9a-f]{32}$/),
    });
    void c;
  });

  it('refuses approve when the initiator reached the cap after starting', async () => {
    const c = await connect(ctx, pageSender(C, TAB_C));
    for (let i = 0; i < MAX_ROOMS_PER_ENDPOINT - 1; i++) await pairKeying(ctx, a, b);
    const { code } = await ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_A }, proposal: proposal() });
    await pairKeying(ctx, b, a); // A (as joiner) now at the cap
    await expect(ctx.router.handleUi('pair.approve', { code, endpoint: { tabId: TAB_C } })).rejects.toMatchObject({ code: 'TOO_MANY_ROOMS' });
    void c;
  });
});

// ------------------------------------------------------------------------ frame policy

describe('frame policy (§5.3)', () => {
  let ctx: Ctx;
  let a: Client;
  let b: Client;
  let roomId: string;
  const P = proposal(dir({ files: true, fileTypes: ['image/png', 'text/plain'], maxFileBytes: 1000 }), dir({ tasks: false }));

  beforeEach(async () => {
    ctx = await setup();
    a = await connect(ctx, pageSender(A, TAB_A));
    b = await connect(ctx, pageSender(B, TAB_B));
    roomId = await pairActive(ctx, a, b, P);
  });

  const expectReject = async (sender: Client, msg: Msg, code: string) => {
    sender.clear();
    const peer = sender === a ? b : a;
    peer.clear();
    sender.send(msg);
    await flush(ctx);
    expect(sender.lastAck()).toMatchObject({ t: 'ack', ok: false, code });
    expect(peer.of('frame')).toHaveLength(0);
  };

  it('accepts a valid frame: forwards unchanged, acks, persists before posting, audits', async () => {
    const f = frame(a, roomId, 2, 'prompt', 120);
    let seenSeq: number | undefined;
    b.port.onMessage.addListener((m: Msg) => {
      if (m.t === 'frame') {
        const raw = ctx.kv.data.get(ROUTER_STATE_KEY)!;
        seenSeq = (JSON.parse(raw) as RouterState).rooms[roomId]!.lastSeq[a.endpointId];
      }
    });
    a.send(f);
    await flush(ctx);
    expect(b.last('frame')).toEqual(f);
    expect(a.lastAck()).toEqual({ t: 'ack', v: 1, roomId, frameId: f.header.frameId, ok: true });
    expect(seenSeq).toBe(2); // written through before the forward was posted
    const routed = (await auditOf(ctx, 'frame.routed')).find((e) => e.data.frameId === f.header.frameId)!;
    expect(routed.roomId).toBe(roomId);
    expect(routed.actor).toEqual({ kind: 'endpoint', endpointId: a.endpointId, origin: A });
    expect(routed.data).toMatchObject({ from: a.endpointId, to: b.endpointId, kind: 'prompt', size: 120, seq: 2 });
    expect(routed.data.ctSha256).toMatch(/^[0-9a-f]{64}$/);
    const room = (await state(ctx)).rooms.find((r) => r.roomId === roomId)!;
    expect(room.frames).toEqual({ routed: 3, rejected: 0 }); // 2 confirms + 1 prompt
  });

  it('1. paused → PAUSED', async () => {
    await ctx.router.handleUi('pause.set', { paused: true });
    await expectReject(a, frame(a, roomId, 2), 'PAUSED');
  });

  it('2. invalid header → INVALID_MESSAGE; ct length mismatch → INVALID_MESSAGE / PAYLOAD_TOO_LARGE', async () => {
    const f = frame(a, roomId, 2);
    delete f.header.ts;
    await expectReject(a, f, 'INVALID_MESSAGE');
    await expectReject(a, frame(a, roomId, 2, 'prompt', 10, { mime: 'text/plain' }), 'INVALID_MESSAGE');
    const extra = frame(a, roomId, 2);
    extra.extra = 1;
    await expectReject(a, extra, 'INVALID_MESSAGE');
    await expectReject(a, frame(a, roomId, 2, 'prompt', 64, { ct: ctFor(63) }), 'INVALID_MESSAGE');
    await expectReject(a, frame(a, roomId, 2, 'prompt', 64, { ct: ctFor(65) }), 'PAYLOAD_TOO_LARGE');
    await expectReject(a, frame(a, roomId, 2, 'prompt', 64, { ct: ctFor(5000) }), 'PAYLOAD_TOO_LARGE');
    await expectReject(a, frame(a, roomId, 2, 'prompt', 64, { ct: '!!!!' + ctFor(64).slice(4) }), 'INVALID_MESSAGE');
    // seq was never advanced by any of those
    a.send(frame(a, roomId, 2));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true });
  });

  it('2b. an unparseable header without ids → error{INVALID_MESSAGE}', async () => {
    a.clear();
    a.send({ t: 'frame', v: 1, header: 'nope', ct: ctFor(1) });
    await flush(ctx);
    expect(a.last('error')).toMatchObject({ code: 'INVALID_MESSAGE' });
    expect(a.disconnected).toBe(false);
  });

  it('3. spoofed from → SPOOFED_SENDER', async () => {
    await expectReject(a, frame(b.endpointId, roomId, 2), 'SPOOFED_SENDER');
  });

  it('4. unknown room, non-member, closed room', async () => {
    await expectReject(a, frame(a, randomHex32(), 2), 'ROOM_NOT_FOUND');
    const c = await connect(ctx, pageSender(C, TAB_C));
    await expectReject(c, frame(c, roomId, 1), 'NOT_A_MEMBER');
    await ctx.router.handleUi('room.close', { roomId });
    await flush(ctx);
    await expectReject(a, frame(a, roomId, 2), 'ROOM_CLOSED');
  });

  it('5. expired → ROOM_EXPIRED and the room closes', async () => {
    ctx.clock.advance(P.ttlMs);
    await expectReject(a, frame(a, roomId, 2), 'ROOM_EXPIRED');
    expect(a.last('room').room).toMatchObject({ state: 'closed', closedReason: 'expired' });
    expect(b.last('room').room).toMatchObject({ state: 'closed', closedReason: 'expired' });
  });

  it('5b. expiry is also enforced by sweep', async () => {
    ctx.clock.advance(P.ttlMs + 1);
    await ctx.router.sweep();
    await flush(ctx);
    expect(b.last('room').room).toMatchObject({ state: 'closed', closedReason: 'expired' });
    expect((await auditOf(ctx, 'room.closed'))[0]?.data).toEqual({ reason: 'expired' });
  });

  it('6. active forbids confirm', async () => {
    await expectReject(a, frame(a, roomId, 2, 'confirm', 90), 'ROOM_NOT_ACTIVE');
  });

  it('7. size above the per-kind limit → PAYLOAD_TOO_LARGE', async () => {
    await expectReject(a, frame(a, roomId, 2, 'task', 8193), 'PAYLOAD_TOO_LARGE');
    await expectReject(a, frame(a, roomId, 2, 'prompt', 36_865), 'PAYLOAD_TOO_LARGE');
  });

  it('8. grant: NOT_PERMITTED kind / mime, FILE_TOO_LARGE', async () => {
    await expectReject(b, frame(b, roomId, 2, 'task', 30), 'NOT_PERMITTED'); // j2i tasks=false
    await expectReject(b, frame(b, roomId, 2, 'file', 30, { mime: 'image/png' }), 'NOT_PERMITTED'); // j2i files=false
    await expectReject(a, frame(a, roomId, 2, 'file', 30, { mime: 'application/pdf' }), 'NOT_PERMITTED');
    await expectReject(a, frame(a, roomId, 2, 'file', 1000 + 4 + FILE_META_MAX + 1, { mime: 'image/png' }), 'FILE_TOO_LARGE');
    a.send(frame(a, roomId, 2, 'file', 1000 + 4 + FILE_META_MAX, { mime: 'image/png' }));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true });
    expect(b.last('frame').header.mime).toBe('image/png');
  });

  it('9. replay: wrong seq or duplicate frameId → REPLAY', async () => {
    const f = frame(a, roomId, 2);
    a.send(f);
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true });
    await expectReject(a, f, 'REPLAY'); // exact replay
    await expectReject(a, frame(a, roomId, 4), 'REPLAY'); // gap
    await expectReject(a, frame(a, roomId, 2), 'REPLAY'); // old seq
    await expectReject(a, frame(a, roomId, 3, 'prompt', 64, { frameId: f.header.frameId }), 'REPLAY'); // dup id
    a.send(frame(a, roomId, 3));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true });
  });

  it('10. rate limit → RATE_LIMITED; window resets after a minute', async () => {
    // 1 confirm frame already counted in this window.
    let seq = 2;
    for (let i = 1; i < DEFAULT_RATE.framesPerMinute; i++) a.send(frame(a, roomId, seq++, 'prompt', 16));
    await flush(ctx);
    expect(a.acks().filter((x) => x.ok)).toHaveLength(DEFAULT_RATE.framesPerMinute - 1);
    await expectReject(a, frame(a, roomId, seq), 'RATE_LIMITED');
    ctx.clock.advance(60_000);
    a.send(frame(a, roomId, seq));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true });
  });

  it('11. peer unavailable → PEER_UNAVAILABLE and seq is not consumed', async () => {
    b.port.disconnect();
    await flush(ctx);
    const f = frame(a, roomId, 2);
    await expectReject(a, f, 'PEER_UNAVAILABLE');
    const b2 = await connect(ctx, pageSender(B, TAB_B), 'page', { endpointId: b.endpointId, resumeToken: b.resumeToken });
    a.send(frame(a, roomId, 2));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true });
    expect(b2.last('frame').header.seq).toBe(2);
  });

  it('counts rejections and audits frame.rejected', async () => {
    await expectReject(a, frame(a, roomId, 9), 'REPLAY');
    const rej = await auditOf(ctx, 'frame.rejected');
    expect(rej.at(0)?.data).toMatchObject({ code: 'REPLAY', kind: 'prompt', size: 64 });
    expect(rej.at(0)?.roomId).toBe(roomId);
    expect((await state(ctx)).rooms[0]!.frames.rejected).toBe(1);
  });

  it('caps recentFrameIds and routed at 256 (FIFO)', async () => {
    let seq = 2;
    for (let i = 0; i < 300; i++) {
      if (i % 55 === 0) ctx.clock.advance(60_000); // stay under the rate limit
      a.send(frame(a, roomId, seq++, 'prompt', 8));
      await ctx.router.whenIdle();
      await settle(2);
    }
    await flush(ctx);
    const st = (await ctx.kv.get<RouterState>(ROUTER_STATE_KEY))!.rooms[roomId]!;
    expect(st.recentFrameIds).toHaveLength(256);
    expect(Object.keys(st.routed)).toHaveLength(256);
    expect(st.lastSeq[a.endpointId]).toBe(301);
  });
});

// --------------------------------------------------------- receipts, details, violations

describe('receipt / audit-detail / violation / leave (§4)', () => {
  let ctx: Ctx;
  let a: Client;
  let b: Client;
  let roomId: string;
  beforeEach(async () => {
    ctx = await setup();
    a = await connect(ctx, pageSender(A, TAB_A));
    b = await connect(ctx, pageSender(B, TAB_B));
    roomId = await pairActive(ctx, a, b);
  });

  const sendPrompt = async (seq = 2) => {
    const f = frame(a, roomId, seq, 'prompt', 40);
    a.send(f);
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: true });
    return f.header.frameId as string;
  };
  const detail = (kind = 'prompt') =>
    kind === 'task'
      ? { kind: 'task', task: { taskId: 't1', status: 'done' }, sha256: 'a'.repeat(64) }
      : { kind, text: 'hello', threadId: 'th1', sha256: 'a'.repeat(64) };

  it('forwards receipts from the recipient to the sender, once, and audits them', async () => {
    const fid = await sendPrompt();
    b.send({ t: 'receipt', v: 1, roomId, frameId: fid, status: 'rejected', code: 'FILE_TYPE_DENIED' });
    await flush(ctx);
    expect(a.last('receipt')).toEqual({ t: 'receipt', v: 1, roomId, frameId: fid, status: 'rejected', code: 'FILE_TYPE_DENIED' });
    expect((await auditOf(ctx, 'frame.receipt'))[0]?.data).toEqual({ frameId: fid, status: 'rejected', code: 'FILE_TYPE_DENIED' });
    // twice
    b.send({ t: 'receipt', v: 1, roomId, frameId: fid, status: 'accepted' });
    // from the sender itself
    const fid2 = await sendPrompt(3);
    a.send({ t: 'receipt', v: 1, roomId, frameId: fid2, status: 'accepted' });
    // unknown frame
    b.send({ t: 'receipt', v: 1, roomId, frameId: randomHex32(), status: 'accepted' });
    await flush(ctx);
    expect(b.of('error').map((e) => e.code)).toEqual(['INVALID_MESSAGE', 'INVALID_MESSAGE']);
    expect(a.last('error')).toMatchObject({ code: 'INVALID_MESSAGE' });
    expect(a.of('receipt')).toHaveLength(1);
  });

  it('accepts audit-detail strictly: right party, once per direction, matching kind, routed frames only', async () => {
    const fid = await sendPrompt();
    // received before an accepted receipt → refused
    b.send({ t: 'audit-detail', v: 1, roomId, frameId: fid, direction: 'received', detail: detail() });
    // sent from the wrong party
    b.send({ t: 'audit-detail', v: 1, roomId, frameId: fid, direction: 'sent', detail: detail() });
    // kind mismatch
    a.send({ t: 'audit-detail', v: 1, roomId, frameId: fid, direction: 'sent', detail: detail('response') });
    // unrouted frame
    a.send({ t: 'audit-detail', v: 1, roomId, frameId: randomHex32(), direction: 'sent', detail: detail() });
    await flush(ctx);
    expect(b.of('error').map((e) => e.code)).toEqual(['INVALID_MESSAGE', 'INVALID_MESSAGE']);
    expect(a.of('error').map((e) => e.code)).toEqual(['INVALID_MESSAGE', 'INVALID_MESSAGE']);
    expect(await auditOf(ctx, 'content.sent')).toHaveLength(0);

    a.send({ t: 'audit-detail', v: 1, roomId, frameId: fid, direction: 'sent', detail: detail() });
    b.send({ t: 'receipt', v: 1, roomId, frameId: fid, status: 'accepted' });
    b.send({ t: 'audit-detail', v: 1, roomId, frameId: fid, direction: 'received', detail: detail() });
    await flush(ctx);
    // twice
    a.send({ t: 'audit-detail', v: 1, roomId, frameId: fid, direction: 'sent', detail: detail() });
    b.send({ t: 'audit-detail', v: 1, roomId, frameId: fid, direction: 'received', detail: detail() });
    await flush(ctx);
    expect(a.of('error')).toHaveLength(3);
    expect(b.of('error')).toHaveLength(3);
    const sent = await auditOf(ctx, 'content.sent');
    const recv = await auditOf(ctx, 'content.received');
    expect(sent).toHaveLength(1);
    expect(recv).toHaveLength(1);
    expect(sent[0]).toMatchObject({ roomId, actor: { kind: 'endpoint', endpointId: a.endpointId, origin: A }, data: { frameId: fid, detail: detail() } });
    expect(recv[0]).toMatchObject({ actor: { endpointId: b.endpointId, origin: B } });
  });

  it('violation: audited; DECRYPT_FAILED / REPLAY / KEY_CONFIRM_FAILED close the room', async () => {
    b.send({ t: 'violation', v: 1, roomId, code: 'FILE_TYPE_MISMATCH', message: 'bad file' });
    await flush(ctx);
    expect((await state(ctx)).rooms[0]!.state).toBe('active');
    b.send({ t: 'violation', v: 1, roomId, code: 'DECRYPT_FAILED' });
    await flush(ctx);
    expect(a.last('room').room).toMatchObject({ state: 'closed', closedReason: 'violation' });
    expect(b.last('room').room).toMatchObject({ state: 'closed', closedReason: 'violation' });
    expect((await auditOf(ctx, 'violation')).map((e) => e.data.code)).toEqual(['DECRYPT_FAILED', 'FILE_TYPE_MISMATCH']);

    const room2 = await pairKeying(ctx, a, b);
    a.send({ t: 'violation', v: 1, roomId: room2, code: 'KEY_CONFIRM_FAILED' });
    await flush(ctx);
    expect(b.last('room').room).toMatchObject({ roomId: room2, state: 'closed', closedReason: 'key-confirm-failed' });

    const c = await connect(ctx, pageSender(C, TAB_C));
    const room3 = await pairActive(ctx, a, c);
    b.send({ t: 'violation', v: 1, roomId: room3, code: 'DECRYPT_FAILED' }); // non-member cannot close it
    await flush(ctx);
    expect(b.last('error')).toMatchObject({ code: 'NOT_A_MEMBER' });
    expect((await state(ctx)).rooms.find((r) => r.roomId === room3)!.state).toBe('active');
  });

  it('leave closes the room (peer-left) for both sides', async () => {
    b.send({ t: 'leave', v: 1, roomId });
    await flush(ctx);
    expect(a.last('room').room).toMatchObject({ state: 'closed', closedReason: 'peer-left' });
    expect(b.last('room').room).toMatchObject({ state: 'closed', closedReason: 'peer-left' });
  });
});

// -------------------------------------------------------------------- lifecycle via UI

describe('room lifecycle & UI operations (§5.2, §7)', () => {
  let ctx: Ctx;
  let a: Client;
  let b: Client;
  let roomId: string;
  beforeEach(async () => {
    ctx = await setup();
    a = await connect(ctx, pageSender(A, TAB_A));
    b = await connect(ctx, pageSender(B, TAB_B));
    roomId = await pairActive(ctx, a, b);
  });

  it('room.narrow narrows, pushes room updates, and rejects widening', async () => {
    const v = await ctx.router.handleUi('room.narrow', { roomId, patch: { i2j: { prompts: false } } });
    expect(v.grant.i2j.prompts).toBe(false);
    await flush(ctx);
    expect(a.last('room').room.outbound.prompts).toBe(false);
    expect(b.last('room').room.inbound.prompts).toBe(false);
    a.send(frame(a, roomId, 2));
    await flush(ctx);
    expect(a.lastAck()).toMatchObject({ ok: false, code: 'NOT_PERMITTED' });
    await expect(ctx.router.handleUi('room.narrow', { roomId, patch: { i2j: { prompts: true } } })).rejects.toMatchObject({ code: 'NOT_PERMITTED' });
    await expect(ctx.router.handleUi('room.narrow', { roomId, patch: { expiresAt: ctx.clock.t + 10 ** 9 } })).rejects.toMatchObject({
      code: 'NOT_PERMITTED',
    });
    await expect(ctx.router.handleUi('room.narrow', { roomId, patch: { bogus: 1 } as never })).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    expect((await auditOf(ctx, 'room.narrowed'))).toHaveLength(1);
  });

  it('room.close closes for both (user) and is idempotent', async () => {
    expect(await ctx.router.handleUi('room.close', { roomId })).toEqual({ closed: true });
    await flush(ctx);
    expect(a.last('room').room).toMatchObject({ state: 'closed', closedReason: 'user' });
    expect(b.last('room').room).toMatchObject({ state: 'closed', closedReason: 'user' });
    expect(await ctx.router.handleUi('room.close', { roomId })).toEqual({ closed: false });
    await expect(ctx.router.handleUi('room.close', { roomId: randomHex32() })).rejects.toMatchObject({ code: 'ROOM_NOT_FOUND' });
    await expect(ctx.router.handleUi('room.close', { roomId: 'x' })).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
  });

  it('closed rooms are pruned after the retention period', async () => {
    await ctx.router.handleUi('room.close', { roomId });
    ctx.clock.advance(599_999);
    await ctx.router.sweep();
    expect((await state(ctx)).rooms).toHaveLength(1);
    ctx.clock.advance(1);
    await ctx.router.sweep();
    expect((await state(ctx)).rooms).toHaveLength(0);
  });

  it('tab removal closes that tab’s rooms immediately (tab-closed)', async () => {
    await ctx.router.onTabRemoved(TAB_A);
    await flush(ctx);
    expect(b.last('room').room).toMatchObject({ state: 'closed', closedReason: 'tab-closed' });
    expect((await state(ctx)).endpoints.map((e) => e.endpointId)).not.toContain(a.endpointId);
  });

  it('site.disable closes rooms, disconnects that origin, unregisters scripts, audits', async () => {
    expect(await ctx.router.handleUi('site.disable', { origin: A })).toEqual({ status: 'disabled' });
    await flush(ctx);
    expect(b.last('room').room).toMatchObject({ state: 'closed', closedReason: 'site-disabled' });
    expect(a.disconnected).toBe(true);
    expect(b.disconnected).toBe(false);
    expect(ctx.platform.synced.at(-1)).toEqual([B, C]);
    expect(ctx.platform.settings!.sites).toEqual([B, C]);
    expect((await auditOf(ctx, 'site.disabled'))[0]?.data).toEqual({ origin: A });
    const again = await connect(ctx, pageSender(A, TAB_A));
    expect(again.msgs).toEqual([{ t: 'rejected', v: 1, code: 'ORIGIN_NOT_ENABLED' }]);
  });

  it('pause.set persists, broadcasts paused, blocks frames and pairing', async () => {
    const panel = await connect(ctx, panelSender(), 'panel');
    expect(await ctx.router.handleUi('pause.set', { paused: true })).toEqual({ paused: true });
    await flush(ctx);
    for (const c of [a, b, panel]) expect(c.last('paused')).toEqual({ t: 'paused', v: 1, paused: true });
    expect(ctx.platform.settings!.paused).toBe(true);
    await expect(ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_A }, proposal: proposal() })).rejects.toMatchObject({ code: 'PAUSED' });
    await expect(ctx.router.handleUi('pair.lookup', { code: '123456', endpoint: { tabId: TAB_B } })).rejects.toMatchObject({ code: 'PAUSED' });
    await expect(ctx.router.handleUi('pair.approve', { code: '123456', endpoint: { tabId: TAB_B } })).rejects.toMatchObject({ code: 'PAUSED' });
    const fresh = await connect(ctx, pageSender(C, TAB_C));
    expect(fresh.last('welcome').paused).toBe(true);
    await ctx.router.handleUi('pause.set', { paused: false });
    await flush(ctx);
    expect(a.last('paused')).toEqual({ t: 'paused', v: 1, paused: false });
    expect((await auditOf(ctx, 'pause.changed')).map((e) => e.data.paused)).toEqual([false, true]);
  });
});

// -------------------------------------------------------------------------- sites & settings

describe('sites, permissions & settings (§1.1, §7)', () => {
  it('site.enable: strict origin, pending permission, completion via onPermissionsAdded', async () => {
    const ctx = await makeRouter();
    for (const bad of ['https://x.example/', 'https://X.example', 'ftp://x.example', 'null', 'x', 'https://u:p@x.example', 'chrome-extension://abc'])
      await expect(ctx.router.handleUi('site.enable', { origin: bad })).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    const o = 'https://new.example';
    expect(await ctx.router.handleUi('site.enable', { origin: o })).toEqual({ status: 'pending-permission' });
    expect((await state(ctx)).pendingSites).toEqual([o]);
    expect(ctx.platform.synced).toHaveLength(0);
    ctx.platform.granted.add(o);
    await ctx.router.onPermissionsAdded();
    await flush(ctx);
    const s = await state(ctx);
    expect(s.sites).toEqual([o]);
    expect(s.pendingSites).toEqual([]);
    expect(ctx.platform.synced.at(-1)).toEqual([o]);
    expect(ctx.platform.injected).toEqual([o]);
    expect((await auditOf(ctx, 'site.enabled'))[0]?.actor).toEqual({ kind: 'router' });
    // revocation in browser settings disables the site
    const c = await connect(ctx, pageSender(o, 5));
    expect(c.last('welcome')).toBeTruthy();
    ctx.platform.granted.delete(o);
    await ctx.router.onPermissionsRemoved();
    await flush(ctx);
    expect((await state(ctx)).sites).toEqual([]);
    expect(c.disconnected).toBe(true);
  });

  it('settings default, settings.set clamps auditMaxEntries and validates defaultProposal', async () => {
    const ctx = await makeRouter();
    const s0 = await ctx.router.handleUi('settings.get', undefined);
    expect(s0).toMatchObject({ sites: [], paused: false, auditMaxEntries: 5000 });
    expect(s0.defaultProposal.ttlMs).toBe(3_600_000);
    expect((await ctx.router.handleUi('settings.set', { auditMaxEntries: 1 })).auditMaxEntries).toBe(AUDIT_MIN_MAX_ENTRIES);
    expect((await ctx.router.handleUi('settings.set', { auditMaxEntries: 10 ** 9 })).auditMaxEntries).toBe(AUDIT_MAX_MAX_ENTRIES);
    await expect(ctx.router.handleUi('settings.set', { auditMaxEntries: 1.5 })).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    await expect(ctx.router.handleUi('settings.set', { defaultProposal: { ...proposal(), ttlMs: 1 } })).rejects.toMatchObject({
      code: 'INVALID_MESSAGE',
    });
    const p = proposal(dir({ tasks: false }));
    expect((await ctx.router.handleUi('settings.set', { defaultProposal: p })).defaultProposal).toEqual(p);
    expect(ctx.platform.settings?.defaultProposal).toEqual(p);
    // stored settings are re-validated on load
    ctx.platform.settings = { sites: ['https://ok.example', 'javascript:alert(1)', 7], paused: 'yes', auditMaxEntries: -5 } as never;
    const ctx2 = await makeRouter({ platform: ctx.platform });
    expect(await ctx2.router.handleUi('settings.get', undefined)).toMatchObject({
      sites: ['https://ok.example'],
      paused: false,
      auditMaxEntries: AUDIT_MIN_MAX_ENTRIES,
    });
  });

  it('validates UI params strictly', async () => {
    const ctx = await setup([A]);
    const r = ctx.router;
    const bad = [
      r.handleUi('state.get', { x: 1 } as never),
      r.handleUi('site.enable', { origin: A, extra: 1 } as never),
      r.handleUi('pair.start', { endpoint: { tabId: -1 }, proposal: proposal() }),
      r.handleUi('pair.start', { endpoint: { tabId: 1, endpointId: randomHex32() } as never, proposal: proposal() }),
      r.handleUi('pair.lookup', { code: 123456 as never, endpoint: { tabId: 1 } }),
      r.handleUi('pause.set', { paused: 'yes' as never }),
      r.handleUi('audit.list', { limit: 0 }),
      r.handleUi('audit.list', { roomId: 'zz' }),
      r.handleUi('nope' as never, undefined as never),
    ];
    for (const p of bad) await expect(p).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
  });
});

// ------------------------------------------------------------------------------ UI port

describe('UI port (§5.1, §7)', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await setup([A, B]);
  });

  const uiConnect = (sender: SenderInfo) => {
    const [c, s] = portPair(PORT_UI);
    const got: Msg[] = [];
    let disconnected = false;
    c.onMessage.addListener((m) => got.push(m));
    c.onDisconnect.addListener(() => {
      disconnected = true;
    });
    ctx.router.connectUi(s, sender);
    return { c, got, isDisconnected: () => disconnected };
  };
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it('rejects non-extension senders silently', async () => {
    const senders: SenderInfo[] = [
      { url: 'https://evil.example/', origin: 'https://evil.example', tabId: 1, frameId: 0 },
      pageSender(A, TAB_A), // our own content script: right extensionId, web URL
      { url: `${EXT}/ui/popup.html`, origin: EXT, extensionId: 'otherextension' },
      { url: `chrome-extension://otherextension/ui/popup.html`, extensionId: 'otherextension' },
      { url: `${EXT}/ui/popup.html` }, // no extension id
    ];
    for (const s of senders) {
      const u = uiConnect(s);
      u.c.postMessage({ id: 1, m: 'state.get' });
      await flush(ctx);
      expect(u.got).toHaveLength(0);
      expect(u.isDisconnected()).toBe(true);
    }
  });

  it('serves extension pages: state on connect, responses, coalesced state pushes', async () => {
    const u = uiConnect({ url: `${EXT}/ui/popup.html?tabId=3`, origin: EXT, extensionId: EXT_ID });
    await wait(10);
    await flush(ctx);
    expect(u.got[0]).toMatchObject({ t: 'ev', ev: 'state', d: { sites: [A, B], paused: false } });
    u.c.postMessage({ id: 7, m: 'settings.get' });
    u.c.postMessage({ id: 8, m: 'nope' });
    u.c.postMessage({ id: 9, m: 'site.enable', p: { origin: 'bad' } });
    u.c.postMessage({ id: 10, m: 'state.get', p: undefined, extra: 1 });
    await flush(ctx);
    const res = u.got.filter((m) => m.t === 'res');
    expect(res[0]).toMatchObject({ t: 'res', id: 7, ok: true, r: { sites: [A, B] } });
    expect(res.slice(1).map((r) => [r.id, r.ok, r.e.code])).toEqual([
      [8, false, 'INVALID_MESSAGE'],
      [9, false, 'INVALID_MESSAGE'],
      [10, false, 'INVALID_MESSAGE'],
    ]);
    // A burst of changes (5 connects, each a separate op) is coalesced: ≤ 1 push per 50 ms.
    await wait(60);
    u.got.length = 0;
    for (let i = 0; i < 5; i++) open(ctx, pageSender(A, 100 + i)).send({ t: 'hello', v: 1, kind: 'page' });
    await flush(ctx);
    await wait(120);
    await flush(ctx);
    const pushes = u.got.filter((m) => m.t === 'ev');
    expect(pushes.length).toBeGreaterThanOrEqual(1);
    expect(pushes.length).toBeLessThanOrEqual(2);
    expect(pushes.at(-1).d.endpoints).toHaveLength(5);
  });
});

// ------------------------------------------------------------------------ UiState & audit

describe('UiState and the audit chain', () => {
  it('exposes a complete UiState; the audit chain verifies and never contains the pairing code', async () => {
    const ctx = await setup([A, B]);
    const a = await connect(ctx, pageSender(A, TAB_A));
    const b = await connect(ctx, pageSender(B, TAB_B));
    a.send({ t: 'agent', v: 1, attached: true, name: 'Planner' });
    a.send({ t: 'pair-request', v: 1, note: 'hi' });
    await flush(ctx);
    const { code } = await ctx.router.handleUi('pair.start', { endpoint: { tabId: TAB_B }, proposal: proposal() });
    let s = await state(ctx);
    expect(s.pairings).toEqual([{ code, initiator: { endpointId: b.endpointId, kind: 'page', origin: B, tabId: TAB_B }, expiresAt: expect.any(Number) }]);
    expect(s.endpoints).toEqual([
      { endpointId: a.endpointId, kind: 'page', origin: A, tabId: TAB_A, title: `Tab ${TAB_A}`, agent: { attached: true, name: 'Planner' }, connected: true },
      { endpointId: b.endpointId, kind: 'page', origin: B, tabId: TAB_B, title: `Tab ${TAB_B}`, agent: { attached: false }, connected: true },
    ]);
    expect(s.pairRequests).toEqual([{ tabId: TAB_A, origin: A, note: 'hi', at: ctx.clock.t }]);
    expect(s.lockedUntil).toBe(0);
    await ctx.router.handleUi('pair.cancel', { code });

    const roomId = await pairActive(ctx, a, b);
    const f = frame(a, roomId, 2);
    a.send(f);
    await flush(ctx);
    b.send({ t: 'receipt', v: 1, roomId, frameId: f.header.frameId, status: 'accepted' });
    a.send({ t: 'audit-detail', v: 1, roomId, frameId: f.header.frameId, direction: 'sent', detail: { kind: 'prompt', text: 'x', threadId: 't', sha256: 'b'.repeat(64) } });
    b.send({ t: 'audit-detail', v: 1, roomId, frameId: f.header.frameId, direction: 'received', detail: { kind: 'prompt', text: 'x', threadId: 't', sha256: 'b'.repeat(64) } });
    a.send(frame(a, roomId, 9));
    await flush(ctx);
    await ctx.router.handleUi('room.narrow', { roomId, patch: { j2i: { tasks: false } } });
    await ctx.router.handleUi('room.close', { roomId });
    s = await state(ctx);
    expect(s.rooms).toEqual([
      expect.objectContaining({ roomId, state: 'closed', closedReason: 'user', frames: { routed: 3, rejected: 1 } }),
    ]);
    expect(s.pairings).toEqual([]);

    const verify = await ctx.router.handleUi('audit.verify', undefined);
    expect(verify).toMatchObject({ ok: true });
    const types = new Set((await ctx.router.handleUi('audit.list', { limit: 1000 })).map((e) => e.type));
    for (const t of ['site.enabled', 'pair.requested', 'pair.started', 'pair.cancelled', 'pair.approved', 'room.opened', 'frame.routed', 'frame.rejected', 'frame.receipt', 'content.sent', 'content.received', 'room.narrowed', 'room.closed'])
      expect(types, t).toContain(t);
    const all = JSON.stringify(await ctx.router.handleUi('audit.export', undefined));
    expect(all).not.toContain(`"${code}"`);
    expect(all).not.toMatch(/"code":"\d{6}"/);
    // The session state DOES hold live codes (trusted storage), the audit log does not.
    const cleared = await ctx.router.handleUi('audit.clear', undefined);
    expect(cleared.cleared).toBeGreaterThan(10);
    expect(await ctx.router.handleUi('audit.verify', undefined)).toEqual({ ok: true, count: 1 });
  });

  it('throttles endpoint-triggered audit records', async () => {
    const ctx = await setup([A, B]);
    const a = await connect(ctx, pageSender(A, TAB_A));
    for (let i = 0; i < 100; i++) a.send(frame(a, randomHex32(), 1));
    await flush(ctx);
    expect(a.acks().filter((x) => x.code === 'ROOM_NOT_FOUND')).toHaveLength(100);
    expect((await auditOf(ctx, 'frame.rejected')).length).toBe(60);
    ctx.clock.advance(60_000);
    a.send(frame(a, randomHex32(), 1));
    await flush(ctx);
    const rej = await auditOf(ctx, 'frame.rejected');
    expect(rej[0]?.data.suppressedBefore).toBe(40);
  });
});
