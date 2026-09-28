// Integration: real Router + two real Endpoints over chrome-shaped fake ports, real WebCrypto.
// Exercises the full pairing → keying → bidirectional conversation → files → revocation path.
import { beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/background/audit';
import { Router, type RouterPlatform } from '../../src/background/router';
import { Endpoint, type EndpointSink } from '../../src/endpoint/endpoint';
import { randomBytes, randomHex32 } from '../../src/shared/encoding';
import { encryptFrame } from '../../src/shared/crypto';
import { encodeBody } from '../../src/shared/protocol';
import { PORT_ENDPOINT, PORT_UI } from '../../src/shared/limits';
import type {
  AgentErrorEvent,
  FrameHeader,
  GrantProposal,
  InboundFileData,
  InboundMessage,
  InboundTask,
  RoomView,
  SenderInfo,
  Settings,
} from '../../src/shared/types';
import { FakePort, MemoryAuditStore, MemoryKV, portPair, settle } from '../helpers/fakes';

const EXT = 'chrome-extension://tbtestextension';
const A = 'https://planner.example';
const B = 'http://127.0.0.1:5302';

const PNG = Uint8Array.from(
  Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64'),
);

class RecordingSink implements EndpointSink {
  agent = true;
  prompts: InboundMessage[] = [];
  responses: InboundMessage[] = [];
  tasks: InboundTask[] = [];
  files: InboundFileData[] = [];
  rooms: RoomView[] = [];
  errors: AgentErrorEvent[] = [];
  onPromptHook?: (m: InboundMessage) => void;
  hasAgent() {
    return this.agent;
  }
  onPrompt(m: InboundMessage) {
    this.prompts.push(m);
    this.onPromptHook?.(m);
  }
  onResponse(m: InboundMessage) {
    this.responses.push(m);
  }
  onTask(t: InboundTask) {
    this.tasks.push(t);
  }
  onFile(f: InboundFileData) {
    this.files.push(f);
  }
  onRoom(r: RoomView) {
    this.rooms.push(r);
  }
  onError(e: AgentErrorEvent) {
    this.errors.push(e);
  }
}

function fakePlatform(): RouterPlatform & { settings?: Settings } {
  const p: RouterPlatform & { settings?: Settings } = {
    extensionOrigin: EXT,
    extensionId: 'tbtestextension',
    hasHostPermission: async () => true,
    syncContentScripts: async () => {},
    injectIntoOpenTabs: async () => {},
    setBadge: () => {},
    loadSettings: async () => p.settings,
    saveSettings: async (s) => {
      p.settings = JSON.parse(JSON.stringify(s)) as Settings;
    },
  };
  return p;
}

interface World {
  router: Router;
  audit: AuditLog;
  now: { t: number };
  a: Endpoint;
  b: Endpoint;
  sa: RecordingSink;
  sb: RecordingSink;
  roomId: string;
  serverPorts: Map<Endpoint, FakePort[]>;
}

const proposal = (over: Partial<GrantProposal> = {}): GrantProposal => ({
  i2j: { prompts: true, tasks: true, files: true, fileTypes: ['image/png', 'text/plain'], maxFileBytes: 1024 * 1024 },
  j2i: { prompts: true, tasks: true, files: false, fileTypes: [], maxFileBytes: 1024 * 1024 },
  ttlMs: 900_000,
  ...over,
});

async function makeWorld(p = proposal()): Promise<World> {
  const now = { t: 1_700_000_000_000 };
  const audit = new AuditLog({ store: new MemoryAuditStore(), now: () => now.t, flushDelayMs: 1 });
  await audit.init();
  const router = new Router({
    session: new MemoryKV(),
    audit,
    platform: fakePlatform(),
    now: () => now.t,
    randomBytes,
  });
  await router.init();
  for (const o of [A, B]) {
    expect(await router.handleUi('site.enable', { origin: o })).toEqual({ status: 'enabled' });
  }
  const serverPorts = new Map<Endpoint, FakePort[]>();
  const mk = (sender: SenderInfo, sink: RecordingSink) => {
    const list: FakePort[] = [];
    const ep = new Endpoint({
      kind: 'page',
      sink,
      now: () => now.t,
      deliveryTimeoutMs: 2_000,
      connect: () => {
        const [client, server] = portPair(PORT_ENDPOINT);
        list.push(server);
        router.connectEndpoint(server, sender);
        return client;
      },
    });
    serverPorts.set(ep, list);
    return ep;
  };
  const sa = new RecordingSink();
  const sb = new RecordingSink();
  const a = mk({ tabId: 11, frameId: 0, url: `${A}/planner.html`, origin: A }, sa);
  const b = mk({ tabId: 22, frameId: 0, url: `${B}/researcher.html`, origin: B }, sb);
  await a.start();
  await b.start();
  a.setAgent(true, 'Planner');
  b.setAgent(true, 'Researcher');
  await settle();

  const { code } = await router.handleUi('pair.start', { endpoint: { tabId: 11 }, proposal: p });
  const preview = await router.handleUi('pair.lookup', { code, endpoint: { tabId: 22 } });
  expect(preview.initiator.origin).toBe(A);
  expect(preview.joiner.origin).toBe(B);
  // Approval is pinned to the reviewed joiner endpoint, not the tab (SECURITY_REVIEW M1).
  const { roomId } = await router.handleUi('pair.approve', { code, endpoint: { endpointId: preview.joiner.endpointId } });
  await waitFor(() => a.rooms().some((r) => r.roomId === roomId && r.state === 'active') && b.rooms().some((r) => r.state === 'active'));
  return { router, audit, now, a, b, sa, sb, roomId, serverPorts };
}

async function waitFor(cond: () => boolean, ms = 3_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('waitFor timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('integration: pairing → conversation → files → revocation', () => {
  let w: World;
  beforeEach(async () => {
    w = await makeWorld();
  });

  it('opens an active room with correct perspectives on both sides', () => {
    const ra = w.a.rooms().find((r) => r.roomId === w.roomId)!;
    const rb = w.b.rooms().find((r) => r.roomId === w.roomId)!;
    expect(ra.role).toBe('initiator');
    expect(rb.role).toBe('joiner');
    expect(ra.peer.origin).toBe(B);
    expect(rb.peer.origin).toBe(A);
    expect(ra.outbound.files).toBe(true);
    expect(rb.outbound.files).toBe(false);
    expect(rb.inbound.fileTypes).toEqual(['image/png', 'text/plain']);
  });

  it('runs a bidirectional prompt/response loop in both directions', async () => {
    // B auto-replies to A's prompts; A auto-replies to B's prompts.
    w.sb.onPromptHook = (m) => void w.b.sendText(m.roomId, 'response', `B heard: ${m.text}`, { threadId: m.threadId, inReplyTo: m.id });
    w.sa.onPromptHook = (m) => void w.a.sendText(m.roomId, 'response', `A heard: ${m.text}`, { threadId: m.threadId, inReplyTo: m.id });

    const sent = await w.a.sendText(w.roomId, 'prompt', 'hello from A', { threadId: 'thread-1' });
    expect(sent.status).toBe('accepted');
    await waitFor(() => w.sa.responses.length === 1);
    expect(w.sb.prompts[0]).toMatchObject({ text: 'hello from A', threadId: 'thread-1', from: { origin: A, agentName: 'Planner' } });
    expect(w.sa.responses[0]).toMatchObject({ text: 'B heard: hello from A', inReplyTo: sent.frameId, threadId: 'thread-1' });

    const sent2 = await w.b.sendText(w.roomId, 'prompt', 'hello from B');
    await waitFor(() => w.sb.responses.length === 1);
    expect(w.sb.responses[0]).toMatchObject({ text: 'A heard: hello from B', inReplyTo: sent2.frameId });
  });

  it('exchanges task state', async () => {
    await w.b.sendTask(w.roomId, { taskId: 'research-1', status: 'running', progress: 0.25, summary: 'reading' });
    await waitFor(() => w.sa.tasks.length === 1);
    expect(w.sa.tasks[0]!.task).toEqual({ taskId: 'research-1', status: 'running', progress: 0.25, summary: 'reading' });
  });

  it('transfers an allowed file with provenance; rejects disguised and ungranted files', async () => {
    await w.a.sendFile(w.roomId, { name: 'chart.png', bytes: PNG });
    await waitFor(() => w.sb.files.length === 1);
    const f = w.sb.files[0]!;
    expect(f.name).toBe('chart.png');
    expect(f.mime).toBe('image/png');
    expect(Array.from(f.bytes)).toEqual(Array.from(PNG));
    expect(f.provenance).toMatchObject({ fromOrigin: A, roomId: w.roomId, detectedType: 'image/png', size: PNG.length, validated: true });
    expect(f.provenance.sha256).toMatch(/^[0-9a-f]{64}$/);

    const html = new TextEncoder().encode('<!doctype html><script>alert(1)</script>');
    await expect(w.a.sendFile(w.roomId, { name: 'x.png', bytes: html })).rejects.toMatchObject({ code: 'FILE_TYPE_MISMATCH' });
    await expect(w.a.sendFile(w.roomId, { name: 'x.html', bytes: html })).rejects.toMatchObject({ code: 'FILE_TYPE_DENIED' });
    await expect(w.a.sendFile(w.roomId, { name: 'notes.pdf', bytes: PNG })).rejects.toMatchObject({ code: 'FILE_TYPE_MISMATCH' });
    // B → A files not granted.
    await expect(w.b.sendFile(w.roomId, { name: 'chart.png', bytes: PNG })).rejects.toMatchObject({ code: 'NOT_PERMITTED' });
    expect(w.sb.files).toHaveLength(1);
    expect(w.sa.files).toHaveLength(0);
  });

  it('reports NO_AGENT when the peer has no agent attached', async () => {
    w.sb.agent = false;
    await expect(w.a.sendText(w.roomId, 'prompt', 'anyone?')).rejects.toMatchObject({ code: 'NO_AGENT' });
    expect(w.sb.prompts).toHaveLength(0);
  });

  it('enforces narrowing, rejects widening, and closes rooms on user revoke', async () => {
    const narrowed = await w.router.handleUi('room.narrow', { roomId: w.roomId, patch: { i2j: { prompts: false } } });
    expect(narrowed.grant.i2j.prompts).toBe(false);
    await waitFor(() => w.a.rooms().find((r) => r.roomId === w.roomId)?.outbound.prompts === false);
    await expect(w.a.sendText(w.roomId, 'prompt', 'still there?')).rejects.toMatchObject({ code: 'NOT_PERMITTED' });
    await expect(w.router.handleUi('room.narrow', { roomId: w.roomId, patch: { j2i: { files: true } } })).rejects.toMatchObject({
      code: 'NOT_PERMITTED',
    });

    await w.router.handleUi('room.close', { roomId: w.roomId });
    await waitFor(() => w.b.rooms().find((r) => r.roomId === w.roomId)?.state === 'closed');
    await expect(w.b.sendText(w.roomId, 'prompt', 'hello?')).rejects.toMatchObject({ code: expect.stringMatching(/ROOM_(CLOSED|NOT_ACTIVE)/) });
  });

  it('pause blocks all traffic until resumed', async () => {
    await w.router.handleUi('pause.set', { paused: true });
    await expect(w.a.sendText(w.roomId, 'prompt', 'x')).rejects.toMatchObject({ code: 'PAUSED' });
    await w.router.handleUi('pause.set', { paused: false });
    w.sb.onPromptHook = (m) => void w.b.sendText(m.roomId, 'response', 'ok', { threadId: m.threadId, inReplyTo: m.id });
    await expect(w.a.sendText(w.roomId, 'prompt', 'x')).resolves.toMatchObject({ status: 'accepted' });
  });

  it('expires rooms after their TTL', async () => {
    w.now.t += 900_001;
    await expect(w.a.sendText(w.roomId, 'prompt', 'late')).rejects.toMatchObject({ code: expect.stringMatching(/ROOM_(EXPIRED|CLOSED|NOT_ACTIVE)/) });
    await w.router.sweep();
    await waitFor(() => w.b.rooms().find((r) => r.roomId === w.roomId)?.state === 'closed');
  });

  it('router rejects a replayed frame and a spoofed sender injected on the wire', async () => {
    // Capture A's next outbound frame as it hits the router, then replay it.
    const serverA = w.serverPorts.get(w.a)!.at(-1)!;
    const clientA = serverA.peer;
    const acks: unknown[] = [];
    clientA.onMessage.addListener((m) => {
      if ((m as { t: string }).t === 'ack') acks.push(m);
    });
    w.sb.onPromptHook = (m) => void w.b.sendText(m.roomId, 'response', 'r', { threadId: m.threadId, inReplyTo: m.id });
    await w.a.sendText(w.roomId, 'prompt', 'original');
    const frame = clientA.sent.find((m) => (m as { t: string }).t === 'frame' && (m as { header: FrameHeader }).header.kind === 'prompt');
    expect(frame).toBeTruthy();
    clientA.postMessage(frame); // replay
    await waitFor(() => acks.some((a) => (a as { code?: string }).code === 'REPLAY'));
    expect(w.sb.prompts).toHaveLength(1);

    // Spoof: A's port sends a frame claiming to be from B.
    const bId = w.b.endpointId!;
    const h: FrameHeader = { v: 1, frameId: randomHex32(), roomId: w.roomId, from: bId, seq: 99, kind: 'prompt', size: 10, ts: w.now.t };
    clientA.postMessage({ t: 'frame', v: 1, header: h, ct: Buffer.alloc(38).toString('base64') });
    await waitFor(() => acks.some((a) => (a as { code?: string }).code === 'SPOOFED_SENDER'));
  });

  it('receiver independently rejects a disguised file pushed by a compromised sender', async () => {
    // Build a malicious frame with a key that is NOT the room key: receiver must fail decryption,
    // report a violation, and the router closes the room. (A compromised sender *with* the key is
    // covered by the endpoint unit tests: receiver-side validation rejects the content.)
    const serverA = w.serverPorts.get(w.a)!.at(-1)!;
    const clientA = serverA.peer;
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const body = encodeBody('prompt', { text: 'forged', threadId: 't' });
    const lastSeq = clientA.sent.filter((m) => (m as { t: string }).t === 'frame').length;
    const h: FrameHeader = { v: 1, frameId: randomHex32(), roomId: w.roomId, from: w.a.endpointId!, seq: lastSeq + 1, kind: 'prompt', size: body.length, ts: w.now.t };
    clientA.postMessage({ t: 'frame', v: 1, header: h, ct: await encryptFrame(key, h, body) });
    await waitFor(() => w.b.rooms().find((r) => r.roomId === w.roomId)?.state === 'closed');
    expect(w.sb.prompts).toHaveLength(0);
  });

  it('keeps a verifiable audit chain with routing and content records, never the pairing code', async () => {
    w.sb.onPromptHook = (m) => void w.b.sendText(m.roomId, 'response', 'answer', { threadId: m.threadId, inReplyTo: m.id });
    await w.a.sendText(w.roomId, 'prompt', 'audit me');
    await waitFor(() => w.sa.responses.length === 1);
    await settle();
    await w.router.whenIdle();
    const verify = await w.router.handleUi('audit.verify', undefined);
    expect(verify).toMatchObject({ ok: true });
    const entries = await w.router.handleUi('audit.list', { limit: 1000 });
    const types = new Set(entries.map((e) => e.type));
    for (const t of ['site.enabled', 'pair.started', 'pair.approved', 'room.opened', 'frame.routed', 'frame.receipt', 'content.sent', 'content.received'])
      expect(types, t).toContain(t);
    const received = entries.find((e) => e.type === 'content.received' && (e.data as { detail?: { text?: string } }).detail?.text === 'audit me');
    expect(received?.actor.origin).toBe(B);
    // Honest endpoints report equal content hashes, so the cross-check must not false-positive.
    expect(types.has('content.mismatch')).toBe(false);
    const exported = JSON.stringify(await w.router.handleUi('audit.export', undefined));
    const codes = [...exported.matchAll(/"code":"(\d{6})"/g)];
    expect(codes).toHaveLength(0);
  });
});

describe('integration: origin isolation & UI port', () => {
  it('rejects endpoints from non-enabled origins and non-top frames; UI port only for extension pages', async () => {
    const audit = new AuditLog({ store: new MemoryAuditStore(), now: () => 1, flushDelayMs: 1 });
    await audit.init();
    const router = new Router({ session: new MemoryKV(), audit, platform: fakePlatform(), now: () => 1, randomBytes });
    await router.init();
    await router.handleUi('site.enable', { origin: A });

    const tryConnect = async (sender: SenderInfo) => {
      const sink = new RecordingSink();
      const ep = new Endpoint({
        kind: 'page',
        sink,
        connect: () => {
          const [c, s] = portPair(PORT_ENDPOINT);
          router.connectEndpoint(s, sender);
          return c;
        },
      });
      return ep.start().then(
        () => 'ok',
        (e: { code?: string }) => e.code,
      );
    };
    expect(await tryConnect({ tabId: 1, frameId: 0, url: 'https://evil.example/', origin: 'https://evil.example' })).toBe('ORIGIN_NOT_ENABLED');
    expect(await tryConnect({ tabId: 1, frameId: 3, url: `${A}/`, origin: A })).toBe('SENDER_REJECTED');
    expect(await tryConnect({ tabId: 1, frameId: 0, url: 'https://planner.example:8443/', origin: 'https://planner.example:8443' })).toBe(
      'ORIGIN_NOT_ENABLED',
    );
    expect(await tryConnect({ tabId: 1, frameId: 0, url: `${A}/x`, origin: A })).toBe('ok');

    const [c, s] = portPair(PORT_UI);
    const got: unknown[] = [];
    c.onMessage.addListener((m) => got.push(m));
    router.connectUi(s, { url: 'https://evil.example/', origin: 'https://evil.example', tabId: 1, frameId: 0 });
    c.postMessage({ id: 1, m: 'state.get' });
    await settle();
    expect(got).toHaveLength(0);
  });
});
