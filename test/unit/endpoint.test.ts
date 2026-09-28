// Endpoint unit tests (SPEC.md §4, §4.1, §4.2, §6.3). The test plays the router with raw R2E
// messages over FakePorts and, where needed, a "manual peer" holding real ECDH/AES-GCM keys so it
// can craft arbitrary (including malicious) encrypted frames.
import { describe, expect, it } from 'vitest';
import { Endpoint, type EndpointSink } from '../../src/endpoint/endpoint';
import { FakeClock, portPair, type FakePort } from '../helpers/fakes';
import {
  decryptFrame,
  deriveRoomKey,
  encryptFrame,
  generateKeyPair,
  sha256Hex,
  transcriptHash,
} from '../../src/shared/crypto';
import { decodeBody, encodeBody, validateE2R } from '../../src/shared/protocol';
import { base64ToBytes, bytesToBase64, randomHex32, utf8Encode } from '../../src/shared/encoding';
import { TabBridgeError } from '../../src/shared/errors';
import type {
  AgentErrorEvent,
  DirectionGrant,
  FileMeta,
  FrameHeader,
  FrameKind,
  Grant,
  InboundFileData,
  InboundMessage,
  InboundTask,
  Role,
  RoomView,
  Transcript,
  TranscriptParty,
} from '../../src/shared/types';

// ------------------------------------------------------------------ helpers

type Msg = Record<string, any>;
const T0 = 1_700_000_000_000;
const HOUR = 3_600_000;
const ORIGIN_A = 'https://a.example';
const ORIGIN_B = 'https://b.example';
const RATE = { framesPerMinute: 60, bytesPerMinute: 16 * 1024 * 1024 };
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);

function dg(over: Partial<DirectionGrant> = {}): DirectionGrant {
  return { prompts: true, tasks: true, files: true, fileTypes: ['image/png', 'text/plain', 'application/json'], maxFileBytes: 1 << 20, ...over };
}

async function waitFor<T>(fn: () => T | undefined | null | false, ms = 3000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('waitFor timed out');
    await new Promise((r) => setTimeout(r, 2));
  }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  const e = await p.then(
    () => undefined,
    (x: unknown) => x,
  );
  expect(e).toBeInstanceOf(TabBridgeError);
  expect((e as TabBridgeError).code).toBe(code);
}

class RecSink implements EndpointSink {
  agent = true;
  prompts: InboundMessage[] = [];
  responses: InboundMessage[] = [];
  tasks: InboundTask[] = [];
  files: InboundFileData[] = [];
  rooms: RoomView[] = [];
  errors: AgentErrorEvent[] = [];
  paused: boolean[] = [];
  onDeliver?: () => void;
  hasAgent(): boolean {
    return this.agent;
  }
  onPrompt(m: InboundMessage): void {
    this.onDeliver?.();
    this.prompts.push(m);
  }
  onResponse(m: InboundMessage): void {
    this.onDeliver?.();
    this.responses.push(m);
  }
  onTask(t: InboundTask): void {
    this.onDeliver?.();
    this.tasks.push(t);
  }
  onFile(f: InboundFileData): void {
    this.onDeliver?.();
    this.files.push(f);
  }
  onRoom(r: RoomView): void {
    this.rooms.push(r);
  }
  onError(e: AgentErrorEvent): void {
    this.errors.push(e);
  }
  onPaused(p: boolean): void {
    this.paused.push(p);
  }
}

/** Router side of one endpoint's (successive) ports. */
class Server {
  ports: FakePort[] = [];
  clients: FakePort[] = [];
  msgs: Msg[] = [];
  onMsg?: (m: Msg) => void;
  connect = () => {
    const [c, s] = portPair('tb.endpoint');
    this.ports.push(s);
    this.clients.push(c);
    s.onMessage.addListener((m) => {
      this.msgs.push(m as Msg);
      this.onMsg?.(m as Msg);
    });
    return c;
  };
  get port(): FakePort {
    return this.ports[this.ports.length - 1]!;
  }
  send(m: Msg): void {
    this.port.postMessage(m);
  }
  of(t: string): Msg[] {
    return this.msgs.filter((m) => m.t === t);
  }
}

function welcome(endpointId: string, resumeToken: string, origin: string, extra: Partial<Msg> = {}): Msg {
  return { t: 'welcome', v: 1, endpointId, resumeToken, origin, kind: 'page', rooms: [], paused: false, resumed: false, ...extra };
}

interface ManualOpts {
  outbound?: Partial<DirectionGrant>;
  inbound?: Partial<DirectionGrant>;
  /** Grants bound in the transcript (defaults to the view grants). */
  boundOutbound?: Partial<DirectionGrant>;
  boundInbound?: Partial<DirectionGrant>;
  role?: Role;
  deliveryTimeoutMs?: number;
  /** Mutate the transcript the router sends to the endpoint. */
  tamper?: (t: Transcript) => Transcript;
  /** Stop after room-keys (do not complete confirmation). */
  stopAfterKeys?: boolean;
}

/** One real Endpoint; the test plays the router AND the peer (with real keys). */
async function setupManual(o: ManualOpts = {}) {
  const clock = new FakeClock(T0);
  const server = new Server();
  const sink = new RecSink();
  const ep = new Endpoint({
    connect: server.connect,
    kind: 'page',
    sink,
    now: clock.now,
    deliveryTimeoutMs: o.deliveryTimeoutMs ?? 3000,
    reconnectDelayMs: 5,
  });
  const EP = randomHex32();
  const TOKEN = randomHex32();
  const PEER = randomHex32();
  const ROOM = randomHex32();
  const role: Role = o.role ?? 'initiator';

  const started = ep.start();
  await waitFor(() => server.of('hello')[0]);
  server.send(welcome(EP, TOKEN, ORIGIN_A));
  const info = await started;

  const outbound = dg(o.outbound);
  const inbound = dg(o.inbound);
  const view = (state: RoomView['state'], over: Partial<RoomView> = {}): RoomView => ({
    roomId: ROOM,
    state,
    createdAt: T0,
    expiresAt: T0 + HOUR,
    role,
    peer: { origin: ORIGIN_B, kind: 'page', connected: true, agentName: 'bob' },
    outbound,
    inbound,
    ...over,
  });

  server.send({ t: 'room', v: 1, room: view('keying') });
  server.send({ t: 'key-request', v: 1, roomId: ROOM });
  const ks = await waitFor(() => server.of('key-share')[0]);
  expect(validateE2R(ks)).toEqual(ks);

  const peerKp = await generateKeyPair();
  const bOut = dg({ ...o.outbound, ...o.boundOutbound });
  const bIn = dg({ ...o.inbound, ...o.boundInbound });
  const grant: Grant =
    role === 'initiator'
      ? { i2j: bOut, j2i: bIn, expiresAt: T0 + HOUR, rate: RATE }
      : { i2j: bIn, j2i: bOut, expiresAt: T0 + HOUR, rate: RATE };
  const me: TranscriptParty = { endpointId: EP, origin: ORIGIN_A, kind: 'page', publicKey: ks.publicKey };
  const peerParty: TranscriptParty = { endpointId: PEER, origin: ORIGIN_B, kind: 'page', publicKey: bytesToBase64(peerKp.publicKeyRaw) };
  const transcript: Transcript = {
    v: 1,
    roomId: ROOM,
    initiator: role === 'initiator' ? me : peerParty,
    joiner: role === 'initiator' ? peerParty : me,
    grant,
  };
  const sentTranscript = o.tamper ? o.tamper(structuredClone(transcript)) : transcript;
  const hash = await transcriptHash(transcript);
  const key = await deriveRoomKey(peerKp.privateKey, base64ToBytes(ks.publicKey), ROOM, hash);

  let peerSeq = 0;
  const peer = {
    async frame(kind: FrameKind, plaintext: Uint8Array, over: Partial<FrameHeader> = {}, mutateCt?: (ct: string) => string) {
      const header: FrameHeader = {
        v: 1,
        frameId: randomHex32(),
        roomId: ROOM,
        from: PEER,
        seq: over.seq ?? peerSeq + 1,
        kind,
        size: plaintext.length,
        ts: clock.now(),
        ...over,
      };
      peerSeq = Math.max(peerSeq, header.seq);
      let ct = await encryptFrame(key, header, plaintext);
      if (mutateCt) ct = mutateCt(ct);
      server.send({ t: 'frame', v: 1, header, ct });
      return header;
    },
    text(kind: 'prompt' | 'response', text: string, extra: Record<string, string> = {}, over: Partial<FrameHeader> = {}) {
      return this.frame(kind, encodeBody(kind, { text, threadId: 'th1', ...extra }), over);
    },
    file(meta: FileMeta, bytes: Uint8Array, over: Partial<FrameHeader> = {}) {
      return this.frame('file', encodeBody('file', { meta, bytes }), { mime: meta.mime, ...over });
    },
  };

  server.send({ t: 'room-keys', v: 1, roomId: ROOM, transcript: sentTranscript });
  const ctx = { ep, server, sink, clock, EP, TOKEN, PEER, ROOM, key, hash, transcript, view, peer, info };
  if (o.stopAfterKeys) return ctx;

  const confirm = await waitFor(() => server.of('frame')[0]);
  server.send({ t: 'ack', v: 1, roomId: ROOM, frameId: confirm.header.frameId, ok: true });
  await peer.frame('confirm', encodeBody('confirm', { transcriptHash: hash }));
  await waitFor(() => server.of('confirmed')[0]);
  server.send({ t: 'room', v: 1, room: view('active') });
  await waitFor(() => sink.rooms.find((r) => r.state === 'active'));
  return ctx;
}

type Ctx = Awaited<ReturnType<typeof setupManual>>;

/** Decrypt the n-th frame the endpoint sent (0 = its confirm). */
async function sentFrame(c: Ctx, n: number) {
  const f = await waitFor(() => c.server.of('frame')[n]);
  const pt = await decryptFrame(c.key, f.header, f.ct);
  return { f, header: f.header as FrameHeader, pt };
}

function ack(c: Ctx, frameId: string, ok = true, code?: string) {
  c.server.send({ t: 'ack', v: 1, roomId: c.ROOM, frameId, ok, ...(code ? { code } : {}) });
}
function receipt(c: Ctx, frameId: string, status: string, code?: string) {
  c.server.send({ t: 'receipt', v: 1, roomId: c.ROOM, frameId, status, ...(code ? { code } : {}) });
}
const byFrame = (c: Ctx, t: string, frameId: string) => c.server.msgs.find((m) => m.t === t && m.frameId === frameId);

// ------------------------------------------------------------------ tests

describe('Endpoint: connect', () => {
  it('sends hello and resolves with welcome info; resume token is never exposed', async () => {
    const server = new Server();
    const sink = new RecSink();
    const ep = new Endpoint({ connect: server.connect, kind: 'panel', sink });
    const p = ep.start();
    const hello = await waitFor(() => server.of('hello')[0]);
    expect(hello).toEqual({ t: 'hello', v: 1, kind: 'panel' });
    const id = randomHex32();
    const token = randomHex32();
    server.send(welcome(id, token, 'tabbridge://console', { kind: 'panel', paused: true }));
    const info = await p;
    expect(info).toEqual({ endpointId: id, origin: 'tabbridge://console', kind: 'panel', rooms: [], paused: true });
    expect(ep.endpointId).toBe(id);
    expect(ep.origin).toBe('tabbridge://console');
    expect(JSON.stringify(ep)).not.toContain(token);
    expect(Object.keys(ep)).toEqual([]);
    expect(ep.start()).toBe(p); // idempotent
    ep.stop();
  });

  it('rejects start with the router code and never reconnects', async () => {
    const server = new Server();
    const ep = new Endpoint({ connect: server.connect, kind: 'page', sink: new RecSink(), reconnectDelayMs: 1 });
    server.onMsg = (m) => {
      if (m.t === 'hello') {
        server.send({ t: 'rejected', v: 1, code: 'ORIGIN_NOT_ENABLED' });
        server.port.disconnect();
      }
    };
    await expectCode(ep.start(), 'ORIGIN_NOT_ENABLED');
    await sleep(30);
    expect(server.ports.length).toBe(1);
    expect(() => ep.requestPairing()).toThrow(TabBridgeError);
  });

  it('stops permanently when connect() throws (extension context invalidated)', async () => {
    const ep = new Endpoint({
      connect: () => {
        throw new Error('Extension context invalidated.');
      },
      kind: 'page',
      sink: new RecSink(),
    });
    await expectCode(ep.start(), 'NOT_CONNECTED');
  });

  it('drops malformed router messages', async () => {
    const c = await setupManual();
    c.server.send({ t: 'room', v: 1, room: { ...c.view('closed'), extra: 1 } });
    c.server.send({ t: 'nope', v: 1 });
    await sleep(10);
    expect(c.sink.rooms.some((r) => r.state === 'closed')).toBe(false);
    expect(c.ep.rooms()[0]!.state).toBe('active');
  });

  it('sends agent, pair-request and paused notifications', async () => {
    const c = await setupManual();
    c.ep.setAgent(true, 'ali\u0000ce');
    c.ep.requestPairing('please\npair');
    c.server.send({ t: 'paused', v: 1, paused: true });
    await waitFor(() => c.server.of('pair-request')[0]);
    expect(c.server.of('agent')[0]).toEqual({ t: 'agent', v: 1, attached: true, name: 'alice' });
    expect(c.server.of('pair-request')[0]).toEqual({ t: 'pair-request', v: 1, note: 'pleasepair' });
    await waitFor(() => c.sink.paused.length === 1);
    c.ep.setAgent(false);
    await waitFor(() => c.server.of('agent')[1]);
    expect(c.server.of('agent')[1]).toEqual({ t: 'agent', v: 1, attached: false });
  });
});

describe('Endpoint: key agreement', () => {
  it('confirms with a correct transcript (manual peer)', async () => {
    const c = await setupManual();
    const { header, pt } = await sentFrame(c, 0);
    expect(header.kind).toBe('confirm');
    expect(header.seq).toBe(1);
    expect(header.from).toBe(c.EP);
    expect(decodeBody('confirm', pt)).toEqual({ transcriptHash: c.hash });
    expect(c.server.of('confirmed')).toEqual([{ t: 'confirmed', v: 1, roomId: c.ROOM }]);
    expect(c.server.of('violation')).toEqual([]);
  });

  it.each([
    ['wrong own public key', (t: Transcript) => ({ ...t, initiator: { ...t.initiator, publicKey: t.joiner.publicKey } })],
    ['wrong own endpointId', (t: Transcript) => ({ ...t, initiator: { ...t.initiator, endpointId: randomHex32() } })],
    ['wrong own origin', (t: Transcript) => ({ ...t, initiator: { ...t.initiator, origin: 'https://evil.example' } })],
    ['swapped roles', (t: Transcript) => ({ ...t, initiator: t.joiner, joiner: t.initiator })],
  ])('rejects room-keys with %s → KEY_CONFIRM_FAILED, no confirm frame', async (_n, tamper) => {
    const c = await setupManual({ tamper, stopAfterKeys: true });
    const v = await waitFor(() => c.server.of('violation')[0]);
    expect(v).toMatchObject({ t: 'violation', roomId: c.ROOM, code: 'KEY_CONFIRM_FAILED' });
    await sleep(10);
    expect(c.server.of('frame')).toEqual([]);
    expect(c.sink.errors[0]!.code).toBe('KEY_CONFIRM_FAILED');
    expect(c.sink.rooms.at(-1)).toMatchObject({ state: 'closed', closedReason: 'key-confirm-failed' });
  });

  it('tampered transcript (grant changed by router) → confirm fails with KEY_CONFIRM_FAILED', async () => {
    const c = await setupManual({
      stopAfterKeys: true,
      tamper: (t) => ({ ...t, grant: { ...t.grant, expiresAt: t.grant.expiresAt + 1 } }),
    });
    // The endpoint derives a key from a different transcript than the peer.
    const f = await waitFor(() => c.server.of('frame')[0]);
    await expect(decryptFrame(c.key, f.header, f.ct)).rejects.toThrow();
    c.server.send({ t: 'ack', v: 1, roomId: c.ROOM, frameId: f.header.frameId, ok: true });
    await c.peer.frame('confirm', encodeBody('confirm', { transcriptHash: c.hash }));
    const v = await waitFor(() => c.server.of('violation')[0]);
    expect(v.code).toBe('KEY_CONFIRM_FAILED');
    expect(c.server.of('confirmed')).toEqual([]);
  });

  it('peer confirm that decrypts but carries a different hash → KEY_CONFIRM_FAILED', async () => {
    const c = await setupManual({ stopAfterKeys: true });
    const f = await waitFor(() => c.server.of('frame')[0]);
    c.server.send({ t: 'ack', v: 1, roomId: c.ROOM, frameId: f.header.frameId, ok: true });
    await c.peer.frame('confirm', encodeBody('confirm', { transcriptHash: 'ab'.repeat(32) }));
    const v = await waitFor(() => c.server.of('violation')[0]);
    expect(v.code).toBe('KEY_CONFIRM_FAILED');
    expect(c.server.of('confirmed')).toEqual([]);
  });

  it('peer data frame before its confirm → KEY_CONFIRM_FAILED, not delivered', async () => {
    const c = await setupManual({ stopAfterKeys: true });
    await waitFor(() => c.server.of('frame')[0]);
    await c.peer.text('prompt', 'sneaky', {}, { seq: 1 });
    const v = await waitFor(() => c.server.of('violation')[0]);
    expect(v.code).toBe('KEY_CONFIRM_FAILED');
    expect(c.sink.prompts).toEqual([]);
  });

  it('frame before any key → ROOM_NOT_ACTIVE, dropped', async () => {
    const c = await setupManual({ stopAfterKeys: true });
    const R2 = randomHex32();
    c.server.send({ t: 'room', v: 1, room: c.view('keying', { roomId: R2 }) });
    c.server.send({
      t: 'frame',
      v: 1,
      header: { v: 1, frameId: randomHex32(), roomId: R2, from: c.PEER, seq: 1, kind: 'confirm', size: 10, ts: T0 },
      ct: bytesToBase64(new Uint8Array(38)),
    });
    const v = await waitFor(() => c.server.of('violation').find((x) => x.roomId === R2));
    expect(v.code).toBe('ROOM_NOT_ACTIVE');
  });

  it('never re-keys a room on a second key-request', async () => {
    const c = await setupManual();
    c.server.send({ t: 'key-request', v: 1, roomId: c.ROOM });
    await sleep(20);
    expect(c.server.of('key-share').length).toBe(1);
  });
});

describe('Endpoint: outbound', () => {
  it('send → ack → audit-detail(sent) → receipt accepted resolves', async () => {
    const c = await setupManual();
    const p = c.ep.sendText(c.ROOM, 'prompt', 'hello bob');
    const { header, pt } = await sentFrame(c, 1);
    expect(header).toMatchObject({ v: 1, roomId: c.ROOM, from: c.EP, seq: 2, kind: 'prompt', size: pt.length, ts: T0 });
    expect(header.mime).toBeUndefined();
    const body = decodeBody('prompt', pt);
    expect(body.text).toBe('hello bob');
    expect(body.threadId).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
    await sleep(5);
    expect(c.server.of('audit-detail')).toEqual([]); // not before ack
    ack(c, header.frameId);
    const ad = await waitFor(() => c.server.of('audit-detail')[0]);
    expect(validateE2R(ad)).toEqual(ad);
    expect(ad).toEqual({
      t: 'audit-detail',
      v: 1,
      roomId: c.ROOM,
      frameId: header.frameId,
      direction: 'sent',
      detail: { kind: 'prompt', text: 'hello bob', threadId: body.threadId, sha256: await sha256Hex(pt) },
    });
    receipt(c, header.frameId, 'accepted');
    await expect(p).resolves.toEqual({ frameId: header.frameId, roomId: c.ROOM, status: 'accepted' });
  });

  it('response requires inReplyTo; bodies are schema-validated', async () => {
    const c = await setupManual();
    await expectCode(c.ep.sendText(c.ROOM, 'response', 'x'), 'INVALID_MESSAGE');
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', ''), 'INVALID_MESSAGE');
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', 'x', { threadId: 'bad id!' }), 'INVALID_MESSAGE');
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', '\u00e9'.repeat(20_000)), 'PAYLOAD_TOO_LARGE');
    await expectCode(c.ep.sendTask(c.ROOM, { taskId: 't1', status: 'weird' } as never), 'INVALID_MESSAGE');
    await expectCode(c.ep.sendText(randomHex32(), 'prompt', 'x'), 'ROOM_NOT_FOUND');
    await sleep(5);
    expect(c.server.of('frame').length).toBe(1); // only the confirm
  });

  it('receipt no-agent → NO_AGENT; receipt rejected propagates its code', async () => {
    const c = await setupManual();
    const p1 = c.ep.sendText(c.ROOM, 'prompt', 'one');
    const f1 = await sentFrame(c, 1);
    ack(c, f1.header.frameId);
    receipt(c, f1.header.frameId, 'no-agent');
    await expectCode(p1, 'NO_AGENT');
    const p2 = c.ep.sendTask(c.ROOM, { taskId: 'job-1', status: 'running', progress: 0.5 });
    const f2 = await sentFrame(c, 2);
    expect(f2.header.seq).toBe(3);
    expect(decodeBody('task', f2.pt)).toEqual({ taskId: 'job-1', status: 'running', progress: 0.5 });
    ack(c, f2.header.frameId);
    receipt(c, f2.header.frameId, 'rejected', 'NOT_PERMITTED');
    await expectCode(p2, 'NOT_PERMITTED');
    const ad = await waitFor(() => byFrame(c, 'audit-detail', f2.header.frameId));
    expect(ad.detail).toEqual({ kind: 'task', task: { taskId: 'job-1', status: 'running', progress: 0.5 }, sha256: await sha256Hex(f2.pt) });
  });

  it('DELIVERY_TIMEOUT when no receipt arrives', async () => {
    const c = await setupManual({ deliveryTimeoutMs: 80 });
    const p = c.ep.sendText(c.ROOM, 'prompt', 'anyone?');
    const f = await sentFrame(c, 1);
    ack(c, f.header.frameId);
    await expectCode(p, 'DELIVERY_TIMEOUT');
  });

  it('ack rejection propagates and does not consume the sequence number', async () => {
    const c = await setupManual();
    const p = c.ep.sendText(c.ROOM, 'prompt', 'x');
    const f = await sentFrame(c, 1);
    ack(c, f.header.frameId, false, 'RATE_LIMITED');
    await expectCode(p, 'RATE_LIMITED');
    await sleep(5);
    expect(c.server.of('audit-detail')).toEqual([]);
    void c.ep.sendText(c.ROOM, 'prompt', 'y').catch(() => {});
    const f2 = await sentFrame(c, 2);
    expect(f2.header.seq).toBe(f.header.seq);
    expect(f2.header.frameId).not.toBe(f.header.frameId);
  });

  it('serializes outbound frames per room (next frame only after the previous ack)', async () => {
    const c = await setupManual();
    const p1 = c.ep.sendText(c.ROOM, 'prompt', 'first');
    const p2 = c.ep.sendText(c.ROOM, 'prompt', 'second');
    const f1 = await sentFrame(c, 1);
    await sleep(20);
    expect(c.server.of('frame').length).toBe(2);
    ack(c, f1.header.frameId);
    const f2 = await sentFrame(c, 2);
    expect(decodeBody('prompt', f2.pt).text).toBe('second');
    expect(f2.header.seq).toBe(f1.header.seq + 1);
    ack(c, f2.header.frameId);
    receipt(c, f2.header.frameId, 'accepted');
    receipt(c, f1.header.frameId, 'accepted');
    await expect(p1).resolves.toMatchObject({ frameId: f1.header.frameId });
    await expect(p2).resolves.toMatchObject({ frameId: f2.header.frameId });
  });

  it('enforces the outbound grant without sending a frame', async () => {
    const c = await setupManual({ outbound: { prompts: false, tasks: false, fileTypes: ['text/plain'] } });
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', 'x'), 'NOT_PERMITTED');
    await expectCode(c.ep.sendTask(c.ROOM, { taskId: 'a', status: 'done' }), 'NOT_PERMITTED');
    await expectCode(c.ep.sendFile(c.ROOM, { name: 'a.png', bytes: PNG }), 'FILE_TYPE_DENIED');
    await expectCode(c.ep.sendFile(c.ROOM, { name: 'a.html', bytes: utf8Encode('<html></html>') }), 'FILE_TYPE_DENIED');
    await expectCode(c.ep.sendFile(c.ROOM, { name: 'a.txt', bytes: new Uint8Array(0) }), 'FILE_EMPTY');
    const c2 = await setupManual({ outbound: { files: false, fileTypes: [] } });
    await expectCode(c2.ep.sendFile(c2.ROOM, { name: 'a.png', bytes: PNG }), 'NOT_PERMITTED');
    await sleep(5);
    expect(c.server.of('frame').length).toBe(1);
    expect(c2.server.of('frame').length).toBe(1);
  });

  it('never exceeds the grant bound in the transcript even if a room view widens it', async () => {
    const c = await setupManual({ outbound: { prompts: true }, boundOutbound: { prompts: false } });
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', 'x'), 'NOT_PERMITTED');
  });

  it('applies narrowed grants from room updates and refuses after expiry', async () => {
    const c = await setupManual();
    c.server.send({ t: 'room', v: 1, room: c.view('active', { outbound: dg({ prompts: false }) }) });
    await waitFor(() => c.sink.rooms.length >= 3);
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', 'x'), 'NOT_PERMITTED');
    c.clock.advance(HOUR);
    await expectCode(c.ep.sendTask(c.ROOM, { taskId: 'a', status: 'done' }), 'ROOM_EXPIRED');
  });

  it('sends a validated PNG with sanitized name, detected mime and sha256', async () => {
    const c = await setupManual();
    const p = c.ep.sendFile(c.ROOM, { name: '../dir/‮cat.png', bytes: PNG }, { threadId: 'th9' });
    const { header, pt } = await sentFrame(c, 1);
    expect(header.kind).toBe('file');
    expect(header.mime).toBe('image/png');
    const body = decodeBody('file', pt);
    const sha = await sha256Hex(PNG);
    expect(body.meta).toEqual({ name: 'cat.png', mime: 'image/png', size: PNG.length, sha256: sha, threadId: 'th9' });
    expect([...body.bytes]).toEqual([...PNG]);
    ack(c, header.frameId);
    const ad = await waitFor(() => c.server.of('audit-detail')[0]);
    expect(ad.detail).toEqual({ kind: 'file', name: 'cat.png', mime: 'image/png', size: PNG.length, sha256: sha, threadId: 'th9' });
    receipt(c, header.frameId, 'accepted');
    await expect(p).resolves.toMatchObject({ status: 'accepted' });
  });

  it('room closed rejects pending and queued sends with ROOM_CLOSED', async () => {
    const c = await setupManual();
    const p1 = c.ep.sendText(c.ROOM, 'prompt', 'a');
    const p2 = c.ep.sendText(c.ROOM, 'prompt', 'b');
    await sentFrame(c, 1);
    c.server.send({ t: 'room', v: 1, room: c.view('closed', { closedReason: 'user' }) });
    await expectCode(p1, 'ROOM_CLOSED');
    await expectCode(p2, 'ROOM_CLOSED');
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', 'c'), 'ROOM_CLOSED');
    expect(c.sink.rooms.at(-1)).toMatchObject({ state: 'closed', closedReason: 'user' });
  });

  it('leave() drops the room locally and notifies the router', async () => {
    const c = await setupManual();
    const p = c.ep.sendText(c.ROOM, 'prompt', 'a');
    await sentFrame(c, 1);
    c.ep.leave(c.ROOM);
    await expectCode(p, 'ROOM_CLOSED');
    await waitFor(() => c.server.of('leave')[0]);
    expect(c.server.of('leave')[0]).toEqual({ t: 'leave', v: 1, roomId: c.ROOM });
    // Frames arriving afterwards are ignored.
    await c.peer.text('prompt', 'late');
    await sleep(10);
    expect(c.sink.prompts).toEqual([]);
  });

  it('stop() rejects pending sends with NOT_CONNECTED and does not reconnect', async () => {
    const c = await setupManual();
    const p = c.ep.sendText(c.ROOM, 'prompt', 'a');
    await sentFrame(c, 1);
    c.ep.stop();
    await expectCode(p, 'NOT_CONNECTED');
    await sleep(20);
    expect(c.server.ports.length).toBe(1);
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', 'b'), 'NOT_CONNECTED');
  });
});

describe('Endpoint: inbound', () => {
  it('delivers a prompt: receipt accepted first, then sink, then audit-detail(received)', async () => {
    const c = await setupManual();
    const client = c.server.clients[0]!;
    let sentAtDelivery: Msg[] = [];
    c.sink.onDeliver = () => (sentAtDelivery = [...client.sent] as Msg[]);
    c.clock.advance(7);
    const h = await c.peer.text('prompt', 'hi alice', { threadId: 'thr' }, { ts: T0 + 1 });
    await waitFor(() => c.sink.prompts[0]);
    expect(c.sink.prompts[0]).toEqual({
      id: h.frameId,
      roomId: c.ROOM,
      type: 'prompt',
      text: 'hi alice',
      threadId: 'thr',
      from: { origin: ORIGIN_B, kind: 'page', agentName: 'bob' },
      sentAt: T0 + 1,
      receivedAt: T0 + 7,
    });
    expect(sentAtDelivery.at(-1)).toEqual({ t: 'receipt', v: 1, roomId: c.ROOM, frameId: h.frameId, status: 'accepted' });
    const ad = await waitFor(() => byFrame(c, 'audit-detail', h.frameId));
    expect(validateE2R(ad)).toEqual(ad);
    const pt = encodeBody('prompt', { text: 'hi alice', threadId: 'thr' });
    expect(ad).toEqual({
      t: 'audit-detail',
      v: 1,
      roomId: c.ROOM,
      frameId: h.frameId,
      direction: 'received',
      detail: { kind: 'prompt', text: 'hi alice', threadId: 'thr', sha256: await sha256Hex(pt) },
    });
    expect(c.server.msgs.indexOf(byFrame(c, 'receipt', h.frameId)!)).toBeLessThan(c.server.msgs.indexOf(ad));
  });

  it('delivers responses and tasks', async () => {
    const c = await setupManual();
    const irt = randomHex32();
    await c.peer.text('response', 'answer', { inReplyTo: irt });
    await c.peer.frame('task', encodeBody('task', { taskId: 'x', status: 'done', summary: 'ok' }));
    await waitFor(() => c.sink.tasks[0]);
    expect(c.sink.responses[0]).toMatchObject({ type: 'response', text: 'answer', inReplyTo: irt });
    expect(c.sink.tasks[0]!.task).toEqual({ taskId: 'x', status: 'done', summary: 'ok' });
  });

  it('no agent attached → receipt no-agent, nothing delivered or audited', async () => {
    const c = await setupManual();
    c.sink.agent = false;
    const h = await c.peer.text('prompt', 'hello?');
    const r = await waitFor(() => byFrame(c, 'receipt', h.frameId));
    expect(r.status).toBe('no-agent');
    await sleep(10);
    expect(c.sink.prompts).toEqual([]);
    expect(c.server.of('audit-detail')).toEqual([]);
  });

  it('enforces the inbound grant: receipt rejected + violation + onError, not delivered', async () => {
    const c = await setupManual({ inbound: { tasks: false, fileTypes: ['text/plain'] } });
    const h = await c.peer.frame('task', encodeBody('task', { taskId: 'x', status: 'done' }));
    const r = await waitFor(() => byFrame(c, 'receipt', h.frameId));
    expect(r).toEqual({ t: 'receipt', v: 1, roomId: c.ROOM, frameId: h.frameId, status: 'rejected', code: 'NOT_PERMITTED' });
    expect(byFrame(c, 'violation', h.frameId)).toMatchObject({ code: 'NOT_PERMITTED' });
    const meta: FileMeta = { name: 'a.png', mime: 'image/png', size: PNG.length, sha256: await sha256Hex(PNG) };
    const h2 = await c.peer.file(meta, PNG);
    const r2 = await waitFor(() => byFrame(c, 'receipt', h2.frameId));
    expect(r2.code).toBe('NOT_PERMITTED');
    expect(c.sink.tasks).toEqual([]);
    expect(c.sink.files).toEqual([]);
    expect(c.sink.errors.map((e) => e.code)).toEqual(['NOT_PERMITTED', 'NOT_PERMITTED']);
    // Room stays usable after a policy rejection.
    await c.peer.text('prompt', 'fine');
    await waitFor(() => c.sink.prompts[0]);
  });

  it('enforces inbound narrowing from room updates, bounded by the transcript grant', async () => {
    const c = await setupManual({ inbound: { prompts: true }, boundInbound: { tasks: false } });
    const h = await c.peer.frame('task', encodeBody('task', { taskId: 'x', status: 'done' }));
    expect((await waitFor(() => byFrame(c, 'receipt', h.frameId))).code).toBe('NOT_PERMITTED');
    c.server.send({ t: 'room', v: 1, room: c.view('active', { inbound: dg({ prompts: false }) }) });
    const h2 = await c.peer.text('prompt', 'x');
    expect((await waitFor(() => byFrame(c, 'receipt', h2.frameId))).code).toBe('NOT_PERMITTED');
    expect(c.sink.prompts).toEqual([]);
  });

  it('replayed or out-of-order seq → violation REPLAY, not delivered, not decrypted', async () => {
    const c = await setupManual();
    const h1 = await c.peer.text('prompt', 'one');
    await waitFor(() => c.sink.prompts[0]);
    await c.peer.text('prompt', 'one again', {}, { seq: h1.seq });
    const v = await waitFor(() => c.server.of('violation')[0]);
    expect(v).toMatchObject({ code: 'REPLAY', roomId: c.ROOM });
    expect(c.sink.prompts.length).toBe(1);
    // Router closes the room on REPLAY; the endpoint drops its keys immediately.
    expect(c.sink.rooms.at(-1)).toMatchObject({ state: 'closed', closedReason: 'violation' });

    const d = await setupManual();
    const h = await d.peer.text('prompt', 'skip', {}, { seq: 4 });
    expect((await waitFor(() => d.server.of('violation')[0])).code).toBe('REPLAY');
    expect(byFrame(d, 'receipt', h.frameId)).toBeUndefined();
    expect(d.sink.prompts).toEqual([]);
  });

  it('tampered ciphertext or header → DECRYPT_FAILED', async () => {
    const c = await setupManual();
    await c.peer.frame('prompt', encodeBody('prompt', { text: 'x', threadId: 't' }), {}, (ct) => {
      const b = base64ToBytes(ct);
      b[20] = b[20]! ^ 1;
      return bytesToBase64(b);
    });
    expect((await waitFor(() => c.server.of('violation')[0])).code).toBe('DECRYPT_FAILED');
    expect(c.sink.prompts).toEqual([]);

    const d = await setupManual();
    const pt = encodeBody('prompt', { text: 'x', threadId: 't' });
    const header: FrameHeader = { v: 1, frameId: randomHex32(), roomId: d.ROOM, from: d.PEER, seq: 2, kind: 'prompt', size: pt.length, ts: T0 };
    const ct = await encryptFrame(d.key, header, pt);
    d.server.send({ t: 'frame', v: 1, header: { ...header, kind: 'response' }, ct }); // kind flipped in transit
    expect((await waitFor(() => d.server.of('violation')[0])).code).toBe('DECRYPT_FAILED');
    expect(d.sink.responses).toEqual([]);
  });

  it('rejects frames not claiming to come from the transcript peer (reflection)', async () => {
    const c = await setupManual();
    await c.peer.text('prompt', 'me?', {}, { from: c.EP });
    expect((await waitFor(() => c.server.of('violation')[0])).code).toBe('SPOOFED_SENDER');
    expect(c.sink.prompts).toEqual([]);
  });

  it('delivers a valid PNG with provenance and sha256', async () => {
    const c = await setupManual();
    c.clock.advance(3);
    const sha = await sha256Hex(PNG);
    const h = await c.peer.file({ name: 'pic.png', mime: 'image/png', size: PNG.length, sha256: sha, threadId: 'tt' }, PNG, { ts: T0 + 1 });
    const f = await waitFor(() => c.sink.files[0]);
    expect(f).toMatchObject({ id: h.frameId, roomId: c.ROOM, name: 'pic.png', mime: 'image/png', threadId: 'tt' });
    expect([...f.bytes]).toEqual([...PNG]);
    expect(f.provenance).toEqual({
      fromOrigin: ORIGIN_B,
      fromKind: 'page',
      roomId: c.ROOM,
      frameId: h.frameId,
      sha256: sha,
      detectedType: 'image/png',
      size: PNG.length,
      sentAt: T0 + 1,
      receivedAt: T0 + 3,
      validated: true,
    });
    const ad = await waitFor(() => byFrame(c, 'audit-detail', h.frameId));
    expect(ad.detail).toEqual({ kind: 'file', name: 'pic.png', mime: 'image/png', size: PNG.length, sha256: sha, threadId: 'tt' });
    expect(byFrame(c, 'receipt', h.frameId)!.status).toBe('accepted');
  });

  it.each([
    ['HTML disguised as PNG', 'x.png', 'image/png', utf8Encode('<html><script>alert(1)</script></html>'), ['FILE_TYPE_MISMATCH', 'FILE_TYPE_DENIED']],
    ['HTML disguised as text', 'x.txt', 'text/plain', utf8Encode('<!doctype html><script>alert(1)</script>'), ['FILE_TYPE_DENIED']],
    ['executable disguised as text', 'x.txt', 'text/plain', utf8Encode('MZ\u0090\u0000'), ['FILE_TYPE_DENIED']],
    ['PNG declared as text', 'x.txt', 'text/plain', PNG, ['FILE_TYPE_MISMATCH']],
  ] as const)('malicious peer: %s → rejected, not delivered', async (_n, name, mime, bytes, codes) => {
    const c = await setupManual();
    const meta: FileMeta = { name, mime, size: bytes.length, sha256: await sha256Hex(bytes) };
    const h = await c.peer.file(meta, bytes);
    const r = await waitFor(() => byFrame(c, 'receipt', h.frameId));
    expect(r.status).toBe('rejected');
    expect(codes).toContain(r.code);
    expect(byFrame(c, 'violation', h.frameId)!.code).toBe(r.code);
    expect(c.sink.files).toEqual([]);
    expect(c.server.of('audit-detail')).toEqual([]);
  });

  it('header mime ≠ meta mime → FILE_TYPE_MISMATCH', async () => {
    const c = await setupManual();
    const meta: FileMeta = { name: 'a.png', mime: 'image/png', size: PNG.length, sha256: await sha256Hex(PNG) };
    const h = await c.peer.file(meta, PNG, { mime: 'text/plain' });
    expect((await waitFor(() => byFrame(c, 'receipt', h.frameId))).code).toBe('FILE_TYPE_MISMATCH');
    expect(c.sink.files).toEqual([]);
  });

  it('sha256 mismatch → FILE_HASH_MISMATCH; size mismatch → rejected', async () => {
    const c = await setupManual();
    const h = await c.peer.file({ name: 'a.png', mime: 'image/png', size: PNG.length, sha256: 'cd'.repeat(32) }, PNG);
    expect((await waitFor(() => byFrame(c, 'receipt', h.frameId))).code).toBe('FILE_HASH_MISMATCH');
    const h2 = await c.peer.file({ name: 'a.png', mime: 'image/png', size: PNG.length + 1, sha256: await sha256Hex(PNG) }, PNG);
    expect((await waitFor(() => byFrame(c, 'receipt', h2.frameId))).status).toBe('rejected');
    expect(c.sink.files).toEqual([]);
  });

  it('file larger than the inbound maxFileBytes → FILE_TOO_LARGE', async () => {
    const c = await setupManual({ inbound: { maxFileBytes: 16 } });
    const h = await c.peer.file({ name: 'a.png', mime: 'image/png', size: PNG.length, sha256: await sha256Hex(PNG) }, PNG);
    expect((await waitFor(() => byFrame(c, 'receipt', h.frameId))).code).toBe('FILE_TOO_LARGE');
  });
});

describe('Endpoint: reconnect', () => {
  it('reconnects with resume, re-sends agent state and keeps room keys and seq', async () => {
    const c = await setupManual();
    c.ep.setAgent(true, 'alice');
    await waitFor(() => c.server.of('agent')[0]);
    c.server.port.disconnect();
    const hello = await waitFor(() => c.server.of('hello')[1]);
    expect(hello).toEqual({ t: 'hello', v: 1, kind: 'page', resume: { endpointId: c.EP, resumeToken: c.TOKEN } });
    const token2 = randomHex32();
    c.server.send(welcome(c.EP, token2, ORIGIN_A, { resumed: true, rooms: [c.view('active')] }));
    await waitFor(() => c.server.of('agent')[1]);
    expect(c.server.of('agent')[1]).toEqual({ t: 'agent', v: 1, attached: true, name: 'alice' });
    const p = c.ep.sendText(c.ROOM, 'prompt', 'still here');
    const f = await sentFrame(c, 1);
    expect(f.header.seq).toBe(2);
    ack(c, f.header.frameId);
    receipt(c, f.header.frameId, 'accepted');
    await expect(p).resolves.toMatchObject({ status: 'accepted' });
    await c.peer.text('prompt', 'welcome back');
    await waitFor(() => c.sink.prompts[0]);
    // The next resume uses the rotated token.
    c.server.port.disconnect();
    const hello3 = await waitFor(() => c.server.of('hello')[2]);
    expect(hello3.resume.resumeToken).toBe(token2);
  });

  it('re-posts an unacked frame after resume; a REPLAY ack means it was accepted earlier', async () => {
    const c = await setupManual();
    const p = c.ep.sendText(c.ROOM, 'prompt', 'in flight');
    const f = await sentFrame(c, 1);
    c.server.port.disconnect();
    await waitFor(() => c.server.of('hello')[1]);
    c.server.send(welcome(c.EP, randomHex32(), ORIGIN_A, { resumed: true, rooms: [c.view('active')] }));
    const again = await waitFor(() => c.server.of('frame')[2]);
    expect(again).toEqual(f.f);
    ack(c, f.header.frameId, false, 'REPLAY');
    receipt(c, f.header.frameId, 'accepted');
    await expect(p).resolves.toMatchObject({ frameId: f.header.frameId });
    void c.ep.sendText(c.ROOM, 'prompt', 'next').catch(() => {});
    expect((await sentFrame(c, 3)).header.seq).toBe(3);
  });

  it('resumed:false wipes rooms (closed endpoint-gone) and rejects their pending sends', async () => {
    const c = await setupManual();
    const p = c.ep.sendText(c.ROOM, 'prompt', 'x');
    await sentFrame(c, 1);
    c.server.port.disconnect();
    await waitFor(() => c.server.of('hello')[1]);
    const newId = randomHex32();
    c.server.send(welcome(newId, randomHex32(), ORIGIN_A, { resumed: false }));
    await expectCode(p, 'ROOM_CLOSED');
    await waitFor(() => c.sink.rooms.find((r) => r.state === 'closed'));
    expect(c.sink.rooms.at(-1)).toMatchObject({ roomId: c.ROOM, state: 'closed', closedReason: 'endpoint-gone' });
    expect(c.ep.endpointId).toBe(newId);
    expect(c.ep.rooms()).toEqual([]);
    await expectCode(c.ep.sendText(c.ROOM, 'prompt', 'y'), 'ROOM_NOT_FOUND');
  });

  it('rejects pending sends NOT_CONNECTED after 3 failed reconnects, keeps retrying', async () => {
    const c = await setupManual({ deliveryTimeoutMs: 10_000 });
    const p = c.ep.sendText(c.ROOM, 'prompt', 'x');
    await sentFrame(c, 1);
    c.server.onMsg = (m) => {
      if (m.t === 'hello') c.server.port.disconnect();
    };
    c.server.port.disconnect();
    await expectCode(p, 'NOT_CONNECTED');
    expect(c.server.ports.length).toBeGreaterThanOrEqual(4);
    c.server.onMsg = undefined;
    const n = c.server.of('hello').length;
    await waitFor(() => c.server.of('hello').length > n, 6000);
  });
});

describe('Endpoint: two real endpoints through a relay', () => {
  it('pairs, confirms and exchanges prompt/response both ways', async () => {
    const mk = (origin: string) => {
      const server = new Server();
      const sink = new RecSink();
      const ep = new Endpoint({ connect: server.connect, kind: 'page', sink, reconnectDelayMs: 5 });
      return { server, sink, ep, id: randomHex32(), origin };
    };
    const A = mk(ORIGIN_A);
    const B = mk(ORIGIN_B);
    const ROOM = randomHex32();
    const g: Grant = { i2j: dg(), j2i: dg({ files: false, fileTypes: [] }), expiresAt: Date.now() + HOUR, rate: RATE };
    const view = (side: typeof A, state: RoomView['state']): RoomView => {
      const initiator = side === A;
      const other = initiator ? B : A;
      return {
        roomId: ROOM,
        state,
        createdAt: Date.now(),
        expiresAt: g.expiresAt,
        role: initiator ? 'initiator' : 'joiner',
        peer: { origin: other.origin, kind: 'page', connected: true },
        outbound: initiator ? g.i2j : g.j2i,
        inbound: initiator ? g.j2i : g.i2j,
      };
    };
    const keys: Record<string, string> = {};
    const confirmed = new Set<string>();
    const routedFrom = new Map<string, typeof A>();
    for (const [me, other] of [
      [A, B],
      [B, A],
    ] as const) {
      me.server.onMsg = (m) => {
        if (m.t === 'hello') me.server.send(welcome(me.id, randomHex32(), me.origin));
        if (m.t === 'key-share') {
          keys[me.id] = m.publicKey;
          if (keys[A.id] && keys[B.id]) {
            const transcript: Transcript = {
              v: 1,
              roomId: ROOM,
              initiator: { endpointId: A.id, origin: A.origin, kind: 'page', publicKey: keys[A.id]! },
              joiner: { endpointId: B.id, origin: B.origin, kind: 'page', publicKey: keys[B.id]! },
              grant: g,
            };
            for (const s of [A, B]) s.server.send({ t: 'room-keys', v: 1, roomId: ROOM, transcript });
          }
        }
        if (m.t === 'frame') {
          routedFrom.set(m.header.frameId, me);
          other.server.send(m);
          me.server.send({ t: 'ack', v: 1, roomId: ROOM, frameId: m.header.frameId, ok: true });
        }
        if (m.t === 'confirmed') {
          confirmed.add(me.id);
          if (confirmed.size === 2) for (const s of [A, B]) s.server.send({ t: 'room', v: 1, room: view(s, 'active') });
        }
        if (m.t === 'receipt') routedFrom.get(m.frameId)?.server.send(m);
      };
    }
    await Promise.all([A.ep.start(), B.ep.start()]);
    for (const s of [A, B]) {
      s.server.send({ t: 'room', v: 1, room: view(s, 'keying') });
      s.server.send({ t: 'key-request', v: 1, roomId: ROOM });
    }
    await waitFor(() => A.ep.rooms()[0]?.state === 'active' && B.ep.rooms()[0]?.state === 'active');

    const sent = await A.ep.sendText(ROOM, 'prompt', 'What is 2+2?');
    const prompt = await waitFor(() => B.sink.prompts[0]);
    expect(prompt).toMatchObject({ id: sent.frameId, text: 'What is 2+2?', from: { origin: ORIGIN_A, kind: 'page' } });
    const reply = await B.ep.sendText(ROOM, 'response', '4', { threadId: prompt.threadId, inReplyTo: prompt.id });
    const resp = await waitFor(() => A.sink.responses[0]);
    expect(resp).toMatchObject({ id: reply.frameId, text: '4', inReplyTo: sent.frameId, threadId: prompt.threadId });
    // j2i grant has no files: B cannot send a file to A.
    await expectCode(B.ep.sendFile(ROOM, { name: 'a.png', bytes: PNG }), 'NOT_PERMITTED');
    const fr = await A.ep.sendFile(ROOM, { name: 'a.png', bytes: PNG });
    expect((await waitFor(() => B.sink.files[0])).id).toBe(fr.frameId);
    expect(A.server.of('violation')).toEqual([]);
    expect(B.server.of('violation')).toEqual([]);
    A.ep.stop();
    B.ep.stop();
  });
});
