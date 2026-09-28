// Regression tests for SECURITY_REVIEW findings M1 and M2.
// M1: pairing approval is pinned to the reviewed joiner endpoint, so a joiner tab that navigates
//     to another (even enabled) origin after review cannot be bound in its place.
// M2: the router cross-checks the two endpoints' content attestations and logs `content.mismatch`
//     when a sender and receiver report different hashes for the same routed frame.
//
// A "manual peer" drives raw endpoint ports directly. The router never decrypts, so frame bodies
// are dummy ciphertext of the correct length; only key-share needs a real P-256 public key.
import { describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/background/audit';
import { Router, type RouterPlatform } from '../../src/background/router';
import { generateKeyPair } from '../../src/shared/crypto';
import { bytesToBase64, randomBytes, randomHex32 } from '../../src/shared/encoding';
import { AES_GCM_OVERHEAD, PORT_ENDPOINT } from '../../src/shared/limits';
import type { RoomId, SenderInfo, Settings } from '../../src/shared/types';
import { FakePort, MemoryAuditStore, MemoryKV, portPair, settle } from '../helpers/fakes';

function fakePlatform(): RouterPlatform {
  let s: Settings | undefined;
  return {
    extensionOrigin: 'chrome-extension://tbtest',
    extensionId: 'tbtest',
    hasHostPermission: async () => true,
    syncContentScripts: async () => {},
    injectIntoOpenTabs: async () => {},
    setBadge: () => {},
    loadSettings: async () => s,
    saveSettings: async (x) => {
      s = JSON.parse(JSON.stringify(x)) as Settings;
    },
  };
}

async function makeRouter() {
  const now = { t: 1_700_000_000_000 };
  const audit = new AuditLog({ store: new MemoryAuditStore(), now: () => now.t, flushDelayMs: 1 });
  await audit.init();
  const router = new Router({ session: new MemoryKV(), audit, platform: fakePlatform(), now: () => now.t, randomBytes });
  await router.init();
  return { router, now };
}

/** base64 ciphertext of the right length for a plaintext of `size` bytes (never decrypted here). */
function dummyCt(size: number): string {
  return Buffer.alloc(size + AES_GCM_OVERHEAD).toString('base64');
}

class Peer {
  readonly client: FakePort;
  readonly msgs: Record<string, unknown>[] = [];
  id!: string;
  constructor(router: Router, sender: SenderInfo) {
    const [client, server] = portPair(PORT_ENDPOINT);
    this.client = client;
    client.onMessage.addListener((m) => this.msgs.push(m as Record<string, unknown>));
    router.connectEndpoint(server, sender);
  }
  async hello(): Promise<this> {
    this.client.postMessage({ t: 'hello', v: 1, kind: 'page' });
    await settle();
    const w = this.msgs.find((m) => m.t === 'welcome');
    if (!w) throw new Error('no welcome');
    this.id = w.endpointId as string;
    return this;
  }
  last<T extends { t: string }>(t: string): T | undefined {
    for (let i = this.msgs.length - 1; i >= 0; i--) if ((this.msgs[i] as { t: string }).t === t) return this.msgs[i] as unknown as T;
    return undefined;
  }
  send(msg: Record<string, unknown>): void {
    this.client.postMessage(msg);
  }
}

const PROPOSAL = {
  i2j: { prompts: true, tasks: true, files: false, fileTypes: [], maxFileBytes: 1024 },
  j2i: { prompts: true, tasks: true, files: false, fileTypes: [], maxFileBytes: 1024 },
  ttlMs: 3_600_000,
};

async function shareKey(peer: Peer, roomId: RoomId): Promise<void> {
  const kp = await generateKeyPair();
  peer.send({ t: 'key-share', v: 1, roomId, publicKey: bytesToBase64(kp.publicKeyRaw) });
}

function confirmFrame(peer: Peer, roomId: RoomId): void {
  const size = 32;
  peer.send({ t: 'frame', v: 1, header: { v: 1, frameId: randomHex32(), roomId, from: peer.id, seq: 1, kind: 'confirm', size, ts: 1 }, ct: dummyCt(size) });
}

/** Drive two manual peers through keying to an active room. */
async function openRoom(router: Router, a: Peer, b: Peer, roomId: RoomId): Promise<void> {
  await shareKey(a, roomId);
  await shareKey(b, roomId);
  await settle();
  confirmFrame(a, roomId);
  confirmFrame(b, roomId);
  await settle();
  a.send({ t: 'confirmed', v: 1, roomId });
  b.send({ t: 'confirmed', v: 1, roomId });
  await settle();
}

describe('SECURITY_REVIEW M1: approval is pinned to the reviewed joiner endpoint', () => {
  it('does not bind a different origin when the joiner tab navigates after review', async () => {
    const { router } = await makeRouter();
    for (const o of ['https://a.example', 'https://b-good.example', 'https://c-evil.example'])
      expect(await router.handleUi('site.enable', { origin: o })).toEqual({ status: 'enabled' });

    const a = await new Peer(router, { tabId: 1, frameId: 0, url: 'https://a.example/', origin: 'https://a.example' }).hello();
    const bGood = await new Peer(router, { tabId: 2, frameId: 0, url: 'https://b-good.example/', origin: 'https://b-good.example' }).hello();

    const { code } = await router.handleUi('pair.start', { endpoint: { endpointId: a.id }, proposal: PROPOSAL });
    const preview = await router.handleUi('pair.lookup', { code, endpoint: { endpointId: bGood.id } });
    expect(preview.joiner.origin).toBe('https://b-good.example');
    expect(preview.joiner.endpointId).toBe(bGood.id);

    // The joiner tab navigates to a different enabled origin: the reviewed endpoint disconnects,
    // a fresh endpoint (different id, different origin) connects on the same tab.
    bGood.client.disconnect();
    await settle();
    const cEvil = await new Peer(router, { tabId: 2, frameId: 0, url: 'https://c-evil.example/', origin: 'https://c-evil.example' }).hello();
    expect(cEvil.id).not.toBe(bGood.id);

    // Approving the reviewed endpoint now fails cleanly instead of binding c-evil.
    await expect(router.handleUi('pair.approve', { code, endpoint: { endpointId: preview.joiner.endpointId } })).rejects.toMatchObject({
      code: 'PEER_UNAVAILABLE',
    });
    const st = await router.handleUi('state.get', undefined);
    expect(st.rooms).toHaveLength(0); // no room opened with any origin

    // Sanity: the pre-navigation flow (no substitution) still opens a room bound to the reviewed origin.
    const { code: code2 } = await router.handleUi('pair.start', { endpoint: { endpointId: a.id }, proposal: PROPOSAL });
    const preview2 = await router.handleUi('pair.lookup', { code: code2, endpoint: { endpointId: cEvil.id } });
    const { roomId } = await router.handleUi('pair.approve', { code: code2, endpoint: { endpointId: preview2.joiner.endpointId } });
    const st2 = await router.handleUi('state.get', undefined);
    const room = st2.rooms.find((r) => r.roomId === roomId)!;
    expect(room.members.find((m) => m.role === 'joiner')!.origin).toBe('https://c-evil.example'); // exactly what was reviewed
  });
});

describe('SECURITY_REVIEW M2: content attestations are cross-checked', () => {
  async function routeOnePrompt() {
    const { router } = await makeRouter();
    await router.handleUi('site.enable', { origin: 'https://a.example' });
    await router.handleUi('site.enable', { origin: 'https://b.example' });
    const a = await new Peer(router, { tabId: 1, frameId: 0, url: 'https://a.example/', origin: 'https://a.example' }).hello();
    const b = await new Peer(router, { tabId: 2, frameId: 0, url: 'https://b.example/', origin: 'https://b.example' }).hello();
    const { code } = await router.handleUi('pair.start', { endpoint: { endpointId: a.id }, proposal: PROPOSAL });
    const preview = await router.handleUi('pair.lookup', { code, endpoint: { endpointId: b.id } });
    const { roomId } = await router.handleUi('pair.approve', { code, endpoint: { endpointId: preview.joiner.endpointId } });
    await openRoom(router, a, b, roomId);
    const st = await router.handleUi('state.get', undefined);
    expect(st.rooms.find((r) => r.roomId === roomId)?.state).toBe('active');

    // A routes a prompt frame (seq 2); dummy ciphertext, since the router never decrypts.
    const frameId = randomHex32();
    const size = 24;
    a.send({ t: 'frame', v: 1, header: { v: 1, frameId, roomId, from: a.id, seq: 2, kind: 'prompt', size, ts: 1 }, ct: dummyCt(size) });
    await settle();
    expect(a.last('ack')).toMatchObject({ frameId, ok: true });
    // B accepts delivery so its received-detail is admissible.
    b.send({ t: 'receipt', v: 1, roomId, frameId, status: 'accepted' });
    await settle();
    return { router, a, b, roomId, frameId };
  }

  const detail = (sha: string) => ({ kind: 'prompt' as const, text: 'x', threadId: 't', sha256: sha });
  const SHA_A = 'a'.repeat(64);
  const SHA_B = 'b'.repeat(64);

  it('logs content.mismatch when sender and receiver report different hashes', async () => {
    const { router, a, b, roomId, frameId } = await routeOnePrompt();
    a.send({ t: 'audit-detail', v: 1, roomId, frameId, direction: 'sent', detail: detail(SHA_A) });
    b.send({ t: 'audit-detail', v: 1, roomId, frameId, direction: 'received', detail: detail(SHA_B) });
    await settle();
    await router.whenIdle();
    const entries = await router.handleUi('audit.list', { limit: 1000 });
    const mism = entries.find((e) => e.type === 'content.mismatch');
    expect(mism, 'a content.mismatch entry should be logged').toBeTruthy();
    expect(mism!.actor.kind).toBe('router');
    expect(mism!.data).toMatchObject({ frameId, sentSha: SHA_A, recvSha: SHA_B });
    expect((await router.handleUi('audit.verify', undefined))).toMatchObject({ ok: true });
  });

  it('does not log content.mismatch when both sides report the same hash', async () => {
    const { router, a, b, roomId, frameId } = await routeOnePrompt();
    a.send({ t: 'audit-detail', v: 1, roomId, frameId, direction: 'sent', detail: detail(SHA_A) });
    b.send({ t: 'audit-detail', v: 1, roomId, frameId, direction: 'received', detail: detail(SHA_A) });
    await settle();
    await router.whenIdle();
    const entries = await router.handleUi('audit.list', { limit: 1000 });
    expect(entries.some((e) => e.type === 'content.mismatch')).toBe(false);
    expect(entries.some((e) => e.type === 'content.sent')).toBe(true);
    expect(entries.some((e) => e.type === 'content.received')).toBe(true);
  });
});
