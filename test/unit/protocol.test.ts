import { describe, expect, it } from 'vitest';
import { randomHex32, utf8Encode } from '../../src/shared/encoding';
import {
  decodeBody,
  encodeBody,
  headerAad,
  validateContentDetail,
  validateE2R,
  validateHeader,
  validateProposalShape,
  validateR2E,
  validateTaskBody,
  validateTextBody,
} from '../../src/shared/protocol';
import { MAX_TEXT_BYTES } from '../../src/shared/limits';
import type { FrameHeader } from '../../src/shared/types';

const id = () => randomHex32();
const pk = 'B' + 'A'.repeat(86) + '='; // 65 bytes, first byte 0x04
const sha = 'a'.repeat(64);

function hdr(over: Partial<FrameHeader> = {}): FrameHeader {
  return { v: 1, frameId: id(), roomId: id(), from: id(), seq: 1, kind: 'prompt', size: 10, ts: 5, ...over };
}

const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return 'OK';
};

describe('validateHeader', () => {
  it('accepts a valid header and requires mime only for files', () => {
    expect(validateHeader(hdr())).toBeTruthy();
    expect(validateHeader(hdr({ kind: 'file', mime: 'image/png' })).mime).toBe('image/png');
    expect(code(() => validateHeader(hdr({ kind: 'file' })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader(hdr({ mime: 'image/png' })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader(hdr({ kind: 'file', mime: 'text/html' as never })))).toBe('INVALID_MESSAGE');
  });

  it('rejects unknown keys, bad ids, bad seq, bad version', () => {
    expect(code(() => validateHeader({ ...hdr(), extra: 1 }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader(hdr({ frameId: 'XYZ' })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader(hdr({ seq: 0 })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader(hdr({ seq: 1.5 })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader(hdr({ size: 0 })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader({ ...hdr(), v: 2 }))).toBe('UNSUPPORTED_VERSION');
    expect(code(() => validateHeader([]))).toBe('INVALID_MESSAGE');
    expect(code(() => validateHeader(null))).toBe('INVALID_MESSAGE');
  });

  it('AAD is canonical (key order independent)', () => {
    const h = hdr();
    const reordered = Object.fromEntries(Object.entries(h).reverse()) as FrameHeader;
    expect(Buffer.from(headerAad(h)).equals(Buffer.from(headerAad(reordered)))).toBe(true);
  });
});

describe('bodies', () => {
  it('text body rules', () => {
    expect(validateTextBody({ text: 'hi', threadId: 't_1' }, 'prompt')).toEqual({ text: 'hi', threadId: 't_1' });
    expect(code(() => validateTextBody({ text: '', threadId: 't' }, 'prompt'))).toBe('INVALID_MESSAGE');
    expect(code(() => validateTextBody({ text: 'x', threadId: 'bad id!' }, 'prompt'))).toBe('INVALID_MESSAGE');
    expect(code(() => validateTextBody({ text: 'x', threadId: 't' }, 'response'))).toBe('INVALID_MESSAGE');
    expect(validateTextBody({ text: 'x', threadId: 't', inReplyTo: id() }, 'response').inReplyTo).toMatch(/^[0-9a-f]{32}$/);
    expect(code(() => validateTextBody({ text: 'é'.repeat(MAX_TEXT_BYTES / 2 + 1), threadId: 't' }, 'prompt'))).toBe('PAYLOAD_TOO_LARGE');
    expect(code(() => validateTextBody({ text: 'x', threadId: 't', html: '<b>' }, 'prompt'))).toBe('INVALID_MESSAGE');
  });

  it('task body rules', () => {
    expect(validateTaskBody({ taskId: 'a', status: 'running', progress: 0.5, summary: 's' }).progress).toBe(0.5);
    expect(code(() => validateTaskBody({ taskId: 'a', status: 'exploded' }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateTaskBody({ taskId: 'a', status: 'done', progress: 2 }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateTaskBody({ taskId: 'a', status: 'done', progress: NaN }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateTaskBody({ taskId: 'a', status: 'done', summary: 'x'.repeat(3000) }))).toBe('INVALID_MESSAGE');
  });

  it('round-trips every kind through the codec', () => {
    const text = { text: 'hello', threadId: 't1' };
    expect(decodeBody('prompt', encodeBody('prompt', text))).toEqual(text);
    const task = { taskId: 'job-1', status: 'done' as const, summary: 'ok' };
    expect(decodeBody('task', encodeBody('task', task))).toEqual(task);
    const confirm = { transcriptHash: sha };
    expect(decodeBody('confirm', encodeBody('confirm', confirm))).toEqual(confirm);
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const meta = { name: 'a.png', mime: 'image/png' as const, size: 4, sha256: sha };
    const fb = decodeBody('file', encodeBody('file', { meta, bytes }));
    expect(fb.meta).toEqual(meta);
    expect(Array.from(fb.bytes)).toEqual([1, 2, 3, 4]);
  });

  it('rejects malformed bodies', () => {
    expect(code(() => decodeBody('prompt', utf8Encode('not json')))).toBe('INVALID_MESSAGE');
    expect(code(() => decodeBody('prompt', new Uint8Array([0xff, 0xfe])))).toBe('INVALID_MESSAGE');
    expect(code(() => decodeBody('file', new Uint8Array([0, 0, 0xff, 0xff, 1])))).toBe('INVALID_MESSAGE');
    expect(code(() => decodeBody('confirm', new Uint8Array(300)))).toBe('PAYLOAD_TOO_LARGE');
  });
});

describe('validateE2R / validateR2E', () => {
  it('accepts every valid E2R shape', () => {
    const rid = id();
    const msgs = [
      { t: 'hello', v: 1, kind: 'page' },
      { t: 'hello', v: 1, kind: 'panel', resume: { endpointId: id(), resumeToken: id() } },
      { t: 'agent', v: 1, attached: true, name: 'Planner' },
      { t: 'pair-request', v: 1, note: 'pls' },
      { t: 'key-share', v: 1, roomId: rid, publicKey: pk },
      { t: 'confirmed', v: 1, roomId: rid },
      { t: 'leave', v: 1, roomId: rid },
      { t: 'frame', v: 1, header: hdr(), ct: 'AAAA' },
      { t: 'receipt', v: 1, roomId: rid, frameId: id(), status: 'rejected', code: 'FILE_TYPE_DENIED' },
      { t: 'audit-detail', v: 1, roomId: rid, frameId: id(), direction: 'sent', detail: { kind: 'prompt', text: 'x', threadId: 't', sha256: sha } },
      { t: 'violation', v: 1, roomId: rid, code: 'REPLAY' },
    ];
    for (const m of msgs) expect(validateE2R(m)).toEqual(m);
  });

  it('rejects bad E2R', () => {
    expect(code(() => validateE2R({ t: 'hello', v: 1, kind: 'native' }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateE2R({ t: 'hello', v: 9, kind: 'page' }))).toBe('UNSUPPORTED_VERSION');
    expect(code(() => validateE2R({ t: 'hello', v: 1, kind: 'page', origin: 'https://evil' }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateE2R({ t: 'nope', v: 1 }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateE2R({ t: 'key-share', v: 1, roomId: id(), publicKey: 'AAAA' }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateE2R({ t: 'frame', v: 1, header: hdr(), ct: 'a*==' }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateE2R({ t: 'receipt', v: 1, roomId: id(), frameId: id(), status: 'accepted', code: 'MADE_UP' }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateE2R('hello'))).toBe('INVALID_MESSAGE');
  });

  it('validates R2E including transcript/room consistency', () => {
    const roomId = id();
    const dg = { prompts: true, tasks: false, files: false, fileTypes: [], maxFileBytes: 10 };
    const transcript = {
      v: 1,
      roomId,
      initiator: { endpointId: id(), origin: 'https://a', kind: 'page', publicKey: pk },
      joiner: { endpointId: id(), origin: 'https://b', kind: 'panel', publicKey: pk },
      grant: { i2j: dg, j2i: dg, expiresAt: 10, rate: { framesPerMinute: 1, bytesPerMinute: 1 } },
    };
    expect(validateR2E({ t: 'room-keys', v: 1, roomId, transcript })).toBeTruthy();
    expect(code(() => validateR2E({ t: 'room-keys', v: 1, roomId: id(), transcript }))).toBe('INVALID_MESSAGE');
    const room = {
      roomId, state: 'active', createdAt: 1, expiresAt: 2, role: 'joiner',
      peer: { origin: 'https://a', kind: 'page', connected: true, agentName: 'P' }, outbound: dg, inbound: dg,
    };
    expect(validateR2E({ t: 'room', v: 1, room })).toEqual({ t: 'room', v: 1, room });
    expect(validateR2E({ t: 'welcome', v: 1, endpointId: id(), resumeToken: id(), origin: 'https://a', kind: 'page', rooms: [room], paused: false, resumed: false })).toBeTruthy();
    expect(code(() => validateR2E({ t: 'ack', v: 1, roomId, frameId: id() }))).toBe('INVALID_MESSAGE');
  });

  it('validates content detail and proposals', () => {
    expect(validateContentDetail({ kind: 'file', name: 'a.png', mime: 'image/png', size: 3, sha256: sha })).toBeTruthy();
    expect(code(() => validateContentDetail({ kind: 'file', name: 'a', mime: 'text/html', size: 3, sha256: sha }))).toBe('INVALID_MESSAGE');
    const dg = { prompts: true, tasks: true, files: true, fileTypes: ['image/png', 'image/png'], maxFileBytes: 100 };
    expect(validateProposalShape({ i2j: dg, j2i: dg, ttlMs: 900000 }).i2j.fileTypes).toEqual(['image/png']);
    expect(code(() => validateProposalShape({ i2j: dg, j2i: { ...dg, maxFileBytes: 1e9 }, ttlMs: 1 }))).toBe('INVALID_MESSAGE');
  });
});

describe('public key format', () => {
  it('requires the uncompressed-point prefix byte 0x04', () => {
    const roomId = id();
    const ok = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]).toString('base64');
    const bad = Buffer.concat([Buffer.from([5]), Buffer.alloc(64, 1)]).toString('base64');
    expect(validateE2R({ t: 'key-share', v: 1, roomId, publicKey: ok })).toBeTruthy();
    expect(code(() => validateE2R({ t: 'key-share', v: 1, roomId, publicKey: bad }))).toBe('INVALID_MESSAGE');
  });
});
