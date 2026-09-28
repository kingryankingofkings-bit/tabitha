import { describe, expect, it } from 'vitest';
import {
  constantTimeEqual,
  decryptFrame,
  deriveRoomKey,
  encryptFrame,
  generateKeyPair,
  publicKeyToBase64,
  sha256Hex,
  transcriptHash,
} from '../../src/shared/crypto';
import { randomHex32, utf8Encode } from '../../src/shared/encoding';
import { base64DecodedLength, encodeBody, expectedCtBytes } from '../../src/shared/protocol';
import type { FrameHeader, Grant, Transcript } from '../../src/shared/types';

const grant: Grant = {
  i2j: { prompts: true, tasks: true, files: false, fileTypes: [], maxFileBytes: 1024 },
  j2i: { prompts: true, tasks: false, files: false, fileTypes: [], maxFileBytes: 1024 },
  expiresAt: 1_800_000_000_000,
  rate: { framesPerMinute: 60, bytesPerMinute: 1 << 24 },
};

async function setup() {
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const roomId = randomHex32();
  const t: Transcript = {
    v: 1,
    roomId,
    initiator: { endpointId: randomHex32(), origin: 'https://a.test', kind: 'page', publicKey: publicKeyToBase64(a.publicKeyRaw) },
    joiner: { endpointId: randomHex32(), origin: 'https://b.test', kind: 'page', publicKey: publicKeyToBase64(b.publicKeyRaw) },
    grant,
  };
  const th = await transcriptHash(t);
  const ka = await deriveRoomKey(a.privateKey, b.publicKeyRaw, roomId, th);
  const kb = await deriveRoomKey(b.privateKey, a.publicKeyRaw, roomId, th);
  return { a, b, roomId, t, th, ka, kb };
}

function header(roomId: string, from: string, size: number, seq = 1): FrameHeader {
  return { v: 1, frameId: randomHex32(), roomId, from, seq, kind: 'prompt', size, ts: 1 };
}

describe('crypto', () => {
  it('generates raw uncompressed P-256 keys with non-extractable private keys', async () => {
    const kp = await generateKeyPair();
    expect(kp.publicKeyRaw.length).toBe(65);
    expect(kp.publicKeyRaw[0]).toBe(4);
    expect(kp.privateKey.extractable).toBe(false);
  });

  it('both sides derive the same key; round trip works; ct length = size + 28', async () => {
    const { t, ka, kb } = await setup();
    const body = encodeBody('prompt', { text: 'hello 👋', threadId: 't1' });
    const h = header(t.roomId, t.initiator.endpointId, body.length);
    const ct = await encryptFrame(ka, h, body);
    expect(base64DecodedLength(ct)).toBe(expectedCtBytes(h.size));
    expect(Array.from(await decryptFrame(kb, h, ct))).toEqual(Array.from(body));
    expect(ka.extractable).toBe(false);
  });

  it('header tampering (AAD) fails decryption', async () => {
    const { t, ka, kb } = await setup();
    const body = utf8Encode('{"text":"x","threadId":"t"}');
    const h = header(t.roomId, t.initiator.endpointId, body.length);
    const ct = await encryptFrame(ka, h, body);
    for (const tampered of [
      { ...h, seq: 2 },
      { ...h, from: t.joiner.endpointId },
      { ...h, kind: 'response' as const },
      { ...h, frameId: randomHex32() },
    ]) {
      await expect(decryptFrame(kb, tampered, ct)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    }
  });

  it('ciphertext tampering fails decryption', async () => {
    const { t, ka, kb } = await setup();
    const body = utf8Encode('0123456789');
    const h = header(t.roomId, t.initiator.endpointId, body.length);
    const ct = await encryptFrame(ka, h, body);
    const bytes = Buffer.from(ct, 'base64');
    bytes[20] = (bytes[20] as number) ^ 1;
    await expect(decryptFrame(kb, h, bytes.toString('base64'))).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    await expect(decryptFrame(kb, h, 'not base64!')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('a different transcript (e.g. tampered grant) yields a different key', async () => {
    const { a, b, t, ka } = await setup();
    const t2: Transcript = { ...t, grant: { ...grant, j2i: { ...grant.j2i, files: true, fileTypes: ['image/png'] } } };
    const th2 = await transcriptHash(t2);
    const kb2 = await deriveRoomKey(b.privateKey, a.publicKeyRaw, t.roomId, th2);
    const body = utf8Encode('x');
    const h = header(t.roomId, t.initiator.endpointId, 1);
    const ct = await encryptFrame(ka, h, body);
    await expect(decryptFrame(kb2, h, ct)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('a third party key cannot decrypt', async () => {
    const { a, t, th, ka } = await setup();
    const eve = await generateKeyPair();
    const ke = await deriveRoomKey(eve.privateKey, a.publicKeyRaw, t.roomId, th);
    const h = header(t.roomId, t.initiator.endpointId, 1);
    const ct = await encryptFrame(ka, h, utf8Encode('x'));
    await expect(decryptFrame(ke, h, ct)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('rejects size mismatch and invalid peer keys', async () => {
    const { t, ka, a, th } = await setup();
    await expect(encryptFrame(ka, header(t.roomId, t.initiator.endpointId, 5), utf8Encode('x'))).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    await expect(deriveRoomKey(a.privateKey, new Uint8Array(65), t.roomId, th)).rejects.toMatchObject({ code: 'KEY_CONFIRM_FAILED' });
  });

  it('sha256Hex and constantTimeEqual', async () => {
    expect(await sha256Hex(utf8Encode('abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(constantTimeEqual('abc', 'abc')).toBe(true);
    expect(constantTimeEqual('abc', 'abd')).toBe(false);
    expect(constantTimeEqual('abc', 'ab')).toBe(false);
  });
});
