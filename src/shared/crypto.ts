// End-to-end frame encryption. SPEC.md §4.1, DECISIONS.md D2.
// ECDH P-256 → HKDF-SHA-256 (salt = roomId, info binds the transcript hash) → AES-256-GCM.

import { TabBridgeError } from './errors';
import { base64ToBytes, bytesToBase64, bytesToHex, canonicalJson, hexToBytes, randomBytes, utf8Encode } from './encoding';
import { headerAad } from './protocol';
import type { FrameHeader, RoomId, Transcript } from './types';

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;
const ECDH_PARAMS: EcKeyImportParams = { name: 'ECDH', namedCurve: 'P-256' };
const IV_BYTES = 12;

/** Copy into a fresh ArrayBuffer-backed view (satisfies BufferSource typing across realms). */
function buf(b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(b.byteLength));
  out.set(b);
  return out;
}

export async function generateKeyPair(): Promise<{ privateKey: CryptoKey; publicKeyRaw: Uint8Array }> {
  const kp = (await subtle().generateKey(ECDH_PARAMS, false, ['deriveBits'])) as CryptoKeyPair;
  const raw = new Uint8Array(await subtle().exportKey('raw', kp.publicKey));
  return { privateKey: kp.privateKey, publicKeyRaw: raw };
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await subtle().digest('SHA-256', buf(bytes))));
}

export async function transcriptHash(t: Transcript): Promise<string> {
  return sha256Hex(utf8Encode(canonicalJson(t)));
}

export async function deriveRoomKey(
  privateKey: CryptoKey,
  peerPublicKeyRaw: Uint8Array,
  roomId: RoomId,
  transcriptHashHex: string,
): Promise<CryptoKey> {
  let peer: CryptoKey;
  try {
    peer = await subtle().importKey('raw', buf(peerPublicKeyRaw), ECDH_PARAMS, false, []);
  } catch {
    throw new TabBridgeError('KEY_CONFIRM_FAILED', 'Invalid peer public key');
  }
  const bits = await subtle().deriveBits({ name: 'ECDH', public: peer }, privateKey, 256);
  const ikm = await subtle().importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: buf(hexToBytes(roomId)),
      info: buf(utf8Encode('tabbridge/v1/room-key|' + transcriptHashHex)),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptFrame(key: CryptoKey, header: FrameHeader, plaintext: Uint8Array): Promise<string> {
  if (plaintext.length !== header.size) throw new TabBridgeError('INVALID_MESSAGE', 'header.size must equal plaintext length');
  const iv = randomBytes(IV_BYTES);
  const ct = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv: buf(iv), additionalData: buf(headerAad(header)), tagLength: 128 }, key, buf(plaintext)),
  );
  const out = new Uint8Array(IV_BYTES + ct.length);
  out.set(iv, 0);
  out.set(ct, IV_BYTES);
  return bytesToBase64(out);
}

export async function decryptFrame(key: CryptoKey, header: FrameHeader, ct: string): Promise<Uint8Array> {
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(ct);
  } catch {
    throw new TabBridgeError('DECRYPT_FAILED', 'Malformed ciphertext');
  }
  if (bytes.length !== header.size + IV_BYTES + 16) throw new TabBridgeError('DECRYPT_FAILED', 'Ciphertext length mismatch');
  try {
    const pt = await subtle().decrypt(
      { name: 'AES-GCM', iv: buf(bytes.subarray(0, IV_BYTES)), additionalData: buf(headerAad(header)), tagLength: 128 },
      key,
      buf(bytes.subarray(IV_BYTES)),
    );
    return new Uint8Array(pt);
  } catch {
    throw new TabBridgeError('DECRYPT_FAILED');
  }
}

/** Constant-time string comparison (length leak only). */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function publicKeyToBase64(raw: Uint8Array): string {
  return bytesToBase64(raw);
}

export function publicKeyFromBase64(b64: string): Uint8Array {
  return base64ToBytes(b64);
}
