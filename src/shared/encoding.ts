// Byte/string encoding helpers shared by every component. No browser-specific APIs.

const te = new TextEncoder();

export function utf8Encode(s: string): Uint8Array {
  return te.encode(s);
}

/** Lenient decode (replacement chars). Use `utf8DecodeStrict` when validating input. */
export function utf8Decode(b: Uint8Array): string {
  return new TextDecoder('utf-8').decode(b);
}

/** Throws TypeError on invalid UTF-8. */
export function utf8DecodeStrict(b: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(b);
}

export function utf8Length(s: string): number {
  // Fast path without allocating for pure ASCII.
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n += 4;
        i++;
      } else n += 3;
    } else n += 3;
  }
  return n;
}

export function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += (b[i] as number).toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new TypeError('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64.length; i++) t[B64.charCodeAt(i)] = i;
  return t;
})();

export function bytesToBase64(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = ((b[i] as number) << 16) | ((b[i + 1] as number) << 8) | (b[i + 2] as number);
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + B64[n & 63]!;
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = (b[i] as number) << 16;
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + '==';
  } else if (rem === 2) {
    const n = ((b[i] as number) << 16) | ((b[i + 1] as number) << 8);
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + '=';
  }
  return out;
}

/** Strict standard base64 (with padding). Throws TypeError on malformed input. */
export function base64ToBytes(s: string): Uint8Array {
  const len = base64DecodedLength(s);
  if (len < 0) throw new TypeError('invalid base64');
  const out = new Uint8Array(len);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const a = B64_LOOKUP[s.charCodeAt(i)]!;
    const b = B64_LOOKUP[s.charCodeAt(i + 1)]!;
    const c = s[i + 2] === '=' ? 0 : B64_LOOKUP[s.charCodeAt(i + 2)]!;
    const d = s[i + 3] === '=' ? 0 : B64_LOOKUP[s.charCodeAt(i + 3)]!;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    if (o < len) out[o++] = (n >> 16) & 255;
    if (o < len) out[o++] = (n >> 8) & 255;
    if (o < len) out[o++] = n & 255;
  }
  return out;
}

/**
 * Decoded byte length of a strict, padded base64 string, computed arithmetically.
 * Validates the alphabet and padding. Returns -1 if malformed.
 */
export function base64DecodedLength(s: string): number {
  if (typeof s !== 'string' || s.length % 4 !== 0) return -1;
  if (s.length === 0) return 0;
  let pad = 0;
  if (s.endsWith('==')) pad = 2;
  else if (s.endsWith('=')) pad = 1;
  const body = s.length - pad;
  for (let i = 0; i < body; i++) {
    const c = s.charCodeAt(i);
    if (c >= 128 || B64_LOOKUP[c] === -1) return -1;
  }
  return (s.length / 4) * 3 - pad;
}

/** Deterministic JSON: sorted keys, undefined omitted, no whitespace. Rejects non-finite numbers. */
export function canonicalJson(value: unknown): string {
  return serialize(value);
}

function serialize(v: unknown): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string':
      return JSON.stringify(v);
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new TypeError('non-finite number in canonical JSON');
      return JSON.stringify(v);
    case 'object': {
      if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : serialize(x))).join(',') + ']';
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + serialize(obj[k])).join(',') + '}';
    }
    default:
      throw new TypeError(`unsupported type in canonical JSON: ${typeof v}`);
  }
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

/** 128-bit random id as 32 lowercase hex chars. */
export function randomHex32(rand: (n: number) => Uint8Array = randomBytes): string {
  return bytesToHex(rand(16));
}

/** Unbiased random integer in [0, maxExclusive). */
export function randomInt(maxExclusive: number, rand: (n: number) => Uint8Array = randomBytes): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > 2 ** 32) throw new RangeError('bad bound');
  const limit = Math.floor(2 ** 32 / maxExclusive) * maxExclusive;
  for (;;) {
    const b = rand(4);
    const n = (((b[0] as number) << 24) >>> 0) + ((b[1] as number) << 16) + ((b[2] as number) << 8) + (b[3] as number);
    if (n < limit) return n % maxExclusive;
  }
}

/** Random ID token matching ID_TOKEN_RE (used for thread ids). */
export function randomToken(rand: (n: number) => Uint8Array = randomBytes): string {
  return 't_' + bytesToHex(rand(8));
}

/** Remove C0/C1 control characters and trim. */
export function stripControl(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').trim();
}
