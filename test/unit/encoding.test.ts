import { describe, expect, it } from 'vitest';
import {
  base64DecodedLength,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  canonicalJson,
  hexToBytes,
  randomHex32,
  randomInt,
  utf8Encode,
  utf8Length,
} from '../../src/shared/encoding';

describe('encoding', () => {
  it('base64 round-trips all lengths and matches Buffer', () => {
    for (let n = 0; n < 70; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 37 + n) & 255);
      const s = bytesToBase64(b);
      expect(s).toBe(Buffer.from(b).toString('base64'));
      expect(base64DecodedLength(s)).toBe(n);
      expect(Array.from(base64ToBytes(s))).toEqual(Array.from(b));
    }
  });

  it('rejects malformed base64', () => {
    for (const bad of ['abc', 'ab=c', '====', 'a*bc', 'ab\ncd', 'YQ==YQ==', 'é123']) {
      expect(base64DecodedLength(bad)).toBe(-1);
      expect(() => base64ToBytes(bad)).toThrow();
    }
  });

  it('hex round-trips and rejects bad hex', () => {
    const b = new Uint8Array([0, 1, 127, 128, 255]);
    expect(bytesToHex(b)).toBe('00017f80ff');
    expect(Array.from(hexToBytes('00017f80ff'))).toEqual(Array.from(b));
    expect(() => hexToBytes('abc')).toThrow();
    expect(() => hexToBytes('zz')).toThrow();
  });

  it('canonicalJson sorts keys recursively and omits undefined', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: undefined } })).toBe('{"a":{"d":[3,{"y":2,"z":1}]},"b":1}');
    expect(() => canonicalJson({ a: NaN })).toThrow();
    expect(() => canonicalJson({ a: () => 1 })).toThrow();
  });

  it('utf8Length matches TextEncoder', () => {
    for (const s of ['', 'abc', 'é', '€', '😀', 'a😀b€', '\ud800x']) expect(utf8Length(s)).toBe(utf8Encode(s).length);
  });

  it('random ids have the right shape and randomInt is in range', () => {
    expect(randomHex32()).toMatch(/^[0-9a-f]{32}$/);
    expect(randomHex32()).not.toBe(randomHex32());
    for (let i = 0; i < 1000; i++) {
      const n = randomInt(1_000_000);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(1_000_000);
    }
  });
});
