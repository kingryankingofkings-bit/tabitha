import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildProvenance } from '../../src/files/provenance';
import {
  EXTENSIONS,
  baseMimeType,
  looksLikeActiveContent,
  mimeForExtension,
  sanitizeFileName,
  sniffBinary,
  sniffDenied,
  validateFile,
  type FileCheck,
} from '../../src/files/validate';
import { TabBridgeError } from '../../src/shared/errors';
import { ALLOWED_MIMES, DEFAULT_MAX_FILE_BYTES, HARD_MAX_FILE_BYTES } from '../../src/shared/limits';
import type { AllowedMime } from '../../src/shared/types';

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

const te = new TextEncoder();
const u8 = (...parts: (number[] | string | Uint8Array)[]): Uint8Array => {
  const chunks = parts.map((p) => (typeof p === 'string' ? te.encode(p) : p instanceof Uint8Array ? p : Uint8Array.from(p)));
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
};
/** Latin-1 string → bytes (for binary magic written as text). */
const bin = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0));

const PNG = u8(
  [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  [0, 0, 0, 13],
  'IHDR',
  [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89],
  [0, 0, 0, 0],
  'IEND',
  [0xae, 0x42, 0x60, 0x82],
);
const JPEG = u8([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10], 'JFIF', [0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0xff, 0xd9]);
const GIF87 = u8('GIF87a', [1, 0, 1, 0, 0, 0, 0, 0x3b]);
const GIF89 = u8('GIF89a', [1, 0, 1, 0, 0x80, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x3b]);
const WEBP = u8('RIFF', [0x1a, 0, 0, 0], 'WEBPVP8L', [0x0d, 0, 0, 0, 0x2f, 0, 0, 0, 0x10, 0x07, 0x10, 0x11, 0x11, 0x88, 0x88, 0xfe, 0x07, 0x00]);
const PDF = u8('%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n');

const DENIED: Record<string, Uint8Array> = {
  pe: u8('MZ', [0x90, 0, 3, 0, 0, 0]),
  elf: u8([0x7f], 'ELF', [2, 1, 1, 0]),
  machoBE32: u8([0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 7]),
  machoBE64: u8([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 7]),
  machoLE32: u8([0xce, 0xfa, 0xed, 0xfe, 7, 0, 0, 0]),
  machoLE64: u8([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 0]),
  fat: u8([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]),
  zipLocal: u8('PK', [3, 4, 20, 0, 0, 0]),
  zipEmpty: u8('PK', [5, 6, 0, 0, 0, 0]),
  zipSpanned: u8('PK', [7, 8, 0, 0, 0, 0]),
  gzip: u8([0x1f, 0x8b, 8, 0, 0, 0]),
  sevenZ: u8([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]),
  rar: u8('Rar!', [0x1a, 7, 0]),
  wasm: u8([0], 'asm', [1, 0, 0, 0]),
  shebang: u8('#!/bin/sh\necho hi\n'),
  php: u8('<?php echo 1; ?>\n'),
  phpUpper: u8('<?PHP echo 1; ?>\n'),
};

const ALL: { allowed: readonly AllowedMime[]; maxBytes: number } = { allowed: ALLOWED_MIMES, maxBytes: DEFAULT_MAX_FILE_BYTES };
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

async function expectFail(r: Promise<FileCheck>, code: string): Promise<string> {
  const res = await r;
  expect(res.ok, JSON.stringify(res)).toBe(false);
  if (res.ok) throw new Error('unreachable');
  expect(res.code).toBe(code);
  expect(typeof res.detail).toBe('string');
  expect(res.detail.length).toBeGreaterThan(0);
  expect(res.detail.length).toBeLessThan(160);
  // detail must never carry invisible/control characters
  expect(res.detail).not.toMatch(/[\p{Cc}\p{Cf}]/u);
  return res.detail;
}

// ---------------------------------------------------------------------------------------------
// Tables & sniffers
// ---------------------------------------------------------------------------------------------

describe('EXTENSIONS', () => {
  it('covers every allowed MIME and maps back', () => {
    expect(Object.keys(EXTENSIONS).sort()).toEqual([...ALLOWED_MIMES].sort());
    for (const mime of ALLOWED_MIMES) for (const ext of EXTENSIONS[mime]) expect(mimeForExtension(ext)).toBe(mime);
    expect(mimeForExtension('JPEG')).toBe('image/jpeg');
    expect(mimeForExtension('exe')).toBeNull();
    expect(mimeForExtension('html')).toBeNull();
    expect(mimeForExtension('svg')).toBeNull();
  });
  it('is frozen', () => {
    expect(Object.isFrozen(EXTENSIONS)).toBe(true);
    expect(Object.isFrozen(EXTENSIONS['image/png'])).toBe(true);
  });
});

describe('sniffBinary', () => {
  it('identifies each allowed binary type', () => {
    expect(sniffBinary(PNG)).toBe('image/png');
    expect(sniffBinary(JPEG)).toBe('image/jpeg');
    expect(sniffBinary(GIF87)).toBe('image/gif');
    expect(sniffBinary(GIF89)).toBe('image/gif');
    expect(sniffBinary(WEBP)).toBe('image/webp');
    expect(sniffBinary(PDF)).toBe('application/pdf');
  });
  it('returns null for text, truncated or near-miss signatures', () => {
    expect(sniffBinary(u8('hello'))).toBeNull();
    expect(sniffBinary(new Uint8Array())).toBeNull();
    expect(sniffBinary(PNG.subarray(0, 7))).toBeNull();
    expect(sniffBinary(u8([0xff, 0xd8]))).toBeNull();
    expect(sniffBinary(u8('GIF88a'))).toBeNull();
    expect(sniffBinary(u8('RIFF', [0, 0, 0, 0], 'WAVE'))).toBeNull(); // RIFF but not WebP
    expect(sniffBinary(u8('RIFF', [0, 0, 0, 0], 'WEB'))).toBeNull();
    expect(sniffBinary(u8(' %PDF-1.4'))).toBeNull(); // must be at offset 0
    expect(sniffBinary(u8('%PDF'))).toBeNull();
  });
});

describe('sniffDenied', () => {
  it.each(Object.entries(DENIED))('flags %s', (_name, bytes) => {
    expect(sniffDenied(bytes)).toEqual(expect.any(String));
  });
  it('returns stable labels', () => {
    expect(sniffDenied(DENIED.pe!)).toBe('pe');
    expect(sniffDenied(DENIED.elf!)).toBe('elf');
    expect(sniffDenied(DENIED.zipLocal!)).toBe('zip');
    expect(sniffDenied(DENIED.shebang!)).toBe('shebang');
    expect(sniffDenied(DENIED.php!)).toBe('php');
  });
  it('ignores allowed files and signatures not at offset 0', () => {
    for (const b of [PNG, JPEG, GIF87, GIF89, WEBP, PDF, u8('hello world'), u8(' MZ'), u8('# heading\n#!x')])
      expect(sniffDenied(b)).toBeNull();
    expect(sniffDenied(new Uint8Array())).toBeNull();
    expect(sniffDenied(u8('M'))).toBeNull();
    expect(sniffDenied(u8('PK'))).toBeNull();
  });
});

describe('looksLikeActiveContent', () => {
  const prefixes = ['<!DOCTYPE html>', '<html>', '<script>x</script>', '<svg xmlns="http://www.w3.org/2000/svg">', '<?xml version="1.0"?>',
    '<iframe src=x>', '<object data=x>', '<embed src=x>', '<body onload=x>', '<head>', '<meta http-equiv=refresh>',
    '<link rel=import>', '<style>*{}</style>'];
  it.each(prefixes)('flags leading %s', (p) => {
    expect(looksLikeActiveContent(p)).toBe(true);
    expect(looksLikeActiveContent(p.toUpperCase())).toBe(true);
    expect(looksLikeActiveContent('\uFEFF \n\t\r ' + p)).toBe(true);
    expect(looksLikeActiveContent('\uFEFF\uFEFF\u200B' + p)).toBe(true);
  });
  it('flags <script anywhere in the first 4 KiB', () => {
    expect(looksLikeActiveContent('# Title\n\nsome text <ScRiPt src=//evil></script>')).toBe(true);
    expect(looksLikeActiveContent('a'.repeat(4000) + '<script>')).toBe(true);
    expect(looksLikeActiveContent('a'.repeat(4095) + '<script>')).toBe(true);
    expect(looksLikeActiveContent('a'.repeat(4096) + '<script>')).toBe(false);
    expect(looksLikeActiveContent('a'.repeat(10_000) + '<script>')).toBe(false);
  });
  it('flags javascript: URLs', () => {
    expect(looksLikeActiveContent('javascript:alert(1)')).toBe(true);
    expect(looksLikeActiveContent('  JavaScript:alert(1)')).toBe(true);
    expect(looksLikeActiveContent('java\tscript:alert(1)')).toBe(true);
  });
  it('allows ordinary text and markdown with HTML-ish text later', () => {
    expect(looksLikeActiveContent('hello world')).toBe(false);
    expect(looksLikeActiveContent('')).toBe(false);
    expect(looksLikeActiveContent('# Readme\n\n<div align="center">hi</div>\n<svg></svg>\n<html>')).toBe(false);
    expect(looksLikeActiveContent('a < b and c > d')).toBe(false);
    expect(looksLikeActiveContent('Use the javascript: scheme carefully')).toBe(false);
    expect(looksLikeActiveContent('{"html": "<b>x</b>"}')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
// sanitizeFileName
// ---------------------------------------------------------------------------------------------

function okName(input: string): { name: string; ext: string } {
  const r = sanitizeFileName(input);
  expect(r.ok, JSON.stringify(r)).toBe(true);
  if (!r.ok) throw new Error('unreachable');
  return { name: r.name, ext: r.ext };
}
function badName(input: string): string {
  const r = sanitizeFileName(input);
  expect(r.ok).toBe(false);
  if (r.ok) throw new Error('unreachable');
  expect(r.code).toBe('FILE_NAME_INVALID');
  if (input.length > 0) expect(r.detail).not.toContain(input);
  return r.detail;
}

describe('sanitizeFileName', () => {
  it('keeps plain names', () => {
    expect(okName('notes.txt')).toEqual({ name: 'notes.txt', ext: 'txt' });
    expect(okName('my report (final).pdf')).toEqual({ name: 'my report (final).pdf', ext: 'pdf' });
  });
  it('strips path components', () => {
    expect(okName('../../etc/passwd.txt').name).toBe('passwd.txt');
    expect(okName('C:\\x\\y.txt').name).toBe('y.txt');
    expect(okName('/abs/path/to/a.md').name).toBe('a.md');
    expect(okName('a\\b/c\\d.csv').name).toBe('d.csv');
    badName('dir/');
    badName('..');
    badName('../..');
  });
  it('strips bidi overrides so the real extension is visible', () => {
    const r = okName('evil\u202Egnp.exe');
    expect(r.name).toBe('evilgnp.exe');
    expect(r.ext).toBe('exe');
    for (const c of ['\u061C', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069'])
      expect(okName(`a${c}b.txt`).name).toBe('ab.txt');
  });
  it('strips zero-width characters and BOM', () => {
    for (const c of ['\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF']) expect(okName(`in${c}voice.pdf`).name).toBe('invoice.pdf');
    expect(okName('photo.\u200Bpng').name).toBe('photo.png');
  });
  it('strips C0/C1 control characters', () => {
    expect(okName('a\u0000b\u0007c\u001b[31md\u007f\u0085\u009b.txt').name).toBe('abc[31md.txt');
    expect(okName('line\r\nbreak.txt').name).toBe('linebreak.txt');
    expect(okName('file.t\u0000xt').name).toBe('file.txt');
  });
  it('strips lone surrogates and line separators', () => {
    expect(okName('a\uD800b\u2028c.txt').name).toBe('abc.txt');
  });
  it('replaces reserved punctuation with _', () => {
    expect(okName('a<b>c:d"e|f?g*h.txt').name).toBe('a_b_c_d_e_f_g_h.txt');
  });
  it('trims spaces and dots at both ends', () => {
    expect(okName('  report.pdf  ').name).toBe('report.pdf');
    expect(okName('report.pdf...').name).toBe('report.pdf');
    expect(okName('report.pdf. . ').name).toBe('report.pdf');
    expect(okName('...hidden.txt').name).toBe('hidden.txt');
    expect(okName('\u00A0report.pdf\u3000').name).toBe('report.pdf');
  });
  it('NFC-normalizes', () => {
    expect(okName('cafe\u0301.txt').name).toBe('caf\u00e9.txt');
    // zero-width char between base and combining mark: stripping then renormalizing composes
    expect(okName('cafe\u200B\u0301.txt').name).toBe('caf\u00e9.txt');
  });
  it('rejects empty names', () => {
    for (const n of ['', '   ', '...', ' . . ', '\u202E\u200B', '\u0000']) badName(n);
  });
  it('rejects reserved Windows device names with any extension and case', () => {
    for (const n of ['CON.txt', 'con.txt', 'Nul.PNG', 'prn.pdf', 'aux.md', 'COM1.csv', 'com9.json', 'LPT1.txt', 'lpt9.gif',
      'con.tar.gz', 'CON .txt', 'COM\u00B9.txt', 'CONIN$.txt', 'conout$.txt', 'dir/con.txt', 'con', 'NUL'])
      expect(badName(n)).toMatch(/reserved/);
    // near-misses are fine
    expect(okName('console.txt').name).toBe('console.txt');
    expect(okName('com10.txt').name).toBe('com10.txt');
    expect(okName('nul_.txt').name).toBe('nul_.txt');
    expect(okName('my.con.txt').name).toBe('my.con.txt');
  });
  it('requires a well-formed extension', () => {
    for (const n of ['README', 'noext', '.txt', 'file.', 'file.t-t', 'file.abcdefghijk', 'file.p\u00F1g'])
      expect(badName(n)).toMatch(/extension|empty/);
    expect(okName('file.abcdefghij').ext).toBe('abcdefghij');
    expect(okName('file.mp4').ext).toBe('mp4');
    // NFC maps KELVIN SIGN (U+212A) to ASCII 'K' before the extension check
    expect(okName('x.\u212Aey')).toEqual({ name: 'x.key', ext: 'key' });
  });
  it('lowercases the extension only', () => {
    expect(okName('Photo.PNG')).toEqual({ name: 'Photo.png', ext: 'png' });
    expect(okName('README.Md')).toEqual({ name: 'README.md', ext: 'md' });
  });
  it('judges double extensions by the last one', () => {
    expect(okName('report.pdf.exe')).toEqual({ name: 'report.pdf.exe', ext: 'exe' });
    expect(okName('archive.tar.gz').ext).toBe('gz');
  });
  it('truncates long names to 128 chars keeping the extension', () => {
    const r = okName('a'.repeat(300) + '.TXT');
    expect(r.name.length).toBe(128);
    expect(r.name.endsWith('.txt')).toBe(true);
    expect(okName('b'.repeat(124) + '.txt').name.length).toBe(128);
    expect(okName('b'.repeat(123) + '.txt').name.length).toBe(127);
  });
  it('never splits a surrogate pair when truncating', () => {
    for (let pad = 0; pad < 4; pad++) {
      const r = okName('x'.repeat(pad) + '\u{1F600}'.repeat(200) + '.png');
      expect(r.name.length).toBeLessThanOrEqual(128);
      expect(r.name.endsWith('.png')).toBe(true);
      expect(r.name).not.toMatch(/\p{Cs}/u);
      expect(r.name).toBe(r.name.normalize('NFC'));
      // round-trips cleanly through UTF-8
      expect(new TextDecoder().decode(te.encode(r.name))).toBe(r.name);
    }
  });
  it('re-trims dots/spaces exposed by truncation', () => {
    const r = okName('a'.repeat(122) + ' . . . . . .' + '.txt');
    expect(r.name).toBe('a'.repeat(122) + '.txt');
  });
  it('rejects absurdly long raw input and non-strings', () => {
    badName('a'.repeat(5000) + '.txt');
    expect(sanitizeFileName(undefined as unknown as string).ok).toBe(false);
    expect(sanitizeFileName(42 as unknown as string).ok).toBe(false);
  });
  it('output never contains separators, controls or reserved chars', () => {
    const nasty = ['..\\..\\a\u202E<b>.txt', 'x\u0000/y\u0001:z.md', ' \u200B.\u200B.a*?.csv', 'q\u2066"|.json'];
    for (const n of nasty) {
      const r = sanitizeFileName(n);
      if (r.ok) expect(r.name).not.toMatch(/[\/\\<>:"|?*\p{Cc}\p{Cf}]|^[ .]|[ .]$/u);
    }
  });
});

// ---------------------------------------------------------------------------------------------
// validateFile
// ---------------------------------------------------------------------------------------------

describe('validateFile: accepted types', () => {
  const cases: [string, Uint8Array, AllowedMime][] = [
    ['notes.txt', u8('hello\tworld\r\n\fnext page\n'), 'text/plain'],
    ['README.md', u8('# Title\n\n- item\n\n<div align="center">ok</div>\n'), 'text/markdown'],
    ['doc.markdown', u8('*emphasis*'), 'text/markdown'],
    ['data.csv', u8('a,b\n1,2\n'), 'text/csv'],
    ['cfg.json', u8('{"a":[1,2,{"b":null}]}'), 'application/json'],
    ['img.png', PNG, 'image/png'],
    ['img.jpg', JPEG, 'image/jpeg'],
    ['img.jpeg', JPEG, 'image/jpeg'],
    ['old.gif', GIF87, 'image/gif'],
    ['anim.gif', GIF89, 'image/gif'],
    ['pic.webp', WEBP, 'image/webp'],
    ['paper.pdf', PDF, 'application/pdf'],
    ['UPPER.PNG', PNG, 'image/png'],
    ['unicode.txt', u8('héllo wörld — 日本語 😀'), 'text/plain'],
  ];
  it.each(cases)('%s → %s', async (name, bytes, mime) => {
    const r = await validateFile({ name, bytes }, ALL);
    expect(r).toEqual({ ok: true, name: sanitizeFileName(name).ok ? (sanitizeFileName(name) as { name: string }).name : '', mime, size: bytes.length, sha256: sha(bytes) });
  });
  it('returns the sanitized name and lowercase hex sha256 over raw bytes', async () => {
    const bytes = u8('\uFEFFhello');
    const r = await validateFile({ name: '../x/My\u202EFile.TXT', bytes }, ALL);
    expect(r).toEqual({ ok: true, name: 'MyFile.txt', mime: 'text/plain', size: bytes.length, sha256: sha(bytes) });
    if (r.ok) expect(r.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('validateFile: denied signatures', () => {
  it.each(Object.entries(DENIED))('%s is denied under every allowed extension', async (_label, bytes) => {
    for (const mime of ALLOWED_MIMES)
      for (const ext of EXTENSIONS[mime]) await expectFail(validateFile({ name: `file.${ext}`, bytes }, ALL), 'FILE_TYPE_DENIED');
  });
  it('specific disguises', async () => {
    await expectFail(validateFile({ name: 'notes.txt', bytes: DENIED.pe! }, ALL), 'FILE_TYPE_DENIED');
    await expectFail(validateFile({ name: 'data.csv', bytes: DENIED.zipLocal! }, ALL), 'FILE_TYPE_DENIED');
    await expectFail(validateFile({ name: 'img.png', bytes: DENIED.elf! }, ALL), 'FILE_TYPE_DENIED');
    await expectFail(validateFile({ name: 'run.md', bytes: DENIED.shebang! }, ALL), 'FILE_TYPE_DENIED');
    // text that merely starts with "MZ" is denied too (conservative)
    await expectFail(validateFile({ name: 'notes.txt', bytes: u8('MZ is a two-letter code') }, ALL), 'FILE_TYPE_DENIED');
  });
  it('denied before extension is considered (even for unknown ext)', async () => {
    const d = await expectFail(validateFile({ name: 'x.exe', bytes: DENIED.pe! }, ALL), 'FILE_TYPE_DENIED');
    expect(d).toMatch(/pe/);
  });
});

describe('validateFile: extensions', () => {
  it('unknown extensions are denied', async () => {
    for (const n of ['a.exe', 'a.html', 'a.htm', 'a.svg', 'a.xml', 'a.js', 'a.mjs', 'a.zip', 'a.bat', 'a.docx', 'report.pdf.exe', 'x.pdf.html'])
      await expectFail(validateFile({ name: n, bytes: u8('hello') }, ALL), 'FILE_TYPE_DENIED');
  });
  it('invalid names fail with FILE_NAME_INVALID', async () => {
    for (const n of ['', 'CON.txt', 'noext', '...'])
      await expectFail(validateFile({ name: n, bytes: u8('hello') }, ALL), 'FILE_NAME_INVALID');
  });
  it('detail never echoes a bidi/control-laden name', async () => {
    const evil = 'x\u202E\u0007.exe';
    const r = await validateFile({ name: evil, bytes: u8('hello') }, ALL);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.detail).not.toContain(evil);
      expect(r.detail).not.toMatch(/[\u202E\u0007]/);
    }
  });
});

describe('validateFile: type mismatches and disguises', () => {
  it('binary content under the wrong binary extension', async () => {
    await expectFail(validateFile({ name: 'a.jpg', bytes: PNG }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.png', bytes: GIF89 }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.pdf', bytes: WEBP }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.webp', bytes: JPEG }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('binary content under a text extension', async () => {
    for (const [n, b] of [['a.txt', PNG], ['a.md', PDF], ['a.csv', GIF87], ['a.json', JPEG]] as const)
      await expectFail(validateFile({ name: n, bytes: b }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('binary extension without a matching signature', async () => {
    await expectFail(validateFile({ name: 'a.png', bytes: u8('just text') }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.pdf', bytes: u8([0, 1, 2, 3]) }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('HTML/SVG/XML renamed to a binary extension', async () => {
    await expectFail(validateFile({ name: 'x.png', bytes: u8('<html><script>alert(1)</script>') }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'x.gif', bytes: u8('<svg onload=alert(1)>') }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'x.pdf', bytes: u8('<?xml version="1.0"?>') }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('HTML/SVG/XML disguised as text types', async () => {
    const payloads = ['<!doctype html><p>x', '<html>', '<svg xmlns="http://www.w3.org/2000/svg"/>', '<?xml version="1.0"?><a/>',
      '\uFEFF  <SCRIPT>alert(1)</SCRIPT>', '<iframe src="https://evil">', 'javascript:alert(1)'];
    for (const p of payloads)
      for (const n of ['a.txt', 'a.md', 'a.csv', 'a.json'])
        await expectFail(validateFile({ name: n, bytes: u8(p) }, ALL), 'FILE_TYPE_DENIED');
  });
  it('<script deep inside the first 4 KiB of markdown is denied; beyond it is allowed', async () => {
    const deep = '# Notes\n' + 'lorem ipsum '.repeat(300) + '\n<script>alert(1)</script>\n';
    expect(deep.indexOf('<script')).toBeLessThan(4096);
    await expectFail(validateFile({ name: 'n.md', bytes: u8(deep) }, ALL), 'FILE_TYPE_DENIED');
    const far = '# Notes\n' + 'lorem ipsum '.repeat(500) + '\n<script>alert(1)</script>\n';
    expect(far.indexOf('<script')).toBeGreaterThan(4096);
    expect((await validateFile({ name: 'n.md', bytes: u8(far) }, ALL)).ok).toBe(true);
  });
  it('HTML-ish text later in markdown is allowed', async () => {
    const md = '# Title\n\nSee <b>bold</b> and <svg> mentions and <html> tags.\n';
    expect((await validateFile({ name: 'n.md', bytes: u8(md) }, ALL)).ok).toBe(true);
  });
});

describe('validateFile: text encoding and control characters', () => {
  it('invalid UTF-8 is a mismatch', async () => {
    for (const b of [u8([0xff, 0xfe, 0x68, 0x00]), u8('ok', [0xc3]), u8([0xc0, 0xaf]), u8([0xed, 0xa0, 0x80]), u8('a', [0x80], 'b')])
      await expectFail(validateFile({ name: 'a.txt', bytes: b }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('UTF-16 encoded HTML is rejected', async () => {
    const utf16 = u8([0xff, 0xfe], bin('<\0h\0t\0m\0l\0>\0'));
    await expectFail(validateFile({ name: 'a.txt', bytes: utf16 }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('NUL and other C0 controls are a mismatch', async () => {
    for (const c of [0x00, 0x01, 0x07, 0x08, 0x0b, 0x0e, 0x1b, 0x1f, 0x7f])
      await expectFail(validateFile({ name: 'a.txt', bytes: u8('abc', [c], 'def') }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('C1 controls (encoded as UTF-8) are a mismatch', async () => {
    await expectFail(validateFile({ name: 'a.txt', bytes: u8('abc\u009b31mdef') }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.csv', bytes: u8('a,\u0085b') }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('TAB, LF, CR and FF are allowed', async () => {
    expect((await validateFile({ name: 'a.txt', bytes: u8('a\tb\nc\rd\fe') }, ALL)).ok).toBe(true);
  });
  it('a leading UTF-8 BOM is allowed (text and JSON)', async () => {
    expect((await validateFile({ name: 'a.txt', bytes: u8([0xef, 0xbb, 0xbf], 'hello') }, ALL)).ok).toBe(true);
    expect((await validateFile({ name: 'a.json', bytes: u8([0xef, 0xbb, 0xbf], '{"a":1}') }, ALL)).ok).toBe(true);
  });
  it('a BOM does not hide active content', async () => {
    await expectFail(validateFile({ name: 'a.txt', bytes: u8([0xef, 0xbb, 0xbf], '<html>') }, ALL), 'FILE_TYPE_DENIED');
    await expectFail(validateFile({ name: 'a.txt', bytes: u8([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf], '<svg>') }, ALL), 'FILE_TYPE_DENIED');
  });
  it('invalid JSON is a mismatch; any valid JSON value is accepted', async () => {
    for (const s of ['{', '{"a":1,}', "{'a':1}", 'undefined', 'NaN', '[1,2', ' '])
      await expectFail(validateFile({ name: 'a.json', bytes: u8(s) }, ALL), 'FILE_TYPE_MISMATCH');
    for (const s of ['[]', '1', '"str"', 'null', ' {"a":{"b":[true,false]}} \n'])
      expect((await validateFile({ name: 'a.json', bytes: u8(s) }, ALL)).ok).toBe(true);
  });
});

describe('validateFile: declaredMime', () => {
  it('matching declared types (with params, any case) are accepted', async () => {
    expect((await validateFile({ name: 'a.txt', bytes: u8('hi'), declaredMime: 'text/plain' }, ALL)).ok).toBe(true);
    expect((await validateFile({ name: 'a.txt', bytes: u8('hi'), declaredMime: 'Text/Plain; charset=utf-8' }, ALL)).ok).toBe(true);
    expect((await validateFile({ name: 'a.png', bytes: PNG, declaredMime: ' image/png ' }, ALL)).ok).toBe(true);
    expect((await validateFile({ name: 'a.jpeg', bytes: JPEG, declaredMime: 'image/jpeg' }, ALL)).ok).toBe(true);
  });
  it('mismatching declared types are rejected', async () => {
    await expectFail(validateFile({ name: 'a.txt', bytes: u8('hi'), declaredMime: 'text/html' }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.txt', bytes: u8('hi'), declaredMime: 'text/markdown' }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.jpg', bytes: JPEG, declaredMime: 'image/jpg' }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.png', bytes: PNG, declaredMime: 'image/svg+xml' }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.png', bytes: PNG, declaredMime: '' }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.png', bytes: PNG, declaredMime: 'image/png+x; a=b' }, ALL), 'FILE_TYPE_MISMATCH');
  });
  it('baseMimeType', () => {
    expect(baseMimeType('Text/Plain; charset=UTF-8')).toBe('text/plain');
    expect(baseMimeType('image/png')).toBe('image/png');
    expect(baseMimeType(undefined as unknown as string)).toBe('');
  });
});

describe('validateFile: policy', () => {
  it('types not in policy.allowed are denied', async () => {
    const pol = { allowed: ['text/plain'] as AllowedMime[], maxBytes: 1024 };
    expect((await validateFile({ name: 'a.txt', bytes: u8('x') }, pol)).ok).toBe(true);
    await expectFail(validateFile({ name: 'a.png', bytes: PNG }, pol), 'FILE_TYPE_DENIED');
    await expectFail(validateFile({ name: 'a.md', bytes: u8('x') }, pol), 'FILE_TYPE_DENIED');
    await expectFail(validateFile({ name: 'a.txt', bytes: u8('x') }, { allowed: [], maxBytes: 1024 }), 'FILE_TYPE_DENIED');
  });
});

describe('validateFile: size limits', () => {
  const pol = { allowed: ALLOWED_MIMES, maxBytes: 100 };
  it('empty → FILE_EMPTY', async () => {
    await expectFail(validateFile({ name: 'a.txt', bytes: new Uint8Array(0) }, pol), 'FILE_EMPTY');
    await expectFail(validateFile({ name: 'CON', bytes: new Uint8Array(0) }, pol), 'FILE_EMPTY'); // size checked first
  });
  it('exactly maxBytes is accepted, maxBytes+1 is too large', async () => {
    expect((await validateFile({ name: 'a.txt', bytes: new Uint8Array(100).fill(0x61) }, pol)).ok).toBe(true);
    await expectFail(validateFile({ name: 'a.txt', bytes: new Uint8Array(101).fill(0x61) }, pol), 'FILE_TOO_LARGE');
  });
  it('size is checked before name and content', async () => {
    await expectFail(validateFile({ name: '', bytes: new Uint8Array(101) }, pol), 'FILE_TOO_LARGE');
    await expectFail(validateFile({ name: 'a.txt', bytes: u8(DENIED.pe!, new Uint8Array(200)) }, pol), 'FILE_TOO_LARGE');
  });
  it('HARD_MAX_FILE_BYTES caps even a larger policy', async () => {
    const big = { allowed: ALLOWED_MIMES, maxBytes: HARD_MAX_FILE_BYTES * 2 };
    const atHard = new Uint8Array(HARD_MAX_FILE_BYTES).fill(0x61);
    expect((await validateFile({ name: 'a.txt', bytes: atHard }, big)).ok).toBe(true);
    await expectFail(validateFile({ name: 'a.txt', bytes: new Uint8Array(HARD_MAX_FILE_BYTES + 1).fill(0x61) }, big), 'FILE_TOO_LARGE');
  });
  it('a nonsensical policy limit allows nothing', async () => {
    for (const maxBytes of [NaN, 0, -1, Infinity])
      await expectFail(validateFile({ name: 'a.txt', bytes: u8('x') }, { allowed: ALLOWED_MIMES, maxBytes }), 'FILE_TOO_LARGE');
  });
  it('non-Uint8Array bytes are rejected', async () => {
    await expectFail(validateFile({ name: 'a.txt', bytes: 'hello' as unknown as Uint8Array }, ALL), 'FILE_TYPE_MISMATCH');
    await expectFail(validateFile({ name: 'a.txt', bytes: [104, 105] as unknown as Uint8Array }, ALL), 'FILE_TYPE_MISMATCH');
  });
});

// ---------------------------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------------------------

describe('buildProvenance', () => {
  const base = {
    from: { origin: 'https://a.example', kind: 'page' as const, agentName: 'bot' },
    roomId: 'a'.repeat(32),
    frameId: 'b'.repeat(32),
    sha256: 'c'.repeat(64),
    mime: 'image/png' as const,
    size: 123,
    sentAt: 1_000,
    receivedAt: 2_000,
  };
  it('has the exact Provenance shape with validated: true', () => {
    const p = buildProvenance(base);
    expect(p).toEqual({
      fromOrigin: 'https://a.example',
      fromKind: 'page',
      roomId: 'a'.repeat(32),
      frameId: 'b'.repeat(32),
      sha256: 'c'.repeat(64),
      detectedType: 'image/png',
      size: 123,
      sentAt: 1_000,
      receivedAt: 2_000,
      validated: true,
    });
    expect(Object.keys(p)).toHaveLength(10);
    expect(Object.isFrozen(p)).toBe(true);
    expect(JSON.parse(JSON.stringify(p))).toEqual(p);
  });
  it('works end-to-end with validateFile output', async () => {
    const r = await validateFile({ name: 'x.pdf', bytes: PDF }, ALL);
    if (!r.ok) throw new Error('expected ok');
    const p = buildProvenance({ ...base, sha256: r.sha256, mime: r.mime, size: r.size });
    expect(p.detectedType).toBe('application/pdf');
    expect(p.sha256).toBe(sha(PDF));
  });
  it('rejects malformed input', () => {
    const bad: Partial<Record<keyof typeof base, unknown>>[] = [
      { sha256: 'C'.repeat(64) },
      { sha256: 'c'.repeat(63) },
      { roomId: 'xyz' },
      { frameId: 'B'.repeat(32) },
      { mime: 'text/html' },
      { size: 0 },
      { size: 1.5 },
      { size: HARD_MAX_FILE_BYTES + 1 },
      { sentAt: NaN },
      { receivedAt: undefined },
      { from: { origin: '', kind: 'page' } },
      { from: { origin: 'https://a', kind: 'evil' } },
      { from: undefined },
    ];
    for (const patch of bad) {
      expect(() => buildProvenance({ ...base, ...patch } as typeof base)).toThrow(TabBridgeError);
      try {
        buildProvenance({ ...base, ...patch } as typeof base);
      } catch (e) {
        expect((e as TabBridgeError).code).toBe('VALIDATION_FAILED');
      }
    }
  });
});
