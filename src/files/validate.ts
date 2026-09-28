// File validation: magic-byte sniffing, dangerous-signature denial, active-content detection,
// file-name sanitization and the full validateFile pipeline. SPEC.md §13, DECISIONS.md D6.
// Runs in content scripts, extension pages and Node: no Node-only APIs.

import { sha256Hex } from '../shared/crypto';
import { utf8DecodeStrict } from '../shared/encoding';
import { ALLOWED_MIMES, HARD_MAX_FILE_BYTES } from '../shared/limits';
import type { AllowedMime } from '../shared/types';

// ---------------------------------------------------------------------------------------------
// Types & tables
// ---------------------------------------------------------------------------------------------

export const EXTENSIONS: Record<AllowedMime, readonly string[]> = Object.freeze({
  'text/plain': Object.freeze(['txt']),
  'text/markdown': Object.freeze(['md', 'markdown']),
  'text/csv': Object.freeze(['csv']),
  'application/json': Object.freeze(['json']),
  'image/png': Object.freeze(['png']),
  'image/jpeg': Object.freeze(['jpg', 'jpeg']),
  'image/gif': Object.freeze(['gif']),
  'image/webp': Object.freeze(['webp']),
  'application/pdf': Object.freeze(['pdf']),
});

export const TEXT_MIMES: readonly AllowedMime[] = Object.freeze([
  'text/plain',
  'text/markdown',
  'text/csv',
  'application/json',
] as AllowedMime[]);

/** Maximum total length (UTF-16 code units) of a sanitized file name, including `.ext`. */
export const MAX_FILE_NAME_CHARS = 128;
/** Raw names longer than this are rejected outright (bounds normalization work). */
export const MAX_RAW_FILE_NAME_CHARS = 4_096;
/** Window (in decoded chars) searched for `<script` by `looksLikeActiveContent`. */
export const ACTIVE_CONTENT_SCAN_CHARS = 4_096;

export type NameResult = { ok: true; name: string; ext: string } | { ok: false; code: 'FILE_NAME_INVALID'; detail: string };

export type FileCheck =
  | { ok: true; name: string; mime: AllowedMime; size: number; sha256: string }
  | {
      ok: false;
      code: 'FILE_TOO_LARGE' | 'FILE_TYPE_DENIED' | 'FILE_TYPE_MISMATCH' | 'FILE_NAME_INVALID' | 'FILE_EMPTY';
      detail: string;
    };

const EXT_TO_MIME: ReadonlyMap<string, AllowedMime> = (() => {
  const m = new Map<string, AllowedMime>();
  for (const mime of ALLOWED_MIMES) for (const ext of EXTENSIONS[mime]) m.set(ext, mime);
  return m;
})();

/** Lowercased extension (no dot) → MIME, or null if the extension is not allowlisted. */
export function mimeForExtension(ext: string): AllowedMime | null {
  if (typeof ext !== 'string') return null;
  return EXT_TO_MIME.get(ext.toLowerCase()) ?? null;
}

export function isTextMime(mime: string): boolean {
  return (TEXT_MIMES as readonly string[]).includes(mime);
}

/** `'Text/Plain; charset=utf-8'` → `'text/plain'`. Returns '' for non-strings. */
export function baseMimeType(declared: string): string {
  if (typeof declared !== 'string') return '';
  const semi = declared.indexOf(';');
  return (semi === -1 ? declared : declared.slice(0, semi)).trim().toLowerCase();
}

// ---------------------------------------------------------------------------------------------
// Magic bytes
// ---------------------------------------------------------------------------------------------

function startsWith(bytes: Uint8Array, sig: readonly number[], offset = 0): boolean {
  if (bytes.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[offset + i] !== sig[i]) return false;
  return true;
}

function ascii(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
  return out;
}

/** ASCII case-insensitive prefix match (`sig` must be lowercase ASCII). */
function startsWithCI(bytes: Uint8Array, sig: string): boolean {
  if (bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    let b = bytes[i] as number;
    if (b >= 0x41 && b <= 0x5a) b += 0x20;
    if (b !== sig.charCodeAt(i)) return false;
  }
  return true;
}

const SIG_PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const SIG_JPEG = [0xff, 0xd8, 0xff];
const SIG_GIF87 = ascii('GIF87a');
const SIG_GIF89 = ascii('GIF89a');
const SIG_RIFF = ascii('RIFF');
const SIG_WEBP = ascii('WEBP');
const SIG_PDF = ascii('%PDF-');

/** Allowlisted binary type identified by magic bytes at offset 0, or null. */
export function sniffBinary(bytes: Uint8Array): AllowedMime | null {
  if (startsWith(bytes, SIG_PNG)) return 'image/png';
  if (startsWith(bytes, SIG_JPEG)) return 'image/jpeg';
  if (startsWith(bytes, SIG_GIF87) || startsWith(bytes, SIG_GIF89)) return 'image/gif';
  if (startsWith(bytes, SIG_RIFF) && startsWith(bytes, SIG_WEBP, 8)) return 'image/webp';
  if (startsWith(bytes, SIG_PDF)) return 'application/pdf';
  return null;
}

const DENIED_SIGNATURES: ReadonlyArray<readonly [label: string, sig: readonly number[]]> = [
  ['pe', ascii('MZ')],
  ['elf', [0x7f, 0x45, 0x4c, 0x46]],
  ['mach-o', [0xfe, 0xed, 0xfa, 0xce]],
  ['mach-o', [0xfe, 0xed, 0xfa, 0xcf]],
  ['mach-o', [0xce, 0xfa, 0xed, 0xfe]],
  ['mach-o', [0xcf, 0xfa, 0xed, 0xfe]],
  ['mach-o-fat', [0xca, 0xfe, 0xba, 0xbe]], // also Java class files
  ['mach-o-fat', [0xbe, 0xba, 0xfe, 0xca]],
  ['zip', [0x50, 0x4b, 0x03, 0x04]],
  ['zip', [0x50, 0x4b, 0x05, 0x06]],
  ['zip', [0x50, 0x4b, 0x07, 0x08]],
  ['gzip', [0x1f, 0x8b]],
  ['7z', [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
  ['rar', ascii('Rar!')],
  ['wasm', [0x00, 0x61, 0x73, 0x6d]],
  ['shebang', ascii('#!')],
];

/** Label for a known-dangerous signature at offset 0 (executables, archives, scripts), else null. */
export function sniffDenied(bytes: Uint8Array): string | null {
  for (const [label, sig] of DENIED_SIGNATURES) if (startsWith(bytes, sig)) return label;
  if (startsWithCI(bytes, '<?php')) return 'php';
  return null;
}

// ---------------------------------------------------------------------------------------------
// Active content
// ---------------------------------------------------------------------------------------------

const ACTIVE_PREFIXES: readonly string[] = [
  '<!doctype',
  '<html',
  '<script',
  '<svg',
  '<?xml',
  '<?php',
  '<iframe',
  '<object',
  '<embed',
  '<body',
  '<head',
  '<meta',
  '<link',
  '<style',
];

// Leading BOMs, whitespace, NULs and invisible format characters are skipped before prefix checks.
const LEADING_IGNORABLE_RE = /^[\s\u0000\p{Cf}]+/u;

/**
 * True if `text` looks like markup or script a consumer might execute or render as a document.
 * Conservative: only leading markup prefixes, `<script` in the first 4 KiB, or a leading
 * `javascript:` URL are flagged; markdown with HTML-ish text further down is allowed.
 */
export function looksLikeActiveContent(text: string): boolean {
  if (typeof text !== 'string') return false;
  const head = text.slice(0, ACTIVE_CONTENT_SCAN_CHARS + 8);
  const lead = head.replace(LEADING_IGNORABLE_RE, '').slice(0, 64).toLowerCase();
  for (const p of ACTIVE_PREFIXES) if (lead.startsWith(p)) return true;
  // URL parsers drop ASCII tab/newline inside schemes ("java\tscript:").
  if (lead.replace(/[\t\n\r]/g, '').startsWith('javascript:')) return true;
  const idx = head.search(/<script/i);
  return idx !== -1 && idx < ACTIVE_CONTENT_SCAN_CHARS;
}

// ---------------------------------------------------------------------------------------------
// File names
// ---------------------------------------------------------------------------------------------

// Stripped from names: C0/C1 controls (Cc), all format chars (Cf: bidi controls, zero-width,
// BOM, soft hyphen, tags), lone surrogates (Cs), line/paragraph separators, plus the explicit
// SPEC list (redundant with Cf but kept for clarity).
const NAME_STRIP_RE =
  /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}؜​-‏‪-‮⁠⁦-⁩﻿]/gu;
const NAME_SPACE_RE = /\p{Zs}/gu;
const NAME_RESERVED_CHARS_RE = /[<>:"|?*]/g;
const TRIM_RE = /^[ .]+|[ .]+$/g;
const EXT_RE = /^[A-Za-z0-9]{1,10}$/;
// Windows reserved device names (checked on the part before the first dot, trailing spaces
// ignored). Includes superscript-digit COM/LPT variants and CONIN$/CONOUT$.
const RESERVED_RE = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)$/i;

function invalidName(detail: string): NameResult {
  return { ok: false, code: 'FILE_NAME_INVALID', detail };
}

function isReservedBase(name: string): boolean {
  const dot = name.indexOf('.');
  const first = (dot === -1 ? name : name.slice(0, dot)).replace(/ +$/, '');
  return RESERVED_RE.test(first);
}

/** Truncate to at most `max` UTF-16 code units without splitting a surrogate pair. */
function truncateUtf16(s: string, max: number): string {
  if (s.length <= max) return s;
  let end = max;
  const last = s.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return s.slice(0, end);
}

/**
 * Sanitize an untrusted file name (SPEC §13). Never echoes the input in `detail`.
 * Result names are NFC, have no path components or invisible/control characters, no
 * `<>:"|?*`, no leading/trailing spaces or dots, a lowercase allowlist-shaped extension
 * (not necessarily an allowed type — see validateFile), and are at most 128 UTF-16 code units.
 */
export function sanitizeFileName(name: string): NameResult {
  if (typeof name !== 'string') return invalidName('File name must be a string');
  if (name.length > MAX_RAW_FILE_NAME_CHARS) return invalidName('File name is too long');
  let s = name.normalize('NFC');
  s = s.replace(NAME_STRIP_RE, '').replace(NAME_SPACE_RE, ' ');
  s = s.replace(NAME_RESERVED_CHARS_RE, '_');
  const sep = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  if (sep !== -1) s = s.slice(sep + 1);
  // Stripping may have juxtaposed a base char and combining mark; renormalize.
  s = s.normalize('NFC').replace(TRIM_RE, '');
  if (s === '') return invalidName('File name is empty');
  if (isReservedBase(s)) return invalidName('File name is a reserved device name');
  const dot = s.lastIndexOf('.');
  if (dot <= 0) return invalidName('File name has no extension');
  const rawExt = s.slice(dot + 1);
  if (!EXT_RE.test(rawExt)) return invalidName('File extension is invalid');
  const ext = rawExt.toLowerCase();
  let base = s.slice(0, dot);
  const maxBase = MAX_FILE_NAME_CHARS - (ext.length + 1);
  if (base.length > maxBase) base = truncateUtf16(base, maxBase).replace(/[ .]+$/, '');
  if (base === '') return invalidName('File name is empty');
  const out = `${base}.${ext}`;
  if (isReservedBase(out)) return invalidName('File name is a reserved device name');
  return { ok: true, name: out, ext };
}

// ---------------------------------------------------------------------------------------------
// validateFile
// ---------------------------------------------------------------------------------------------

type FileFail = Extract<FileCheck, { ok: false }>;

function fail(code: FileFail['code'], detail: string): FileFail {
  return { ok: false, code, detail };
}

function isUint8Array(x: unknown): x is Uint8Array {
  // Cross-realm safe (content-script isolated world vs. page world).
  return Object.prototype.toString.call(x) === '[object Uint8Array]';
}

/**
 * Reject C0 controls except TAB, LF, FF, CR; reject DEL and C1 controls (U+0080–U+009F,
 * e.g. U+009B CSI terminal escapes).
 */
function hasForbiddenControl(text: string): boolean {
  return /[\u0000-\u0008\u000b\u000e-\u001f\u007f-\u009f]/.test(text);
}

/**
 * Validate an untrusted file (SPEC §13 order). Used by the sender before encryption and by the
 * receiver after decryption. `detail` never contains the (unsanitized) file name.
 */
export async function validateFile(
  input: { name: string; bytes: Uint8Array; declaredMime?: string },
  policy: { allowed: readonly AllowedMime[]; maxBytes: number },
): Promise<FileCheck> {
  const bytes = input?.bytes;
  if (!isUint8Array(bytes)) return fail('FILE_TYPE_MISMATCH', 'File data is not a byte array');
  const size = bytes.byteLength;

  // 1. Size (before any decoding work). A non-finite / non-positive policy limit allows nothing.
  if (size === 0) return fail('FILE_EMPTY', 'File is empty');
  const maxBytes = policy && Number.isFinite(policy.maxBytes) && policy.maxBytes > 0 ? policy.maxBytes : 0;
  if (size > HARD_MAX_FILE_BYTES) return fail('FILE_TOO_LARGE', `File exceeds the hard limit of ${HARD_MAX_FILE_BYTES} bytes`);
  if (size > maxBytes) return fail('FILE_TOO_LARGE', `File exceeds the limit of ${maxBytes} bytes`);

  // 2. Name.
  const nr = sanitizeFileName(input.name);
  if (!nr.ok) return fail('FILE_NAME_INVALID', nr.detail);

  // 3. Always-denied signatures, regardless of name.
  const denied = sniffDenied(bytes);
  if (denied !== null) return fail('FILE_TYPE_DENIED', `Content type is not allowed (${denied})`);

  // 4. Extension → expected type.
  const expected = mimeForExtension(nr.ext);
  if (expected === null) return fail('FILE_TYPE_DENIED', `File extension .${nr.ext} is not allowed`);

  // 5. Binary sniff.
  const sniffed = sniffBinary(bytes);
  if (sniffed !== null && sniffed !== expected)
    return fail('FILE_TYPE_MISMATCH', `Content is ${sniffed}, but the extension implies ${expected}`);

  if (isTextMime(expected)) {
    // 6. Text: strict UTF-8 (leading BOM stripped by the decoder), no control characters.
    let text: string;
    try {
      text = utf8DecodeStrict(bytes);
    } catch {
      return fail('FILE_TYPE_MISMATCH', 'Text file is not valid UTF-8');
    }
    if (hasForbiddenControl(text)) return fail('FILE_TYPE_MISMATCH', 'Text file contains control characters');
    // 7. Markup / script.
    if (looksLikeActiveContent(text)) return fail('FILE_TYPE_DENIED', 'Text file looks like HTML, SVG, XML or script');
    // 8. JSON must parse.
    if (expected === 'application/json') {
      try {
        JSON.parse(text);
      } catch {
        return fail('FILE_TYPE_MISMATCH', 'JSON file does not parse');
      }
    }
  } else if (sniffed === null) {
    return fail('FILE_TYPE_MISMATCH', `Content does not match ${expected}`);
  }

  // 9. Declared MIME (parameters ignored, strict equality — 'image/jpg' ≠ 'image/jpeg').
  if (input.declaredMime !== undefined) {
    const declared = baseMimeType(input.declaredMime);
    if (declared !== expected) return fail('FILE_TYPE_MISMATCH', `Declared type does not match detected ${expected}`);
  }

  // 10. Policy.
  const allowed = Array.isArray(policy?.allowed) ? policy.allowed : [];
  if (!allowed.includes(expected)) return fail('FILE_TYPE_DENIED', `Type ${expected} is not permitted in this room`);

  return { ok: true, name: nr.name, mime: expected, size, sha256: await sha256Hex(bytes) };
}
