// Strict wire validators and the frame body codec. SPEC.md §4, §4.2.
// Every validator rejects unknown keys, wrong types and out-of-range values with INVALID_MESSAGE.

import { isErrorCode, TabBridgeError } from './errors';
import {
  AES_GCM_OVERHEAD,
  ALLOWED_MIMES,
  BODY_LIMITS,
  FILE_META_MAX,
  HARD_MAX_FILE_BYTES,
  HEX32_RE,
  HEX64_RE,
  ID_TOKEN_RE,
  MAX_AGENT_NAME,
  MAX_NOTE_CHARS,
  MAX_SUMMARY_CHARS,
  MAX_TEXT_BYTES,
  PROTOCOL_VERSION,
  TASK_STATUSES,
} from './limits';
import {
  base64DecodedLength as b64len,
  canonicalJson,
  utf8DecodeStrict,
  utf8Encode,
  utf8Length,
} from './encoding';
import type {
  AllowedMime,
  Body,
  ConfirmBody,
  ContentDetail,
  DirectionGrant,
  E2R,
  EndpointKind,
  FileBody,
  FileMeta,
  FrameHeader,
  FrameKind,
  Grant,
  GrantProposal,
  R2E,
  RoomView,
  TaskBody,
  TextBody,
  Transcript,
  TranscriptParty,
} from './types';

// ---------------------------------------------------------------- primitives

type Obj = Record<string, unknown>;

function fail(what: string): never {
  throw new TabBridgeError('INVALID_MESSAGE', `Invalid message: ${what}`);
}

function isObj(x: unknown): x is Obj {
  // toString check (not prototype identity) so structured-cloned objects from other realms pass.
  return typeof x === 'object' && x !== null && !Array.isArray(x) && Object.prototype.toString.call(x) === '[object Object]';
}

function obj(x: unknown, what: string, required: readonly string[], optional: readonly string[] = []): Obj {
  if (!isObj(x)) fail(`${what} must be an object`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(x)) if (!allowed.has(k)) fail(`${what} has unknown key "${k}"`);
  for (const k of required) if (x[k] === undefined) fail(`${what}.${k} is required`);
  return x;
}

function str(x: unknown, what: string, maxLen = 1_000_000): string {
  if (typeof x !== 'string') fail(`${what} must be a string`);
  if (x.length > maxLen) fail(`${what} too long`);
  return x;
}

function re(x: unknown, pattern: RegExp, what: string): string {
  const s = str(x, what, 256);
  if (!pattern.test(s)) fail(`${what} has invalid format`);
  return s;
}

function int(x: unknown, what: string, min: number, max: number): number {
  if (typeof x !== 'number' || !Number.isInteger(x) || x < min || x > max) fail(`${what} out of range`);
  return x;
}

function bool(x: unknown, what: string): boolean {
  if (typeof x !== 'boolean') fail(`${what} must be boolean`);
  return x;
}

function oneOf<T extends string>(x: unknown, values: readonly T[], what: string): T {
  if (typeof x !== 'string' || !(values as readonly string[]).includes(x)) fail(`${what} invalid`);
  return x as T;
}

function version(x: unknown): 1 {
  if (x !== PROTOCOL_VERSION) throw new TabBridgeError('UNSUPPORTED_VERSION');
  return 1;
}

const hex32 = (x: unknown, what: string) => re(x, HEX32_RE, what);
const hex64 = (x: unknown, what: string) => re(x, HEX64_RE, what);
const idToken = (x: unknown, what: string) => re(x, ID_TOKEN_RE, what);
const timestamp = (x: unknown, what: string) => int(x, what, 0, 8.64e15);

const FRAME_KINDS: readonly FrameKind[] = ['confirm', 'prompt', 'response', 'task', 'file'];
const ENDPOINT_KINDS: readonly EndpointKind[] = ['page', 'panel', 'native'];
const RECEIPT_STATUSES = ['accepted', 'rejected', 'no-agent'] as const;

function errorCode(x: unknown, what: string) {
  if (!isErrorCode(x)) fail(`${what} invalid`);
  return x;
}

function base64(x: unknown, what: string, maxBytes: number): string {
  const s = str(x, what, Math.ceil((maxBytes + 2) / 3) * 4);
  if (b64len(s) < 0) fail(`${what} is not valid base64`);
  return s;
}

function publicKey(x: unknown, what: string): string {
  const s = base64(x, what, 65);
  // Raw uncompressed P-256 point: 65 bytes, first byte 0x04 (base64 'B' + next char in A–P).
  if (b64len(s) !== 65 || s[0] !== 'B' || !/^[A-P]$/.test(s[1] ?? '')) fail(`${what} must be a raw uncompressed P-256 key`);
  return s;
}

// ---------------------------------------------------------------- grants

export function validateDirectionGrantShape(x: unknown, what = 'grant'): DirectionGrant {
  const o = obj(x, what, ['prompts', 'tasks', 'files', 'fileTypes', 'maxFileBytes']);
  if (!Array.isArray(o.fileTypes) || o.fileTypes.length > ALLOWED_MIMES.length * 2) fail(`${what}.fileTypes invalid`);
  const fileTypes = o.fileTypes.map((t, i) => oneOf(t, ALLOWED_MIMES, `${what}.fileTypes[${i}]`));
  return {
    prompts: bool(o.prompts, `${what}.prompts`),
    tasks: bool(o.tasks, `${what}.tasks`),
    files: bool(o.files, `${what}.files`),
    fileTypes: [...new Set(fileTypes)],
    maxFileBytes: int(o.maxFileBytes, `${what}.maxFileBytes`, 1, HARD_MAX_FILE_BYTES),
  };
}

export function validateProposalShape(p: unknown): GrantProposal {
  const o = obj(p, 'proposal', ['i2j', 'j2i', 'ttlMs']);
  return {
    i2j: validateDirectionGrantShape(o.i2j, 'proposal.i2j'),
    j2i: validateDirectionGrantShape(o.j2i, 'proposal.j2i'),
    ttlMs: int(o.ttlMs, 'proposal.ttlMs', 1, 7 * 24 * 3_600_000),
  };
}

export function validateGrantShape(g: unknown): Grant {
  const o = obj(g, 'grant', ['i2j', 'j2i', 'expiresAt', 'rate']);
  const r = obj(o.rate, 'grant.rate', ['framesPerMinute', 'bytesPerMinute']);
  return {
    i2j: validateDirectionGrantShape(o.i2j, 'grant.i2j'),
    j2i: validateDirectionGrantShape(o.j2i, 'grant.j2i'),
    expiresAt: timestamp(o.expiresAt, 'grant.expiresAt'),
    rate: {
      framesPerMinute: int(r.framesPerMinute, 'rate.framesPerMinute', 1, 1_000_000),
      bytesPerMinute: int(r.bytesPerMinute, 'rate.bytesPerMinute', 1, 2 ** 40),
    },
  };
}

// ---------------------------------------------------------------- header & bodies

export function bodyLimit(kind: FrameKind): number {
  return BODY_LIMITS[kind];
}

export function expectedCtBytes(size: number): number {
  return size + AES_GCM_OVERHEAD;
}

export function base64DecodedLength(b64: string): number {
  return b64len(b64);
}

export function validateHeader(h: unknown): FrameHeader {
  const o = obj(h, 'header', ['v', 'frameId', 'roomId', 'from', 'seq', 'kind', 'size', 'ts'], ['mime']);
  version(o.v);
  const kind = oneOf(o.kind, FRAME_KINDS, 'header.kind');
  const header: FrameHeader = {
    v: 1,
    frameId: hex32(o.frameId, 'header.frameId'),
    roomId: hex32(o.roomId, 'header.roomId'),
    from: hex32(o.from, 'header.from'),
    seq: int(o.seq, 'header.seq', 1, Number.MAX_SAFE_INTEGER),
    kind,
    size: int(o.size, 'header.size', 1, BODY_LIMITS.file),
    ts: timestamp(o.ts, 'header.ts'),
  };
  if (kind === 'file') {
    header.mime = oneOf(o.mime, ALLOWED_MIMES, 'header.mime');
  } else if (o.mime !== undefined) {
    fail('header.mime only allowed for file frames');
  }
  return header;
}

export function headerAad(h: FrameHeader): Uint8Array {
  return utf8Encode(canonicalJson(h));
}

function text(x: unknown, what: string): string {
  const s = str(x, what, MAX_TEXT_BYTES);
  if (s.length === 0) fail(`${what} must not be empty`);
  if (utf8Length(s) > MAX_TEXT_BYTES) throw new TabBridgeError('PAYLOAD_TOO_LARGE', `${what} exceeds ${MAX_TEXT_BYTES} bytes`);
  return s;
}

export function validateTextBody(b: unknown, kind: 'prompt' | 'response'): TextBody {
  const o = obj(b, `${kind} body`, ['text', 'threadId'], ['inReplyTo']);
  const out: TextBody = { text: text(o.text, 'text'), threadId: idToken(o.threadId, 'threadId') };
  if (o.inReplyTo !== undefined) out.inReplyTo = hex32(o.inReplyTo, 'inReplyTo');
  if (kind === 'response' && out.inReplyTo === undefined) fail('response requires inReplyTo');
  return out;
}

export function validateTaskBody(b: unknown): TaskBody {
  const o = obj(b, 'task', ['taskId', 'status'], ['progress', 'summary', 'threadId']);
  const out: TaskBody = {
    taskId: idToken(o.taskId, 'task.taskId'),
    status: oneOf(o.status, TASK_STATUSES, 'task.status'),
  };
  if (o.progress !== undefined) {
    if (typeof o.progress !== 'number' || !Number.isFinite(o.progress) || o.progress < 0 || o.progress > 1)
      fail('task.progress must be within [0,1]');
    out.progress = o.progress;
  }
  if (o.summary !== undefined) out.summary = str(o.summary, 'task.summary', MAX_SUMMARY_CHARS);
  if (o.threadId !== undefined) out.threadId = idToken(o.threadId, 'task.threadId');
  return out;
}

export function validateFileMeta(b: unknown): FileMeta {
  const o = obj(b, 'file meta', ['name', 'mime', 'size', 'sha256'], ['threadId']);
  const out: FileMeta = {
    name: str(o.name, 'meta.name', 256),
    mime: oneOf(o.mime, ALLOWED_MIMES, 'meta.mime'),
    size: int(o.size, 'meta.size', 1, HARD_MAX_FILE_BYTES),
    sha256: hex64(o.sha256, 'meta.sha256'),
  };
  if (out.name.length === 0) fail('meta.name empty');
  if (o.threadId !== undefined) out.threadId = idToken(o.threadId, 'meta.threadId');
  return out;
}

function validateConfirmBody(b: unknown): ConfirmBody {
  const o = obj(b, 'confirm', ['transcriptHash']);
  return { transcriptHash: hex64(o.transcriptHash, 'transcriptHash') };
}

export function encodeBody(kind: FrameKind, body: Body): Uint8Array {
  let out: Uint8Array;
  if (kind === 'file') {
    const fb = body as FileBody;
    const meta = utf8Encode(canonicalJson(validateFileMeta(fb.meta)));
    if (meta.length > FILE_META_MAX) throw new TabBridgeError('PAYLOAD_TOO_LARGE', 'file metadata too large');
    out = new Uint8Array(4 + meta.length + fb.bytes.length);
    new DataView(out.buffer).setUint32(0, meta.length, false);
    out.set(meta, 4);
    out.set(fb.bytes, 4 + meta.length);
  } else {
    let validated: unknown;
    if (kind === 'confirm') validated = validateConfirmBody(body);
    else if (kind === 'task') validated = validateTaskBody(body);
    else validated = validateTextBody(body, kind);
    out = utf8Encode(canonicalJson(validated));
  }
  if (out.length > bodyLimit(kind)) throw new TabBridgeError('PAYLOAD_TOO_LARGE');
  return out;
}

export function decodeBody(kind: 'confirm', bytes: Uint8Array): ConfirmBody;
export function decodeBody(kind: 'prompt' | 'response', bytes: Uint8Array): TextBody;
export function decodeBody(kind: 'task', bytes: Uint8Array): TaskBody;
export function decodeBody(kind: 'file', bytes: Uint8Array): FileBody;
export function decodeBody(kind: FrameKind, bytes: Uint8Array): Body;
export function decodeBody(kind: FrameKind, bytes: Uint8Array): Body {
  if (bytes.length > bodyLimit(kind)) throw new TabBridgeError('PAYLOAD_TOO_LARGE');
  if (kind === 'file') {
    if (bytes.length < 5) fail('file body too short');
    const metaLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
    if (metaLen > FILE_META_MAX || 4 + metaLen > bytes.length) fail('file meta length invalid');
    const meta = validateFileMeta(parseJson(bytes.subarray(4, 4 + metaLen)));
    const fileBytes = bytes.slice(4 + metaLen);
    return { meta, bytes: fileBytes };
  }
  const parsed = parseJson(bytes);
  if (kind === 'confirm') return validateConfirmBody(parsed);
  if (kind === 'task') return validateTaskBody(parsed);
  return validateTextBody(parsed, kind);
}

function parseJson(bytes: Uint8Array): unknown {
  let s: string;
  try {
    s = utf8DecodeStrict(bytes);
  } catch {
    fail('body is not valid UTF-8');
  }
  try {
    return JSON.parse(s);
  } catch {
    fail('body is not valid JSON');
  }
}

// ---------------------------------------------------------------- content detail (audit)

export function validateContentDetail(d: unknown): ContentDetail {
  if (!isObj(d)) fail('detail must be an object');
  const kind = oneOf(d.kind, ['prompt', 'response', 'task', 'file'] as const, 'detail.kind');
  if (kind === 'prompt' || kind === 'response') {
    const o = obj(d, 'detail', ['kind', 'text', 'threadId', 'sha256'], ['inReplyTo']);
    const out: ContentDetail = {
      kind,
      text: text(o.text, 'detail.text'),
      threadId: idToken(o.threadId, 'detail.threadId'),
      sha256: hex64(o.sha256, 'detail.sha256'),
    };
    if (o.inReplyTo !== undefined) out.inReplyTo = hex32(o.inReplyTo, 'detail.inReplyTo');
    return out;
  }
  if (kind === 'task') {
    const o = obj(d, 'detail', ['kind', 'task', 'sha256']);
    return { kind, task: validateTaskBody(o.task), sha256: hex64(o.sha256, 'detail.sha256') };
  }
  const o = obj(d, 'detail', ['kind', 'name', 'mime', 'size', 'sha256'], ['threadId']);
  const out: ContentDetail = {
    kind,
    name: str(o.name, 'detail.name', 256),
    mime: oneOf(o.mime, ALLOWED_MIMES, 'detail.mime') as AllowedMime,
    size: int(o.size, 'detail.size', 1, HARD_MAX_FILE_BYTES),
    sha256: hex64(o.sha256, 'detail.sha256'),
  };
  if (o.threadId !== undefined) out.threadId = idToken(o.threadId, 'detail.threadId');
  return out;
}

// ---------------------------------------------------------------- E2R

export function validateE2R(m: unknown): E2R {
  if (!isObj(m)) fail('message must be an object');
  const t = m.t;
  switch (t) {
    case 'hello': {
      const o = obj(m, 'hello', ['t', 'v', 'kind'], ['resume']);
      version(o.v);
      const out: E2R = { t, v: 1, kind: oneOf(o.kind, ['page', 'panel'] as const, 'hello.kind') };
      if (o.resume !== undefined) {
        const r = obj(o.resume, 'hello.resume', ['endpointId', 'resumeToken']);
        out.resume = { endpointId: hex32(r.endpointId, 'resume.endpointId'), resumeToken: hex32(r.resumeToken, 'resume.resumeToken') };
      }
      return out;
    }
    case 'agent': {
      const o = obj(m, 'agent', ['t', 'v', 'attached'], ['name']);
      version(o.v);
      const out: E2R = { t, v: 1, attached: bool(o.attached, 'agent.attached') };
      if (o.name !== undefined) out.name = str(o.name, 'agent.name', MAX_AGENT_NAME * 4);
      return out;
    }
    case 'pair-request': {
      const o = obj(m, 'pair-request', ['t', 'v'], ['note']);
      version(o.v);
      const out: E2R = { t, v: 1 };
      if (o.note !== undefined) out.note = str(o.note, 'note', MAX_NOTE_CHARS);
      return out;
    }
    case 'key-share': {
      const o = obj(m, 'key-share', ['t', 'v', 'roomId', 'publicKey']);
      version(o.v);
      return { t, v: 1, roomId: hex32(o.roomId, 'roomId'), publicKey: publicKey(o.publicKey, 'publicKey') };
    }
    case 'confirmed':
    case 'leave': {
      const o = obj(m, t, ['t', 'v', 'roomId']);
      version(o.v);
      return { t, v: 1, roomId: hex32(o.roomId, 'roomId') };
    }
    case 'frame': {
      const o = obj(m, 'frame', ['t', 'v', 'header', 'ct']);
      version(o.v);
      return { t, v: 1, header: validateHeader(o.header), ct: base64(o.ct, 'ct', BODY_LIMITS.file + AES_GCM_OVERHEAD) };
    }
    case 'receipt': {
      const o = obj(m, 'receipt', ['t', 'v', 'roomId', 'frameId', 'status'], ['code']);
      version(o.v);
      const out: E2R = {
        t,
        v: 1,
        roomId: hex32(o.roomId, 'roomId'),
        frameId: hex32(o.frameId, 'frameId'),
        status: oneOf(o.status, RECEIPT_STATUSES, 'status'),
      };
      if (o.code !== undefined) out.code = errorCode(o.code, 'code');
      return out;
    }
    case 'audit-detail': {
      const o = obj(m, 'audit-detail', ['t', 'v', 'roomId', 'frameId', 'direction', 'detail']);
      version(o.v);
      return {
        t,
        v: 1,
        roomId: hex32(o.roomId, 'roomId'),
        frameId: hex32(o.frameId, 'frameId'),
        direction: oneOf(o.direction, ['sent', 'received'] as const, 'direction'),
        detail: validateContentDetail(o.detail),
      };
    }
    case 'violation': {
      const o = obj(m, 'violation', ['t', 'v', 'roomId', 'code'], ['frameId', 'message']);
      version(o.v);
      const out: E2R = { t, v: 1, roomId: hex32(o.roomId, 'roomId'), code: errorCode(o.code, 'code') };
      if (o.frameId !== undefined) out.frameId = hex32(o.frameId, 'frameId');
      if (o.message !== undefined) out.message = str(o.message, 'message', 500);
      return out;
    }
    default:
      fail('unknown message type');
  }
}

// ---------------------------------------------------------------- R2E

function validateTranscriptParty(x: unknown, what: string): TranscriptParty {
  const o = obj(x, what, ['endpointId', 'origin', 'kind', 'publicKey']);
  return {
    endpointId: hex32(o.endpointId, `${what}.endpointId`),
    origin: str(o.origin, `${what}.origin`, 2048),
    kind: oneOf(o.kind, ENDPOINT_KINDS, `${what}.kind`),
    publicKey: publicKey(o.publicKey, `${what}.publicKey`),
  };
}

export function validateTranscript(x: unknown): Transcript {
  const o = obj(x, 'transcript', ['v', 'roomId', 'initiator', 'joiner', 'grant']);
  version(o.v);
  return {
    v: 1,
    roomId: hex32(o.roomId, 'transcript.roomId'),
    initiator: validateTranscriptParty(o.initiator, 'initiator'),
    joiner: validateTranscriptParty(o.joiner, 'joiner'),
    grant: validateGrantShape(o.grant),
  };
}

export function validateRoomView(x: unknown): RoomView {
  const o = obj(x, 'room', ['roomId', 'state', 'createdAt', 'expiresAt', 'role', 'peer', 'outbound', 'inbound'], ['closedReason']);
  const p = obj(o.peer, 'room.peer', ['origin', 'kind', 'connected'], ['agentName']);
  const out: RoomView = {
    roomId: hex32(o.roomId, 'room.roomId'),
    state: oneOf(o.state, ['keying', 'active', 'closed'] as const, 'room.state'),
    createdAt: timestamp(o.createdAt, 'room.createdAt'),
    expiresAt: timestamp(o.expiresAt, 'room.expiresAt'),
    role: oneOf(o.role, ['initiator', 'joiner'] as const, 'room.role'),
    peer: {
      origin: str(p.origin, 'peer.origin', 2048),
      kind: oneOf(p.kind, ENDPOINT_KINDS, 'peer.kind'),
      connected: bool(p.connected, 'peer.connected'),
    },
    outbound: validateDirectionGrantShape(o.outbound, 'room.outbound'),
    inbound: validateDirectionGrantShape(o.inbound, 'room.inbound'),
  };
  if (p.agentName !== undefined) out.peer.agentName = str(p.agentName, 'peer.agentName', MAX_AGENT_NAME * 4);
  if (o.closedReason !== undefined)
    out.closedReason = oneOf(
      o.closedReason,
      ['user', 'peer-left', 'expired', 'tab-closed', 'endpoint-gone', 'site-disabled', 'violation', 'key-confirm-failed'] as const,
      'room.closedReason',
    );
  return out;
}

export function validateR2E(m: unknown): R2E {
  if (!isObj(m)) fail('message must be an object');
  const t = m.t;
  switch (t) {
    case 'welcome': {
      const o = obj(m, 'welcome', ['t', 'v', 'endpointId', 'resumeToken', 'origin', 'kind', 'rooms', 'paused', 'resumed']);
      version(o.v);
      if (!Array.isArray(o.rooms)) fail('welcome.rooms must be an array');
      return {
        t,
        v: 1,
        endpointId: hex32(o.endpointId, 'endpointId'),
        resumeToken: hex32(o.resumeToken, 'resumeToken'),
        origin: str(o.origin, 'origin', 2048),
        kind: oneOf(o.kind, ENDPOINT_KINDS, 'kind'),
        rooms: o.rooms.map(validateRoomView),
        paused: bool(o.paused, 'paused'),
        resumed: bool(o.resumed, 'resumed'),
      };
    }
    case 'rejected': {
      const o = obj(m, 'rejected', ['t', 'v', 'code']);
      version(o.v);
      return { t, v: 1, code: errorCode(o.code, 'code') };
    }
    case 'key-request': {
      const o = obj(m, 'key-request', ['t', 'v', 'roomId']);
      version(o.v);
      return { t, v: 1, roomId: hex32(o.roomId, 'roomId') };
    }
    case 'room-keys': {
      const o = obj(m, 'room-keys', ['t', 'v', 'roomId', 'transcript']);
      version(o.v);
      const transcript = validateTranscript(o.transcript);
      const roomId = hex32(o.roomId, 'roomId');
      if (transcript.roomId !== roomId) fail('transcript roomId mismatch');
      return { t, v: 1, roomId, transcript };
    }
    case 'room': {
      const o = obj(m, 'room', ['t', 'v', 'room']);
      version(o.v);
      return { t, v: 1, room: validateRoomView(o.room) };
    }
    case 'frame': {
      const o = obj(m, 'frame', ['t', 'v', 'header', 'ct']);
      version(o.v);
      return { t, v: 1, header: validateHeader(o.header), ct: base64(o.ct, 'ct', BODY_LIMITS.file + AES_GCM_OVERHEAD) };
    }
    case 'ack': {
      const o = obj(m, 'ack', ['t', 'v', 'roomId', 'frameId', 'ok'], ['code']);
      version(o.v);
      const out: R2E = { t, v: 1, roomId: hex32(o.roomId, 'roomId'), frameId: hex32(o.frameId, 'frameId'), ok: bool(o.ok, 'ok') };
      if (o.code !== undefined) out.code = errorCode(o.code, 'code');
      return out;
    }
    case 'receipt': {
      const o = obj(m, 'receipt', ['t', 'v', 'roomId', 'frameId', 'status'], ['code']);
      version(o.v);
      const out: R2E = {
        t,
        v: 1,
        roomId: hex32(o.roomId, 'roomId'),
        frameId: hex32(o.frameId, 'frameId'),
        status: oneOf(o.status, RECEIPT_STATUSES, 'status'),
      };
      if (o.code !== undefined) out.code = errorCode(o.code, 'code');
      return out;
    }
    case 'paused': {
      const o = obj(m, 'paused', ['t', 'v', 'paused']);
      version(o.v);
      return { t, v: 1, paused: bool(o.paused, 'paused') };
    }
    case 'error': {
      const o = obj(m, 'error', ['t', 'v', 'code'], ['message']);
      version(o.v);
      const out: R2E = { t, v: 1, code: errorCode(o.code, 'code') };
      if (o.message !== undefined) out.message = str(o.message, 'message', 500);
      return out;
    }
    default:
      fail('unknown message type');
  }
}
