// Grant policy: proposal validation, per-frame checks, narrowing and rate limiting. SPEC.md §10.
// Everything here is pure: inputs are never mutated and outputs never alias inputs.

import { TabBridgeError, type ErrorCode } from '../shared/errors';
import {
  ALLOWED_MIMES,
  DEFAULT_MAX_FILE_BYTES,
  DEFAULT_RATE,
  DEFAULT_ROOM_TTL_MS,
  FILE_META_MAX,
  HARD_MAX_FILE_BYTES,
  ROOM_TTL_OPTIONS_MS,
} from '../shared/limits';
import { validateProposalShape } from '../shared/protocol';
import type {
  AllowedMime,
  Direction,
  DirectionGrant,
  EndpointId,
  FrameHeader,
  Grant,
  GrantNarrowing,
  GrantProposal,
  RateBucket,
  RateLimit,
  Role,
  RoomMember,
} from '../shared/types';

export type { RateBucket } from '../shared/types';

/** Length of the fixed rate-limit window. */
export const RATE_WINDOW_MS = 60_000;

const DIRECTION_KEYS: readonly (keyof DirectionGrant)[] = ['prompts', 'tasks', 'files', 'fileTypes', 'maxFileBytes'];
const NARROWING_KEYS: readonly (keyof GrantNarrowing)[] = ['i2j', 'j2i', 'expiresAt'];

function invalid(what: string): never {
  throw new TabBridgeError('INVALID_MESSAGE', `Invalid message: ${what}`);
}

function notPermitted(what: string): never {
  throw new TabBridgeError('NOT_PERMITTED', `Not permitted: ${what}`);
}

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x) && Object.prototype.toString.call(x) === '[object Object]';
}

function copyDirection(d: DirectionGrant): DirectionGrant {
  return {
    prompts: d.prompts,
    tasks: d.tasks,
    files: d.files,
    fileTypes: [...d.fileTypes],
    maxFileBytes: d.maxFileBytes,
  };
}

/** Deep copy of a grant (no shared arrays or objects). */
export function copyGrant(g: Grant): Grant {
  return {
    i2j: copyDirection(g.i2j),
    j2i: copyDirection(g.j2i),
    expiresAt: g.expiresAt,
    rate: { framesPerMinute: g.rate.framesPerMinute, bytesPerMinute: g.rate.bytesPerMinute },
  };
}

/** Deep copy of a proposal. */
export function copyProposal(p: GrantProposal): GrantProposal {
  return { i2j: copyDirection(p.i2j), j2i: copyDirection(p.j2i), ttlMs: p.ttlMs };
}

export function defaultDirectionGrant(): DirectionGrant {
  return { prompts: true, tasks: true, files: false, fileTypes: [], maxFileBytes: DEFAULT_MAX_FILE_BYTES };
}

export function defaultProposal(): GrantProposal {
  return { i2j: defaultDirectionGrant(), j2i: defaultDirectionGrant(), ttlMs: DEFAULT_ROOM_TTL_MS };
}

function checkDirectionSemantics(d: DirectionGrant, what: string): DirectionGrant {
  const types: AllowedMime[] = [];
  for (const t of d.fileTypes) {
    if (!ALLOWED_MIMES.includes(t)) invalid(`${what}.fileTypes contains a type that is not allowed`);
    if (!types.includes(t)) types.push(t);
  }
  if (!Number.isInteger(d.maxFileBytes) || d.maxFileBytes < 1 || d.maxFileBytes > HARD_MAX_FILE_BYTES)
    invalid(`${what}.maxFileBytes out of range`);
  if (d.files && types.length === 0) invalid(`${what}.files requires at least one file type`);
  return { prompts: d.prompts, tasks: d.tasks, files: d.files, fileTypes: types, maxFileBytes: d.maxFileBytes };
}

/** Strict shape + semantic validation. Returns a fresh, normalized proposal. */
export function validateProposal(p: unknown): GrantProposal {
  const shaped = validateProposalShape(p);
  const out: GrantProposal = {
    i2j: checkDirectionSemantics(shaped.i2j, 'proposal.i2j'),
    j2i: checkDirectionSemantics(shaped.j2i, 'proposal.j2i'),
    ttlMs: shaped.ttlMs,
  };
  if (!ROOM_TTL_OPTIONS_MS.includes(out.ttlMs)) invalid('proposal.ttlMs is not an allowed option');
  return out;
}

export function grantFromProposal(p: GrantProposal, now: number): Grant {
  return {
    i2j: copyDirection(p.i2j),
    j2i: copyDirection(p.j2i),
    expiresAt: now + p.ttlMs,
    rate: { framesPerMinute: DEFAULT_RATE.framesPerMinute, bytesPerMinute: DEFAULT_RATE.bytesPerMinute },
  };
}

/**
 * Direction of a frame sent by `from`. Fails closed (null) for non-members, and for malformed
 * member pairs (duplicate endpointIds or roles that are not exactly one initiator + one joiner).
 */
export function directionOf(members: [RoomMember, RoomMember], from: EndpointId): Direction | null {
  if (!Array.isArray(members) || members.length !== 2) return null;
  const [a, b] = members;
  if (!a || !b || a.endpointId === b.endpointId || a.role === b.role) return null;
  const m = a.endpointId === from ? a : b.endpointId === from ? b : undefined;
  if (!m) return null;
  if (m.role === 'initiator') return 'i2j';
  if (m.role === 'joiner') return 'j2i';
  return null;
}

export function perspective(grant: Grant, role: Role): { outbound: DirectionGrant; inbound: DirectionGrant } {
  if (role === 'initiator') return { outbound: copyDirection(grant.i2j), inbound: copyDirection(grant.j2i) };
  if (role === 'joiner') return { outbound: copyDirection(grant.j2i), inbound: copyDirection(grant.i2j) };
  throw new TabBridgeError('INVALID_MESSAGE', 'Invalid message: unknown role');
}

export type PolicyResult = { ok: true } | { ok: false; code: ErrorCode };

const deny = (code: ErrorCode): PolicyResult => ({ ok: false, code });

export function checkFrame(
  grant: Grant,
  dir: Direction,
  h: Pick<FrameHeader, 'kind' | 'size' | 'mime'>,
  now: number,
): PolicyResult {
  // `!(now < x)` so a NaN/garbage expiry fails closed.
  if (!(now < grant.expiresAt)) return deny('ROOM_EXPIRED');
  if (dir !== 'i2j' && dir !== 'j2i') return deny('NOT_PERMITTED');
  const d = grant[dir];
  // Defense in depth: mime is only meaningful (and only allowed) on file frames.
  if (h.kind !== 'file' && h.mime !== undefined) return deny('NOT_PERMITTED');
  switch (h.kind) {
    case 'confirm':
      return { ok: true };
    case 'prompt':
    case 'response':
      return d.prompts === true ? { ok: true } : deny('NOT_PERMITTED');
    case 'task':
      return d.tasks === true ? { ok: true } : deny('NOT_PERMITTED');
    case 'file': {
      if (d.files !== true || h.mime === undefined || !d.fileTypes.includes(h.mime)) return deny('NOT_PERMITTED');
      if (!(typeof h.size === 'number' && h.size <= d.maxFileBytes + 4 + FILE_META_MAX)) return deny('FILE_TOO_LARGE');
      return { ok: true };
    }
    default:
      return deny('NOT_PERMITTED');
  }
}

function validateDirectionPatch(x: unknown, what: string): Partial<DirectionGrant> {
  if (!isPlainObject(x)) invalid(`${what} must be an object`);
  const out: Partial<DirectionGrant> = {};
  for (const k of Object.keys(x)) {
    if (!(DIRECTION_KEYS as readonly string[]).includes(k)) invalid(`${what} has unknown key "${k}"`);
  }
  for (const k of ['prompts', 'tasks', 'files'] as const) {
    const v = x[k];
    if (v === undefined) continue;
    if (typeof v !== 'boolean') invalid(`${what}.${k} must be boolean`);
    out[k] = v;
  }
  if (x.fileTypes !== undefined) {
    const ft = x.fileTypes;
    if (!Array.isArray(ft) || ft.length > ALLOWED_MIMES.length * 2) invalid(`${what}.fileTypes invalid`);
    const types: AllowedMime[] = [];
    for (const t of ft) {
      if (typeof t !== 'string' || !(ALLOWED_MIMES as readonly string[]).includes(t)) invalid(`${what}.fileTypes invalid`);
      if (!types.includes(t as AllowedMime)) types.push(t as AllowedMime);
    }
    out.fileTypes = types;
  }
  if (x.maxFileBytes !== undefined) {
    const m = x.maxFileBytes;
    if (typeof m !== 'number' || !Number.isInteger(m) || m < 1 || m > HARD_MAX_FILE_BYTES) invalid(`${what}.maxFileBytes out of range`);
    out.maxFileBytes = m;
  }
  return out;
}

function narrowDirection(cur: DirectionGrant, patch: Partial<DirectionGrant>, what: string): DirectionGrant {
  const next = copyDirection(cur);
  for (const k of ['prompts', 'tasks', 'files'] as const) {
    const v = patch[k];
    if (v === undefined) continue;
    if (v && !cur[k]) notPermitted(`${what}.${k} cannot be widened`);
    next[k] = v;
  }
  if (patch.fileTypes !== undefined) {
    for (const t of patch.fileTypes) if (!cur.fileTypes.includes(t)) notPermitted(`${what}.fileTypes cannot be widened`);
    next.fileTypes = [...patch.fileTypes];
  }
  if (patch.maxFileBytes !== undefined) {
    if (patch.maxFileBytes > cur.maxFileBytes) notPermitted(`${what}.maxFileBytes cannot be widened`);
    next.maxFileBytes = patch.maxFileBytes;
  }
  return next;
}

/**
 * Apply a narrowing patch. The whole patch is shape-validated first (INVALID_MESSAGE), then any
 * widening of any field rejects the entire patch (NOT_PERMITTED). Never mutates `grant`.
 */
export function applyNarrowing(grant: Grant, patch: GrantNarrowing): Grant {
  if (!isPlainObject(patch)) invalid('narrowing must be an object');
  for (const k of Object.keys(patch)) {
    if (!(NARROWING_KEYS as readonly string[]).includes(k)) invalid(`narrowing has unknown key "${k}"`);
  }
  const raw = patch as Record<string, unknown>;
  const i2j = raw.i2j === undefined ? undefined : validateDirectionPatch(raw.i2j, 'narrowing.i2j');
  const j2i = raw.j2i === undefined ? undefined : validateDirectionPatch(raw.j2i, 'narrowing.j2i');
  let expiresAt: number | undefined;
  if (raw.expiresAt !== undefined) {
    const e = raw.expiresAt;
    if (typeof e !== 'number' || !Number.isSafeInteger(e) || e < 0) invalid('narrowing.expiresAt invalid');
    expiresAt = e;
  }

  const next = copyGrant(grant);
  if (i2j) next.i2j = narrowDirection(grant.i2j, i2j, 'i2j');
  if (j2i) next.j2i = narrowDirection(grant.j2i, j2i, 'j2i');
  if (expiresAt !== undefined) {
    if (!(expiresAt <= grant.expiresAt)) notPermitted('expiresAt cannot be extended');
    next.expiresAt = expiresAt;
  }
  return next;
}

/**
 * Fixed 60 s window rate limiter. `ok` iff the frame fits in the (possibly new) window.
 * On success the returned bucket includes the frame; on failure it does not. Never mutates `b`.
 */
export function checkRate(
  b: RateBucket | undefined,
  now: number,
  bytes: number,
  rate: RateLimit,
): { ok: boolean; bucket: RateBucket } {
  const bucket: RateBucket =
    b === undefined || now - b.windowStart >= RATE_WINDOW_MS
      ? { windowStart: now, frames: 0, bytes: 0 }
      : { windowStart: b.windowStart, frames: b.frames, bytes: b.bytes };
  if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) return { ok: false, bucket };
  const frames = bucket.frames + 1;
  const total = bucket.bytes + bytes;
  // Written as `<=` comparisons so NaN anywhere fails closed.
  if (!(frames <= rate.framesPerMinute && total <= rate.bytesPerMinute)) return { ok: false, bucket };
  return { ok: true, bucket: { windowStart: bucket.windowStart, frames, bytes: total } };
}
