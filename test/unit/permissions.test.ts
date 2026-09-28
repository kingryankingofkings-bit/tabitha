import { describe, expect, it } from 'vitest';
import {
  applyNarrowing,
  checkFrame,
  checkRate,
  defaultDirectionGrant,
  defaultProposal,
  directionOf,
  grantFromProposal,
  perspective,
  validateProposal,
} from '../../src/background/permissions';
import {
  ALLOWED_MIMES,
  DEFAULT_MAX_FILE_BYTES,
  DEFAULT_RATE,
  DEFAULT_ROOM_TTL_MS,
  FILE_META_MAX,
  HARD_MAX_FILE_BYTES,
  ROOM_TTL_OPTIONS_MS,
} from '../../src/shared/limits';
import { randomHex32 } from '../../src/shared/encoding';
import type { DirectionGrant, Grant, GrantProposal, RoomMember } from '../../src/shared/types';

const code = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code ?? 'THREW';
  }
  return 'OK';
};

const NOW = 1_700_000_000_000;

function dg(over: Partial<DirectionGrant> = {}): DirectionGrant {
  return { prompts: true, tasks: true, files: true, fileTypes: ['text/plain', 'image/png'], maxFileBytes: 1000, ...over };
}

function proposal(over: Partial<GrantProposal> = {}): GrantProposal {
  return { i2j: dg(), j2i: dg({ files: false, fileTypes: [] }), ttlMs: DEFAULT_ROOM_TTL_MS, ...over };
}

function grant(over: Partial<Grant> = {}): Grant {
  return { ...grantFromProposal(proposal(), NOW), ...over };
}

describe('defaults', () => {
  it('defaultDirectionGrant matches spec', () => {
    expect(defaultDirectionGrant()).toEqual({
      prompts: true,
      tasks: true,
      files: false,
      fileTypes: [],
      maxFileBytes: DEFAULT_MAX_FILE_BYTES,
    });
  });
  it('defaultProposal uses default ttl, validates, and returns fresh objects', () => {
    const a = defaultProposal();
    expect(a.ttlMs).toBe(DEFAULT_ROOM_TTL_MS);
    expect(validateProposal(a)).toEqual(a);
    const b = defaultProposal();
    expect(a.i2j).not.toBe(b.i2j);
    expect(a.i2j.fileTypes).not.toBe(a.j2i.fileTypes);
  });
});

describe('validateProposal', () => {
  it('accepts a valid proposal and every ttl option', () => {
    for (const ttlMs of ROOM_TTL_OPTIONS_MS) expect(validateProposal(proposal({ ttlMs })).ttlMs).toBe(ttlMs);
  });
  it('dedupes fileTypes and returns a copy', () => {
    const p = proposal({ i2j: dg({ fileTypes: ['text/plain', 'text/plain', 'image/png'] }) });
    const out = validateProposal(p);
    expect(out.i2j.fileTypes).toEqual(['text/plain', 'image/png']);
    expect(out.i2j).not.toBe(p.i2j);
    expect(out.i2j.fileTypes).not.toBe(p.i2j.fileTypes);
  });
  it('rejects ttl not in the options list', () => {
    for (const ttlMs of [1, 60_000, DEFAULT_ROOM_TTL_MS + 1, 0, -1, 1.5, Infinity, NaN])
      expect(code(() => validateProposal(proposal({ ttlMs })))).toBe('INVALID_MESSAGE');
  });
  it('rejects maxFileBytes out of range', () => {
    for (const maxFileBytes of [0, -1, HARD_MAX_FILE_BYTES + 1, 1.5, NaN])
      expect(code(() => validateProposal(proposal({ j2i: dg({ maxFileBytes }) })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal(proposal({ j2i: dg({ maxFileBytes: 1 }) })))).toBe('OK');
    expect(code(() => validateProposal(proposal({ j2i: dg({ maxFileBytes: HARD_MAX_FILE_BYTES }) })))).toBe('OK');
  });
  it('rejects unknown file types', () => {
    const bad = dg({ fileTypes: ['text/html' as never] });
    expect(code(() => validateProposal(proposal({ i2j: bad })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal(proposal({ i2j: dg({ fileTypes: ['image/svg+xml' as never] }) })))).toBe('INVALID_MESSAGE');
  });
  it('files=true requires at least one type; files=false may have none', () => {
    expect(code(() => validateProposal(proposal({ i2j: dg({ files: true, fileTypes: [] }) })))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal(proposal({ i2j: dg({ files: false, fileTypes: [] }) })))).toBe('OK');
  });
  it('rejects bad shapes and unknown keys', () => {
    expect(code(() => validateProposal(null))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal('x'))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal({ ...proposal(), extra: 1 }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal({ ...proposal(), i2j: { ...dg(), admin: true } }))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal({ ...proposal(), i2j: { ...dg(), prompts: 'yes' } }))).toBe('INVALID_MESSAGE');
    const { j2i: _drop, ...missing } = proposal();
    expect(code(() => validateProposal(missing))).toBe('INVALID_MESSAGE');
    expect(code(() => validateProposal(JSON.parse('{"__proto__":{"x":1},"i2j":{},"j2i":{},"ttlMs":900000}')))).toBe(
      'INVALID_MESSAGE',
    );
  });
});

describe('grantFromProposal', () => {
  it('sets expiry and default rate', () => {
    const g = grantFromProposal(proposal({ ttlMs: 900_000 }), NOW);
    expect(g.expiresAt).toBe(NOW + 900_000);
    expect(g.rate).toEqual(DEFAULT_RATE);
    expect(g.rate).not.toBe(DEFAULT_RATE);
  });
  it('deep-copies (no shared references)', () => {
    const p = proposal();
    const g = grantFromProposal(p, NOW);
    expect(g.i2j).toEqual(p.i2j);
    expect(g.i2j).not.toBe(p.i2j);
    expect(g.i2j.fileTypes).not.toBe(p.i2j.fileTypes);
    p.i2j.fileTypes.push('application/pdf');
    p.i2j.prompts = false;
    expect(g.i2j.fileTypes).toEqual(['text/plain', 'image/png']);
    expect(g.i2j.prompts).toBe(true);
    g.rate.framesPerMinute = 1;
    expect(DEFAULT_RATE.framesPerMinute).toBe(60);
  });
});

describe('directionOf / perspective', () => {
  const a = randomHex32();
  const b = randomHex32();
  const m = (endpointId: string, role: 'initiator' | 'joiner'): RoomMember => ({ endpointId, kind: 'page', origin: 'https://x.test', role });
  it('maps roles to directions, independent of member order', () => {
    expect(directionOf([m(a, 'initiator'), m(b, 'joiner')], a)).toBe('i2j');
    expect(directionOf([m(a, 'initiator'), m(b, 'joiner')], b)).toBe('j2i');
    expect(directionOf([m(b, 'joiner'), m(a, 'initiator')], a)).toBe('i2j');
    expect(directionOf([m(b, 'joiner'), m(a, 'initiator')], b)).toBe('j2i');
  });
  it('non-member → null', () => {
    expect(directionOf([m(a, 'initiator'), m(b, 'joiner')], randomHex32())).toBeNull();
    expect(directionOf([m(a, 'initiator'), m(b, 'joiner')], '')).toBeNull();
  });
  it('malformed member pairs fail closed', () => {
    expect(directionOf([m(a, 'initiator'), m(a, 'joiner')], a)).toBeNull();
    expect(directionOf([m(a, 'initiator'), m(b, 'initiator')], b)).toBeNull();
    expect(directionOf([m(a, 'initiator'), { ...m(b, 'joiner'), role: 'admin' as never }], b)).toBeNull();
  });
  it('perspective returns outbound/inbound copies', () => {
    const g = grant({ i2j: dg({ prompts: true, tasks: false }), j2i: dg({ prompts: false, tasks: true }) });
    const ini = perspective(g, 'initiator');
    expect(ini.outbound).toEqual(g.i2j);
    expect(ini.inbound).toEqual(g.j2i);
    const joi = perspective(g, 'joiner');
    expect(joi.outbound).toEqual(g.j2i);
    expect(joi.inbound).toEqual(g.i2j);
    expect(ini.outbound).not.toBe(g.i2j);
    ini.outbound.fileTypes.push('application/pdf');
    ini.outbound.prompts = false;
    expect(g.i2j.fileTypes).toEqual(['text/plain', 'image/png']);
    expect(g.i2j.prompts).toBe(true);
    expect(code(() => perspective(g, 'boss' as never))).toBe('INVALID_MESSAGE');
  });
});

describe('checkFrame', () => {
  const g = grant({
    i2j: dg({ prompts: true, tasks: true, files: true, fileTypes: ['image/png'], maxFileBytes: 1000 }),
    j2i: dg({ prompts: false, tasks: false, files: false, fileTypes: [] }),
  });
  const now = NOW + 1;
  it('allows what the direction grants', () => {
    expect(checkFrame(g, 'i2j', { kind: 'prompt', size: 10 }, now)).toEqual({ ok: true });
    expect(checkFrame(g, 'i2j', { kind: 'response', size: 10 }, now)).toEqual({ ok: true });
    expect(checkFrame(g, 'i2j', { kind: 'task', size: 10 }, now)).toEqual({ ok: true });
    expect(checkFrame(g, 'i2j', { kind: 'file', size: 10, mime: 'image/png' }, now)).toEqual({ ok: true });
  });
  it('denies what the direction does not grant', () => {
    for (const kind of ['prompt', 'response', 'task'] as const)
      expect(checkFrame(g, 'j2i', { kind, size: 10 }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
    expect(checkFrame(g, 'j2i', { kind: 'file', size: 10, mime: 'image/png' }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
  });
  it('prompts and tasks are independent', () => {
    const g2 = grant({ i2j: dg({ prompts: false, tasks: true }) });
    expect(checkFrame(g2, 'i2j', { kind: 'prompt', size: 1 }, now).ok).toBe(false);
    expect(checkFrame(g2, 'i2j', { kind: 'response', size: 1 }, now).ok).toBe(false);
    expect(checkFrame(g2, 'i2j', { kind: 'task', size: 1 }, now).ok).toBe(true);
  });
  it('confirm is always allowed (before expiry), even with nothing granted', () => {
    expect(checkFrame(g, 'j2i', { kind: 'confirm', size: 10 }, now)).toEqual({ ok: true });
  });
  it('file mime must be in fileTypes and present', () => {
    expect(checkFrame(g, 'i2j', { kind: 'file', size: 10, mime: 'image/jpeg' }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
    expect(checkFrame(g, 'i2j', { kind: 'file', size: 10 }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
  });
  it('files=false denies even if fileTypes lists the mime', () => {
    const g2 = grant({ i2j: dg({ files: false, fileTypes: ['image/png'] }) });
    expect(checkFrame(g2, 'i2j', { kind: 'file', size: 10, mime: 'image/png' }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
  });
  it('mime on a non-file frame is denied', () => {
    expect(checkFrame(g, 'i2j', { kind: 'prompt', size: 10, mime: 'image/png' }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
  });
  it('file size limit is maxFileBytes + framing + meta', () => {
    const limit = 1000 + 4 + FILE_META_MAX;
    expect(checkFrame(g, 'i2j', { kind: 'file', size: limit, mime: 'image/png' }, now)).toEqual({ ok: true });
    expect(checkFrame(g, 'i2j', { kind: 'file', size: limit + 1, mime: 'image/png' }, now)).toEqual({ ok: false, code: 'FILE_TOO_LARGE' });
    expect(checkFrame(g, 'i2j', { kind: 'file', size: NaN, mime: 'image/png' }, now)).toEqual({ ok: false, code: 'FILE_TOO_LARGE' });
  });
  it('NOT_PERMITTED takes precedence over FILE_TOO_LARGE for a denied mime', () => {
    expect(checkFrame(g, 'i2j', { kind: 'file', size: 10 ** 9, mime: 'text/plain' }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
  });
  it('expiry is checked first, at exactly expiresAt', () => {
    expect(checkFrame(g, 'i2j', { kind: 'prompt', size: 1 }, g.expiresAt - 1)).toEqual({ ok: true });
    expect(checkFrame(g, 'i2j', { kind: 'prompt', size: 1 }, g.expiresAt)).toEqual({ ok: false, code: 'ROOM_EXPIRED' });
    expect(checkFrame(g, 'i2j', { kind: 'confirm', size: 1 }, g.expiresAt)).toEqual({ ok: false, code: 'ROOM_EXPIRED' });
    expect(checkFrame(g, 'j2i', { kind: 'bogus' as never, size: 1 }, g.expiresAt + 5)).toEqual({ ok: false, code: 'ROOM_EXPIRED' });
    expect(checkFrame({ ...g, expiresAt: NaN }, 'i2j', { kind: 'prompt', size: 1 }, now)).toEqual({ ok: false, code: 'ROOM_EXPIRED' });
  });
  it('unknown kind or direction → NOT_PERMITTED', () => {
    expect(checkFrame(g, 'i2j', { kind: 'admin' as never, size: 1 }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
    expect(checkFrame(g, 'x2y' as never, { kind: 'prompt', size: 1 }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
    expect(checkFrame(g, 'expiresAt' as never, { kind: 'prompt', size: 1 }, now)).toEqual({ ok: false, code: 'NOT_PERMITTED' });
  });
});

describe('applyNarrowing', () => {
  const base = (): Grant =>
    grant({
      i2j: dg({ prompts: true, tasks: true, files: true, fileTypes: ['text/plain', 'image/png'], maxFileBytes: 1000 }),
      j2i: dg({ prompts: false, tasks: false, files: false, fileTypes: [], maxFileBytes: 500 }),
    });

  it('narrows each field and does not mutate the input', () => {
    const g = base();
    const before = JSON.parse(JSON.stringify(g));
    const n = applyNarrowing(g, {
      i2j: { prompts: false, tasks: false, files: false, fileTypes: ['image/png'], maxFileBytes: 10 },
      expiresAt: g.expiresAt - 1000,
    });
    expect(n.i2j).toEqual({ prompts: false, tasks: false, files: false, fileTypes: ['image/png'], maxFileBytes: 10 });
    expect(n.j2i).toEqual(g.j2i);
    expect(n.expiresAt).toBe(g.expiresAt - 1000);
    expect(n.rate).toEqual(g.rate);
    expect(g).toEqual(before);
    expect(n).not.toBe(g);
    expect(n.j2i).not.toBe(g.j2i);
    expect(n.j2i.fileTypes).not.toBe(g.j2i.fileTypes);
    expect(n.rate).not.toBe(g.rate);
  });
  it('empty patch returns an equal copy; equal values are fine', () => {
    const g = base();
    expect(applyNarrowing(g, {})).toEqual(g);
    expect(applyNarrowing(g, { i2j: { ...g.i2j }, j2i: { ...g.j2i }, expiresAt: g.expiresAt })).toEqual(g);
  });
  it('dedupes fileTypes and allows narrowing to []', () => {
    const g = base();
    expect(applyNarrowing(g, { i2j: { fileTypes: ['image/png', 'image/png'] } }).i2j.fileTypes).toEqual(['image/png']);
    expect(applyNarrowing(g, { i2j: { fileTypes: [] } }).i2j.fileTypes).toEqual([]);
  });
  it('rejects widening of every boolean', () => {
    for (const k of ['prompts', 'tasks', 'files'] as const) {
      expect(code(() => applyNarrowing(base(), { j2i: { [k]: true } }))).toBe('NOT_PERMITTED');
      // true → true is fine
      expect(code(() => applyNarrowing(base(), { i2j: { [k]: true } }))).toBe('OK');
    }
  });
  it('rejects adding a file type', () => {
    expect(code(() => applyNarrowing(base(), { i2j: { fileTypes: ['application/pdf'] } }))).toBe('NOT_PERMITTED');
    expect(code(() => applyNarrowing(base(), { i2j: { fileTypes: ['image/png', 'application/pdf'] } }))).toBe('NOT_PERMITTED');
    expect(code(() => applyNarrowing(base(), { j2i: { fileTypes: ['text/plain'] } }))).toBe('NOT_PERMITTED');
  });
  it('rejects increasing maxFileBytes', () => {
    expect(code(() => applyNarrowing(base(), { i2j: { maxFileBytes: 1001 } }))).toBe('NOT_PERMITTED');
    expect(code(() => applyNarrowing(base(), { i2j: { maxFileBytes: 1000 } }))).toBe('OK');
  });
  it('rejects extending expiresAt', () => {
    const g = base();
    expect(code(() => applyNarrowing(g, { expiresAt: g.expiresAt + 1 }))).toBe('NOT_PERMITTED');
  });
  it('one widening field rejects the whole patch (no partial application)', () => {
    const g = base();
    const before = JSON.parse(JSON.stringify(g));
    expect(code(() => applyNarrowing(g, { i2j: { prompts: false }, j2i: { prompts: true } }))).toBe('NOT_PERMITTED');
    expect(g).toEqual(before);
  });
  it('rejects bad shapes with INVALID_MESSAGE', () => {
    const g = base();
    const bad: unknown[] = [
      null,
      'x',
      [],
      { rate: { framesPerMinute: 1 } },
      { i2j: { admin: true } },
      { i2j: null },
      { i2j: [] },
      { i2j: { prompts: 'false' } },
      { i2j: { prompts: 0 } },
      { i2j: { fileTypes: 'image/png' } },
      { i2j: { fileTypes: ['text/html'] } },
      { i2j: { fileTypes: [1] } },
      { i2j: { maxFileBytes: 0 } },
      { i2j: { maxFileBytes: 1.5 } },
      { i2j: { maxFileBytes: '10' } },
      { i2j: { maxFileBytes: HARD_MAX_FILE_BYTES + 1 } },
      { expiresAt: 'soon' },
      { expiresAt: NaN },
      { expiresAt: -1 },
      { expiresAt: 1.5 },
      JSON.parse('{"__proto__":{"i2j":{"prompts":true}}}'),
    ];
    for (const p of bad) expect(code(() => applyNarrowing(g, p as never))).toBe('INVALID_MESSAGE');
  });
  it('shape errors take precedence over widening', () => {
    expect(code(() => applyNarrowing(base(), { j2i: { prompts: true }, extra: 1 } as never))).toBe('INVALID_MESSAGE');
  });
});

describe('checkRate', () => {
  const rate = { framesPerMinute: 3, bytesPerMinute: 100 };
  it('starts a new window when there is no bucket', () => {
    const r = checkRate(undefined, 1000, 10, rate);
    expect(r).toEqual({ ok: true, bucket: { windowStart: 1000, frames: 1, bytes: 10 } });
  });
  it('limits frames per window', () => {
    let b = checkRate(undefined, 0, 1, rate).bucket;
    b = checkRate(b, 1, 1, rate).bucket;
    const third = checkRate(b, 2, 1, rate);
    expect(third.ok).toBe(true);
    const fourth = checkRate(third.bucket, 3, 1, rate);
    expect(fourth).toEqual({ ok: false, bucket: { windowStart: 0, frames: 3, bytes: 3 } });
  });
  it('limits bytes per window (exact boundary allowed)', () => {
    const a = checkRate(undefined, 0, 60, rate);
    expect(checkRate(a.bucket, 1, 40, rate).ok).toBe(true);
    const r = checkRate(a.bucket, 1, 41, rate);
    expect(r).toEqual({ ok: false, bucket: { windowStart: 0, frames: 1, bytes: 60 } });
    expect(checkRate(undefined, 0, 101, rate).ok).toBe(false);
  });
  it('rolls over at exactly 60 s', () => {
    const full = { windowStart: 0, frames: 3, bytes: 100 };
    expect(checkRate(full, 59_999, 1, rate).ok).toBe(false);
    expect(checkRate(full, 60_000, 1, rate)).toEqual({ ok: true, bucket: { windowStart: 60_000, frames: 1, bytes: 1 } });
  });
  it('returns the reset bucket (not incremented) when a new window still rejects', () => {
    const r = checkRate({ windowStart: 0, frames: 3, bytes: 100 }, 120_000, 500, rate);
    expect(r).toEqual({ ok: false, bucket: { windowStart: 120_000, frames: 0, bytes: 0 } });
  });
  it('never mutates the input bucket', () => {
    const b = { windowStart: 0, frames: 1, bytes: 1 };
    const r = checkRate(b, 10, 5, rate);
    expect(b).toEqual({ windowStart: 0, frames: 1, bytes: 1 });
    expect(r.bucket).not.toBe(b);
    const r2 = checkRate(b, 70_000, 5, rate);
    expect(b).toEqual({ windowStart: 0, frames: 1, bytes: 1 });
    expect(r2.bucket).not.toBe(b);
    const r3 = checkRate(b, 10, 1000, rate);
    expect(r3.bucket).not.toBe(b);
  });
  it('fails closed on invalid byte counts and garbage buckets', () => {
    expect(checkRate(undefined, 0, -1, rate).ok).toBe(false);
    expect(checkRate(undefined, 0, NaN, rate).ok).toBe(false);
    expect(checkRate(undefined, 0, Infinity, rate).ok).toBe(false);
    expect(checkRate({ windowStart: 0, frames: NaN, bytes: 0 }, 1, 1, rate).ok).toBe(false);
  });
  it('works with DEFAULT_RATE', () => {
    let b = undefined as ReturnType<typeof checkRate>['bucket'] | undefined;
    for (let i = 0; i < DEFAULT_RATE.framesPerMinute; i++) {
      const r = checkRate(b, i, 1, DEFAULT_RATE);
      expect(r.ok).toBe(true);
      b = r.bucket;
    }
    expect(checkRate(b, 100, 1, DEFAULT_RATE).ok).toBe(false);
  });
});

describe('ALLOWED_MIMES sanity', () => {
  it('every allowed mime passes proposal validation', () => {
    const p = proposal({ i2j: dg({ fileTypes: [...ALLOWED_MIMES] }) });
    expect(validateProposal(p).i2j.fileTypes).toEqual([...ALLOWED_MIMES]);
  });
});
