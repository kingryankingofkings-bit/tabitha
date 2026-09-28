import { describe, expect, it } from 'vitest';
import { PairingManager } from '../../src/background/pairing';
import { defaultProposal } from '../../src/background/permissions';
import { randomHex32, randomInt } from '../../src/shared/encoding';
import {
  CODE_RE,
  PAIRING_CODE_TTL_MS,
  PAIRING_GLOBAL_FAILS_PER_MIN,
  PAIRING_LOCKOUT_MS,
  PAIRING_MAX_FAILURES,
} from '../../src/shared/limits';
import type { GrantProposal, PairingEndpointRef, PairingSnapshot } from '../../src/shared/types';
import { FakeClock } from '../helpers/fakes';

const ref = (origin = 'https://a.test', tabId = 1, kind: PairingEndpointRef['kind'] = 'page'): PairingEndpointRef => ({
  endpointId: randomHex32(),
  kind,
  origin,
  tabId,
});

/** randomInt stub returning queued values, then falling back to real randomness. */
function seq(...values: number[]): (max: number) => number {
  return (max) => (values.length ? (values.shift() as number) : randomInt(max));
}

function setup(opts: { values?: number[]; snapshot?: PairingSnapshot } = {}) {
  const clock = new FakeClock();
  const pm = new PairingManager({ now: clock.now, randomInt: seq(...(opts.values ?? [])), snapshot: opts.snapshot });
  return { clock, pm };
}

const err = (fn: () => unknown): { code: string; message: string } | 'OK' => {
  try {
    fn();
  } catch (e) {
    return { code: (e as { code: string }).code, message: (e as Error).message };
  }
  return 'OK';
};
const code = (fn: () => unknown): string => {
  const r = err(fn);
  return r === 'OK' ? 'OK' : r.code;
};

/** A 6-digit code guaranteed to differ from every code in `active`. */
function wrong(pm: PairingManager): string {
  const active = new Set(pm.list().map((p) => p.code));
  for (let i = 0; ; i++) {
    const c = String(i).padStart(6, '0');
    if (!active.has(c)) return c;
  }
}

describe('PairingManager.start', () => {
  it('issues a 6-digit code with ttl, copying inputs', () => {
    const { clock, pm } = setup({ values: [42] });
    const a = ref();
    const p = defaultProposal();
    const rec = pm.start(a, p);
    expect(rec.code).toBe('000042');
    expect(CODE_RE.test(rec.code)).toBe(true);
    expect(rec.createdAt).toBe(clock.t);
    expect(rec.expiresAt).toBe(clock.t + PAIRING_CODE_TTL_MS);
    expect(rec.initiator).toEqual(a);
    expect(rec.proposal).toEqual(p);
    // mutating the input or the returned record does not affect state
    p.i2j.prompts = false;
    a.origin = 'https://evil.test';
    rec.proposal.j2i.tasks = false;
    const listed = pm.list()[0]!;
    expect(listed.proposal).toEqual(defaultProposal());
    expect(listed.initiator.origin).toBe('https://a.test');
  });
  it('zero-pads every value including 0 and 999999', () => {
    const { pm } = setup({ values: [0, 999_999, 7_000] });
    expect(pm.start(ref(), defaultProposal()).code).toBe('000000');
    expect(pm.start(ref(), defaultProposal()).code).toBe('999999');
    expect(pm.start(ref(), defaultProposal()).code).toBe('007000');
  });
  it('asks randomInt for 1_000_000 and redraws on collision with an active code', () => {
    const asked: number[] = [];
    const values = [5, 5, 5, 6];
    const clock = new FakeClock();
    const pm = new PairingManager({ now: clock.now, randomInt: (m) => (asked.push(m), values.shift()!) });
    expect(pm.start(ref(), defaultProposal()).code).toBe('000005');
    expect(pm.start(ref(), defaultProposal()).code).toBe('000006');
    expect(asked).toEqual([1_000_000, 1_000_000, 1_000_000, 1_000_000]);
  });
  it('fails closed on a broken random source', () => {
    for (const v of [-1, 1_000_000, 1.5, NaN]) {
      const { pm } = setup({ values: [v] });
      expect(code(() => pm.start(ref(), defaultProposal()))).toBe('INTERNAL');
    }
    const clock = new FakeClock();
    const stuck = new PairingManager({ now: clock.now, randomInt: () => 1 });
    stuck.start(ref(), defaultProposal());
    expect(code(() => stuck.start(ref(), defaultProposal()))).toBe('INTERNAL');
  });
  it('replaces the same initiator’s previous pairing', () => {
    const { pm } = setup({ values: [1, 2] });
    const a = ref();
    pm.start(a, defaultProposal());
    pm.start(a, defaultProposal());
    expect(pm.list().map((r) => r.code)).toEqual(['000002']);
    expect(code(() => pm.lookup('000001', ref('https://b.test', 2)))).toBe('PAIRING_CODE_INVALID');
  });
  it('validates the proposal and initiator (defense in depth)', () => {
    const { pm } = setup();
    const bad = { ...defaultProposal(), ttlMs: 5 } as GrantProposal;
    expect(code(() => pm.start(ref(), bad))).toBe('INVALID_MESSAGE');
    expect(code(() => pm.start({ ...ref(), endpointId: 'nope' }, defaultProposal()))).toBe('INVALID_MESSAGE');
    expect(pm.list()).toEqual([]);
  });
});

describe('lookup / approve', () => {
  it('lookup returns a preview with the joiner’s origin/kind and deep-copied proposal', () => {
    const { pm } = setup();
    const a = ref('https://a.test', 1);
    const rec = pm.start(a, defaultProposal());
    const b = ref('https://b.test', 2, 'panel');
    const prev = pm.lookup(rec.code, b);
    expect(prev).toEqual({
      code: rec.code,
      initiator: { origin: 'https://a.test', kind: 'page' },
      joiner: { origin: 'https://b.test', kind: 'panel' },
      proposal: defaultProposal(),
      expiresAt: rec.expiresAt,
    });
    prev.proposal.i2j.files = true;
    prev.proposal.i2j.fileTypes.push('application/pdf');
    expect(pm.lookup(rec.code, b).proposal).toEqual(defaultProposal());
  });
  it('lookup is repeatable and does not consume', () => {
    const { pm } = setup();
    const rec = pm.start(ref(), defaultProposal());
    const b = ref('https://b.test', 2);
    pm.lookup(rec.code, b);
    pm.lookup(rec.code, b);
    expect(pm.list()).toHaveLength(1);
  });
  it('approve returns both refs and the proposal, and is single-use', () => {
    const { pm } = setup();
    const a = ref();
    const rec = pm.start(a, defaultProposal());
    const b = ref('https://b.test', 2);
    const r = pm.approve(rec.code, b);
    expect(r).toEqual({ initiator: a, joiner: b, proposal: defaultProposal() });
    expect(pm.list()).toEqual([]);
    expect(code(() => pm.approve(rec.code, b))).toBe('PAIRING_CODE_INVALID');
    expect(code(() => pm.lookup(rec.code, b))).toBe('PAIRING_CODE_INVALID');
  });
  it('approve returns copies', () => {
    const { pm } = setup();
    const b = ref('https://b.test', 2);
    const r = pm.approve(pm.start(ref(), defaultProposal()).code, b);
    r.joiner.origin = 'x';
    expect(b.origin).toBe('https://b.test');
  });
  it('self-pairing is rejected and not counted as a failure', () => {
    const { pm } = setup();
    const a = ref();
    const rec = pm.start(a, defaultProposal());
    for (let i = 0; i < PAIRING_MAX_FAILURES + 2; i++) {
      expect(code(() => pm.lookup(rec.code, { ...a, tabId: 99 }))).toBe('PAIRING_SELF');
      expect(code(() => pm.approve(rec.code, a))).toBe('PAIRING_SELF');
    }
    expect(pm.snapshot().failures).toEqual([]);
    expect(pm.list()).toHaveLength(1);
    expect(code(() => pm.approve(rec.code, ref('https://b.test', 2)))).toBe('OK');
  });
  it('same origin, different endpoint is allowed', () => {
    const { pm } = setup();
    const rec = pm.start(ref('https://a.test', 1), defaultProposal());
    expect(code(() => pm.approve(rec.code, ref('https://a.test', 2)))).toBe('OK');
  });
  it('expired pairing → PAIRING_EXPIRED, removed, not counted', () => {
    const { clock, pm } = setup();
    const rec = pm.start(ref(), defaultProposal());
    clock.advance(PAIRING_CODE_TTL_MS - 1);
    expect(code(() => pm.lookup(rec.code, ref('https://b.test', 2)))).toBe('OK');
    clock.advance(1);
    expect(code(() => pm.approve(rec.code, ref('https://b.test', 2)))).toBe('PAIRING_EXPIRED');
    expect(pm.snapshot().pairings).toEqual([]);
    expect(pm.snapshot().failures).toEqual([]);
    // second attempt: now simply unknown → counted
    expect(code(() => pm.approve(rec.code, ref('https://b.test', 2)))).toBe('PAIRING_CODE_INVALID');
  });
  it('malformed codes count as failures', () => {
    const { pm } = setup();
    const rec = pm.start(ref(), defaultProposal());
    const b = ref('https://b.test', 2);
    for (const c of [' ' + rec.code, rec.code + '\n', '12345', '1234567', 'abcdef', '１２３４５６', '', rec.code.slice(0, 5) + 'x']) {
      expect(code(() => pm.lookup(c, b))).toBe('PAIRING_CODE_INVALID');
    }
    expect(code(() => pm.lookup(123456 as never, b))).toBe('PAIRING_CODE_INVALID');
    expect(code(() => pm.lookup('__proto__', b))).toBe('PAIRING_CODE_INVALID');
    expect(code(() => pm.lookup('constructor', b))).toBe('PAIRING_CODE_INVALID');
  });
  it('rejects a malformed joiner ref without counting', () => {
    const { pm } = setup();
    const rec = pm.start(ref(), defaultProposal());
    expect(code(() => pm.lookup(rec.code, { endpointId: 'x' } as never))).toBe('INVALID_MESSAGE');
    expect(code(() => pm.lookup(rec.code, null as never))).toBe('INVALID_MESSAGE');
    expect(pm.snapshot().failuresSinceReset).toBe(0);
  });
  it('never includes the code in error messages', () => {
    const { clock, pm } = setup({ values: [123_456] });
    const a = ref();
    pm.start(a, defaultProposal());
    const b = ref('https://b.test', 2);
    const msgs: string[] = [];
    const collect = (fn: () => unknown) => {
      const r = err(fn);
      if (r !== 'OK') msgs.push(r.message);
    };
    collect(() => pm.lookup('123456', a)); // self
    collect(() => pm.lookup('123457', b)); // wrong
    clock.advance(PAIRING_CODE_TTL_MS);
    pm.start(a, defaultProposal());
    const live = pm.list()[0]!.code;
    clock.advance(PAIRING_CODE_TTL_MS);
    collect(() => pm.lookup(live, b)); // expired
    expect(msgs).toHaveLength(3);
    for (const m of msgs) {
      expect(m).not.toMatch(/\d{6}/);
      expect(m).not.toContain(live);
    }
  });
});

describe('brute-force protection', () => {
  it(`${PAIRING_MAX_FAILURES} wrong codes invalidate ALL active codes and reset the counter`, () => {
    const { pm } = setup();
    const r1 = pm.start(ref('https://a.test', 1), defaultProposal());
    const r2 = pm.start(ref('https://c.test', 3), defaultProposal());
    const b = ref('https://b.test', 2);
    for (let i = 0; i < PAIRING_MAX_FAILURES - 1; i++) expect(code(() => pm.lookup(wrong(pm), b))).toBe('PAIRING_CODE_INVALID');
    expect(pm.list()).toHaveLength(2);
    expect(pm.snapshot().failuresSinceReset).toBe(PAIRING_MAX_FAILURES - 1);
    expect(code(() => pm.lookup(wrong(pm), b))).toBe('PAIRING_CODE_INVALID');
    expect(pm.list()).toEqual([]);
    expect(pm.snapshot().failuresSinceReset).toBe(0);
    // the previously valid codes are now dead
    expect(code(() => pm.approve(r1.code, b))).toBe('PAIRING_CODE_INVALID');
    expect(code(() => pm.approve(r2.code, b))).toBe('PAIRING_CODE_INVALID');
  });
  it('approve and lookup share the failure counter', () => {
    const { pm } = setup();
    const r = pm.start(ref(), defaultProposal());
    const b = ref('https://b.test', 2);
    pm.lookup(r.code, b);
    expect(code(() => pm.lookup(wrong(pm), b))).toBe('PAIRING_CODE_INVALID');
    expect(code(() => pm.approve(wrong(pm), b))).toBe('PAIRING_CODE_INVALID');
    expect(code(() => pm.approve(wrong(pm), b))).toBe('PAIRING_CODE_INVALID');
    expect(code(() => pm.approve(r.code, b))).toBe('PAIRING_CODE_INVALID');
  });
  it('start resets failuresSinceReset', () => {
    const { pm } = setup();
    const b = ref('https://b.test', 2);
    pm.start(ref('https://a.test', 1), defaultProposal());
    code(() => pm.lookup(wrong(pm), b));
    code(() => pm.lookup(wrong(pm), b));
    expect(pm.snapshot().failuresSinceReset).toBe(2);
    const r = pm.start(ref('https://c.test', 3), defaultProposal());
    expect(pm.snapshot().failuresSinceReset).toBe(0);
    code(() => pm.lookup(wrong(pm), b));
    expect(pm.list()).toHaveLength(2);
    expect(code(() => pm.approve(r.code, b))).toBe('OK');
  });
  it(`> ${PAIRING_GLOBAL_FAILS_PER_MIN} failures within 60 s locks for ${PAIRING_LOCKOUT_MS} ms`, () => {
    const { clock, pm } = setup();
    const b = ref('https://b.test', 2);
    for (let i = 0; i < PAIRING_GLOBAL_FAILS_PER_MIN; i++) {
      expect(code(() => pm.lookup('000000', b))).toBe('PAIRING_CODE_INVALID');
      clock.advance(1000);
    }
    expect(pm.lockedUntil()).toBe(0);
    expect(code(() => pm.lookup('000000', b))).toBe('PAIRING_CODE_INVALID'); // 11th
    const lockedAt = clock.t;
    expect(pm.lockedUntil()).toBe(lockedAt + PAIRING_LOCKOUT_MS);
    // start still works (UI-only), but lookup/approve are locked — even with the right code
    const r = pm.start(ref(), defaultProposal());
    expect(code(() => pm.lookup(r.code, b))).toBe('PAIRING_LOCKED');
    expect(code(() => pm.approve(r.code, b))).toBe('PAIRING_LOCKED');
    // locked attempts are not counted
    const before = pm.snapshot().failures.length;
    for (let i = 0; i < 20; i++) code(() => pm.lookup('000001', b));
    expect(pm.snapshot().failures.length).toBe(before);
    expect(pm.lockedUntil()).toBe(lockedAt + PAIRING_LOCKOUT_MS);
    // lock expires
    clock.t = lockedAt + PAIRING_LOCKOUT_MS - 1;
    expect(code(() => pm.lookup(r.code, b))).toBe('PAIRING_LOCKED');
    clock.t = lockedAt + PAIRING_LOCKOUT_MS;
    const r2 = pm.start(ref(), defaultProposal());
    expect(code(() => pm.approve(r2.code, b))).toBe('OK');
  });
  it('failures older than 60 s do not count toward the lockout', () => {
    const { clock, pm } = setup();
    const b = ref('https://b.test', 2);
    for (let i = 0; i < PAIRING_GLOBAL_FAILS_PER_MIN; i++) code(() => pm.lookup('000000', b));
    clock.advance(60_000);
    for (let i = 0; i < PAIRING_GLOBAL_FAILS_PER_MIN; i++) code(() => pm.lookup('000000', b));
    expect(pm.lockedUntil()).toBe(0);
    expect(pm.snapshot().failures).toHaveLength(PAIRING_GLOBAL_FAILS_PER_MIN);
    code(() => pm.lookup('000000', b));
    expect(pm.lockedUntil()).toBe(clock.t + PAIRING_LOCKOUT_MS);
  });
  it('a brute-force sweep of codes never hits a live code', () => {
    const { pm } = setup({ values: [500_000] });
    const target = pm.start(ref(), defaultProposal());
    const b = ref('https://b.test', 2);
    let hits = 0;
    for (let i = 499_990; i < 500_010; i++) {
      const c = String(i).padStart(6, '0');
      const r = code(() => pm.approve(c, b));
      if (r === 'OK') hits++;
    }
    expect(hits).toBe(0);
    expect(code(() => pm.approve(target.code, b))).not.toBe('OK');
  });
});

describe('cancel / sweep / list', () => {
  it('cancel removes by code without counting', () => {
    const { pm } = setup();
    const r = pm.start(ref(), defaultProposal());
    expect(pm.cancel('999999' === r.code ? '999998' : '999999')).toBe(false);
    expect(pm.cancel(r.code)).toBe(true);
    expect(pm.cancel(r.code)).toBe(false);
    expect(pm.cancel(undefined as never)).toBe(false);
    expect(pm.snapshot().failuresSinceReset).toBe(0);
  });
  it('cancelForEndpoint removes only that initiator', () => {
    const { pm } = setup();
    const a = ref('https://a.test', 1);
    const c = ref('https://c.test', 3);
    pm.start(a, defaultProposal());
    pm.start(c, defaultProposal());
    pm.cancelForEndpoint(a.endpointId);
    expect(pm.list().map((r) => r.initiator.endpointId)).toEqual([c.endpointId]);
    pm.cancelForEndpoint(randomHex32());
    expect(pm.list()).toHaveLength(1);
  });
  it('sweep removes and returns expired only; list hides expired', () => {
    const { clock, pm } = setup();
    pm.start(ref('https://a.test', 1), defaultProposal());
    clock.advance(60_000);
    const fresh = pm.start(ref('https://c.test', 3), defaultProposal());
    clock.advance(PAIRING_CODE_TTL_MS - 60_000);
    expect(pm.list().map((r) => r.code)).toEqual([fresh.code]);
    const swept = pm.sweep();
    expect(swept).toHaveLength(1);
    expect(swept[0]!.initiator.origin).toBe('https://a.test');
    expect(pm.snapshot().pairings.map((r) => r.code)).toEqual([fresh.code]);
    expect(pm.sweep()).toEqual([]);
  });
  it('list returns copies', () => {
    const { pm } = setup();
    pm.start(ref(), defaultProposal());
    const l = pm.list();
    l[0]!.proposal.i2j.prompts = false;
    l[0]!.expiresAt = Number.MAX_SAFE_INTEGER;
    expect(pm.list()[0]!.proposal.i2j.prompts).toBe(true);
    expect(pm.list()[0]!.expiresAt).not.toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe('snapshot / restore', () => {
  it('round-trips through JSON', () => {
    const { clock, pm } = setup();
    const a = ref();
    const r = pm.start(a, defaultProposal());
    const b = ref('https://b.test', 2);
    code(() => pm.lookup(wrong(pm), b));
    const snap = JSON.parse(JSON.stringify(pm.snapshot())) as PairingSnapshot;
    expect(snap.pairings).toHaveLength(1);
    expect(snap.failures).toEqual([clock.t]);
    expect(snap.failuresSinceReset).toBe(1);
    const pm2 = new PairingManager({ now: clock.now, randomInt: (m) => randomInt(m), snapshot: snap });
    expect(pm2.snapshot()).toEqual(pm.snapshot());
    // counter continues across restore
    code(() => pm2.lookup(wrong(pm2), b));
    code(() => pm2.lookup(wrong(pm2), b));
    expect(code(() => pm2.approve(r.code, b))).toBe('PAIRING_CODE_INVALID');
  });
  it('restores the lock', () => {
    const clock = new FakeClock();
    const pm = new PairingManager({
      now: clock.now,
      randomInt: (m) => randomInt(m),
      snapshot: { pairings: [], failures: [], failuresSinceReset: 0, lockedUntil: clock.t + 1000 },
    });
    expect(code(() => pm.lookup('123456', ref()))).toBe('PAIRING_LOCKED');
    expect(pm.lockedUntil()).toBe(clock.t + 1000);
  });
  it('snapshot is a deep copy', () => {
    const { pm } = setup();
    pm.start(ref(), defaultProposal());
    const s = pm.snapshot();
    s.pairings[0]!.proposal.i2j.fileTypes.push('image/png');
    s.pairings.length = 0;
    s.failures.push(1);
    expect(pm.snapshot().pairings).toHaveLength(1);
    expect(pm.snapshot().pairings[0]!.proposal.i2j.fileTypes).toEqual([]);
    expect(pm.snapshot().failures).toEqual([]);
  });
  it('drops malformed records and fields', () => {
    const clock = new FakeClock();
    const good = {
      code: '123456',
      initiator: { endpointId: randomHex32(), kind: 'page', origin: 'https://a.test', tabId: 1 },
      proposal: defaultProposal(),
      createdAt: clock.t,
      expiresAt: clock.t + PAIRING_CODE_TTL_MS,
    };
    const snap = {
      pairings: [
        good,
        { ...good, code: '123456', initiator: { ...good.initiator, endpointId: randomHex32() } }, // duplicate code
        { ...good, code: '222222' }, // duplicate initiator
        { ...good, code: '12345' },
        { ...good, code: '333333', initiator: { ...good.initiator, endpointId: 'x' } },
        { ...good, code: '444444', initiator: { ...good.initiator, endpointId: randomHex32(), kind: 'robot' } },
        { ...good, code: '555555', initiator: { ...good.initiator, endpointId: randomHex32() }, proposal: { ...defaultProposal(), ttlMs: 7 } },
        { ...good, code: '666666', initiator: { ...good.initiator, endpointId: randomHex32() }, expiresAt: clock.t + 10 * PAIRING_CODE_TTL_MS },
        { ...good, code: '777777', initiator: { ...good.initiator, endpointId: randomHex32() }, createdAt: 'x' },
        null,
        'junk',
      ],
      failures: [1, 'x', NaN, 2],
      failuresSinceReset: -5,
      lockedUntil: 'never',
    } as unknown as PairingSnapshot;
    const pm = new PairingManager({ now: clock.now, randomInt: (m) => randomInt(m), snapshot: snap });
    const s = pm.snapshot();
    expect(s.pairings.map((p) => p.code)).toEqual(['123456']);
    expect(s.failures).toEqual([1, 2]);
    expect(s.failuresSinceReset).toBe(0);
    expect(s.lockedUntil).toBe(0);
    for (const bad of [null, 'x', [], { pairings: 'x' }]) {
      const p = new PairingManager({ now: clock.now, randomInt: (m) => randomInt(m), snapshot: bad as never });
      expect(p.snapshot()).toEqual({ pairings: [], failures: [], failuresSinceReset: 0, lockedUntil: 0 });
    }
  });
});
