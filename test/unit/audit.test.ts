import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuditLog, GENESIS_HASH, hashEntry, verifyChain } from '../../src/background/audit';
import { sha256Hex } from '../../src/shared/crypto';
import { canonicalJson, randomHex32, utf8Encode, utf8Length } from '../../src/shared/encoding';
import { AUDIT_DEFAULT_MAX_ENTRIES, AUDIT_FLUSH_MS, AUDIT_MAX_MAX_ENTRIES, AUDIT_MIN_MAX_ENTRIES, MAX_TEXT_BYTES } from '../../src/shared/limits';
import type { AuditActor, AuditEntry, AuditPersisted, AuditStore } from '../../src/shared/types';
import { FakeClock, MemoryAuditStore } from '../helpers/fakes';

const router: AuditActor = { kind: 'router' };
const ui: AuditActor = { kind: 'ui' };

function mk(opts: { maxEntries?: number; flushDelayMs?: number; store?: AuditStore; clock?: FakeClock } = {}) {
  const clock = opts.clock ?? new FakeClock();
  const store = (opts.store ?? new MemoryAuditStore()) as MemoryAuditStore;
  const log = new AuditLog({ store, now: clock.now, maxEntries: opts.maxEntries, flushDelayMs: opts.flushDelayMs ?? 1_000_000 });
  return { clock, store, log };
}

async function fill(log: AuditLog, n: number, clock?: FakeClock): Promise<AuditEntry[]> {
  const out: AuditEntry[] = [];
  for (let i = 0; i < n; i++) {
    out.push(await log.append({ type: 'frame.routed', roomId: i % 2 ? 'a'.repeat(32) : 'b'.repeat(32), actor: router, data: { i } }));
    clock?.advance(1);
  }
  return out;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('hashEntry', () => {
  it('matches the spec formula', async () => {
    const e: Omit<AuditEntry, 'hash'> = { seq: 1, ts: 5, type: 'site.enabled', actor: ui, data: { origin: 'https://a.test' }, prevHash: GENESIS_HASH };
    const expected = await sha256Hex(utf8Encode(GENESIS_HASH + '\n' + canonicalJson(e)));
    expect(await hashEntry(GENESIS_HASH, e)).toBe(expected);
    expect(GENESIS_HASH).toBe('0'.repeat(64));
  });
  it('ignores a stray hash field and is key-order independent', async () => {
    const e = { seq: 1, ts: 5, type: 'site.enabled' as const, actor: ui, data: { a: 1, b: 2 }, prevHash: GENESIS_HASH };
    const h = await hashEntry(GENESIS_HASH, e);
    expect(await hashEntry(GENESIS_HASH, { ...e, hash: 'f'.repeat(64) } as AuditEntry)).toBe(h);
    expect(await hashEntry(GENESIS_HASH, { data: { b: 2, a: 1 }, prevHash: GENESIS_HASH, actor: ui, type: 'site.enabled', ts: 5, seq: 1 })).toBe(h);
    expect(await hashEntry('1'.repeat(64), e)).not.toBe(h);
  });
});

describe('append + verify', () => {
  it('builds a valid chain with monotonic seq starting at 1', async () => {
    const { log, clock } = mk();
    const entries = await fill(log, 5, clock);
    expect(entries.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(entries[0]!.prevHash).toBe(GENESIS_HASH);
    for (let i = 1; i < 5; i++) expect(entries[i]!.prevHash).toBe(entries[i - 1]!.hash);
    expect(entries[2]!.ts).toBe(clock.t - 3);
    expect(await log.verify()).toEqual({ ok: true, count: 5 });
    expect(await verifyChain(GENESIS_HASH, log.export().entries)).toEqual({ ok: true, count: 5 });
  });
  it('empty log verifies', async () => {
    const { log } = mk();
    expect(await log.verify()).toEqual({ ok: true, count: 0 });
    expect(await verifyChain(GENESIS_HASH, [])).toEqual({ ok: true, count: 0 });
  });
  it('concurrent appends form a valid chain in call order', async () => {
    const { log } = mk();
    const ps = Array.from({ length: 50 }, (_, i) => log.append({ type: 'frame.routed', actor: router, data: { i } }));
    const res = await Promise.all(ps);
    expect(res.map((e) => e.seq)).toEqual(Array.from({ length: 50 }, (_, i) => i + 1));
    expect(res.map((e) => e.data.i)).toEqual(Array.from({ length: 50 }, (_, i) => i));
    expect(await log.verify()).toEqual({ ok: true, count: 50 });
  });
  it('omits roomId when absent and keeps it when present', async () => {
    const { log } = mk();
    const a = await log.append({ type: 'pause.changed', actor: ui, data: { paused: true } });
    const b = await log.append({ type: 'room.closed', roomId: 'c'.repeat(32), actor: router, data: {} });
    expect('roomId' in a).toBe(false);
    expect(b.roomId).toBe('c'.repeat(32));
  });
  it('snapshots input at call time; returned entries are copies', async () => {
    const { log } = mk();
    const data: Record<string, unknown> = { n: 1, nested: { x: 1 } };
    const p = log.append({ type: 'violation', actor: router, data });
    data.n = 2;
    (data.nested as { x: number }).x = 2;
    const e = await p;
    expect(e.data).toEqual({ n: 1, nested: { x: 1 } });
    e.data.n = 99;
    e.actor.kind = 'ui';
    expect(log.list()[0]!.data.n).toBe(1);
    expect(log.list()[0]!.actor.kind).toBe('router');
    expect(await log.verify()).toEqual({ ok: true, count: 1 });
  });
  it('rejects invalid type/actor without breaking the chain', async () => {
    const { log } = mk();
    await log.append({ type: 'site.enabled', actor: ui, data: {} });
    await expect(log.append({ type: 'bogus' as never, actor: ui, data: {} })).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    await expect(log.append({ type: 'site.enabled', actor: { kind: 'god' } as never, data: {} })).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    const e = await log.append({ type: 'site.disabled', actor: { kind: 'endpoint', endpointId: 'e'.repeat(32), extra: 1 } as never, data: {} });
    expect(e.seq).toBe(2);
    expect(e.actor).toEqual({ kind: 'endpoint', endpointId: 'e'.repeat(32) });
    expect(await log.verify()).toEqual({ ok: true, count: 2 });
  });
  it('sanitizes non-JSON data so appends never fail', async () => {
    const { log } = mk();
    const cyc: Record<string, unknown> = { a: 1 };
    cyc.self = cyc;
    const e = await log.append({
      type: 'violation',
      actor: router,
      data: { inf: Infinity, nan: NaN, u: undefined, f: () => 1, big: BigInt(1) as unknown, date: new Date(0), cyc, arr: [1, undefined] },
    });
    expect(e.data).toEqual({ inf: null, nan: null, date: null, cyc: { a: 1, self: '[circular]' }, arr: [1, null] });
    expect(await log.verify()).toEqual({ ok: true, count: 1 });
  });
  it('treats a __proto__ key in data as plain data', async () => {
    const { log } = mk();
    const e = await log.append({ type: 'violation', actor: router, data: JSON.parse('{"__proto__":{"polluted":true}}') });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.keys(e.data)).toEqual(['__proto__']);
    expect(await log.verify()).toEqual({ ok: true, count: 1 });
  });
});

describe('truncation', () => {
  it('truncates long strings anywhere in data and marks data.truncated', async () => {
    const { log } = mk();
    const long = 'x'.repeat(MAX_TEXT_BYTES + 10);
    const e = await log.append({ type: 'content.sent', actor: router, data: { text: long, deep: { list: ['ok', long] }, short: 'hi' } });
    const text = e.data.text as string;
    expect(text.endsWith('…[truncated]')).toBe(true);
    expect(utf8Length(text)).toBeLessThanOrEqual(MAX_TEXT_BYTES);
    expect(((e.data.deep as { list: string[] }).list[1] as string).endsWith('…[truncated]')).toBe(true);
    expect((e.data.deep as { list: string[] }).list[0]).toBe('ok');
    expect(e.data.short).toBe('hi');
    expect(e.data.truncated).toBe(true);
    expect(await log.verify()).toEqual({ ok: true, count: 1 });
  });
  it('does not truncate at exactly the limit', async () => {
    const { log } = mk();
    const exact = 'y'.repeat(MAX_TEXT_BYTES);
    const e = await log.append({ type: 'content.sent', actor: router, data: { text: exact } });
    expect(e.data.text).toBe(exact);
    expect('truncated' in e.data).toBe(false);
  });
  it('measures UTF-8 bytes and never splits a code point', async () => {
    const { log } = mk();
    const s = '😀'.repeat(MAX_TEXT_BYTES / 4 + 1); // 4 bytes each, just over the limit
    expect(s.length).toBeLessThan(MAX_TEXT_BYTES);
    const e = await log.append({ type: 'content.received', actor: router, data: { text: s } });
    const t = e.data.text as string;
    expect(utf8Length(t)).toBeLessThanOrEqual(MAX_TEXT_BYTES);
    expect(t).not.toContain('�');
    expect(t.replace('…[truncated]', '')).toMatch(/^(😀)+$/u);
  });
});

describe('tamper detection', () => {
  async function chain(n = 6): Promise<{ anchor: string; entries: AuditEntry[] }> {
    const { log, clock } = mk();
    await fill(log, n, clock);
    const x = log.export();
    return { anchor: x.anchor, entries: x.entries };
  }
  const mutators: [string, (e: AuditEntry) => void][] = [
    ['data', (e) => void (e.data.i = 999)],
    ['data (added key)', (e) => void (e.data.extra = true)],
    ['ts', (e) => void (e.ts += 1)],
    ['type', (e) => void (e.type = 'site.enabled')],
    ['seq', (e) => void (e.seq += 10)],
    ['prevHash', (e) => void (e.prevHash = 'f'.repeat(64))],
    ['hash', (e) => void (e.hash = 'f'.repeat(64))],
    ['actor', (e) => void (e.actor = { kind: 'ui' })],
    ['roomId', (e) => void (e.roomId = 'd'.repeat(32))],
    ['roomId removed', (e) => void delete e.roomId],
  ];
  for (const [field, mutate] of mutators) {
    for (const idx of [0, 3, 5]) {
      it(`detects tampering of ${field} at index ${idx}`, async () => {
        const { anchor, entries } = await chain();
        mutate(entries[idx]!);
        const r = await verifyChain(anchor, entries);
        expect(r.ok).toBe(false);
        if (!r.ok) {
          const expectedSeq = field === 'seq' && idx === 0 ? 11 : idx + 1;
          expect(r.brokenAtSeq).toBe(expectedSeq);
          expect(typeof r.reason).toBe('string');
        }
      });
    }
  }
  it('detects a recomputed-hash edit at the following entry', async () => {
    const { anchor, entries } = await chain();
    const e = entries[2]!;
    e.data.i = 12345;
    const { hash: _h, ...rest } = e;
    e.hash = await hashEntry(e.prevHash, rest);
    const r = await verifyChain(anchor, entries);
    expect(r).toMatchObject({ ok: false, brokenAtSeq: 4 });
  });
  it('detects deletion, reordering and insertion', async () => {
    const base = await chain();
    const del = structuredClone(base.entries);
    del.splice(2, 1);
    expect(await verifyChain(base.anchor, del)).toMatchObject({ ok: false, brokenAtSeq: 3 });
    const swap = structuredClone(base.entries);
    [swap[2], swap[3]] = [swap[3]!, swap[2]!];
    expect(await verifyChain(base.anchor, swap)).toMatchObject({ ok: false, brokenAtSeq: 3 });
    const dup = structuredClone(base.entries);
    dup.splice(3, 0, structuredClone(dup[2]!));
    expect(await verifyChain(base.anchor, dup)).toMatchObject({ ok: false, brokenAtSeq: 4 });
  });
  it('detects a wrong anchor', async () => {
    const { entries } = await chain();
    expect(await verifyChain('1'.repeat(64), entries)).toMatchObject({ ok: false, brokenAtSeq: 1 });
  });
  it('reports malformed entries', async () => {
    const { anchor, entries } = await chain(3);
    const bad = [...entries];
    (bad as unknown[])[1] = null;
    expect(await verifyChain(anchor, bad)).toMatchObject({ ok: false, brokenAtSeq: 2 });
    expect(await verifyChain(anchor, 'x' as never)).toMatchObject({ ok: false });
  });
  it('AuditLog.verify reports a store-level tamper after init', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store });
    await fill(a.log, 5, a.clock);
    await a.log.flush();
    store.saved!.entries[2]!.data.i = 'forged';
    const b = mk({ store });
    await b.log.init();
    expect(await b.log.verify()).toMatchObject({ ok: false, brokenAtSeq: 3 });
    // kept as-is, never repaired
    expect(b.log.export()).toEqual(store.saved);
  });
});

describe('retention', () => {
  it('clamps maxEntries', () => {
    expect(mk({ maxEntries: 1 }).log.getMaxEntries()).toBe(AUDIT_MIN_MAX_ENTRIES);
    expect(mk({ maxEntries: 10 ** 9 }).log.getMaxEntries()).toBe(AUDIT_MAX_MAX_ENTRIES);
    expect(mk({}).log.getMaxEntries()).toBe(AUDIT_DEFAULT_MAX_ENTRIES);
    expect(mk({ maxEntries: NaN }).log.getMaxEntries()).toBe(AUDIT_DEFAULT_MAX_ENTRIES);
    const { log } = mk();
    log.setMaxEntries(5);
    expect(log.getMaxEntries()).toBe(AUDIT_MIN_MAX_ENTRIES);
    log.setMaxEntries(250.7);
    expect(log.getMaxEntries()).toBe(250);
  });
  it('drops oldest and anchors the retained suffix', async () => {
    const { log } = mk({ maxEntries: AUDIT_MIN_MAX_ENTRIES });
    const all = await fill(log, AUDIT_MIN_MAX_ENTRIES + 7);
    const x = log.export();
    expect(x.entries).toHaveLength(AUDIT_MIN_MAX_ENTRIES);
    expect(x.entries[0]!.seq).toBe(8);
    expect(x.anchor).toBe(all[6]!.hash);
    expect(x.nextSeq).toBe(AUDIT_MIN_MAX_ENTRIES + 8);
    expect(await log.verify()).toEqual({ ok: true, count: AUDIT_MIN_MAX_ENTRIES });
    expect(await verifyChain(x.anchor, x.entries)).toEqual({ ok: true, count: AUDIT_MIN_MAX_ENTRIES });
    // the suffix does NOT verify from genesis
    expect((await verifyChain(GENESIS_HASH, x.entries)).ok).toBe(false);
  });
  it('setMaxEntries applies retention immediately', async () => {
    const { log } = mk({ maxEntries: 300 });
    const all = await fill(log, 250);
    log.setMaxEntries(120);
    const x = log.export();
    expect(x.entries).toHaveLength(120);
    expect(x.entries[0]!.seq).toBe(131);
    expect(x.anchor).toBe(all[129]!.hash);
    expect(await log.verify()).toEqual({ ok: true, count: 120 });
  });
});

describe('list', () => {
  it('newest first with default limit 200 and max 1000', async () => {
    const { log } = mk({ maxEntries: 2000 });
    await fill(log, 1100);
    const d = log.list();
    expect(d).toHaveLength(200);
    expect(d[0]!.seq).toBe(1100);
    expect(d[199]!.seq).toBe(901);
    expect(log.list({ limit: 5000 })).toHaveLength(1000);
    expect(log.list({ limit: 3 }).map((e) => e.seq)).toEqual([1100, 1099, 1098]);
    expect(log.list({ limit: 0 })).toEqual([]);
    expect(log.list({ limit: -4 })).toEqual([]);
    expect(log.list({ limit: NaN })).toHaveLength(200);
  });
  it('filters by beforeSeq, roomId and types', async () => {
    const { log } = mk();
    await fill(log, 10);
    await log.append({ type: 'room.closed', roomId: 'a'.repeat(32), actor: router, data: {} });
    expect(log.list({ beforeSeq: 4 }).map((e) => e.seq)).toEqual([3, 2, 1]);
    expect(log.list({ roomId: 'a'.repeat(32) }).map((e) => e.seq)).toEqual([11, 10, 8, 6, 4, 2]);
    expect(log.list({ types: ['room.closed'] }).map((e) => e.seq)).toEqual([11]);
    expect(log.list({ types: ['room.closed', 'frame.routed'], beforeSeq: 11, roomId: 'b'.repeat(32), limit: 2 }).map((e) => e.seq)).toEqual([9, 7]);
    expect(log.list({ types: [] })).toEqual([]);
  });
  it('returns copies', async () => {
    const { log } = mk();
    await fill(log, 2);
    const l = log.list();
    l[0]!.data.i = 'x';
    l[0]!.hash = 'x';
    expect(await log.verify()).toEqual({ ok: true, count: 2 });
  });
});

describe('clear', () => {
  it('empties the log and starts a new chain with log.cleared', async () => {
    const { log } = mk();
    await fill(log, 7);
    const r = await log.clear(ui);
    expect(r).toEqual({ cleared: 7 });
    const x = log.export();
    expect(x.anchor).toBe(GENESIS_HASH);
    expect(x.entries).toHaveLength(1);
    expect(x.entries[0]).toMatchObject({ seq: 8, type: 'log.cleared', actor: ui, data: { cleared: 7 }, prevHash: GENESIS_HASH });
    expect(x.nextSeq).toBe(9);
    expect(await log.verify()).toEqual({ ok: true, count: 1 });
    const e = await log.append({ type: 'site.enabled', actor: ui, data: {} });
    expect(e.seq).toBe(9);
    expect(await log.verify()).toEqual({ ok: true, count: 2 });
  });
  it('is serialized with in-flight appends', async () => {
    const { log } = mk();
    const a = log.append({ type: 'site.enabled', actor: ui, data: {} });
    const b = log.append({ type: 'site.enabled', actor: ui, data: {} });
    const c = log.clear(ui);
    const d = log.append({ type: 'site.disabled', actor: ui, data: {} });
    await Promise.all([a, b, d]);
    expect(await c).toEqual({ cleared: 2 });
    expect(log.export().entries.map((e) => e.type)).toEqual(['log.cleared', 'site.disabled']);
    expect(await log.verify()).toEqual({ ok: true, count: 2 });
  });
  it('clears a sticky tamper failure loaded from the store', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store });
    await fill(a.log, 3);
    await a.log.flush();
    store.saved!.entries[0]!.ts = 1;
    const b = mk({ store });
    await b.log.init();
    expect((await b.log.verify()).ok).toBe(false);
    expect(await b.log.clear(ui)).toEqual({ cleared: 3 });
    expect(await b.log.verify()).toEqual({ ok: true, count: 1 });
  });
});

describe('export', () => {
  it('is a deep copy', async () => {
    const { log } = mk();
    await fill(log, 2);
    const x = log.export();
    expect(x.v).toBe(1);
    expect(x.nextSeq).toBe(3);
    x.entries[0]!.data.i = 'x';
    x.entries.pop();
    x.anchor = 'x';
    expect(log.export().entries).toHaveLength(2);
    expect(await log.verify()).toEqual({ ok: true, count: 2 });
  });
});

describe('persistence', () => {
  it('debounces saves by flushDelayMs (batched, throttled)', async () => {
    vi.useFakeTimers();
    const store = new MemoryAuditStore();
    const clock = new FakeClock();
    const log = new AuditLog({ store, now: clock.now });
    await log.append({ type: 'site.enabled', actor: ui, data: {} });
    await log.append({ type: 'site.enabled', actor: ui, data: {} });
    expect(store.saves).toBe(0);
    await vi.advanceTimersByTimeAsync(AUDIT_FLUSH_MS - 1);
    expect(store.saves).toBe(0);
    await log.append({ type: 'site.enabled', actor: ui, data: {} });
    await vi.advanceTimersByTimeAsync(1);
    expect(store.saves).toBe(1);
    expect(store.saved!.entries).toHaveLength(3);
    expect(store.saved!.nextSeq).toBe(4);
    await vi.advanceTimersByTimeAsync(AUDIT_FLUSH_MS * 4);
    expect(store.saves).toBe(1); // nothing new → no extra save
  });
  it('a steady stream of appends cannot postpone saving indefinitely', async () => {
    vi.useFakeTimers();
    const store = new MemoryAuditStore();
    const log = new AuditLog({ store, now: () => 1, flushDelayMs: 100 });
    for (let i = 0; i < 10; i++) {
      await log.append({ type: 'frame.routed', actor: router, data: { i } });
      await vi.advanceTimersByTimeAsync(30);
    }
    expect(store.saves).toBeGreaterThanOrEqual(2);
  });
  it('flush forces a save including queued appends', async () => {
    const { log, store } = mk();
    const p = log.append({ type: 'site.enabled', actor: ui, data: {} });
    await log.flush();
    await p;
    expect(store.saves).toBe(1);
    expect(store.saved!.entries).toHaveLength(1);
    expect(store.saved).toEqual(log.export());
  });
  it('flush propagates store errors and retries later', async () => {
    let fail = true;
    const inner = new MemoryAuditStore();
    const store: AuditStore = {
      load: () => inner.load(),
      save: async (p) => {
        if (fail) throw new Error('quota');
        await inner.save(p);
      },
    };
    const { log } = mk({ store });
    await log.append({ type: 'site.enabled', actor: ui, data: {} });
    await expect(log.flush()).rejects.toThrow('quota');
    fail = false;
    await log.flush();
    expect(inner.saved!.entries).toHaveLength(1);
  });
  it('init restores a persisted log and continues the chain', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store, maxEntries: 100 });
    await fill(a.log, 120);
    await a.log.flush();
    const b = mk({ store, maxEntries: 100 });
    await b.log.init();
    expect(b.log.export()).toEqual(a.log.export());
    const e = await b.log.append({ type: 'site.enabled', actor: ui, data: {} });
    expect(e.seq).toBe(121);
    expect(await b.log.verify()).toEqual({ ok: true, count: 100 });
  });
  it('init with an empty or malformed store starts fresh', async () => {
    for (const saved of [undefined, null, 'x', { v: 2, anchor: GENESIS_HASH, entries: [], nextSeq: 1 }, { v: 1, anchor: 5, entries: [], nextSeq: 1 },
      { v: 1, anchor: GENESIS_HASH, entries: 'x', nextSeq: 1 }, { v: 1, anchor: GENESIS_HASH, entries: [1], nextSeq: 1 },
      { v: 1, anchor: GENESIS_HASH, entries: [], nextSeq: 0 }]) {
      const store = new MemoryAuditStore();
      store.saved = saved as unknown as AuditPersisted;
      const { log } = mk({ store });
      await log.init();
      expect(log.export()).toEqual({ v: 1, anchor: GENESIS_HASH, entries: [], nextSeq: 1 });
      expect(await log.verify()).toEqual({ ok: true, count: 0 });
    }
  });
  it('init survives a throwing store', async () => {
    const { log } = mk({ store: { load: async () => { throw new Error('boom'); }, save: async () => {} } });
    await log.init();
    expect(await log.verify()).toEqual({ ok: true, count: 0 });
  });
  it('init keeps a tampered chain as-is; appends on top do not hide it', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store });
    await fill(a.log, 4);
    await a.log.flush();
    store.saved!.entries[1]!.type = 'site.enabled';
    const tampered = structuredClone(store.saved);
    const b = mk({ store });
    await b.log.init();
    expect(b.log.export()).toEqual(tampered);
    await b.log.append({ type: 'site.disabled', actor: ui, data: {} });
    expect(await b.log.verify()).toMatchObject({ ok: false, brokenAtSeq: 2 });
  });
  it('tamper evidence persists in memory even after retention drops the bad entry', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store, maxEntries: 100 });
    await fill(a.log, 100);
    await a.log.flush();
    store.saved!.entries[0]!.data.i = 'forged';
    const b = mk({ store, maxEntries: 100 });
    await b.log.init();
    await fill(b.log, 5);
    expect(b.log.export().entries[0]!.seq).toBe(6);
    expect(await b.log.verify()).toMatchObject({ ok: false, brokenAtSeq: 1 });
  });
  it('detects truncation of the newest entries via nextSeq', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store });
    await fill(a.log, 5);
    await a.log.flush();
    store.saved!.entries.splice(3); // attacker drops seq 4 and 5 but leaves nextSeq=6
    const b = mk({ store });
    await b.log.init();
    expect(await b.log.verify()).toMatchObject({ ok: false, brokenAtSeq: 4 });
  });
  it('entries appended before init are re-chained on top of the loaded log', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store });
    await fill(a.log, 3);
    await a.log.flush();
    const b = mk({ store });
    const early = b.log.append({ type: 'pause.changed', actor: ui, data: { paused: true } });
    await early;
    await b.log.init();
    const x = b.log.export();
    expect(x.entries.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect(x.entries[3]!.type).toBe('pause.changed');
    expect(await b.log.verify()).toEqual({ ok: true, count: 4 });
  });
  it('store round-trip of a random room id keeps filters working', async () => {
    const store = new MemoryAuditStore();
    const a = mk({ store });
    const rid = randomHex32();
    await a.log.append({ type: 'room.opened', roomId: rid, actor: router, data: {} });
    await a.log.flush();
    const b = mk({ store });
    await b.log.init();
    expect(b.log.list({ roomId: rid })).toHaveLength(1);
  });
});
