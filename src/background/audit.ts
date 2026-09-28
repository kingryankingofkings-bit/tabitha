// Hash-chained, bounded, persisted audit log. SPEC.md §12, DECISIONS.md T16.
// Tamper-evident (not tamper-proof): every entry commits to its predecessor's hash; the retained
// suffix verifies from `anchor` (the hash of the last entry dropped by retention).

import { TabBridgeError } from '../shared/errors';
import { canonicalJson, utf8Encode, utf8Length } from '../shared/encoding';
import { sha256Hex } from '../shared/crypto';
import {
  AUDIT_DEFAULT_MAX_ENTRIES,
  AUDIT_FLUSH_MS,
  AUDIT_MAX_MAX_ENTRIES,
  AUDIT_MIN_MAX_ENTRIES,
  MAX_TEXT_BYTES,
} from '../shared/limits';
import type {
  AuditActor,
  AuditEntry,
  AuditPersisted,
  AuditStore,
  AuditType,
  AuditVerifyResult,
  RoomId,
} from '../shared/types';

export const GENESIS_HASH = '0'.repeat(64);

export const AUDIT_TYPES: readonly AuditType[] = Object.freeze([
  'site.enabled', 'site.disabled', 'pause.changed', 'endpoint.rejected',
  'pair.requested', 'pair.started', 'pair.failed', 'pair.approved', 'pair.cancelled',
  'room.opened', 'room.narrowed', 'room.closed',
  'frame.routed', 'frame.rejected', 'frame.receipt',
  'content.sent', 'content.received', 'violation', 'log.cleared',
] as AuditType[]);

const ACTOR_KINDS: readonly AuditActor['kind'][] = ['router', 'endpoint', 'ui'];

export const AUDIT_LIST_DEFAULT_LIMIT = 200;
export const AUDIT_LIST_MAX_LIMIT = 1000;
export const TRUNCATION_SUFFIX = '…[truncated]';
/** Nesting deeper than this inside `data` is replaced by a marker string. */
const MAX_DATA_DEPTH = 16;

type Obj = Record<string, unknown>;

function isPlainObject(x: unknown): x is Obj {
  return typeof x === 'object' && x !== null && !Array.isArray(x) && Object.prototype.toString.call(x) === '[object Object]';
}

function deepCopy<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}

function copyEntry(e: AuditEntry): AuditEntry {
  return deepCopy(e);
}

export async function hashEntry(prevHash: string, e: Omit<AuditEntry, 'hash'>): Promise<string> {
  // Strip a stray `hash` so passing a full entry can never make the hash self-referential.
  const { hash: _ignored, ...rest } = e as AuditEntry;
  return sha256Hex(utf8Encode(prevHash + '\n' + canonicalJson(rest)));
}

/** Verifies a chain (oldest first) against `anchor`. Reports the first break. */
export async function verifyChain(anchor: string, entries: AuditEntry[]): Promise<AuditVerifyResult> {
  if (!Array.isArray(entries)) return { ok: false, brokenAtSeq: -1, reason: 'entries is not an array' };
  let prevHash = anchor;
  let prevSeq: number | undefined;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i] as unknown;
    const storedSeq = isPlainObject(e) && typeof e.seq === 'number' ? e.seq : -1;
    // Where a break is found: the seq this position should have (prev + 1), else what is stored.
    const at = prevSeq !== undefined ? prevSeq + 1 : storedSeq;
    const broken = (reason: string): AuditVerifyResult => ({ ok: false, brokenAtSeq: at, reason });
    if (!isPlainObject(e)) return broken('malformed entry');
    if (typeof e.hash !== 'string' || typeof e.prevHash !== 'string') return broken('malformed entry');
    if (e.prevHash !== prevHash) return broken(i === 0 ? 'first entry does not link to the anchor' : 'prevHash does not match previous entry');
    if (!Number.isSafeInteger(e.seq) || (e.seq as number) < 1) return broken('invalid seq');
    if (prevSeq !== undefined && e.seq !== prevSeq + 1) return broken('seq is not contiguous');
    let expected: string;
    try {
      expected = await hashEntry(prevHash, e as unknown as AuditEntry);
    } catch {
      return broken('entry cannot be hashed');
    }
    if (expected !== e.hash) return broken('hash mismatch');
    prevHash = e.hash;
    prevSeq = e.seq as number;
  }
  return { ok: true, count: entries.length };
}

function truncateUtf8(s: string): string {
  const budget = MAX_TEXT_BYTES - utf8Length(TRUNCATION_SUFFIX);
  const bytes = utf8Encode(s);
  let cut = Math.min(budget, bytes.length);
  // Never split a multi-byte sequence: back up to a lead byte.
  while (cut > 0 && ((bytes[cut] as number) & 0xc0) === 0x80) cut--;
  return new TextDecoder('utf-8').decode(bytes.subarray(0, cut)) + TRUNCATION_SUFFIX;
}

/**
 * Produces a JSON-safe copy of `data`: long strings truncated, non-finite numbers → null,
 * non-JSON values dropped, cycles and excessive depth replaced by markers.
 */
function sanitizeData(data: unknown): { data: Obj; truncated: boolean } {
  let truncated = false;
  const seen = new WeakSet<object>();
  const walk = (v: unknown, depth: number): unknown => {
    if (v === null) return null;
    switch (typeof v) {
      case 'string':
        if (utf8Length(v) > MAX_TEXT_BYTES) {
          truncated = true;
          return truncateUtf8(v);
        }
        return v;
      case 'boolean':
        return v;
      case 'number':
        return Number.isFinite(v) ? v : null;
      case 'object': {
        if (depth >= MAX_DATA_DEPTH) return '[too deep]';
        if (seen.has(v as object)) return '[circular]';
        seen.add(v as object);
        let out: unknown;
        if (Array.isArray(v)) out = v.map((x) => (x === undefined ? null : walk(x, depth + 1)));
        else if (isPlainObject(v)) {
          const o: Obj = {};
          for (const k of Object.keys(v)) {
            const w = walk(v[k], depth + 1);
            if (w !== undefined) Object.defineProperty(o, k, { value: w, enumerable: true, writable: true, configurable: true });
          }
          out = o;
        } else out = null; // Dates, typed arrays, Maps, class instances: not audit data
        seen.delete(v as object);
        return out;
      }
      default:
        return undefined; // undefined, function, symbol, bigint
    }
  };
  const top = isPlainObject(data) ? (walk(data, 0) as Obj) : {};
  if (truncated) top.truncated = true;
  return { data: top, truncated };
}

function clampMaxEntries(n: unknown): number {
  if (typeof n !== 'number' || !Number.isFinite(n)) return AUDIT_DEFAULT_MAX_ENTRIES;
  return Math.min(AUDIT_MAX_MAX_ENTRIES, Math.max(AUDIT_MIN_MAX_ENTRIES, Math.floor(n)));
}

function isPersistedShape(p: unknown): p is AuditPersisted {
  return (
    isPlainObject(p) &&
    p.v === 1 &&
    typeof p.anchor === 'string' &&
    Array.isArray(p.entries) &&
    p.entries.every(isPlainObject) &&
    typeof p.nextSeq === 'number' &&
    Number.isSafeInteger(p.nextSeq) &&
    p.nextSeq >= 1
  );
}

export interface AuditLogOptions {
  store: AuditStore;
  now(): number;
  maxEntries?: number;
  flushDelayMs?: number;
}

type AppendInput = { type: AuditType; roomId?: RoomId; actor: AuditActor; data: Record<string, unknown> };
type Normalized = { type: AuditType; roomId?: RoomId; actor: AuditActor; data: Obj; ts: number };

export class AuditLog {
  private readonly store: AuditStore;
  private readonly now: () => number;
  private readonly flushDelayMs: number;
  private maxEntries: number;
  private entries: AuditEntry[] = [];
  private anchor = GENESIS_HASH;
  private nextSeq = 1;
  /** Serializes every mutation (append/clear/init) in call order. */
  private queue: Promise<unknown> = Promise.resolve();
  /** Serializes store.save calls so an older snapshot never overwrites a newer one. */
  private saving: Promise<void> = Promise.resolve();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private dirty = false;
  /** Result of verifying the chain loaded at init. A failure stays reported until clear(). */
  private loadCheck: Promise<void> = Promise.resolve();
  private stickyFailure: AuditVerifyResult | undefined;

  constructor(opts: AuditLogOptions) {
    this.store = opts.store;
    this.now = opts.now;
    this.maxEntries = clampMaxEntries(opts.maxEntries ?? AUDIT_DEFAULT_MAX_ENTRIES);
    const d = opts.flushDelayMs ?? AUDIT_FLUSH_MS;
    this.flushDelayMs = typeof d === 'number' && Number.isFinite(d) && d >= 0 ? d : AUDIT_FLUSH_MS;
  }

  private enqueue<T>(fn: () => Promise<T> | T): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  /**
   * Loads persisted state. A loaded chain is kept exactly as stored, even if it fails
   * verification, so that verify() reports the tampering. Entries appended before init()
   * are re-chained on top of the loaded log.
   */
  init(): Promise<void> {
    return this.enqueue(async () => {
      let loaded: unknown;
      try {
        loaded = await this.store.load();
      } catch {
        loaded = undefined;
      }
      if (!isPersistedShape(loaded)) return;
      const early = this.entries;
      this.entries = deepCopy(loaded.entries);
      this.anchor = loaded.anchor;
      this.nextSeq = loaded.nextSeq;
      const anchor = this.anchor;
      const snapshot = this.entries.slice();
      const nextSeq = this.nextSeq;
      this.loadCheck = (async () => {
        const r = await verifyChain(anchor, snapshot);
        if (!r.ok) this.stickyFailure = r;
        else {
          const last = snapshot[snapshot.length - 1];
          if (last && nextSeq !== last.seq + 1)
            this.stickyFailure = { ok: false, brokenAtSeq: last.seq + 1, reason: 'nextSeq does not follow the last entry' };
        }
      })();
      for (const e of early) {
        const n: Normalized = { type: e.type, actor: e.actor, data: e.data, ts: e.ts };
        if (e.roomId !== undefined) n.roomId = e.roomId;
        await this.appendNow(n);
      }
      if (early.length > 0) this.scheduleSave();
    });
  }

  private normalize(e: AppendInput): Normalized {
    if (!isPlainObject(e)) throw new TabBridgeError('INVALID_MESSAGE', 'Invalid audit entry');
    if (!AUDIT_TYPES.includes(e.type)) throw new TabBridgeError('INVALID_MESSAGE', 'Invalid audit type');
    const a = e.actor as unknown;
    if (!isPlainObject(a) || !(ACTOR_KINDS as readonly unknown[]).includes(a.kind))
      throw new TabBridgeError('INVALID_MESSAGE', 'Invalid audit actor');
    const actor: AuditActor = { kind: a.kind as AuditActor['kind'] };
    if (typeof a.endpointId === 'string') actor.endpointId = a.endpointId;
    if (typeof a.origin === 'string') actor.origin = a.origin;
    const out: Normalized = { type: e.type, actor, data: sanitizeData(e.data).data, ts: this.now() };
    if (typeof e.roomId === 'string') out.roomId = e.roomId;
    return out;
  }

  /** Must only be called from inside the queue. */
  private async appendNow(n: Normalized): Promise<AuditEntry> {
    const last = this.entries[this.entries.length - 1];
    const prevHash = last ? last.hash : this.anchor;
    const body: Omit<AuditEntry, 'hash'> = { seq: this.nextSeq, ts: n.ts, type: n.type, actor: n.actor, data: n.data, prevHash };
    if (n.roomId !== undefined) body.roomId = n.roomId;
    const hash = await hashEntry(prevHash, body);
    const entry: AuditEntry = { ...body, hash };
    this.nextSeq = body.seq + 1;
    this.entries.push(entry);
    this.applyRetention();
    return entry;
  }

  private applyRetention(): boolean {
    const excess = this.entries.length - this.maxEntries;
    if (excess <= 0) return false;
    const dropped = this.entries.splice(0, excess);
    this.anchor = (dropped[dropped.length - 1] as AuditEntry).hash;
    return true;
  }

  /** Appends an entry. Serialized: concurrent calls chain in call order. */
  append(e: AppendInput): Promise<AuditEntry> {
    let n: Normalized;
    try {
      n = this.normalize(e); // snapshot input + timestamp at call time
    } catch (err) {
      return Promise.reject(err);
    }
    return this.enqueue(async () => {
      const entry = await this.appendNow(n);
      this.scheduleSave();
      return copyEntry(entry);
    });
  }

  list(q?: { limit?: number; beforeSeq?: number; roomId?: RoomId; types?: AuditType[] }): AuditEntry[] {
    let limit = AUDIT_LIST_DEFAULT_LIMIT;
    if (q && typeof q.limit === 'number' && Number.isFinite(q.limit))
      limit = Math.min(AUDIT_LIST_MAX_LIMIT, Math.max(0, Math.floor(q.limit)));
    const before = q && typeof q.beforeSeq === 'number' ? q.beforeSeq : undefined;
    const roomId = q?.roomId;
    const types = q && Array.isArray(q.types) ? q.types : undefined;
    const out: AuditEntry[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i--) {
      const e = this.entries[i] as AuditEntry;
      if (before !== undefined && !(e.seq < before)) continue;
      if (roomId !== undefined && e.roomId !== roomId) continue;
      if (types !== undefined && !types.includes(e.type)) continue;
      out.push(copyEntry(e));
    }
    return out;
  }

  verify(): Promise<AuditVerifyResult> {
    return this.enqueue(async () => {
      await this.loadCheck;
      if (this.stickyFailure) return { ...this.stickyFailure };
      const r = await verifyChain(this.anchor, this.entries.slice());
      if (!r.ok) return r;
      const last = this.entries[this.entries.length - 1];
      if (last && this.nextSeq !== last.seq + 1)
        return { ok: false, brokenAtSeq: last.seq + 1, reason: 'nextSeq does not follow the last entry' };
      return r;
    });
  }

  /** Empties the log and starts a new chain whose first entry is `log.cleared { cleared }`. */
  clear(actor: AuditActor): Promise<{ cleared: number }> {
    let n: Normalized;
    try {
      n = this.normalize({ type: 'log.cleared', actor, data: {} });
    } catch (err) {
      return Promise.reject(err);
    }
    return this.enqueue(async () => {
      await this.loadCheck;
      const cleared = this.entries.length;
      this.entries = [];
      this.anchor = GENESIS_HASH;
      this.stickyFailure = undefined;
      await this.appendNow({ ...n, data: { cleared } });
      this.scheduleSave();
      return { cleared };
    });
  }

  setMaxEntries(n: number): void {
    this.maxEntries = clampMaxEntries(n);
    if (this.applyRetention()) this.scheduleSave();
  }

  getMaxEntries(): number {
    return this.maxEntries;
  }

  export(): AuditPersisted {
    return deepCopy({ v: 1 as const, anchor: this.anchor, entries: this.entries, nextSeq: this.nextSeq });
  }

  private scheduleSave(): void {
    this.dirty = true;
    // Throttled rather than trailing-debounced: a steady stream of appends cannot postpone
    // persistence indefinitely (bounds loss if the worker is killed; DECISIONS OSQ-4).
    if (this.timer !== undefined) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.save().catch(() => undefined); // stays dirty; retried on the next append or flush()
    }, this.flushDelayMs);
  }

  private save(): Promise<void> {
    const run = this.saving.then(async () => {
      if (!this.dirty) return;
      this.dirty = false;
      try {
        await this.store.save(this.export());
      } catch (err) {
        this.dirty = true;
        throw err;
      }
    });
    this.saving = run.catch(() => undefined);
    return run;
  }

  /** Forces a save of everything appended so far (including queued appends). */
  async flush(): Promise<void> {
    await this.queue;
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    this.dirty = true;
    await this.save();
  }
}
