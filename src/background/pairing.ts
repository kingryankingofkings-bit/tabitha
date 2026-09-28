// Pairing-code state machine. SPEC.md §11, DECISIONS.md D3.
// SECURITY: pairing codes are secrets. They must never appear in logs, audit records or error
// messages. Errors here always use the fixed default messages from errors.ts.

import { TabBridgeError } from '../shared/errors';
import {
  CODE_RE,
  HEX32_RE,
  PAIRING_CODE_TTL_MS,
  PAIRING_GLOBAL_FAILS_PER_MIN,
  PAIRING_LOCKOUT_MS,
  PAIRING_MAX_FAILURES,
} from '../shared/limits';
import type {
  EndpointId,
  EndpointKind,
  GrantProposal,
  PairingEndpointRef,
  PairingPreview,
  PairingRecord,
  PairingSnapshot,
} from '../shared/types';
import { copyProposal, validateProposal } from './permissions';

export interface PairingOptions {
  now(): number;
  randomInt(maxExclusive: number): number;
  snapshot?: PairingSnapshot;
}

/** Window over which failed attempts are counted for the global lockout. */
export const PAIRING_FAILURE_WINDOW_MS = 60_000;
const CODE_SPACE = 1_000_000;
const MAX_CODE_DRAWS = 1_000;
/** Hard cap on remembered failure timestamps (they are also pruned to the last 60 s). */
const MAX_FAILURE_RECORDS = 256;
const ENDPOINT_KINDS: readonly EndpointKind[] = ['page', 'panel', 'native'];

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x) && Object.prototype.toString.call(x) === '[object Object]';
}

function copyRef(r: PairingEndpointRef): PairingEndpointRef {
  const out: PairingEndpointRef = { endpointId: r.endpointId, kind: r.kind, origin: r.origin };
  if (r.tabId !== undefined) out.tabId = r.tabId;
  return out;
}

function copyRecord(r: PairingRecord): PairingRecord {
  return {
    code: r.code,
    initiator: copyRef(r.initiator),
    proposal: copyProposal(r.proposal),
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
  };
}

/** Light validation of a persisted endpoint ref. Returns a fresh copy or null. */
function restoreRef(x: unknown): PairingEndpointRef | null {
  if (!isPlainObject(x)) return null;
  const { endpointId, kind, origin, tabId } = x;
  if (typeof endpointId !== 'string' || !HEX32_RE.test(endpointId)) return null;
  if (typeof kind !== 'string' || !(ENDPOINT_KINDS as readonly string[]).includes(kind)) return null;
  if (typeof origin !== 'string' || origin.length === 0 || origin.length > 2048) return null;
  if (tabId !== undefined && !(typeof tabId === 'number' && Number.isInteger(tabId) && tabId >= 0)) return null;
  const out: PairingEndpointRef = { endpointId, kind: kind as EndpointKind, origin };
  if (tabId !== undefined) out.tabId = tabId as number;
  return out;
}

function restoreRecord(x: unknown): PairingRecord | null {
  if (!isPlainObject(x)) return null;
  const { code, initiator, proposal, createdAt, expiresAt } = x;
  if (typeof code !== 'string' || !CODE_RE.test(code)) return null;
  const ref = restoreRef(initiator);
  if (!ref) return null;
  if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) return null;
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) return null;
  // A restored pairing may never live longer than a fresh one would.
  if (expiresAt - createdAt > PAIRING_CODE_TTL_MS || expiresAt < createdAt) return null;
  let p: GrantProposal;
  try {
    p = validateProposal(proposal);
  } catch {
    return null;
  }
  return { code, initiator: ref, proposal: p, createdAt, expiresAt };
}

export class PairingManager {
  private readonly now: () => number;
  private readonly randomInt: (maxExclusive: number) => number;
  /** Keyed by code. A Map (not an object) so user-supplied strings can't hit prototype keys. */
  private readonly pairings = new Map<string, PairingRecord>();
  private failures: number[] = [];
  private failuresSinceReset = 0;
  private locked = 0;

  constructor(opts: PairingOptions) {
    this.now = opts.now;
    this.randomInt = opts.randomInt;
    if (opts.snapshot !== undefined) this.restore(opts.snapshot);
  }

  private restore(s: unknown): void {
    if (!isPlainObject(s)) return;
    if (Array.isArray(s.pairings)) {
      const seenInitiators = new Set<EndpointId>();
      for (const raw of s.pairings) {
        const rec = restoreRecord(raw);
        if (!rec) continue;
        // Invariants: unique code; at most one pairing per initiator endpoint.
        if (this.pairings.has(rec.code) || seenInitiators.has(rec.initiator.endpointId)) continue;
        seenInitiators.add(rec.initiator.endpointId);
        this.pairings.set(rec.code, rec);
      }
    }
    if (Array.isArray(s.failures)) {
      this.failures = s.failures
        .filter((f): f is number => typeof f === 'number' && Number.isFinite(f))
        .slice(-MAX_FAILURE_RECORDS);
    }
    const fsr = s.failuresSinceReset;
    if (typeof fsr === 'number' && Number.isSafeInteger(fsr) && fsr >= 0) this.failuresSinceReset = fsr;
    const lu = s.lockedUntil;
    if (typeof lu === 'number' && Number.isFinite(lu) && lu >= 0) this.locked = lu;
  }

  private drawCode(): string {
    for (let i = 0; i < MAX_CODE_DRAWS; i++) {
      const n = this.randomInt(CODE_SPACE);
      if (!Number.isInteger(n) || n < 0 || n >= CODE_SPACE) throw new TabBridgeError('INTERNAL');
      const code = String(n).padStart(6, '0');
      if (!this.pairings.has(code)) return code;
    }
    throw new TabBridgeError('INTERNAL');
  }

  /** Starts a pairing for `initiator`, replacing any previous one it had. */
  start(initiator: PairingEndpointRef, proposal: GrantProposal): PairingRecord {
    const ref = restoreRef(initiator);
    if (!ref) throw new TabBridgeError('INVALID_MESSAGE');
    const p = validateProposal(proposal); // defense in depth; returns a fresh copy
    this.cancelForEndpoint(ref.endpointId);
    const now = this.now();
    const rec: PairingRecord = {
      code: this.drawCode(),
      initiator: ref,
      proposal: p,
      createdAt: now,
      expiresAt: now + PAIRING_CODE_TTL_MS,
    };
    this.pairings.set(rec.code, rec);
    this.failuresSinceReset = 0;
    return copyRecord(rec);
  }

  private recordFailure(now: number): never {
    this.failures = this.failures.filter((f) => now - f < PAIRING_FAILURE_WINDOW_MS && f <= now);
    this.failures.push(now);
    if (this.failures.length > MAX_FAILURE_RECORDS) this.failures = this.failures.slice(-MAX_FAILURE_RECORDS);
    this.failuresSinceReset++;
    if (this.failuresSinceReset >= PAIRING_MAX_FAILURES) {
      // A wrong guess may have been aimed at any active code, so every code is burned.
      this.pairings.clear();
      this.failuresSinceReset = 0;
    }
    if (this.failures.length > PAIRING_GLOBAL_FAILS_PER_MIN) this.locked = now + PAIRING_LOCKOUT_MS;
    throw new TabBridgeError('PAIRING_CODE_INVALID');
  }

  /** Shared rules for lookup/approve (SPEC §11 1–4). Returns the live record. */
  private check(code: unknown, joiner: PairingEndpointRef): { rec: PairingRecord; joiner: PairingEndpointRef } {
    const j = restoreRef(joiner);
    if (!j) throw new TabBridgeError('INVALID_MESSAGE');
    const now = this.now();
    if (now < this.locked) throw new TabBridgeError('PAIRING_LOCKED');
    if (typeof code !== 'string' || !CODE_RE.test(code)) this.recordFailure(now);
    const rec = this.pairings.get(code as string);
    if (!rec) this.recordFailure(now);
    if (!(now < rec.expiresAt)) {
      this.pairings.delete(rec.code);
      throw new TabBridgeError('PAIRING_EXPIRED');
    }
    if (j.endpointId === rec.initiator.endpointId) throw new TabBridgeError('PAIRING_SELF');
    return { rec, joiner: j };
  }

  lookup(code: string, joiner: PairingEndpointRef): PairingPreview {
    const { rec, joiner: j } = this.check(code, joiner);
    return {
      code: rec.code,
      initiator: { origin: rec.initiator.origin, kind: rec.initiator.kind },
      // endpointId pins approval to the exact endpoint the user reviewed (SECURITY_REVIEW M1).
      joiner: { origin: j.origin, kind: j.kind, endpointId: j.endpointId },
      proposal: copyProposal(rec.proposal),
      expiresAt: rec.expiresAt,
    };
  }

  approve(
    code: string,
    joiner: PairingEndpointRef,
  ): { initiator: PairingEndpointRef; joiner: PairingEndpointRef; proposal: GrantProposal } {
    const { rec, joiner: j } = this.check(code, joiner);
    this.pairings.delete(rec.code); // single use
    return { initiator: copyRef(rec.initiator), joiner: j, proposal: copyProposal(rec.proposal) };
  }

  /** UI-only cancellation. Not counted as a failure. */
  cancel(code: string): boolean {
    if (typeof code !== 'string') return false;
    return this.pairings.delete(code);
  }

  cancelForEndpoint(endpointId: EndpointId): void {
    for (const [code, rec] of this.pairings) if (rec.initiator.endpointId === endpointId) this.pairings.delete(code);
  }

  /** Removes and returns expired pairings. */
  sweep(): PairingRecord[] {
    const now = this.now();
    const expired: PairingRecord[] = [];
    for (const [code, rec] of this.pairings) {
      if (!(now < rec.expiresAt)) {
        this.pairings.delete(code);
        expired.push(copyRecord(rec));
      }
    }
    return expired;
  }

  /** Active (unexpired) pairings, oldest first. Copies. */
  list(): PairingRecord[] {
    const now = this.now();
    return [...this.pairings.values()]
      .filter((r) => now < r.expiresAt)
      .sort((a, b) => a.createdAt - b.createdAt)
      .map(copyRecord);
  }

  lockedUntil(): number {
    return this.locked;
  }

  /** JSON-safe deep copy for persistence (storage.session). Contains live codes. */
  snapshot(): PairingSnapshot {
    return {
      pairings: [...this.pairings.values()].map(copyRecord),
      failures: [...this.failures],
      failuresSinceReset: this.failuresSinceReset,
      lockedUntil: this.locked,
    };
  }
}
