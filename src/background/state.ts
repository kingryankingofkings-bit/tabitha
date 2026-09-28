// Router state persistence (storage.session key "tb.router"). SPEC.md §5, §15, DECISIONS.md D7.
// storage.session is in-memory, cleared on browser restart, and (at the default access level)
// only readable by trusted extension contexts. We still treat what we read back defensively:
// anything malformed is dropped, which fails closed (unknown endpoints/rooms cannot resume).

import { HEX32_RE } from '../shared/limits';
import type { KeyValueStore, PairingSnapshot, RouterState } from '../shared/types';

export type { EndpointRecord, RateBucket, RoomRecord, RoutedFrame, RouterState } from '../shared/types';

export const ROUTER_STATE_KEY = 'tb.router';

export function emptyPairingSnapshot(): PairingSnapshot {
  return { pairings: [], failures: [], failuresSinceReset: 0, lockedUntil: 0 };
}

export function emptyRouterState(): RouterState {
  return { v: 1, endpoints: {}, rooms: {}, pairing: emptyPairingSnapshot(), pairRequests: [], pendingSites: [] };
}

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

/** Structural sanity check. Entries that do not look right are dropped individually. */
function sanitize(raw: unknown): RouterState {
  const out = emptyRouterState();
  if (!isObj(raw) || raw.v !== 1) return out;
  if (isObj(raw.endpoints)) {
    for (const [id, rec] of Object.entries(raw.endpoints)) {
      if (!HEX32_RE.test(id) || !isObj(rec) || rec.endpointId !== id) continue;
      if (typeof rec.origin !== 'string' || typeof rec.resumeTokenHash !== 'string' || !isObj(rec.agent)) continue;
      if (rec.kind !== 'page' && rec.kind !== 'panel') continue; // 'native' can never be registered
      out.endpoints[id] = rec as unknown as RouterState['endpoints'][string];
    }
  }
  if (isObj(raw.rooms)) {
    for (const [id, room] of Object.entries(raw.rooms)) {
      if (!HEX32_RE.test(id) || !isObj(room) || room.roomId !== id) continue;
      if (!Array.isArray(room.members) || room.members.length !== 2 || !isObj(room.grant)) continue;
      if (room.state !== 'keying' && room.state !== 'active' && room.state !== 'closed') continue;
      if (!isObj(room.pubKeys) || !Array.isArray(room.confirmed) || !isObj(room.lastSeq) || !isObj(room.rate)) continue;
      if (!Array.isArray(room.recentFrameIds) || !isObj(room.routed) || !isObj(room.counters)) continue;
      out.rooms[id] = room as unknown as RouterState['rooms'][string];
    }
  }
  if (isObj(raw.pairing)) out.pairing = raw.pairing as unknown as PairingSnapshot; // PairingManager re-validates
  if (Array.isArray(raw.pairRequests)) {
    out.pairRequests = raw.pairRequests.filter(
      (r): r is RouterState['pairRequests'][number] =>
        isObj(r) && typeof r.tabId === 'number' && typeof r.origin === 'string' && typeof r.at === 'number',
    );
  }
  if (Array.isArray(raw.pendingSites)) out.pendingSites = raw.pendingSites.filter((s): s is string => typeof s === 'string');
  return out;
}

export class RouterStateStore {
  constructor(private readonly kv: KeyValueStore) {}

  /** Never throws: a missing or unreadable state yields an empty one (fail closed). */
  async load(): Promise<RouterState> {
    try {
      return sanitize(await this.kv.get<unknown>(ROUTER_STATE_KEY));
    } catch {
      return emptyRouterState();
    }
  }

  async save(s: RouterState): Promise<void> {
    await this.kv.set(ROUTER_STATE_KEY, s);
  }
}
