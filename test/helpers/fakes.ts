// Shared test doubles. Ports mimic chrome.runtime.Port semantics, including JSON serialization
// (Chrome serializes runtime messages as JSON) and asynchronous delivery.
import type { AuditPersisted, AuditStore, KeyValueStore, RuntimePortLike } from '../../src/shared/types';

type Listener<T> = (x: T) => void;

export class FakePort implements RuntimePortLike {
  peer!: FakePort;
  connected = true;
  readonly sent: unknown[] = [];
  private msgListeners: Listener<unknown>[] = [];
  private discListeners: Listener<void>[] = [];

  constructor(readonly name: string) {}

  postMessage(msg: unknown): void {
    if (!this.connected) throw new Error('Attempting to use a disconnected port object');
    const wire = JSON.parse(JSON.stringify(msg)); // enforce JSON-serializable, like Chrome
    this.sent.push(wire);
    const peer = this.peer;
    queueMicrotask(() => {
      if (!peer.connected) return;
      for (const l of [...peer.msgListeners]) l(JSON.parse(JSON.stringify(wire)));
    });
  }

  onMessage = { addListener: (cb: Listener<unknown>) => void this.msgListeners.push(cb) };
  onDisconnect = { addListener: (cb: Listener<void>) => void this.discListeners.push(cb) };

  disconnect(): void {
    if (!this.connected) return;
    this.connected = false;
    const peer = this.peer;
    // Like Chrome: the side calling disconnect() does not get its own onDisconnect.
    queueMicrotask(() => {
      if (!peer.connected) return;
      peer.connected = false;
      for (const l of [...peer.discListeners]) l();
    });
  }
}

/** Returns [clientSide, serverSide]. */
export function portPair(name: string): [FakePort, FakePort] {
  const a = new FakePort(name);
  const b = new FakePort(name);
  a.peer = b;
  b.peer = a;
  return [a, b];
}

export class MemoryKV implements KeyValueStore {
  readonly data = new Map<string, string>();
  async get<T>(key: string): Promise<T | undefined> {
    const v = this.data.get(key);
    return v === undefined ? undefined : (JSON.parse(v) as T);
  }
  async set(key: string, value: unknown): Promise<void> {
    this.data.set(key, JSON.stringify(value));
  }
}

export class MemoryAuditStore implements AuditStore {
  saved: AuditPersisted | undefined;
  saves = 0;
  async load(): Promise<AuditPersisted | undefined> {
    return this.saved ? (JSON.parse(JSON.stringify(this.saved)) as AuditPersisted) : undefined;
  }
  async save(p: AuditPersisted): Promise<void> {
    this.saves++;
    this.saved = JSON.parse(JSON.stringify(p)) as AuditPersisted;
  }
}

/** Manually advanced clock. */
export class FakeClock {
  constructor(public t = 1_700_000_000_000) {}
  now = (): number => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

/** Flush pending microtasks/macrotasks a few times. */
export async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}
