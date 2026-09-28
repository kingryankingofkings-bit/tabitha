// UiClient: id-correlated RPC over the 'tb.ui' runtime port (SPEC §7).
import { ext } from '../../platform/ext';
import { PORT_UI } from '../../shared/limits';
import { TabBridgeError, fromErrorPayload } from '../../shared/errors';
import type { RuntimePortLike, UiMethod, UiMethods, UiState } from '../../shared/types';

export interface UiClientOptions {
  /** Opens a new 'tb.ui' port. Default: ext.runtime.connect({name: PORT_UI}). */
  connect?: () => RuntimePortLike;
  /** Per-call timeout. Default 30 s. */
  callTimeoutMs?: number;
}

interface Pending {
  resolve: (r: unknown) => void;
  reject: (e: TabBridgeError) => void;
  timer: ReturnType<typeof setTimeout>;
}

const MIN_BACKOFF = 250;
const MAX_BACKOFF = 5000;

export class UiClient {
  private readonly connectFn: () => RuntimePortLike;
  private readonly callTimeoutMs: number;
  private port: RuntimePortLike | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private readonly stateListeners = new Set<(s: UiState) => void>();
  private readonly connListeners = new Set<(connected: boolean) => void>();
  private lastState: UiState | undefined;
  private closed = false;
  private backoff = MIN_BACKOFF;
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(opts: UiClientOptions = {}) {
    this.connectFn = opts.connect ?? (() => ext.runtime.connect({ name: PORT_UI }) as unknown as RuntimePortLike);
    this.callTimeoutMs = opts.callTimeoutMs ?? 30_000;
    this.open();
  }

  /** Latest state pushed by the router, if any. */
  get state(): UiState | undefined {
    return this.lastState;
  }

  get connected(): boolean {
    return this.port !== undefined;
  }

  call<M extends UiMethod>(m: M, p?: UiMethods[M]['p']): Promise<UiMethods[M]['r']> {
    return new Promise<UiMethods[M]['r']>((resolve, reject) => {
      if (this.closed) {
        reject(new TabBridgeError('NOT_CONNECTED', 'Client closed'));
        return;
      }
      if (!this.port) this.open();
      const port = this.port;
      if (!port) {
        reject(new TabBridgeError('NOT_CONNECTED'));
        return;
      }
      const id = this.nextId++;
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new TabBridgeError('TIMEOUT', `UI call ${m} timed out`));
      }, this.callTimeoutMs);
      this.pending.set(id, { resolve: resolve as (r: unknown) => void, reject, timer });
      try {
        const msg: { id: number; m: M; p?: unknown } = { id, m };
        if (p !== undefined) msg.p = p;
        port.postMessage(msg);
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new TabBridgeError('NOT_CONNECTED'));
        this.handleDisconnect(port);
      }
    });
  }

  /** Subscribe to state pushes. Called immediately (async) with the last known state. */
  onState(cb: (s: UiState) => void): () => void {
    this.stateListeners.add(cb);
    const s = this.lastState;
    if (s) queueMicrotask(() => {
      if (this.stateListeners.has(cb)) cb(s);
    });
    return () => {
      this.stateListeners.delete(cb);
    };
  }

  /** Subscribe to connection changes (true = port open). */
  onConnection(cb: (connected: boolean) => void): () => void {
    this.connListeners.add(cb);
    return () => {
      this.connListeners.delete(cb);
    };
  }

  close(): void {
    this.closed = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
    const port = this.port;
    this.port = undefined;
    this.rejectAll('Client closed');
    this.stateListeners.clear();
    this.connListeners.clear();
    try {
      port?.disconnect();
    } catch {
      /* already gone */
    }
  }

  // ---------------------------------------------------------------------------

  private open(): void {
    if (this.closed || this.port) return;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    let port: RuntimePortLike;
    try {
      port = this.connectFn();
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.port = port;
    port.onMessage.addListener((msg) => this.onMessage(port, msg));
    port.onDisconnect.addListener(() => {
      // Touch lastError so Chrome does not log "Unchecked runtime.lastError".
      try {
        void (ext?.runtime as { lastError?: unknown } | undefined)?.lastError;
      } catch {
        /* ignore */
      }
      this.handleDisconnect(port);
    });
    this.emitConn(true);
  }

  private handleDisconnect(port: RuntimePortLike): void {
    if (this.port !== port) return;
    this.port = undefined;
    this.rejectAll();
    this.emitConn(false);
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.closed || this.reconnectTimer) return;
    const delay = this.backoff;
    this.backoff = Math.min(this.backoff * 2, MAX_BACKOFF);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.open();
    }, delay);
  }

  private rejectAll(message?: string): void {
    const all = [...this.pending.values()];
    this.pending.clear();
    for (const p of all) {
      clearTimeout(p.timer);
      p.reject(new TabBridgeError('NOT_CONNECTED', message));
    }
  }

  private emitConn(connected: boolean): void {
    for (const cb of [...this.connListeners]) {
      try {
        cb(connected);
      } catch {
        /* listener errors must not break the client */
      }
    }
  }

  private onMessage(port: RuntimePortLike, raw: unknown): void {
    if (port !== this.port || !raw || typeof raw !== 'object') return;
    const msg = raw as { t?: unknown; id?: unknown; ok?: unknown; r?: unknown; e?: unknown; ev?: unknown; d?: unknown };
    if (msg.t === 'res' && typeof msg.id === 'number') {
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      this.backoff = MIN_BACKOFF;
      if (msg.ok === true) p.resolve(msg.r);
      else p.reject(fromErrorPayload((msg.e as { code?: unknown; message?: unknown } | undefined) ?? undefined));
      return;
    }
    if (msg.t === 'ev' && msg.ev === 'state' && msg.d && typeof msg.d === 'object') {
      this.backoff = MIN_BACKOFF;
      const s = msg.d as UiState;
      this.lastState = s;
      for (const cb of [...this.stateListeners]) {
        try {
          cb(s);
        } catch {
          /* listener errors must not break the client */
        }
      }
    }
  }
}
