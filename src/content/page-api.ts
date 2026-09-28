// MAIN-world shim defining `window.tabBridge`. SPEC.md §6.1, §6.2; DECISIONS.md D5, T12.
//
// Self-contained IIFE: nothing but `window.tabBridge` (and the `tabbridge:ready` event) is exposed.
// The private MessagePort, RPC ids and all helpers stay inside this closure.

import { ASK_DEFAULT_TIMEOUT_MS, ASK_MAX_TIMEOUT_MS, HARD_MAX_FILE_BYTES } from '../shared/limits';
import type {
  AgentEventMap,
  AgentEventName,
  InboundMessage,
  RoomView,
  SendResult,
  TabBridgeGlobal,
  TabBridgeSession,
  TaskBody,
} from '../shared/types';

(() => {
  const w = window;
  if (w.top !== w) return; // top frame only
  if (Object.prototype.hasOwnProperty.call(w, 'tabBridge')) return; // already defined (double injection)

  // Capture builtins before page scripts can replace them.
  const MC = MessageChannel;
  const winPost = w.postMessage.bind(w);
  const addWinListener = w.addEventListener.bind(w);
  const removeWinListener = w.removeEventListener.bind(w);
  const dispatch = w.dispatchEvent.bind(w);
  const freeze = Object.freeze;
  const defineProperty = Object.defineProperty;
  const toStr = Object.prototype.toString;
  const EventCtor = Event;
  const FileCtor = File;
  const setT = setTimeout;
  const clearT = clearTimeout;

  const EVENT_NAMES: readonly AgentEventName[] = ['prompt', 'response', 'task', 'file', 'room', 'error'];
  const MAX_HANDSHAKE_OFFERS = 8;
  const RESPONSE_BUFFER_MAX = 64;
  const RESPONSE_BUFFER_TTL_MS = 60_000;

  type Obj = Record<string, unknown>;
  const isObj = (x: unknown): x is Obj => typeof x === 'object' && x !== null && toStr.call(x) === '[object Object]';

  class TabBridgeError extends Error {
    readonly code: string;
    constructor(code: string, message?: string) {
      super(message ?? code);
      this.name = 'TabBridgeError';
      this.code = code;
    }
  }
  const tbError = (code: string, message?: string): TabBridgeError => new TabBridgeError(code, message);

  function deepFreeze<T>(x: T): T {
    if (typeof x === 'object' && x !== null && !Object.isFrozen(x) && !(x instanceof FileCtor)) {
      for (const k of Object.keys(x)) deepFreeze((x as Obj)[k]);
      freeze(x);
    }
    return x;
  }

  // ---------------------------------------------------------------- handshake (§6.1)

  let bound: MessagePort | null = null;
  let isReady = false;
  let offers = 0;
  const candidates: MessagePort[] = [];

  function offer(): void {
    if (bound || offers >= MAX_HANDSHAKE_OFFERS) return;
    offers++;
    const ch = new MC();
    const port = ch.port1;
    candidates.push(port);
    port.onmessage = (ev: MessageEvent) => onPortMessage(port, ev.data);
    try {
      winPost({ __tabbridge: 'hs1', v: 1 }, '*', [ch.port2]);
    } catch {
      /* ignore */
    }
  }

  function onWindowMessage(ev: MessageEvent): void {
    if (bound || ev.source !== w) return;
    const d: unknown = ev.data;
    if (isObj(d) && d.__tabbridge === 'hs0') offer(); // isolated world announced itself: new channel
  }
  addWinListener('message', onWindowMessage);

  function onPortMessage(port: MessagePort, d: unknown): void {
    if (!isObj(d)) return;
    if (!bound) {
      if (d.t !== 'bound') return;
      bound = port;
      removeWinListener('message', onWindowMessage);
      for (const c of candidates) {
        if (c !== port) {
          c.onmessage = null;
          c.close();
        }
      }
      candidates.length = 0;
      return;
    }
    if (port !== bound) return;
    switch (d.t) {
      case 'ready':
        onReady(d);
        return;
      case 'res':
        onRes(d);
        return;
      case 'ev':
        onEvent(d);
        return;
      default:
        return;
    }
  }

  // ---------------------------------------------------------------- RPC

  let nextId = 1;
  const calls = new Map<number, { resolve(r: unknown): void; reject(e: TabBridgeError): void }>();

  function rpc(m: string, p?: Obj, transfer?: Transferable[]): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!bound || !isReady) {
        reject(tbError('NOT_CONNECTED', 'Not connected to TabBridge'));
        return;
      }
      const id = nextId++;
      calls.set(id, { resolve, reject });
      const msg: Obj = p === undefined ? { id, m } : { id, m, p };
      try {
        bound.postMessage(msg, transfer ?? []);
      } catch {
        calls.delete(id);
        reject(tbError('INVALID_MESSAGE', 'Arguments could not be sent'));
      }
    });
  }

  function onRes(d: Obj): void {
    const id = d.id;
    if (typeof id !== 'number') return;
    const call = calls.get(id);
    if (!call) return;
    calls.delete(id);
    if (d.ok === true) {
      call.resolve(d.r);
    } else {
      const e = isObj(d.e) ? d.e : {};
      call.reject(tbError(typeof e.code === 'string' ? e.code : 'INTERNAL', typeof e.message === 'string' ? e.message : 'Internal error'));
    }
  }

  // ---------------------------------------------------------------- session

  interface SessionState {
    active: boolean;
    listeners: Map<AgentEventName, Set<(d: unknown) => void>>;
    askWaiters: Map<string, (m: InboundMessage) => void>;
    unresolvedAsks: number; // asks whose frameId is not known yet
    recentResponses: Map<string, { m: InboundMessage; at: number }>;
    askRejects: Set<(e: TabBridgeError) => void>;
  }

  let state: SessionState | null = null;
  let sessionPromise: Promise<TabBridgeSession> | null = null;

  function notConnected(): Promise<never> {
    return Promise.reject(tbError('NOT_CONNECTED', 'Session is closed'));
  }

  function makeSession(st: SessionState): TabBridgeSession {
    const guard = <T>(fn: () => Promise<T>): Promise<T> => (st.active ? fn() : notConnected());

    const send = (roomId: string, msg: { type: 'prompt' | 'response'; text: string; threadId?: string; inReplyTo?: string }) =>
      guard(() => {
        const p: Obj = { roomId, type: msg?.type, text: msg?.text };
        if (msg?.threadId !== undefined) p.threadId = msg.threadId;
        if (msg?.inReplyTo !== undefined) p.inReplyTo = msg.inReplyTo;
        return rpc('send', p) as Promise<SendResult>;
      });

    const ask = (roomId: string, text: string, opts?: { threadId?: string; timeoutMs?: number }): Promise<InboundMessage> =>
      guard(
        () =>
          new Promise<InboundMessage>((resolve, reject) => {
            let timeoutMs = ASK_DEFAULT_TIMEOUT_MS;
            const t = opts?.timeoutMs;
            if (typeof t === 'number' && Number.isFinite(t) && t > 0) timeoutMs = Math.min(t, ASK_MAX_TIMEOUT_MS);
            let done = false;
            let frameId: string | undefined;
            let unresolved = true;
            st.unresolvedAsks++;
            const markResolved = () => {
              if (unresolved) {
                unresolved = false;
                st.unresolvedAsks--;
              }
            };
            const finish = (fn: () => void) => {
              if (done) return;
              done = true;
              clearT(timer);
              markResolved();
              if (frameId !== undefined) st.askWaiters.delete(frameId);
              st.askRejects.delete(rejectFn);
              fn();
            };
            const rejectFn = (e: TabBridgeError) => finish(() => reject(e));
            st.askRejects.add(rejectFn);
            const timer = setT(() => rejectFn(tbError('TIMEOUT', 'No response before the timeout')), timeoutMs);
            const msg: { type: 'prompt'; text: string; threadId?: string } = { type: 'prompt', text };
            if (opts?.threadId !== undefined) msg.threadId = opts.threadId;
            send(roomId, msg).then(
              (sr) => {
                if (done) return;
                frameId = sr.frameId;
                markResolved();
                const buffered = st.recentResponses.get(frameId);
                if (buffered) {
                  st.recentResponses.delete(frameId);
                  finish(() => resolve(buffered.m));
                  return;
                }
                st.askWaiters.set(frameId, (m) => finish(() => resolve(m)));
              },
              (e: TabBridgeError) => rejectFn(e),
            );
          }),
      );

    const on = <E extends AgentEventName>(ev: E, cb: (d: AgentEventMap[E]) => void): (() => void) => {
      if (!EVENT_NAMES.includes(ev)) throw tbError('INVALID_MESSAGE', `Unknown event "${String(ev)}"`);
      if (typeof cb !== 'function') throw tbError('INVALID_MESSAGE', 'Listener must be a function');
      if (!st.active) throw tbError('NOT_CONNECTED', 'Session is closed');
      st.listeners.get(ev)!.add(cb as (d: unknown) => void);
      return () => off(ev, cb);
    };

    const off = <E extends AgentEventName>(ev: E, cb: (d: AgentEventMap[E]) => void): void => {
      st.listeners.get(ev)?.delete(cb as (d: unknown) => void);
    };

    const session: TabBridgeSession = {
      apiVersion: 1,
      rooms: () => guard(async () => deepFreeze((await rpc('rooms')) as RoomView[])),
      requestPairing: (opts?: { note?: string }) =>
        guard(async () => {
          const p: Obj = {};
          if (opts?.note !== undefined) p.note = opts.note;
          await rpc('requestPairing', p);
        }),
      send,
      ask,
      sendTask: (roomId: string, task: TaskBody) => guard(() => rpc('sendTask', { roomId, task }) as Promise<SendResult>),
      sendFile: (roomId: string, file: Blob, opts?: { name?: string; threadId?: string }) =>
        guard(async () => {
          if (!(file instanceof Blob)) throw tbError('INVALID_MESSAGE', 'file must be a Blob or File');
          if (file.size > HARD_MAX_FILE_BYTES) throw tbError('FILE_TOO_LARGE', 'File exceeds the size limit');
          const name = opts?.name ?? (file as File).name ?? '';
          const buf = await file.arrayBuffer();
          const p: Obj = { roomId, name: typeof name === 'string' ? name : String(name), bytes: buf };
          if (opts?.threadId !== undefined) p.threadId = opts.threadId;
          return rpc('sendFile', p, [buf]) as Promise<SendResult>;
        }),
      leave: (roomId: string) =>
        guard(async () => {
          await rpc('leave', { roomId });
        }),
      on,
      off,
      close: async () => {
        if (!st.active) return;
        endSession(st);
        await rpc('disconnect').catch(() => {});
      },
    };
    return freeze(session);
  }

  function endSession(st: SessionState): void {
    st.active = false;
    for (const r of [...st.askRejects]) r(tbError('NOT_CONNECTED', 'Session closed'));
    st.listeners.forEach((s) => s.clear());
    st.askWaiters.clear();
    st.recentResponses.clear();
    if (state === st) {
      state = null;
      sessionPromise = null;
    }
  }

  function connect(opts: { apiVersion: 1; agentName: string }): Promise<TabBridgeSession> {
    if (sessionPromise) return sessionPromise;
    const apiVersion: unknown = opts?.apiVersion;
    const agentName: unknown = opts?.agentName;
    const pending = rpc('connect', { apiVersion, agentName }).then(
      () => {
        const st: SessionState = {
          active: true,
          listeners: new Map(EVENT_NAMES.map((n) => [n, new Set()])),
          askWaiters: new Map(),
          unresolvedAsks: 0,
          recentResponses: new Map(),
          askRejects: new Set(),
        };
        state = st;
        return makeSession(st);
      },
      (e: unknown) => {
        if (sessionPromise === pending) sessionPromise = null; // allow a retry after failure
        throw e;
      },
    );
    sessionPromise = pending;
    return pending;
  }

  // ---------------------------------------------------------------- events

  function emit(st: SessionState, ev: AgentEventName, d: unknown): void {
    for (const cb of [...st.listeners.get(ev)!]) {
      try {
        cb(d);
      } catch (e) {
        // A throwing handler must not break dispatch; surface it asynchronously.
        setT(() => {
          throw e;
        }, 0);
      }
    }
  }

  function bufferResponse(st: SessionState, m: InboundMessage): void {
    if (st.unresolvedAsks <= 0 || m.inReplyTo === undefined) return;
    const now = Date.now();
    for (const [k, v] of st.recentResponses) {
      if (now - v.at > RESPONSE_BUFFER_TTL_MS) st.recentResponses.delete(k);
    }
    while (st.recentResponses.size >= RESPONSE_BUFFER_MAX) {
      const oldest = st.recentResponses.keys().next().value as string;
      st.recentResponses.delete(oldest);
    }
    if (!st.recentResponses.has(m.inReplyTo)) st.recentResponses.set(m.inReplyTo, { m, at: now });
  }

  function onEvent(msg: Obj): void {
    const st = state;
    if (!st || !st.active) return;
    const ev = msg.ev as AgentEventName;
    if (!EVENT_NAMES.includes(ev) || !isObj(msg.d)) return;
    const d = msg.d;
    switch (ev) {
      case 'prompt': {
        const m = d as unknown as InboundMessage;
        const reply = (text: string): Promise<SendResult> =>
          st.active ? makeReply(st, m, text) : notConnected();
        emit(st, 'prompt', deepFreeze({ ...m, reply }));
        return;
      }
      case 'response': {
        const m = deepFreeze(d as unknown as InboundMessage);
        const waiter = m.inReplyTo !== undefined ? st.askWaiters.get(m.inReplyTo) : undefined;
        if (waiter) waiter(m);
        else bufferResponse(st, m);
        emit(st, 'response', m);
        return;
      }
      case 'file': {
        if (toStr.call(d.bytes) !== '[object ArrayBuffer]') return;
        const file = new FileCtor([d.bytes as ArrayBuffer], String(d.name), { type: String(d.mime) });
        const out: Obj = { id: d.id, roomId: d.roomId, file, provenance: d.provenance, from: d.from };
        if (d.threadId !== undefined) out.threadId = d.threadId;
        emit(st, 'file', deepFreeze(out));
        return;
      }
      default:
        emit(st, ev, deepFreeze(d));
    }
  }

  function makeReply(st: SessionState, m: InboundMessage, text: string): Promise<SendResult> {
    if (!st.active) return notConnected();
    const p: Obj = { roomId: m.roomId, type: 'response', text, threadId: m.threadId, inReplyTo: m.id };
    return rpc('send', p) as Promise<SendResult>;
  }

  // ---------------------------------------------------------------- ready → define window.tabBridge

  function onReady(d: Obj): void {
    if (isReady) return;
    const versions = Array.isArray(d.apiVersions) ? d.apiVersions.filter((v): v is number => typeof v === 'number') : [];
    const version = typeof d.version === 'string' ? d.version : '';
    isReady = true;
    const api: TabBridgeGlobal = freeze({
      version,
      apiVersions: freeze(versions.slice()),
      connect: (opts: { apiVersion: 1; agentName: string }) => connect(opts),
    });
    try {
      defineProperty(w, 'tabBridge', { value: api, writable: false, configurable: false, enumerable: false });
    } catch {
      return; // something else already owns the name: do not announce
    }
    dispatch(new EventCtor('tabbridge:ready'));
  }

  offer();
})();
