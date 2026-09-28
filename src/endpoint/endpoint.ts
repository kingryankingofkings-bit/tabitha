// Endpoint: one party of TabBridge rooms. SPEC.md §4, §4.1, §4.2, §6.3; DECISIONS.md D2, D6, T6, T7, T14.
//
// Environment-agnostic: used by the isolated content script (kind 'page') and by the side panel
// (kind 'panel'). It never imports background code; the router tells it (via RoomView) what it may
// send and receive, and the E2E transcript bounds those grants from above.
//
// Plaintext only ever appears in: the encrypted frame, the `audit-detail` message (by design, the
// user chose a full-text audit log, D0.2), and the sink (the local agent).

import { TabBridgeError, isErrorCode } from '../shared/errors';
import type { ErrorCode } from '../shared/errors';
import {
  constantTimeEqual,
  decryptFrame,
  deriveRoomKey,
  encryptFrame,
  generateKeyPair,
  sha256Hex,
  transcriptHash,
} from '../shared/crypto';
import { base64ToBytes, bytesToBase64, randomHex32, randomToken, stripControl } from '../shared/encoding';
import { DELIVERY_TIMEOUT_MS, MAX_AGENT_NAME, MAX_NOTE_CHARS } from '../shared/limits';
import { decodeBody, encodeBody, validateR2E, validateTaskBody } from '../shared/protocol';
import type {
  AgentErrorEvent,
  AllowedMime,
  ConfirmBody,
  ContentDetail,
  DirectionGrant,
  E2R,
  EndpointId,
  EndpointKind,
  FileBody,
  FrameHeader,
  FrameId,
  FrameKind,
  InboundFileData,
  InboundMessage,
  InboundTask,
  PeerRef,
  R2E,
  Role,
  RoomId,
  RoomView,
  RuntimePortLike,
  SendResult,
  TaskBody,
  TextBody,
  Transcript,
  TranscriptParty,
} from '../shared/types';
import { validateFile } from '../files/validate';
import { buildProvenance } from '../files/provenance';

export interface EndpointSink {
  hasAgent(): boolean;
  onPrompt(m: InboundMessage): void;
  onResponse(m: InboundMessage): void;
  onTask(t: InboundTask): void;
  onFile(f: InboundFileData): void;
  onRoom(r: RoomView): void;
  onError(e: AgentErrorEvent): void;
  onPaused?(paused: boolean): void;
}

export interface EndpointOptions {
  connect(): RuntimePortLike; // opens a new 'tb.endpoint' port
  kind: 'page' | 'panel';
  sink: EndpointSink;
  now?: () => number;
  deliveryTimeoutMs?: number; // default DELIVERY_TIMEOUT_MS
  reconnectDelayMs?: number; // default 250; exponential to 5000
}

export interface WelcomeInfo {
  endpointId: EndpointId;
  origin: string;
  kind: EndpointKind;
  rooms: RoomView[];
  paused: boolean;
}

// ------------------------------------------------------------------ internals

const MAX_RECONNECT_DELAY_MS = 5_000;
/** Consecutive failed reconnects after which pending sends are rejected NOT_CONNECTED (§6.3). */
const RECONNECT_FAILURES_BEFORE_REJECT = 3;
/** Closed rooms kept for `rooms()`; older ones are pruned. */
const MAX_CLOSED_ROOMS_KEPT = 16;
/** Violation codes on which the router closes the room (§4); we drop keys immediately too. */
const ROOM_FATAL_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>(['DECRYPT_FAILED', 'KEY_CONFIRM_FAILED', 'REPLAY']);

interface PendingSend {
  frameId: FrameId;
  roomId: RoomId;
  resolve(r: SendResult): void;
  reject(e: TabBridgeError): void;
  timer: ReturnType<typeof setTimeout> | undefined;
  settled: boolean;
  acked: boolean;
  earlyReceipt?: { status: 'accepted' | 'rejected' | 'no-agent'; code?: ErrorCode };
  job: OutJob;
}

interface OutJob {
  kind: FrameKind;
  frameId: FrameId;
  plaintext: Uint8Array;
  mime?: AllowedMime;
  detail?: ContentDetail; // absent for 'confirm'
  pending?: PendingSend; // absent for 'confirm'
  cancelled: boolean;
  msg?: Extract<E2R, { t: 'frame' }>; // set once encrypted
  postedOnGen?: number; // port generation the frame was posted on (undefined = never posted)
  resent: boolean; // re-posted after a reconnect: router may have accepted the original
}

interface BoundGrants {
  outbound: DirectionGrant;
  inbound: DirectionGrant;
  expiresAt: number;
}

interface RoomCtx {
  roomId: RoomId;
  view?: RoomView;
  role?: Role; // fixed once keying starts
  closed: boolean;
  privateKey?: CryptoKey;
  publicKeyB64?: string;
  roomKey?: CryptoKey;
  transcriptHash?: string;
  peer?: TranscriptParty; // from the verified transcript
  bound?: BoundGrants; // grants bound into the E2E transcript (upper bound for any RoomView)
  mySeq: number; // next outbound seq
  peerSeq: number; // last accepted inbound seq
  peerConfirmed: boolean;
  queue: OutJob[];
  inflight?: OutJob;
}

function err(code: ErrorCode, message?: string): TabBridgeError {
  return new TabBridgeError(code, message);
}

function codeOf(e: unknown, fallback: ErrorCode): ErrorCode {
  return e instanceof TabBridgeError ? e.code : fallback;
}

function intersectGrant(a: DirectionGrant, b: DirectionGrant): DirectionGrant {
  const files = a.files && b.files;
  return {
    prompts: a.prompts && b.prompts,
    tasks: a.tasks && b.tasks,
    files,
    fileTypes: files ? a.fileTypes.filter((t) => b.fileTypes.includes(t)) : [],
    maxFileBytes: Math.min(a.maxFileBytes, b.maxFileBytes),
  };
}

const CLOSED_GRANT: DirectionGrant = Object.freeze({
  prompts: false,
  tasks: false,
  files: false,
  fileTypes: [] as never[],
  maxFileBytes: 1,
}) as DirectionGrant;

function cloneView(v: RoomView): RoomView {
  return JSON.parse(JSON.stringify(v)) as RoomView;
}

/** Truncate to n UTF-16 units without leaving a dangling high surrogate. */
function truncate(s: string, n: number): string {
  let out = s.slice(0, n);
  const last = out.charCodeAt(out.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) out = out.slice(0, -1);
  return out;
}

// ------------------------------------------------------------------ Endpoint

export class Endpoint {
  readonly #opts: EndpointOptions;
  readonly #sink: EndpointSink;
  readonly #now: () => number;
  readonly #deliveryTimeoutMs: number;
  readonly #reconnectDelayMs: number;

  #port: RuntimePortLike | undefined;
  #portGen = 0;
  #welcomed = false; // current port has received welcome
  #everWelcomed = false;
  #stopped = false;
  #reconnectAttempt = 0;
  #reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  #startPromise: Promise<WelcomeInfo> | undefined;
  #startResolve: ((w: WelcomeInfo) => void) | undefined;
  #startReject: ((e: TabBridgeError) => void) | undefined;

  // Identity: kept private. `endpointId`/`origin` are readable per SPEC; the resume token never is.
  #endpointId: EndpointId | undefined;
  #resumeToken: string | undefined;
  #origin: string | undefined;
  #paused = false;

  #agent: { attached: boolean; name?: string } = { attached: false };
  #rooms = new Map<RoomId, RoomCtx>();
  #pending = new Map<FrameId, PendingSend>();
  #inbox: Promise<void> = Promise.resolve();
  #welcomeGen = -1; // port generation on which a welcome was received
  #minGen = 0; // messages from older port generations are dropped (room state was wiped)

  constructor(opts: EndpointOptions) {
    if (opts.kind !== 'page' && opts.kind !== 'panel') throw err('INVALID_MESSAGE', 'Invalid endpoint kind');
    this.#opts = opts;
    this.#sink = opts.sink;
    this.#now = opts.now ?? (() => Date.now());
    this.#deliveryTimeoutMs = opts.deliveryTimeoutMs ?? DELIVERY_TIMEOUT_MS;
    this.#reconnectDelayMs = opts.reconnectDelayMs ?? 250;
  }

  get endpointId(): EndpointId | undefined {
    return this.#endpointId;
  }

  get origin(): string | undefined {
    return this.#origin;
  }

  // ---------------------------------------------------------------- lifecycle

  start(): Promise<WelcomeInfo> {
    if (this.#startPromise) return this.#startPromise;
    if (this.#stopped) return Promise.reject(err('NOT_CONNECTED'));
    this.#startPromise = new Promise<WelcomeInfo>((resolve, reject) => {
      this.#startResolve = resolve;
      this.#startReject = reject;
    });
    this.#startPromise.catch(() => {}); // callers observe it; avoid unhandled-rejection noise
    this.#openPort();
    return this.#startPromise;
  }

  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#clearReconnect();
    this.#failStart(err('NOT_CONNECTED'));
    this.#rejectAllPending('NOT_CONNECTED');
    this.#wipeRooms(undefined);
    const p = this.#port;
    this.#port = undefined;
    this.#welcomed = false;
    try {
      p?.disconnect();
    } catch {
      /* already gone */
    }
  }

  rooms(): RoomView[] {
    const out: RoomView[] = [];
    for (const ctx of this.#rooms.values()) if (ctx.view) out.push(cloneView(ctx.view));
    return out;
  }

  setAgent(attached: boolean, name?: string): void {
    if (attached) {
      const n = typeof name === 'string' ? truncate(stripControl(name), MAX_AGENT_NAME) : '';
      this.#agent = n ? { attached: true, name: n } : { attached: true };
    } else {
      this.#agent = { attached: false };
    }
    this.#sendAgent();
  }

  requestPairing(note?: string): void {
    this.#requireConnected();
    if (!this.#welcomed) throw err('NOT_CONNECTED');
    const msg: E2R = { t: 'pair-request', v: 1 };
    if (typeof note === 'string') {
      const n = truncate(stripControl(note), MAX_NOTE_CHARS);
      if (n) msg.note = n;
    }
    this.#post(msg);
  }

  leave(roomId: RoomId): void {
    this.#requireConnected();
    const ctx = this.#rooms.get(roomId);
    if (!ctx || !ctx.view) throw err('ROOM_NOT_FOUND');
    if (ctx.closed) throw err('ROOM_CLOSED');
    // Drop keys immediately; the router confirms with a 'room' update.
    this.#closeRoomLocal(ctx, 'user', true);
    this.#post({ t: 'leave', v: 1, roomId });
  }

  // ---------------------------------------------------------------- outbound API

  async sendText(
    roomId: RoomId,
    type: 'prompt' | 'response',
    text: string,
    opts?: { threadId?: string; inReplyTo?: FrameId },
  ): Promise<SendResult> {
    if (type !== 'prompt' && type !== 'response') throw err('INVALID_MESSAGE', 'Invalid message type');
    const ctx = this.#requireActive(roomId);
    if (!this.#outbound(ctx).prompts) throw err('NOT_PERMITTED', 'Prompts are not permitted in this room');
    const inReplyTo = opts?.inReplyTo;
    if (type === 'response' && inReplyTo === undefined) throw err('INVALID_MESSAGE', 'A response requires inReplyTo');
    const body: TextBody = { text, threadId: opts?.threadId ?? randomToken() };
    if (inReplyTo !== undefined) body.inReplyTo = inReplyTo;
    const plaintext = encodeBody(type, body); // strict schema validation (throws INVALID_MESSAGE / PAYLOAD_TOO_LARGE)
    const sha256 = await sha256Hex(plaintext);
    const detail: ContentDetail = { kind: type, text: body.text, threadId: body.threadId, sha256 };
    if (body.inReplyTo !== undefined) detail.inReplyTo = body.inReplyTo;
    return this.#submit(roomId, type, plaintext, detail);
  }

  async sendTask(roomId: RoomId, task: TaskBody): Promise<SendResult> {
    const ctx = this.#requireActive(roomId);
    if (!this.#outbound(ctx).tasks) throw err('NOT_PERMITTED', 'Tasks are not permitted in this room');
    const validated = validateTaskBody(task); // fresh copy: caller mutations after this point are irrelevant
    const plaintext = encodeBody('task', validated);
    const sha256 = await sha256Hex(plaintext);
    return this.#submit(roomId, 'task', plaintext, { kind: 'task', task: validated, sha256 });
  }

  async sendFile(roomId: RoomId, file: { name: string; bytes: Uint8Array }, opts?: { threadId?: string }): Promise<SendResult> {
    const ctx = this.#requireActive(roomId);
    const grant = this.#outbound(ctx);
    if (!grant.files) throw err('NOT_PERMITTED', 'Files are not permitted in this room');
    if (!file || typeof file.name !== 'string' || !(file.bytes instanceof Uint8Array)) throw err('INVALID_MESSAGE', 'Invalid file');
    const bytes = file.bytes.slice(); // snapshot: validation and encryption see the same bytes
    const check = await validateFile({ name: file.name, bytes }, { allowed: grant.fileTypes, maxBytes: grant.maxFileBytes });
    if (!check.ok) throw err(check.code, check.detail);
    // Re-check after the await: the room may have closed or been narrowed meanwhile.
    const ctx2 = this.#requireActive(roomId);
    const grant2 = this.#outbound(ctx2);
    if (!grant2.files || !grant2.fileTypes.includes(check.mime)) throw err('FILE_TYPE_DENIED');
    if (check.size > grant2.maxFileBytes) throw err('FILE_TOO_LARGE');
    const meta: FileBody['meta'] = { name: check.name, mime: check.mime, size: check.size, sha256: check.sha256 };
    if (opts?.threadId !== undefined) meta.threadId = opts.threadId;
    const plaintext = encodeBody('file', { meta, bytes });
    const detail: ContentDetail = { kind: 'file', name: check.name, mime: check.mime, size: check.size, sha256: check.sha256 };
    if (meta.threadId !== undefined) detail.threadId = meta.threadId;
    return this.#submit(roomId, 'file', plaintext, detail, check.mime);
  }

  // ---------------------------------------------------------------- port management

  #openPort(): void {
    let port: RuntimePortLike;
    try {
      port = this.#opts.connect();
    } catch {
      // Extension context invalidated (or similar): stop for good.
      this.#fatal('NOT_CONNECTED');
      return;
    }
    const gen = ++this.#portGen;
    this.#port = port;
    this.#welcomed = false;
    port.onMessage.addListener((raw: unknown) => this.#onPortMessage(port, raw));
    port.onDisconnect.addListener(() => this.#onPortDisconnect(port));
    const hello: E2R = { t: 'hello', v: 1, kind: this.#opts.kind };
    if (this.#endpointId && this.#resumeToken) hello.resume = { endpointId: this.#endpointId, resumeToken: this.#resumeToken };
    try {
      port.postMessage(hello);
    } catch {
      if (this.#portGen === gen) this.#onPortDisconnect(port);
    }
  }

  #onPortDisconnect(port: RuntimePortLike): void {
    if (port !== this.#port) return;
    this.#port = undefined;
    this.#welcomed = false;
    if (this.#stopped) return;
    const attempt = this.#reconnectAttempt;
    if (attempt >= RECONNECT_FAILURES_BEFORE_REJECT) {
      if (!this.#everWelcomed) {
        this.#fatal('NOT_CONNECTED');
        return;
      }
      this.#rejectAllPending('NOT_CONNECTED');
    }
    const delay = Math.min(this.#reconnectDelayMs * 2 ** attempt, MAX_RECONNECT_DELAY_MS);
    this.#reconnectAttempt = attempt + 1;
    this.#clearReconnect();
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = undefined;
      if (!this.#stopped) this.#openPort();
    }, delay);
  }

  #clearReconnect(): void {
    if (this.#reconnectTimer !== undefined) clearTimeout(this.#reconnectTimer);
    this.#reconnectTimer = undefined;
  }

  #onPortMessage(port: RuntimePortLike, raw: unknown): void {
    if (port !== this.#port || this.#stopped) return;
    let m: R2E;
    try {
      m = validateR2E(raw);
    } catch {
      return; // strict validation: malformed router messages are dropped
    }
    const gen = this.#portGen;
    if (m.t === 'rejected') {
      this.#fatal(m.code); // followed by disconnect; nothing else matters
      return;
    }
    if (m.t === 'welcome') {
      if (this.#welcomeGen === gen) return; // duplicate welcome
      this.#welcomeGen = gen;
    } else if (this.#welcomeGen !== gen) {
      return; // nothing but welcome/rejected before welcome
    }
    this.#inbox = this.#inbox
      .then(() => this.#handle(m, gen))
      .catch(() => {
        /* handler errors never break the queue */
      });
  }

  #post(msg: E2R): void {
    if (!this.#port || !this.#welcomed) return;
    try {
      this.#port.postMessage(msg);
    } catch {
      /* disconnect handler takes over */
    }
  }

  #requireConnected(): void {
    if (this.#stopped || !this.#everWelcomed) throw err('NOT_CONNECTED');
  }

  #fatal(code: ErrorCode): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#clearReconnect();
    const p = this.#port;
    this.#port = undefined;
    this.#welcomed = false;
    try {
      p?.disconnect();
    } catch {
      /* ignore */
    }
    const wasStarted = this.#everWelcomed;
    this.#failStart(err(code));
    this.#rejectAllPending('NOT_CONNECTED');
    this.#wipeRooms('endpoint-gone');
    if (wasStarted) this.#emitError({ code, message: err(code).message });
  }

  #failStart(e: TabBridgeError): void {
    const rej = this.#startReject;
    this.#startResolve = undefined;
    this.#startReject = undefined;
    rej?.(e);
  }

  // ---------------------------------------------------------------- inbound dispatch

  async #handle(m: R2E, gen: number): Promise<void> {
    if (this.#stopped) return;
    if (m.t === 'welcome') return this.#onWelcome(m, gen);
    if (gen < this.#minGen) return; // room state was wiped after this message arrived
    switch (m.t) {
      case 'key-request':
        return this.#onKeyRequest(m.roomId);
      case 'room-keys':
        return this.#onRoomKeys(m.roomId, m.transcript);
      case 'room':
        return this.#onRoomView(m.room, true);
      case 'frame':
        return this.#onFrame(m.header, m.ct);
      case 'ack':
        return this.#onAck(m.roomId, m.frameId, m.ok, m.code);
      case 'receipt':
        return this.#onReceipt(m.roomId, m.frameId, m.status, m.code);
      case 'paused':
        this.#paused = m.paused;
        this.#safe(() => this.#sink.onPaused?.(m.paused));
        return;
      case 'error':
        this.#emitError({ code: m.code, message: m.message ?? err(m.code).message });
        return;
      default:
        return;
    }
  }

  #onWelcome(m: Extract<R2E, { t: 'welcome' }>, gen: number): void {
    if (gen !== this.#portGen || this.#welcomed) return; // stale port, or a duplicate welcome
    const first = !this.#everWelcomed;
    const resumed = !first && m.resumed && m.endpointId === this.#endpointId;
    if (!first && !resumed) {
      // Resume refused: keys are useless now; every known room is gone for us.
      this.#wipeRooms('endpoint-gone');
    }
    this.#endpointId = m.endpointId;
    this.#resumeToken = m.resumeToken;
    this.#origin = m.origin;
    this.#welcomed = true;
    this.#everWelcomed = true;
    this.#reconnectAttempt = 0;
    const pausedChanged = this.#paused !== m.paused;
    this.#paused = m.paused;

    if (resumed) {
      const listed = new Set(m.rooms.map((r) => r.roomId));
      for (const ctx of [...this.#rooms.values()]) {
        if (!ctx.closed && !listed.has(ctx.roomId)) this.#closeRoomLocal(ctx, 'endpoint-gone', true);
      }
      // Rooms we closed locally (e.g. leave() while disconnected) that the router still has open.
      for (const v of m.rooms) {
        if (v.state !== 'closed' && this.#rooms.get(v.roomId)?.closed) this.#post({ t: 'leave', v: 1, roomId: v.roomId });
      }
    }
    for (const v of m.rooms) this.#onRoomView(v, !first);

    if (this.#agent.attached || !first) this.#sendAgent(); // resync the router after a reconnect
    if (resumed) {
      // Frames encrypted but not yet acked. If posted on the old port the router may or may not
      // have accepted them, so re-post verbatim; a REPLAY ack for a re-post means "accepted earlier".
      for (const ctx of this.#rooms.values()) {
        const job = ctx.inflight;
        if (!job?.msg || job.postedOnGen === this.#portGen) continue;
        if (job.postedOnGen !== undefined) job.resent = true;
        job.postedOnGen = this.#portGen;
        this.#post(job.msg);
      }
    }
    for (const ctx of this.#rooms.values()) this.#pump(ctx);

    if (first) {
      const resolve = this.#startResolve;
      this.#startResolve = undefined;
      this.#startReject = undefined;
      resolve?.({ endpointId: m.endpointId, origin: m.origin, kind: m.kind, rooms: this.rooms(), paused: m.paused });
    } else if (pausedChanged) {
      this.#safe(() => this.#sink.onPaused?.(m.paused));
    }
  }

  #sendAgent(): void {
    const msg: E2R = { t: 'agent', v: 1, attached: this.#agent.attached };
    if (this.#agent.attached && this.#agent.name) msg.name = this.#agent.name;
    this.#post(msg);
  }

  // ---------------------------------------------------------------- rooms

  #ctx(roomId: RoomId): RoomCtx {
    let ctx = this.#rooms.get(roomId);
    if (!ctx) {
      ctx = { roomId, closed: false, mySeq: 1, peerSeq: 0, peerConfirmed: false, queue: [] };
      this.#rooms.set(roomId, ctx);
    }
    return ctx;
  }

  #onRoomView(v: RoomView, emit: boolean): void {
    const existing = this.#rooms.get(v.roomId);
    if (existing?.closed) {
      // Closed rooms never reopen. Adopt the router's final view (reason) but never re-key.
      if (v.state === 'closed') existing.view = v;
      return;
    }
    if (!existing && v.state === 'closed') {
      if (emit) this.#safe(() => this.#sink.onRoom(cloneView(v)));
      return;
    }
    const ctx = existing ?? this.#ctx(v.roomId);
    if (ctx.role === undefined && v.state !== 'closed') ctx.role = v.role;
    ctx.view = v;
    if (v.state === 'closed') {
      this.#closeRoomLocal(ctx, v.closedReason, false);
    } else if (v.state === 'active') {
      this.#pump(ctx);
    }
    if (emit) this.#safe(() => this.#sink.onRoom(cloneView(v)));
  }

  /** Drop keys, reject pending sends; optionally synthesize & emit a closed view. */
  #closeRoomLocal(ctx: RoomCtx, reason: RoomView['closedReason'], emit: boolean): void {
    if (ctx.closed) return;
    ctx.closed = true;
    ctx.privateKey = undefined;
    ctx.roomKey = undefined;
    ctx.inflight = undefined;
    for (const job of ctx.queue) job.cancelled = true;
    ctx.queue = [];
    for (const p of [...this.#pending.values()]) if (p.roomId === ctx.roomId) this.#settle(p, err('ROOM_CLOSED'));
    if (ctx.view && ctx.view.state !== 'closed') {
      ctx.view = { ...ctx.view, state: 'closed' };
      if (reason) ctx.view.closedReason = reason;
    }
    if (emit && ctx.view) {
      const v = cloneView(ctx.view);
      this.#safe(() => this.#sink.onRoom(v));
    }
    this.#pruneClosed();
  }

  #pruneClosed(): void {
    const closed = [...this.#rooms.values()].filter((c) => c.closed);
    for (let i = 0; i < closed.length - MAX_CLOSED_ROOMS_KEPT; i++) this.#rooms.delete(closed[i]!.roomId);
  }

  /** Forget all rooms. With a reason, emit each open room as closed. */
  #wipeRooms(reason: RoomView['closedReason'] | undefined): void {
    this.#minGen = this.#portGen;
    for (const ctx of [...this.#rooms.values()]) this.#closeRoomLocal(ctx, reason ?? 'endpoint-gone', reason !== undefined);
    this.#rooms.clear();
  }

  #effective(ctx: RoomCtx): { outbound: DirectionGrant; inbound: DirectionGrant; expiresAt: number } {
    const v = ctx.view;
    if (!v) return { outbound: CLOSED_GRANT, inbound: CLOSED_GRANT, expiresAt: 0 };
    if (!ctx.bound) return { outbound: v.outbound, inbound: v.inbound, expiresAt: v.expiresAt };
    // Never allow more than the grant bound into the E2E transcript (OSQ-10): narrowing only.
    return {
      outbound: intersectGrant(v.outbound, ctx.bound.outbound),
      inbound: intersectGrant(v.inbound, ctx.bound.inbound),
      expiresAt: Math.min(v.expiresAt, ctx.bound.expiresAt),
    };
  }

  #outbound(ctx: RoomCtx): DirectionGrant {
    return this.#effective(ctx).outbound;
  }

  #requireActive(roomId: RoomId): RoomCtx {
    if (this.#stopped || !this.#everWelcomed) throw err('NOT_CONNECTED');
    if (typeof roomId !== 'string') throw err('ROOM_NOT_FOUND');
    const ctx = this.#rooms.get(roomId);
    if (!ctx || !ctx.view) throw err('ROOM_NOT_FOUND');
    if (ctx.closed || ctx.view.state === 'closed') throw err('ROOM_CLOSED');
    if (ctx.view.state !== 'active' || !ctx.roomKey || !ctx.peerConfirmed) throw err('ROOM_NOT_ACTIVE');
    if (this.#now() >= this.#effective(ctx).expiresAt) throw err('ROOM_EXPIRED');
    return ctx;
  }

  // ---------------------------------------------------------------- key agreement

  async #onKeyRequest(roomId: RoomId): Promise<void> {
    const existing = this.#rooms.get(roomId);
    if (existing && (existing.closed || existing.privateKey || existing.roomKey)) return; // never re-key a room
    const ctx = this.#ctx(roomId);
    const { privateKey, publicKeyRaw } = await generateKeyPair();
    if (this.#rooms.get(roomId) !== ctx || ctx.closed || ctx.privateKey || ctx.roomKey) return;
    ctx.privateKey = privateKey;
    ctx.publicKeyB64 = bytesToBase64(publicKeyRaw);
    this.#post({ t: 'key-share', v: 1, roomId, publicKey: ctx.publicKeyB64 });
  }

  async #onRoomKeys(roomId: RoomId, t: Transcript): Promise<void> {
    const ctx = this.#rooms.get(roomId);
    if (!ctx || ctx.closed || !ctx.privateKey || !ctx.publicKeyB64 || ctx.roomKey) return;
    const me = this.#endpointId!;
    let role = ctx.role;
    if (role === undefined) {
      if (t.initiator.endpointId === me && t.joiner.endpointId !== me) role = 'initiator';
      else if (t.joiner.endpointId === me && t.initiator.endpointId !== me) role = 'joiner';
    }
    const mine = role === 'initiator' ? t.initiator : role === 'joiner' ? t.joiner : undefined;
    const peer = role === 'initiator' ? t.joiner : role === 'joiner' ? t.initiator : undefined;
    const ok =
      mine !== undefined &&
      peer !== undefined &&
      t.roomId === roomId &&
      mine.endpointId === me &&
      constantTimeEqual(mine.publicKey, ctx.publicKeyB64) &&
      mine.kind === this.#opts.kind &&
      (this.#origin === undefined || mine.origin === this.#origin) &&
      peer.endpointId !== me &&
      peer.publicKey !== ctx.publicKeyB64; // reflection of our own key
    if (!ok || !role || !peer) {
      this.#violation(roomId, 'KEY_CONFIRM_FAILED', undefined, 'Transcript does not match this endpoint');
      return;
    }
    let hash: string;
    let key: CryptoKey;
    try {
      hash = await transcriptHash(t);
      key = await deriveRoomKey(ctx.privateKey, base64ToBytes(peer.publicKey), roomId, hash);
    } catch {
      if (this.#rooms.get(roomId) === ctx && !ctx.closed) this.#violation(roomId, 'KEY_CONFIRM_FAILED', undefined, 'Key derivation failed');
      return;
    }
    if (this.#rooms.get(roomId) !== ctx || ctx.closed || ctx.roomKey) return;
    ctx.role = role;
    ctx.roomKey = key;
    ctx.privateKey = undefined; // no longer needed
    ctx.transcriptHash = hash;
    ctx.peer = peer;
    const g = t.grant;
    ctx.bound =
      role === 'initiator'
        ? { outbound: g.i2j, inbound: g.j2i, expiresAt: g.expiresAt }
        : { outbound: g.j2i, inbound: g.i2j, expiresAt: g.expiresAt };
    const body: ConfirmBody = { transcriptHash: hash };
    ctx.queue.unshift({ kind: 'confirm', frameId: randomHex32(), plaintext: encodeBody('confirm', body), cancelled: false, resent: false });
    this.#pump(ctx);
  }

  // ---------------------------------------------------------------- outbound machinery

  #submit(roomId: RoomId, kind: FrameKind, plaintext: Uint8Array, detail: ContentDetail, mime?: AllowedMime): Promise<SendResult> {
    const ctx = this.#requireActive(roomId); // re-check after any awaits in the caller
    return new Promise<SendResult>((resolve, reject) => {
      const frameId = randomHex32();
      const job: OutJob = { kind, frameId, plaintext, detail, cancelled: false, resent: false };
      if (mime) job.mime = mime;
      const p: PendingSend = { frameId, roomId, resolve, reject, timer: undefined, settled: false, acked: false, job };
      job.pending = p;
      p.timer = setTimeout(() => this.#settle(p, err('DELIVERY_TIMEOUT')), this.#deliveryTimeoutMs);
      this.#pending.set(frameId, p);
      ctx.queue.push(job);
      this.#pump(ctx);
    });
  }

  /** Outbound frames are serialized per room: the next one is sent only after the previous ack. */
  #pump(ctx: RoomCtx): void {
    if (ctx.inflight || ctx.closed || !this.#welcomed || this.#stopped || !ctx.roomKey) return;
    let job: OutJob | undefined;
    while ((job = ctx.queue.shift()) && job.cancelled) {
      /* skip */
    }
    if (!job) return;
    // Data frames only once the room is active (the confirm frame goes first, while keying).
    if (job.kind !== 'confirm' && (ctx.view?.state !== 'active' || !ctx.peerConfirmed)) {
      ctx.queue.unshift(job);
      return;
    }
    ctx.inflight = job;
    void this.#transmit(ctx, job);
  }

  async #transmit(ctx: RoomCtx, job: OutJob): Promise<void> {
    const header: FrameHeader = {
      v: 1,
      frameId: job.frameId,
      roomId: ctx.roomId,
      from: this.#endpointId!,
      seq: ctx.mySeq,
      kind: job.kind,
      size: job.plaintext.length,
      ts: this.#now(),
    };
    if (job.mime) header.mime = job.mime;
    let ct: string;
    try {
      ct = await encryptFrame(ctx.roomKey!, header, job.plaintext);
    } catch (e) {
      if (ctx.inflight === job) ctx.inflight = undefined;
      if (job.pending) this.#settle(job.pending, err(codeOf(e, 'INTERNAL')));
      this.#pump(ctx);
      return;
    }
    if (ctx.inflight !== job || this.#rooms.get(ctx.roomId) !== ctx || ctx.closed) return;
    if (job.cancelled) {
      ctx.inflight = undefined;
      this.#pump(ctx);
      return;
    }
    job.plaintext = new Uint8Array(0); // plaintext no longer needed
    job.msg = { t: 'frame', v: 1, header, ct };
    if (this.#welcomed && this.#port) {
      job.postedOnGen = this.#portGen;
      this.#post(job.msg);
    }
    // else: disconnected meanwhile — posted on the next welcome (see below).
  }

  #onAck(roomId: RoomId, frameId: FrameId, ok: boolean, code: ErrorCode | undefined): void {
    const ctx = this.#rooms.get(roomId);
    const job = ctx?.inflight;
    if (!ctx || !job || job.frameId !== frameId || !job.msg) return;
    ctx.inflight = undefined;
    // Re-posted after reconnect and the router says REPLAY: it had accepted the original post.
    const accepted = ok || (job.resent && code === 'REPLAY');
    if (accepted) {
      ctx.mySeq = job.msg.header.seq + 1;
      if (job.detail) this.#post({ t: 'audit-detail', v: 1, roomId, frameId, direction: 'sent', detail: job.detail });
      const p = job.pending;
      if (p && !p.settled) {
        p.acked = true;
        if (p.earlyReceipt) this.#applyReceipt(p, p.earlyReceipt.status, p.earlyReceipt.code);
      }
    } else {
      // Router did not advance seq; mySeq stays, so no gap is created.
      const c: ErrorCode = code ?? 'INTERNAL';
      if (job.pending) this.#settle(job.pending, err(c));
      else if (job.kind === 'confirm') this.#emitError({ code: c, message: 'Key confirmation frame was rejected', roomId });
    }
    job.msg = undefined;
    this.#pump(ctx);
  }

  #onReceipt(roomId: RoomId, frameId: FrameId, status: 'accepted' | 'rejected' | 'no-agent', code: ErrorCode | undefined): void {
    const p = this.#pending.get(frameId);
    if (!p || p.roomId !== roomId || p.settled) return;
    if (!p.acked) {
      p.earlyReceipt = code === undefined ? { status } : { status, code };
      return;
    }
    this.#applyReceipt(p, status, code);
  }

  #applyReceipt(p: PendingSend, status: 'accepted' | 'rejected' | 'no-agent', code: ErrorCode | undefined): void {
    if (status === 'accepted') this.#settle(p, { frameId: p.frameId, roomId: p.roomId, status: 'accepted' });
    else if (status === 'no-agent') this.#settle(p, err('NO_AGENT'));
    else this.#settle(p, err(code && isErrorCode(code) ? code : 'VALIDATION_FAILED'));
  }

  #settle(p: PendingSend, result: SendResult | TabBridgeError): void {
    if (p.settled) return;
    p.settled = true;
    if (p.timer !== undefined) clearTimeout(p.timer);
    this.#pending.delete(p.frameId);
    p.job.cancelled = true; // if not yet posted, it will never be
    if (result instanceof TabBridgeError) p.reject(result);
    else p.resolve(result);
  }

  #rejectAllPending(code: ErrorCode): void {
    for (const p of [...this.#pending.values()]) this.#settle(p, err(code));
  }

  // ---------------------------------------------------------------- inbound frames

  async #onFrame(h: FrameHeader, ct: string): Promise<void> {
    const ctx = this.#rooms.get(h.roomId);
    if (!ctx || ctx.closed) return; // unknown/closed room: drop
    if (!ctx.roomKey || !ctx.peer || !ctx.transcriptHash) {
      this.#violation(h.roomId, 'ROOM_NOT_ACTIVE', h.frameId, 'Frame before key agreement');
      return;
    }
    // The AAD binds `from`, but our own frames would also authenticate (same key): reject
    // anything not claiming to come from the transcript peer (reflection / misrouting).
    if (h.from !== ctx.peer.endpointId) {
      this.#violation(h.roomId, 'SPOOFED_SENDER', h.frameId, 'Frame is not from the room peer');
      return;
    }
    if (h.seq !== ctx.peerSeq + 1) {
      this.#violation(h.roomId, 'REPLAY', h.frameId, 'Unexpected sequence number');
      return;
    }
    if ((h.kind === 'confirm') !== (h.seq === 1)) {
      this.#violation(h.roomId, 'KEY_CONFIRM_FAILED', h.frameId, 'The first frame must be the key confirmation');
      return;
    }
    let pt: Uint8Array;
    try {
      pt = await decryptFrame(ctx.roomKey, h, ct);
    } catch {
      if (!this.#live(ctx)) return;
      // A confirm that does not decrypt means the two sides derived different keys.
      this.#violation(h.roomId, h.kind === 'confirm' ? 'KEY_CONFIRM_FAILED' : 'DECRYPT_FAILED', h.frameId);
      return;
    }
    if (!this.#live(ctx)) return;
    ctx.peerSeq = h.seq; // authentic and in order: consumed (the router advanced too)
    if (h.kind === 'confirm') return this.#onPeerConfirm(ctx, h, pt);
    return this.#onData(ctx, h, pt);
  }

  #live(ctx: RoomCtx): boolean {
    return this.#rooms.get(ctx.roomId) === ctx && !ctx.closed;
  }

  #onPeerConfirm(ctx: RoomCtx, h: FrameHeader, pt: Uint8Array): void {
    let body: ConfirmBody;
    try {
      body = decodeBody('confirm', pt);
    } catch {
      this.#violation(ctx.roomId, 'KEY_CONFIRM_FAILED', h.frameId, 'Malformed key confirmation');
      return;
    }
    if (!constantTimeEqual(body.transcriptHash, ctx.transcriptHash!)) {
      this.#violation(ctx.roomId, 'KEY_CONFIRM_FAILED', h.frameId, 'Transcript hash mismatch');
      return;
    }
    ctx.peerConfirmed = true;
    this.#post({ t: 'confirmed', v: 1, roomId: ctx.roomId });
    this.#pump(ctx);
  }

  async #onData(ctx: RoomCtx, h: FrameHeader, pt: Uint8Array): Promise<void> {
    const roomId = ctx.roomId;
    const reject = (code: ErrorCode, message?: string): void => {
      this.#post({ t: 'receipt', v: 1, roomId, frameId: h.frameId, status: 'rejected', code });
      this.#violation(roomId, code, h.frameId, message);
    };
    if (!ctx.peerConfirmed || ctx.view?.state !== 'active') return reject('ROOM_NOT_ACTIVE');
    const eff = this.#effective(ctx);
    if (this.#now() >= eff.expiresAt) return reject('ROOM_EXPIRED');
    const inbound = eff.inbound;
    // Grant check on the authenticated header before parsing the body.
    if ((h.kind === 'prompt' || h.kind === 'response') && !inbound.prompts) return reject('NOT_PERMITTED');
    if (h.kind === 'task' && !inbound.tasks) return reject('NOT_PERMITTED');
    if (h.kind === 'file' && (!inbound.files || !h.mime || !inbound.fileTypes.includes(h.mime))) return reject('NOT_PERMITTED');

    let body: TextBody | TaskBody | FileBody;
    try {
      body = decodeBody(h.kind, pt) as TextBody | TaskBody | FileBody;
    } catch (e) {
      return reject(codeOf(e, 'INVALID_MESSAGE'));
    }

    const peer = ctx.peer!;
    const from: PeerRef = { origin: peer.origin, kind: peer.kind };
    const agentName = ctx.view?.peer.agentName;
    if (agentName !== undefined) from.agentName = agentName;
    let deliver: () => void;
    let detail: ContentDetail;

    if (h.kind === 'prompt' || h.kind === 'response') {
      const b = body as TextBody;
      const sha256 = await sha256Hex(pt);
      if (!this.#live(ctx)) return;
      const msg: InboundMessage = {
        id: h.frameId,
        roomId,
        type: h.kind,
        text: b.text,
        threadId: b.threadId,
        from,
        sentAt: h.ts,
        receivedAt: this.#now(),
      };
      if (b.inReplyTo !== undefined) msg.inReplyTo = b.inReplyTo;
      detail = { kind: h.kind, text: b.text, threadId: b.threadId, sha256 };
      if (b.inReplyTo !== undefined) detail.inReplyTo = b.inReplyTo;
      deliver = h.kind === 'prompt' ? () => this.#sink.onPrompt(msg) : () => this.#sink.onResponse(msg);
    } else if (h.kind === 'task') {
      const task = body as TaskBody;
      const sha256 = await sha256Hex(pt);
      if (!this.#live(ctx)) return;
      const t: InboundTask = { id: h.frameId, roomId, task, from, sentAt: h.ts, receivedAt: this.#now() };
      detail = { kind: 'task', task, sha256 };
      deliver = () => this.#sink.onTask(t);
    } else {
      const { meta, bytes } = body as FileBody;
      if (meta.size > inbound.maxFileBytes || bytes.length > inbound.maxFileBytes) return reject('FILE_TOO_LARGE');
      if (meta.size !== bytes.length) return reject('VALIDATION_FAILED', 'File size does not match metadata');
      if (meta.mime !== h.mime) return reject('FILE_TYPE_MISMATCH', 'Metadata type does not match header');
      const check = await validateFile(
        { name: meta.name, bytes, declaredMime: meta.mime },
        { allowed: inbound.fileTypes, maxBytes: inbound.maxFileBytes },
      );
      if (!this.#live(ctx)) return;
      if (!check.ok) return reject(check.code, check.detail);
      if (check.mime !== h.mime || check.mime !== meta.mime) return reject('FILE_TYPE_MISMATCH');
      const digest = await sha256Hex(bytes);
      if (!this.#live(ctx)) return;
      if (!constantTimeEqual(digest, meta.sha256)) return reject('FILE_HASH_MISMATCH');
      const receivedAt = this.#now();
      let provenance;
      try {
        provenance = buildProvenance({ from, roomId, frameId: h.frameId, sha256: digest, mime: check.mime, size: bytes.length, sentAt: h.ts, receivedAt });
      } catch (e) {
        return reject(codeOf(e, 'VALIDATION_FAILED'));
      }
      const f: InboundFileData = { id: h.frameId, roomId, name: check.name, mime: check.mime, bytes, provenance, from };
      if (meta.threadId !== undefined) f.threadId = meta.threadId;
      detail = { kind: 'file', name: check.name, mime: check.mime, size: bytes.length, sha256: digest };
      if (meta.threadId !== undefined) detail.threadId = meta.threadId;
      deliver = () => this.#sink.onFile(f);
    }

    let hasAgent = false;
    try {
      hasAgent = this.#sink.hasAgent() === true;
    } catch {
      hasAgent = false;
    }
    if (!hasAgent) {
      this.#post({ t: 'receipt', v: 1, roomId, frameId: h.frameId, status: 'no-agent' });
      return;
    }
    this.#post({ t: 'receipt', v: 1, roomId, frameId: h.frameId, status: 'accepted' });
    this.#safe(deliver);
    this.#post({ t: 'audit-detail', v: 1, roomId, frameId: h.frameId, direction: 'received', detail });
  }

  // ---------------------------------------------------------------- errors

  #violation(roomId: RoomId, code: ErrorCode, frameId?: FrameId, message?: string): void {
    const msg: E2R = { t: 'violation', v: 1, roomId, code };
    if (frameId !== undefined) msg.frameId = frameId;
    if (message !== undefined) msg.message = message.slice(0, 500);
    this.#post(msg);
    const ev: AgentErrorEvent = { code, message: message ?? err(code).message, roomId };
    if (frameId !== undefined) ev.frameId = frameId;
    this.#emitError(ev);
    if (ROOM_FATAL_CODES.has(code)) {
      const ctx = this.#rooms.get(roomId);
      if (ctx && !ctx.closed) this.#closeRoomLocal(ctx, code === 'KEY_CONFIRM_FAILED' ? 'key-confirm-failed' : 'violation', true);
    }
  }

  #emitError(e: AgentErrorEvent): void {
    this.#safe(() => this.#sink.onError(e));
  }

  #safe(fn: () => void): void {
    try {
      fn();
    } catch {
      /* sink exceptions never break the endpoint */
    }
  }
}
