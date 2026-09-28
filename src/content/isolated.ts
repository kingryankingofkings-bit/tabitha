// Isolated-world content script. SPEC.md §1.2, §6.1, §3 (AgentRPC); DECISIONS.md T11, T12, OSQ-1/2/3.
//
// 1. Starts an Endpoint(kind 'page') on the 'tb.endpoint' runtime port.
// 2. Captures exactly one private MessagePort from the MAIN-world shim (first hs1 from this window).
// 3. After the router's welcome, posts {t:'ready'}; if rejected, closes the port and does nothing else.
// 4. Serves AgentRPC requests from the page, strictly validated.

import { Endpoint, type EndpointSink } from '../endpoint/endpoint';
import { ext } from '../platform/ext';
import { TabBridgeError, toErrorPayload } from '../shared/errors';
import { stripControl } from '../shared/encoding';
import {
  API_VERSIONS,
  EXT_VERSION,
  HARD_MAX_FILE_BYTES,
  HEX32_RE,
  MAX_AGENT_NAME,
  MAX_NOTE_CHARS,
  MAX_TEXT_BYTES,
  PORT_ENDPOINT,
} from '../shared/limits';
import type { AgentEventName, IsolatedMessage, RuntimePortLike } from '../shared/types';

/** Max concurrent in-flight page requests (each send holds a slot until delivery resolves). */
const MAX_INFLIGHT_REQUESTS = 64;
const LOADED_FLAG = '__tabbridgeIsolatedLoaded';

type Obj = Record<string, unknown>;

function bad(what: string): never {
  throw new TabBridgeError('INVALID_MESSAGE', `Invalid request: ${what}`);
}

function isPlainObject(x: unknown): x is Obj {
  return typeof x === 'object' && x !== null && Object.prototype.toString.call(x) === '[object Object]';
}

/** Exact-shape check. Optional keys may be present with value `undefined` (structured clone keeps them). */
function shape(x: unknown, what: string, required: readonly string[], optional: readonly string[] = []): Obj {
  if (!isPlainObject(x)) bad(`${what} must be an object`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(x)) if (!allowed.has(k)) bad(`${what} has unknown key "${k}"`);
  for (const k of required) if (x[k] === undefined) bad(`${what}.${k} is required`);
  return x;
}

function str(x: unknown, what: string, maxLen: number): string {
  if (typeof x !== 'string' || x.length > maxLen) bad(`${what} must be a string of at most ${maxLen} chars`);
  return x;
}

function optStr(x: unknown, what: string, maxLen: number): string | undefined {
  return x === undefined ? undefined : str(x, what, maxLen);
}

function roomId(x: unknown): string {
  if (typeof x !== 'string' || !HEX32_RE.test(x)) bad('roomId');
  return x;
}

function main(): void {
  const g = globalThis as unknown as Record<string, unknown>;
  if (g[LOADED_FLAG]) return; // injected twice into the same isolated world
  g[LOADED_FLAG] = true;
  if (window.top !== window) return; // top frame only (registration also sets allFrames:false)

  let pagePort: MessagePort | null = null;
  let ready = false; // router welcomed us
  let dead = false; // router rejected us: never talk to the page again
  let agentAttached = false;
  let inflight = 0;

  const post = (msg: IsolatedMessage, transfer?: Transferable[]): boolean => {
    if (!pagePort || dead) return false;
    try {
      pagePort.postMessage(msg, transfer ?? []);
      return true;
    } catch {
      return false;
    }
  };

  const emit = (ev: AgentEventName, d: unknown, transfer?: Transferable[]): void => {
    if (!agentAttached || !pagePort) return;
    if (!post({ t: 'ev', ev, d }, transfer)) detachAgent();
  };

  const sink: EndpointSink = {
    hasAgent: () => agentAttached && pagePort !== null && !dead,
    onPrompt: (m) => emit('prompt', m),
    onResponse: (m) => emit('response', m),
    onTask: (t) => emit('task', t),
    onFile: (f) => {
      const buf = f.bytes.slice().buffer; // standalone buffer, transferred to the page
      const d: Obj = { id: f.id, roomId: f.roomId, name: f.name, mime: f.mime, bytes: buf, provenance: f.provenance, from: f.from };
      if (f.threadId !== undefined) d.threadId = f.threadId;
      emit('file', d, [buf]);
    },
    onRoom: (r) => emit('room', r),
    onError: (e) => emit('error', e),
  };

  const endpoint = new Endpoint({
    connect: () => ext.runtime.connect({ name: PORT_ENDPOINT }) as unknown as RuntimePortLike,
    kind: 'page',
    sink,
  });

  function detachAgent(): void {
    if (!agentAttached) return;
    agentAttached = false;
    try {
      endpoint.setAgent(false);
    } catch {
      /* ignore */
    }
  }

  const sendReady = (): void => {
    post({ t: 'ready', apiVersions: [...API_VERSIONS], version: EXT_VERSION });
  };

  // ---------------------------------------------------------------- handshake (§6.1)

  const onWindowMessage = (event: MessageEvent): void => {
    if (pagePort || dead) return;
    if (event.source !== window) return;
    const data: unknown = event.data;
    if (!isPlainObject(data) || data.__tabbridge !== 'hs1' || data.v !== 1) return;
    const ports = event.ports;
    if (!ports || ports.length !== 1) return;
    const port = ports[0]!;
    pagePort = port; // first valid hs1 wins; all later ones are ignored
    window.removeEventListener('message', onWindowMessage, true);
    port.onmessage = (ev: MessageEvent) => void onPageMessage(ev.data);
    port.onmessageerror = () => {};
    port.addEventListener('close', () => {
      // Page side gone (supported in newer browsers): detach but keep the endpoint alive.
      if (pagePort === port) pagePort = null;
      detachAgent();
    });
    post({ t: 'bound' });
    if (ready) sendReady();
  };
  window.addEventListener('message', onWindowMessage, true);

  endpoint.start().then(
    () => {
      if (dead) return;
      ready = true;
      if (pagePort) sendReady();
      // Announce ourselves only once the router accepted this origin (limits OSQ-1 detection).
      else window.postMessage({ __tabbridge: 'hs0' }, '*');
    },
    () => {
      // Rejected (origin not enabled, etc.): nothing is ever defined in the page.
      dead = true;
      window.removeEventListener('message', onWindowMessage, true);
      if (pagePort) {
        try {
          pagePort.onmessage = null;
          pagePort.close();
        } catch {
          /* ignore */
        }
        pagePort = null;
      }
    },
  );

  // ---------------------------------------------------------------- AgentRPC server

  async function onPageMessage(raw: unknown): Promise<void> {
    if (dead) return;
    if (!isPlainObject(raw)) return;
    const id = raw.id;
    if (typeof id !== 'number' || !Number.isSafeInteger(id) || id < 0) return; // cannot even reply
    if (inflight >= MAX_INFLIGHT_REQUESTS) {
      post({ t: 'res', id, ok: false, e: { code: 'RATE_LIMITED', message: 'Too many concurrent requests' } });
      return;
    }
    inflight++;
    try {
      const r = await dispatch(raw);
      post({ t: 'res', id, ok: true, r: r === undefined ? null : r });
    } catch (e) {
      post({ t: 'res', id, ok: false, e: toErrorPayload(e) });
    } finally {
      inflight--;
    }
  }

  async function dispatch(req: Obj): Promise<unknown> {
    const m = req.m;
    switch (m) {
      case 'connect': {
        shape(req, 'request', ['id', 'm', 'p']);
        const p = shape(req.p, 'p', ['apiVersion', 'agentName']);
        if (!ready) throw new TabBridgeError('NOT_CONNECTED');
        if (typeof p.apiVersion !== 'number' || !API_VERSIONS.includes(p.apiVersion))
          throw new TabBridgeError('UNSUPPORTED_VERSION', `Supported apiVersions: ${API_VERSIONS.join(',')}`);
        const name = stripControl(str(p.agentName, 'agentName', MAX_AGENT_NAME * 4));
        if (name.length < 1 || name.length > MAX_AGENT_NAME) bad(`agentName must be 1..${MAX_AGENT_NAME} characters`);
        agentAttached = true;
        endpoint.setAgent(true, name);
        return { apiVersion: 1 };
      }
      case 'rooms':
      case 'disconnect': {
        shape(req, 'request', ['id', 'm'], ['p']);
        if (req.p !== undefined) bad('unexpected params');
        break;
      }
      case 'requestPairing':
      case 'send':
      case 'sendTask':
      case 'sendFile':
      case 'leave':
        shape(req, 'request', m === 'requestPairing' ? ['id', 'm'] : ['id', 'm', 'p'], m === 'requestPairing' ? ['p'] : []);
        break;
      default:
        bad('unknown method');
    }
    if (!ready || !agentAttached) throw new TabBridgeError('NOT_CONNECTED');

    switch (m) {
      case 'rooms':
        return endpoint.rooms();
      case 'disconnect':
        detachAgent();
        return null;
      case 'requestPairing': {
        const p = req.p === undefined ? {} : shape(req.p, 'p', [], ['note']);
        const note = optStr(p.note, 'note', MAX_NOTE_CHARS);
        endpoint.requestPairing(note);
        return null;
      }
      case 'send': {
        const p = shape(req.p, 'p', ['roomId', 'type', 'text'], ['threadId', 'inReplyTo']);
        const type = p.type;
        if (type !== 'prompt' && type !== 'response') bad('type');
        const text = str(p.text, 'text', MAX_TEXT_BYTES);
        const opts: { threadId?: string; inReplyTo?: string } = {};
        const threadId = optStr(p.threadId, 'threadId', 64);
        const inReplyTo = optStr(p.inReplyTo, 'inReplyTo', 32);
        if (threadId !== undefined) opts.threadId = threadId;
        if (inReplyTo !== undefined) opts.inReplyTo = inReplyTo;
        return endpoint.sendText(roomId(p.roomId), type, text, opts);
      }
      case 'sendTask': {
        const p = shape(req.p, 'p', ['roomId', 'task']);
        if (!isPlainObject(p.task)) bad('task');
        return endpoint.sendTask(roomId(p.roomId), p.task as never); // strict schema check in Endpoint
      }
      case 'sendFile': {
        const p = shape(req.p, 'p', ['roomId', 'name', 'bytes'], ['threadId']);
        const name = str(p.name, 'name', 4096);
        const buf = p.bytes;
        if (Object.prototype.toString.call(buf) !== '[object ArrayBuffer]') bad('bytes must be an ArrayBuffer');
        if ((buf as ArrayBuffer).byteLength > HARD_MAX_FILE_BYTES) throw new TabBridgeError('FILE_TOO_LARGE');
        const threadId = optStr(p.threadId, 'threadId', 64);
        const bytes = new Uint8Array((buf as ArrayBuffer).slice(0));
        return endpoint.sendFile(roomId(p.roomId), { name, bytes }, threadId === undefined ? undefined : { threadId });
      }
      case 'leave': {
        const p = shape(req.p, 'p', ['roomId']);
        endpoint.leave(roomId(p.roomId));
        return null;
      }
      default:
        return bad('unknown method');
    }
  }
}

main();
