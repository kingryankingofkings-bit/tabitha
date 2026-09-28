# TabBridge — Technical Specification (v1)

> **This document is the source of truth.** Code MUST match it. To deviate, update this file
> first (with a changelog line at the bottom) and then change code.
> TypeScript contracts in §3 are mirrored verbatim in `src/shared/types.ts`.

## 0. Conventions
- Language: TypeScript (strict), bundled with esbuild to IIFE scripts (MV3 content scripts
  cannot be modules). Tests: vitest (Node 22, WebCrypto via `globalThis.crypto`).
- IDs (`EndpointId`, `RoomId`, `FrameId`, `resumeToken`): 32 lowercase hex chars (128 bits,
  CSPRNG). Pairing code: 6 decimal digits (string, may start with 0).
- Time: epoch milliseconds (`number`). Byte sizes: bytes.
- "canonical JSON": `JSON.stringify` with object keys sorted recursively; `undefined`
  properties omitted; no whitespace. Used for AAD, transcript hash, audit hashes.
- Every wire message has `v: 1`. Validators are **strict**: unknown keys, wrong types, or
  out-of-range values → `INVALID_MESSAGE`.
- All paths below are relative to repo root.

## 1. Components & data flow

```
Page main world ──(private MessagePort, AgentRPC §6)──► Isolated content script
  src/content/page-api.ts                                src/content/isolated.ts
                                                          └─ Endpoint (src/endpoint/endpoint.ts)
                                                                │ runtime.Port "tb.endpoint" (§4)
Side panel (src/ui/sidepanel) ─ Endpoint(kind:'panel') ─────────┤
                                                                ▼
                                      Background: Router (src/background/router.ts)
                                       ├─ permissions.ts  (grant checks, rate limits)
                                       ├─ pairing.ts      (code state machine)
                                       ├─ audit.ts        (hash-chained log)
                                       ├─ state.ts        (storage.session persistence)
                                       └─ platform.ts     (content-script registration, badge, tabs)
Popup / Dashboard / Side panel ── runtime.Port "tb.ui" (UiRPC §7) ──► Router
```

### 1.1 Lifecycle: enable site
1. Popup click → (no await) `ui:site.enable{origin}` → router stores pending origin, returns
   `{status:'pending-permission'}` if host permission is missing.
2. Popup → `permissions.request({origins:[matchPattern(origin)]})` (browser prompt).
3. Popup → `ui:site.enable{origin}` again; router checks `permissions.contains` → adds origin
   to `settings.sites`, (re)registers content scripts, injects into already-open matching
   tabs, audits `site.enabled`. Router ALSO listens to `permissions.onAdded` and completes
   pending enables (popup may close during the browser prompt).

### 1.2 Lifecycle: endpoint connect
1. `isolated.js` (document_start, top frame) creates `Endpoint(kind:'page')` →
   `runtime.connect({name:'tb.endpoint'})` → `hello`.
2. Router derives `SenderInfo` from `port.sender` (never from message) and admits only if:
   `tabId>=0 && frameId===0 && origin is http(s) && origin ∈ settings.sites`. Else sends
   `rejected{code}` and disconnects; the page API is **never defined**.
3. Router replies `welcome{endpointId, resumeToken, ...}`. Isolated script posts `{t:'ready'}`
   on the private port; `page-api.js` defines `window.tabBridge` and dispatches
   `window` event `tabbridge:ready`.
4. Side panel: `Endpoint(kind:'panel')`; router admits if sender URL is exactly
   `<extensionOrigin>/ui/sidepanel.html` (query/hash ignored) and `sender.id===runtime.id`.
   Panel origin label: `"tabbridge://console"`.

### 1.3 Lifecycle: pairing → active room
```
UI(A): pair.start{endpoint:A, proposal} ─► Router: PairingManager.start → code (shown in UI only)
UI(B): pair.lookup{code, endpoint:B}   ─► preview (origins + both grants)
UI(B): pair.approve{code, endpoint:B}  ─► Router creates Room(state 'keying'), sends key-request to A and B
A,B:   key-share{publicKey}            ─► when both received: Router sends room-keys{transcript} to both
A,B:   derive key; send frame kind 'confirm' (seq 1) body {transcriptHash}
A,B:   on peer confirm decrypted & hash equal → 'confirmed'
Router: both confirmed → state 'active' → room{RoomView} to both; audit room.opened
```
### 1.4 Lifecycle: message
```
Agent A ─send─► Endpoint A: outbound grant check → sender-side validation → encode body →
  AES-GCM(key, iv, AAD=canonical(header)) → frame ─► Router checks (§5.3) → forward to B,
  ack{ok} to A, audit frame.routed ─► Endpoint B: seq check → decrypt → decode → receiver-side
  validation (inbound grant, schemas, file checks) → receipt{accepted} → deliver to agent →
  audit-detail{received}. Endpoint A resolves send() on receipt{accepted}; A sends
  audit-detail{sent} after ack ok.
```

## 2. Module map & ownership

| Path | Responsibility |
|---|---|
| `src/shared/limits.ts` | All numeric limits & enums (§8) |
| `src/shared/errors.ts` | `ErrorCode`, `TabBridgeError`, helpers |
| `src/shared/types.ts` | All contracts in §3 |
| `src/shared/encoding.ts` | base64, hex, utf8, canonicalJson, randomHex, byteLength |
| `src/shared/protocol.ts` | Strict validators for every wire message; body codec; AAD |
| `src/shared/crypto.ts` | ECDH/HKDF/AES-GCM, transcript hash, sha256Hex |
| `src/files/validate.ts` | Type detection, name sanitization, `validateFile` |
| `src/files/provenance.ts` | `buildProvenance` |
| `src/background/permissions.ts` | Proposal validation, grant checks, narrowing, rate limit |
| `src/background/pairing.ts` | `PairingManager` |
| `src/background/audit.ts` | `AuditLog`, `verifyChain`, `hashEntry` |
| `src/background/state.ts` | `RouterStateStore` (persist/restore router state) |
| `src/background/router.ts` | `Router` (PEP, routing, UI RPC handlers) |
| `src/background/platform.ts` | Chrome/Firefox glue implementing `RouterPlatform` |
| `src/background/index.ts` | Wires listeners (`onConnect`, `tabs.onRemoved`, `alarms`, `permissions.onAdded`) |
| `src/platform/ext.ts` | `ext` = `globalThis.browser ?? globalThis.chrome` |
| `src/endpoint/endpoint.ts` | `Endpoint` class (environment-agnostic) |
| `src/content/isolated.ts` | Handshake + Endpoint + AgentRPC server |
| `src/content/page-api.ts` | MAIN-world shim: `window.tabBridge` |
| `src/ui/lib/client.ts` | `UiClient` for `tb.ui` port |
| `src/ui/{popup,dashboard,sidepanel}/*` | UI pages |
| `src/ui/styles/tokens.css`, `base.css` | Design tokens (DESIGN.md) |
| `scripts/build.mjs` | Build `dist/chrome`, `dist/firefox`, `dist/chrome-e2e` |
| `test/helpers/*` | `FakePort` pair, `MemoryKV`, `MemoryAuditStore`, fake platform |

## 3. Contracts (mirrored in `src/shared/types.ts`)

```ts
export type Hex32 = string;
export type EndpointId = Hex32; export type RoomId = Hex32; export type FrameId = Hex32;
export type EndpointKind = 'page' | 'panel' | 'native';          // 'native' reserved, always rejected in v1
export type AllowedMime =
  | 'text/plain' | 'text/markdown' | 'text/csv' | 'application/json'
  | 'image/png' | 'image/jpeg' | 'image/gif' | 'image/webp' | 'application/pdf';
export type FrameKind = 'confirm' | 'prompt' | 'response' | 'task' | 'file';
export type TaskStatus = 'queued' | 'running' | 'blocked' | 'done' | 'failed' | 'cancelled';
export type Direction = 'i2j' | 'j2i';                           // initiator→joiner, joiner→initiator
export type Role = 'initiator' | 'joiner';

// ---------- Grants ----------
export interface DirectionGrant {
  prompts: boolean;            // may send 'prompt' and 'response'
  tasks: boolean;              // may send 'task'
  files: boolean;              // may send 'file'
  fileTypes: AllowedMime[];    // subset of ALLOWED_MIMES; [] when files=false allowed
  maxFileBytes: number;        // 1..HARD_MAX_FILE_BYTES
}
export interface RateLimit { framesPerMinute: number; bytesPerMinute: number; }
export interface GrantProposal { i2j: DirectionGrant; j2i: DirectionGrant; ttlMs: number; }
export interface Grant { i2j: DirectionGrant; j2i: DirectionGrant; expiresAt: number; rate: RateLimit; }
export interface GrantNarrowing {
  i2j?: Partial<DirectionGrant>; j2i?: Partial<DirectionGrant>; expiresAt?: number;
}

// ---------- Endpoints & rooms ----------
export interface AgentInfo { attached: boolean; name?: string; }
export interface EndpointInfo {
  endpointId: EndpointId; kind: EndpointKind; origin: string; tabId?: number; title?: string;
  agent: AgentInfo; connected: boolean;
}
export interface RoomMember { endpointId: EndpointId; kind: EndpointKind; origin: string; tabId?: number; role: Role; }
export type RoomState = 'keying' | 'active' | 'closed';
export type CloseReason = 'user' | 'peer-left' | 'expired' | 'tab-closed' | 'endpoint-gone'
  | 'site-disabled' | 'violation' | 'key-confirm-failed';
/** Room as seen by one endpoint. */
export interface RoomView {
  roomId: RoomId; state: RoomState; createdAt: number; expiresAt: number; role: Role;
  peer: { origin: string; kind: EndpointKind; agentName?: string; connected: boolean };
  outbound: DirectionGrant;   // what I may send
  inbound: DirectionGrant;    // what my peer may send me
  closedReason?: CloseReason;
}
/** Room as seen by trusted UI. */
export interface RoomAdminView {
  roomId: RoomId; state: RoomState; createdAt: number; members: [RoomMember, RoomMember];
  grant: Grant; closedReason?: CloseReason; frames: { routed: number; rejected: number };
}

// ---------- Frames ----------
export interface FrameHeader {
  v: 1; frameId: FrameId; roomId: RoomId; from: EndpointId; seq: number;  // seq: integer ≥1
  kind: FrameKind; size: number;   // plaintext body length in bytes
  mime?: AllowedMime;              // REQUIRED iff kind==='file'; forbidden otherwise
  ts: number;
}
export interface ConfirmBody { transcriptHash: string; }                  // 64 hex
export interface TextBody { text: string; threadId: string; inReplyTo?: FrameId; } // prompt/response; response REQUIRES inReplyTo
export interface TaskBody { taskId: string; status: TaskStatus; progress?: number; summary?: string; threadId?: string; }
export interface FileMeta { name: string; mime: AllowedMime; size: number; sha256: string; threadId?: string; }
export interface FileBody { meta: FileMeta; bytes: Uint8Array; }
export type Body = ConfirmBody | TextBody | TaskBody | FileBody;

export interface TranscriptParty { endpointId: EndpointId; origin: string; kind: EndpointKind; publicKey: string; } // base64 raw P-256 (65 bytes)
export interface Transcript { v: 1; roomId: RoomId; initiator: TranscriptParty; joiner: TranscriptParty; grant: Grant; }

export type ContentDetail =
  | { kind: 'prompt' | 'response'; text: string; threadId: string; inReplyTo?: FrameId; sha256: string }
  | { kind: 'task'; task: TaskBody; sha256: string }
  | { kind: 'file'; name: string; mime: AllowedMime; size: number; sha256: string; threadId?: string };

// ---------- Endpoint <-> Router wire (§4) ----------
export type ReceiptStatus = 'accepted' | 'rejected' | 'no-agent';
export type E2R =
  | { t: 'hello'; v: 1; kind: 'page' | 'panel'; resume?: { endpointId: EndpointId; resumeToken: string } }
  | { t: 'agent'; v: 1; attached: boolean; name?: string }
  | { t: 'pair-request'; v: 1; note?: string }
  | { t: 'key-share'; v: 1; roomId: RoomId; publicKey: string }
  | { t: 'confirmed'; v: 1; roomId: RoomId }
  | { t: 'frame'; v: 1; header: FrameHeader; ct: string }
  | { t: 'receipt'; v: 1; roomId: RoomId; frameId: FrameId; status: ReceiptStatus; code?: ErrorCode }
  | { t: 'audit-detail'; v: 1; roomId: RoomId; frameId: FrameId; direction: 'sent' | 'received'; detail: ContentDetail }
  | { t: 'violation'; v: 1; roomId: RoomId; frameId?: FrameId; code: ErrorCode; message?: string }
  | { t: 'leave'; v: 1; roomId: RoomId };
export type R2E =
  | { t: 'welcome'; v: 1; endpointId: EndpointId; resumeToken: string; origin: string; kind: EndpointKind; rooms: RoomView[]; paused: boolean; resumed: boolean }
  | { t: 'rejected'; v: 1; code: ErrorCode }
  | { t: 'key-request'; v: 1; roomId: RoomId }
  | { t: 'room-keys'; v: 1; roomId: RoomId; transcript: Transcript }
  | { t: 'room'; v: 1; room: RoomView }
  | { t: 'frame'; v: 1; header: FrameHeader; ct: string }
  | { t: 'ack'; v: 1; roomId: RoomId; frameId: FrameId; ok: boolean; code?: ErrorCode }
  | { t: 'receipt'; v: 1; roomId: RoomId; frameId: FrameId; status: ReceiptStatus; code?: ErrorCode }
  | { t: 'paused'; v: 1; paused: boolean }
  | { t: 'error'; v: 1; code: ErrorCode; message?: string };

// ---------- Delivered to agents ----------
export interface PeerRef { origin: string; kind: EndpointKind; agentName?: string; }
export interface InboundMessage {
  id: FrameId; roomId: RoomId; type: 'prompt' | 'response'; text: string; threadId: string;
  inReplyTo?: FrameId; from: PeerRef; sentAt: number; receivedAt: number;
}
export interface InboundTask { id: FrameId; roomId: RoomId; task: TaskBody; from: PeerRef; sentAt: number; receivedAt: number; }
export interface Provenance {
  fromOrigin: string; fromKind: EndpointKind; roomId: RoomId; frameId: FrameId; sha256: string;
  detectedType: AllowedMime; size: number; sentAt: number; receivedAt: number; validated: true;
}
export interface InboundFileData {  // endpoint-level (bytes); page-api wraps into a File
  id: FrameId; roomId: RoomId; name: string; mime: AllowedMime; bytes: Uint8Array;
  threadId?: string; provenance: Provenance; from: PeerRef;
}
export interface SendResult { frameId: FrameId; roomId: RoomId; status: 'accepted'; }
export interface AgentErrorEvent { code: ErrorCode; message: string; roomId?: RoomId; frameId?: FrameId; }

// ---------- Pairing ----------
export interface PairingEndpointRef { endpointId: EndpointId; kind: EndpointKind; origin: string; tabId?: number; }
export interface PairingRecord { code: string; initiator: PairingEndpointRef; proposal: GrantProposal; createdAt: number; expiresAt: number; }
export interface PairingSnapshot { pairings: PairingRecord[]; failures: number[]; failuresSinceReset: number; lockedUntil: number; }
export interface PairingPreview {
  code: string; initiator: { origin: string; kind: EndpointKind }; joiner: { origin: string; kind: EndpointKind };
  proposal: GrantProposal; expiresAt: number;
}

// ---------- Audit ----------
export type AuditType =
  | 'site.enabled' | 'site.disabled' | 'pause.changed' | 'endpoint.rejected'
  | 'pair.requested' | 'pair.started' | 'pair.failed' | 'pair.approved' | 'pair.cancelled'
  | 'room.opened' | 'room.narrowed' | 'room.closed'
  | 'frame.routed' | 'frame.rejected' | 'frame.receipt'
  | 'content.sent' | 'content.received' | 'violation' | 'log.cleared';
export interface AuditActor { kind: 'router' | 'endpoint' | 'ui'; endpointId?: EndpointId; origin?: string; }
export interface AuditEntry {
  seq: number; ts: number; type: AuditType; roomId?: RoomId; actor: AuditActor;
  data: Record<string, unknown>; prevHash: string; hash: string;
}
export interface AuditPersisted { v: 1; anchor: string; entries: AuditEntry[]; nextSeq: number; }
export interface AuditStore { load(): Promise<AuditPersisted | undefined>; save(p: AuditPersisted): Promise<void>; }
export type AuditVerifyResult = { ok: true; count: number } | { ok: false; brokenAtSeq: number; reason: string };

// ---------- UI RPC (§7) ----------
export type EndpointSelector = { tabId: number } | { endpointId: EndpointId };
export interface Settings { sites: string[]; paused: boolean; auditMaxEntries: number; defaultProposal: GrantProposal; }
export interface UiState {
  paused: boolean; sites: string[]; pendingSites: string[]; endpoints: EndpointInfo[]; rooms: RoomAdminView[];
  pairings: { code: string; initiator: PairingEndpointRef; expiresAt: number }[];
  pairRequests: { tabId: number; origin: string; note?: string; at: number }[];
  lockedUntil: number;
}
export interface UiMethods {
  'state.get': { p: undefined; r: UiState };
  'site.enable': { p: { origin: string }; r: { status: 'enabled' | 'pending-permission' } };
  'site.disable': { p: { origin: string }; r: { status: 'disabled' } };
  'pair.start': { p: { endpoint: EndpointSelector; proposal: GrantProposal }; r: { code: string; expiresAt: number } };
  'pair.lookup': { p: { code: string; endpoint: EndpointSelector }; r: PairingPreview };
  'pair.approve': { p: { code: string; endpoint: EndpointSelector }; r: { roomId: RoomId } };
  'pair.cancel': { p: { code: string }; r: { cancelled: boolean } };
  'room.close': { p: { roomId: RoomId }; r: { closed: boolean } };
  'room.narrow': { p: { roomId: RoomId; patch: GrantNarrowing }; r: RoomAdminView };
  'pause.set': { p: { paused: boolean }; r: { paused: boolean } };
  'audit.list': { p: { limit?: number; beforeSeq?: number; roomId?: RoomId } | undefined; r: AuditEntry[] };
  'audit.verify': { p: undefined; r: AuditVerifyResult };
  'audit.clear': { p: undefined; r: { cleared: number } };
  'audit.export': { p: undefined; r: AuditPersisted };
  'settings.get': { p: undefined; r: Settings };
  'settings.set': { p: { auditMaxEntries?: number; defaultProposal?: GrantProposal }; r: Settings };
}
export type UiMethod = keyof UiMethods;
export type UiRequest = { id: number; m: UiMethod; p?: unknown };
export type UiMessage =
  | { t: 'res'; id: number; ok: true; r: unknown }
  | { t: 'res'; id: number; ok: false; e: { code: ErrorCode; message: string } }
  | { t: 'ev'; ev: 'state'; d: UiState };

// ---------- AgentRPC (page ⇄ isolated, §6) ----------
export type AgentEventName = 'prompt' | 'response' | 'task' | 'file' | 'room' | 'error';
export type PageRequest =
  | { id: number; m: 'connect'; p: { apiVersion: number; agentName: string } }
  | { id: number; m: 'rooms' }
  | { id: number; m: 'requestPairing'; p: { note?: string } }
  | { id: number; m: 'send'; p: { roomId: RoomId; type: 'prompt' | 'response'; text: string; threadId?: string; inReplyTo?: FrameId } }
  | { id: number; m: 'sendTask'; p: { roomId: RoomId; task: TaskBody } }
  | { id: number; m: 'sendFile'; p: { roomId: RoomId; name: string; bytes: ArrayBuffer; threadId?: string } }
  | { id: number; m: 'leave'; p: { roomId: RoomId } }
  | { id: number; m: 'disconnect' };
export type IsolatedMessage =
  | { t: 'bound' }
  | { t: 'ready'; apiVersions: number[]; version: string }
  | { t: 'res'; id: number; ok: true; r: unknown }
  | { t: 'res'; id: number; ok: false; e: { code: ErrorCode; message: string } }
  | { t: 'ev'; ev: AgentEventName; d: unknown };

// ---------- Ports (chrome-shaped, so fakes are trivial) ----------
export interface RuntimePortLike {
  name: string;
  postMessage(msg: unknown): void;
  onMessage: { addListener(cb: (msg: unknown) => void): void };
  onDisconnect: { addListener(cb: () => void): void };
  disconnect(): void;
}
export interface SenderInfo {           // normalized from runtime.Port.sender by platform.ts
  tabId?: number; frameId?: number; url?: string; origin?: string; extensionId?: string; tabTitle?: string;
}
export interface KeyValueStore { get<T>(key: string): Promise<T | undefined>; set(key: string, value: unknown): Promise<void>; }
```

## 4. Endpoint ⇄ Router protocol (`runtime.Port` name `"tb.endpoint"`)

Validated by `validateE2R`/`validateR2E` (`src/shared/protocol.ts`). Per-message rules:

| Message | Rules |
|---|---|
| `hello` | First message; anything before it → `error{INVALID_MESSAGE}` + disconnect. `kind` must match sender classification (§1.2). `resume` accepted iff stored endpoint exists, `sha256(resumeToken)` equals stored hash (constant-time compare), stored `kind`, `tabId` and `origin` equal the current sender's, and it is not currently connected; else a fresh endpoint is created (`resumed:false`). |
| `agent` | `name`: 1..64 chars after stripping control chars. Updates EndpointInfo; peers get `room` updates. |
| `pair-request` | page endpoints only; `note` ≤ 140 chars. Stores `pairRequests` entry (dedupe per tab, TTL 5 min), badge `"!"` on tab; audit `pair.requested`. |
| `key-share` | Only for a room in `keying` where sender is a member and hasn't shared yet. `publicKey` base64 decoding to 65 bytes starting 0x04. When both shared → `room-keys` to both. |
| `confirmed` | Only in `keying` after `room-keys`. Both confirmed → `active`. |
| `frame` | §5.3 |
| `receipt` | Sender must be the recipient of a routed `frameId` in that room; forwarded to the frame's sender; audit `frame.receipt`. |
| `audit-detail` | Accepted once per (frameId, direction): `sent` only from the frame's sender after routing; `received` only from its recipient. `detail.kind` must equal the routed kind. Audit `content.sent` / `content.received` with actor from port. |
| `violation` | Audit `violation`. If `code ∈ {DECRYPT_FAILED, KEY_CONFIRM_FAILED, REPLAY}` → close room (`violation` / `key-confirm-failed`). |
| `leave` | Member closes room (`peer-left` shown to the other side). |

Router → endpoint messages are only sent by the router. `rejected` is followed by disconnect.

### 4.1 Frame encryption (`src/shared/crypto.ts`)
```ts
export async function generateKeyPair(): Promise<{ privateKey: CryptoKey; publicKeyRaw: Uint8Array }>;  // ECDH P-256, private non-extractable
export async function transcriptHash(t: Transcript): Promise<string>;         // hex sha256(utf8(canonicalJson(t)))
export async function deriveRoomKey(privateKey: CryptoKey, peerPublicKeyRaw: Uint8Array, roomId: RoomId, transcriptHashHex: string): Promise<CryptoKey>;
//   bits = ECDH(256); key = HKDF-SHA-256(ikm=bits, salt=hexToBytes(roomId), info=utf8("tabbridge/v1/room-key|"+transcriptHashHex)) → AES-GCM-256, non-extractable, [encrypt,decrypt]
export async function encryptFrame(key: CryptoKey, header: FrameHeader, plaintext: Uint8Array): Promise<string>; // base64(iv12 || ct || tag16), AAD = headerAad(header)
export async function decryptFrame(key: CryptoKey, header: FrameHeader, ct: string): Promise<Uint8Array>;     // throws TabBridgeError('DECRYPT_FAILED')
export async function sha256Hex(bytes: Uint8Array): Promise<string>;
export function constantTimeEqual(a: string, b: string): boolean;
```
`headerAad(h)` (protocol.ts) = `utf8(canonicalJson(h))`. Header `size` MUST equal plaintext length;
ciphertext decoded length MUST equal `size + 28` (`expectedCtBytes(size)`).

### 4.2 Body codec (`src/shared/protocol.ts`)
- `confirm|prompt|response|task`: `utf8(canonicalJson(body))`.
- `file`: `u32be(metaLen) || utf8(canonicalJson(meta)) || bytes`; `metaLen ≤ FILE_META_MAX`.
```ts
export function encodeBody(kind: FrameKind, body: Body): Uint8Array;
export function decodeBody(kind: FrameKind, bytes: Uint8Array): Body;   // strict schema validation, throws INVALID_MESSAGE / PAYLOAD_TOO_LARGE
export function validateTextBody(b: unknown, kind: 'prompt'|'response'): TextBody;
export function validateTaskBody(b: unknown): TaskBody;
export function validateFileMeta(b: unknown): FileMeta;
export function validateHeader(h: unknown): FrameHeader;
export function validateE2R(m: unknown): E2R;
export function validateR2E(m: unknown): R2E;
export function validateContentDetail(d: unknown): ContentDetail;
export function validateProposalShape(p: unknown): GrantProposal;  // shape only; semantic caps in permissions.ts
export function headerAad(h: FrameHeader): Uint8Array;
export function bodyLimit(kind: FrameKind): number;
export function expectedCtBytes(size: number): number;             // size + 28
export function base64DecodedLength(b64: string): number;           // arithmetic, no decode; -1 if malformed
```
Schema rules: `text` non-empty, `utf8Length ≤ MAX_TEXT_BYTES`; `threadId`/`taskId` match
`ID_TOKEN_RE = /^[A-Za-z0-9_-]{1,64}$/`; `inReplyTo`/ids match `HEX32_RE`; `progress` finite in
[0,1]; `summary` ≤ 2048 chars; `status ∈ TASK_STATUSES`; `FileMeta.sha256` 64 hex;
`FileMeta.size` integer 1..HARD_MAX_FILE_BYTES.

## 5. Router (`src/background/router.ts`)

```ts
export interface RouterPlatform {
  extensionOrigin: string;                         // e.g. 'chrome-extension://abc'
  extensionId: string;
  hasHostPermission(origin: string): Promise<boolean>;
  syncContentScripts(sites: string[]): Promise<void>; // (re)register isolated+MAIN scripts for sites
  injectIntoOpenTabs(origin: string): Promise<void>;
  setBadge(tabId: number, text: string): void;
  loadSettings(): Promise<Settings | undefined>;     // storage.local 'tb.settings'
  saveSettings(s: Settings): Promise<void>;
}
export interface RouterDeps {
  session: KeyValueStore;        // storage.session (router state)
  audit: AuditLog;
  platform: RouterPlatform;
  now(): number;
  randomBytes(n: number): Uint8Array;
}
export class Router {
  constructor(deps: RouterDeps);
  init(): Promise<void>;                                            // load settings + state; sweep
  connectEndpoint(port: RuntimePortLike, sender: SenderInfo): void;
  connectUi(port: RuntimePortLike, sender: SenderInfo): void;
  handleUi<M extends UiMethod>(m: M, p: UiMethods[M]['p']): Promise<UiMethods[M]['r']>; // also used by tests
  onTabRemoved(tabId: number): Promise<void>;
  onPermissionsAdded(): Promise<void>;                              // completes pendingSites
  onPermissionsRemoved(): Promise<void>;                            // disables sites that lost permission
  sweep(): Promise<void>;                                           // expiries, stale endpoints, pairings
  whenIdle(): Promise<void>;                                        // resolves when the op queue drains (tests)
}
```
- **Serialization:** every inbound event (endpoint msg, UI call, tab event, sweep) runs through a
  single FIFO async queue. State is written through to `session` key `"tb.router"` after each
  mutating operation, before any resulting message is posted.
- **Persisted router state** (`RouterStateStore` in `state.ts`):
  ```ts
  interface EndpointRecord { endpointId; kind; origin; tabId?; title?; agent: AgentInfo; resumeTokenHash: string; connected: boolean; disconnectedAt?: number; }
  interface RoomRecord {
    roomId; state: RoomState; createdAt; members: [RoomMember, RoomMember]; grant: Grant;
    pubKeys: Record<EndpointId, string>; confirmed: EndpointId[]; lastSeq: Record<EndpointId, number>;
    rate: Record<EndpointId, RateBucket>; recentFrameIds: FrameId[];           // ≤ 256, FIFO
    routed: Record<FrameId, RoutedFrame>;                                      // ≤ 256 most recent
    counters: { routed: number; rejected: number }; closedReason?: CloseReason; closedAt?: number;
  }
  interface RoutedFrame { from: EndpointId; to: EndpointId; kind: FrameKind; at: number; sentDetail: boolean; recvDetail: boolean; receipt?: ReceiptStatus; }
  interface RouterState { v: 1; endpoints: Record<EndpointId, EndpointRecord>; rooms: Record<RoomId, RoomRecord>;
    pairing: PairingSnapshot; pairRequests: UiState['pairRequests']; pendingSites: string[]; }
  export class RouterStateStore { constructor(kv: KeyValueStore); load(): Promise<RouterState>; save(s: RouterState): Promise<void>; }
  ```
  Closed rooms are kept for 10 minutes (for UI display) then pruned by `sweep`.
- On `init` after a worker restart all endpoints are marked `connected:false, disconnectedAt:now`.

### 5.1 Sender classification
`classifyEndpointSender(sender, platform) → {kind:'page', origin, tabId, title} | {kind:'panel', origin:'tabbridge://console'} | {reject: ErrorCode}`:
- URL origin === `extensionOrigin` → panel iff pathname === `/ui/sidepanel.html` and `extensionId` matches, else `SENDER_REJECTED`.
- Else require `tabId ≥ 0`, `frameId === 0`; `origin = sender.origin ?? new URL(sender.url).origin`;
  must be `http:`/`https:` and not `"null"` → else `SENDER_REJECTED`; must be in `settings.sites`
  → else `ORIGIN_NOT_ENABLED` (audit `endpoint.rejected`).
- UI port (`"tb.ui"`): URL origin === `extensionOrigin` and `extensionId` matches; else disconnect silently.
- Port names other than `tb.endpoint`/`tb.ui` → disconnect. `onConnectExternal` is never registered.

### 5.2 Room rules
- ≤ `MAX_ROOMS_PER_ENDPOINT` non-closed rooms per endpoint (`TOO_MANY_ROOMS` at approve).
- Endpoint disconnect → mark `connected:false`; peers get `room` update (peer.connected=false).
  If not resumed within `RESUME_GRACE_MS` → rooms close (`endpoint-gone`) at next sweep/event.
- `tabs.onRemoved` → close that tab's endpoint rooms (`tab-closed`) immediately.
- Site disabled → close rooms with a member of that origin (`site-disabled`), disconnect endpoints.
- Expiry: `now ≥ grant.expiresAt` → close (`expired`), checked on every frame and in `sweep`
  (background registers a 1-minute `alarms` sweep).
- Closing: state `closed`, `closedReason`, notify both members with `room`, audit `room.closed`.
  Keying-state rooms not active within `KEYING_TIMEOUT_MS` → close (`key-confirm-failed`).

### 5.3 Frame policy (in order; first failure → `ack{ok:false, code}` to sender, audit `frame.rejected{frameId?, code, kind, size}`)
1. `settings.paused` → `PAUSED`.
2. `validateHeader` → `INVALID_MESSAGE`. `ct` must be a string with `base64DecodedLength(ct) === expectedCtBytes(header.size)` → else `PAYLOAD_TOO_LARGE` if too long else `INVALID_MESSAGE`.
3. `header.from !== port endpointId` → `SPOOFED_SENDER`.
4. Room exists → else `ROOM_NOT_FOUND`; sender is member → else `NOT_A_MEMBER`; room closed → `ROOM_CLOSED`.
5. Expired → close room, `ROOM_EXPIRED`.
6. State: `keying` allows only `kind==='confirm'` (once per sender, seq 1); `active` forbids `confirm` → `ROOM_NOT_ACTIVE`.
7. `header.size > bodyLimit(kind)` → `PAYLOAD_TOO_LARGE`.
8. `checkFrame(grant, direction, header)` (permissions.ts) → `NOT_PERMITTED` / `FILE_TOO_LARGE`.
9. `header.seq !== lastSeq[from] + 1` or `frameId ∈ recentFrameIds` → `REPLAY`.
10. Rate: `checkRate` → `RATE_LIMITED`.
11. Peer not connected → `PEER_UNAVAILABLE` (no queuing; seq still consumed? **No**: on rejection seq is NOT advanced).
12. Accept: advance `lastSeq`, record `routed`, update rate bucket, persist, forward `frame` to peer
    unchanged, `ack{ok:true}` to sender, audit `frame.routed{frameId, from, to, kind, size, mime?, seq, ctSha256}`.

## 6. Agent-facing API (public surface, `apiVersion: 1`)

### 6.1 Page handshake (`page-api.ts` ⇄ `isolated.ts`)
- Both scripts are registered for enabled sites at `document_start`, top frame only
  (`allFrames:false`); `page-api.js` in `world:'MAIN'`, `isolated.js` in `'ISOLATED'`.
- MAIN: creates `MessageChannel`, keeps `port1`, `window.postMessage({__tabbridge:'hs1', v:1}, '*', [port2])`.
  Also listens for `{__tabbridge:'hs0'}` (isolated announces itself) and re-sends `hs1` with a
  **new** channel if not yet bound. Uses the port on which `{t:'bound'}` arrives.
- ISOLATED: on start posts `{__tabbridge:'hs0'}`; accepts the **first** message with
  `event.source === window && data.__tabbridge==='hs1' && event.ports.length===1`; replies
  `{t:'bound'}` on that port; ignores all later hs1. After router `welcome` posts `{t:'ready', apiVersions:[1], version}`.
  If router `rejected` → closes the port; nothing is ever defined in the page.
- MAIN on `ready`: `Object.defineProperty(window,'tabBridge',{value:Object.freeze(api), writable:false, configurable:false, enumerable:false})`
  then `window.dispatchEvent(new Event('tabbridge:ready'))`.

### 6.2 `window.tabBridge`
```ts
interface TabBridgeGlobal {
  readonly version: string;                    // extension version
  readonly apiVersions: readonly number[];     // [1]
  connect(opts: { apiVersion: 1; agentName: string }): Promise<TabBridgeSession>; // idempotent per page
}
interface TabBridgeSession {
  readonly apiVersion: 1;
  rooms(): Promise<RoomView[]>;
  requestPairing(opts?: { note?: string }): Promise<void>;
  send(roomId: string, msg: { type: 'prompt' | 'response'; text: string; threadId?: string; inReplyTo?: string }): Promise<SendResult>;
  ask(roomId: string, text: string, opts?: { threadId?: string; timeoutMs?: number }): Promise<InboundMessage>; // default 60000, max 600000
  sendTask(roomId: string, task: TaskBody): Promise<SendResult>;
  sendFile(roomId: string, file: Blob, opts?: { name?: string; threadId?: string }): Promise<SendResult>; // name defaults to (file as File).name
  leave(roomId: string): Promise<void>;
  on<E extends AgentEventName>(ev: E, cb: (d: AgentEventMap[E]) => void): () => void;  // returns unsubscribe
  off<E extends AgentEventName>(ev: E, cb: (d: AgentEventMap[E]) => void): void;
  close(): Promise<void>;                      // detaches agent (peers see agent detached)
}
interface AgentEventMap {
  prompt: InboundMessage & { reply(text: string): Promise<SendResult> };
  response: InboundMessage;
  task: InboundTask;
  file: { id: string; roomId: string; file: File; threadId?: string; provenance: Provenance; from: PeerRef };
  room: RoomView;
  error: AgentErrorEvent;
}
```
- All methods reject with `TabBridgeError {name:'TabBridgeError', code, message}`.
- `ask`: sends a `prompt` (auto `threadId` = random ID token if omitted), resolves with the first
  `response` whose `inReplyTo === sentFrameId`; `TIMEOUT` on expiry. Implementation MUST buffer
  responses received between send and SendResult.
- `send()` resolves when the **peer endpoint** returns `receipt: accepted` (delivered to its agent);
  rejects `NO_AGENT` (peer has no agent attached), receiver validation code, or `DELIVERY_TIMEOUT`.
- Graceful degradation snippet (documented in README):
  ```js
  const tb = window.tabBridge ?? await new Promise(r => { const t = setTimeout(() => r(null), 3000);
    addEventListener('tabbridge:ready', () => { clearTimeout(t); r(window.tabBridge); }, { once: true }); });
  ```

### 6.3 Endpoint class (`src/endpoint/endpoint.ts`)
```ts
export interface EndpointSink {
  hasAgent(): boolean;
  onPrompt(m: InboundMessage): void; onResponse(m: InboundMessage): void; onTask(t: InboundTask): void;
  onFile(f: InboundFileData): void; onRoom(r: RoomView): void; onError(e: AgentErrorEvent): void;
  onPaused?(paused: boolean): void;
}
export interface EndpointOptions {
  connect(): RuntimePortLike;           // opens a new 'tb.endpoint' port
  kind: 'page' | 'panel';
  sink: EndpointSink;
  now?: () => number;
  deliveryTimeoutMs?: number;           // default DELIVERY_TIMEOUT_MS
  reconnectDelayMs?: number;            // default 250; exponential to 5000
}
export interface WelcomeInfo { endpointId: EndpointId; origin: string; kind: EndpointKind; rooms: RoomView[]; paused: boolean; }
export class Endpoint {
  constructor(opts: EndpointOptions);
  start(): Promise<WelcomeInfo>;        // rejects TabBridgeError(code from 'rejected')
  readonly endpointId: EndpointId | undefined;
  readonly origin: string | undefined;
  rooms(): RoomView[];
  setAgent(attached: boolean, name?: string): void;
  requestPairing(note?: string): void;
  sendText(roomId: RoomId, type: 'prompt' | 'response', text: string, opts?: { threadId?: string; inReplyTo?: FrameId }): Promise<SendResult>;
  sendTask(roomId: RoomId, task: TaskBody): Promise<SendResult>;
  sendFile(roomId: RoomId, file: { name: string; bytes: Uint8Array }, opts?: { threadId?: string }): Promise<SendResult>;
  leave(roomId: RoomId): void;
  stop(): void;                         // disconnect, forget keys, no reconnect
}
```
Endpoint behavior:
- Keeps per room: `privateKey`, `roomKey`, `transcriptHash`, `mySeq` (next outbound), `peerSeq`
  (last inbound), `RoomView` (latest from router). Keys only in memory.
- On disconnect: reconnect with `resume` (backoff); pending sends reject `NOT_CONNECTED` only if
  reconnect fails `3×`. Rejected resume ⇒ keys discarded, rooms dropped locally.
- `key-request` → `generateKeyPair`, send `key-share`. `room-keys` → verify the transcript party for
  my role has my `endpointId` and my public key (else `violation KEY_CONFIRM_FAILED`), compute
  hash, derive key, send `confirm` frame (seq 1). On peer `confirm` → decrypt, compare hash in
  constant time → `confirmed`; mismatch → `violation KEY_CONFIRM_FAILED`.
- **Outbound:** room must be `active`; check `outbound` grant (`NOT_PERMITTED`); text/task schema;
  files: `validateFile({name, bytes}, {allowed: outbound.fileTypes, maxBytes: outbound.maxFileBytes})`,
  meta `{name: sanitized, mime: detected, size, sha256}`; header `mime` = detected. Encrypt, send
  `frame`. Await `ack` (reject with its code) then `receipt` (accepted → resolve; `no-agent` →
  `NO_AGENT`; rejected → its code) within `deliveryTimeoutMs` → else `DELIVERY_TIMEOUT`.
  After `ack ok`, send `audit-detail{direction:'sent'}`.
- **Inbound frame:** `header.seq === peerSeq+1` (else `violation REPLAY`, drop); decrypt (fail →
  `violation DECRYPT_FAILED`); `decodeBody`; check `inbound` grant for kind/mime/size; for files
  `validateFile` with inbound policy **and** `meta.sha256 === sha256(bytes)` (`FILE_HASH_MISMATCH`),
  `meta.mime === header.mime === detected` (`FILE_TYPE_MISMATCH`), `meta.size === bytes.length`.
  Failure → `receipt{rejected, code}` + `violation{code}` + sink.onError. If `!sink.hasAgent()`
  → `receipt{no-agent}`. Else `receipt{accepted}` **then** deliver to sink **then**
  `audit-detail{direction:'received'}`. Provenance via `buildProvenance`.

## 7. UI RPC (`runtime.Port` name `"tb.ui"`)
- Request `{id, m, p}` → response `UiMessage{t:'res'}`; router pushes `{t:'ev', ev:'state'}` to all
  UI ports after any state change (coalesced ≤ 1 per 50 ms) and once on connect.
- Method semantics (`handleUi`):
  - `pair.start`: rejects `PAUSED`; resolves selector to a **connected** endpoint (tabId → page
    endpoint of that tab; endpointId → must exist and be connected) else `PEER_UNAVAILABLE`;
    `validateProposal`; clears pair request for that tab; audit `pair.started{initiator, proposal}` (no code in audit).
  - `pair.lookup`/`pair.approve`: `PairingManager` errors pass through; audit `pair.failed{reason}`
    on failure; approve → create room (`keying`), audit `pair.approved{roomId, initiator, joiner, grant}`,
    send `key-request` to both.
  - `room.narrow`: `applyNarrowing` (widening → `NOT_PERMITTED`); push `room` to both members; audit.
  - `pause.set`: persist in settings; broadcast `paused` to all endpoints; audit `pause.changed`.
  - `site.disable`: remove from `sites`, `syncContentScripts`, close rooms, disconnect endpoints of that origin, audit.
  - `audit.clear`: `AuditLog.clear` (writes `log.cleared{count}` as the new chain's first entry).
- Popup targeting: popup uses the active tab of the current window, or `?tabId=<n>` when opened
  as a page (used by E2E and by "open in window").

## 8. Limits (`src/shared/limits.ts`)
```ts
PROTOCOL_VERSION = 1; API_VERSIONS = [1]; EXT_VERSION = '0.1.0';
ALLOWED_MIMES: AllowedMime[] (the 9 above); TASK_STATUSES (6 above);
MAX_TEXT_BYTES = 32_768; MAX_SUMMARY_CHARS = 2_048; MAX_AGENT_NAME = 64; MAX_NOTE_CHARS = 140;
HARD_MAX_FILE_BYTES = 8 * 1024 * 1024; DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024; FILE_META_MAX = 1_024;
BODY_LIMITS = { confirm: 256, prompt: 36_864, response: 36_864, task: 8_192, file: HARD_MAX_FILE_BYTES + 4 + FILE_META_MAX };
AES_GCM_OVERHEAD = 28;
PAIRING_CODE_TTL_MS = 120_000; PAIRING_MAX_FAILURES = 3; PAIRING_GLOBAL_FAILS_PER_MIN = 10; PAIRING_LOCKOUT_MS = 60_000;
ROOM_TTL_OPTIONS_MS = [900_000, 3_600_000, 28_800_000]; DEFAULT_ROOM_TTL_MS = 3_600_000;
DEFAULT_RATE = { framesPerMinute: 60, bytesPerMinute: 16 * 1024 * 1024 } (also the maximum);
MAX_ROOMS_PER_ENDPOINT = 8; KEYING_TIMEOUT_MS = 30_000; RESUME_GRACE_MS = 30_000;
DELIVERY_TIMEOUT_MS = 15_000; ASK_DEFAULT_TIMEOUT_MS = 60_000; ASK_MAX_TIMEOUT_MS = 600_000;
PAIR_REQUEST_TTL_MS = 300_000; CLOSED_ROOM_RETENTION_MS = 600_000;
AUDIT_DEFAULT_MAX_ENTRIES = 5_000; AUDIT_MIN_MAX_ENTRIES = 100; AUDIT_MAX_MAX_ENTRIES = 20_000; AUDIT_FLUSH_MS = 250;
ID_TOKEN_RE = /^[A-Za-z0-9_-]{1,64}$/; HEX32_RE = /^[0-9a-f]{32}$/; HEX64_RE = /^[0-9a-f]{64}$/; CODE_RE = /^[0-9]{6}$/;
PANEL_ORIGIN = 'tabbridge://console'; PANEL_PATH = '/ui/sidepanel.html';
```

## 9. Error codes (`src/shared/errors.ts`)
```ts
export const ERROR_CODES = [
 'UNSUPPORTED_VERSION','INVALID_MESSAGE','INTERNAL','TIMEOUT',
 'NOT_CONNECTED','ORIGIN_NOT_ENABLED','SENDER_REJECTED','RESUME_REJECTED','PAUSED',
 'ROOM_NOT_FOUND','ROOM_NOT_ACTIVE','ROOM_EXPIRED','ROOM_CLOSED','NOT_A_MEMBER','TOO_MANY_ROOMS',
 'NOT_PERMITTED','PEER_UNAVAILABLE','NO_AGENT','DELIVERY_TIMEOUT',
 'RATE_LIMITED','PAYLOAD_TOO_LARGE','REPLAY','SPOOFED_SENDER','DECRYPT_FAILED','KEY_CONFIRM_FAILED','VALIDATION_FAILED',
 'FILE_TOO_LARGE','FILE_TYPE_DENIED','FILE_TYPE_MISMATCH','FILE_NAME_INVALID','FILE_EMPTY','FILE_HASH_MISMATCH',
 'PAIRING_CODE_INVALID','PAIRING_EXPIRED','PAIRING_LOCKED','PAIRING_SELF',
] as const;
export type ErrorCode = typeof ERROR_CODES[number];
export class TabBridgeError extends Error { readonly code: ErrorCode; constructor(code: ErrorCode, message?: string); toJSON(): { code: ErrorCode; message: string } }
export function isErrorCode(x: unknown): x is ErrorCode;
export function toErrorPayload(e: unknown): { code: ErrorCode; message: string }; // non-TabBridgeError → INTERNAL (message generic, no stack)
```
The public API guarantees this set for `apiVersion: 1`; additions are minor, removals need v2.

## 10. Permissions module (`src/background/permissions.ts`)
```ts
export function defaultDirectionGrant(): DirectionGrant;      // prompts+tasks true, files false, fileTypes [], maxFileBytes DEFAULT
export function defaultProposal(): GrantProposal;             // both directions default, ttl DEFAULT_ROOM_TTL_MS
export function validateProposal(p: unknown): GrantProposal;  // shape + fileTypes ⊆ ALLOWED_MIMES (deduped), 1 ≤ maxFileBytes ≤ HARD_MAX, ttlMs ∈ ROOM_TTL_OPTIONS_MS; files=true requires ≥1 type
export function grantFromProposal(p: GrantProposal, now: number): Grant; // expiresAt = now + ttlMs, rate = DEFAULT_RATE
export function directionOf(members: [RoomMember, RoomMember], from: EndpointId): Direction | null;
export function perspective(grant: Grant, role: Role): { outbound: DirectionGrant; inbound: DirectionGrant };
export type PolicyResult = { ok: true } | { ok: false; code: ErrorCode };
export function checkFrame(grant: Grant, dir: Direction, h: Pick<FrameHeader, 'kind' | 'size' | 'mime'>, now: number): PolicyResult;
//  confirm → ok; prompt/response → prompts; task → tasks; file → files && mime ∈ fileTypes && size ≤ maxFileBytes + 4 + FILE_META_MAX (else FILE_TOO_LARGE); expired → ROOM_EXPIRED
export function applyNarrowing(grant: Grant, patch: GrantNarrowing): Grant; // throws TabBridgeError('NOT_PERMITTED') on any widening; INVALID_MESSAGE on bad shape
export interface RateBucket { windowStart: number; frames: number; bytes: number; }
export function checkRate(b: RateBucket | undefined, now: number, bytes: number, rate: RateLimit): { ok: boolean; bucket: RateBucket }; // 60s fixed window
```

## 11. Pairing module (`src/background/pairing.ts`)
```ts
export interface PairingOptions { now(): number; randomInt(maxExclusive: number): number; snapshot?: PairingSnapshot; }
export class PairingManager {
  constructor(opts: PairingOptions);
  start(initiator: PairingEndpointRef, proposal: GrantProposal): PairingRecord; // replaces initiator's previous pairing; unique code among active
  lookup(code: string, joiner: PairingEndpointRef): PairingPreview;
  approve(code: string, joiner: PairingEndpointRef): { initiator: PairingEndpointRef; joiner: PairingEndpointRef; proposal: GrantProposal };
  cancel(code: string): boolean;
  cancelForEndpoint(endpointId: EndpointId): void;
  sweep(): PairingRecord[];          // removes & returns expired
  list(): PairingRecord[];
  lockedUntil(): number;
  snapshot(): PairingSnapshot;
}
```
Rules (`lookup` and `approve` share them):
1. `now < lockedUntil` → `PAIRING_LOCKED` (not counted).
2. `!CODE_RE.test(code)` or no active pairing with that code → **failure**: push `now` to
   `failures` (keep last 60 s), `failuresSinceReset++`. If `failuresSinceReset ≥ PAIRING_MAX_FAILURES`
   → cancel **all** active pairings and reset counter (a wrong guess may target any code). If
   failures in last 60 s `> PAIRING_GLOBAL_FAILS_PER_MIN` → `lockedUntil = now + PAIRING_LOCKOUT_MS`.
   Throw `PAIRING_CODE_INVALID`.
3. Expired pairing → remove, `PAIRING_EXPIRED`.
4. `joiner.endpointId === initiator.endpointId` → `PAIRING_SELF`.
5. `approve` consumes the pairing (single use). `start` resets `failuresSinceReset`.
Codes: `randomInt(1_000_000)` zero-padded to 6 digits, re-drawn on collision.

## 12. Audit module (`src/background/audit.ts`)
```ts
export const GENESIS_HASH = '0'.repeat(64);
export async function hashEntry(prevHash: string, e: Omit<AuditEntry, 'hash'>): Promise<string>; // sha256Hex(utf8(prevHash + '\n' + canonicalJson(e)))
export async function verifyChain(anchor: string, entries: AuditEntry[]): Promise<AuditVerifyResult>; // entries oldest-first
export interface AuditLogOptions { store: AuditStore; now(): number; maxEntries?: number; flushDelayMs?: number; }
export class AuditLog {
  constructor(opts: AuditLogOptions);
  init(): Promise<void>;
  append(e: { type: AuditType; roomId?: RoomId; actor: AuditActor; data: Record<string, unknown> }): Promise<AuditEntry>; // serialized; seq monotonic
  list(q?: { limit?: number; beforeSeq?: number; roomId?: RoomId; types?: AuditType[] }): AuditEntry[]; // newest first; default limit 200, max 1000
  verify(): Promise<AuditVerifyResult>;
  clear(actor: AuditActor): Promise<{ cleared: number }>;
  setMaxEntries(n: number): void;
  export(): AuditPersisted;
  flush(): Promise<void>;
}
```
- Retention: when `entries.length > maxEntries`, drop oldest; `anchor` becomes the dropped
  entry's `hash` (so the retained suffix still verifies from `anchor`).
- Persistence: debounced `store.save` after `flushDelayMs` (default `AUDIT_FLUSH_MS`); `flush()` forces.
- `data` string values longer than `MAX_TEXT_BYTES` bytes are truncated with suffix `"…[truncated]"`
  and `data.truncated = true` (defense in depth; router already validates).
- Store key in `storage.local`: `"tb.audit"`.

## 13. Files module (`src/files/validate.ts`, `provenance.ts`)
```ts
export const EXTENSIONS: Record<AllowedMime, readonly string[]> = {
  'text/plain':['txt'], 'text/markdown':['md','markdown'], 'text/csv':['csv'], 'application/json':['json'],
  'image/png':['png'], 'image/jpeg':['jpg','jpeg'], 'image/gif':['gif'], 'image/webp':['webp'], 'application/pdf':['pdf'] };
export function sniffBinary(bytes: Uint8Array): AllowedMime | null;   // png/jpeg/gif/webp/pdf magic
export function sniffDenied(bytes: Uint8Array): string | null;        // known-dangerous signatures → label: PE 'MZ', ELF '\x7fELF', Mach-O (FEEDFACE/FEEDFACF/CAFEBABE, both endians), ZIP 'PK\x03\x04'/'PK\x05\x06', gzip 1F8B, 7z, RAR 'Rar!', wasm '\0asm', shebang '#!'
export function looksLikeActiveContent(text: string): boolean;         // leading (after BOM/whitespace, case-insens.) '<!doctype','<html','<script','<svg','<?xml','<iframe','<object','<embed' OR contains '<script' anywhere in the first 4 KiB
export type NameResult = { ok: true; name: string; ext: string } | { ok: false; code: 'FILE_NAME_INVALID'; detail: string };
export function sanitizeFileName(name: string): NameResult;
export type FileCheck =
  | { ok: true; name: string; mime: AllowedMime; size: number; sha256: string }
  | { ok: false; code: 'FILE_TOO_LARGE' | 'FILE_TYPE_DENIED' | 'FILE_TYPE_MISMATCH' | 'FILE_NAME_INVALID' | 'FILE_EMPTY'; detail: string };
export async function validateFile(input: { name: string; bytes: Uint8Array; declaredMime?: string },
  policy: { allowed: readonly AllowedMime[]; maxBytes: number }): Promise<FileCheck>;
export function buildProvenance(a: { from: PeerRef; roomId: RoomId; frameId: FrameId; sha256: string; mime: AllowedMime; size: number; sentAt: number; receivedAt: number }): Provenance;
```
`validateFile` order: empty → `FILE_EMPTY`; `> maxBytes` or `> HARD_MAX_FILE_BYTES` →
`FILE_TOO_LARGE`; `sanitizeFileName`; `sniffDenied` hit → `FILE_TYPE_DENIED` (regardless of name);
ext → expected MIME (unknown ext → `FILE_TYPE_DENIED`);
binary sniff: if a binary signature matches, it must equal the ext's MIME (else
`FILE_TYPE_MISMATCH`); if ext is binary type but no signature → `FILE_TYPE_MISMATCH`; text types:
must decode as fatal UTF-8 (BOM allowed) and contain no C0 control chars other than TAB, LF, CR, FF
(nor U+007F) → else `FILE_TYPE_MISMATCH`;
`looksLikeActiveContent` → `FILE_TYPE_DENIED`; JSON must `JSON.parse` → else `FILE_TYPE_MISMATCH`;
`declaredMime` (if given, ignoring params) must equal detected → else `FILE_TYPE_MISMATCH`;
detected ∉ `policy.allowed` → `FILE_TYPE_DENIED`. `sha256` over the bytes.
`sanitizeFileName`: NFC; take substring after last `/` or `\`; remove C0/C1 controls, bidi
(U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), zero-width (U+200B–U+200D, U+FEFF);
replace `<>:"|?*` with `_`; trim spaces and dots at both ends; reject empty, reserved Windows
basenames (`CON PRN AUX NUL COM1-9 LPT1-9`, case-insensitive, any extension); require an extension
(last `.` segment, lowercased); truncate the base so total ≤ 128 chars keeping `.ext`.

## 14. Build & manifests (`scripts/build.mjs`)
- `npm run build` → `dist/chrome`, `dist/firefox`; `npm run build:e2e` → also `dist/chrome-e2e`.
- Entry points → outputs: `background/index.ts→background.js`, `content/isolated.ts→content/isolated.js`,
  `content/page-api.ts→content/page-api.js`, `ui/{popup,dashboard,sidepanel}/main.ts→ui/{name}.js`;
  HTML copied from `src/ui/*/index.html` → `ui/{name}.html`; CSS `src/ui/styles/*.css` → `ui/styles/`.
- esbuild: `format:'iife'`, `target:['chrome116','firefox128']`, `bundle:true`, `minify:false`,
  `sourcemap:false`, `define: { __TB_VERSION__: '"0.1.0"' }`.
- Chrome manifest:
  ```json
  { "manifest_version": 3, "name": "TabBridge", "version": "0.1.0",
    "description": "Consent-gated, encrypted, audited AI-agent messaging between browser tabs.",
    "minimum_chrome_version": "116",
    "permissions": ["storage", "scripting", "activeTab", "alarms", "sidePanel"],
    "optional_host_permissions": ["http://*/*", "https://*/*"],
    "background": { "service_worker": "background.js" },
    "action": { "default_title": "TabBridge", "default_popup": "ui/popup.html" },
    "side_panel": { "default_path": "ui/sidepanel.html" },
    "options_ui": { "page": "ui/dashboard.html", "open_in_tab": true },
    "content_security_policy": { "extension_pages": "script-src 'self'; object-src 'none'; base-uri 'none'" } }
  ```
- Firefox manifest: same minus `sidePanel`/`side_panel`/`minimum_chrome_version`; plus
  `"background": {"scripts": ["background.js"]}`, `"sidebar_action": {"default_panel": "ui/sidepanel.html", "default_title": "TabBridge Console"}`,
  `"browser_specific_settings": {"gecko": {"id": "tabbridge@tabbridge.invalid", "strict_min_version": "128.0"}}`.
- `chrome-e2e`: Chrome manifest plus `"host_permissions": ["http://127.0.0.1/*", "http://localhost/*"]`
  (so tests need no browser permission prompt). **Never shipped.** Site enabling logic is unchanged.
- No `web_accessible_resources`, no `externally_connectable`.
- Content-script registration (`platform.syncContentScripts`): ids `tb-isolated` and `tb-main`,
  `matches = sites.map(matchPattern)` (deduped; `matchPattern(o) = scheme://host/*`), `runAt:'document_start'`,
  `allFrames:false`, `persistAcrossSessions:true`; unregister both when `sites` is empty.

## 15. Storage layout
| Area | Key | Content |
|---|---|---|
| `storage.local` | `tb.settings` | `Settings` |
| `storage.local` | `tb.audit` | `AuditPersisted` |
| `storage.session` | `tb.router` | `RouterState` |
Nothing else is persisted. No plaintext or ciphertext message bodies are persisted outside the audit log's content records.

## 16. Tests
- `test/unit/*.test.ts`: encoding, protocol (validators, codec, AAD), crypto (key agreement,
  tamper → DECRYPT_FAILED, header tamper), permissions, pairing, audit (chain, tamper, retention),
  files (each type, disguises, names), router (sender classification, every §5.3 rule), endpoint.
- `test/integration/exchange.test.ts`: Router + 2 Endpoints over FakePorts with real crypto: pair,
  bidirectional `ask/reply`, task, file ok/denied, narrowing, close, expiry, replay injection,
  audit verify.
- `test/e2e/extension.spec.ts` (Playwright, Chromium, `dist/chrome-e2e`): demo pages on two
  origins, pairing via popup pages, bidirectional exchange, file transfer, audit verify.

---
### Changelog
- v1.0 — initial spec.
- v1.1 — §13: added `sniffDenied` (executables/archives/shebang always denied) and stricter text control-char rule.
