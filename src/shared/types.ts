// Shared contracts. Mirrors SPEC.md §3 verbatim, plus §5 router records and §6.2 public API types.
// Do not change without updating SPEC.md first.
import type { ErrorCode } from './errors';
export type { ErrorCode } from './errors';

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

// ---------- Router persisted state (SPEC §5) ----------
export interface RateBucket { windowStart: number; frames: number; bytes: number; }
export interface EndpointRecord {
  endpointId: EndpointId; kind: EndpointKind; origin: string; tabId?: number; title?: string;
  agent: AgentInfo; resumeTokenHash: string; connected: boolean; disconnectedAt?: number;
}
export interface RoutedFrame {
  from: EndpointId; to: EndpointId; kind: FrameKind; at: number;
  sentDetail: boolean; recvDetail: boolean; receipt?: ReceiptStatus;
}
export interface RoomRecord {
  roomId: RoomId; state: RoomState; createdAt: number; members: [RoomMember, RoomMember]; grant: Grant;
  pubKeys: Record<EndpointId, string>; confirmed: EndpointId[]; lastSeq: Record<EndpointId, number>;
  rate: Record<EndpointId, RateBucket>; recentFrameIds: FrameId[];
  routed: Record<FrameId, RoutedFrame>;
  counters: { routed: number; rejected: number }; closedReason?: CloseReason; closedAt?: number;
}
export interface RouterState {
  v: 1; endpoints: Record<EndpointId, EndpointRecord>; rooms: Record<RoomId, RoomRecord>;
  pairing: PairingSnapshot; pairRequests: UiState['pairRequests']; pendingSites: string[];
}

// ---------- Public page API (SPEC §6.2) ----------
export interface AgentEventMap {
  prompt: InboundMessage & { reply(text: string): Promise<SendResult> };
  response: InboundMessage;
  task: InboundTask;
  file: { id: FrameId; roomId: RoomId; file: File; threadId?: string; provenance: Provenance; from: PeerRef };
  room: RoomView;
  error: AgentErrorEvent;
}
export interface TabBridgeSession {
  readonly apiVersion: 1;
  rooms(): Promise<RoomView[]>;
  requestPairing(opts?: { note?: string }): Promise<void>;
  send(roomId: string, msg: { type: 'prompt' | 'response'; text: string; threadId?: string; inReplyTo?: string }): Promise<SendResult>;
  ask(roomId: string, text: string, opts?: { threadId?: string; timeoutMs?: number }): Promise<InboundMessage>;
  sendTask(roomId: string, task: TaskBody): Promise<SendResult>;
  sendFile(roomId: string, file: Blob, opts?: { name?: string; threadId?: string }): Promise<SendResult>;
  leave(roomId: string): Promise<void>;
  on<E extends AgentEventName>(ev: E, cb: (d: AgentEventMap[E]) => void): () => void;
  off<E extends AgentEventName>(ev: E, cb: (d: AgentEventMap[E]) => void): void;
  close(): Promise<void>;
}
export interface TabBridgeGlobal {
  readonly version: string;
  readonly apiVersions: readonly number[];
  connect(opts: { apiVersion: 1; agentName: string }): Promise<TabBridgeSession>;
}
