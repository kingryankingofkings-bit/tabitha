// Agent Console (side panel / sidebar): a human-operated endpoint (kind 'panel'). It can pair
// like a tab, read incoming prompts/tasks/files and answer by hand.
import { ext } from '../../platform/ext';
import { ID_TOKEN_RE, MAX_SUMMARY_CHARS, PANEL_ORIGIN, PORT_ENDPOINT, TASK_STATUSES } from '../../shared/limits';
import { TabBridgeError } from '../../shared/errors';
import type {
  AgentErrorEvent,
  AllowedMime,
  FrameId,
  InboundFileData,
  InboundMessage,
  InboundTask,
  RoomId,
  RoomView,
  RuntimePortLike,
  TaskBody,
  TaskStatus,
  UiState,
} from '../../shared/types';
import { Endpoint } from '../../endpoint/endpoint';
import { UiClient } from '../lib/client';
import { connectionNotice, errorArea, pauseControl, wordmark } from '../lib/common';
import { $, countdownEl, downloadBytes, h, originEl, reconcile, replaceChildren, show, stamp, startTicker, uid, type StampTone } from '../lib/dom';
import { CLOSE_REASONS, MIME_LABELS, TEXT_MIMES, describeError, formatBytes, formatDateTime, formatTime, kindLabel, shortId } from '../lib/format';
import { grantLines, roomStateStamp } from '../lib/grants';
import { pairingSection } from '../lib/pairing';

const TEXT_PREVIEW_MAX = 64 * 1024;
const MAX_ITEMS_PER_ROOM = 500;
const AGENT_NAME = 'Agent Console (human)';

type ItemType = 'prompt' | 'response' | 'task' | 'file' | 'error';
interface Item {
  key: string;
  id?: FrameId;
  dir: 'in' | 'out';
  type: ItemType;
  at: number;
  sentAt?: number;
  fromOrigin?: string;
  text?: string;
  threadId?: string;
  inReplyTo?: FrameId;
  task?: TaskBody;
  file?: InboundFileData;
  outFile?: { name: string; size: number };
  status?: 'sending' | 'delivered' | 'failed';
  error?: { code: string; message: string };
}

const client = new UiClient();
startTicker();

const app = $('#app');
const err = errorArea();
const pause = pauseControl(client, err.show);

const rooms = new Map<RoomId, RoomView>();
const timelines = new Map<RoomId, Item[]>();
const unread = new Map<RoomId, number>();
let selected: RoomId | null = null;
let replyTo: { id: FrameId; threadId: string; text: string } | null = null;
let uiState: UiState | undefined;
let started = false;
let keySeq = 0;
const nextKey = (): string => `i${++keySeq}`;

function push(roomId: RoomId, item: Item): void {
  let list = timelines.get(roomId);
  if (!list) {
    list = [];
    timelines.set(roomId, list);
  }
  list.push(item);
  if (list.length > MAX_ITEMS_PER_ROOM) list.splice(0, list.length - MAX_ITEMS_PER_ROOM);
  if (item.dir === 'in' && roomId !== selected) unread.set(roomId, (unread.get(roomId) ?? 0) + 1);
  if (!selected && rooms.has(roomId)) selected = roomId;
  renderRooms();
  if (roomId === selected) renderTimeline();
}

// =====================================================================================
// Endpoint (kind 'panel'); the human operator is the agent.
// =====================================================================================
function makeEndpoint(): Endpoint {
  return new Endpoint({
  connect: () => ext.runtime.connect({ name: PORT_ENDPOINT }) as unknown as RuntimePortLike,
  kind: 'panel',
  sink: {
    hasAgent: () => true,
    onPrompt: (m: InboundMessage) => push(m.roomId, inboundText(m)),
    onResponse: (m: InboundMessage) => push(m.roomId, inboundText(m)),
    onTask: (t: InboundTask) =>
      push(t.roomId, { key: nextKey(), id: t.id, dir: 'in', type: 'task', at: t.receivedAt, sentAt: t.sentAt, fromOrigin: t.from.origin, task: t.task, threadId: t.task.threadId }),
    onFile: (f: InboundFileData) =>
      push(f.roomId, { key: nextKey(), id: f.id, dir: 'in', type: 'file', at: f.provenance.receivedAt, sentAt: f.provenance.sentAt, fromOrigin: f.from.origin, file: f, threadId: f.threadId }),
    onRoom: (r: RoomView) => {
      rooms.set(r.roomId, r);
      if (!selected || (rooms.get(selected)?.state === 'closed' && r.state !== 'closed')) selected = r.roomId;
      renderRooms();
      renderConversation();
    },
    onError: (e: AgentErrorEvent) => {
      if (e.roomId && rooms.has(e.roomId)) {
        push(e.roomId, { key: nextKey(), id: e.frameId, dir: 'in', type: 'error', at: Date.now(), error: { code: e.code, message: e.message } });
      }
      err.show(e);
    },
    onPaused: (p: boolean) => pause.update(p),
  },
  });
}
let endpoint = makeEndpoint();

function inboundText(m: InboundMessage): Item {
  return { key: nextKey(), id: m.id, dir: 'in', type: m.type, at: m.receivedAt, sentAt: m.sentAt, fromOrigin: m.from.origin, text: m.text, threadId: m.threadId, inReplyTo: m.inReplyTo };
}

// =====================================================================================
// Identity
// =====================================================================================
const endpointLabel = h('span', { class: 'mono', 'data-testid': 'console-endpoint' }, '—');
const endpointPill = h('span', { class: 'pill' }, 'starting');
const retryBtn = h('button', { type: 'button', class: 'btn btn--sm', hidden: true }, 'Retry');
const identity = h(
  'section',
  { class: 'section', 'aria-labelledby': 'id-h' },
  h('div', { class: 'section__head' }, h('h2', { id: 'id-h' }, 'This console')),
  h('div', { class: 'row' }, originEl(PANEL_ORIGIN), h('span', { class: 'muted small' }, 'endpoint'), endpointLabel, h('span', { class: 'spacer' }), endpointPill, retryBtn),
  h('p', { class: 'small muted' }, 'Use this console as the other end of a room when a tab has no AI agent: you read incoming prompts, tasks and files and answer by hand.'),
);

function renderIdentity(): void {
  const id = endpoint.endpointId;
  endpointLabel.textContent = id ? shortId(id) : '—';
  endpointLabel.title = id ?? '';
  const info = id ? uiState?.endpoints.find((e) => e.endpointId === id) : undefined;
  const connected = started && (info ? info.connected : !!id);
  endpointPill.textContent = !started ? 'starting' : connected ? 'connected' : 'offline';
  endpointPill.className = `pill ${connected ? 'pill--ok' : started ? 'pill--warn' : ''}`;
}

// =====================================================================================
// Pairing (as this console)
// =====================================================================================
const pairing = pairingSection({
  client,
  selector: () => {
    const id = endpoint.endpointId;
    if (!started || !id) return null;
    const info = uiState?.endpoints.find((e) => e.endpointId === id);
    return info && !info.connected ? null : { endpointId: id };
  },
  isMine: (ref) => !!endpoint.endpointId && ref.endpointId === endpoint.endpointId,
  selfName: 'This console',
  otherName: 'The other tab',
  onError: err.show,
  clearError: err.clear,
});

// =====================================================================================
// Rooms list
// =====================================================================================
const roomList = h('div', { class: 'room-tabs', role: 'list' });
const roomsSection = h(
  'section',
  { class: 'section', 'aria-labelledby': 'rooms-h' },
  h('div', { class: 'section__head' }, h('h2', { id: 'rooms-h' }, 'Rooms')),
  roomList,
);

function sortedRooms(): RoomView[] {
  return [...rooms.values()].sort((a, b) => Number(a.state === 'closed') - Number(b.state === 'closed') || b.createdAt - a.createdAt);
}

function renderRooms(): void {
  reconcile(
    roomList,
    sortedRooms(),
    (r) => r.roomId,
    (r) => JSON.stringify([r.state, r.peer, r.expiresAt, r.roomId === selected, unread.get(r.roomId) ?? 0]),
    (r) => {
      const n = unread.get(r.roomId) ?? 0;
      const btn = h(
        'button',
        {
          type: 'button',
          class: 'room-tab',
          role: 'listitem',
          'aria-current': String(r.roomId === selected),
          'data-testid': 'console-room',
          'data-room-id': r.roomId,
          'data-state': r.state,
        },
        h(
          'span',
          { class: 'row' },
          roomStateStamp(r.state),
          h('span', { class: 'small muted' }, `with ${kindLabel(r.peer.kind)}`),
          h('span', { class: 'spacer' }),
          n ? h('span', { class: 'pill pill--info', 'aria-label': `${n} new` }, String(n)) : null,
        ),
        originEl(r.peer.origin),
      );
      btn.addEventListener('click', () => {
        selected = r.roomId;
        unread.delete(r.roomId);
        replyTo = null;
        renderRooms();
        renderConversation();
      });
      return btn;
    },
    () => h('p', { class: 'small muted' }, 'No rooms yet. Start pairing above, or join with a code shown in a tab’s popup.'),
  );
}

// =====================================================================================
// Conversation
// =====================================================================================
const convHead = h('div', { class: 'stack' });
const timeline = h('div', { class: 'timeline', role: 'log', 'aria-live': 'polite', 'aria-label': 'Conversation' });
const replyChip = h('div', { class: 'reply-chip', hidden: true });
const composeId = uid('compose');
const compose = h('textarea', { id: composeId, rows: '4', placeholder: 'Write a prompt…', 'data-testid': 'console-compose' });
const sendBtn = h('button', { type: 'button', class: 'btn btn--primary', 'data-testid': 'console-send' }, 'Send prompt');
const composeNote = h('p', { class: 'small muted' });
const composer = h(
  'div',
  { class: 'composer' },
  replyChip,
  h('label', { class: 'label', for: composeId }, 'Message'),
  compose,
  h('div', { class: 'row' }, sendBtn, h('span', { class: 'small muted' }, 'Ctrl/⌘ + Enter to send')),
  composeNote,
);

// task update
const taskIdId = uid('task');
const taskStatusId = uid('task');
const taskProgId = uid('task');
const taskSumId = uid('task');
const taskIdInput = h('input', { type: 'text', id: taskIdId, placeholder: 'task-1', 'data-testid': 'console-task-id', autocomplete: 'off' });
const taskStatus = h('select', { id: taskStatusId, 'data-testid': 'console-task-status' }, TASK_STATUSES.map((s) => h('option', { value: s }, s)));
const taskProgress = h('input', { type: 'number', id: taskProgId, min: '0', max: '100', step: '1', placeholder: '—', 'data-testid': 'console-task-progress' });
const taskSummary = h('textarea', { id: taskSumId, rows: '2', maxlength: String(MAX_SUMMARY_CHARS), 'data-testid': 'console-task-summary' });
const taskSend = h('button', { type: 'button', class: 'btn', 'data-testid': 'console-task-send' }, 'Send task update');
const taskBlock = h(
  'details',
  { class: 'disclosure' },
  h('summary', null, 'Send task update'),
  h(
    'div',
    { class: 'disclosure__body' },
    h('div', { class: 'row' }, h('div', { class: 'field' }, h('label', { class: 'label', for: taskIdId }, 'Task ID'), taskIdInput), h('div', { class: 'field' }, h('label', { class: 'label', for: taskStatusId }, 'Status'), taskStatus), h('div', { class: 'field' }, h('label', { class: 'label', for: taskProgId }, 'Progress %'), taskProgress)),
    h('div', { class: 'field' }, h('label', { class: 'label', for: taskSumId }, 'Summary'), taskSummary),
    h('div', { class: 'row' }, taskSend),
  ),
);

// file
const fileId = uid('file');
const fileInput = h('input', { type: 'file', id: fileId, 'data-testid': 'console-file' });
const fileSend = h('button', { type: 'button', class: 'btn', 'data-testid': 'console-file-send' }, 'Send file');
const fileNote = h('p', { class: 'small muted' });
const fileBlock = h(
  'details',
  { class: 'disclosure' },
  h('summary', null, 'Send file'),
  h('div', { class: 'disclosure__body' }, h('label', { class: 'label', for: fileId }, 'File'), fileInput, fileNote, h('div', { class: 'row' }, fileSend)),
);

const convSection = h(
  'section',
  { class: 'section', 'aria-labelledby': 'conv-h', hidden: true },
  h('div', { class: 'section__head' }, h('h2', { id: 'conv-h' }, 'Conversation')),
  convHead,
  timeline,
  composer,
  taskBlock,
  fileBlock,
);

function selectedRoom(): RoomView | undefined {
  return selected ? rooms.get(selected) : undefined;
}

function renderConversation(): void {
  const r = selectedRoom();
  show(convSection, !!r);
  if (!r) return;
  const closed = r.state === 'closed';
  const active = r.state === 'active';
  const closeBtn = h('button', { type: 'button', class: 'btn btn--deny-ghost btn--sm', 'data-testid': 'room-close' }, 'Close room');
  closeBtn.addEventListener('click', () => {
    closeBtn.disabled = true;
    client.call('room.close', { roomId: r.roomId }).then(err.clear, (e) => {
      closeBtn.disabled = false;
      err.show(e);
    });
  });
  replaceChildren(
    convHead,
    h(
      'div',
      { class: 'row' },
      roomStateStamp(r.state),
      h('span', { class: 'mono small', title: r.roomId }, `room ${shortId(r.roomId)}`),
      h('span', { class: 'spacer' }),
      closed
        ? h('span', { class: 'small muted' }, CLOSE_REASONS[r.closedReason ?? 'user'] ?? r.closedReason)
        : h('span', { class: 'small mono' }, 'expires in ', countdownEl(r.expiresAt)),
    ),
    h(
      'div',
      { class: 'passport' },
      h('span', { class: 'label' }, `Other side · ${kindLabel(r.peer.kind)} · ${r.peer.connected ? 'connected' : 'offline'}`),
      originEl(r.peer.origin, {}, true),
      h('span', { class: 'small muted' }, r.peer.agentName ? `agent: ${r.peer.agentName}` : 'no agent attached'),
    ),
    grantLines([
      { who: 'This console', grant: r.outbound },
      { who: 'The other side', grant: r.inbound },
    ]),
    closed ? null : h('div', { class: 'row' }, closeBtn),
  );

  // Gate controls by room state and the outbound grant (the router enforces this too).
  const canPrompt = active && r.outbound.prompts;
  compose.disabled = !canPrompt;
  sendBtn.disabled = !canPrompt;
  composeNote.textContent = !active
    ? closed
      ? 'This room is closed.'
      : 'Keys are being exchanged. Sending unlocks when the room is active.'
    : r.outbound.prompts
      ? ''
      : 'This room does not allow the console to send prompts or replies.';
  taskSend.disabled = !(active && r.outbound.tasks);
  taskBlock.hidden = !r.outbound.tasks;
  const canFile = active && r.outbound.files && r.outbound.fileTypes.length > 0;
  fileSend.disabled = !canFile;
  fileBlock.hidden = !r.outbound.files;
  fileNote.textContent = r.outbound.files
    ? `Allowed: ${r.outbound.fileTypes.map((m) => MIME_LABELS[m]?.short ?? m).join(', ')} up to ${formatBytes(r.outbound.maxFileBytes)}. Content is checked before sending.`
    : '';
  if (replyTo && !timelines.get(r.roomId)?.some((i) => i.id === replyTo?.id)) replyTo = null;
  renderReplyChip();
  renderTimeline();
}

function renderReplyChip(): void {
  show(replyChip, !!replyTo);
  sendBtn.textContent = replyTo ? 'Send reply' : 'Send prompt';
  compose.placeholder = replyTo ? 'Write a reply…' : 'Write a prompt…';
  if (!replyTo) return;
  const snippet = replyTo.text.length > 80 ? `${replyTo.text.slice(0, 80)}…` : replyTo.text;
  const cancel = h('button', { type: 'button', class: 'btn btn--ghost btn--sm' }, 'Cancel reply');
  cancel.addEventListener('click', () => {
    replyTo = null;
    renderReplyChip();
  });
  replaceChildren(replyChip, h('span', { class: 'truncate' }, 'Replying to ', h('span', { class: 'mono' }, shortId(replyTo.id)), ': “', snippet, '”'), h('span', { class: 'spacer' }), cancel);
}

function itemStamp(it: Item): HTMLElement {
  const tone: StampTone = it.type === 'error' ? 'deny' : it.dir === 'in' ? 'info' : 'ink';
  return stamp(it.type === 'error' ? 'Rejected' : it.type, tone);
}

function statusText(it: Item): HTMLElement | null {
  if (it.dir !== 'out') return null;
  if (it.status === 'sending') return h('span', null, 'sending…');
  if (it.status === 'delivered') return h('span', { class: 'pill pill--ok' }, 'delivered');
  if (it.status === 'failed') return h('span', { class: 'pill pill--deny' }, 'not delivered');
  return null;
}

function fileDetails(f: InboundFileData): HTMLElement {
  const p = f.provenance;
  const saveBtn = h('button', { type: 'button', class: 'btn btn--sm', 'data-testid': 'console-file-save' }, 'Save…');
  saveBtn.addEventListener('click', () => downloadBytes(f.bytes, f.name));
  let preview: HTMLElement | null = null;
  if (TEXT_MIMES.has(f.mime)) {
    const slice = f.bytes.subarray(0, TEXT_PREVIEW_MAX);
    const text = new TextDecoder('utf-8').decode(slice);
    preview = h(
      'details',
      { class: 'disclosure' },
      h('summary', null, f.bytes.length > TEXT_PREVIEW_MAX ? 'Show text (first 64 KB)' : 'Show text'),
      h('div', { class: 'disclosure__body' }, h('pre', { class: 'pre' }, text)),
    );
  }
  return h(
    'div',
    { class: 'stack stack--sm' },
    h(
      'dl',
      { class: 'kv' },
      h('dt', null, 'Name'),
      h('dd', { class: 'mono break' }, f.name),
      h('dt', null, 'Type'),
      h('dd', null, `${MIME_LABELS[f.mime as AllowedMime]?.long ?? f.mime} `, h('span', { class: 'mono muted' }, `(${p.detectedType}, detected from content)`)),
      h('dt', null, 'Size'),
      h('dd', { class: 'mono' }, `${formatBytes(p.size)} (${p.size} bytes)`),
      h('dt', null, 'SHA-256'),
      h('dd', { class: 'mono break' }, p.sha256),
      h('dt', null, 'From'),
      h('dd', null, originEl(p.fromOrigin), h('span', { class: 'muted' }, ` · ${kindLabel(p.fromKind)}`)),
      h('dt', null, 'Frame'),
      h('dd', { class: 'mono break', title: p.frameId }, shortId(p.frameId, 16)),
      h('dt', null, 'Sent / received'),
      h('dd', { class: 'mono' }, `${formatDateTime(p.sentAt)} / ${formatTime(p.receivedAt)}`),
      h('dt', null, 'Validated'),
      h('dd', null, p.validated ? stamp('Inspected', 'ok') : stamp('No', 'deny')),
    ),
    h('p', { class: 'small muted' }, 'Files are never opened or rendered here. Type and size were checked, but the content was not scanned for malware.'),
    preview,
    h('div', { class: 'row' }, saveBtn),
  );
}

function renderItem(it: Item): HTMLElement {
  const actions: HTMLElement[] = [];
  const r = selectedRoom();
  if (it.dir === 'in' && it.type === 'prompt' && it.id && it.threadId) {
    const reply = h('button', { type: 'button', class: 'btn btn--sm', 'data-testid': 'console-reply', disabled: !(r?.state === 'active' && r.outbound.prompts) }, 'Reply');
    const msgId = it.id;
    const threadId = it.threadId;
    const text = it.text ?? '';
    reply.addEventListener('click', () => {
      replyTo = { id: msgId, threadId, text };
      renderReplyChip();
      compose.focus();
    });
    actions.push(reply);
  }
  if (it.dir === 'out' && it.status === 'failed' && it.text) {
    const again = h('button', { type: 'button', class: 'btn btn--ghost btn--sm' }, 'Copy to composer');
    const text = it.text;
    again.addEventListener('click', () => {
      compose.value = text;
      compose.focus();
    });
    actions.push(again);
  }
  let body: HTMLElement | null = null;
  if (it.type === 'prompt' || it.type === 'response') {
    body = h('div', { class: 'msg__text' }, it.text ?? '');
  } else if (it.type === 'task' && it.task) {
    const t = it.task;
    const tone: StampTone = t.status === 'done' ? 'ok' : t.status === 'failed' || t.status === 'cancelled' ? 'deny' : t.status === 'blocked' ? 'warn' : 'info';
    body = h(
      'dl',
      { class: 'kv' },
      h('dt', null, 'Task'),
      h('dd', { class: 'mono' }, t.taskId),
      h('dt', null, 'Status'),
      h('dd', null, stamp(t.status, tone)),
      t.progress !== undefined ? [h('dt', null, 'Progress'), h('dd', { class: 'mono' }, `${Math.round(t.progress * 100)}%`)] : null,
      t.summary ? [h('dt', null, 'Summary'), h('dd', { class: 'msg__text' }, t.summary)] : null,
    );
  } else if (it.type === 'file') {
    if (it.file) body = fileDetails(it.file);
    else if (it.outFile) body = h('dl', { class: 'kv' }, h('dt', null, 'Name'), h('dd', { class: 'mono break' }, it.outFile.name), h('dt', null, 'Size'), h('dd', { class: 'mono' }, formatBytes(it.outFile.size)));
  }
  const errLine = it.error ? h('div', { class: 'msg__error' }, h('span', { class: 'error-area__code' }, it.error.code), it.error.message) : null;
  return h(
    'article',
    {
      class: `msg msg--${it.dir}${it.type === 'error' || it.status === 'failed' ? ' msg--error' : ''}`,
      'data-testid': 'console-message',
      'data-type': it.type,
      'data-dir': it.dir,
      'data-id': it.id ?? '',
    },
    h(
      'div',
      { class: 'msg__head' },
      itemStamp(it),
      h('span', { class: 'mono', title: formatDateTime(it.at) }, formatTime(it.at)),
      it.dir === 'in' && it.fromOrigin ? h('span', null, 'from ', originEl(it.fromOrigin)) : it.dir === 'out' ? h('span', null, 'from this console') : null,
      it.threadId ? h('span', { class: 'mono', title: 'thread' }, `#${it.threadId}`) : null,
      it.inReplyTo ? h('span', { class: 'mono', title: it.inReplyTo }, `↩ ${shortId(it.inReplyTo)}`) : null,
      statusText(it),
    ),
    body,
    errLine,
    actions.length ? h('div', { class: 'msg__actions' }, actions) : null,
  );
}

function renderTimeline(): void {
  const r = selectedRoom();
  if (!r) return;
  const nearBottom = timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 48;
  const items = timelines.get(r.roomId) ?? [];
  reconcile(
    timeline,
    items,
    (it) => it.key,
    (it) => JSON.stringify([it.status, it.id, it.error?.code, r.state, r.outbound.prompts]),
    renderItem,
    () => h('p', { class: 'timeline__empty' }, 'No messages yet.'),
  );
  if (nearBottom) timeline.scrollTop = timeline.scrollHeight;
}

// ---- send actions ----
function track(roomId: RoomId, item: Item, p: Promise<{ frameId: FrameId }>): void {
  push(roomId, item);
  p.then(
    (res) => {
      item.id = res.frameId;
      item.status = 'delivered';
      if (roomId === selected) renderTimeline();
    },
    (e: unknown) => {
      item.status = 'failed';
      item.error = describeError(e);
      err.show(e);
      if (roomId === selected) renderTimeline();
    },
  );
}

function sendMessage(): void {
  const r = selectedRoom();
  const text = compose.value;
  if (!r || !text.trim()) return;
  err.clear();
  const reply = replyTo;
  const type = reply ? 'response' : 'prompt';
  const opts = reply ? { threadId: reply.threadId, inReplyTo: reply.id } : undefined;
  let p: Promise<{ frameId: FrameId }>;
  try {
    p = endpoint.sendText(r.roomId, type, text, opts);
  } catch (e) {
    p = Promise.reject(e);
  }
  track(r.roomId, { key: nextKey(), dir: 'out', type, at: Date.now(), text, threadId: reply?.threadId, inReplyTo: reply?.id, status: 'sending' }, p);
  compose.value = '';
  replyTo = null;
  renderReplyChip();
}
sendBtn.addEventListener('click', sendMessage);
compose.addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
    ev.preventDefault();
    sendMessage();
  }
});

taskSend.addEventListener('click', () => {
  const r = selectedRoom();
  if (!r) return;
  const taskId = taskIdInput.value.trim();
  if (!ID_TOKEN_RE.test(taskId)) {
    err.show(new TabBridgeError('VALIDATION_FAILED', 'Task ID: 1–64 letters, digits, "_" or "-".'));
    return;
  }
  const task: TaskBody = { taskId, status: taskStatus.value as TaskStatus };
  if (taskProgress.value !== '') {
    const n = Number(taskProgress.value);
    if (!Number.isFinite(n) || n < 0 || n > 100) {
      err.show(new TabBridgeError('VALIDATION_FAILED', 'Progress must be between 0 and 100.'));
      return;
    }
    task.progress = n / 100;
  }
  const summary = taskSummary.value.trim();
  if (summary) task.summary = summary.slice(0, MAX_SUMMARY_CHARS);
  err.clear();
  let p: Promise<{ frameId: FrameId }>;
  try {
    p = endpoint.sendTask(r.roomId, task);
  } catch (e) {
    p = Promise.reject(e);
  }
  track(r.roomId, { key: nextKey(), dir: 'out', type: 'task', at: Date.now(), task, status: 'sending' }, p);
  taskSummary.value = '';
});

fileSend.addEventListener('click', () => {
  const r = selectedRoom();
  const file = fileInput.files?.[0];
  if (!r) return;
  if (!file) {
    err.show(new TabBridgeError('VALIDATION_FAILED', 'Choose a file first.'));
    return;
  }
  err.clear();
  const roomId = r.roomId;
  const p = file.arrayBuffer().then((buf) => endpoint.sendFile(roomId, { name: file.name, bytes: new Uint8Array(buf) }));
  track(roomId, { key: nextKey(), dir: 'out', type: 'file', at: Date.now(), outFile: { name: file.name, size: file.size }, status: 'sending' }, p);
  fileInput.value = '';
});

// =====================================================================================
// Page
// =====================================================================================
replaceChildren(
  app,
  h('header', { class: 'masthead' }, wordmark('Agent Console'), h('span', { class: 'spacer' }), pause.button),
  pause.banner,
  connectionNotice(client),
  h('main', { class: 'main panel-grid' }, err.el, identity, pairing.el, roomsSection, convSection),
);
app.removeAttribute('aria-busy');

client.onState((s) => {
  uiState = s;
  pause.update(s.paused);
  renderIdentity();
  pairing.update(s);
});
client.call('settings.get').then(
  (s) => pairing.setDefaults(s.defaultProposal),
  () => undefined,
);

function start(): void {
  retryBtn.hidden = true;
  endpoint.start().then(
    (w) => {
      started = true;
      for (const r of w.rooms) rooms.set(r.roomId, r);
      if (!selected) selected = sortedRooms().find((r) => r.state !== 'closed')?.roomId ?? null;
      pause.update(w.paused);
      endpoint.setAgent(true, AGENT_NAME);
      renderIdentity();
      pairing.update(uiState);
      renderRooms();
      renderConversation();
    },
    (e: unknown) => {
      started = false;
      renderIdentity();
      retryBtn.hidden = false;
      err.show(e);
    },
  );
}
retryBtn.addEventListener('click', () => {
  // A failed start() stays rejected; retry with a fresh endpoint.
  endpoint.stop();
  endpoint = makeEndpoint();
  start();
});
renderIdentity();
renderRooms();
start();
