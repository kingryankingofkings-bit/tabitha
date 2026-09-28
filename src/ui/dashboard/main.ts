// Dashboard (options page): sites, endpoints, rooms, the audit ledger and settings.
import { AUDIT_MAX_MAX_ENTRIES, AUDIT_MIN_MAX_ENTRIES } from '../../shared/limits';
import type { AuditEntry, AuditType, EndpointInfo, RoomAdminView, RoomMember, Settings, UiState } from '../../shared/types';
import { UiClient } from '../lib/client';
import { connectionNotice, errorArea, pauseControl, wordmark } from '../lib/common';
import { $, countdownEl, downloadBytes, h, originEl, reconcile, replaceChildren, stamp, startTicker, uid, unverifiedTitle } from '../lib/dom';
import { AUDIT_TYPES, CLOSE_REASONS, auditStamp, auditSummary, formatBytes, formatDateTime, formatTime, kindLabel, shortId } from '../lib/format';
import { grantEditor, grantLines, narrowControl, roomStateStamp, ttlSelect } from '../lib/grants';

const client = new UiClient();
startTicker();

const app = $('#app');
const err = errorArea();
const pause = pauseControl(client, err.show);
let state: UiState | undefined;

// =====================================================================================
// Sites & endpoints
// =====================================================================================
const sitesBody = h('tbody');
const endpointsBody = h('tbody');
const sitesSection = h(
  'section',
  { class: 'section', id: 'sites', 'aria-labelledby': 'sites-h' },
  h('div', { class: 'section__head' }, h('h2', { id: 'sites-h' }, 'Sites'), h('span', { class: 'section__hint' }, 'Origins where pages may reach TabBridge. Everything else sees nothing.')),
  h(
    'div',
    { class: 'table-wrap' },
    h('table', { class: 'table' }, h('thead', null, h('tr', null, h('th', null, 'Origin'), h('th', null, 'Status'), h('th', { class: 'num' }, 'Endpoints'), h('th', null, ''))), sitesBody),
  ),
  h('h3', null, 'Connected endpoints'),
  h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      { class: 'table' },
      h('thead', null, h('tr', null, h('th', null, 'Endpoint'), h('th', null, 'Origin'), h('th', null, 'Where'), h('th', null, 'Agent'), h('th', null, 'Link'))),
      endpointsBody,
    ),
  ),
);

function renderSites(s: UiState): void {
  const rows: HTMLElement[] = [];
  const all = [...s.sites.map((o) => ({ o, pending: false })), ...s.pendingSites.filter((o) => !s.sites.includes(o)).map((o) => ({ o, pending: true }))];
  for (const { o, pending } of all) {
    const count = s.endpoints.filter((e) => e.origin === o && e.connected).length;
    const btn = h('button', { type: 'button', class: 'btn btn--deny-ghost btn--sm', 'data-testid': 'dash-site-disable' }, 'Disable');
    btn.addEventListener('click', () => {
      btn.disabled = true;
      client.call('site.disable', { origin: o }).then(err.clear, (e) => {
        btn.disabled = false;
        err.show(e);
      });
    });
    rows.push(
      h(
        'tr',
        { 'data-testid': 'dash-site', 'data-origin': o },
        h('td', null, originEl(o)),
        h('td', null, pending ? h('span', { class: 'pill pill--warn' }, 'awaiting permission') : h('span', { class: 'pill pill--ok' }, 'enabled')),
        h('td', { class: 'num' }, String(count)),
        h('td', { class: 'num' }, pending ? null : btn),
      ),
    );
  }
  if (!rows.length) rows.push(h('tr', null, h('td', { class: 'table__empty', colspan: '4' }, 'No sites enabled. Use the TabBridge toolbar popup on a page to enable its site.')));
  sitesBody.replaceChildren(...rows);

  const eps = [...s.endpoints].sort((a, b) => Number(b.connected) - Number(a.connected) || a.origin.localeCompare(b.origin));
  endpointsBody.replaceChildren(
    ...(eps.length
      ? eps.map((e: EndpointInfo, i) =>
          h(
            'tr',
            { class: i % 2 ? '' : 'row--zebra' },
            h('td', { class: 'mono', title: e.endpointId }, shortId(e.endpointId)),
            h('td', null, originEl(e.origin), unverifiedTitle(e.title)),
            h('td', null, kindLabel(e.kind, e.tabId)),
            h('td', null, e.agent.attached ? h('span', { class: 'mono' }, e.agent.name ?? 'unnamed') : h('span', { class: 'muted' }, 'none')),
            h('td', null, e.connected ? h('span', { class: 'pill pill--ok' }, 'connected') : h('span', { class: 'pill' }, 'offline')),
          ),
        )
      : [h('tr', null, h('td', { class: 'table__empty', colspan: '5' }, 'No endpoints.'))]),
  );
}

// =====================================================================================
// Rooms
// =====================================================================================
const roomsList = h('div', { class: 'grid-2', 'data-testid': 'dash-rooms' });
const narrowOpen = new Set<string>();
const roomsSection = h(
  'section',
  { class: 'section', id: 'rooms', 'aria-labelledby': 'rooms-h' },
  h('div', { class: 'section__head' }, h('h2', { id: 'rooms-h' }, 'Rooms'), h('span', { class: 'section__hint' }, 'Closed rooms stay listed for 10 minutes.')),
  roomsList,
);

function memberBlock(label: string, m: RoomMember, eps: Map<string, EndpointInfo>): HTMLElement {
  const e = eps.get(m.endpointId);
  return h(
    'div',
    { class: 'passport' },
    h('span', { class: 'label' }, `${label} · ${kindLabel(m.kind, m.tabId)}`),
    originEl(m.origin),
    h(
      'span',
      { class: 'small muted' },
      h('span', { class: 'mono', title: m.endpointId }, shortId(m.endpointId)),
      ' · ',
      e?.connected ? 'connected' : 'offline',
      ' · ',
      e?.agent.attached ? `agent: ${e.agent.name ?? 'unnamed'}` : 'no agent',
    ),
  );
}

function roomCard(r: RoomAdminView, eps: Map<string, EndpointInfo>): HTMLElement {
  const ini = r.members.find((m) => m.role === 'initiator') ?? r.members[0];
  const joi = r.members.find((m) => m.role === 'joiner') ?? r.members[1];
  const closed = r.state === 'closed';
  const closeBtn = h('button', { type: 'button', class: 'btn btn--deny-ghost btn--sm', 'data-testid': 'room-close' }, 'Close room');
  closeBtn.addEventListener('click', () => {
    closeBtn.disabled = true;
    client.call('room.close', { roomId: r.roomId }).then(err.clear, (e) => {
      closeBtn.disabled = false;
      err.show(e);
    });
  });
  return h(
    'article',
    { class: `card${closed ? ' card--closed' : ''}`, 'data-testid': 'dash-room', 'data-room-id': r.roomId, 'data-state': r.state },
    h(
      'div',
      { class: 'card__head' },
      roomStateStamp(r.state),
      h('span', { class: 'mono small', title: r.roomId }, `room ${shortId(r.roomId)}`),
      h('span', { class: 'spacer' }),
      closed
        ? h('span', { class: 'small muted' }, CLOSE_REASONS[r.closedReason ?? 'user'] ?? r.closedReason)
        : h('span', { class: 'small mono' }, 'expires in ', countdownEl(r.grant.expiresAt)),
    ),
    h('div', { class: 'consent__parties' }, memberBlock('Initiator', ini, eps), memberBlock('Joiner', joi, eps)),
    grantLines([
      { who: 'Initiator', to: 'joiner', grant: r.grant.i2j },
      { who: 'Joiner', to: 'initiator', grant: r.grant.j2i },
    ]),
    h(
      'dl',
      { class: 'kv' },
      h('dt', null, 'Opened'),
      h('dd', { class: 'mono' }, formatDateTime(r.createdAt)),
      h('dt', null, 'Frames'),
      h('dd', { class: 'mono', 'data-room-counters': r.roomId }, `${r.frames.routed} routed · ${r.frames.rejected} rejected`),
      h('dt', null, 'Rate cap'),
      h('dd', { class: 'mono' }, `${r.grant.rate.framesPerMinute}/min · ${formatBytes(r.grant.rate.bytesPerMinute)}/min per sender`),
    ),
    closed
      ? null
      : h(
          'div',
          { class: 'card__foot' },
          closeBtn,
          narrowControl(
            r,
            { i2j: 'Initiator may send', j2i: 'Joiner may send' },
            (patch) =>
              client.call('room.narrow', { roomId: r.roomId, patch }).then(
                () => err.clear(),
                (e) => {
                  err.show(e);
                  throw e;
                },
              ),
            narrowOpen.has(r.roomId),
            (open) => (open ? narrowOpen.add(r.roomId) : narrowOpen.delete(r.roomId)),
          ),
        ),
  );
}

function renderRooms(s: UiState): void {
  const eps = new Map(s.endpoints.map((e) => [e.endpointId, e]));
  const rooms = [...s.rooms].sort((a, b) => Number(a.state === 'closed') - Number(b.state === 'closed') || b.createdAt - a.createdAt);
  reconcile(
    roomsList,
    rooms,
    (r) => r.roomId,
    (r) => JSON.stringify([r.state, r.grant, r.closedReason, r.members.map((m) => [eps.get(m.endpointId)?.connected, eps.get(m.endpointId)?.agent]), narrowOpen.has(r.roomId)]),
    (r) => roomCard(r, eps),
    () => h('p', { class: 'muted small' }, 'No rooms. Pair two tabs from the toolbar popup.'),
  );
  for (const r of rooms) {
    const c = roomsList.querySelector<HTMLElement>(`[data-room-counters="${r.roomId}"]`);
    if (c) c.textContent = `${r.frames.routed} routed · ${r.frames.rejected} rejected`;
  }
}

// =====================================================================================
// Audit ledger
// =====================================================================================
const PAGE = 100;
let entries: AuditEntry[] = []; // newest first
let exhausted = false;
let initialLoaded = false;
const expanded = new Set<number>();
const seenSeqs = new Set<number>();
let lastRenderKey = '';

const roomFilterId = uid('f');
const typeFilterId = uid('f');
const roomFilter = h('select', { id: roomFilterId, 'data-testid': 'audit-filter-room' }, h('option', { value: '' }, 'All rooms'));
const typeFilter = h(
  'select',
  { id: typeFilterId, 'data-testid': 'audit-filter-type' },
  h('option', { value: '' }, 'All types'),
  AUDIT_TYPES.map((t) => h('option', { value: t }, `${auditStamp(t, {}).label.toUpperCase()} · ${t}`)),
);
const verifyBtn = h('button', { type: 'button', class: 'btn', 'data-testid': 'audit-verify' }, 'Verify chain');
const verifyResult = h('span', { class: 'verify-result', 'data-testid': 'audit-verify-result', role: 'status' });
const exportBtn = h('button', { type: 'button', class: 'btn', 'data-testid': 'audit-export' }, 'Export JSON');
const clearBtn = h('button', { type: 'button', class: 'btn btn--deny-ghost', 'data-testid': 'audit-clear' }, 'Clear log…');
const auditBody = h('tbody');
const olderBtn = h('button', { type: 'button', class: 'btn btn--ghost', 'data-testid': 'audit-older' }, 'Load older entries');
const auditCount = h('span', { class: 'small muted', role: 'status' });

const auditSection = h(
  'section',
  { class: 'section', id: 'audit', 'aria-labelledby': 'audit-h' },
  h(
    'div',
    { class: 'section__head' },
    h('h2', { id: 'audit-h' }, 'Audit log'),
    h('span', { class: 'section__hint' }, 'Hash-chained record of every routing decision and every message, task and file. Newest first.'),
  ),
  h(
    'div',
    { class: 'toolbar' },
    h('div', { class: 'field' }, h('label', { class: 'label', for: roomFilterId }, 'Room'), roomFilter),
    h('div', { class: 'field' }, h('label', { class: 'label', for: typeFilterId }, 'Type'), typeFilter),
    h('span', { class: 'spacer' }),
    verifyBtn,
    exportBtn,
    clearBtn,
  ),
  verifyResult,
  h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      { class: 'table' },
      h(
        'thead',
        null,
        h('tr', null, h('th', { class: 'num' }, 'Seq'), h('th', null, 'Time'), h('th', null, 'Stamp'), h('th', null, 'Room'), h('th', null, 'Actor'), h('th', null, 'Summary'), h('th', null, h('span', { class: 'sr-only' }, 'Details'))),
      ),
      auditBody,
    ),
  ),
  h('div', { class: 'row' }, olderBtn, auditCount),
);

function actorText(e: AuditEntry): HTMLElement {
  const a = e.actor;
  return h(
    'span',
    { class: 'stack stack--sm' },
    h('span', { class: 'small' }, a.kind, a.endpointId ? h('span', { class: 'mono muted', title: a.endpointId }, ` ${shortId(a.endpointId)}`) : null),
    a.origin ? originEl(a.origin, { class: 'small' }) : null,
  );
}

function renderAudit(force = false): void {
  const type = typeFilter.value as AuditType | '';
  const shown = type ? entries.filter((e) => e.type === type) : entries;
  const key = JSON.stringify([type, shown.length, shown[0]?.seq, shown[shown.length - 1]?.seq, [...expanded]]);
  if (!force && key === lastRenderKey) return;
  lastRenderKey = key;
  const rows: HTMLElement[] = [];
  shown.forEach((e, i) => {
    const st = auditStamp(e.type, e.data);
    const isNew = initialLoaded && !seenSeqs.has(e.seq);
    const open = expanded.has(e.seq);
    const detailId = `audit-detail-${e.seq}`;
    const toggle = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'aria-expanded': String(open), 'aria-controls': detailId, 'data-testid': 'audit-entry-toggle' }, open ? 'Hide' : 'Details');
    toggle.addEventListener('click', () => {
      if (expanded.has(e.seq)) expanded.delete(e.seq);
      else expanded.add(e.seq);
      renderAudit(true);
      document.querySelector<HTMLElement>(`[aria-controls="${detailId}"]`)?.focus();
    });
    rows.push(
      h(
        'tr',
        { class: `row--entry${i % 2 ? '' : ' row--zebra'}`, 'data-testid': 'audit-entry', 'data-type': e.type, 'data-seq': String(e.seq) },
        h('td', { class: 'num' }, String(e.seq)),
        h('td', { class: 'mono', title: formatDateTime(e.ts) }, formatTime(e.ts)),
        h('td', null, stamp(st.label, st.tone, { class: isNew ? 'stamp--new' : '', title: e.type })),
        h('td', { class: 'mono', title: e.roomId ?? '' }, e.roomId ? shortId(e.roomId) : '—'),
        h('td', null, actorText(e)),
        h('td', { class: 'break' }, auditSummary(e.type, e.data) || h('span', { class: 'muted' }, e.type)),
        h('td', { class: 'num' }, toggle),
      ),
    );
    if (open) {
      rows.push(
        h(
          'tr',
          { class: 'detail', id: detailId },
          h(
            'td',
            { colspan: '7' },
            h(
              'div',
              { class: 'stack' },
              h(
                'dl',
                { class: 'kv' },
                h('dt', null, 'Type'),
                h('dd', { class: 'mono' }, e.type),
                h('dt', null, 'Time'),
                h('dd', { class: 'mono' }, formatDateTime(e.ts)),
                e.roomId ? [h('dt', null, 'Room'), h('dd', { class: 'mono break' }, e.roomId)] : null,
                h('dt', null, 'Hash'),
                h('dd', { class: 'mono break' }, e.hash),
                h('dt', null, 'Prev hash'),
                h('dd', { class: 'mono break' }, e.prevHash),
              ),
              h('span', { class: 'label' }, 'Data'),
              // textContent only: the data may contain full prompt text from web pages.
              h('pre', { class: 'pre' }, JSON.stringify(e.data, null, 2)),
            ),
          ),
        ),
      );
    }
  });
  if (!rows.length) rows.push(h('tr', null, h('td', { class: 'table__empty', colspan: '7' }, entries.length ? 'No entries of this type in the loaded range.' : 'The log is empty.')));
  auditBody.replaceChildren(...rows);
  for (const e of entries) seenSeqs.add(e.seq);
  auditCount.textContent = `${shown.length} shown · ${entries.length} loaded${exhausted ? ' · end of log' : ''}`;
  olderBtn.hidden = exhausted || entries.length === 0;
}

let auditBusy = false;
let auditAgain = false;
async function refreshAudit(reset = false): Promise<void> {
  if (auditBusy) {
    auditAgain = true;
    return;
  }
  auditBusy = true;
  try {
    const roomId = roomFilter.value || undefined;
    const page = await client.call('audit.list', roomId ? { limit: PAGE, roomId } : { limit: PAGE });
    const newest = entries[0]?.seq;
    const oldestOfPage = page[page.length - 1]?.seq;
    const cleared = newest !== undefined && page.some((e) => e.type === 'log.cleared' && e.seq > newest);
    if (reset || newest === undefined || page.length === 0 || (page[0]?.seq ?? 0) < newest || cleared || (oldestOfPage !== undefined && oldestOfPage > newest + 1 && page.length === PAGE)) {
      entries = page;
      exhausted = page.length < PAGE;
    } else {
      entries = [...page.filter((e) => e.seq > newest), ...entries];
    }
    renderAudit();
    initialLoaded = true;
  } catch (e) {
    err.show(e);
  } finally {
    auditBusy = false;
    if (auditAgain) {
      auditAgain = false;
      void refreshAudit();
    }
  }
}

async function loadOlder(): Promise<void> {
  const oldest = entries[entries.length - 1]?.seq;
  if (oldest === undefined) return;
  olderBtn.disabled = true;
  try {
    const roomId = roomFilter.value || undefined;
    const page = await client.call('audit.list', roomId ? { limit: PAGE, beforeSeq: oldest, roomId } : { limit: PAGE, beforeSeq: oldest });
    entries = [...entries, ...page.filter((e) => e.seq < oldest)];
    exhausted = page.length < PAGE;
    renderAudit(true);
  } catch (e) {
    err.show(e);
  } finally {
    olderBtn.disabled = false;
  }
}

let auditTimer: ReturnType<typeof setTimeout> | undefined;
function scheduleAuditRefresh(): void {
  if (auditTimer) return;
  auditTimer = setTimeout(() => {
    auditTimer = undefined;
    void refreshAudit();
  }, 300);
}

function renderRoomFilter(s: UiState): void {
  const current = roomFilter.value;
  const ids = new Set<string>(s.rooms.map((r) => r.roomId));
  for (const e of entries) if (e.roomId) ids.add(e.roomId);
  if (current) ids.add(current);
  const label = (id: string): string => {
    const r = s.rooms.find((x) => x.roomId === id);
    return r ? `${shortId(id)} · ${r.members.map((m) => m.origin).join(' ⇄ ')}` : shortId(id);
  };
  const sig = JSON.stringify([...ids].map(label));
  if (roomFilter.dataset.sig === sig) return;
  roomFilter.dataset.sig = sig;
  roomFilter.replaceChildren(h('option', { value: '' }, 'All rooms'), ...[...ids].map((id) => h('option', { value: id }, label(id))));
  roomFilter.value = current;
}

roomFilter.addEventListener('change', () => {
  expanded.clear();
  void refreshAudit(true);
});
typeFilter.addEventListener('change', () => renderAudit(true));
olderBtn.addEventListener('click', () => void loadOlder());

verifyBtn.addEventListener('click', () => {
  verifyBtn.disabled = true;
  verifyResult.replaceChildren(h('span', { class: 'muted' }, 'Verifying…'));
  client.call('audit.verify').then(
    (r) => {
      verifyBtn.disabled = false;
      verifyResult.dataset.ok = String(r.ok);
      if (r.ok) {
        replaceChildren(verifyResult, stamp('Verified', 'ok', { class: 'stamp--lg stamp--new' }), `Chain intact · ${r.count} entries verified at ${formatTime(Date.now())}`);
      } else {
        replaceChildren(
          verifyResult,
          stamp('BROKEN', 'deny', { class: 'stamp--lg stamp--new' }),
          h('span', null, 'BROKEN at seq ', h('strong', { class: 'mono' }, String(r.brokenAtSeq)), ` · ${r.reason}. The stored log was altered or corrupted after it was written.`),
        );
      }
    },
    (e) => {
      verifyBtn.disabled = false;
      delete verifyResult.dataset.ok;
      verifyResult.replaceChildren();
      err.show(e);
    },
  );
});

async function exportAudit(): Promise<void> {
  const p = await client.call('audit.export');
  const d = new Date();
  const stampStr = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}-${String(d.getHours()).padStart(2, '0')}${String(d.getMinutes()).padStart(2, '0')}`;
  downloadBytes(JSON.stringify(p, null, 2), `tabbridge-audit-${stampStr}.json`, 'application/json');
}
exportBtn.addEventListener('click', () => {
  exportBtn.disabled = true;
  exportAudit().then(
    () => (exportBtn.disabled = false),
    (e) => {
      exportBtn.disabled = false;
      err.show(e);
    },
  );
});

// Clear: explicit confirmation dialog (Cancel is the default focus).
const dlgCancel = h('button', { type: 'button', class: 'btn', autofocus: true, 'data-testid': 'audit-clear-cancel' }, 'Cancel');
const dlgExport = h('button', { type: 'button', class: 'btn btn--ghost' }, 'Export first');
const dlgConfirm = h('button', { type: 'button', class: 'btn btn--danger', 'data-testid': 'audit-clear-confirm' }, 'Clear the log');
const dialog = h(
  'dialog',
  { class: 'dialog', 'aria-labelledby': 'clear-h' },
  h(
    'div',
    { class: 'dialog__body' },
    h('h2', { id: 'clear-h' }, 'Clear the audit log?'),
    h('p', null, 'Every entry is deleted. A new chain starts with a “log cleared” entry that records how many entries were removed. This cannot be undone.'),
    h('div', { class: 'row row--end' }, dlgExport, dlgCancel, dlgConfirm),
  ),
);
clearBtn.addEventListener('click', () => {
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
  dlgCancel.focus();
});
dlgCancel.addEventListener('click', () => dialog.close());
dlgExport.addEventListener('click', () => void exportAudit().catch((e: unknown) => err.show(e)));
dlgConfirm.addEventListener('click', () => {
  dlgConfirm.disabled = true;
  client.call('audit.clear').then(
    (r) => {
      dlgConfirm.disabled = false;
      dialog.close();
      expanded.clear();
      verifyResult.replaceChildren();
      delete verifyResult.dataset.ok;
      auditCount.textContent = `Cleared ${r.cleared} entries.`;
      void refreshAudit(true);
    },
    (e) => {
      dlgConfirm.disabled = false;
      dialog.close();
      err.show(e);
    },
  );
});

// =====================================================================================
// Settings
// =====================================================================================
const retentionId = uid('ret');
const retention = h('input', { type: 'number', id: retentionId, min: String(AUDIT_MIN_MAX_ENTRIES), max: String(AUDIT_MAX_MAX_ENTRIES), step: '100', 'data-testid': 'settings-retention' });
const retentionSave = h('button', { type: 'button', class: 'btn' }, 'Save retention');
const retentionNote = h('span', { class: 'small muted', role: 'status' });
const defaultsHost = h('div', { class: 'stack' });
const defaultsSave = h('button', { type: 'button', class: 'btn btn--primary', 'data-testid': 'settings-save-defaults' }, 'Save default permissions');
const defaultsNote = h('span', { class: 'small muted', role: 'status' });
let editors: { i2j: ReturnType<typeof grantEditor>; j2i: ReturnType<typeof grantEditor>; ttl: HTMLSelectElement } | undefined;

const settingsSection = h(
  'section',
  { class: 'section', id: 'settings', 'aria-labelledby': 'settings-h' },
  h('div', { class: 'section__head' }, h('h2', { id: 'settings-h' }, 'Settings')),
  h(
    'div',
    { class: 'card' },
    h('label', { class: 'label', for: retentionId }, 'Audit retention (entries)'),
    h('div', { class: 'row' }, retention, retentionSave, retentionNote),
    h('p', { class: 'small muted' }, `Between ${AUDIT_MIN_MAX_ENTRIES} and ${AUDIT_MAX_MAX_ENTRIES}. The oldest entries are dropped first. The chain still verifies from its anchor.`),
  ),
  h(
    'div',
    { class: 'card' },
    h('span', { class: 'label' }, 'Default permissions for new pairings'),
    h('p', { class: 'small muted' }, 'Pre-filled in the pairing form. You still review and approve each pairing.'),
    defaultsHost,
    h('div', { class: 'row' }, defaultsSave, defaultsNote),
  ),
);

function renderSettings(s: Settings): void {
  retention.value = String(s.auditMaxEntries);
  const ttlId = uid('ttl');
  const i2j = grantEditor({ testPrefix: 'default-i2j', legend: 'Initiator may send', hint: 'the tab that starts pairing', initial: s.defaultProposal.i2j });
  const j2i = grantEditor({ testPrefix: 'default-j2i', legend: 'Joiner may send', hint: 'the tab that enters the code', initial: s.defaultProposal.j2i });
  const ttl = ttlSelect('default-ttl', s.defaultProposal.ttlMs, ttlId);
  editors = { i2j, j2i, ttl };
  defaultsHost.replaceChildren(i2j.el, j2i.el, h('div', { class: 'field' }, h('label', { class: 'label', for: ttlId }, 'Room expires after'), ttl));
}

retentionSave.addEventListener('click', () => {
  const n = Number(retention.value);
  if (!Number.isInteger(n) || n < AUDIT_MIN_MAX_ENTRIES || n > AUDIT_MAX_MAX_ENTRIES) {
    err.show({ code: 'VALIDATION_FAILED', message: `Retention must be a whole number between ${AUDIT_MIN_MAX_ENTRIES} and ${AUDIT_MAX_MAX_ENTRIES}.` });
    return;
  }
  retentionSave.disabled = true;
  client.call('settings.set', { auditMaxEntries: n }).then(
    (s) => {
      retentionSave.disabled = false;
      retention.value = String(s.auditMaxEntries);
      retentionNote.textContent = 'Saved.';
      err.clear();
    },
    (e) => {
      retentionSave.disabled = false;
      err.show(e);
    },
  );
});

defaultsSave.addEventListener('click', () => {
  if (!editors) return;
  const problem = editors.i2j.validate() ?? editors.j2i.validate();
  if (problem) {
    err.show({ code: 'VALIDATION_FAILED', message: problem });
    return;
  }
  defaultsSave.disabled = true;
  client.call('settings.set', { defaultProposal: { i2j: editors.i2j.get(), j2i: editors.j2i.get(), ttlMs: Number(editors.ttl.value) } }).then(
    () => {
      defaultsSave.disabled = false;
      defaultsNote.textContent = 'Saved.';
      err.clear();
    },
    (e) => {
      defaultsSave.disabled = false;
      err.show(e);
    },
  );
});

// =====================================================================================
// Page
// =====================================================================================
replaceChildren(
  app,
  h('header', { class: 'masthead' }, wordmark('Ledger & controls'), h('span', { class: 'spacer' }), pause.button),
  pause.banner,
  connectionNotice(client),
  h(
    'nav',
    { class: 'nav', 'aria-label': 'Sections' },
    h('a', { href: '#sites' }, 'Sites'),
    h('a', { href: '#rooms' }, 'Rooms'),
    h('a', { href: '#audit' }, 'Audit log'),
    h('a', { href: '#settings' }, 'Settings'),
  ),
  h('main', { class: 'main' }, err.el, sitesSection, roomsSection, auditSection, settingsSection),
  dialog,
);
app.removeAttribute('aria-busy');

function renderAll(s: UiState): void {
  state = s;
  pause.update(s.paused);
  renderSites(s);
  renderRooms(s);
  renderRoomFilter(s);
}

client.onState((s) => {
  renderAll(s);
  scheduleAuditRefresh();
});
client.call('state.get').then(
  (s) => {
    if (!state) renderAll(s);
  },
  (e) => err.show(e),
);
client.call('settings.get').then(renderSettings, (e) => err.show(e));
void refreshAudit(true);

// Not every audit append changes UiState (e.g. content records), so also poll while visible.
setInterval(() => {
  if (document.visibilityState === 'visible') void refreshAudit();
}, 4000);
