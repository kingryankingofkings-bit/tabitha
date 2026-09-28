// Action popup: per-tab checkpoint. Enable the site, see the tab's endpoint, pair, and
// manage this tab's rooms. Target tab = ?tabId=<n> or the active tab of the current window.
import { ext } from '../../platform/ext';
import type { EndpointInfo, RoomAdminView, RoomMember, UiState } from '../../shared/types';
import { UiClient } from '../lib/client';
import { connectionNotice, errorArea, pauseControl, wordmark } from '../lib/common';
import { $, countdownEl, h, originEl, reconcile, replaceChildren, show, startTicker, unverifiedTitle } from '../lib/dom';
import { CLOSE_REASONS, kindLabel } from '../lib/format';
import { grantLines, narrowControl, roomStateStamp } from '../lib/grants';
import { pairingSection } from '../lib/pairing';

interface Target {
  tabId: number | undefined;
  windowId: number | undefined;
  /** http(s) origin from the tab URL; null = unsupported; undefined = URL not visible to us. */
  origin: string | null | undefined;
  title: string | undefined;
}

type SiteStatus = 'enabled' | 'disabled' | 'unsupported';

const client = new UiClient();
startTicker();

function httpOrigin(url: string | undefined): string | null | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null;
  } catch {
    return null;
  }
}

async function resolveTarget(): Promise<Target> {
  const q = new URLSearchParams(location.search).get('tabId');
  let tab: chrome.tabs.Tab | undefined;
  let tabId: number | undefined;
  try {
    if (q !== null && /^\d+$/.test(q)) {
      tabId = Number(q);
      tab = await ext.tabs.get(tabId);
    } else {
      [tab] = await ext.tabs.query({ active: true, currentWindow: true });
      tabId = tab?.id;
    }
  } catch {
    /* tab may be gone or not visible */
  }
  return { tabId, windowId: tab?.windowId, origin: httpOrigin(tab?.url), title: tab?.title };
}

function matchPattern(origin: string): string {
  const u = new URL(origin);
  return `${u.protocol}//${u.hostname}/*`;
}

// --------------------------------------------------------------------------------------

function main(target: Target): void {
  const app = $('#app');
  const err = errorArea();
  const pause = pauseControl(client, err.show);
  let state: UiState | undefined;
  let enabledAt: number | undefined;
  const narrowOpen = new Set<string>();

  // ---- site block ----
  const siteOrigin = h('span', { 'data-testid': 'site-origin' });
  const siteStatus = h('span', { class: 'pill', 'data-testid': 'site-status' });
  const titleSlot = h('div');
  const enableBtn = h('button', { type: 'button', class: 'btn btn--primary', 'data-testid': 'enable-site' });
  const enableNote = h('p', { class: 'small muted', role: 'status' });
  const disabledBlock = h(
    'div',
    { class: 'stack', hidden: true },
    h('p', { class: 'small' }, 'TabBridge is off for this site. Pages on sites you have not enabled cannot see or reach TabBridge.'),
    h('div', null, enableBtn),
    h('p', { class: 'small muted' }, 'Your browser will ask you to allow TabBridge to access this site. Only this site is affected.'),
    enableNote,
  );
  const endpointStatus = h('div', { class: 'row small', 'data-testid': 'endpoint-status', 'data-agent': 'no' });
  const reloadHint = h('p', { class: 'small muted', hidden: true }, 'Reload the tab if it was already open before you enabled TabBridge.');
  const disableBtn = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'data-testid': 'disable-site' }, 'Disable on this site');
  const enabledBlock = h('div', { class: 'stack', hidden: true }, endpointStatus, reloadHint, h('div', { class: 'row' }, disableBtn));
  const unsupportedBlock = h(
    'p',
    { class: 'small muted', hidden: true },
    'TabBridge only works on regular web pages (http:// or https://). Browser pages, files and extension pages cannot be enabled.',
  );
  const pairRequest = h('div', { class: 'banner banner--info', hidden: true, role: 'status' });

  const siteSection = h(
    'section',
    { class: 'section', 'aria-labelledby': 'site-h' },
    h('div', { class: 'section__head' }, h('h2', { id: 'site-h' }, 'This tab')),
    h('div', { class: 'row row--between row--nowrap' }, h('div', { class: 'site-origin' }, siteOrigin), siteStatus),
    titleSlot,
    disabledBlock,
    enabledBlock,
    unsupportedBlock,
    pairRequest,
  );

  // ---- pairing ----
  const pairing = pairingSection({
    client,
    selector: () => {
      const ep = endpointForTab();
      return ep && ep.connected && target.tabId !== undefined ? { tabId: target.tabId } : null;
    },
    isMine: (ref) => ref.kind === 'page' && ref.tabId !== undefined && ref.tabId === target.tabId,
    selfName: 'This tab',
    otherName: 'The other tab',
    onError: err.show,
    clearError: err.clear,
  });

  // ---- rooms ----
  const roomList = h('ul', { class: 'list', 'data-testid': 'room-list' });
  const roomsSection = h(
    'section',
    { class: 'section', 'aria-labelledby': 'rooms-h' },
    h('div', { class: 'section__head' }, h('h2', { id: 'rooms-h' }, 'Rooms for this tab')),
    roomList,
  );

  // ---- footer ----
  const dashBtn = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'data-testid': 'open-dashboard' }, 'Open dashboard');
  const consoleBtn = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'data-testid': 'open-console' }, 'Open Agent Console');
  const popoutBtn = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', title: 'Keep this panel open in its own window' }, 'Pop out');

  replaceChildren(
    app,
    h('header', { class: 'masthead' }, wordmark('Checkpoint'), h('span', { class: 'spacer' }), pause.button),
    pause.banner,
    connectionNotice(client),
    h('main', { class: 'main' }, err.el, siteSection, pairing.el, roomsSection),
    h('footer', { class: 'foot' }, dashBtn, consoleBtn, target.tabId !== undefined && ext.windows ? popoutBtn : null),
  );
  app.removeAttribute('aria-busy');

  // ---- helpers ----
  function endpointForTab(): EndpointInfo | undefined {
    if (!state || target.tabId === undefined) return undefined;
    const eps = state.endpoints.filter((e) => e.kind === 'page' && e.tabId === target.tabId);
    return eps.find((e) => e.connected) ?? eps[0];
  }

  function currentOrigin(): string | null {
    if (target.origin !== undefined) return target.origin;
    // URL not visible (no activeTab grant): fall back to the router-verified endpoint origin.
    return endpointForTab()?.origin ?? null;
  }

  function siteStatusOf(origin: string | null): SiteStatus {
    if (!origin) return 'unsupported';
    return state?.sites.includes(origin) ? 'enabled' : 'disabled';
  }

  function myMember(room: RoomAdminView): RoomMember | undefined {
    return room.members.find((m) => m.kind === 'page' && m.tabId === target.tabId);
  }

  // ---- render ----
  function render(): void {
    const origin = currentOrigin();
    if (!state && origin) {
      // Until the router's first state push we cannot tell enabled from disabled.
      replaceChildren(siteOrigin, originEl(origin, {}, true));
      siteStatus.textContent = '…';
      for (const b of [unsupportedBlock, disabledBlock, enabledBlock, pairing.el, roomsSection]) show(b, false);
      return;
    }
    const status = siteStatusOf(origin);
    if (origin) {
      if (siteOrigin.textContent !== origin) replaceChildren(siteOrigin, originEl(origin, {}, true));
    } else {
      siteOrigin.textContent = 'unsupported page';
    }
    siteStatus.textContent = status;
    siteStatus.className = `pill ${status === 'enabled' ? 'pill--ok' : status === 'unsupported' ? '' : 'pill--warn'}`;
    const ep = endpointForTab();
    replaceChildren(titleSlot, unverifiedTitle(ep?.title ?? target.title));

    show(unsupportedBlock, status === 'unsupported');
    show(disabledBlock, status === 'disabled');
    show(enabledBlock, status === 'enabled');
    show(pairing.el, status === 'enabled');
    show(roomsSection, status === 'enabled');

    if (status === 'disabled' && origin) {
      enableBtn.textContent = `Enable TabBridge on ${origin}`;
      if (state?.pendingSites.includes(origin) && !enableNote.textContent) {
        enableNote.textContent = 'Waiting for the browser permission. Click the button again if the prompt was dismissed.';
      }
    }

    // endpoint status
    const agent = ep?.connected && ep.agent.attached;
    endpointStatus.dataset.agent = agent ? 'yes' : 'no';
    if (ep?.connected) {
      replaceChildren(
        endpointStatus,
        h('span', { class: 'pill pill--ok' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), 'connected'),
        agent
          ? h('span', null, 'Agent attached: ', h('strong', { class: 'mono' }, ep.agent.name ?? 'unnamed'))
          : h('span', { class: 'muted' }, 'No agent attached on this page yet.'),
      );
    } else {
      const waiting = enabledAt !== undefined && Date.now() - enabledAt < 3000;
      replaceChildren(
        endpointStatus,
        h('span', { class: 'pill' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), ep ? 'offline' : waiting ? 'starting' : 'no endpoint'),
        h('span', { class: 'muted' }, waiting ? 'Connecting to the page…' : ep ? 'The page endpoint is offline.' : 'TabBridge is not running in this tab yet.'),
      );
    }
    show(reloadHint, status === 'enabled' && !ep?.connected && !(enabledAt !== undefined && Date.now() - enabledAt < 3000));

    // page-initiated pairing request (badge "!")
    const req = state?.pairRequests.find((r) => r.tabId === target.tabId);
    show(pairRequest, !!req && status === 'enabled');
    if (req) {
      replaceChildren(
        pairRequest,
        h(
          'div',
          { class: 'stack stack--sm' },
          h('strong', null, 'This page asked to pair.'),
          req.note ? h('span', null, h('span', { class: 'unverified__label' }, 'note from the page (unverified)'), `“${req.note}”`) : null,
          h('span', null, 'Nothing happens unless you start pairing below and approve it in the other tab.'),
        ),
      );
    }

    pause.update(!!state?.paused);
    pairing.update(state);
    renderRooms();
  }

  function renderRooms(): void {
    const rooms = (state?.rooms ?? [])
      .filter((r) => myMember(r))
      .sort((a, b) => Number(a.state === 'closed') - Number(b.state === 'closed') || b.createdAt - a.createdAt);
    const eps = new Map((state?.endpoints ?? []).map((e) => [e.endpointId, e]));
    reconcile(
      roomList,
      rooms,
      (r) => r.roomId,
      (r) => {
        const peer = r.members.find((m) => m !== myMember(r));
        const pe = peer ? eps.get(peer.endpointId) : undefined;
        return JSON.stringify([r.state, r.grant, r.closedReason, r.members, pe?.connected, pe?.agent, narrowOpen.has(r.roomId)]);
      },
      (r) => roomItem(r, eps),
      () => h('li', { class: 'small muted' }, 'No rooms yet. Start pairing, or join with a code from another tab.'),
    );
    for (const r of rooms) {
      const c = roomList.querySelector<HTMLElement>(`[data-room-counters="${r.roomId}"]`);
      if (c) c.textContent = `${r.frames.routed} routed · ${r.frames.rejected} rejected`;
    }
  }

  function roomItem(r: RoomAdminView, eps: Map<string, EndpointInfo>): HTMLElement {
    const me = myMember(r) as RoomMember;
    const peer = r.members.find((m) => m !== me) as RoomMember;
    const pe = eps.get(peer.endpointId);
    const out = me.role === 'initiator' ? r.grant.i2j : r.grant.j2i;
    const inb = me.role === 'initiator' ? r.grant.j2i : r.grant.i2j;
    const otherName = peer.kind === 'panel' ? 'The Agent Console' : 'The other tab';
    const closed = r.state === 'closed';
    const closeBtn = h('button', { type: 'button', class: 'btn btn--deny-ghost btn--sm', 'data-testid': 'room-close' }, 'Close room');
    closeBtn.addEventListener('click', () => {
      closeBtn.disabled = true;
      client.call('room.close', { roomId: r.roomId }).then(err.clear, (e) => {
        closeBtn.disabled = false;
        err.show(e);
      });
    });
    const labels = me.role === 'initiator' ? { i2j: 'This tab may send', j2i: `${otherName} may send` } : { i2j: `${otherName} may send`, j2i: 'This tab may send' };
    return h(
      'li',
      { class: `card${closed ? ' card--closed' : ''}`, 'data-testid': 'room-item', 'data-room-id': r.roomId, 'data-state': r.state },
      h(
        'div',
        { class: 'card__head' },
        roomStateStamp(r.state),
        h('span', { class: 'spacer' }),
        closed
          ? h('span', { class: 'small muted' }, CLOSE_REASONS[r.closedReason ?? 'user'] ?? r.closedReason)
          : h('span', { class: 'small mono' }, 'expires in ', countdownEl(r.grant.expiresAt)),
      ),
      h(
        'div',
        { class: 'stack stack--sm' },
        h('span', { class: 'label' }, `Paired with ${kindLabel(peer.kind, peer.tabId)}`),
        originEl(peer.origin, { 'data-testid': 'room-peer-origin' }),
        h(
          'span',
          { class: 'small muted' },
          pe?.connected ? 'connected' : 'offline',
          ' · ',
          pe?.agent.attached ? `agent: ${pe.agent.name ?? 'unnamed'}` : 'no agent',
          ' · ',
          h('span', { class: 'mono', 'data-room-counters': r.roomId }, `${r.frames.routed} routed · ${r.frames.rejected} rejected`),
        ),
      ),
      grantLines([
        { who: 'This tab', grant: out },
        { who: otherName, grant: inb },
      ]),
      closed
        ? null
        : h(
            'div',
            { class: 'card__foot' },
            closeBtn,
            narrowControl(
              r,
              labels,
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

  // ---- actions ----
  enableBtn.addEventListener('click', () => {
    const origin = currentOrigin();
    if (!origin) return;
    err.clear();
    // Order matters (SPEC §1.1): fire the first enable without awaiting, then request the
    // permission synchronously inside the user gesture, then enable again.
    client.call('site.enable', { origin }).catch(() => undefined);
    let pattern: string;
    try {
      pattern = matchPattern(origin);
    } catch (e) {
      err.show(e);
      return;
    }
    enableNote.textContent = 'Your browser is asking for permission to access this site…';
    ext.permissions
      .request({ origins: [pattern] })
      .then(async (granted) => {
        if (!granted) {
          enableNote.textContent = 'Permission was not granted, so TabBridge stays off for this site.';
          return;
        }
        const r = await client.call('site.enable', { origin });
        if (r.status === 'enabled') {
          enableNote.textContent = '';
          enabledAt = Date.now();
          setTimeout(render, 3100);
        } else {
          enableNote.textContent = 'Waiting for the browser to confirm the permission…';
        }
        render();
      })
      .catch((e: unknown) => {
        enableNote.textContent = '';
        err.show(e);
      });
  });

  disableBtn.addEventListener('click', () => {
    const origin = currentOrigin();
    if (!origin) return;
    disableBtn.disabled = true;
    client.call('site.disable', { origin }).then(
      () => {
        disableBtn.disabled = false;
        enabledAt = undefined;
        err.clear();
      },
      (e) => {
        disableBtn.disabled = false;
        err.show(e);
      },
    );
  });

  dashBtn.addEventListener('click', () => {
    ext.runtime.openOptionsPage().catch((e: unknown) => err.show(e));
  });

  consoleBtn.addEventListener('click', () => {
    // Must run synchronously inside the click (user gesture) on both browsers.
    try {
      const sidePanel = (ext as unknown as { sidePanel?: { open(o: { windowId: number }): Promise<void> } }).sidePanel;
      const ffSidebar = (globalThis as unknown as { browser?: { sidebarAction?: { open(): Promise<void> } } }).browser?.sidebarAction;
      if (sidePanel?.open && target.windowId !== undefined) {
        sidePanel.open({ windowId: target.windowId }).catch((e: unknown) => err.show(e));
      } else if (ffSidebar?.open) {
        ffSidebar.open().catch((e: unknown) => err.show(e));
      } else {
        err.show({ code: 'INTERNAL', message: 'This browser cannot open the Agent Console from here. Use the browser side panel menu.' });
      }
    } catch (e) {
      err.show(e);
    }
  });

  popoutBtn.addEventListener('click', () => {
    if (target.tabId === undefined) return;
    ext.windows
      .create({ url: ext.runtime.getURL(`ui/popup.html?tabId=${target.tabId}`), type: 'popup', width: 420, height: 720 })
      .then(() => window.close(), (e: unknown) => err.show(e));
  });

  client.onState((s) => {
    state = s;
    render();
  });
  client.call('settings.get').then(
    (s) => pairing.setDefaults(s.defaultProposal),
    () => undefined,
  );
  client.call('state.get').then(
    (s) => {
      if (!state) {
        state = s;
        render();
      }
    },
    (e) => err.show(e),
  );
  render();
}

resolveTarget().then(main, () => main({ tabId: undefined, windowId: undefined, origin: null, title: undefined }));
