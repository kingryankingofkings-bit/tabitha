// Pairing UI shared by the popup (per tab) and the Agent Console (per panel endpoint).
// Start: choose per-direction grants + expiry, get a 6-digit code shown only here.
// Join: type a code, review BOTH origins and BOTH directions, then Approve or Reject.
import { CODE_RE } from '../../shared/limits';
import { TabBridgeError } from '../../shared/errors';
import type { EndpointSelector, GrantProposal, PairingEndpointRef, PairingPreview, UiState } from '../../shared/types';
import type { UiClient } from './client';
import { countdownEl, h, originEl, replaceChildren, show, uid } from './dom';
import { formatTtl, kindLabel } from './format';
import { grantEditor, grantLines, ttlSelect } from './grants';

export interface PairingSectionOptions {
  client: UiClient;
  /** Selector for "me", or null while my endpoint is not connected. */
  selector(): EndpointSelector | null;
  /** Whether a pairing record was started by me (so the code can be re-shown after reopening). */
  isMine(ref: PairingEndpointRef): boolean;
  /** "This tab" / "This console". */
  selfName: string;
  /** "The other tab". */
  otherName: string;
  onError(e: unknown): void;
  clearError(): void;
  /** Called after a successful approve. */
  onApproved?(roomId: string): void;
}

export interface PairingSection {
  el: HTMLElement;
  update(state: UiState | undefined): void;
  setDefaults(p: GrantProposal): void;
}

const FALLBACK_PROPOSAL: GrantProposal = {
  i2j: { prompts: true, tasks: true, files: false, fileTypes: [], maxFileBytes: 2 * 1024 * 1024 },
  j2i: { prompts: true, tasks: true, files: false, fileTypes: [], maxFileBytes: 2 * 1024 * 1024 },
  ttlMs: 3_600_000,
};

export function pairingSection(o: PairingSectionOptions): PairingSection {
  let lastState: UiState | undefined;
  let active: { code: string; expiresAt: number; seen: boolean } | null = null;
  let dirty = false;

  // ---------------- Start ----------------
  const startBtn = h('button', { type: 'button', class: 'btn btn--primary', 'data-testid': 'start-pairing' }, 'Start pairing…');
  const i2j = grantEditor({ testPrefix: 'grant-i2j', legend: `${o.selfName} may send`, hint: 'to the tab that joins with the code', initial: FALLBACK_PROPOSAL.i2j });
  const j2i = grantEditor({ testPrefix: 'grant-j2i', legend: `${o.otherName} may send`, hint: `to ${o.selfName.toLowerCase()}`, initial: FALLBACK_PROPOSAL.j2i });
  const ttlId = uid('ttl');
  const ttl = ttlSelect('grant-ttl', FALLBACK_PROPOSAL.ttlMs, ttlId);
  const submit = h('button', { type: 'submit', class: 'btn btn--primary', 'data-testid': 'pair-submit' }, 'Issue pairing code');
  const backBtn = h('button', { type: 'button', class: 'btn btn--ghost' }, 'Back');
  const startForm = h(
    'form',
    { class: 'stack', hidden: true, novalidate: true, 'aria-label': 'Pairing permissions' },
    h('p', { class: 'small muted' }, 'Choose what each side may send. Permissions apply per direction and can only be narrowed later.'),
    i2j.el,
    j2i.el,
    h('div', { class: 'field' }, h('label', { class: 'label', for: ttlId }, 'Room expires after'), ttl),
    h('div', { class: 'row' }, submit, backBtn),
  );
  for (const input of startForm.querySelectorAll('input,select')) input.addEventListener('change', () => (dirty = true));

  const digits = h('div', { class: 'code-display__digits', 'data-testid': 'pair-code', 'aria-live': 'polite' });
  const expiry = h('div', { class: 'code-display__expiry' });
  const cancelBtn = h('button', { type: 'button', class: 'btn btn--deny-ghost btn--sm', 'data-testid': 'pair-cancel' }, 'Cancel code');
  const codePanel = h(
    'div',
    { class: 'stack', hidden: true },
    h('span', { class: 'label' }, 'Pairing code'),
    h('div', { class: 'code-display', role: 'group', 'aria-label': 'Pairing code' }, digits, expiry),
    h('p', { class: 'small' }, `Open TabBridge on the other tab and choose “Join with code”. Type this code only into TabBridge's own popup or console, never into a web page.`),
    h('div', { class: 'row' }, cancelBtn),
  );
  const startNote = h('p', { class: 'small muted', role: 'status' });

  startBtn.addEventListener('click', () => {
    dirty = true; // the user is editing: late-arriving defaults must not overwrite choices
    show(startForm, true);
    show(startBtn, false);
    startNote.textContent = '';
    (i2j.el.querySelector('input') as HTMLInputElement | null)?.focus();
  });
  backBtn.addEventListener('click', () => {
    show(startForm, false);
    show(startBtn, true);
    startBtn.focus();
  });
  startForm.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const sel = o.selector();
    if (!sel) return;
    const problem = i2j.validate() ?? j2i.validate();
    if (problem) {
      o.onError(new TabBridgeError('VALIDATION_FAILED', problem));
      return;
    }
    o.clearError();
    const proposal: GrantProposal = { i2j: i2j.get(), j2i: j2i.get(), ttlMs: Number(ttl.value) };
    submit.disabled = true;
    o.client.call('pair.start', { endpoint: sel, proposal }).then(
      (r) => {
        submit.disabled = false;
        active = { code: r.code, expiresAt: r.expiresAt, seen: false };
        show(startForm, false);
        renderCode();
      },
      (e) => {
        submit.disabled = false;
        o.onError(e);
      },
    );
  });
  cancelBtn.addEventListener('click', () => {
    const cur = active;
    if (!cur) return;
    o.client.call('pair.cancel', { code: cur.code }).then(
      () => {
        active = null;
        startNote.textContent = 'Code cancelled.';
        renderCode();
      },
      (e) => o.onError(e),
    );
  });

  function renderCode(): void {
    if (active && active.expiresAt <= Date.now()) {
      active = null;
      startNote.textContent = 'The code expired. Start again to get a new one.';
    }
    if (active) {
      const c = active.code;
      if (digits.dataset.code !== c) {
        digits.dataset.code = c;
        replaceChildren(digits, h('span', { class: 'code-display__group' }, c.slice(0, 3)), h('span', { class: 'code-display__group' }, c.slice(3)));
        replaceChildren(expiry, 'expires in ', countdownEl(active.expiresAt, { class: 'code-display__expiry' }));
      }
      show(codePanel, true);
      show(startBtn, false);
      show(startForm, false);
    } else {
      delete digits.dataset.code;
      digits.replaceChildren();
      show(codePanel, false);
      if (startForm.hidden) show(startBtn, true);
    }
  }

  // ---------------- Join ----------------
  const codeInputId = uid('join');
  const codeInput = h('input', {
    type: 'text',
    id: codeInputId,
    class: 'input--code',
    inputmode: 'numeric',
    autocomplete: 'off',
    spellcheck: 'false',
    maxlength: '7',
    placeholder: '000000',
    'aria-describedby': `${codeInputId}-hint`,
    'data-testid': 'join-code-input',
  });
  const lookupBtn = h('button', { type: 'submit', class: 'btn', 'data-testid': 'join-lookup' }, 'Review');
  const joinForm = h(
    'form',
    { class: 'stack stack--sm', novalidate: true },
    h('label', { class: 'label', for: codeInputId }, 'Join with code'),
    h('div', { class: 'row row--nowrap' }, codeInput, lookupBtn),
    h('p', { class: 'small muted', id: `${codeInputId}-hint` }, 'Enter the 6-digit code shown in the other tab’s TabBridge popup. You will review both sides before anything opens.'),
  );
  const preview = h('div', { hidden: true });
  const joinNote = h('p', { class: 'small', role: 'status' });
  let previewCode: string | null = null;

  joinForm.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const sel = o.selector();
    if (!sel) return;
    const code = codeInput.value.replace(/\s+/g, '');
    if (!CODE_RE.test(code)) {
      o.onError(new TabBridgeError('VALIDATION_FAILED', 'A pairing code is exactly 6 digits.'));
      return;
    }
    o.clearError();
    joinNote.textContent = '';
    lookupBtn.disabled = true;
    o.client.call('pair.lookup', { code, endpoint: sel }).then(
      (p) => {
        lookupBtn.disabled = false;
        renderPreview(p);
      },
      (e) => {
        lookupBtn.disabled = false;
        hidePreview();
        o.onError(e);
      },
    );
  });

  function hidePreview(): void {
    previewCode = null;
    preview.replaceChildren();
    show(preview, false);
  }

  function renderPreview(p: PairingPreview): void {
    previewCode = p.code;
    const heading = h('h3', { tabindex: '-1' }, 'Review before approving');
    const reject = h('button', { type: 'button', class: 'btn btn--deny-ghost', 'data-testid': 'join-reject' }, 'Reject');
    const approve = h('button', { type: 'button', class: 'btn btn--approve', 'data-testid': 'join-approve' }, 'Approve & open room');
    const initiator = originEl(p.initiator.origin, { 'data-testid': 'preview-initiator-origin' }, true);
    const joiner = originEl(p.joiner.origin, { 'data-testid': 'preview-joiner-origin' }, true);
    const warnings: HTMLElement[] = [];
    if (p.initiator.origin === p.joiner.origin) {
      warnings.push(h('div', { class: 'banner banner--warn' }, 'Both sides are on the same origin. Make sure the code came from the tab you expect.'));
    }
    if (p.initiator.origin.startsWith('http:') || p.joiner.origin.startsWith('http:')) {
      warnings.push(h('div', { class: 'banner banner--warn' }, 'One side is served over plain HTTP. Its page content could be altered on the network.'));
    }
    const panel = h(
      'div',
      { class: 'consent', 'data-testid': 'join-preview', role: 'region', 'aria-label': 'Pairing review' },
      heading,
      h('p', { class: 'small muted' }, 'Approving opens a room between these two parties. Messages are end-to-end encrypted between them, and every exchange is written to the audit log.'),
      h(
        'div',
        { class: 'consent__parties' },
        h('div', { class: 'passport' }, h('span', { class: 'label' }, `Other side, started pairing (${kindLabel(p.initiator.kind)})`), initiator),
        h('div', { class: 'passport' }, h('span', { class: 'label' }, `${o.selfName} (you)`), joiner),
      ),
      h(
        'div',
        { class: 'consent__grants' },
        h('div', { class: 'consent__grant' }, grantLines([{ who: originEl(p.initiator.origin), to: 'you', grant: p.proposal.i2j }])),
        h('div', { class: 'consent__grant' }, grantLines([{ who: ['You (', originEl(p.joiner.origin), ')'], to: originEl(p.initiator.origin), grant: p.proposal.j2i }])),
      ),
      h(
        'dl',
        { class: 'kv' },
        h('dt', null, 'Room lasts'),
        h('dd', null, `${formatTtl(p.proposal.ttlMs)} after approval`),
        h('dt', null, 'Code valid'),
        h('dd', { class: 'mono' }, countdownEl(p.expiresAt)),
      ),
      warnings,
      h('div', { class: 'consent__actions' }, reject, approve),
    );
    reject.addEventListener('click', () => {
      const code = previewCode;
      if (!code) return;
      reject.disabled = true;
      approve.disabled = true;
      o.client.call('pair.cancel', { code }).then(
        () => {
          hidePreview();
          codeInput.value = '';
          joinNote.textContent = 'Rejected. The code was cancelled and nothing was opened.';
        },
        (e) => {
          hidePreview();
          o.onError(e);
        },
      );
    });
    approve.addEventListener('click', () => {
      const code = previewCode;
      const sel = o.selector();
      if (!code || !sel) return;
      reject.disabled = true;
      approve.disabled = true;
      o.clearError();
      o.client.call('pair.approve', { code, endpoint: sel }).then(
        (r) => {
          hidePreview();
          codeInput.value = '';
          joinNote.textContent = 'Approved. The two sides are exchanging keys…';
          o.onApproved?.(r.roomId);
        },
        (e) => {
          reject.disabled = false;
          approve.disabled = false;
          o.onError(e);
        },
      );
    });
    preview.replaceChildren(panel);
    show(preview, true);
    // Never default-focus Approve: move focus to the review heading instead.
    heading.focus();
  }

  const lockBanner = h('div', { class: 'banner banner--warn', hidden: true, role: 'status' });

  const el = h(
    'section',
    { class: 'section', 'aria-labelledby': 'pairing-h' },
    h('div', { class: 'section__head' }, h('h2', { id: 'pairing-h' }, 'Pairing')),
    lockBanner,
    h('div', { class: 'stack' }, startBtn, startForm, codePanel, startNote),
    h('div', { class: 'stack join-block' }, joinForm, preview, joinNote),
  );

  function update(state: UiState | undefined): void {
    if (state) lastState = state;
    const s = lastState;
    const ready = o.selector() !== null;
    submit.disabled = !ready;
    lookupBtn.disabled = !ready;
    const why = ready ? '' : 'Waiting for this endpoint to connect to TabBridge…';
    submit.title = why;
    lookupBtn.title = why;
    if (s) {
      const mine = s.pairings.find((p) => o.isMine(p.initiator));
      if (mine) {
        if (!active || active.code !== mine.code) active = { code: mine.code, expiresAt: mine.expiresAt, seen: true };
        else active.seen = true;
      } else if (active && active.seen) {
        active = null;
        startNote.textContent = 'The code is no longer active (used, cancelled or expired).';
      }
      const locked = s.lockedUntil > Date.now();
      show(lockBanner, locked);
      if (locked) replaceChildren(lockBanner, 'Pairing is locked after too many wrong codes. Try again in ', countdownEl(s.lockedUntil, { class: 'mono' }), '.');
    }
    renderCode();
  }

  setInterval(() => {
    if (active && active.expiresAt <= Date.now()) renderCode();
  }, 1000);

  return {
    el,
    update,
    setDefaults(p: GrantProposal): void {
      if (dirty) return;
      i2j.set(p.i2j);
      j2i.set(p.j2i);
      ttl.value = String(p.ttlMs);
      if (!ttl.value) ttl.value = String(FALLBACK_PROPOSAL.ttlMs);
    },
  };
}
