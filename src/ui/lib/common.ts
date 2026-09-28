// Page chrome shared by popup, dashboard and Agent Console.
import type { UiClient } from './client';
import { h, replaceChildren } from './dom';
import { describeError } from './format';

export interface ErrorArea {
  el: HTMLElement;
  show(e: unknown): void;
  clear(): void;
}

/** role=alert region; empty (and hidden via CSS) when there is no error. */
export function errorArea(testid = 'error'): ErrorArea {
  const el = h('div', { class: 'error-area', role: 'alert', 'aria-live': 'assertive', 'data-testid': testid });
  return {
    el,
    show(e: unknown): void {
      const { code, message } = describeError(e);
      replaceChildren(el, h('span', { class: 'error-area__code' }, code), message);
    },
    clear(): void {
      el.replaceChildren();
    },
  };
}

export function wordmark(sub: string): HTMLElement {
  return h(
    'div',
    { class: 'wordmark' },
    h('span', { class: 'wordmark__seal', 'aria-hidden': 'true' }, 'TB'),
    h('span', null, 'TabBridge'),
    h('span', { class: 'wordmark__sub' }, sub),
  );
}

export interface PauseControl {
  button: HTMLButtonElement;
  banner: HTMLElement;
  update(paused: boolean): void;
}

/** Global kill switch: a toggle button (aria-pressed) plus the "All transfers paused" banner. */
export function pauseControl(client: UiClient, onError: (e: unknown) => void): PauseControl {
  let paused = false;
  const button = h('button', { type: 'button', class: 'btn btn--sm btn--toggle', 'aria-pressed': 'false', 'data-testid': 'pause-toggle' }, 'Pause all');
  const banner = h(
    'div',
    { class: 'banner banner--warn banner--pause', role: 'status', hidden: true, 'data-testid': 'pause-banner' },
    'All transfers paused. No messages, files or pairings can go through.',
  );
  const update = (p: boolean): void => {
    paused = p;
    button.setAttribute('aria-pressed', String(p));
    button.textContent = p ? 'Paused · Resume' : 'Pause all';
    button.title = p ? 'Resume all transfers' : 'Stop all transfers and pairing immediately';
    banner.hidden = !p;
  };
  button.addEventListener('click', () => {
    const want = !paused;
    button.disabled = true;
    client.call('pause.set', { paused: want }).then(
      (r) => {
        button.disabled = false;
        update(r.paused);
      },
      (e) => {
        button.disabled = false;
        onError(e);
      },
    );
  });
  return { button, banner, update };
}

/** Shows a thin connection notice when the background port is down. */
export function connectionNotice(client: UiClient): HTMLElement {
  const el = h('div', { class: 'banner banner--info', role: 'status', hidden: true }, 'Reconnecting to the TabBridge background…');
  client.onConnection((c) => {
    el.hidden = c;
  });
  return el;
}
