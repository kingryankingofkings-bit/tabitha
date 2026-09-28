// Safe DOM construction for extension UI. Never uses innerHTML & co. All text goes through
// textContent / createTextNode.

export type Child = Node | string | number | null | undefined | false | Child[];
export type Attrs = Record<string, unknown>;

const FORBIDDEN_KEYS = new Set(['innerHTML', 'outerHTML', 'srcdoc', 'insertAdjacentHTML', 'innerText']);
/** Assigned as DOM properties (after children, so <select value> works). */
const PROP_KEYS = new Set(['value', 'checked', 'selected', 'disabled', 'indeterminate', 'multiple', 'open']);

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs?: Attrs | null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  const deferred: [string, unknown][] = [];
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (FORBIDDEN_KEYS.has(k)) throw new Error(`h(): forbidden attribute ${k}`);
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith('on')) {
        if (typeof v !== 'function') throw new Error('h(): event handlers must be functions');
        el.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
        continue;
      }
      if (PROP_KEYS.has(k)) {
        deferred.push([k, v]);
        continue;
      }
      if (k === 'class') {
        el.className = String(v);
        continue;
      }
      if ((k === 'href' || k === 'src' || k === 'action') && /^\s*(javascript|data|vbscript):/i.test(String(v))) {
        throw new Error('h(): unsafe URL');
      }
      el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  append(el, children);
  for (const [k, v] of deferred) (el as unknown as Record<string, unknown>)[k] = v;
  return el;
}

export function append(parent: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(parent, c);
    else if (c instanceof Node) parent.appendChild(c);
    else parent.appendChild(document.createTextNode(String(c)));
  }
}

export function clear(el: Node): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function replaceChildren(el: Element, ...children: Child[]): void {
  clear(el);
  append(el, children);
}

export function show(el: HTMLElement, visible: boolean): void {
  el.hidden = !visible;
}

export function $(sel: string, root: ParentNode = document): HTMLElement {
  const el = root.querySelector(sel);
  if (!(el instanceof HTMLElement)) throw new Error(`missing element ${sel}`);
  return el;
}

/**
 * Keyed list reconciliation: reuses an item's element while its signature is unchanged, so
 * form controls inside untouched items keep focus/state across state pushes.
 */
const listCache = new WeakMap<Element, Map<string, { sig: string; el: HTMLElement }>>();
export function reconcile<T>(
  container: HTMLElement,
  items: readonly T[],
  key: (t: T) => string,
  sig: (t: T) => string,
  render: (t: T) => HTMLElement,
  empty?: () => HTMLElement,
): void {
  let cache = listCache.get(container);
  if (!cache) {
    cache = new Map();
    listCache.set(container, cache);
    clear(container);
  }
  const next = new Map<string, { sig: string; el: HTMLElement }>();
  const els: HTMLElement[] = [];
  for (const it of items) {
    const k = key(it);
    const s = sig(it);
    const prev = cache.get(k);
    const el = prev && prev.sig === s ? prev.el : render(it);
    next.set(k, { sig: s, el });
    els.push(el);
  }
  listCache.set(container, next);
  if (els.length === 0 && empty) {
    replaceChildren(container, empty());
    return;
  }
  // Minimal DOM moves: only touch nodes that are out of place.
  let cursor: ChildNode | null = container.firstChild;
  for (const el of els) {
    if (cursor === el) {
      cursor = cursor.nextSibling;
      continue;
    }
    container.insertBefore(el, cursor);
  }
  while (cursor) {
    const nextSib: ChildNode | null = cursor.nextSibling;
    container.removeChild(cursor);
    cursor = nextSib;
  }
}

/** Render a full origin with the host emphasized. textContent === origin exactly. */
export function originEl(origin: string, attrs: Attrs = {}, large = false): HTMLSpanElement {
  const cls = `origin${large ? ' origin--lg' : ''}${attrs.class ? ` ${String(attrs.class)}` : ''}`;
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/:]+|\[[^\]]+\])(:\d+)?$/i.exec(origin);
  if (!m) return h('span', { ...attrs, class: cls, title: origin }, origin);
  const scheme = m[1] ?? '';
  const insecure = scheme.toLowerCase() === 'http://';
  return h(
    'span',
    { ...attrs, class: cls, title: insecure ? `${origin} (not HTTPS)` : origin },
    h('span', { class: `origin__scheme${insecure ? ' origin__scheme--insecure' : ''}` }, scheme),
    h('span', { class: 'origin__host' }, m[2] ?? ''),
    m[3] ? h('span', { class: 'origin__port' }, m[3]) : null,
  );
}

/** Secondary, spoofable page title. Always labelled as unverified. */
export function unverifiedTitle(title: string | undefined): HTMLElement | null {
  if (!title) return null;
  const t = title.length > 120 ? `${title.slice(0, 120)}…` : title;
  return h('span', { class: 'unverified', title: `page title (unverified): ${t}` }, h('span', { class: 'unverified__label' }, 'page title (unverified)'), t);
}

export type StampTone = 'ok' | 'deny' | 'info' | 'warn' | 'ink' | 'muted';
export function stamp(label: string, tone: StampTone, extra: Attrs = {}): HTMLSpanElement {
  return h('span', { ...extra, class: `stamp stamp--${tone}${extra.class ? ` ${String(extra.class)}` : ''}` }, label);
}

/** Element whose text is kept up to date by the global countdown ticker. */
export function countdownEl(to: number, attrs: Attrs = {}, prefix = ''): HTMLSpanElement {
  const el = h('span', { ...attrs, 'data-countdown-to': String(to), 'data-countdown-prefix': prefix });
  updateCountdown(el, Date.now());
  return el;
}

export function formatCountdown(ms: number): string {
  if (ms <= 0) return '0:00';
  const s = Math.ceil(ms / 1000);
  const hh = Math.floor(s / 3600);
  const mm = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  const p2 = (n: number): string => String(n).padStart(2, '0');
  return hh > 0 ? `${hh}:${p2(mm)}:${p2(ss)}` : `${mm}:${p2(ss)}`;
}

function updateCountdown(el: HTMLElement, now: number): void {
  const to = Number(el.dataset.countdownTo);
  if (!Number.isFinite(to)) return;
  const left = to - now;
  const prefix = el.dataset.countdownPrefix ?? '';
  el.textContent = left > 0 ? `${prefix}${formatCountdown(left)}` : 'expired';
  el.classList.toggle('countdown--expired', left <= 0);
  el.classList.toggle('code-display__expiry--urgent', left > 0 && left < 20_000 && el.classList.contains('code-display__expiry'));
}

let tickerStarted = false;
const tickListeners = new Set<(now: number) => void>();
/** Starts a 1 s ticker that refreshes every [data-countdown-to] element in the document. */
export function startTicker(): void {
  if (tickerStarted) return;
  tickerStarted = true;
  setInterval(() => {
    const now = Date.now();
    document.querySelectorAll<HTMLElement>('[data-countdown-to]').forEach((el) => updateCountdown(el, now));
    tickListeners.forEach((cb) => cb(now));
  }, 1000);
}
export function onTick(cb: (now: number) => void): () => void {
  tickListeners.add(cb);
  return () => tickListeners.delete(cb);
}

/** Trigger a download of in-memory bytes. The object URL exists only for this click. */
export function downloadBytes(bytes: Uint8Array | string, filename: string, mime = 'application/octet-stream'): void {
  const part: BlobPart = typeof bytes === 'string' ? bytes : (bytes as Uint8Array<ArrayBuffer>);
  const url = URL.createObjectURL(new Blob([part], { type: mime }));
  const a = h('a', { href: url, download: filename, rel: 'noopener', hidden: true });
  document.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

let idCounter = 0;
export function uid(prefix = 'tb'): string {
  idCounter += 1;
  return `${prefix}-${idCounter}`;
}
