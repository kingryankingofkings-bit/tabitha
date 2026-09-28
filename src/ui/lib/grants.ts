// Grant editor (for proposals), grant summaries and the narrowing control.
import { ALLOWED_MIMES, ROOM_TTL_OPTIONS_MS } from '../../shared/limits';
import type { AllowedMime, Direction, DirectionGrant, GrantNarrowing, RoomAdminView } from '../../shared/types';
import { h, uid, type Child } from './dom';
import { FILE_SIZE_OPTIONS, MIME_LABELS, formatBytes, formatTtl, grantSummary } from './format';

export interface GrantEditor {
  el: HTMLFieldSetElement;
  get(): DirectionGrant;
  set(g: DirectionGrant): void;
  /** Returns an error message if the current selection is incomplete. */
  validate(): string | null;
}

/**
 * Checkboxes for one direction. Test ids: `${prefix}-prompts|tasks|files`,
 * `${prefix}-type-<mime>`, `${prefix}-maxbytes`.
 */
export function grantEditor(opts: { testPrefix: string; legend: string; hint?: string; initial: DirectionGrant }): GrantEditor {
  const { testPrefix } = opts;
  const box = (key: string, label: string, hint?: string): HTMLInputElement => {
    const id = uid(testPrefix);
    const input = h('input', { type: 'checkbox', id, 'data-testid': `${testPrefix}-${key}` });
    rows.push(h('label', { class: 'check', for: id }, input, h('span', null, label, hint ? h('span', { class: 'muted small' }, ` ${hint}`) : null)));
    return input;
  };
  const rows: HTMLElement[] = [];
  const prompts = box('prompts', 'Prompts & replies');
  const tasks = box('tasks', 'Task updates');
  const files = box('files', 'Files', '(checked by content, never auto-opened)');
  const filesRow = rows[rows.length - 1] as HTMLElement;
  rows.pop();

  const typeBoxes = new Map<AllowedMime, HTMLInputElement>();
  const typesGrid = h('div', { class: 'grant-editor__types', role: 'group', 'aria-label': `${opts.legend}: allowed file types` });
  for (const m of ALLOWED_MIMES) {
    const id = uid(testPrefix);
    const input = h('input', { type: 'checkbox', id, value: m, 'data-testid': `${testPrefix}-type-${m}` });
    typeBoxes.set(m, input);
    typesGrid.appendChild(h('label', { class: 'check', for: id, title: MIME_LABELS[m].long }, input, MIME_LABELS[m].short));
  }
  const sizeId = uid(testPrefix);
  const size = h('select', { id: sizeId, 'data-testid': `${testPrefix}-maxbytes` });
  const setSizeOptions = (current: number): void => {
    const values = [...new Set([...FILE_SIZE_OPTIONS, current])].sort((a, b) => a - b);
    size.replaceChildren(...values.map((v) => h('option', { value: String(v) }, formatBytes(v))));
    size.value = String(current);
  };
  const sizeRow = h('div', { class: 'grant-editor__size' }, h('label', { for: sizeId, class: 'muted' }, 'Max file size'), size);

  const syncFiles = (): void => {
    typesGrid.classList.toggle('grant-editor__types--off', !files.checked);
    sizeRow.classList.toggle('grant-editor__types--off', !files.checked);
  };
  files.addEventListener('change', syncFiles);

  const el = h(
    'fieldset',
    { class: 'grant-editor' },
    h('legend', null, h('span', { class: 'label' }, opts.legend)),
    opts.hint ? h('p', { class: 'muted small' }, opts.hint) : null,
    rows,
    filesRow,
    typesGrid,
    sizeRow,
  );

  const set = (g: DirectionGrant): void => {
    prompts.checked = g.prompts;
    tasks.checked = g.tasks;
    files.checked = g.files;
    for (const [m, b] of typeBoxes) b.checked = g.fileTypes.includes(m);
    setSizeOptions(g.maxFileBytes);
    syncFiles();
  };
  set(opts.initial);

  const get = (): DirectionGrant => {
    const f = files.checked;
    return {
      prompts: prompts.checked,
      tasks: tasks.checked,
      files: f,
      fileTypes: f ? ALLOWED_MIMES.filter((m) => typeBoxes.get(m)?.checked) : [],
      maxFileBytes: Number(size.value) || FILE_SIZE_OPTIONS[2]!,
    };
  };
  const validate = (): string | null => {
    if (files.checked && !ALLOWED_MIMES.some((m) => typeBoxes.get(m)?.checked)) {
      return `${opts.legend}: pick at least one file type, or untick "Files".`;
    }
    return null;
  };
  return { el, get, set, validate };
}

export function ttlSelect(testid: string, initial: number, id = uid('ttl')): HTMLSelectElement {
  const values = [...new Set([...ROOM_TTL_OPTIONS_MS])];
  const sel = h('select', { id, 'data-testid': testid }, values.map((v) => h('option', { value: String(v) }, formatTtl(v))));
  sel.value = String(values.includes(initial) ? initial : values[1]);
  return sel;
}

/** "<who> may send <to>: prompts, …" lines. */
export function grantLines(lines: { who: Child; to?: Child; grant: DirectionGrant }[]): HTMLElement {
  return h(
    'div',
    { class: 'grant-lines' },
    lines.map(({ who, to, grant }) => {
      const summary = grantSummary(grant);
      return h(
        'div',
        { class: 'grant-line' },
        h('span', { class: 'grant-line__who' }, who),
        to ? [' may send ', to, ': '] : ' may send: ',
        h('span', { class: summary === 'nothing' ? 'grant-line__none' : '' }, summary),
      );
    }),
  );
}

type NarrowField = 'prompts' | 'tasks' | 'files';

/**
 * Narrowing control: only lets the user switch permissions OFF (or drop file types).
 * Widening would be refused by the router anyway (NOT_PERMITTED).
 */
export function narrowControl(
  room: RoomAdminView,
  labels: Record<Direction, string>,
  onApply: (patch: GrantNarrowing) => Promise<void>,
  open = false,
  onToggle?: (open: boolean) => void,
): HTMLDetailsElement {
  const inputs: Record<Direction, Record<NarrowField, HTMLInputElement>> = { i2j: {} as never, j2i: {} as never };
  const typeInputs: Record<Direction, Map<AllowedMime, HTMLInputElement>> = { i2j: new Map(), j2i: new Map() };
  const blocks: HTMLElement[] = [];
  for (const dir of ['i2j', 'j2i'] as const) {
    const g = room.grant[dir];
    const fieldRow: HTMLElement[] = [];
    for (const [f, label] of [['prompts', 'Prompts & replies'], ['tasks', 'Task updates'], ['files', 'Files']] as const) {
      const id = uid('narrow');
      const on = g[f];
      const input = h('input', { type: 'checkbox', id, checked: on, disabled: !on, 'data-testid': `narrow-${dir}-${f}` });
      inputs[dir][f] = input;
      fieldRow.push(h('label', { class: `check${on ? '' : ' check--disabled'}`, for: id, title: on ? 'Untick to revoke' : 'Already off (cannot be widened)' }, input, label));
    }
    let typesRow: HTMLElement | null = null;
    if (g.files && g.fileTypes.length > 1) {
      typesRow = h(
        'div',
        { class: 'grant-editor__types', role: 'group', 'aria-label': `${labels[dir]}: file types` },
        g.fileTypes.map((m) => {
          const id = uid('narrow');
          const input = h('input', { type: 'checkbox', id, checked: true, 'data-testid': `narrow-${dir}-type-${m}` });
          typeInputs[dir].set(m, input);
          return h('label', { class: 'check', for: id }, input, MIME_LABELS[m]?.short ?? m);
        }),
      );
    }
    blocks.push(h('div', { class: 'stack stack--sm' }, h('span', { class: 'label' }, labels[dir]), h('div', { class: 'row' }, fieldRow), typesRow));
  }
  const status = h('span', { class: 'small muted', role: 'status' });
  const apply = h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-testid': 'narrow-apply' }, 'Apply narrowing');
  apply.addEventListener('click', () => {
    const patch: GrantNarrowing = {};
    for (const dir of ['i2j', 'j2i'] as const) {
      const g = room.grant[dir];
      const d: Partial<DirectionGrant> = {};
      if (g.prompts && !inputs[dir].prompts.checked) d.prompts = false;
      if (g.tasks && !inputs[dir].tasks.checked) d.tasks = false;
      if (g.files) {
        const kept = g.fileTypes.filter((m) => typeInputs[dir].get(m)?.checked ?? true);
        if (!inputs[dir].files.checked || kept.length === 0) {
          d.files = false;
          d.fileTypes = [];
        } else if (kept.length < g.fileTypes.length) {
          d.fileTypes = kept;
        }
      }
      if (Object.keys(d).length) patch[dir] = d;
    }
    if (!patch.i2j && !patch.j2i) {
      status.textContent = 'Nothing to change. Untick a permission first.';
      return;
    }
    apply.disabled = true;
    status.textContent = 'Applying…';
    onApply(patch).then(
      () => {
        status.textContent = 'Narrowed.';
      },
      () => {
        status.textContent = '';
        apply.disabled = false;
      },
    );
  });
  const details = h(
    'details',
    { class: 'disclosure', open },
    h('summary', { 'data-testid': 'room-narrow' }, 'Narrow…'),
    h(
      'div',
      { class: 'disclosure__body' },
      h('p', { class: 'small muted' }, 'Permissions can only be reduced while a room is open. To widen them, pair again.'),
      blocks,
      h('div', { class: 'row' }, apply, status),
    ),
  );
  details.addEventListener('toggle', () => onToggle?.(details.open));
  return details;
}

export function roomStateStamp(state: RoomAdminView['state']): HTMLSpanElement {
  const tone = state === 'active' ? 'ok' : state === 'keying' ? 'info' : 'muted';
  return h('span', { class: `stamp stamp--${tone}` }, state === 'keying' ? 'Keying' : state === 'active' ? 'Active' : 'Closed');
}
