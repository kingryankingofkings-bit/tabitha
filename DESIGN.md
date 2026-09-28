# TabBridge Design System: "Customs House"

TabBridge exists so people can see and control what crosses between their tabs. The
visual language borrows from a border checkpoint: every exchange is a declaration that
gets **inspected** and **stamped**. The UI should feel like a ledger, calm and legible,
with ink on paper, so that the rare red stamp gets noticed.

Implementation: tokens live 1:1 in `src/ui/styles/tokens.css` as CSS custom properties.
Component and element styles live in `src/ui/styles/base.css` and use only tokens (no raw
colors, type sizes, spacing or durations outside `tokens.css`; a few fixed layout extents
such as control min-heights and scroll max-heights are set locally).

## 1. Principles

1. **The origin is the passport.** Origins (`scheme://host:port`) are the only trusted
   identity. They are always shown in full, in monospace, at body size or larger
   (`.origin`). Page titles can be spoofed. If a title is shown at all, it is secondary:
   dimmed, truncated, and labelled *page title (unverified)* (`.unverified`).
2. **Data is typeset as data.** Origins, codes, hashes, sizes, sequence numbers,
   timestamps and IDs use the mono stack with `tabular-nums` and `slashed-zero`.
3. **Consent reads as plain language.** Grants are sentences, not toggles alone:
   "https://a.example may send you: prompts, task updates, files (PNG, PDF ≤ 2 MB)".
   The approve action is never focused by default. Reject is always shown next to it.
4. **Color means something.** Stamp red = denied, rejected, violation or destructive
   action. Verified green = approved, paired or active. Customs blue = information and
   links. Amber = caution (paused, pending, locked). Everything else is ink.
5. **Stamps are for events.** Audit entries and room states use the rotated,
   double-bordered stamp. Chrome and controls stay straight and quiet.
6. **Nothing remote.** System font stacks only. No web fonts, remote images or
   analytics. Extension CSP forbids inline scripts. Styles are shipped as files.

## 2. Themes

| Theme | Trigger | Paper | Text |
|---|---|---|---|
| Day shift (light) | default | cream paper `#F4EFE3` | ink `#1C1A17` |
| Night shift (dark) | `prefers-color-scheme: dark` | deep ink-blue `#0E1829` | bone `#ECE5D3` |

Both themes redefine the same token names. Components never branch on theme.

## 3. Color tokens

| Token | Day | Night | Use |
|---|---|---|---|
| `--c-paper` | `#F4EFE3` | `#0E1829` | page background |
| `--c-paper-raised` | `#FBF8F0` | `#15233A` | cards, inputs, dialogs |
| `--c-paper-sunk` | `#EAE3D2` | `#0A1220` | wells, zebra rows, code blocks |
| `--c-ink` | `#1C1A17` | `#ECE5D3` | body text, primary button fill |
| `--c-ink-muted` | `#595347` | `#B4AB97` | secondary text, labels |
| `--c-ink-faint` | `#857D6E` | `#7C8599` | control borders, icons (non-text) |
| `--c-rule` | `#D8CFBC` | `#26364F` | ledger lines, dividers (decorative) |
| `--c-on-ink` | `#FBF8F0` | `#0E1829` | text on ink / accent fills |
| `--c-deny` | `#A8231B` | `#FF8F80` | stamp red |
| `--c-deny-tint` | `#F5DCD5` | `#3A1C22` | deny banner background |
| `--c-ok` | `#2B6636` | `#86D694` | verified green |
| `--c-ok-tint` | `#DDE9D7` | `#15321F` | ok banner background |
| `--c-info` | `#1D4C8A` | `#95BEFF` | customs blue |
| `--c-info-tint` | `#DAE4F1` | `#162C4C` | info banner background |
| `--c-warn` | `#855500` | `#F2C063` | amber caution |
| `--c-warn-tint` | `#F2E3C4` | `#372B12` | warn banner background |
| `--c-focus` | `#1446A0` | `#FFD166` | focus ring |
| `--c-scrim` | `rgb(28 26 23 / .45)` | `rgb(0 0 0 / .6)` | dialog backdrop |

### Verified contrast (WCAG 2.2, computed from the hex values)

| Pair | Day | Night | Requirement |
|---|---|---|---|
| ink on paper | 15.13 | 14.15 | AA text 4.5 ✔ |
| ink on paper-raised | 16.36 | 12.54 | 4.5 ✔ |
| ink on paper-sunk | 13.57 | 14.92 | 4.5 ✔ |
| ink-muted on paper | 6.65 | 7.80 | 4.5 ✔ |
| ink-muted on paper-sunk | 5.96 | 8.22 | 4.5 ✔ |
| deny on paper | 6.27 | 8.04 | 4.5 ✔ |
| ok on paper | 5.99 | 10.21 | 4.5 ✔ |
| info on paper | 7.46 | 9.39 | 4.5 ✔ |
| warn on paper | 5.55 | 10.58 | 4.5 ✔ |
| deny on deny-tint | 5.50 | 6.93 | 4.5 ✔ |
| ok on ok-tint | 5.47 | 8.00 | 4.5 ✔ |
| info on info-tint | 6.66 | 7.40 | 4.5 ✔ |
| warn on warn-tint | 5.02 | 8.24 | 4.5 ✔ |
| on-ink on ink (primary button) | 16.36 | 14.15 | 4.5 ✔ |
| on-ink on deny (danger button) | 6.77 | 8.04 | 4.5 ✔ |
| on-ink on ok (approve button) | 6.47 | 10.21 | 4.5 ✔ |
| ink-faint on paper (control borders) | 3.55 | 4.80 | non-text 3.0 ✔ |
| focus on paper (focus ring) | 7.58 | 12.33 | non-text 3.0 ✔ |

`--c-rule` is decorative only and is never the sole boundary of an interactive control.

## 4. Typography

System stacks only:

| Token | Value |
|---|---|
| `--font-sans` | `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` |
| `--font-serif` | `"Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif` (headings, wordmark) |
| `--font-mono` | `ui-monospace, "SF Mono", "Cascadia Mono", "Segoe UI Mono", "Roboto Mono", Menlo, Consolas, "Liberation Mono", monospace` |

| Token | Size | Line height | Use |
|---|---|---|---|
| `--fs-2xs` | 10px | 1.3 | stamp micro label |
| `--fs-xs` | 11px | 1.35 | form labels (uppercase, tracked), captions |
| `--fs-sm` | 12px | 1.4 | table cells, secondary text |
| `--fs-base` | 13px | 1.5 | body (dense extension UI) |
| `--fs-md` | 15px | 1.45 | section intro, origin in consent screens |
| `--fs-lg` | 18px | 1.3 | h2 / card titles |
| `--fs-xl` | 22px | 1.25 | h1 page title |
| `--fs-2xl` | 28px | 1.2 | dashboard masthead |
| `--fs-code` | 40px | 1 | pairing code |

Weights: `--fw-regular 400`, `--fw-medium 500`, `--fw-bold 700`. Labels use uppercase
with `--ls-label: .08em` tracking. Stamps use `--ls-stamp: .14em`.
All data uses `font-variant-numeric: tabular-nums slashed-zero` (`.mono`, `.num`).

## 5. Spacing, radii, borders, shadows

| Token | Value | | Token | Value |
|---|---|---|---|---|
| `--sp-0` | 2px | | `--r-0` | 0 |
| `--sp-1` | 4px | | `--r-1` | 2px (controls) |
| `--sp-2` | 8px | | `--r-2` | 4px (cards) |
| `--sp-3` | 12px | | `--r-stamp` | 3px |
| `--sp-4` | 16px | | `--r-pill` | 999px (status pills only) |
| `--sp-5` | 24px | | `--bw-hair` | 1px |
| `--sp-6` | 32px | | `--bw-strong` | 2px |
| `--sp-7` | 48px | | `--bw-stamp` | 3px (double) |
| | | | `--bw-bar` | 4px (banner/error left bar) |
| `--ledger` | 28px (ruled line pitch) | | `--focus-width` | 3px, `--focus-offset` 2px |

| Token | Day | Night |
|---|---|---|
| `--sh-card` | `0 1px 0 var(--c-rule), 0 2px 6px rgb(28 26 23 / .06)` | `0 1px 0 rgb(0 0 0 / .4), 0 2px 8px rgb(0 0 0 / .35)` |
| `--sh-lift` | `0 6px 24px rgb(28 26 23 / .14)` | `0 8px 28px rgb(0 0 0 / .55)` |

Corners are nearly square (paperwork, not bubbles). Dividers are ruled lines. Section
mastheads use a double rule (`border-bottom: 3px double`).

## 6. Motion

| Token | Value | Use |
|---|---|---|
| `--dur-fast` | 120ms | hover, press |
| `--dur-base` | 200ms | disclosure, banners |
| `--dur-stamp` | 260ms | stamp "thunk" on new audit rows and state changes |
| `--ease-out` | `cubic-bezier(.2, .7, .2, 1)` | general |
| `--ease-stamp` | `cubic-bezier(.2, .9, .3, 1.35)` | stamp overshoot |

Under `prefers-reduced-motion: reduce` every duration token becomes `0ms` and the stamp
keyframe is disabled. The static -1.5° stamp rotation stays because it is not motion.
Countdowns update text only and never animate.

## 7. Components (`base.css`)

| Class | Description |
|---|---|
| `.btn` | Straight-edged button. Variants: `.btn--primary` (ink fill), `.btn--approve` (green fill), `.btn--danger` (red fill), `.btn--ghost` (text with rule border), `.btn--sm`. Disabled buttons are at 45% opacity with `cursor: not-allowed`. |
| `.field`, `.label`, `input`, `select`, `textarea` | Raised paper with an ink-faint 1px border. Labels are uppercase, tracked and muted. |
| `.check` | Checkbox plus label row. Uses `accent-color: var(--c-ink)`. |
| `.card` | Raised paper, hairline border, `--sh-card`. `.card--closed` is dimmed. |
| `.ledger` | Ruled-line background at `--ledger` pitch for forms and lists. |
| `.stamp` | Inline, uppercase mono, 3px double border in `currentColor`, rotated -1.5°. Tones: `.stamp--ok`, `.stamp--deny`, `.stamp--info`, `.stamp--warn`, `.stamp--ink`, `.stamp--muted`. `.stamp--new` plays the thunk animation once. |
| `.origin` | Full origin in mono, medium weight, `word-break: break-all`. The scheme is dimmed, `http:` is amber (`.origin__scheme--insecure`), and the host is bold. |
| `.unverified` | Dimmed, italic, single-line truncated text with a "page title (unverified)" label. |
| `.code-display` | Pairing code "ticket": dashed 2px border, `--fs-code` mono digits in two groups of three. Expiry countdown sits below. |
| `.banner` | Full-width notice with a left `--bw-bar` bar. Tones: `--deny`, `--ok`, `--info`, `--warn`. The pause banner is `.banner--warn`. |
| `.error-area` | `role="alert"` region. Empty means hidden. Shows `CODE` in mono followed by a friendly message. |
| `.pill` | Small status pill for site/endpoint status (`--ok`, `--muted`, `--warn`). |
| `.table` | Ledger table: sticky header, ruled rows, zebra on `--c-paper-sunk`, mono numeric cells. |
| `.kv` | Definition grid (label/value) for provenance, hashes and room details. |
| `.consent` | Consent screen: two origin "passports" side by side, per-direction sentences, and a button row with Reject first and Approve last. Approve is never autofocused. |
| `.timeline`, `.msg` | Agent Console conversation. Incoming messages sit left on raised paper, outgoing ones sit right on sunk paper. The type stamp sits in the corner. |
| `dialog.dialog` | Native `<dialog>` with a scrim backdrop, used for destructive confirmations (clear log). |

### Focus

`:focus-visible` draws a `--focus-width` solid `--c-focus` outline at `--focus-offset`,
on every interactive element including checkboxes and summary toggles. It is never
removed. Mouse focus stays quiet because `:focus:not(:focus-visible)` has no outline.

## 8. Audit stamp vocabulary

| Audit type(s) | Stamp | Tone |
|---|---|---|
| `frame.routed` | ROUTED | ink |
| `frame.rejected`, `endpoint.rejected`, `pair.failed` | REJECTED | deny |
| `violation` | VIOLATION | deny |
| `content.sent` | SENT | info |
| `content.received` | RECEIVED | info |
| `frame.receipt` | RECEIPT | muted |
| `pair.approved`, `room.opened` | PAIRED / OPENED | ok |
| `pair.started`, `pair.requested` | ISSUED / REQUESTED | info |
| `pair.cancelled` | CANCELLED | muted |
| `room.narrowed` | NARROWED | warn |
| `room.closed` | CLOSED | muted |
| `site.enabled` / `site.disabled` | ENABLED / DISABLED | ok / muted |
| `pause.changed` | PAUSED / RESUMED | warn |
| `log.cleared` | CLEARED | warn |

## 9. Copy rules

- Direction labels use the viewer's own perspective. In the popup, "This tab may send"
  is the initiator→joiner direction (`i2j`) and "The other tab may send" is `j2i`.
- Sizes use binary multiples, written KB/MB (`2 MB` = 2,097,152 bytes).
- Error text: `CODE` (mono) + one plain sentence saying what happened and what to do.
- Never say "secure" without saying what it means. Say "end-to-end encrypted between
  the two tabs" instead.
