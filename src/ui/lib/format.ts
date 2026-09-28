// Plain-language formatting shared by all UI pages.
import { TabBridgeError, isErrorCode, type ErrorCode } from '../../shared/errors';
import type { AllowedMime, AuditType, CloseReason, DirectionGrant, EndpointKind } from '../../shared/types';
import type { StampTone } from './dom';

export const MIME_LABELS: Record<AllowedMime, { short: string; long: string }> = {
  'text/plain': { short: 'TXT', long: 'Plain text (.txt)' },
  'text/markdown': { short: 'MD', long: 'Markdown (.md)' },
  'text/csv': { short: 'CSV', long: 'CSV table (.csv)' },
  'application/json': { short: 'JSON', long: 'JSON (.json)' },
  'image/png': { short: 'PNG', long: 'PNG image' },
  'image/jpeg': { short: 'JPEG', long: 'JPEG image' },
  'image/gif': { short: 'GIF', long: 'GIF image' },
  'image/webp': { short: 'WEBP', long: 'WebP image' },
  'application/pdf': { short: 'PDF', long: 'PDF document' },
};

export const TEXT_MIMES: ReadonlySet<AllowedMime> = new Set(['text/plain', 'text/markdown', 'text/csv', 'application/json']);

export const FILE_SIZE_OPTIONS: readonly number[] = [256 * 1024, 1024 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024];

export function mimeShort(m: string): string {
  return (MIME_LABELS as Record<string, { short: string } | undefined>)[m]?.short ?? m;
}

/** Binary multiples, written KB/MB (see DESIGN.md §9). */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '?';
  if (n < 1024) return `${n} B`;
  const trim = (x: number): string => (x >= 10 || Number.isInteger(x) ? String(Math.round(x)) : x.toFixed(1).replace(/\.0$/, ''));
  if (n < 1024 * 1024) return `${trim(n / 1024)} KB`;
  return `${trim(n / (1024 * 1024))} MB`;
}

export function formatTtl(ms: number): string {
  const min = Math.round(ms / 60_000);
  if (min < 60) return `${min} min`;
  const hr = min / 60;
  return `${Number.isInteger(hr) ? hr : hr.toFixed(1)} hour${hr === 1 ? '' : 's'}`;
}

const p2 = (n: number): string => String(n).padStart(2, '0');
export function formatTime(ts: number): string {
  const d = new Date(ts);
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
}
export function formatDateTime(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${formatTime(ts)}`;
}

export function shortId(id: string | undefined, n = 8): string {
  return id ? id.slice(0, n) : '—';
}

/** "prompts, task updates, files (PNG, PDF ≤ 2 MB)" or "nothing". */
export function grantSummary(g: DirectionGrant): string {
  const parts: string[] = [];
  if (g.prompts) parts.push('prompts');
  if (g.tasks) parts.push('task updates');
  if (g.files) {
    const types = g.fileTypes.length ? g.fileTypes.map(mimeShort).join(', ') : 'no types';
    parts.push(`files (${types} ≤ ${formatBytes(g.maxFileBytes)})`);
  }
  return parts.length ? parts.join(', ') : 'nothing';
}

export function kindLabel(kind: EndpointKind, tabId?: number): string {
  if (kind === 'panel') return 'Agent Console';
  if (kind === 'native') return 'native agent';
  return tabId !== undefined ? `tab ${tabId}` : 'tab';
}

export const CLOSE_REASONS: Record<CloseReason, string> = {
  user: 'closed by you',
  'peer-left': 'the other side left',
  expired: 'expired',
  'tab-closed': 'a tab was closed',
  'endpoint-gone': 'a tab navigated or reloaded',
  'site-disabled': 'a site was disabled',
  violation: 'closed after a security violation',
  'key-confirm-failed': 'key confirmation failed',
};

const FRIENDLY: Partial<Record<ErrorCode, string>> = {
  NOT_CONNECTED: 'Lost contact with the TabBridge background. Retrying. Try again in a moment.',
  ORIGIN_NOT_ENABLED: 'TabBridge is not enabled for this site.',
  SENDER_REJECTED: 'This page is not allowed to connect.',
  PAUSED: 'All transfers are paused. Resume to continue.',
  ROOM_NOT_FOUND: 'That room no longer exists.',
  ROOM_NOT_ACTIVE: 'The room is not active yet (still exchanging keys) or already closed.',
  ROOM_EXPIRED: 'The room has expired.',
  ROOM_CLOSED: 'The room is closed.',
  TOO_MANY_ROOMS: 'This tab already has the maximum number of open rooms.',
  NOT_PERMITTED: 'The room permissions do not allow this. Permissions can only be narrowed, never widened; pair again to widen.',
  PEER_UNAVAILABLE: 'The tab is not connected to TabBridge. Reload it and try again.',
  NO_AGENT: 'The other side has no agent attached.',
  DELIVERY_TIMEOUT: 'The other side did not confirm delivery in time.',
  RATE_LIMITED: 'Too many messages. Wait a minute.',
  PAYLOAD_TOO_LARGE: 'The message is too large.',
  FILE_TOO_LARGE: 'The file is larger than this room allows.',
  FILE_TYPE_DENIED: 'This file type is not allowed.',
  FILE_TYPE_MISMATCH: 'The file content does not match its name/type.',
  FILE_NAME_INVALID: 'The file name is not allowed.',
  FILE_EMPTY: 'The file is empty.',
  FILE_HASH_MISMATCH: 'The file was altered in transit (hash mismatch).',
  PAIRING_CODE_INVALID: 'That code is not valid. After 3 wrong tries all codes are cancelled.',
  PAIRING_EXPIRED: 'That code has expired. Ask for a new one.',
  PAIRING_LOCKED: 'Too many wrong codes. Pairing is locked for a minute.',
  PAIRING_SELF: 'A tab cannot pair with itself. Enter the code in the other tab.',
  TIMEOUT: 'The request timed out.',
  INVALID_MESSAGE: 'The request was rejected as malformed.',
  INTERNAL: 'Something went wrong inside TabBridge.',
};

export function describeError(e: unknown): { code: ErrorCode; message: string } {
  if (e instanceof TabBridgeError) return { code: e.code, message: FRIENDLY[e.code] ?? e.message };
  const maybe = e as { code?: unknown; message?: unknown } | null;
  if (maybe && isErrorCode(maybe.code)) {
    const m = typeof maybe.message === 'string' && maybe.message ? maybe.message : undefined;
    return { code: maybe.code, message: m ?? FRIENDLY[maybe.code] ?? maybe.code };
  }
  return { code: 'INTERNAL', message: FRIENDLY.INTERNAL as string };
}

export interface StampSpec { label: string; tone: StampTone }
export function auditStamp(type: AuditType, data: Record<string, unknown>): StampSpec {
  switch (type) {
    case 'frame.routed': return { label: 'Routed', tone: 'ink' };
    case 'frame.rejected':
    case 'endpoint.rejected':
    case 'pair.failed': return { label: 'Rejected', tone: 'deny' };
    case 'violation': return { label: 'Violation', tone: 'deny' };
    case 'content.sent': return { label: 'Sent', tone: 'info' };
    case 'content.received': return { label: 'Received', tone: 'info' };
    case 'frame.receipt': return { label: 'Receipt', tone: 'muted' };
    case 'pair.approved': return { label: 'Paired', tone: 'ok' };
    case 'room.opened': return { label: 'Opened', tone: 'ok' };
    case 'pair.started': return { label: 'Issued', tone: 'info' };
    case 'pair.requested': return { label: 'Requested', tone: 'info' };
    case 'pair.cancelled': return { label: 'Cancelled', tone: 'muted' };
    case 'room.narrowed': return { label: 'Narrowed', tone: 'warn' };
    case 'room.closed': return { label: 'Closed', tone: 'muted' };
    case 'site.enabled': return { label: 'Enabled', tone: 'ok' };
    case 'site.disabled': return { label: 'Disabled', tone: 'muted' };
    case 'pause.changed': return data.paused === false ? { label: 'Resumed', tone: 'warn' } : { label: 'Paused', tone: 'warn' };
    case 'log.cleared': return { label: 'Cleared', tone: 'warn' };
    default: return { label: String(type), tone: 'ink' };
  }
}

export const AUDIT_TYPES: readonly AuditType[] = [
  'site.enabled', 'site.disabled', 'pause.changed', 'endpoint.rejected',
  'pair.requested', 'pair.started', 'pair.failed', 'pair.approved', 'pair.cancelled',
  'room.opened', 'room.narrowed', 'room.closed',
  'frame.routed', 'frame.rejected', 'frame.receipt',
  'content.sent', 'content.received', 'violation', 'log.cleared',
];

/** One-line human summary of an audit entry's data (no full content). */
export function auditSummary(type: AuditType, data: Record<string, unknown>): string {
  const s = (k: string): string | undefined => (typeof data[k] === 'string' ? (data[k] as string) : undefined);
  const n = (k: string): number | undefined => (typeof data[k] === 'number' ? (data[k] as number) : undefined);
  const parts: string[] = [];
  if (s('origin')) parts.push(s('origin') as string);
  if (s('kind')) parts.push(s('kind') as string);
  if (s('mime')) parts.push(s('mime') as string);
  if (n('size') !== undefined) parts.push(formatBytes(n('size') as number));
  if (n('seq') !== undefined) parts.push(`seq ${n('seq')}`);
  if (s('code')) parts.push(s('code') as string);
  if (s('reason')) parts.push(s('reason') as string);
  if (s('status')) parts.push(s('status') as string);
  if (s('direction')) parts.push(s('direction') as string);
  if (type === 'pause.changed') parts.push(data.paused ? 'paused' : 'resumed');
  if (n('count') !== undefined) parts.push(`${n('count')} entries`);
  const detail = data.detail as Record<string, unknown> | undefined;
  if (detail && typeof detail === 'object') {
    if (typeof detail.kind === 'string') parts.push(detail.kind);
    if (typeof detail.name === 'string') parts.push(`“${detail.name}”`);
    if (typeof detail.text === 'string') {
      const t = detail.text.replace(/\s+/g, ' ');
      parts.push(`“${t.length > 60 ? `${t.slice(0, 60)}…` : t}”`);
    }
  }
  return parts.join(' · ');
}
