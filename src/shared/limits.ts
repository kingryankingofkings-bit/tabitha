// All numeric limits and enums. SPEC.md §8 is authoritative.
import type { AllowedMime, RateLimit, TaskStatus } from './types';

declare const __TB_VERSION__: string;

export const PROTOCOL_VERSION = 1 as const;
export const API_VERSIONS: readonly number[] = Object.freeze([1]);
export const EXT_VERSION: string = typeof __TB_VERSION__ === 'string' ? __TB_VERSION__ : '0.1.0';

export const ALLOWED_MIMES: readonly AllowedMime[] = Object.freeze([
  'text/plain',
  'text/markdown',
  'text/csv',
  'application/json',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'application/pdf',
] as AllowedMime[]);

export const TASK_STATUSES: readonly TaskStatus[] = Object.freeze([
  'queued',
  'running',
  'blocked',
  'done',
  'failed',
  'cancelled',
] as TaskStatus[]);

export const MAX_TEXT_BYTES = 32_768;
export const MAX_SUMMARY_CHARS = 2_048;
export const MAX_AGENT_NAME = 64;
export const MAX_NOTE_CHARS = 140;

export const HARD_MAX_FILE_BYTES = 8 * 1024 * 1024;
export const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
export const FILE_META_MAX = 1_024;

export const BODY_LIMITS = Object.freeze({
  confirm: 256,
  prompt: 36_864,
  response: 36_864,
  task: 8_192,
  file: HARD_MAX_FILE_BYTES + 4 + FILE_META_MAX,
});

/** 12-byte IV + 16-byte GCM tag. */
export const AES_GCM_OVERHEAD = 28;

export const PAIRING_CODE_TTL_MS = 120_000;
export const PAIRING_MAX_FAILURES = 3;
export const PAIRING_GLOBAL_FAILS_PER_MIN = 10;
export const PAIRING_LOCKOUT_MS = 60_000;

export const ROOM_TTL_OPTIONS_MS: readonly number[] = Object.freeze([900_000, 3_600_000, 28_800_000]);
export const DEFAULT_ROOM_TTL_MS = 3_600_000;

export const DEFAULT_RATE: Readonly<RateLimit> = Object.freeze({
  framesPerMinute: 60,
  bytesPerMinute: 16 * 1024 * 1024,
});

export const MAX_ROOMS_PER_ENDPOINT = 8;
export const KEYING_TIMEOUT_MS = 30_000;
export const RESUME_GRACE_MS = 30_000;
export const DELIVERY_TIMEOUT_MS = 15_000;
export const ASK_DEFAULT_TIMEOUT_MS = 60_000;
export const ASK_MAX_TIMEOUT_MS = 600_000;
export const PAIR_REQUEST_TTL_MS = 300_000;
export const CLOSED_ROOM_RETENTION_MS = 600_000;

export const AUDIT_DEFAULT_MAX_ENTRIES = 5_000;
export const AUDIT_MIN_MAX_ENTRIES = 100;
export const AUDIT_MAX_MAX_ENTRIES = 20_000;
export const AUDIT_FLUSH_MS = 250;

export const ID_TOKEN_RE = /^[A-Za-z0-9_-]{1,64}$/;
export const HEX32_RE = /^[0-9a-f]{32}$/;
export const HEX64_RE = /^[0-9a-f]{64}$/;
export const CODE_RE = /^[0-9]{6}$/;

export const PANEL_ORIGIN = 'tabbridge://console';
export const PANEL_PATH = '/ui/sidepanel.html';

export const PORT_ENDPOINT = 'tb.endpoint';
export const PORT_UI = 'tb.ui';
