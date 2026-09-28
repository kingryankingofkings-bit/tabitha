// Stable error codes. Part of the public API (apiVersion 1). SPEC.md §9.

export const ERROR_CODES = [
  'UNSUPPORTED_VERSION',
  'INVALID_MESSAGE',
  'INTERNAL',
  'TIMEOUT',
  'NOT_CONNECTED',
  'ORIGIN_NOT_ENABLED',
  'SENDER_REJECTED',
  'RESUME_REJECTED',
  'PAUSED',
  'ROOM_NOT_FOUND',
  'ROOM_NOT_ACTIVE',
  'ROOM_EXPIRED',
  'ROOM_CLOSED',
  'NOT_A_MEMBER',
  'TOO_MANY_ROOMS',
  'NOT_PERMITTED',
  'PEER_UNAVAILABLE',
  'NO_AGENT',
  'DELIVERY_TIMEOUT',
  'RATE_LIMITED',
  'PAYLOAD_TOO_LARGE',
  'REPLAY',
  'SPOOFED_SENDER',
  'DECRYPT_FAILED',
  'KEY_CONFIRM_FAILED',
  'VALIDATION_FAILED',
  'FILE_TOO_LARGE',
  'FILE_TYPE_DENIED',
  'FILE_TYPE_MISMATCH',
  'FILE_NAME_INVALID',
  'FILE_EMPTY',
  'FILE_HASH_MISMATCH',
  'PAIRING_CODE_INVALID',
  'PAIRING_EXPIRED',
  'PAIRING_LOCKED',
  'PAIRING_SELF',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

const CODE_SET: ReadonlySet<string> = new Set(ERROR_CODES);

const DEFAULT_MESSAGES: Partial<Record<ErrorCode, string>> = {
  UNSUPPORTED_VERSION: 'Unsupported protocol or API version',
  INVALID_MESSAGE: 'Malformed message',
  INTERNAL: 'Internal error',
  TIMEOUT: 'Timed out',
  NOT_CONNECTED: 'Not connected to TabBridge',
  ORIGIN_NOT_ENABLED: 'TabBridge is not enabled for this site',
  PAUSED: 'TabBridge is paused',
  ROOM_NOT_FOUND: 'Room not found',
  ROOM_NOT_ACTIVE: 'Room is not active',
  ROOM_EXPIRED: 'Room has expired',
  ROOM_CLOSED: 'Room is closed',
  NOT_A_MEMBER: 'Not a member of this room',
  NOT_PERMITTED: 'Not permitted by the room grant',
  PEER_UNAVAILABLE: 'Peer is not connected',
  NO_AGENT: 'Peer tab has no agent attached',
  DELIVERY_TIMEOUT: 'Peer did not confirm delivery in time',
  RATE_LIMITED: 'Rate limit exceeded',
  PAYLOAD_TOO_LARGE: 'Payload too large',
  REPLAY: 'Replayed or out-of-order frame',
  DECRYPT_FAILED: 'Decryption failed',
  FILE_TOO_LARGE: 'File exceeds the size limit',
  FILE_TYPE_DENIED: 'File type is not allowed',
  FILE_TYPE_MISMATCH: 'File content does not match its declared type',
  FILE_NAME_INVALID: 'Invalid file name',
  FILE_EMPTY: 'File is empty',
  FILE_HASH_MISMATCH: 'File hash mismatch',
  PAIRING_CODE_INVALID: 'Invalid pairing code',
  PAIRING_EXPIRED: 'Pairing code expired',
  PAIRING_LOCKED: 'Pairing temporarily locked after too many failed attempts',
  PAIRING_SELF: 'Cannot pair an endpoint with itself',
};

export function isErrorCode(x: unknown): x is ErrorCode {
  return typeof x === 'string' && CODE_SET.has(x);
}

export class TabBridgeError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message?: string) {
    super(message ?? DEFAULT_MESSAGES[code] ?? code);
    this.name = 'TabBridgeError';
    this.code = code;
  }

  toJSON(): { code: ErrorCode; message: string } {
    return { code: this.code, message: this.message };
  }
}

/** Serialize any thrown value for the wire. Non-TabBridge errors never leak details. */
export function toErrorPayload(e: unknown): { code: ErrorCode; message: string } {
  if (e instanceof TabBridgeError) return { code: e.code, message: e.message };
  return { code: 'INTERNAL', message: 'Internal error' };
}

export function fromErrorPayload(p: { code?: unknown; message?: unknown } | undefined): TabBridgeError {
  const code = isErrorCode(p?.code) ? p.code : 'INTERNAL';
  const message = typeof p?.message === 'string' ? p.message.slice(0, 500) : undefined;
  return new TabBridgeError(code, message);
}
