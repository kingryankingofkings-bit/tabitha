// Provenance records attached to delivered files. SPEC.md §3 (Provenance), §13; DECISIONS.md D6.

import { TabBridgeError } from '../shared/errors';
import { ALLOWED_MIMES, HARD_MAX_FILE_BYTES, HEX32_RE, HEX64_RE } from '../shared/limits';
import type { AllowedMime, FrameId, PeerRef, Provenance, RoomId } from '../shared/types';

const KINDS: readonly string[] = ['page', 'panel', 'native'];

/**
 * Build the provenance for a file that has passed `validateFile` on the receiver.
 * Throws `VALIDATION_FAILED` on malformed input rather than producing a misleading record.
 * The result is a fresh frozen object containing only the Provenance fields.
 */
export function buildProvenance(a: {
  from: PeerRef;
  roomId: RoomId;
  frameId: FrameId;
  sha256: string;
  mime: AllowedMime;
  size: number;
  sentAt: number;
  receivedAt: number;
}): Provenance {
  const ok =
    a != null &&
    a.from != null &&
    typeof a.from.origin === 'string' &&
    a.from.origin.length > 0 &&
    KINDS.includes(a.from.kind) &&
    typeof a.roomId === 'string' &&
    HEX32_RE.test(a.roomId) &&
    typeof a.frameId === 'string' &&
    HEX32_RE.test(a.frameId) &&
    typeof a.sha256 === 'string' &&
    HEX64_RE.test(a.sha256) &&
    (ALLOWED_MIMES as readonly string[]).includes(a.mime) &&
    Number.isSafeInteger(a.size) &&
    a.size >= 1 &&
    a.size <= HARD_MAX_FILE_BYTES &&
    Number.isFinite(a.sentAt) &&
    Number.isFinite(a.receivedAt);
  if (!ok) throw new TabBridgeError('VALIDATION_FAILED', 'Invalid provenance input');
  return Object.freeze({
    fromOrigin: a.from.origin,
    fromKind: a.from.kind,
    roomId: a.roomId,
    frameId: a.frameId,
    sha256: a.sha256,
    detectedType: a.mime,
    size: a.size,
    sentAt: a.sentAt,
    receivedAt: a.receivedAt,
    validated: true as const,
  });
}
