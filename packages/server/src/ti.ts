/**
 * Transaction id (`ti`) generation and validation (M4).
 *
 *   FR-5       Generate a UUID `ti` when the caller supplies none; validate a
 *              caller-supplied `ti` (charset + length bounds).
 *   NFR-SEC-7  Bound and constrain caller-controlled input so a hostile `ti`
 *              cannot be used for injection or resource abuse (it is also used
 *              as a storage key and echoed to EVINA / dashboards).
 *   ADR-006    Uses native `node:crypto` — no runtime dependency.
 *
 * EVINA_API_FACTS §5: `ti` is a "unique transaction id, UUID format suggested,
 * alphanumeric". We accept alphanumerics plus `-` and `_` (so standard UUIDs
 * and common id schemes pass) within conservative length bounds.
 */

import { randomUUID } from "node:crypto";

/** Minimum accepted length for a caller-supplied `ti`. */
export const TI_MIN_LENGTH = 8;
/** Maximum accepted length for a caller-supplied `ti` (NFR-SEC-7 bound). */
export const TI_MAX_LENGTH = 64;

/** Allowed characters: alphanumerics, hyphen, underscore. */
const TI_PATTERN = /^[A-Za-z0-9_-]+$/;

/** Generate a fresh, cryptographically-random UUID v4 transaction id (FR-5). */
export function generateTransactionId(): string {
  return randomUUID();
}

/**
 * True when `ti` is a string within the length bounds and uses only the allowed
 * charset (FR-5, NFR-SEC-7).
 */
export function isValidTransactionId(ti: unknown): ti is string {
  return (
    typeof ti === "string" &&
    ti.length >= TI_MIN_LENGTH &&
    ti.length <= TI_MAX_LENGTH &&
    TI_PATTERN.test(ti)
  );
}

/**
 * Throw a `TypeError` if `ti` is not a valid transaction id. The message states
 * the constraint but never echoes the (possibly hostile) value.
 */
export function assertValidTransactionId(ti: unknown): asserts ti is string {
  if (!isValidTransactionId(ti)) {
    throw new TypeError(
      `transactionId must be ${TI_MIN_LENGTH}-${TI_MAX_LENGTH} characters using only [A-Za-z0-9_-]`,
    );
  }
}
