/**
 * Framework-agnostic HTTP integration endpoint handlers (M6.5).
 *
 * Provides two handler factories that a consuming backend mounts on its own
 * routes. Each factory takes an {@link EvinaClient} and returns an async
 * function that accepts a parsed input object and returns `{ status, body }`.
 * No web-framework dependency is introduced (ADR-006, FR-A3).
 *
 * Security invariants (FR-A5, THREAT_MODEL):
 *  - The EVINA token is NEVER included in any response body (FR-A1).
 *  - Raw `ft`, API key, username, and MSISDNs are NEVER included in responses.
 *  - Only `{ transactionId, script }` leaves the request-script handler.
 *  - Only `{ allowed, category, reason }` leaves the verify handler.
 *  - Input validation errors surface as 400 before any client call.
 *  - Upstream failures surface as 502; unexpected errors as 500.
 *  - The verify handler never lets a client claim "allowed" — the verdict is
 *    always computed server-side by EvinaClient.checkTransaction (T-T1).
 */

import { EvinaClient } from "./client.js";
import { EvinaScriptError, EvinaTransportError } from "./errors.js";
import type { ArgKey, FraudCategory } from "./types.js";

// ---------------------------------------------------------------------------
// Public input / output types
// ---------------------------------------------------------------------------

/** Input to the request-script handler (FR-A1). */
export interface RequestScriptInput {
  /** CSS selector of the protected element → `te`. Required. */
  targetSelector: string;
  /** Transaction id → `ti`. Generated if absent. */
  transactionId?: string;
  /** ISO-3166 alpha-2 country. */
  country?: string;
  /** MCC-MNC carrier. */
  carrier?: string;
  /** Service name. */
  service?: string;
  /** End-user id (passes through `userIdTransform`, ADR-008). */
  userId?: string;
  /** Free-form dashboard args. */
  args?: Partial<Record<ArgKey, string>>;
}

/** Successful response body from the request-script handler. Token excluded (FR-A1, FR-A5). */
export interface RequestScriptBody {
  transactionId: string;
  script: string;
}

/** Input to the verify handler (FR-A2). */
export interface VerifyInput {
  /** Transaction id → `ti`. Required. */
  transactionId: string;
  /** ISO-3166 alpha-2 country. */
  country?: string;
  /** MCC-MNC carrier. */
  carrier?: string;
  /** Service name. */
  service?: string;
  /** End-user id (passes through `userIdTransform`, ADR-008). */
  userId?: string;
  /** Free-form dashboard args. */
  args?: Partial<Record<ArgKey, string>>;
}

/** Successful response body from the verify handler. ft/token/secrets excluded (FR-A2, FR-A5). */
export interface VerifyBody {
  allowed: boolean;
  category: FraudCategory;
  reason?: string;
}

/** Error response body. Message is safe-to-expose (no secrets/PII). */
export interface ErrorBody {
  error: string;
}

/** The shape every handler returns: an HTTP status + a JSON-serialisable body. */
export type HandlerResponse<T> = { status: number; body: T | ErrorBody };

// ---------------------------------------------------------------------------
// Handler factories
// ---------------------------------------------------------------------------

/**
 * Create a request-script handler bound to `client` (FR-A1, FR-A3).
 *
 * The returned function accepts a {@link RequestScriptInput} and returns
 * `{ status, body }` where a successful body is `{ transactionId, script }`.
 * The EVINA token is stripped before returning (FR-A5).
 *
 * @param client - A configured {@link EvinaClient}.
 */
export function requestScriptHandler(
  client: EvinaClient,
): (input: RequestScriptInput) => Promise<HandlerResponse<RequestScriptBody>> {
  return async (input) => {
    // --- Input validation → 400 (NFR-SEC-7) ---
    if (
      typeof input.targetSelector !== "string" ||
      input.targetSelector.trim().length === 0
    ) {
      return { status: 400, body: { error: "targetSelector is required" } };
    }

    let result;
    try {
      result = await client.getScript({
        targetSelector: input.targetSelector,
        ...(input.transactionId !== undefined && { transactionId: input.transactionId }),
        ...(input.country !== undefined && { country: input.country }),
        ...(input.carrier !== undefined && { carrier: input.carrier }),
        ...(input.service !== undefined && { service: input.service }),
        ...(input.userId !== undefined && { userId: input.userId }),
        ...(input.args !== undefined && { args: input.args }),
      });
    } catch (err) {
      return mapScriptError(err);
    }

    // Token deliberately excluded from the response (FR-A1, FR-A5, T-I5).
    return {
      status: 200,
      body: { transactionId: result.transactionId, script: result.script },
    };
  };
}

/**
 * Create a verify handler bound to `client` (FR-A2, FR-A3).
 *
 * The returned function accepts a {@link VerifyInput} and returns
 * `{ status, body }` where a successful body is `{ allowed, category, reason }`.
 * Raw `ft`, the EVINA token, and all secrets are excluded (FR-A5).
 *
 * The verdict is always computed server-side — the client cannot influence
 * `allowed` by supplying a crafted input (T-T1).
 *
 * @param client - A configured {@link EvinaClient}.
 */
export function verifyHandler(
  client: EvinaClient,
): (input: VerifyInput) => Promise<HandlerResponse<VerifyBody>> {
  return async (input) => {
    // --- Input validation → 400 (NFR-SEC-7) ---
    if (
      typeof input.transactionId !== "string" ||
      input.transactionId.trim().length === 0
    ) {
      return { status: 400, body: { error: "transactionId is required" } };
    }

    let verdict;
    try {
      verdict = await client.checkTransaction({
        transactionId: input.transactionId,
        ...(input.country !== undefined && { country: input.country }),
        ...(input.carrier !== undefined && { carrier: input.carrier }),
        ...(input.service !== undefined && { service: input.service }),
        ...(input.userId !== undefined && { userId: input.userId }),
        ...(input.args !== undefined && { args: input.args }),
      });
    } catch (err) {
      // TypeError from assertValidTransactionId → bad input from caller.
      if (err instanceof TypeError) {
        return { status: 400, body: { error: "invalid transactionId" } };
      }
      return { status: 500, body: { error: "internal error" } };
    }

    // Only expose the coarse verdict — no ft, no token, no secrets (FR-A5, FR-29).
    const body: VerifyBody = {
      allowed: verdict.allowed,
      category: verdict.category,
    };
    if (verdict.reason !== undefined) body.reason = verdict.reason;

    return { status: 200, body };
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function mapScriptError(err: unknown): HandlerResponse<RequestScriptBody> {
  if (err instanceof TypeError) {
    return { status: 400, body: { error: "invalid transactionId" } };
  }
  if (err instanceof EvinaScriptError || err instanceof EvinaTransportError) {
    return { status: 502, body: { error: "upstream error" } };
  }
  return { status: 500, body: { error: "internal error" } };
}
