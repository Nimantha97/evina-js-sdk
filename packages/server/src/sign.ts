/**
 * EVINA v1 signature auth (opt-in) — ADR-015.
 * =====================================================================
 *
 * ADR-002 makes v2 API-key the default and only *recommended* auth. Some legacy
 * EVINA accounts (e.g. `dialog_sl`) are provisioned for the **v1 signature**
 * method instead: an HTTP GET to `/{username}/<endpoint>` with all query
 * parameters plus a computed signature `s`.
 *
 * EVINA does not publish the signature algorithm. This implementation uses the
 * algorithm reverse-engineered from the IdeaBiz Java widget and recorded in
 * `documents/EVINA_AUDIT_REPORT.md`:
 *
 *     s = SHA-256( username + queryString + password )  → lowercase hex
 *
 * The exact meaning of "queryString" (ordering, separators, leading `?`,
 * encoding) is the only uncertain part, so this module centralises it in ONE
 * pure function and exposes named strategies. `signQuery` uses the default
 * strategy; the standalone probe (scripts/probe-v1.ts) can try alternatives
 * against the live API to confirm which one the account accepts.
 *
 * Security notes:
 *  - The password (signature secret) is treated like the API key: never logged,
 *    never returned, redacted by the logger.
 *  - Uses native `node:crypto` only (ADR-006, zero runtime deps).
 */

import { createHash } from "node:crypto";

/**
 * Build the canonical query string from ordered params (no leading `?`).
 * Values are percent-encoded via URLSearchParams (RFC-3986), matching the
 * encoding EVINA expects on the wire.
 */
export function buildQueryString(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

/**
 * Compute the v1 signature.
 *
 * @param username    - EVINA account username (path + signature input).
 * @param queryString - The exact query string that will be sent (no `?`, no
 *                      trailing `s=`), in the same order as the request.
 * @param password    - EVINA v1 signature secret.
 * @returns lowercase hex SHA-256 digest.
 */
export function computeSignature(
  username: string,
  queryString: string,
  password: string,
): string {
  return createHash("sha256")
    .update(`${username}${queryString}${password}`, "utf8")
    .digest("hex");
}

/**
 * Given ordered params (WITHOUT `s`), return the full query string WITH the
 * appended `s=<signature>`. This is what gets placed after `?` in the GET URL.
 *
 * The signature is computed over the query string that precedes it, so the
 * caller must pass `params` in the exact order they will be sent.
 */
export function signQuery(
  params: Record<string, string>,
  username: string,
  password: string,
): string {
  const queryString = buildQueryString(params);
  const s = computeSignature(username, queryString, password);
  return `${queryString}&s=${s}`;
}
