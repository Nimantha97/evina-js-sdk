/**
 * Fraud-code interpretation and verdict evaluation (M5).
 *
 * These are PURE functions (no I/O, no secrets) so they are trivially and
 * exhaustively unit-testable (FR-17). The blocking rule and category bands come
 * straight from EVINA_API_FACTS §7:
 *
 *   1xxx authentic → ALLOW    2xxx fraud       3xxx accidental
 *   4xxx error     5xxx bot   6xxx custom      else → unknown (all block)
 *
 * The ONLY allowing band is 1000–1999 (FR-15).
 */

import type { FraudCategory, Verdict } from "./types.js";

/** Lowest / highest `ft` in the "authentic" (allow) band. */
export const AUTHENTIC_MIN = 1000;
export const AUTHENTIC_MAX = 1999;

/**
 * Map a numeric `ft` to a stable {@link FraudCategory} (FR-17).
 * Non-integers / out-of-range / null map to `"unknown"` (which never allows).
 */
export function mapFtToCategory(ft: number | null): FraudCategory {
  if (ft === null || !Number.isInteger(ft)) return "unknown";
  if (ft >= 1000 && ft <= 1999) return "authentic";
  if (ft >= 2000 && ft <= 2999) return "fraud";
  if (ft >= 3000 && ft <= 3999) return "accidental";
  if (ft >= 4000 && ft <= 4999) return "error";
  if (ft >= 5000 && ft <= 5999) return "bot";
  if (ft >= 6000 && ft <= 6999) return "custom";
  return "unknown";
}

/**
 * Evaluate an EVINA `/check` response body into a {@link Verdict} (FR-14/15/17).
 *
 * Defensive: accepts `unknown`, never trusts shape, and only allows on a clear
 * authentic code with `success === true`.
 *
 * @param raw - The parsed EVINA response.
 */
export function evaluateVerdict(raw: unknown): Verdict {
  const body: Record<string, unknown> =
    typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};

  const success = body["success"] === true;
  const ft = toIntOrNull(body["ft"]);
  const authenticityScore = toIntOrNull(body["as"]);
  const opinion = toOpinion(body["oo"]);
  const category = mapFtToCategory(ft);
  const allowed = success && ft !== null && ft >= AUTHENTIC_MIN && ft <= AUTHENTIC_MAX;
  const reason = buildReason(success, ft, category, body["e"]);

  return { allowed, ft, category, authenticityScore, opinion, success, reason, raw };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toIntOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

function toOpinion(value: unknown): 0 | 1 | null {
  if (value === 0) return 0;
  if (value === 1) return 1;
  return null;
}

function buildReason(
  success: boolean,
  ft: number | null,
  category: FraudCategory,
  e: unknown,
): string {
  if (!success) {
    const codes = Array.isArray(e)
      ? (e as unknown[]).filter((x): x is string => typeof x === "string")
      : [];
    return codes.length > 0
      ? `check unsuccessful: ${codes.join(", ")}`
      : "check unsuccessful";
  }
  return ft === null ? "no fraud code returned" : `${category} (ft=${ft})`;
}
