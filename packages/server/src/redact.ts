/**
 * Redaction utilities and the SDK `Logger` interface.
 *
 * This module is a security control, not a convenience (NFR-SEC-2, NFR-SEC-4,
 * NFR-SEC-13, THREAT_MODEL T-I1 / T-I3). Everything that could reach a log sink
 * or an error surface should pass through `redact()` first so that:
 *
 *   - EVINA API keys / usernames (caller-supplied secrets) never appear in
 *     logs, error messages, or serialized output (NFR-SEC-2, T-I1).
 *   - Raw MSISDNs (PII) are never logged in the clear; only a masked form is
 *     ever emitted (NFR-SEC-4, T-I3).
 *
 * Design notes:
 *   - `redact()` returns a NEW value; it never mutates its input.
 *   - Object walking builds fresh plain objects and skips dangerous keys
 *     (`__proto__`, `constructor`, `prototype`) so a malicious/odd payload
 *     cannot pollute prototypes during redaction (T-E2).
 *   - The default logger is a no-op (ADR-013); consumers opt in to real output
 *     by wrapping their own sink with `createRedactingLogger`.
 */

/** Replacement token used wherever a known secret value is found. */
const SECRET_MASK = "***REDACTED***";

/**
 * Matches contiguous digit runs 7–15 long, optionally prefixed with `+`.
 * This is deliberately broad: MSISDNs vary by country, so we mask any run that
 * could plausibly be a phone number. Over-masking is the safe failure mode for
 * a PII control (NFR-SEC-4).
 */
const MSISDN_PATTERN = /\+?\d{7,15}/g;

/** Guard against pathological / cyclic structures while walking objects. */
const MAX_DEPTH = 8;

/**
 * Structured logging interface (ADR-013).
 *
 * The SDK emits structured events (call counts, latencies, verdict outcomes,
 * fail-open occurrences) through this interface but must never pass secrets or
 * raw PII to it — see `createRedactingLogger`.
 */
export interface Logger {
  debug(message: string, meta?: object): void;
  info(message: string, meta?: object): void;
  warn(message: string, meta?: object): void;
  error(message: string, meta?: object): void;
}

/**
 * The default logger: does nothing (ADR-013 "default is a no-op or redacting
 * logger"). Chosen as the default so the SDK is silent unless a consumer opts
 * into observability, and so it can never accidentally leak.
 */
export const NOOP_LOGGER: Logger = {
  debug() {
    /* no-op default (ADR-013) */
  },
  info() {
    /* no-op default (ADR-013) */
  },
  warn() {
    /* no-op default (ADR-013) */
  },
  error() {
    /* no-op default (ADR-013) */
  },
};

/**
 * Mask MSISDN-like digit runs in a string, keeping only the last two digits so
 * logs stay minimally correlatable without exposing the number (NFR-SEC-4).
 *
 * e.g. `"user 94771234567 charged"` → `"user *********67 charged"`.
 */
export function maskMsisdns(text: string): string {
  return text.replace(MSISDN_PATTERN, (match) => {
    // The pattern guarantees 7–15 digits (a leading `+` is the only non-digit).
    const digits = match.replace(/\D/g, "");
    const visible = digits.slice(-2);
    return `${"*".repeat(digits.length - 2)}${visible}`;
  });
}

/**
 * Redact a single string: blank out any known secret values, then mask any
 * MSISDN-like runs. `split/join` is used for secret replacement so that a
 * secret containing regex metacharacters is treated literally.
 */
function redactString(input: string, secrets: readonly string[]): string {
  let result = input;
  for (const secret of secrets) {
    // split/join replaces all occurrences and treats the secret literally
    // (no regex metacharacter risk). A no-op when the secret is absent.
    result = result.split(secret).join(SECRET_MASK);
  }
  return maskMsisdns(result);
}

/**
 * Recursively redact an arbitrary value. Returns a new, safe-to-log value.
 *
 * @param value   - Any value (string/number/object/array/…).
 * @param secrets - Known secret strings (e.g. apiKey, username) to blank out.
 */
export function redact(value: unknown, secrets: readonly string[] = []): unknown {
  const cleanSecrets = secrets.filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  return redactInternal(value, cleanSecrets, new WeakSet<object>(), 0);
}

function redactInternal(
  value: unknown,
  secrets: readonly string[],
  seen: WeakSet<object>,
  depth: number,
): unknown {
  if (value === null || value === undefined) return value;

  switch (typeof value) {
    case "string":
      return redactString(value, secrets);
    case "number":
      return redactNumber(value);
    case "bigint":
      return maskMsisdns(value.toString());
    case "boolean":
      return value;
    case "function":
      return "[Function]";
    case "symbol":
      return "[Symbol]";
    default:
      break;
  }

  // typeof === "object" (narrowed by the switch above; null already handled)
  const obj = value;
  if (seen.has(obj)) return "[Circular]";
  if (depth >= MAX_DEPTH) return "[MaxDepth]";
  seen.add(obj);

  if (Array.isArray(obj)) {
    return (obj as unknown[]).map((item) =>
      redactInternal(item, secrets, seen, depth + 1),
    );
  }

  if (obj instanceof Error) {
    return { name: obj.name, message: redactString(obj.message, secrets) };
  }

  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    // Never copy prototype-polluting keys into the redacted output (T-E2).
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    const child = (obj as Record<string, unknown>)[key];
    out[key] = redactInternal(child, secrets, seen, depth + 1);
  }
  return out;
}

/**
 * Numbers are masked only when they look like an MSISDN-length integer, so
 * ordinary values (status codes, small counts) survive for debugging while a
 * phone number logged as a number is still masked (NFR-SEC-4).
 */
function redactNumber(n: number): unknown {
  if (Number.isInteger(n) && /^\d{7,15}$/.test(String(n))) {
    return maskMsisdns(String(n));
  }
  return n;
}

/**
 * Wrap a real logging sink so every message and metadata object is redacted
 * before it is written (NFR-SEC-2, NFR-SEC-4, ADR-013).
 *
 * The client passes its known secrets (apiKey, username) as `secrets` so they
 * are blanked even if they accidentally end up in a log string.
 *
 * @param sink    - The consumer-provided logger to forward redacted output to.
 * @param secrets - Known secret strings to blank out (e.g. [apiKey, username]).
 */
export function createRedactingLogger(
  sink: Logger,
  secrets: readonly string[] = [],
): Logger {
  const clean = secrets.filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );

  const forward =
    (emit: (message: string, meta?: object) => void) =>
    (message: string, meta?: object): void => {
      const safeMessage = redactString(message, clean);
      if (meta === undefined) {
        emit(safeMessage);
      } else {
        emit(safeMessage, redact(meta, clean) as object);
      }
    };

  return {
    debug: forward(sink.debug.bind(sink)),
    info: forward(sink.info.bind(sink)),
    warn: forward(sink.warn.bind(sink)),
    error: forward(sink.error.bind(sink)),
  };
}
