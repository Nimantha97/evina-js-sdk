/**
 * Transport layer for the EVINA server SDK.
 *
 * Provides a single function, `httpPostForm`, that sends an
 * `application/x-www-form-urlencoded` POST to an EVINA endpoint and returns
 * the parsed JSON body.
 *
 * Security controls implemented here (all required before any EVINA call):
 *
 *  NFR-SEC-6 / T-T2 / T-E1
 *    - HTTPS-only: rejects any URL whose protocol is not `https:`.
 *    - Host allow-list (pinning): only the two documented EVINA hostnames are
 *      accepted; arbitrary hosts (including redirects) are rejected to prevent
 *      SSRF.
 *    - Redirects: `fetch` is called with `redirect: "error"` so the runtime
 *      never silently follows a redirect to an attacker-controlled host.
 *
 *  NFR-SEC-8 / T-D1
 *    - Timeout: every request is wrapped in an `AbortController`; the signal
 *      is cancelled after `timeoutMs` milliseconds.
 *    - Response size cap: the response body is read as text and rejected if it
 *      exceeds `maxBytes` before JSON parsing, preventing memory exhaustion
 *      from a slow-loris or oversized-response attack.
 *
 *  FR-10
 *    - Percent-encoding: parameter values are encoded via `URLSearchParams`
 *      which applies RFC-3986 percent-encoding (e.g. `#` → `%23`).
 *
 *  ADR-002
 *    - The `X-EVINA-APIKEY` header is set by the caller (EvinaClient); this
 *      layer only enforces the structural security constraints.
 *
 *  ADR-006
 *    - Zero runtime dependencies: uses native `fetch`, `AbortController`, and
 *      `URLSearchParams` (all available in Node ≥ 20, ADR-005).
 *
 *  NFR-SEC-2 / T-I1
 *    - Error messages never embed the API key or raw MSISDNs. The caller is
 *      responsible for not passing secrets as URL path segments.
 */

import { EvinaTransportError } from "./errors.js";

// ---------------------------------------------------------------------------
// Host allow-list (NFR-SEC-6, T-T2, T-E1)
// ---------------------------------------------------------------------------

/**
 * The two documented EVINA base hostnames (EVINA_API_FACTS.md §3).
 * Only these are permitted as the target host for any outbound call.
 */
export const ALLOWED_EVINA_HOSTS = new Set([
  "api.dcbprotect.com",
  "api.clfldcbprotect.com",
]);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface HttpPostFormOptions {
  /** Request headers (must include X-EVINA-APIKEY and Content-Type). */
  headers: Record<string, string>;
  /** Abort the request after this many milliseconds. Default: 10 000. */
  timeoutMs?: number;
  /** Reject the response body if it exceeds this many bytes. Default: 1 MiB. */
  maxBytes?: number;
}

// ---------------------------------------------------------------------------
// Internal defaults
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 1_048_576; // 1 MiB — generous for EVINA JSON payloads

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

/** Options for {@link httpGetJson}. */
export interface HttpGetJsonOptions {
  headers: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
}

/**
 * Send a GET request to `url` (with any query string already appended) and
 * return the parsed JSON body.
 *
 * Used for `/v1/test_session`, which the live EVINA API serves over **GET**
 * (confirmed against the real API: a POST returns HTTP 405 Method Not Allowed).
 *
 * @throws {EvinaTransportError} on HTTPS/host violation, timeout, non-200,
 *   oversized body, or JSON parse failure.
 */
export async function httpGetJson(
  url: string,
  options: HttpGetJsonOptions,
): Promise<unknown> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

  validateEvinaUrl(url);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: options.headers,
      redirect: "error",
      signal: controller.signal,
    });
  } catch (cause) {
    clearTimeout(timer);
    if (controller.signal.aborted) {
      throw new EvinaTransportError(`EVINA request timed out after ${timeoutMs}ms`);
    }
    const msg = cause instanceof Error ? cause.message : "network error";
    throw new EvinaTransportError(`EVINA request failed: ${msg}`);
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new EvinaTransportError(`EVINA returned HTTP ${response.status}`, response.status);
  }

  const text = await readBodyCapped(response, maxBytes);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new EvinaTransportError("EVINA response is not valid JSON", response.status);
  }
}

/**
 * Send a percent-encoded form POST to `url` and return the parsed JSON body.
 *
 * @param url     - Full HTTPS URL of the EVINA endpoint.
 * @param params  - Key/value pairs to encode as `application/x-www-form-urlencoded`.
 * @param options - Headers, timeout, and size cap.
 * @returns       Parsed JSON (typed as `unknown`; callers must type-guard).
 *
 * @throws {EvinaTransportError} on HTTPS/host violation, timeout, non-200,
 *   oversized body, or JSON parse failure.
 */
export async function httpPostForm(
  url: string,
  params: Record<string, string>,
  options: HttpPostFormOptions,
): Promise<unknown> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

  // --- Security: validate URL before any network activity ---
  validateEvinaUrl(url);

  // --- Encode body (FR-10, percent-encoding via URLSearchParams) ---
  const body = new URLSearchParams(params).toString();

  // --- Timeout via AbortController (NFR-SEC-8, T-D1) ---
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        ...options.headers,
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body, "utf8")),
      },
      body,
      // Never follow redirects to arbitrary hosts (NFR-SEC-6, T-E1).
      redirect: "error",
      signal: controller.signal,
    });
  } catch (cause) {
    clearTimeout(timer);
    if (controller.signal.aborted) {
      throw new EvinaTransportError(
        `EVINA request timed out after ${timeoutMs}ms`,
      );
    }
    // Redirect-error or network failure.
    const msg =
      cause instanceof Error ? cause.message : "network error";
    throw new EvinaTransportError(`EVINA request failed: ${msg}`);
  } finally {
    clearTimeout(timer);
  }

  // --- Non-200 response (FR-11, FR-16) ---
  if (!response.ok) {
    throw new EvinaTransportError(
      `EVINA returned HTTP ${response.status}`,
      response.status,
    );
  }

  // --- Response size cap (NFR-SEC-8, T-D1) ---
  const text = await readBodyCapped(response, maxBytes);

  // --- JSON parse guard (T-E2) ---
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new EvinaTransportError(
      "EVINA response is not valid JSON",
      response.status,
    );
  }

  return parsed;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Validate that `rawUrl` is HTTPS and targets an allowed EVINA host.
 *
 * Throws `EvinaTransportError` (not `EvinaConfigError`) because this check
 * runs at call-time; config-level HTTPS validation is M2's responsibility.
 *
 * Exported for unit testing.
 */
export function validateEvinaUrl(rawUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new EvinaTransportError(`Invalid EVINA URL: ${rawUrl}`);
  }

  if (parsed.protocol !== "https:") {
    throw new EvinaTransportError(
      `EVINA URL must use HTTPS (got "${parsed.protocol}")`,
    );
  }

  if (!ALLOWED_EVINA_HOSTS.has(parsed.hostname)) {
    throw new EvinaTransportError(
      `EVINA host "${parsed.hostname}" is not in the allow-list`,
    );
  }
}

/**
 * Read the response body as text, aborting if it exceeds `maxBytes`.
 *
 * Uses the streaming `ReadableStream` API so we never buffer more than
 * `maxBytes` + one chunk in memory (NFR-SEC-8).
 */
async function readBodyCapped(
  response: Response,
  maxBytes: number,
): Promise<string> {
  // Fast path: if Content-Length is present and already over the cap, reject
  // immediately without reading the body.
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const declared = parseInt(contentLength, 10);
    if (!isNaN(declared) && declared > maxBytes) {
      throw new EvinaTransportError(
        `EVINA response body too large (Content-Length: ${declared}, cap: ${maxBytes})`,
        response.status,
      );
    }
  }

  if (response.body === null) {
    return "";
  }

  // Cast to the concrete reader type so TypeScript can narrow the discriminated
  // union returned by .read() without unsafe-member-access errors.
  const reader = response.body.getReader() as {
    read(): Promise<{ done: true; value?: undefined } | { done: false; value: Uint8Array }>;
    releaseLock(): void;
  };
  const decoder = new TextDecoder();
  let result = "";
  let bytesRead = 0;

  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;

      bytesRead += chunk.value.byteLength;
      if (bytesRead > maxBytes) {
        throw new EvinaTransportError(
          `EVINA response body exceeded size cap of ${maxBytes} bytes`,
          response.status,
        );
      }
      result += decoder.decode(chunk.value, { stream: true });
    }
    // Flush any remaining bytes in the decoder.
    result += decoder.decode();
  } finally {
    reader.releaseLock();
  }

  return result;
}
