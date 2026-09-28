/**
 * EvinaClient — the server SDK entry point.
 *
 * M4 implements the constructor and `getScript`. `checkTransaction`,
 * `notifyTransaction`, and `createTestSession` arrive in later milestones.
 *
 * Security posture:
 *  - The API key is sent ONLY as the `X-EVINA-APIKEY` header (ADR-002); it is
 *    never placed in a URL, body, or log.
 *  - All logging goes through a redacting wrapper seeded with the known secrets
 *    (apiKey, username) so nothing sensitive can leak (NFR-SEC-2, ADR-013).
 *  - `user_id` is never logged and is transformed via `userIdTransform` before
 *    being sent (ADR-008, NFR-SEC-4).
 */

import {
  resolveConfig,
  CLOUDFLARE_BASE_URL,
  type EvinaConfig,
  type ResolvedConfig,
} from "./config.js";
import { httpPostForm, httpGetJson } from "./transport.js";
import { signQuery } from "./sign.js";
import {
  EvinaScriptError,
  EvinaTransportError,
  EvinaTestSessionError,
} from "./errors.js";
import { createRedactingLogger, type Logger } from "./redact.js";
import { TOKEN_TTL_MS } from "./store.js";
import { evaluateVerdict } from "./verdict.js";
import {
  assertValidTransactionId,
  generateTransactionId,
} from "./ti.js";
import type {
  GetScriptInput,
  GetScriptResult,
  ArgKey,
  CheckInput,
  Verdict,
  NotifyInput,
  TestSession,
  PurchaseArgKey,
} from "./types.js";

const PURCHASE_ARG_KEYS: readonly PurchaseArgKey[] = [
  "purchase_arg1",
  "purchase_arg2",
  "purchase_arg3",
  "purchase_arg4",
  "purchase_arg5",
];

const ARG_KEYS: readonly ArgKey[] = [
  "arg1",
  "arg2",
  "arg3",
  "arg4",
  "arg5",
  "arg6",
  "arg7",
  "arg8",
  "arg9",
  "arg10",
];

export class EvinaClient {
  private readonly config: ResolvedConfig;
  private readonly logger: Logger;

  /**
   * @param config - Explicit configuration. Validated eagerly; invalid config
   *   throws {@link EvinaConfigError} at construction (FR-1, FR-4).
   */
  constructor(config: EvinaConfig) {
    this.config = resolveConfig(config);
    // Wrap the (possibly consumer-provided) logger so secrets/PII are redacted
    // even if they ever reach a log call (NFR-SEC-2, ADR-013). Seed ALL secrets
    // — apiKey, username, and (v1) password — so none can leak.
    this.logger = createRedactingLogger(this.config.logger, [
      this.config.apiKey,
      this.config.username,
      ...(this.config.password !== undefined ? [this.config.password] : []),
    ]);
  }

  /**
   * Perform an authenticated EVINA web-service call, dispatching on the
   * configured auth mode (ADR-002 v2 default / ADR-015 v1 opt-in):
   *
   *  - v2-apikey: `POST <baseUrl><path>` with `X-EVINA-APIKEY` header and a
   *    form-encoded body.
   *  - v1-signature: `GET <baseUrl>/{username}<path>?<params>&s=<signature>`,
   *    signature = SHA-256(username + queryString + password). No API key.
   *
   * `path` is the v1-style suffix WITHOUT the leading `/v1` for v1 mode; both
   * modes are handled here so callers pass a single logical endpoint.
   *
   * @param endpoint - one of "script" | "check" | "transaction" | "test_session"
   * @param params   - request parameters (without auth material)
   * @param baseUrl  - base URL to use (allows the Cloudflare override for script)
   */
  private async evinaCall(
    endpoint: "script" | "check" | "transaction" | "test_session",
    params: Record<string, string>,
    baseUrl: string,
  ): Promise<unknown> {
    const base = baseUrl.replace(/\/+$/, "");

    if (this.config.authMode === "v1-signature") {
      // v1: GET /{username}/<endpoint>?<params>&s=<sig>
      // NO API-key header — v1 authenticates purely via the signature, exactly
      // like the verified probe. Sending X-EVINA-APIKEY alongside a signed v1
      // request can make EVINA evaluate the wrong auth path and reject it.
      const password = this.config.password ?? "";
      const signedQuery = signQuery(params, this.config.username, password);
      const url = `${base}/${encodeURIComponent(this.config.username)}/${endpoint}?${signedQuery}`;
      return httpGetJson(url, {
        headers: {},
        timeoutMs: this.config.timeoutMs,
      });
    }

    // v2: POST /v1/<endpoint> with the API key header + form body.
    const url = `${base}/v1/${endpoint}`;
    return httpPostForm(url, params, {
      headers: { "X-EVINA-APIKEY": this.config.apiKey },
      timeoutMs: this.config.timeoutMs,
    });
  }

  /**
   * Retrieve the EVINA JS kit for a transaction (`POST /v1/script`).
   *
   * Generates/validates `ti`, builds the params, applies `userIdTransform`,
   * calls EVINA, parses `{t,s,success,e}`, persists `{ti,token,country,
   * createdAt,expiresAt}` (6h TTL), and returns the kit (FR-5/6/9/10/11/12).
   */
  async getScript(input: GetScriptInput): Promise<GetScriptResult> {
    if (typeof input.targetSelector !== "string" || input.targetSelector.trim().length === 0) {
      throw new TypeError("targetSelector (te) is required and must be a non-empty string");
    }

    // --- Transaction id (FR-5) ---
    let ti: string;
    if (input.transactionId !== undefined) {
      assertValidTransactionId(input.transactionId);
      ti = input.transactionId;
    } else {
      ti = generateTransactionId();
    }

    // --- Country is mandatory for /script (FR-9) ---
    const country = input.country ?? this.config.defaultCountry;
    if (country === undefined || country.length === 0) {
      throw new TypeError(
        "country is required for getScript (provide input.country or config.defaultCountry)",
      );
    }

    // --- pl is Phase 2 (transparent gateway): accepted but not sent (FR-9) ---
    if (input.permissionList !== undefined) {
      this.logger.debug(
        "getScript: permissionList ignored (transparent-gateway is Phase 2)",
        { ti },
      );
    }

    const tsSeconds = Math.floor(Date.now() / 1000);
    const params = buildScriptParams(input, this.config, { ti, country, tsSeconds });
    // /script may use the Cloudflare mirror (v2 only); v1 uses the base URL.
    const scriptBase =
      this.config.authMode === "v2-apikey" && this.config.useCloudflareForScript
        ? CLOUDFLARE_BASE_URL
        : this.config.baseUrl;

    // --- Call EVINA (auth mode dispatched inside evinaCall) ---
    let raw: unknown;
    try {
      raw = await this.evinaCall("script", params, scriptBase);
    } catch (err) {
      // FR-11: a non-200 HTTP status surfaces as a typed EvinaScriptError.
      // Network/timeout/SSRF/parse failures remain EvinaTransportError.
      if (
        err instanceof EvinaTransportError &&
        err.statusCode !== undefined &&
        err.statusCode !== 200
      ) {
        throw new EvinaScriptError(`EVINA /script returned HTTP ${err.statusCode}`);
      }
      throw err;
    }

    // --- Parse response (FR-11) ---
    const { token, script } = parseScriptResponse(raw);

    // --- Persist transaction context (FR-6) ---
    const createdAt = Date.now();
    await this.config.store.save({
      ti,
      token,
      country,
      createdAt,
      expiresAt: createdAt + TOKEN_TTL_MS,
    });

    this.logger.info("getScript ok", { ti, country });

    return { transactionId: ti, token, script, raw };
  }

  /**
   * Compute the fraud verdict for a transaction (`POST /v1/check`).
   *
   * Loads the stored context by `ti` (FR-7), applies the SAME `userIdTransform`
   * as `/script` (FR-13, ADR-008), calls EVINA, and maps `{success,ft,as,oo,e}`
   * to a {@link Verdict} (FR-14/15/17). Unknown/expired `ti` (FR-8) and
   * infrastructure failures (FR-16) are resolved by the fail-open/closed policy
   * (ADR-009); every fail-open is logged at warn level, PII-safe.
   */
  async checkTransaction(input: CheckInput): Promise<Verdict> {
    // Invalid ti is a caller error, not an infra failure — surface it directly.
    assertValidTransactionId(input.transactionId);
    const ti = input.transactionId;

    // --- FR-7 / FR-8: load stored context; unknown or expired → policy ---
    const stored = await this.config.store.get(ti);
    if (stored === null) {
      return this.policyVerdict(ti, "unknown or expired transaction");
    }

    // owner is Phase 2 (transparent gateway): accepted but not sent (FR-13).
    if (input.owner !== undefined) {
      this.logger.debug(
        "checkTransaction: owner ignored (transparent-gateway is Phase 2)",
        { ti },
      );
    }

    // Country resolved consistently: explicit → stored → config default (FR-7).
    const country = input.country ?? stored.country ?? this.config.defaultCountry;
    if (country === undefined || country.length === 0) {
      throw new TypeError(
        "country is required for checkTransaction (none supplied, stored, or configured)",
      );
    }

    const tsSeconds = Math.floor(Date.now() / 1000);
    const params = buildCheckParams(input, this.config, { ti, country, tsSeconds });

    let raw: unknown;
    try {
      raw = await this.evinaCall("check", params, this.config.baseUrl);
    } catch (err) {
      // FR-16: non-200 / non-JSON / timeout / network → fail-open/closed policy.
      if (err instanceof EvinaTransportError) {
        return this.policyVerdict(ti, err.message, err.statusCode);
      }
      // Defensive: httpPostForm only ever throws EvinaTransportError, so this
      // rethrow is unreachable in practice — kept for safety.
      /* v8 ignore next */
      throw err;
    }

    const verdict = evaluateVerdict(raw);
    this.logger.info("checkTransaction verdict", {
      ti,
      allowed: verdict.allowed,
      ft: verdict.ft,
      category: verdict.category,
    });
    return verdict;
  }

  /**
   * Create a test session that forces a chosen `ft` on the next `/check`
   * (`POST /v1/test_session`), enabling deterministic allow/block testing
   * without real fraud (FR-19, EVINA_API_FACTS §11).
   *
   * @param ft - The fraud code to force. Must be an integer.
   * @returns `{etsid, ft, username}`; append the `etsid` to the page URL via
   *   {@link withEtsid}.
   * @throws {TypeError} if `ft` is not an integer.
   * @throws {EvinaTestSessionError} on a failed/malformed EVINA response.
   * @throws {EvinaTransportError} on an infrastructure failure.
   */
  async createTestSession(ft: number): Promise<TestSession> {
    if (typeof ft !== "number" || !Number.isInteger(ft)) {
      throw new TypeError("ft must be an integer");
    }
    // The EVINA test_session endpoint requires the v1 SIGNATURE even in its
    // "v2" documentation (its mandatory params include `s`, and the URL uses the
    // /{username}/test_session path). It therefore only works in v1-signature
    // mode. A v2-apikey POST returns HTTP 405 / invalid-signature.
    if (this.config.authMode !== "v1-signature") {
      throw new EvinaTestSessionError(
        "createTestSession requires authMode 'v1-signature' (the test_session " +
          "endpoint is signature-based; API-key-only auth is not supported by EVINA here)",
      );
    }

    const tsSeconds = Math.floor(Date.now() / 1000);
    // v1 signature path: GET /{username}/test_session?ft=..&ts=..&s=..
    // (username is in the URL path, not a query param). evinaCall signs it.
    const raw = await this.evinaCall(
      "test_session",
      { ft: String(ft), ts: String(tsSeconds) },
      this.config.baseUrl,
    );
    const session = parseTestSession(raw);
    this.logger.info("createTestSession ok", { etsid: session.etsid, ft: session.ft });
    return session;
  }

  /**
   * Notify EVINA that the user was actually charged (`POST /v1/transaction`,
   * FR-18). Best-effort: this NEVER throws — any failure (validation, network,
   * HTTP) is logged at warn level and swallowed, so it can never break the
   * consumer's billing path (NFR-REL-3).
   */
  async notifyTransaction(input: NotifyInput): Promise<void> {
    const ti = input.transactionId;
    try {
      assertValidTransactionId(ti);
      const tsSeconds = Math.floor(Date.now() / 1000);
      const params = buildNotifyParams(input, this.config, tsSeconds);
      await this.evinaCall("transaction", params, this.config.baseUrl);
      this.logger.info("notifyTransaction ok", { ti });
    } catch (err) {
      const cause = err instanceof Error ? err.message : "unknown error";
      this.logger.warn("notifyTransaction failed (ignored)", { ti, cause });
    }
  }

  /**
   * Build a verdict from the fail-open/closed policy (FR-16, ADR-009).
   * Fail-open (default) allows the transaction; fail-closed blocks it. Every
   * fail-open is logged at warn level with only PII-safe fields.
   */
  private policyVerdict(ti: string, cause: string, statusCode?: number): Verdict {
    const base = {
      ft: null,
      category: "unknown" as const,
      authenticityScore: null,
      opinion: null as 0 | 1 | null,
      success: false,
      raw: null,
    };
    if (this.config.failOpen) {
      this.logger.warn("checkTransaction fail-open", { ti, cause, statusCode });
      return { ...base, allowed: true, reason: `fail-open: ${cause}`, failOpen: true };
    }
    return { ...base, allowed: false, reason: `fail-closed: ${cause}`, failOpen: false };
  }
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit testing; not part of the public index)
// ---------------------------------------------------------------------------

/**
 * Build the `application/x-www-form-urlencoded` params for `/v1/script`
 * (FR-9, FR-10, FR-12). Only present optionals are included. `pl` is
 * intentionally omitted (Phase 2). Percent-encoding is handled by the
 * transport via `URLSearchParams`.
 */
export function buildScriptParams(
  input: GetScriptInput,
  config: Pick<ResolvedConfig, "defaultCarrier" | "userIdTransform">,
  fixed: { ti: string; country: string; tsSeconds: number },
): Record<string, string> {
  const params: Record<string, string> = {
    ti: fixed.ti,
    te: input.targetSelector,
    ts: String(fixed.tsSeconds),
    country: fixed.country,
  };

  const carrier = input.carrier ?? config.defaultCarrier;
  if (carrier !== undefined) params["carrier"] = carrier;
  if (input.service !== undefined) params["service"] = input.service;
  // ADR-008: transform user_id before sending; raw value never leaves as-is
  // unless the (default identity) transform returns it unchanged.
  if (input.userId !== undefined) params["user_id"] = config.userIdTransform(input.userId);
  if (input.purchaseId !== undefined) params["purchase_id"] = input.purchaseId;
  if (input.tck !== undefined) params["tck"] = input.tck;
  if (input.cjv !== undefined) params["cjv"] = String(input.cjv);

  if (input.args !== undefined) {
    for (const key of ARG_KEYS) {
      const value = input.args[key];
      if (value !== undefined) params[key] = value;
    }
  }

  return params;
}

/**
 * Build the params for `/v1/check` (FR-13). `/check` takes `ti,ts,country`
 * (+ `owner` in Phase 2) plus the same optionals as `/script` except the
 * page-only fields (`te`,`tck`,`cjv`,`pl`). The SAME `userIdTransform` is
 * applied to `user_id` (ADR-008). `owner` is intentionally omitted (Phase 2).
 */
export function buildCheckParams(
  input: CheckInput,
  config: Pick<ResolvedConfig, "defaultCarrier" | "userIdTransform">,
  fixed: { ti: string; country: string; tsSeconds: number },
): Record<string, string> {
  const params: Record<string, string> = {
    ti: fixed.ti,
    ts: String(fixed.tsSeconds),
    country: fixed.country,
  };

  const carrier = input.carrier ?? config.defaultCarrier;
  if (carrier !== undefined) params["carrier"] = carrier;
  if (input.service !== undefined) params["service"] = input.service;
  if (input.userId !== undefined) params["user_id"] = config.userIdTransform(input.userId);
  if (input.purchaseId !== undefined) params["purchase_id"] = input.purchaseId;

  if (input.args !== undefined) {
    for (const key of ARG_KEYS) {
      const value = input.args[key];
      if (value !== undefined) params[key] = value;
    }
  }

  return params;
}

/**
 * Append `?etsid=<value>` to a protected-page URL so the next `/check` returns
 * the forced `ft` from a test session (FR-20, EVINA_API_FACTS §11).
 *
 * @param pageUrl - Absolute URL of the protected page.
 * @param etsid   - Test session id from {@link EvinaClient.createTestSession}.
 * @throws {TypeError} if `pageUrl` is not a valid absolute URL.
 */
export function withEtsid(pageUrl: string, etsid: string): string {
  let url: URL;
  try {
    url = new URL(pageUrl);
  } catch {
    throw new TypeError("withEtsid: pageUrl must be a valid absolute URL");
  }
  url.searchParams.set("etsid", etsid);
  return url.toString();
}

/**
 * Build params for `/v1/transaction` (FR-18). `ti`+`ts` are top-level; all
 * other fields are packed into the `d` JSON object (percent-encoded by the
 * transport). `msisdn` passes through `userIdTransform` (ADR-008). `d` is
 * omitted entirely when no optional fields are supplied.
 */
export function buildNotifyParams(
  input: NotifyInput,
  config: Pick<ResolvedConfig, "defaultCarrier" | "userIdTransform">,
  tsSeconds: number,
): Record<string, string> {
  const params: Record<string, string> = {
    ti: input.transactionId,
    ts: String(tsSeconds),
  };

  const d: Record<string, string> = {};
  if (input.purchaseId !== undefined) d["purchase_id"] = input.purchaseId;
  if (input.msisdn !== undefined) d["msisdn"] = config.userIdTransform(input.msisdn);
  const carrier = input.carrier ?? config.defaultCarrier;
  if (carrier !== undefined) d["carrier"] = carrier;
  if (input.country !== undefined) d["country"] = input.country;
  if (input.service !== undefined) d["service"] = input.service;
  if (input.purchaseArgs !== undefined) {
    for (const key of PURCHASE_ARG_KEYS) {
      const value = input.purchaseArgs[key];
      if (value !== undefined) d[key] = value;
    }
  }

  if (Object.keys(d).length > 0) {
    params["d"] = JSON.stringify(d);
  }
  return params;
}

/**
 * Defensively parse a `/v1/test_session` response into a {@link TestSession}
 * (FR-19), throwing a secret-free {@link EvinaTestSessionError} on failure.
 */
export function parseTestSession(raw: unknown): TestSession {
  if (typeof raw !== "object" || raw === null) {
    throw new EvinaTestSessionError(
      "EVINA /test_session returned an unexpected (non-object) response",
    );
  }
  const body = raw as Record<string, unknown>;

  const etsid = body["etsid"];
  if (typeof etsid !== "string" || etsid.length === 0) {
    const codes = extractErrorCodes(body["e"]);
    throw new EvinaTestSessionError(
      codes.length > 0
        ? `EVINA /test_session failed: ${codes.join(", ")}`
        : "EVINA /test_session failed",
      codes,
    );
  }

  const ft = body["ft"];
  const username = body["username"];
  if (typeof ft !== "number" || !Number.isInteger(ft) || typeof username !== "string") {
    throw new EvinaTestSessionError(
      "EVINA /test_session response missing ft or username",
    );
  }

  return { etsid, ft, username };
}

interface ParsedScript {
  token: string;
  script: string;
}

/**
 * Defensively parse an EVINA `/script` response (`{t,s,success,e}`), throwing a
 * secret-free {@link EvinaScriptError} on logical failure (FR-11, NFR-SEC-2,
 * T-E2).
 */
export function parseScriptResponse(raw: unknown): ParsedScript {
  if (typeof raw !== "object" || raw === null) {
    throw new EvinaScriptError("EVINA /script returned an unexpected (non-object) response");
  }
  const body = raw as Record<string, unknown>;

  if (body["success"] === false) {
    const codes = extractErrorCodes(body["e"]);
    throw new EvinaScriptError(
      codes.length > 0 ? `EVINA /script failed: ${codes.join(", ")}` : "EVINA /script failed",
      codes,
    );
  }

  const token = body["t"];
  const script = body["s"];
  if (typeof token !== "string" || token.length === 0 || typeof script !== "string") {
    throw new EvinaScriptError("EVINA /script response missing token (t) or script (s)");
  }

  return { token, script };
}

/** Extract string error codes from an EVINA `e` field, ignoring non-strings. */
function extractErrorCodes(e: unknown): string[] {
  if (!Array.isArray(e)) return [];
  return (e as unknown[]).filter((x): x is string => typeof x === "string");
}
