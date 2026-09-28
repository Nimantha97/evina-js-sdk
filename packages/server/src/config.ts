/**
 * Configuration types, validation, defaults, and the opt-in env helper.
 *
 * Requirements covered:
 *   FR-1   The server SDK is constructed with an explicit `EvinaConfig`.
 *   FR-2   Required: apiKey, username. Optional fields have documented defaults.
 *   FR-3   The core never reads `process.env` implicitly; `configFromEnv()` is
 *          an OPT-IN helper that takes the environment as an argument (ADR-012).
 *   FR-4   Invalid config fails fast at construction with a clear, secret-free
 *          error (NFR-SEC-2).
 *   NFR-SEC-6  `baseUrl` must be HTTPS and pinned to an allowed EVINA host.
 *
 * Secret-safety: no validation error message ever embeds the apiKey/username
 * VALUE — only the field name (NFR-SEC-2, T-I1).
 */

import { EvinaConfigError } from "./errors.js";
import { ALLOWED_EVINA_HOSTS } from "./transport.js";
import { NOOP_LOGGER, type Logger } from "./redact.js";
import { InMemoryTransactionStore } from "./store.js";
import type { TransactionStore } from "./types.js";

// ---------------------------------------------------------------------------
// Defaults (FR-2) — exported so consumers/tests can reference them.
// ---------------------------------------------------------------------------

/** Default EVINA base URL (EVINA_API_FACTS.md §3). */
export const DEFAULT_BASE_URL = "https://api.dcbprotect.com";
/** Cloudflare mirror, opt-in via `useCloudflareForScript` (EVINA_API_FACTS.md §3). */
export const CLOUDFLARE_BASE_URL = "https://api.clfldcbprotect.com";
/** Default network timeout (NFR-PERF-1). */
export const DEFAULT_TIMEOUT_MS = 10_000;
/** Default retries — 0 for idempotency caution (ADR-009 / SRS §4.1). */
export const DEFAULT_RETRIES = 0;
/** Default verdict policy on infra errors — fail-open (ADR-009). */
export const DEFAULT_FAIL_OPEN = true;

// Bounds for validation.
const MIN_TIMEOUT_MS = 1;
const MAX_TIMEOUT_MS = 120_000; // 2 minutes hard ceiling
const MIN_RETRIES = 0;
const MAX_RETRIES = 5;
const MAX_CREDENTIAL_LEN = 4096; // guards against absurd inputs (NFR-SEC-7)

// ---------------------------------------------------------------------------
// Public config type (SRS §4.1)
// ---------------------------------------------------------------------------

/**
 * Explicit configuration object for {@link EvinaClient} (FR-1).
 */
/**
 * EVINA authentication method.
 *  - `"v2-apikey"` (default, recommended — ADR-002): POST with `X-EVINA-APIKEY`.
 *  - `"v1-signature"` (opt-in, ADR-015): GET `/{username}/<ep>` with a computed
 *    `s` signature. For legacy accounts provisioned for v1 only.
 */
export type EvinaAuthMode = "v2-apikey" | "v1-signature";

export interface EvinaConfig {
  /**
   * EVINA API key — SECRET, server-side only (ADR-004).
   * Required for `authMode: "v2-apikey"` (the default). May be omitted only when
   * `authMode: "v1-signature"` is used (which authenticates via signature).
   */
  apiKey?: string;
  /** DCB account username (owner). Treated as a secret for logging (NFR-SEC-2). */
  username: string;
  /**
   * Authentication method. Default `"v2-apikey"` (ADR-002). Set to
   * `"v1-signature"` for legacy accounts that require signature auth (ADR-015).
   */
  authMode?: EvinaAuthMode;
  /**
   * EVINA v1 signature secret (a.k.a. "password") — SECRET, server-side only.
   * Required when `authMode: "v1-signature"`; ignored for v2.
   */
  password?: string;
  /** Override base URL; must be HTTPS + an allowed EVINA host. Default {@link DEFAULT_BASE_URL}. */
  baseUrl?: string;
  /** Use the Cloudflare mirror for `/v1/script`. Default false. */
  useCloudflareForScript?: boolean;
  /** Default ISO-3166 alpha-2 country, e.g. "LK". */
  defaultCountry?: string;
  /** Default MCC-MNC carrier, e.g. "41302". */
  defaultCarrier?: string;
  /** Network timeout in ms. Default {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** Retry count for transport. Default {@link DEFAULT_RETRIES}. */
  retries?: number;
  /** Fail-open on infra errors. Default {@link DEFAULT_FAIL_OPEN} (ADR-009). */
  failOpen?: boolean;
  /** Optional one-way transform applied to user_id on BOTH /script and /check (ADR-008). */
  userIdTransform?: (raw: string) => string;
  /** Structured logger. Default {@link NOOP_LOGGER} (ADR-013). */
  logger?: Logger;
  /** Transaction store. Default {@link InMemoryTransactionStore} (ADR-007, FR-25). */
  store?: TransactionStore;
}

/**
 * Fully-resolved configuration with all defaults applied. Produced by
 * {@link resolveConfig}; this is the internal shape the client will consume.
 */
export interface ResolvedConfig {
  apiKey: string;
  username: string;
  authMode: EvinaAuthMode;
  password: string | undefined;
  baseUrl: string;
  useCloudflareForScript: boolean;
  defaultCountry: string | undefined;
  defaultCarrier: string | undefined;
  timeoutMs: number;
  retries: number;
  failOpen: boolean;
  userIdTransform: (raw: string) => string;
  logger: Logger;
  store: TransactionStore;
}

// ---------------------------------------------------------------------------
// Validation (FR-4, NFR-SEC-6/7)
// ---------------------------------------------------------------------------

/**
 * Validate an {@link EvinaConfig}, throwing {@link EvinaConfigError} on the
 * first problem. Error messages contain field names only — never secret values
 * (NFR-SEC-2).
 */
export function validateConfig(config: EvinaConfig): void {
  if (typeof config !== "object" || config === null) {
    throw new EvinaConfigError("EvinaConfig must be an object");
  }

  const authMode: EvinaAuthMode = config.authMode ?? "v2-apikey";
  if (authMode !== "v2-apikey" && authMode !== "v1-signature") {
    throw new EvinaConfigError(
      'authMode must be "v2-apikey" or "v1-signature"',
    );
  }

  // username is always required (path in v1, account id in v2).
  requireCredential(config.username, "username");

  if (authMode === "v2-apikey") {
    // v2: API key is the credential; password is not used.
    requireCredential(config.apiKey, "apiKey");
  } else {
    // v1: signature is computed from username + password; apiKey is optional.
    requireCredential(config.password, "password");
  }

  if (config.baseUrl !== undefined) {
    validateBaseUrl(config.baseUrl);
  }

  if (config.defaultCountry !== undefined && !/^[A-Za-z]{2}$/.test(config.defaultCountry)) {
    throw new EvinaConfigError(
      "defaultCountry must be an ISO-3166 alpha-2 code (two letters)",
    );
  }

  if (config.defaultCarrier !== undefined && !/^\d{5,6}$/.test(config.defaultCarrier)) {
    throw new EvinaConfigError(
      "defaultCarrier must be an MCC-MNC value (5 or 6 digits)",
    );
  }

  if (config.timeoutMs !== undefined) {
    if (
      !Number.isInteger(config.timeoutMs) ||
      config.timeoutMs < MIN_TIMEOUT_MS ||
      config.timeoutMs > MAX_TIMEOUT_MS
    ) {
      throw new EvinaConfigError(
        `timeoutMs must be an integer between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`,
      );
    }
  }

  if (config.retries !== undefined) {
    if (
      !Number.isInteger(config.retries) ||
      config.retries < MIN_RETRIES ||
      config.retries > MAX_RETRIES
    ) {
      throw new EvinaConfigError(
        `retries must be an integer between ${MIN_RETRIES} and ${MAX_RETRIES}`,
      );
    }
  }

  if (config.failOpen !== undefined && typeof config.failOpen !== "boolean") {
    throw new EvinaConfigError("failOpen must be a boolean");
  }

  if (
    config.useCloudflareForScript !== undefined &&
    typeof config.useCloudflareForScript !== "boolean"
  ) {
    throw new EvinaConfigError("useCloudflareForScript must be a boolean");
  }

  if (config.userIdTransform !== undefined && typeof config.userIdTransform !== "function") {
    throw new EvinaConfigError("userIdTransform must be a function");
  }

  if (config.logger !== undefined && !isLogger(config.logger)) {
    throw new EvinaConfigError(
      "logger must implement debug/info/warn/error methods",
    );
  }

  if (config.store !== undefined && !isTransactionStore(config.store)) {
    throw new EvinaConfigError(
      "store must implement save/get/delete methods",
    );
  }
}

/** Require a non-empty, bounded credential string. Never echoes the value. */
function requireCredential(
  value: unknown,
  field: "apiKey" | "username" | "password",
): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new EvinaConfigError(`${field} is required and must be a non-empty string`);
  }
  if (value.length > MAX_CREDENTIAL_LEN) {
    throw new EvinaConfigError(`${field} exceeds the maximum allowed length`);
  }
}

/**
 * Validate `baseUrl`: HTTPS-only + pinned to an allowed EVINA host (NFR-SEC-6,
 * T-T2, T-E1). Reuses {@link ALLOWED_EVINA_HOSTS} so the config and transport
 * layers share a single source of truth for the host allow-list.
 */
function validateBaseUrl(baseUrl: string): void {
  if (typeof baseUrl !== "string" || baseUrl.trim().length === 0) {
    throw new EvinaConfigError("baseUrl must be a non-empty string");
  }
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new EvinaConfigError("baseUrl is not a valid URL");
  }
  if (url.protocol !== "https:") {
    throw new EvinaConfigError("baseUrl must use HTTPS");
  }
  if (!ALLOWED_EVINA_HOSTS.has(url.hostname)) {
    throw new EvinaConfigError(
      `baseUrl host "${url.hostname}" is not an allowed EVINA host`,
    );
  }
}

/** Structural check that a value satisfies the {@link Logger} interface. */
function isLogger(value: unknown): value is Logger {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate["debug"] === "function" &&
    typeof candidate["info"] === "function" &&
    typeof candidate["warn"] === "function" &&
    typeof candidate["error"] === "function"
  );
}

/** Structural check that a value satisfies the {@link TransactionStore} interface. */
function isTransactionStore(value: unknown): value is TransactionStore {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate["save"] === "function" &&
    typeof candidate["get"] === "function" &&
    typeof candidate["delete"] === "function"
  );
}

// ---------------------------------------------------------------------------
// Resolution (apply defaults) — FR-2
// ---------------------------------------------------------------------------

/**
 * Validate `config` and return a {@link ResolvedConfig} with all defaults
 * applied. This is the single place defaults are materialized.
 */
export function resolveConfig(config: EvinaConfig): ResolvedConfig {
  validateConfig(config);
  return {
    apiKey: config.apiKey ?? "",
    username: config.username,
    authMode: config.authMode ?? "v2-apikey",
    password: config.password,
    baseUrl: config.baseUrl ?? DEFAULT_BASE_URL,
    useCloudflareForScript: config.useCloudflareForScript ?? false,
    defaultCountry: config.defaultCountry,
    defaultCarrier: config.defaultCarrier,
    timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    retries: config.retries ?? DEFAULT_RETRIES,
    failOpen: config.failOpen ?? DEFAULT_FAIL_OPEN,
    userIdTransform: config.userIdTransform ?? ((raw) => raw),
    logger: config.logger ?? NOOP_LOGGER,
    store: config.store ?? new InMemoryTransactionStore(),
  };
}

// ---------------------------------------------------------------------------
// Env helper (opt-in) — FR-3, ADR-012
// ---------------------------------------------------------------------------

/**
 * Documented environment variable names consumed by {@link configFromEnv}.
 * Mirrors `.env.example`.
 */
export const ENV_VAR_NAMES = {
  apiKey: "EVINA_API_KEY",
  username: "EVINA_USERNAME",
  password: "EVINA_PASSWORD",
  authMode: "EVINA_AUTH_MODE",
  baseUrl: "EVINA_BASE_URL",
  defaultCountry: "EVINA_DEFAULT_COUNTRY",
  defaultCarrier: "EVINA_DEFAULT_CARRIER",
  timeoutMs: "EVINA_TIMEOUT_MS",
  retries: "EVINA_RETRIES",
  failOpen: "EVINA_FAIL_OPEN",
  useCloudflareForScript: "EVINA_USE_CLOUDFLARE",
} as const;

/**
 * Build (and validate) an {@link EvinaConfig} from environment variables.
 *
 * This is the ONLY place `process.env` is read, and only because the caller
 * explicitly invoked this helper (ADR-012, FR-3). The environment is passed as
 * an argument (defaulting to `process.env`) so it is trivially testable without
 * mutating the real process environment.
 *
 * @throws {EvinaConfigError} if required vars are missing or any value is invalid.
 */
export function configFromEnv(
  env: Record<string, string | undefined> = process.env,
): EvinaConfig {
  const apiKey = env[ENV_VAR_NAMES.apiKey];
  const username = env[ENV_VAR_NAMES.username];
  const password = env[ENV_VAR_NAMES.password];
  const authModeRaw = env[ENV_VAR_NAMES.authMode];

  if (username === undefined || username.length === 0) {
    throw new EvinaConfigError(
      `Missing required environment variable ${ENV_VAR_NAMES.username}`,
    );
  }

  const authMode: EvinaAuthMode =
    authModeRaw === "v1-signature" ? "v1-signature" : "v2-apikey";

  if (authMode === "v2-apikey") {
    if (apiKey === undefined || apiKey.length === 0) {
      throw new EvinaConfigError(
        `Missing required environment variable ${ENV_VAR_NAMES.apiKey}`,
      );
    }
  } else {
    if (password === undefined || password.length === 0) {
      throw new EvinaConfigError(
        `Missing required environment variable ${ENV_VAR_NAMES.password} (required for ${ENV_VAR_NAMES.authMode}=v1-signature)`,
      );
    }
  }

  const config: EvinaConfig = { username, authMode };
  if (apiKey !== undefined && apiKey.length > 0) config.apiKey = apiKey;
  if (password !== undefined && password.length > 0) config.password = password;

  const baseUrl = env[ENV_VAR_NAMES.baseUrl];
  if (baseUrl !== undefined && baseUrl.length > 0) {
    config.baseUrl = baseUrl;
  }

  const defaultCountry = env[ENV_VAR_NAMES.defaultCountry];
  if (defaultCountry !== undefined && defaultCountry.length > 0) {
    config.defaultCountry = defaultCountry;
  }

  const defaultCarrier = env[ENV_VAR_NAMES.defaultCarrier];
  if (defaultCarrier !== undefined && defaultCarrier.length > 0) {
    config.defaultCarrier = defaultCarrier;
  }

  const timeoutRaw = env[ENV_VAR_NAMES.timeoutMs];
  if (timeoutRaw !== undefined && timeoutRaw.length > 0) {
    config.timeoutMs = parseIntEnv(timeoutRaw, ENV_VAR_NAMES.timeoutMs);
  }

  const retriesRaw = env[ENV_VAR_NAMES.retries];
  if (retriesRaw !== undefined && retriesRaw.length > 0) {
    config.retries = parseIntEnv(retriesRaw, ENV_VAR_NAMES.retries);
  }

  const failOpenRaw = env[ENV_VAR_NAMES.failOpen];
  if (failOpenRaw !== undefined && failOpenRaw.length > 0) {
    config.failOpen = parseBoolEnv(failOpenRaw, ENV_VAR_NAMES.failOpen);
  }

  const useCloudflareRaw = env[ENV_VAR_NAMES.useCloudflareForScript];
  if (useCloudflareRaw !== undefined && useCloudflareRaw.length > 0) {
    config.useCloudflareForScript = parseBoolEnv(
      useCloudflareRaw,
      ENV_VAR_NAMES.useCloudflareForScript,
    );
  }

  // Fail fast on any invalid value (FR-4).
  validateConfig(config);
  return config;
}

function parseIntEnv(raw: string, name: string): number {
  const n = Number(raw);
  if (!Number.isInteger(n)) {
    throw new EvinaConfigError(`${name} must be an integer`);
  }
  return n;
}

function parseBoolEnv(raw: string, name: string): boolean {
  const normalized = raw.trim().toLowerCase();
  if (normalized === "true" || normalized === "1") return true;
  if (normalized === "false" || normalized === "0") return false;
  throw new EvinaConfigError(`${name} must be a boolean ("true"/"false"/"1"/"0")`);
}
