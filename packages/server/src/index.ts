/**
 * `@ideabiz/evina-sdk` — EVINA / DCB Protect anti-fraud server SDK.
 *
 * Trust boundary reminder (ADR-004 / NFR-SEC-1): this package is the ONLY
 * place the EVINA API key and username may live. The browser package must
 * never import from here.
 *
 * Public surface grows milestone by milestone:
 *   M0 — SDK_NAME constant (bootstrap proof)
 *   M1 — transport layer (httpPostForm, validateEvinaUrl, ALLOWED_EVINA_HOSTS,
 *         typed errors)
 *   M2 — config (EvinaConfig, validateConfig, resolveConfig, configFromEnv) +
 *         redaction/logger (redact, Logger, NOOP_LOGGER, createRedactingLogger)
 *   M3 — transaction store (TransactionStore, StoredTransaction,
 *         InMemoryTransactionStore, TOKEN_TTL_MS)
 *   M4 — EvinaClient.getScript, ti helpers, GetScript types
 *   M5 — EvinaClient.checkTransaction, verdict mapping, Check/Verdict types
 *   M6 — createTestSession + withEtsid helper + best-effort notifyTransaction
 */

/** Package identifier — used for logger / User-Agent tagging. */
export const SDK_NAME = "@ideabiz/evina-sdk";

// M1 — Transport & errors
export { httpPostForm, validateEvinaUrl, ALLOWED_EVINA_HOSTS } from "./transport.js";
export type { HttpPostFormOptions } from "./transport.js";
export {
  EvinaError,
  EvinaTransportError,
  EvinaConfigError,
  EvinaScriptError,
  EvinaCheckError,
} from "./errors.js";

// M2 — Config & validation
export {
  validateConfig,
  resolveConfig,
  configFromEnv,
  ENV_VAR_NAMES,
  DEFAULT_BASE_URL,
  CLOUDFLARE_BASE_URL,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_RETRIES,
  DEFAULT_FAIL_OPEN,
} from "./config.js";
export type { EvinaConfig, ResolvedConfig, EvinaAuthMode } from "./config.js";

// M2 — Redaction & logging
export { redact, maskMsisdns, createRedactingLogger, NOOP_LOGGER } from "./redact.js";
export type { Logger } from "./redact.js";

// M3 — Transaction store
export { InMemoryTransactionStore, TOKEN_TTL_MS } from "./store.js";
export type { InMemoryTransactionStoreOptions } from "./store.js";
export type { TransactionStore, StoredTransaction } from "./types.js";

// M4 — Client (getScript) + transaction id helpers
export { EvinaClient } from "./client.js";
export {
  generateTransactionId,
  isValidTransactionId,
  TI_MIN_LENGTH,
  TI_MAX_LENGTH,
} from "./ti.js";
export type { GetScriptInput, GetScriptResult, ArgKey } from "./types.js";

// M5 — Verdict mapping (checkTransaction is a method on EvinaClient)
export {
  mapFtToCategory,
  evaluateVerdict,
  AUTHENTIC_MIN,
  AUTHENTIC_MAX,
} from "./verdict.js";
export type { CheckInput, Verdict, FraudCategory } from "./types.js";

// M6 — test_session + notify (createTestSession/notifyTransaction are EvinaClient methods)
export { withEtsid } from "./client.js";
export { EvinaTestSessionError } from "./errors.js";
export type { NotifyInput, TestSession, PurchaseArgKey } from "./types.js";

// M6.5 — Framework-agnostic HTTP integration endpoint handlers (FR-A1..A5, ADR-014)
export { requestScriptHandler, verifyHandler } from "./handlers.js";
export type {
  RequestScriptInput,
  RequestScriptBody,
  VerifyInput,
  VerifyBody,
  ErrorBody,
  HandlerResponse,
} from "./handlers.js";

// Re-export without .js for Vitest/bundler compatibility (vitest resolves .ts).
// The .js extensions above are correct for Node ESM runtime; Vitest's bundler
// handles both transparently via its resolver.
