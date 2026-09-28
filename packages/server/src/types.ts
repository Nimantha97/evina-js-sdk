/**
 * Shared public type definitions (SRS §4.1).
 *
 * Kept in a dedicated module so both the storage layer and (from M4) the config
 * layer can reference these contracts without importing concrete
 * implementations. Only the types needed so far are declared here; later
 * milestones add the request/result/verdict types.
 */

/**
 * A persisted transaction context, saved after a successful `/v1/script` and
 * read back at `/v1/check` (FR-6, FR-7).
 *
 * PRIVACY: this record intentionally carries NO raw MSISDN or other PII — only
 * the correlation id, EVINA token, country/owner context, and timestamps
 * (NFR-PRV-1, THREAT_MODEL T-I3).
 */
export interface StoredTransaction {
  /** Transaction id shared across `/script` and `/check`. */
  ti: string;
  /** EVINA-issued token (`t`) for this transaction. */
  token: string;
  /** ISO-3166 alpha-2 country used for the transaction. */
  country?: string;
  /** DCB account owner (transparent-gateway / phase 2). */
  owner?: string;
  /** Creation time (epoch ms). */
  createdAt: number;
  /** Expiry time (epoch ms), aligned to the 6h token lifetime. */
  expiresAt: number;
}

/**
 * Pluggable transaction storage (ADR-007, FR-25).
 *
 * Consumers may inject a shared implementation (e.g. Redis) for clustered
 * deployments; the SDK ships an in-memory default.
 */
export interface TransactionStore {
  /** Persist (or overwrite) a transaction record. */
  save(t: StoredTransaction): Promise<void>;
  /** Fetch a record by `ti`, or `null` if absent/expired. */
  get(ti: string): Promise<StoredTransaction | null>;
  /** Remove a record by `ti` (idempotent). */
  delete(ti: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// getScript (M4) — SRS §4.1
// ---------------------------------------------------------------------------

/** Arg keys accepted for dashboard filtering (`arg1`..`arg10`). */
export type ArgKey = `arg${1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10}`;

/**
 * Input to {@link EvinaClient.getScript} (`POST /v1/script`).
 *
 * Maps to EVINA params (EVINA_API_FACTS §5): `targetSelector`→`te`,
 * `transactionId`→`ti`, `userId`→`user_id`, `purchaseId`→`purchase_id`,
 * `permissionList`→`pl`.
 */
export interface GetScriptInput {
  /** CSS-like selector of the protected element → `te` (e.g. "#subscribe"). */
  targetSelector: string;
  /** Transaction id → `ti`. Generated if absent (FR-5). */
  transactionId?: string;
  /** ISO-3166 alpha-2 country → `country`. Falls back to `config.defaultCountry`. */
  country?: string;
  /** MCC-MNC carrier → `carrier`. Falls back to `config.defaultCarrier`. */
  carrier?: string;
  /** Service name shown on the dashboard → `service`. */
  service?: string;
  /** End-user id → `user_id` (passes through `userIdTransform`, ADR-008). */
  userId?: string;
  /** Business transaction id → `purchase_id`. */
  purchaseId?: string;
  /** Free-form dashboard args → `arg1`..`arg10`. */
  args?: Partial<Record<ArgKey, string>>;
  /** Eyewitness replay-merging id → `tck`. */
  tck?: string;
  /** Eyewitness (clickjacking) activation flag → `cjv`. */
  cjv?: number;
  /** Permission list → `pl`. Accepted but NOT sent in the MVP (transparent-gateway is Phase 2). */
  permissionList?: string[];
}

/** Result of a successful {@link EvinaClient.getScript} call (FR-11). */
export interface GetScriptResult {
  /** The transaction id used (generated or caller-supplied). */
  transactionId: string;
  /** EVINA token (`t`) — server-side only; never expose to the browser. */
  token: string;
  /** The opaque EVINA JavaScript kit (`s`) to inject into the page. */
  script: string;
  /** The raw parsed EVINA response, for advanced consumers. */
  raw: unknown;
}

// ---------------------------------------------------------------------------
// checkTransaction + verdict (M5) — SRS §4.1
// ---------------------------------------------------------------------------

/**
 * Input to {@link EvinaClient.checkTransaction} (`POST /v1/check`).
 * `owner` is accepted but NOT sent in the MVP (transparent-gateway is Phase 2).
 */
export interface CheckInput {
  /** Transaction id → `ti` (same id used at `/script`). */
  transactionId: string;
  /** ISO-3166 alpha-2 country → `country`. Falls back to stored ctx / config. */
  country?: string;
  /** MCC-MNC carrier → `carrier`. Falls back to `config.defaultCarrier`. */
  carrier?: string;
  /** Service name → `service`. */
  service?: string;
  /** End-user id → `user_id` (SAME `userIdTransform` as /script, ADR-008). */
  userId?: string;
  /** Business transaction id → `purchase_id`. */
  purchaseId?: string;
  /** DCB account owner → `owner`. Accepted but NOT sent in the MVP (Phase 2). */
  owner?: string;
  /** Free-form dashboard args → `arg1`..`arg10`. */
  args?: Partial<Record<ArgKey, string>>;
}

/** Derived, human-meaningful classification of an `ft` fraud code (EVINA_API_FACTS §7). */
export type FraudCategory =
  | "authentic"
  | "fraud"
  | "accidental"
  | "error"
  | "bot"
  | "custom"
  | "unknown";

/**
 * The result of a fraud check (FR-14/15/16/17).
 *
 * `allowed` is the ONLY field a consumer needs to gate billing; the rest are
 * for logging / UX. `failOpen` is present and true when the verdict came from
 * the fail-open policy rather than a real EVINA response (FR-16).
 */
export interface Verdict {
  /** True iff `success === true && ft in [1000,1999]` (FR-15). */
  allowed: boolean;
  /** Raw numeric fraud code, or null if none/parse-failure. */
  ft: number | null;
  /** Derived category from {@link ft}. */
  category: FraudCategory;
  /** Authenticity score 0–100 (`as`), or null. */
  authenticityScore: number | null;
  /** EVINA "our opinion" (`oo`): 0, 1, or null. */
  opinion: 0 | 1 | null;
  /** Whether EVINA reported the request processed OK (`success`). */
  success: boolean;
  /** Human-readable, PII-safe explanation of the decision. */
  reason?: string;
  /** Present when this verdict was produced by the fail-open/closed policy. */
  failOpen?: boolean;
  /** The raw parsed EVINA response (or null for policy verdicts). */
  raw: unknown;
}

// ---------------------------------------------------------------------------
// test_session + notify (M6) — SRS §4.1 + EVINA_API_FACTS §10/§11
// ---------------------------------------------------------------------------

/** `purchase_arg1`..`purchase_arg5` keys for the `/transaction` `d` object. */
export type PurchaseArgKey = `purchase_arg${1 | 2 | 3 | 4 | 5}`;

/**
 * Input to {@link EvinaClient.notifyTransaction} (`POST /v1/transaction`).
 *
 * All fields except `transactionId` map into the EVINA `d` JSON object
 * (EVINA_API_FACTS §10). `msisdn` passes through `userIdTransform` (ADR-008),
 * so a configured hash/alias is applied here too.
 */
export interface NotifyInput {
  /** Transaction id → `ti` (mandatory). */
  transactionId: string;
  /** → `d.purchase_id`. */
  purchaseId?: string;
  /** → `d.msisdn` (passed through `userIdTransform`). */
  msisdn?: string;
  /** → `d.carrier` (falls back to `config.defaultCarrier`). */
  carrier?: string;
  /** → `d.country`. */
  country?: string;
  /** → `d.service`. */
  service?: string;
  /** → `d.purchase_arg1`..`d.purchase_arg5`. */
  purchaseArgs?: Partial<Record<PurchaseArgKey, string>>;
}

/** Result of {@link EvinaClient.createTestSession} (`POST /v1/test_session`). */
export interface TestSession {
  /** Test session id to append to the page URL as `?etsid=`. */
  etsid: string;
  /** The forced fraud code that the next `/check` will return. */
  ft: number;
  /** DCB account username echoed by EVINA (must match the /script account). */
  username: string;
}
