/**
 * Transaction state storage (M3).
 *
 * Between `/v1/script` and `/v1/check` the SDK must remember the transaction
 * context (`ti`, EVINA token `t`, `country`, `owner?`) and when it expires, so
 * that `/check` can supply consistent parameters and reject unknown/expired
 * transactions (ADR-007, FR-6, FR-7, FR-25).
 *
 * Requirements / decisions:
 *   FR-25   Define a `TransactionStore` (save/get/delete, TTL) and ship an
 *           in-memory default; document the multi-instance limitation.
 *   ADR-007 Pluggable store so consumers can inject Redis/DB backends; entries
 *           carry a TTL aligned to EVINA's 6h token lifetime.
 *   EVINA_API_FACTS §9  Token (`t`) lives 6 hours; a stored transaction is only
 *           meaningful for a few hours.
 *
 * Security / privacy notes (THREAT_MODEL):
 *   - {@link StoredTransaction} deliberately has NO raw MSISDN / PII field — the
 *     store holds only {ti, token, country, owner, timestamps} (NFR-PRV-1).
 *   - The in-memory implementation keys entries in a `Map`, so a hostile `ti`
 *     value cannot pollute object prototypes (T-E2).
 *   - Records are cloned on the way in and out, so callers cannot mutate stored
 *     state by holding a reference.
 */

import type { TransactionStore, StoredTransaction } from "./types.js";

export type { TransactionStore, StoredTransaction } from "./types.js";

/** EVINA token (`t`) lifetime — 6 hours (EVINA_API_FACTS §9). */
export const TOKEN_TTL_MS = 6 * 60 * 60 * 1000;

/** Default interval for the background expiry sweep (5 minutes). */
const DEFAULT_SWEEP_INTERVAL_MS = 5 * 60 * 1000;

/** Options for {@link InMemoryTransactionStore}. */
export interface InMemoryTransactionStoreOptions {
  /**
   * Clock injection for testability. Defaults to `Date.now`. Must return epoch
   * milliseconds.
   */
  now?: () => number;
  /**
   * Interval (ms) for the background sweep that purges expired entries. Set to
   * `0` (or a negative value) to disable the timer and rely solely on lazy
   * expiry (useful in tests). Default 5 minutes.
   */
  sweepIntervalMs?: number;
}

/**
 * Default, in-process {@link TransactionStore}.
 *
 *  **Not suitable for multi-instance / clustered deployments** (ADR-007):
 * state is per-process and is NOT shared across nodes, so a `/script` handled
 * by one instance and a `/check` handled by another will not find the entry.
 * For clustered deployments, inject a shared store (e.g. Redis) — that adapter
 * is a phase-2 deliverable. In-memory is appropriate for single-instance and
 * development, and tokens expire within 6h regardless.
 *
 * Expiry is enforced two ways:
 *   1. **Lazy** — {@link get} treats an entry past its `expiresAt` as absent
 *      (and removes it). This guarantees correctness even with no timer.
 *   2. **Sweep** — an optional unref'd interval purges expired entries so
 *      abandoned transactions (created but never checked) don't accumulate.
 */
export class InMemoryTransactionStore implements TransactionStore {
  private readonly entries = new Map<string, StoredTransaction>();
  private readonly now: () => number;
  private readonly sweepIntervalMs: number;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(options: InMemoryTransactionStoreOptions = {}) {
    this.now = options.now ?? (() => Date.now());
    this.sweepIntervalMs = options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;

    if (this.sweepIntervalMs > 0) {
      this.timer = setInterval(() => {
        this.sweep();
      }, this.sweepIntervalMs);
      // Never keep the host process alive just for the sweep (library-safe).
      this.timer.unref();
    }
  }

  /** Persist a transaction record. Rejects if `ti` is not a usable key. */
  save(t: StoredTransaction): Promise<void> {
    if (typeof t.ti !== "string" || t.ti.length === 0) {
      return Promise.reject(
        new TypeError("StoredTransaction.ti must be a non-empty string"),
      );
    }
    // Clone so later external mutation of the caller's object cannot alter
    // stored state (and vice-versa).
    this.entries.set(t.ti, { ...t });
    return Promise.resolve();
  }

  /** Look up a transaction by `ti`. Returns null if absent or expired. */
  get(ti: string): Promise<StoredTransaction | null> {
    if (typeof ti !== "string") return Promise.resolve(null);

    const record = this.entries.get(ti);
    if (record === undefined) return Promise.resolve(null);

    if (this.isExpired(record)) {
      this.entries.delete(ti);
      return Promise.resolve(null);
    }
    return Promise.resolve({ ...record });
  }

  /** Remove a transaction by `ti` (idempotent). */
  delete(ti: string): Promise<void> {
    this.entries.delete(ti);
    return Promise.resolve();
  }

  /**
   * Purge all expired entries now. Returns the number removed. Exposed so tests
   * (and operators) can trigger a deterministic sweep without waiting for the
   * timer.
   */
  sweep(): number {
    const now = this.now();
    let purged = 0;
    for (const [ti, record] of this.entries) {
      if (record.expiresAt <= now) {
        this.entries.delete(ti);
        purged += 1;
      }
    }
    return purged;
  }

  /** Number of entries currently held (including any not-yet-swept expired ones). */
  get size(): number {
    return this.entries.size;
  }

  /**
   * Stop the background sweep timer and release its handle. Safe to call more
   * than once. Call this when disposing of a store to avoid leaking a timer.
   */
  stop(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  private isExpired(record: StoredTransaction): boolean {
    return record.expiresAt <= this.now();
  }
}
