/**
 * Security test suite — M5 checkTransaction
 *
 *  FR-16 / NFR-SEC-2/4   Every fail-open logs a warn with only PII-safe fields.
 *  ADR-002               API key only in the header, never URL/params.
 *  ADR-008               Same userIdTransform applied on /check as on /script.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { EvinaClient } from "../src/client";
import { InMemoryTransactionStore, TOKEN_TTL_MS } from "../src/store";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";
import type { Logger } from "../src/redact";
import type { StoredTransaction } from "../src/types";

const API_KEY = "sk_live_SUPER_SECRET_KEY";
const USERNAME = "owner_secret_username";
const MSISDN = "94771234567";
const TI = "known-transaction-01";

function storedRecord(): StoredTransaction {
  const now = Date.now();
  return { ti: TI, token: "tok-1", country: "LK", createdAt: now, expiresAt: now + TOKEN_TTL_MS };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("SEC: fail-open warn log is PII-safe (FR-16)", () => {
  it("logs a warn on fail-open with ti but no secrets or MSISDN", async () => {
    installMockEvina(() => jsonResponse({}, 500));

    const warns: string[] = [];
    const logger: Logger = {
      debug: () => undefined,
      info: () => undefined,
      warn: (m, meta) => warns.push(m + " " + JSON.stringify(meta ?? {})),
      error: () => undefined,
    };

    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    await store.save(storedRecord());
    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
      logger,
    });

    await client.checkTransaction({ transactionId: TI, userId: MSISDN });

    expect(warns.length).toBeGreaterThan(0);
    for (const line of warns) {
      expect(line).not.toContain(API_KEY);
      expect(line).not.toContain(USERNAME);
      expect(line).not.toContain(MSISDN);
      expect(line).toContain(TI);
    }
  });
});

describe("SEC: API key only in header (ADR-002)", () => {
  it("does not leak the key into the /check URL or params", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    await store.save(storedRecord());
    const mock = installMockEvina(() => jsonResponse({ success: true, ft: 1000 }));
    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
    });

    await client.checkTransaction({ transactionId: TI, userId: MSISDN });

    const req = mock.last();
    expect(req?.headers["x-evina-apikey"]).toBe(API_KEY);
    expect(req?.url).not.toContain(API_KEY);
    for (const value of Object.values(req?.params ?? {})) {
      expect(value).not.toBe(API_KEY);
    }
  });
});

describe("SEC: same userIdTransform on /check (ADR-008)", () => {
  it("sends the transformed user_id, not the raw MSISDN", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    await store.save(storedRecord());
    const mock = installMockEvina(() => jsonResponse({ success: true, ft: 1000 }));
    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
      userIdTransform: (raw) => `sha256:${raw.length}`,
    });

    await client.checkTransaction({ transactionId: TI, userId: MSISDN });

    const sent = mock.last()?.params["user_id"];
    expect(sent).toBe("sha256:11");
    expect(sent).not.toContain(MSISDN);
  });
});
