/**
 * checkTransaction unit + integration tests — M5
 *
 * Covers FR-7, FR-8, FR-13, FR-14, FR-15, FR-16 and ADR-008/009.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { EvinaClient, buildCheckParams } from "../src/client";
import { InMemoryTransactionStore, TOKEN_TTL_MS } from "../src/store";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";
import type { EvinaConfig } from "../src/config";
import type { StoredTransaction } from "../src/types";

const API_KEY = "test-api-key";
const USERNAME = "test-username";
const TI = "known-transaction-01";

function storedRecord(overrides: Partial<StoredTransaction> = {}): StoredTransaction {
  const now = Date.now();
  return {
    ti: TI,
    token: "tok-1",
    country: "LK",
    createdAt: now,
    expiresAt: now + TOKEN_TTL_MS,
    ...overrides,
  };
}

async function makeClientWithStored(
  overrides: Partial<EvinaConfig> = {},
  record: StoredTransaction | null = storedRecord(),
): Promise<{ client: EvinaClient; store: InMemoryTransactionStore }> {
  const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
  if (record) await store.save(record);
  const client = new EvinaClient({
    apiKey: API_KEY,
    username: USERNAME,
    defaultCountry: "LK",
    store,
    ...overrides,
  });
  return { client, store };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// buildCheckParams (FR-13)
// ---------------------------------------------------------------------------

describe("buildCheckParams", () => {
  const identity = { defaultCarrier: undefined, userIdTransform: (r: string) => r };
  const fixed = { ti: TI, country: "LK", tsSeconds: 1_700_000_000 };

  it("sends the mandatory ti/ts/country", () => {
    const p = buildCheckParams({ transactionId: TI }, identity, fixed);
    expect(p["ti"]).toBe(TI);
    expect(p["ts"]).toBe("1700000000");
    expect(p["country"]).toBe("LK");
  });

  it("does NOT include page-only fields (te/tck/cjv) or owner (Phase 2)", () => {
    const p = buildCheckParams({ transactionId: TI, owner: "partner" }, identity, fixed);
    expect(p["te"]).toBeUndefined();
    expect(p["tck"]).toBeUndefined();
    expect(p["cjv"]).toBeUndefined();
    expect(p["owner"]).toBeUndefined();
  });

  it("applies the same userIdTransform as /script (ADR-008)", () => {
    const p = buildCheckParams(
      { transactionId: TI, userId: "94771234567" },
      { defaultCarrier: undefined, userIdTransform: (r) => `H(${r})` },
      fixed,
    );
    expect(p["user_id"]).toBe("H(94771234567)");
  });

  it("maps provided arg1..arg10", () => {
    const p = buildCheckParams(
      { transactionId: TI, args: { arg1: "a", arg5: "e" } },
      identity,
      fixed,
    );
    expect(p["arg1"]).toBe("a");
    expect(p["arg5"]).toBe("e");
    expect(p["arg2"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// checkTransaction integration
// ---------------------------------------------------------------------------

describe("EvinaClient.checkTransaction — verdicts", () => {
  it("allows an authentic transaction and posts the right request", async () => {
    const mock = installMockEvina(() => jsonResponse({ success: true, ft: 1000, as: 100, oo: 1 }));
    const { client } = await makeClientWithStored();

    const verdict = await client.checkTransaction({ transactionId: TI });

    expect(verdict.allowed).toBe(true);
    expect(verdict.category).toBe("authentic");
    expect(verdict.ft).toBe(1000);

    const req = mock.last();
    expect(req?.url).toBe("https://api.dcbprotect.com/v1/check");
    expect(req?.headers["x-evina-apikey"]).toBe(API_KEY);
    expect(req?.params["ti"]).toBe(TI);
    expect(req?.params["country"]).toBe("LK");
  });

  it("blocks a fraud verdict", async () => {
    installMockEvina(() => jsonResponse({ success: true, ft: 2100 }));
    const { client } = await makeClientWithStored();

    const verdict = await client.checkTransaction({ transactionId: TI });
    expect(verdict.allowed).toBe(false);
    expect(verdict.category).toBe("fraud");
  });

  it("uses the stored country when none is supplied (FR-7)", async () => {
    const mock = installMockEvina(() => jsonResponse({ success: true, ft: 1000 }));
    const { client } = await makeClientWithStored({}, storedRecord({ country: "US" }));

    await client.checkTransaction({ transactionId: TI });
    expect(mock.last()?.params["country"]).toBe("US");
  });

  it("accepts (and ignores) owner without sending it (Phase 2)", async () => {
    const mock = installMockEvina(() => jsonResponse({ success: true, ft: 1000 }));
    const { client } = await makeClientWithStored();

    await client.checkTransaction({ transactionId: TI, owner: "partner" });
    expect(mock.last()?.params["owner"]).toBeUndefined();
  });

  it("throws when no country is available (input/stored/config all absent)", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const now = Date.now();
    // Stored record intentionally has no country.
    await store.save({ ti: TI, token: "tok", createdAt: now, expiresAt: now + TOKEN_TTL_MS });
    const client = new EvinaClient({ apiKey: API_KEY, username: USERNAME, store });

    await expect(client.checkTransaction({ transactionId: TI })).rejects.toBeInstanceOf(
      TypeError,
    );
  });
});

describe("EvinaClient.checkTransaction — unknown/expired ti (FR-8)", () => {
  it("fails open (default) for an unknown ti without calling EVINA", async () => {
    const mock = installMockEvina(() => jsonResponse({ success: true, ft: 1000 }));
    const { client } = await makeClientWithStored({}, null); // nothing stored

    const verdict = await client.checkTransaction({ transactionId: "never-seen-01" });

    expect(verdict.allowed).toBe(true);
    expect(verdict.failOpen).toBe(true);
    expect(verdict.reason).toContain("unknown or expired");
    expect(mock.requests.length).toBe(0);
  });

  it("fails closed for an unknown ti when configured", async () => {
    installMockEvina(() => jsonResponse({ success: true, ft: 1000 }));
    const { client } = await makeClientWithStored({ failOpen: false }, null);

    const verdict = await client.checkTransaction({ transactionId: "never-seen-01" });
    expect(verdict.allowed).toBe(false);
    expect(verdict.failOpen).toBe(false);
  });

  it("treats an expired stored entry as unknown", async () => {
    const mock = installMockEvina(() => jsonResponse({ success: true, ft: 1000 }));
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    // expiresAt in the past → store.get returns null.
    await store.save(storedRecord({ createdAt: 1, expiresAt: 2 }));
    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
    });

    const verdict = await client.checkTransaction({ transactionId: TI });
    expect(verdict.failOpen).toBe(true);
    expect(mock.requests.length).toBe(0);
  });
});

describe("EvinaClient.checkTransaction — fail-open/closed on infra errors (FR-16)", () => {
  it("fails open on a non-200 response", async () => {
    installMockEvina(() => jsonResponse({}, 500));
    const { client } = await makeClientWithStored();

    const verdict = await client.checkTransaction({ transactionId: TI });
    expect(verdict.allowed).toBe(true);
    expect(verdict.failOpen).toBe(true);
    expect(verdict.reason).toContain("fail-open");
  });

  it("fails open on non-JSON body", async () => {
    installMockEvina(() => new Response("<html>oops</html>", { status: 200 }));
    const { client } = await makeClientWithStored();

    const verdict = await client.checkTransaction({ transactionId: TI });
    expect(verdict.allowed).toBe(true);
    expect(verdict.failOpen).toBe(true);
  });

  it("fails open on a network error", async () => {
    installMockEvina(() => {
      throw new Error("connection reset");
    });
    const { client } = await makeClientWithStored();

    const verdict = await client.checkTransaction({ transactionId: TI });
    expect(verdict.allowed).toBe(true);
    expect(verdict.failOpen).toBe(true);
  });

  it("fails closed on a non-200 response when configured", async () => {
    installMockEvina(() => jsonResponse({}, 503));
    const { client } = await makeClientWithStored({ failOpen: false });

    const verdict = await client.checkTransaction({ transactionId: TI });
    expect(verdict.allowed).toBe(false);
    expect(verdict.failOpen).toBe(false);
  });
});

describe("EvinaClient.checkTransaction — input validation", () => {
  it("rejects an invalid ti with TypeError (not a verdict)", async () => {
    const { client } = await makeClientWithStored();
    await expect(
      client.checkTransaction({ transactionId: "bad id!" }),
    ).rejects.toBeInstanceOf(TypeError);
  });
});
