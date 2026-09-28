/**
 * handlers.ts unit + integration tests — M6.5
 *
 * Unit: handler logic against a mock EvinaClient (no network).
 * Integration: real EvinaClient against the mock EVINA fetch stub.
 *
 * Covers FR-A1, FR-A2, FR-A3, FR-A4, FR-A5, FR-A6, ADR-014.
 * Security assertions: token never in response, ft/secrets never in response,
 * input validation → 400, upstream errors → 502.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { requestScriptHandler, verifyHandler } from "../src/handlers";
import { EvinaClient } from "../src/client";
import { EvinaScriptError, EvinaTransportError } from "../src/errors";
import { InMemoryTransactionStore } from "../src/store";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";
import type { EvinaConfig } from "../src/config";
import type { GetScriptResult, Verdict } from "../src/types";

// ---------------------------------------------------------------------------
// Mock EvinaClient helpers
// ---------------------------------------------------------------------------

function mockClient(overrides: {
  getScript?: () => Promise<GetScriptResult>;
  checkTransaction?: () => Promise<Verdict>;
} = {}): EvinaClient {
  return {
    getScript: overrides.getScript ?? vi.fn(),
    checkTransaction: overrides.checkTransaction ?? vi.fn(),
  } as unknown as EvinaClient;
}

function scriptResult(overrides: Partial<GetScriptResult> = {}): GetScriptResult {
  return {
    transactionId: "tx-abc-00000001",
    token: "secret-evina-token",
    script: "<script>kit</script>",
    raw: {},
    ...overrides,
  };
}

function allowVerdict(overrides: Partial<Verdict> = {}): Verdict {
  return {
    allowed: true,
    ft: 1000,
    category: "authentic",
    authenticityScore: 100,
    opinion: 1,
    success: true,
    reason: "authentic (ft=1000)",
    raw: {},
    ...overrides,
  };
}

function blockVerdict(overrides: Partial<Verdict> = {}): Verdict {
  return {
    allowed: false,
    ft: 2100,
    category: "fraud",
    authenticityScore: 0,
    opinion: 0,
    success: true,
    reason: "fraud (ft=2100)",
    raw: {},
    ...overrides,
  };
}

function failOpenVerdict(): Verdict {
  return {
    allowed: true,
    ft: null,
    category: "unknown",
    authenticityScore: null,
    opinion: null,
    success: false,
    reason: "fail-open: upstream error",
    failOpen: true,
    raw: null,
  };
}

// ---------------------------------------------------------------------------
// requestScriptHandler — unit tests
// ---------------------------------------------------------------------------

describe("requestScriptHandler — unit", () => {
  it("returns 200 with { transactionId, script } on success (FR-A1)", async () => {
    const client = mockClient({ getScript: () => Promise.resolve(scriptResult()) });
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "#subscribe" });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      transactionId: "tx-abc-00000001",
      script: "<script>kit</script>",
    });
  });

  it("never includes the EVINA token in the response body (FR-A5)", async () => {
    const client = mockClient({ getScript: () => Promise.resolve(scriptResult()) });
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "#subscribe" });

    expect(JSON.stringify(res.body)).not.toContain("secret-evina-token");
    expect(res.body).not.toHaveProperty("token");
  });

  it("returns 400 when targetSelector is missing (empty string)", async () => {
    const client = mockClient();
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "" });

    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toMatch(/targetSelector/);
  });

  it("returns 400 when targetSelector is whitespace-only", async () => {
    const client = mockClient();
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "   " });

    expect(res.status).toBe(400);
  });

  it("returns 400 when transactionId is invalid (TypeError from client)", async () => {
    const client = mockClient({
      getScript: () => Promise.reject(new TypeError("transactionId must be …")),
    });
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "#b", transactionId: "bad id!" });

    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toBe("invalid transactionId");
  });

  it("returns 502 on EvinaScriptError", async () => {
    const client = mockClient({
      getScript: () => Promise.reject(new EvinaScriptError("EVINA /script failed")),
    });
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "#b" });

    expect(res.status).toBe(502);
    expect((res.body as { error: string }).error).toBe("upstream error");
  });

  it("returns 502 on EvinaTransportError", async () => {
    const client = mockClient({
      getScript: () => Promise.reject(new EvinaTransportError("timeout")),
    });
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "#b" });

    expect(res.status).toBe(502);
  });

  it("returns 500 on an unexpected error", async () => {
    const client = mockClient({
      getScript: () => Promise.reject(new Error("something unexpected")),
    });
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "#b" });

    expect(res.status).toBe(500);
    expect((res.body as { error: string }).error).toBe("internal error");
  });

  it("passes optional fields through to getScript", async () => {
    const getScript = vi.fn(() => Promise.resolve(scriptResult()));
    const client = mockClient({ getScript });
    const handler = requestScriptHandler(client);

    await handler({
      targetSelector: "#b",
      transactionId: "tx-optional-01",
      country: "LK",
      carrier: "41302",
      service: "my-svc",
      userId: "94771234567",
      args: { arg1: "app" },
    });

    expect(getScript).toHaveBeenCalledWith(
      expect.objectContaining({
        targetSelector: "#b",
        transactionId: "tx-optional-01",
        country: "LK",
        carrier: "41302",
        service: "my-svc",
        userId: "94771234567",
        args: { arg1: "app" },
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// verifyHandler — unit tests
// ---------------------------------------------------------------------------

describe("verifyHandler — unit", () => {
  it("returns 200 with { allowed: true, category, reason } for authentic ft", async () => {
    const client = mockClient({ checkTransaction: () => Promise.resolve(allowVerdict()) });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-abc-00000001" });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      allowed: true,
      category: "authentic",
      reason: "authentic (ft=1000)",
    });
  });

  it("returns 200 with { allowed: false, category, reason } for fraud ft", async () => {
    const client = mockClient({ checkTransaction: () => Promise.resolve(blockVerdict()) });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-abc-00000001" });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      allowed: false,
      category: "fraud",
      reason: "fraud (ft=2100)",
    });
  });

  it("returns 200 with allowed:true for a fail-open verdict (no failOpen field in body)", async () => {
    const client = mockClient({ checkTransaction: () => Promise.resolve(failOpenVerdict()) });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-abc-00000001" });

    expect(res.status).toBe(200);
    expect((res.body as { allowed: boolean }).allowed).toBe(true);
    // failOpen is an internal SDK field — not exposed to the browser
    expect(res.body).not.toHaveProperty("failOpen");
  });

  it("returns 400 when transactionId is missing (empty string)", async () => {
    const client = mockClient();
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "" });

    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toMatch(/transactionId/);
  });

  it("returns 400 when transactionId is whitespace-only", async () => {
    const client = mockClient();
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "   " });

    expect(res.status).toBe(400);
  });

  it("returns 400 when transactionId has invalid format (TypeError from client)", async () => {
    const client = mockClient({
      checkTransaction: () => Promise.reject(new TypeError("transactionId must be …")),
    });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "bad id!" });

    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toBe("invalid transactionId");
  });

  it("never includes ft, token, apiKey, username, or raw MSISDN in response (FR-A5)", async () => {
    const client = mockClient({ checkTransaction: () => Promise.resolve(allowVerdict()) });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-abc-00000001" });
    const serialised = JSON.stringify(res.body);

    expect(res.body).not.toHaveProperty("ft");
    expect(res.body).not.toHaveProperty("token");
    expect(res.body).not.toHaveProperty("apiKey");
    expect(res.body).not.toHaveProperty("username");
    expect(serialised).not.toContain("94771234567");
  });

  it("returns 500 on an unexpected error", async () => {
    const client = mockClient({
      checkTransaction: () => Promise.reject(new Error("unexpected")),
    });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-abc-00000001" });

    expect(res.status).toBe(500);
    expect((res.body as { error: string }).error).toBe("internal error");
  });

  it("passes optional fields through to checkTransaction", async () => {
    const checkTransaction = vi.fn(() => Promise.resolve(allowVerdict()));
    const client = mockClient({ checkTransaction });
    const handler = verifyHandler(client);

    await handler({
      transactionId: "tx-abc-00000001",
      country: "LK",
      carrier: "41302",
      service: "my-svc",
      userId: "94771234567",
      args: { arg2: "val" },
    });

    expect(checkTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        transactionId: "tx-abc-00000001",
        country: "LK",
        carrier: "41302",
        service: "my-svc",
        userId: "94771234567",
        args: { arg2: "val" },
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// Integration tests — real EvinaClient + mock EVINA fetch
// ---------------------------------------------------------------------------

const API_KEY = "test-api-key";
const USERNAME = "test-username";

function makeRealClient(overrides: Partial<EvinaConfig> = {}): EvinaClient {
  return new EvinaClient({
    apiKey: API_KEY,
    username: USERNAME,
    defaultCountry: "LK",
    store: new InMemoryTransactionStore({ sweepIntervalMs: 0 }),
    ...overrides,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("requestScriptHandler — integration", () => {
  it("end-to-end: mock EVINA returns script → handler returns 200 with { transactionId, script }", async () => {
    installMockEvina(() => jsonResponse({ t: "tok-real", s: "<script>real-kit</script>" }));
    const client = makeRealClient();
    const handler = requestScriptHandler(client);

    const res = await handler({ targetSelector: "#subscribe", country: "LK" });

    expect(res.status).toBe(200);
    const body = res.body as { transactionId: string; script: string };
    expect(body.script).toBe("<script>real-kit</script>");
    expect(body.transactionId).toMatch(/^[A-Za-z0-9_-]+$/);
    // Token must not appear in the response
    expect(JSON.stringify(res.body)).not.toContain("tok-real");
  });
});

describe("verifyHandler — integration", () => {
  it("end-to-end: ft=1000 → { allowed: true, category: 'authentic' }", async () => {
    // Seed the store so checkTransaction finds the transaction
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const now = Date.now();
    await store.save({
      ti: "tx-integ-00000001",
      token: "tok",
      country: "LK",
      createdAt: now,
      expiresAt: now + 6 * 60 * 60 * 1000,
    });
    installMockEvina(() => jsonResponse({ success: true, ft: 1000, as: 100, oo: 1 }));
    const client = makeRealClient({ store });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-integ-00000001" });

    expect(res.status).toBe(200);
    expect((res.body as { allowed: boolean }).allowed).toBe(true);
    expect((res.body as { category: string }).category).toBe("authentic");
  });

  it("end-to-end: ft=2100 → { allowed: false, category: 'fraud' }", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const now = Date.now();
    await store.save({
      ti: "tx-integ-00000002",
      token: "tok",
      country: "LK",
      createdAt: now,
      expiresAt: now + 6 * 60 * 60 * 1000,
    });
    installMockEvina(() => jsonResponse({ success: true, ft: 2100 }));
    const client = makeRealClient({ store });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-integ-00000002" });

    expect(res.status).toBe(200);
    expect((res.body as { allowed: boolean }).allowed).toBe(false);
    expect((res.body as { category: string }).category).toBe("fraud");
  });

  it("end-to-end: EVINA returns 500 → handler returns 200 with allowed:true (fail-open)", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const now = Date.now();
    await store.save({
      ti: "tx-integ-00000003",
      token: "tok",
      country: "LK",
      createdAt: now,
      expiresAt: now + 6 * 60 * 60 * 1000,
    });
    installMockEvina(() => jsonResponse({}, 500));
    const client = makeRealClient({ store });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-integ-00000003" });

    expect(res.status).toBe(200);
    expect((res.body as { allowed: boolean }).allowed).toBe(true);
  });
});
