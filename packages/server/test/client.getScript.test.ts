/**
 * getScript unit + integration tests — M4
 *
 * Unit: buildScriptParams + parseScriptResponse (pure).
 * Integration: EvinaClient.getScript against the mock EVINA server.
 *
 * Covers FR-5/6/9/10/11/12, ADR-002, ADR-008.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { EvinaClient, buildScriptParams, parseScriptResponse } from "../src/client";
import { EvinaScriptError, EvinaTransportError } from "../src/errors";
import { InMemoryTransactionStore, TOKEN_TTL_MS } from "../src/store";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";
import type { EvinaConfig } from "../src/config";

const API_KEY = "test-api-key";
const USERNAME = "test-username";

function makeClient(overrides: Partial<EvinaConfig> = {}): EvinaClient {
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

// ---------------------------------------------------------------------------
// buildScriptParams (FR-9, FR-10, FR-12)
// ---------------------------------------------------------------------------

describe("buildScriptParams", () => {
  const identity = { defaultCarrier: undefined, userIdTransform: (r: string) => r };
  const fixed = { ti: "tx-abc-123", country: "LK", tsSeconds: 1_700_000_000 };

  it("maps the four mandatory params", () => {
    const p = buildScriptParams({ targetSelector: "#subscribe" }, identity, fixed);
    expect(p["ti"]).toBe("tx-abc-123");
    expect(p["te"]).toBe("#subscribe");
    expect(p["ts"]).toBe("1700000000");
    expect(p["country"]).toBe("LK");
  });

  it("includes provided optionals", () => {
    const p = buildScriptParams(
      {
        targetSelector: "#b",
        carrier: "41302",
        service: "my-svc",
        purchaseId: "po-1",
        tck: "hash-1",
        cjv: 1,
      },
      identity,
      fixed,
    );
    expect(p["carrier"]).toBe("41302");
    expect(p["service"]).toBe("my-svc");
    expect(p["purchase_id"]).toBe("po-1");
    expect(p["tck"]).toBe("hash-1");
    expect(p["cjv"]).toBe("1");
  });

  it("falls back to config.defaultCarrier when carrier not supplied", () => {
    const p = buildScriptParams(
      { targetSelector: "#b" },
      { defaultCarrier: "41302", userIdTransform: (r: string) => r },
      fixed,
    );
    expect(p["carrier"]).toBe("41302");
  });

  it("omits optionals that are not provided", () => {
    const p = buildScriptParams({ targetSelector: "#b" }, identity, fixed);
    expect(p["carrier"]).toBeUndefined();
    expect(p["service"]).toBeUndefined();
    expect(p["user_id"]).toBeUndefined();
    expect(p["purchase_id"]).toBeUndefined();
    expect(p["tck"]).toBeUndefined();
    expect(p["cjv"]).toBeUndefined();
  });

  it("applies userIdTransform to user_id (ADR-008)", () => {
    const p = buildScriptParams(
      { targetSelector: "#b", userId: "94771234567" },
      { defaultCarrier: undefined, userIdTransform: (r) => `H(${r})` },
      fixed,
    );
    expect(p["user_id"]).toBe("H(94771234567)");
  });

  it("maps only the provided arg1..arg10 keys", () => {
    const p = buildScriptParams(
      { targetSelector: "#b", args: { arg1: "app", arg10: "ua" } },
      identity,
      fixed,
    );
    expect(p["arg1"]).toBe("app");
    expect(p["arg10"]).toBe("ua");
    expect(p["arg2"]).toBeUndefined();
  });

  it("never emits pl even when permissionList is supplied (Phase 2)", () => {
    const p = buildScriptParams(
      { targetSelector: "#b", permissionList: ["partner"] },
      identity,
      fixed,
    );
    expect(p["pl"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// parseScriptResponse (FR-11)
// ---------------------------------------------------------------------------

describe("parseScriptResponse", () => {
  it("returns token + script when success is absent", () => {
    expect(parseScriptResponse({ t: "tok", s: "<script>" })).toEqual({
      token: "tok",
      script: "<script>",
    });
  });

  it("returns token + script when success is true", () => {
    expect(parseScriptResponse({ t: "tok", s: "<script>", success: true })).toEqual({
      token: "tok",
      script: "<script>",
    });
  });

  it("throws EvinaScriptError with codes on success:false", () => {
    try {
      parseScriptResponse({ success: false, e: ["unknown-transaction-id"] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(EvinaScriptError);
      expect((err as EvinaScriptError).codes).toEqual(["unknown-transaction-id"]);
    }
  });

  it("throws EvinaScriptError without codes when e is absent", () => {
    const err = (() => {
      try {
        parseScriptResponse({ success: false });
        return null;
      } catch (e) {
        return e as EvinaScriptError;
      }
    })();
    expect(err).toBeInstanceOf(EvinaScriptError);
    expect(err?.codes).toEqual([]);
  });

  it("ignores non-string entries in e", () => {
    try {
      parseScriptResponse({ success: false, e: ["a", 1, null, "b"] });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as EvinaScriptError).codes).toEqual(["a", "b"]);
    }
  });

  it("throws when token is missing", () => {
    expect(() => parseScriptResponse({ s: "<script>" })).toThrow(EvinaScriptError);
  });

  it("throws when script is missing", () => {
    expect(() => parseScriptResponse({ t: "tok" })).toThrow(EvinaScriptError);
  });

  it("throws on a non-object response", () => {
    expect(() => parseScriptResponse("nope")).toThrow(EvinaScriptError);
    expect(() => parseScriptResponse(null)).toThrow(EvinaScriptError);
  });
});

// ---------------------------------------------------------------------------
// getScript integration (mock EVINA)
// ---------------------------------------------------------------------------

describe("EvinaClient.getScript — integration", () => {
  it("returns the kit and posts the right request", async () => {
    const mock = installMockEvina(() =>
      jsonResponse({ t: "token-123", s: "<script>kit</script>" }),
    );
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const client = makeClient({ store });

    const result = await client.getScript({ targetSelector: "#subscribe" });

    expect(result.token).toBe("token-123");
    expect(result.script).toBe("<script>kit</script>");
    expect(result.transactionId).toMatch(/^[A-Za-z0-9_-]+$/);

    const req = mock.last();
    expect(req?.url).toBe("https://api.dcbprotect.com/v1/script");
    expect(req?.method).toBe("POST");
    expect(req?.headers["x-evina-apikey"]).toBe(API_KEY);
    expect(req?.params["ti"]).toBe(result.transactionId);
    expect(req?.params["te"]).toBe("#subscribe");
    expect(req?.params["country"]).toBe("LK");
    expect(req?.params["ts"]).toMatch(/^\d+$/);
  });

  it("persists the transaction with a 6h TTL (FR-6)", async () => {
    installMockEvina(() => jsonResponse({ t: "token-xyz", s: "<script>" }));
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const client = makeClient({ store });

    const result = await client.getScript({ targetSelector: "#b", country: "US" });

    const stored = await store.get(result.transactionId);
    expect(stored).not.toBeNull();
    if (stored) {
      expect(stored.token).toBe("token-xyz");
      expect(stored.country).toBe("US");
      expect(stored.expiresAt - stored.createdAt).toBe(TOKEN_TTL_MS);
    }
  });

  it("uses a caller-supplied valid ti", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = makeClient();

    const result = await client.getScript({
      targetSelector: "#b",
      transactionId: "my-transaction-01",
    });

    expect(result.transactionId).toBe("my-transaction-01");
    expect(mock.last()?.params["ti"]).toBe("my-transaction-01");
  });

  it("uses the Cloudflare mirror host when configured", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = makeClient({ useCloudflareForScript: true });

    await client.getScript({ targetSelector: "#b" });

    expect(mock.last()?.url).toBe("https://api.clfldcbprotect.com/v1/script");
  });

  it("accepts (and ignores) permissionList without sending pl (Phase 2)", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = makeClient();

    await client.getScript({ targetSelector: "#b", permissionList: ["partner"] });

    expect(mock.last()?.params["pl"]).toBeUndefined();
  });

  it("rejects an invalid caller-supplied ti before any network call", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = makeClient();

    await expect(
      client.getScript({ targetSelector: "#b", transactionId: "bad id!" }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(mock.requests.length).toBe(0);
  });

  it("throws when no country is available", async () => {
    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      store: new InMemoryTransactionStore({ sweepIntervalMs: 0 }),
    });
    await expect(client.getScript({ targetSelector: "#b" })).rejects.toBeInstanceOf(
      TypeError,
    );
  });

  it("throws when targetSelector is empty", async () => {
    const client = makeClient();
    await expect(client.getScript({ targetSelector: "   " })).rejects.toBeInstanceOf(
      TypeError,
    );
  });

  it("maps success:false to EvinaScriptError with codes", async () => {
    installMockEvina(() => jsonResponse({ success: false, e: ["unknown-transaction-id"] }));
    const client = makeClient();

    await expect(client.getScript({ targetSelector: "#b" })).rejects.toBeInstanceOf(
      EvinaScriptError,
    );
  });

  it("maps a non-200 HTTP status to EvinaScriptError (FR-11)", async () => {
    installMockEvina(() => jsonResponse({}, 500));
    const client = makeClient();

    await expect(client.getScript({ targetSelector: "#b" })).rejects.toBeInstanceOf(
      EvinaScriptError,
    );
  });

  it("propagates a network failure as EvinaTransportError", async () => {
    installMockEvina(() => {
      throw new Error("connection reset");
    });
    const client = makeClient();

    await expect(client.getScript({ targetSelector: "#b" })).rejects.toBeInstanceOf(
      EvinaTransportError,
    );
  });
});
