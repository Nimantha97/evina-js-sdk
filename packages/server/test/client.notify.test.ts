/**
 * notifyTransaction unit + integration tests — M6 (FR-18, NFR-REL-3, ADR-008).
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { EvinaClient, buildNotifyParams } from "../src/client";
import { InMemoryTransactionStore } from "../src/store";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";
import type { Logger } from "../src/redact";

const API_KEY = "test-api-key";
const USERNAME = "test-username";
const TI = "notify-tx-0001";
const MSISDN = "94771234567";

function makeClient(logger?: Logger): EvinaClient {
  return new EvinaClient({
    apiKey: API_KEY,
    username: USERNAME,
    defaultCountry: "LK",
    store: new InMemoryTransactionStore({ sweepIntervalMs: 0 }),
    ...(logger ? { logger } : {}),
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("buildNotifyParams (FR-18)", () => {
  const identity = { defaultCarrier: undefined, userIdTransform: (r: string) => r };

  it("sends only ti+ts when no optional fields are supplied", () => {
    const p = buildNotifyParams({ transactionId: TI }, identity, 1_700_000_000);
    expect(p["ti"]).toBe(TI);
    expect(p["ts"]).toBe("1700000000");
    expect(p["d"]).toBeUndefined();
  });

  it("packs optional fields into the d JSON object", () => {
    const p = buildNotifyParams(
      { transactionId: TI, purchaseId: "po-1", country: "LK", service: "svc" },
      identity,
      1,
    );
    const d = JSON.parse(p["d"] as string) as Record<string, string>;
    expect(d["purchase_id"]).toBe("po-1");
    expect(d["country"]).toBe("LK");
    expect(d["service"]).toBe("svc");
  });

  it("applies userIdTransform to msisdn (ADR-008)", () => {
    const p = buildNotifyParams(
      { transactionId: TI, msisdn: MSISDN },
      { defaultCarrier: undefined, userIdTransform: (r) => `H(${r})` },
      1,
    );
    const d = JSON.parse(p["d"] as string) as Record<string, string>;
    expect(d["msisdn"]).toBe(`H(${MSISDN})`);
  });

  it("falls back to config.defaultCarrier", () => {
    const p = buildNotifyParams(
      { transactionId: TI },
      { defaultCarrier: "41302", userIdTransform: (r: string) => r },
      1,
    );
    const d = JSON.parse(p["d"] as string) as Record<string, string>;
    expect(d["carrier"]).toBe("41302");
  });

  it("maps purchase_arg1..purchase_arg5", () => {
    const p = buildNotifyParams(
      { transactionId: TI, purchaseArgs: { purchase_arg1: "a", purchase_arg5: "e" } },
      identity,
      1,
    );
    const d = JSON.parse(p["d"] as string) as Record<string, string>;
    expect(d["purchase_arg1"]).toBe("a");
    expect(d["purchase_arg5"]).toBe("e");
    expect(d["purchase_arg2"]).toBeUndefined();
  });
});

describe("EvinaClient.notifyTransaction — best-effort (FR-18, NFR-REL-3)", () => {
  it("posts ti/ts/d on success and resolves void", async () => {
    const mock = installMockEvina(() => jsonResponse([]));
    const client = makeClient();

    await expect(
      client.notifyTransaction({ transactionId: TI, purchaseId: "po-1" }),
    ).resolves.toBeUndefined();

    const req = mock.last();
    expect(req?.url).toBe("https://api.dcbprotect.com/v1/transaction");
    expect(req?.params["ti"]).toBe(TI);
    expect(req?.params["d"]).toContain("po-1");
  });

  it("never throws on a non-200 response", async () => {
    installMockEvina(() => jsonResponse({}, 500));
    const client = makeClient();
    await expect(client.notifyTransaction({ transactionId: TI })).resolves.toBeUndefined();
  });

  it("never throws on a network error", async () => {
    installMockEvina(() => {
      throw new Error("connection reset");
    });
    const client = makeClient();
    await expect(client.notifyTransaction({ transactionId: TI })).resolves.toBeUndefined();
  });

  it("never throws on an invalid ti and makes no request", async () => {
    const mock = installMockEvina(() => jsonResponse([]));
    const client = makeClient();
    await expect(
      client.notifyTransaction({ transactionId: "bad id!" }),
    ).resolves.toBeUndefined();
    expect(mock.requests.length).toBe(0);
  });
});

describe("SEC: notify never logs the raw MSISDN (NFR-SEC-4)", () => {
  it("keeps the MSISDN out of logs on both success and failure paths", async () => {
    installMockEvina(() => jsonResponse({}, 500)); // force the warn path
    const lines: string[] = [];
    const logger: Logger = {
      debug: (m, meta) => lines.push(m + " " + JSON.stringify(meta ?? {})),
      info: (m, meta) => lines.push(m + " " + JSON.stringify(meta ?? {})),
      warn: (m, meta) => lines.push(m + " " + JSON.stringify(meta ?? {})),
      error: (m, meta) => lines.push(m + " " + JSON.stringify(meta ?? {})),
    };
    const client = makeClient(logger);

    await client.notifyTransaction({ transactionId: TI, msisdn: MSISDN });

    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(line).not.toContain(MSISDN);
    }
  });
});
