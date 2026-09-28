/**
 * Security test suite — M4 getScript
 *
 * Controls verified:
 *  ADR-002            API key is sent ONLY as the X-EVINA-APIKEY header, never
 *                     in the URL or body.
 *  NFR-SEC-2 / T-I1   No secret (apiKey/username) appears in thrown errors.
 *  NFR-SEC-4 / T-I3   The raw user_id (MSISDN) is never written to any log.
 *  NFR-SEC-7          Hostile / oversized ti is rejected before any network I/O.
 *  ADR-008            userIdTransform is applied to user_id before sending.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { EvinaClient } from "../src/client";
import { EvinaScriptError } from "../src/errors";
import { InMemoryTransactionStore } from "../src/store";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";
import type { Logger } from "../src/redact";

const API_KEY = "sk_live_SUPER_SECRET_KEY";
const USERNAME = "owner_secret_username";
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

describe("SEC: API key only in the header (ADR-002)", () => {
  it("sends X-EVINA-APIKEY and never puts the key in the URL or body", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = makeClient();

    await client.getScript({ targetSelector: "#b", userId: MSISDN });

    const req = mock.last();
    expect(req?.headers["x-evina-apikey"]).toBe(API_KEY);
    expect(req?.url).not.toContain(API_KEY);
    // No param value should equal the secret key.
    for (const value of Object.values(req?.params ?? {})) {
      expect(value).not.toBe(API_KEY);
    }
  });
});

describe("SEC: secret-free errors (NFR-SEC-2, T-I1)", () => {
  it("EvinaScriptError from success:false carries no secret", async () => {
    installMockEvina(() => jsonResponse({ success: false, e: ["some-error"] }));
    const client = makeClient();

    try {
      await client.getScript({ targetSelector: "#b", userId: MSISDN });
      throw new Error("expected throw");
    } catch (err) {
      const msg = (err as EvinaScriptError).message;
      expect(msg).not.toContain(API_KEY);
      expect(msg).not.toContain(USERNAME);
      expect(msg).not.toContain(MSISDN);
    }
  });

  it("EvinaScriptError from non-200 carries no secret", async () => {
    installMockEvina(() => jsonResponse({}, 403));
    const client = makeClient();

    try {
      await client.getScript({ targetSelector: "#b" });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as Error).message).not.toContain(API_KEY);
    }
  });
});

describe("SEC: raw MSISDN never logged (NFR-SEC-4, T-I3)", () => {
  it("no log line or meta contains the raw user_id", async () => {
    installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));

    const logLines: string[] = [];
    const capturingLogger: Logger = {
      debug: (m, meta) => logLines.push(m + JSON.stringify(meta ?? {})),
      info: (m, meta) => logLines.push(m + JSON.stringify(meta ?? {})),
      warn: (m, meta) => logLines.push(m + JSON.stringify(meta ?? {})),
      error: (m, meta) => logLines.push(m + JSON.stringify(meta ?? {})),
    };

    const client = makeClient(capturingLogger);
    await client.getScript({ targetSelector: "#b", userId: MSISDN });

    for (const line of logLines) {
      expect(line).not.toContain(MSISDN);
    }
  });
});

describe("SEC: hostile ti rejected pre-network (NFR-SEC-7)", () => {
  it("rejects a path-traversal ti without contacting EVINA", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = makeClient();

    await expect(
      client.getScript({ targetSelector: "#b", transactionId: "../../etc/passwd" }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(mock.requests.length).toBe(0);
  });

  it("rejects an oversized ti", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = makeClient();

    await expect(
      client.getScript({ targetSelector: "#b", transactionId: "a".repeat(500) }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(mock.requests.length).toBe(0);
  });
});

describe("SEC: userIdTransform applied (ADR-008)", () => {
  it("the raw MSISDN is not sent when a transform is configured", async () => {
    const mock = installMockEvina(() => jsonResponse({ t: "tok", s: "<script>" }));
    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store: new InMemoryTransactionStore({ sweepIntervalMs: 0 }),
      userIdTransform: (raw) => `sha256:${raw.length}`,
    });

    await client.getScript({ targetSelector: "#b", userId: MSISDN });

    const sent = mock.last()?.params["user_id"];
    expect(sent).toBe("sha256:11");
    expect(sent).not.toContain(MSISDN);
  });
});
