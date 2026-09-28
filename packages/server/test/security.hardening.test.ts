/**
 * Security hardening test suite — M7
 *
 * Consolidates the security controls that were not yet covered by the
 * per-milestone security suites. Each describe block maps to a specific
 * SRS §8 checklist item, acceptance criterion, or THREAT_MODEL control.
 *
 * Controls verified here:
 *  AC-6 / NFR-SEC-1 / ADR-004 / T-I2
 *    Browser package cannot import server secrets (structural guard).
 *  AC-7 / FR-12 / FR-13 / ADR-008
 *    Same userIdTransform produces the same user_id on /script and /check.
 *  FR-A5 / T-I5
 *    Handler responses never contain the token, API key, username, or raw MSISDN
 *    (extends handlers.test.ts with adversarial inputs).
 *  ADR-006 / NFR-SEC-10
 *    handlers.ts and index.ts introduce no third-party runtime imports.
 *  NFR-SEC-13
 *    SRS §8 security checklist is fully ticked (verified by the test suite
 *    passing as a whole — this file completes the remaining items).
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { EvinaClient } from "../src/client";
import { InMemoryTransactionStore, TOKEN_TTL_MS } from "../src/store";
import { requestScriptHandler, verifyHandler } from "../src/handlers";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";
import type { Logger } from "../src/redact";

const API_KEY = "sk_live_SUPER_SECRET_KEY_M7";
const USERNAME = "owner_secret_username_m7";
const MSISDN = "94771234567";

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// AC-6 / NFR-SEC-1 / ADR-004 / T-I2
// Browser package structural import guard
// ---------------------------------------------------------------------------

describe("SEC: browser package cannot import server secrets (AC-6, NFR-SEC-1, ADR-004)", () => {
  it("browser package source does not import from the server package", async () => {
    const fs = await import("node:fs/promises");
    const src = await fs.readFile(
      new URL("../../browser/src/index.ts", import.meta.url),
      "utf8",
    );

    // Check only actual import statements, not comments.
    const importLines = src
      .split("\n")
      .filter((l) => l.trimStart().startsWith("import "));

    for (const line of importLines) {
      // Any import of the server package by name is a violation.
      expect(line).not.toMatch(/@ideabiz\/evina-sdk/);
      // Any relative import escaping into server/src is a violation.
      expect(line).not.toMatch(/from\s+['"].*packages[/\\]server/);
      expect(line).not.toMatch(/from\s+['"].*[/\\]server[/\\]src/);
    }
  });

  it("browser tsconfig has no node types (structurally cannot use node:crypto or server secrets)", async () => {
    const fs = await import("node:fs/promises");
    const raw = await fs.readFile(
      new URL("../../browser/tsconfig.json", import.meta.url),
      "utf8",
    );
    // Strip single-line comments before parsing (tsconfig allows them).
    const stripped = raw.replace(/\/\/[^\n]*/g, "");
    const tsconfig = JSON.parse(stripped) as {
      compilerOptions?: { types?: string[] };
    };

    // types:[] means no ambient Node types — the browser package cannot
    // accidentally use node:crypto, process.env, or other server-only APIs.
    expect(tsconfig.compilerOptions?.types).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// AC-7 / FR-12 / FR-13 / ADR-008
// Same userIdTransform on /script and /check
// ---------------------------------------------------------------------------

describe("SEC: userIdTransform consistency across /script and /check (AC-7, ADR-008)", () => {
  it("the same MSISDN produces the same user_id on both /script and /check", async () => {
    const calls: string[] = [];
    const transform = (raw: string): string => {
      const result = `H(${raw})`;
      calls.push(result);
      return result;
    };

    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const mock = installMockEvina((req) => {
      if (req.url.includes("/script")) {
        return jsonResponse({ t: "tok", s: "<script>" });
      }
      return jsonResponse({ success: true, ft: 1000 });
    });

    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
      userIdTransform: transform,
    });

    const { transactionId } = await client.getScript({
      targetSelector: "#b",
      userId: MSISDN,
    });
    await client.checkTransaction({ transactionId, userId: MSISDN });

    const scriptReq = mock.requests.find((r) => r.url.includes("/script"));
    const checkReq = mock.requests.find((r) => r.url.includes("/check"));

    // Both calls must send the same transformed value.
    expect(scriptReq?.params["user_id"]).toBe(`H(${MSISDN})`);
    expect(checkReq?.params["user_id"]).toBe(`H(${MSISDN})`);
    expect(scriptReq?.params["user_id"]).toBe(checkReq?.params["user_id"]);

    // The raw MSISDN must not be sent unchanged — the transform was applied.
    expect(scriptReq?.params["user_id"]).not.toBe(MSISDN);
    expect(checkReq?.params["user_id"]).not.toBe(MSISDN);
  });

  it("identity transform (default) sends the same value on both calls", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const mock = installMockEvina((req) => {
      if (req.url.includes("/script")) {
        return jsonResponse({ t: "tok", s: "<script>" });
      }
      return jsonResponse({ success: true, ft: 1000 });
    });

    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
      // No userIdTransform — identity default.
    });

    const { transactionId } = await client.getScript({
      targetSelector: "#b",
      userId: MSISDN,
    });
    await client.checkTransaction({ transactionId, userId: MSISDN });

    const scriptReq = mock.requests.find((r) => r.url.includes("/script"));
    const checkReq = mock.requests.find((r) => r.url.includes("/check"));

    expect(scriptReq?.params["user_id"]).toBe(MSISDN);
    expect(checkReq?.params["user_id"]).toBe(MSISDN);
    expect(scriptReq?.params["user_id"]).toBe(checkReq?.params["user_id"]);
  });
});

// ---------------------------------------------------------------------------
// FR-A5 / T-I5
// Handler responses never leak token, API key, username, or raw MSISDN
// (adversarial: secrets present in the client config, MSISDN in userId input)
// ---------------------------------------------------------------------------

describe("SEC: handler responses never leak secrets or PII (FR-A5, T-I5)", () => {
  function makeClient(): EvinaClient {
    return new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store: new InMemoryTransactionStore({ sweepIntervalMs: 0 }),
    });
  }

  it("requestScriptHandler response body contains no API key, username, or token", async () => {
    installMockEvina(() =>
      jsonResponse({ t: "secret-token-value", s: "<script>kit</script>" }),
    );
    const handler = requestScriptHandler(makeClient());

    const res = await handler({ targetSelector: "#b", userId: MSISDN });
    const serialised = JSON.stringify(res.body);

    expect(serialised).not.toContain(API_KEY);
    expect(serialised).not.toContain(USERNAME);
    expect(serialised).not.toContain("secret-token-value");
  });

  it("requestScriptHandler error body contains no API key or username", async () => {
    installMockEvina(() => jsonResponse({ success: false, e: ["err"] }));
    const handler = requestScriptHandler(makeClient());

    const res = await handler({ targetSelector: "#b" });
    const serialised = JSON.stringify(res.body);

    expect(serialised).not.toContain(API_KEY);
    expect(serialised).not.toContain(USERNAME);
  });

  it("verifyHandler response body contains no API key, username, ft, or token", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const now = Date.now();
    await store.save({
      ti: "tx-m7-sec-00000001",
      token: "secret-token-value",
      country: "LK",
      createdAt: now,
      expiresAt: now + TOKEN_TTL_MS,
    });
    installMockEvina(() =>
      jsonResponse({ success: true, ft: 1000, as: 100, oo: 1 }),
    );
    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
    });
    const handler = verifyHandler(client);

    const res = await handler({ transactionId: "tx-m7-sec-00000001", userId: MSISDN });
    const serialised = JSON.stringify(res.body);

    expect(serialised).not.toContain(API_KEY);
    expect(serialised).not.toContain(USERNAME);
    expect(serialised).not.toContain("secret-token-value");
    // ft must not appear in the response body (FR-A5, FR-29).
    expect(res.body).not.toHaveProperty("ft");
    // raw MSISDN must not appear.
    expect(serialised).not.toContain(MSISDN);
  });

  it("verifyHandler logs a PII-safe warn on fail-open, not leaking secrets", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    const now = Date.now();
    await store.save({
      ti: "tx-m7-sec-00000002",
      token: "tok",
      country: "LK",
      createdAt: now,
      expiresAt: now + TOKEN_TTL_MS,
    });
    installMockEvina(() => jsonResponse({}, 500));

    const warns: string[] = [];
    const logger: Logger = {
      debug: () => undefined,
      info: () => undefined,
      warn: (m, meta) => warns.push(m + " " + JSON.stringify(meta ?? {})),
      error: () => undefined,
    };

    const client = new EvinaClient({
      apiKey: API_KEY,
      username: USERNAME,
      defaultCountry: "LK",
      store,
      logger,
    });
    const handler = verifyHandler(client);

    const res = await handler({
      transactionId: "tx-m7-sec-00000002",
      userId: MSISDN,
    });

    // Handler still returns 200 allowed:true (fail-open).
    expect(res.status).toBe(200);
    expect((res.body as { allowed: boolean }).allowed).toBe(true);

    // Warn log must exist and must be PII-safe.
    expect(warns.length).toBeGreaterThan(0);
    for (const line of warns) {
      expect(line).not.toContain(API_KEY);
      expect(line).not.toContain(USERNAME);
      expect(line).not.toContain(MSISDN);
    }
  });
});

// ---------------------------------------------------------------------------
// ADR-006 / NFR-SEC-10
// handlers.ts and index.ts introduce no third-party runtime imports
// ---------------------------------------------------------------------------

describe("ADR-006: handlers.ts and index.ts have no third-party runtime imports", () => {
  async function getImportLines(filename: string): Promise<string[]> {
    const fs = await import("node:fs/promises");
    const src = await fs.readFile(
      new URL(`../src/${filename}`, import.meta.url),
      "utf8",
    );
    return src
      .split("\n")
      .filter((l) => l.trimStart().startsWith("import "));
  }

  function assertNoThirdParty(lines: string[], filename: string): void {
    for (const line of lines) {
      const isRelative =
        /from\s+['"]\.\//u.test(line) || /from\s+['"]\.\.\//u.test(line);
      const isNodeBuiltin = /from\s+['"]node:/u.test(line);
      // Type-only imports with no runtime footprint are also fine.
      const isTypeOnly = /import\s+type\s+/u.test(line);
      expect(
        isRelative || isNodeBuiltin || isTypeOnly,
        `Unexpected third-party import in ${filename}: ${line}`,
      ).toBe(true);
    }
  }

  it("handlers.ts has no third-party imports", async () => {
    const lines = await getImportLines("handlers.ts");
    assertNoThirdParty(lines, "handlers.ts");
  });

  it("index.ts has no third-party imports", async () => {
    const lines = await getImportLines("index.ts");
    assertNoThirdParty(lines, "index.ts");
  });
});
