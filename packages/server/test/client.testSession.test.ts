/**
 * test_session unit + integration tests — M6 (FR-19, FR-20).
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { EvinaClient, parseTestSession, withEtsid } from "../src/client";
import { EvinaTestSessionError, EvinaTransportError } from "../src/errors";
import { InMemoryTransactionStore } from "../src/store";
import { installMockEvina, jsonResponse } from "./helpers/mockEvina";

const USERNAME = "test-username";
const PASSWORD = "test-signature-secret";

// test_session is signature-based (ADR-015), so the client must use v1 mode.
function makeClient(): EvinaClient {
  return new EvinaClient({
    authMode: "v1-signature",
    username: USERNAME,
    password: PASSWORD,
    defaultCountry: "LK",
    store: new InMemoryTransactionStore({ sweepIntervalMs: 0 }),
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("withEtsid (FR-20)", () => {
  it("appends etsid to a plain URL", () => {
    expect(withEtsid("https://site.example/pay", "ETS123")).toBe(
      "https://site.example/pay?etsid=ETS123",
    );
  });

  it("preserves an existing query string", () => {
    const out = withEtsid("https://site.example/pay?a=1", "E2");
    expect(out).toContain("a=1");
    expect(out).toContain("etsid=E2");
  });

  it("URL-encodes the etsid value", () => {
    expect(withEtsid("https://site.example/pay", "a b")).toContain("etsid=a+b");
  });

  it("replaces an existing etsid rather than duplicating it", () => {
    const out = withEtsid("https://site.example/pay?etsid=old", "new");
    expect(out).toContain("etsid=new");
    expect(out).not.toContain("old");
  });

  it("throws on an invalid URL", () => {
    expect(() => withEtsid("not a url", "x")).toThrow(TypeError);
  });
});

describe("parseTestSession (FR-19)", () => {
  it("parses a valid response", () => {
    expect(parseTestSession({ etsid: "E1", ft: 2100, username: "acct", role: "session" })).toEqual({
      etsid: "E1",
      ft: 2100,
      username: "acct",
    });
  });

  it("throws with codes when etsid is absent and e is present", () => {
    try {
      parseTestSession({ e: ["invalid-ft"] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(EvinaTestSessionError);
      expect((err as EvinaTestSessionError).codes).toEqual(["invalid-ft"]);
    }
  });

  it("throws without codes when the response is empty", () => {
    expect(() => parseTestSession({})).toThrow(EvinaTestSessionError);
  });

  it("throws when ft is not an integer", () => {
    expect(() => parseTestSession({ etsid: "E", ft: "x", username: "a" })).toThrow(
      EvinaTestSessionError,
    );
  });

  it("throws when username is missing", () => {
    expect(() => parseTestSession({ etsid: "E", ft: 1000 })).toThrow(
      EvinaTestSessionError,
    );
  });

  it("throws on a non-object response", () => {
    expect(() => parseTestSession(null)).toThrow(EvinaTestSessionError);
  });
});

describe("EvinaClient.createTestSession — integration", () => {
  it("posts ft+ts and returns the parsed session", async () => {
    const mock = installMockEvina(() =>
      jsonResponse({ etsid: "ETS1", ft: 2100, username: "acct", role: "session" }),
    );
    const client = makeClient();

    const session = await client.createTestSession(2100);

    expect(session).toEqual({ etsid: "ETS1", ft: 2100, username: "acct" });
    const req = mock.last();
    // v1-signature (ADR-015): GET /{username}/test_session?ft=..&ts=..&s=..
    expect(req?.method).toBe("GET");
    const url = new URL(req?.url ?? "");
    expect(`${url.origin}${url.pathname}`).toBe(
      `https://api.dcbprotect.com/${USERNAME}/test_session`,
    );
    expect(url.searchParams.get("ft")).toBe("2100");
    expect(url.searchParams.get("ts")).toMatch(/^\d+$/);
    // A signature is present and is a 64-char hex SHA-256 digest.
    expect(url.searchParams.get("s")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a non-integer ft with TypeError", async () => {
    const client = makeClient();
    await expect(client.createTestSession(1.5)).rejects.toBeInstanceOf(TypeError);
  });

  it("propagates a non-200 as EvinaTransportError", async () => {
    installMockEvina(() => jsonResponse({}, 500));
    const client = makeClient();
    await expect(client.createTestSession(1000)).rejects.toBeInstanceOf(
      EvinaTransportError,
    );
  });

  it("throws EvinaTestSessionError on a failed session response", async () => {
    installMockEvina(() => jsonResponse({ e: ["not-allowed"] }));
    const client = makeClient();
    await expect(client.createTestSession(1000)).rejects.toBeInstanceOf(
      EvinaTestSessionError,
    );
  });
});
