/**
 * Unit tests for the v1 signature module (ADR-015). Pure + deterministic —
 * no network. Verifies the SHA-256(username + queryString + password) contract
 * and that signQuery appends s= over the exact preceding query string.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { buildQueryString, computeSignature, signQuery } from "../src/sign";

const sha256hex = (s: string): string =>
  createHash("sha256").update(s, "utf8").digest("hex");

describe("buildQueryString", () => {
  it("percent-encodes values (e.g. # -> %23)", () => {
    expect(buildQueryString({ te: "#cta" })).toBe("te=%23cta");
  });

  it("preserves insertion order", () => {
    const qs = buildQueryString({ ti: "abc", te: "#x", ts: "1", country: "LK" });
    expect(qs).toBe("ti=abc&te=%23x&ts=1&country=LK");
  });
});

describe("computeSignature", () => {
  it("is SHA-256(username + queryString + password) as lowercase hex", () => {
    const sig = computeSignature("user", "ti=1&ts=2", "secret");
    expect(sig).toBe(sha256hex("userti=1&ts=2secret"));
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes when any input changes", () => {
    const base = computeSignature("user", "ti=1", "secret");
    expect(computeSignature("user2", "ti=1", "secret")).not.toBe(base);
    expect(computeSignature("user", "ti=2", "secret")).not.toBe(base);
    expect(computeSignature("user", "ti=1", "secret2")).not.toBe(base);
  });
});

describe("signQuery", () => {
  it("appends s= computed over the preceding query string", () => {
    const params = { ti: "abc", ts: "100" };
    const out = signQuery(params, "user", "secret");
    const qs = "ti=abc&ts=100";
    const expected = `${qs}&s=${sha256hex(`user${qs}secret`)}`;
    expect(out).toBe(expected);
  });

  it("does not include the password in the output", () => {
    const out = signQuery({ ti: "abc" }, "user", "supersecret");
    expect(out).not.toContain("supersecret");
  });
});
