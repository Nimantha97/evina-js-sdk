/**
 * Transaction id unit tests — M4 (FR-5, NFR-SEC-7).
 */

import { describe, it, expect } from "vitest";
import {
  generateTransactionId,
  isValidTransactionId,
  assertValidTransactionId,
  TI_MIN_LENGTH,
  TI_MAX_LENGTH,
} from "../src/ti";

describe("generateTransactionId", () => {
  it("returns a valid UUID v4 that passes validation", () => {
    const ti = generateTransactionId();
    expect(ti).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(isValidTransactionId(ti)).toBe(true);
  });

  it("returns unique ids", () => {
    expect(generateTransactionId()).not.toBe(generateTransactionId());
  });
});

describe("isValidTransactionId", () => {
  it("accepts alphanumerics, hyphen and underscore within bounds", () => {
    expect(isValidTransactionId("abc-123_XYZ")).toBe(true);
  });

  it("accepts the minimum and maximum lengths", () => {
    expect(isValidTransactionId("a".repeat(TI_MIN_LENGTH))).toBe(true);
    expect(isValidTransactionId("a".repeat(TI_MAX_LENGTH))).toBe(true);
  });

  it("rejects a too-short id", () => {
    expect(isValidTransactionId("a".repeat(TI_MIN_LENGTH - 1))).toBe(false);
  });

  it("rejects a too-long id", () => {
    expect(isValidTransactionId("a".repeat(TI_MAX_LENGTH + 1))).toBe(false);
  });

  it("rejects disallowed characters (injection guard)", () => {
    expect(isValidTransactionId("abc 123")).toBe(false); // space
    expect(isValidTransactionId("abc/../123")).toBe(false); // path traversal
    expect(isValidTransactionId("abc#frag")).toBe(false); // fragment
    expect(isValidTransactionId("abc<script>")).toBe(false);
  });

  it("rejects non-string values", () => {
    expect(isValidTransactionId(12345678)).toBe(false);
    expect(isValidTransactionId(null)).toBe(false);
    expect(isValidTransactionId(undefined)).toBe(false);
  });
});

describe("assertValidTransactionId", () => {
  it("does not throw for a valid id", () => {
    expect(() => {
      assertValidTransactionId("valid-transaction-id");
    }).not.toThrow();
  });

  it("throws TypeError for an invalid id", () => {
    expect(() => {
      assertValidTransactionId("bad id!");
    }).toThrow(TypeError);
  });

  it("error message never echoes the offending value", () => {
    try {
      assertValidTransactionId("secret-looking-../../etc/passwd");
      throw new Error("expected to throw");
    } catch (e) {
      expect((e as Error).message).not.toContain("passwd");
    }
  });
});
