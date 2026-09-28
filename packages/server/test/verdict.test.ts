/**
 * Verdict unit tests — M5 (FR-14, FR-15, FR-17).
 *
 * Pure functions: exhaustive band coverage + defensive parsing.
 */

import { describe, it, expect } from "vitest";
import { mapFtToCategory, evaluateVerdict, AUTHENTIC_MIN, AUTHENTIC_MAX } from "../src/verdict";

describe("mapFtToCategory", () => {
  it("maps each documented band (EVINA_API_FACTS §7)", () => {
    expect(mapFtToCategory(1000)).toBe("authentic");
    expect(mapFtToCategory(1999)).toBe("authentic");
    expect(mapFtToCategory(2100)).toBe("fraud");
    expect(mapFtToCategory(3100)).toBe("accidental");
    expect(mapFtToCategory(4102)).toBe("error");
    expect(mapFtToCategory(5101)).toBe("bot");
    expect(mapFtToCategory(6201)).toBe("custom");
  });

  it("returns unknown for out-of-range / undocumented codes", () => {
    expect(mapFtToCategory(999)).toBe("unknown");
    expect(mapFtToCategory(7000)).toBe("unknown");
    expect(mapFtToCategory(0)).toBe("unknown");
  });

  it("returns unknown for null and non-integers", () => {
    expect(mapFtToCategory(null)).toBe("unknown");
    expect(mapFtToCategory(1500.5)).toBe("unknown");
    expect(mapFtToCategory(Number.NaN)).toBe("unknown");
  });

  it("boundary constants match the allow band", () => {
    expect(AUTHENTIC_MIN).toBe(1000);
    expect(AUTHENTIC_MAX).toBe(1999);
  });
});

describe("evaluateVerdict — allow", () => {
  it("allows a clean authentic response", () => {
    const v = evaluateVerdict({ success: true, ft: 1000, as: 100, oo: 1 });
    expect(v.allowed).toBe(true);
    expect(v.category).toBe("authentic");
    expect(v.ft).toBe(1000);
    expect(v.authenticityScore).toBe(100);
    expect(v.opinion).toBe(1);
    expect(v.success).toBe(true);
    expect(v.reason).toBe("authentic (ft=1000)");
    expect(v.failOpen).toBeUndefined();
  });

  it("allows at both edges of the authentic band", () => {
    expect(evaluateVerdict({ success: true, ft: 1000 }).allowed).toBe(true);
    expect(evaluateVerdict({ success: true, ft: 1999 }).allowed).toBe(true);
  });
});

describe("evaluateVerdict — block", () => {
  it("blocks fraud", () => {
    const v = evaluateVerdict({ success: true, ft: 2100, as: 5, oo: 0 });
    expect(v.allowed).toBe(false);
    expect(v.category).toBe("fraud");
    expect(v.opinion).toBe(0);
    expect(v.reason).toBe("fraud (ft=2100)");
  });

  it("blocks just outside the authentic band", () => {
    expect(evaluateVerdict({ success: true, ft: 999 }).allowed).toBe(false);
    expect(evaluateVerdict({ success: true, ft: 2000 }).allowed).toBe(false);
  });

  it("blocks when success is false even if ft is authentic", () => {
    const v = evaluateVerdict({ success: false, ft: 1000 });
    expect(v.allowed).toBe(false);
    expect(v.success).toBe(false);
  });

  it("blocks and reports codes when success is false with e", () => {
    const v = evaluateVerdict({ success: false, e: ["bad-request"] });
    expect(v.allowed).toBe(false);
    expect(v.reason).toBe("check unsuccessful: bad-request");
  });

  it("blocks with 'no fraud code returned' when success but ft missing", () => {
    const v = evaluateVerdict({ success: true });
    expect(v.allowed).toBe(false);
    expect(v.ft).toBeNull();
    expect(v.reason).toBe("no fraud code returned");
  });
});

describe("evaluateVerdict — defensive parsing", () => {
  it("handles a non-object response", () => {
    const v = evaluateVerdict("garbage");
    expect(v.allowed).toBe(false);
    expect(v.success).toBe(false);
    expect(v.ft).toBeNull();
    expect(v.category).toBe("unknown");
  });

  it("handles null", () => {
    expect(evaluateVerdict(null).allowed).toBe(false);
  });

  it("nulls a non-integer ft and non-0/1 opinion", () => {
    const v = evaluateVerdict({ success: true, ft: "1000", as: "x", oo: 2 });
    expect(v.ft).toBeNull();
    expect(v.authenticityScore).toBeNull();
    expect(v.opinion).toBeNull();
    expect(v.allowed).toBe(false);
  });

  it("preserves the raw response", () => {
    const raw = { success: true, ft: 1000 };
    expect(evaluateVerdict(raw).raw).toBe(raw);
  });
});
