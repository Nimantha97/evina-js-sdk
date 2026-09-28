/**
 * Redaction unit tests — M2
 *
 * Covers:
 *  NFR-SEC-2 / T-I1   Secrets are blanked out of strings and nested structures.
 *  NFR-SEC-4 / T-I3   MSISDN-like values are masked (never logged in the clear).
 *  T-E2               Object walking is prototype-pollution safe and cycle-safe.
 *  ADR-013            NOOP_LOGGER + createRedactingLogger behaviour.
 */

import { describe, it, expect, vi } from "vitest";
import {
  redact,
  maskMsisdns,
  NOOP_LOGGER,
  createRedactingLogger,
  type Logger,
} from "../src/redact";

describe("maskMsisdns", () => {
  it("masks an 11-digit MSISDN keeping only the last two digits", () => {
    expect(maskMsisdns("94771234567")).toBe("*********67");
  });

  it("masks a MSISDN embedded in a sentence", () => {
    expect(maskMsisdns("charged user 94771234567 ok")).toBe(
      "charged user *********67 ok",
    );
  });

  it("masks a MSISDN with a leading + (plus is not a kept digit)", () => {
    // 11 digits after the +, last two visible.
    expect(maskMsisdns("+94771234567")).toBe("*********67");
  });

  it("leaves short digit runs (< 7) untouched", () => {
    expect(maskMsisdns("status 500 retry 3")).toBe("status 500 retry 3");
  });

  it("does not mask when there are no digit runs", () => {
    expect(maskMsisdns("no numbers here")).toBe("no numbers here");
  });
});

describe("redact — secrets", () => {
  it("replaces a secret occurring in a string", () => {
    const out = redact("key is sk_live_abc123", ["sk_live_abc123"]);
    expect(out).toBe("key is ***REDACTED***");
  });

  it("replaces every occurrence of a secret", () => {
    const out = redact("sk_live_abc sk_live_abc", ["sk_live_abc"]);
    expect(out).toBe("***REDACTED*** ***REDACTED***");
  });

  it("treats secrets literally even if they contain regex metacharacters", () => {
    const secret = "a.b*c+d";
    const out = redact(`prefix ${secret} suffix`, [secret]);
    expect(out).toBe("prefix ***REDACTED*** suffix");
  });

  it("ignores empty-string secrets", () => {
    expect(redact("unchanged", [""])).toBe("unchanged");
  });

  it("masks secret and MSISDN together", () => {
    const out = redact("key sk_live_x for 94771234567", ["sk_live_x"]);
    expect(out).toBe("key ***REDACTED*** for *********67");
  });
});

describe("redact — primitives", () => {
  it("passes through null and undefined", () => {
    expect(redact(null)).toBeNull();
    expect(redact(undefined)).toBeUndefined();
  });

  it("passes through booleans", () => {
    expect(redact(true)).toBe(true);
    expect(redact(false)).toBe(false);
  });

  it("passes through small numbers", () => {
    expect(redact(42)).toBe(42);
    expect(redact(500)).toBe(500);
  });

  it("passes through non-integer numbers", () => {
    expect(redact(3.14)).toBe(3.14);
  });

  it("masks an MSISDN-length integer", () => {
    expect(redact(94771234567)).toBe("*********67");
  });

  it("masks a bigint that looks like an MSISDN", () => {
    expect(redact(94771234567n)).toBe("*********67");
  });

  it("replaces functions with a placeholder", () => {
    expect(redact(() => "x")).toBe("[Function]");
  });

  it("replaces symbols with a placeholder", () => {
    expect(redact(Symbol("s"))).toBe("[Symbol]");
  });
});

describe("redact — structures", () => {
  it("redacts nested object values", () => {
    const out = redact(
      { user: { msisdn: "94771234567", note: "ok" }, key: "secret" },
      ["secret"],
    );
    expect(out).toEqual({
      user: { msisdn: "*********67", note: "ok" },
      key: "***REDACTED***",
    });
  });

  it("redacts array elements", () => {
    const out = redact(["94771234567", "keep", "secret"], ["secret"]);
    expect(out).toEqual(["*********67", "keep", "***REDACTED***"]);
  });

  it("does not mutate the input object", () => {
    const input = { msisdn: "94771234567" };
    redact(input);
    expect(input.msisdn).toBe("94771234567");
  });

  it("summarizes Error objects with a redacted message", () => {
    const out = redact(new Error("failed for 94771234567")) as {
      name: string;
      message: string;
    };
    expect(out.name).toBe("Error");
    expect(out.message).toBe("failed for *********67");
  });

  it("handles circular references safely", () => {
    const a: Record<string, unknown> = { name: "a" };
    a["self"] = a;
    const out = redact(a) as Record<string, unknown>;
    expect(out["name"]).toBe("a");
    expect(out["self"]).toBe("[Circular]");
  });

  it("stops at max depth", () => {
    // Build a structure deeper than MAX_DEPTH (8).
    let deep: Record<string, unknown> = { value: "leaf" };
    for (let i = 0; i < 12; i++) {
      deep = { nested: deep };
    }
    // Should not throw and should terminate.
    expect(() => redact(deep)).not.toThrow();
  });
});

describe("redact — prototype pollution safety (T-E2)", () => {
  it("does not copy __proto__ / constructor / prototype keys", () => {
    const malicious = JSON.parse(
      '{"__proto__":{"polluted":true},"constructor":{"bad":1},"safe":"ok"}',
    ) as Record<string, unknown>;

    const out = redact(malicious) as Record<string, unknown>;

    expect(out["safe"]).toBe("ok");
    // The dangerous keys were skipped; Object.prototype is untouched.
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(false);
  });
});

describe("NOOP_LOGGER", () => {
  it("exposes all four methods that return undefined", () => {
    expect(NOOP_LOGGER.debug("m")).toBeUndefined();
    expect(NOOP_LOGGER.info("m")).toBeUndefined();
    expect(NOOP_LOGGER.warn("m")).toBeUndefined();
    expect(NOOP_LOGGER.error("m", { a: 1 })).toBeUndefined();
  });
});

describe("createRedactingLogger", () => {
  function spySink(): Logger & {
    calls: Array<[string, string, object | undefined]>;
  } {
    const calls: Array<[string, string, object | undefined]> = [];
    return {
      calls,
      debug: (m, meta) => calls.push(["debug", m, meta]),
      info: (m, meta) => calls.push(["info", m, meta]),
      warn: (m, meta) => calls.push(["warn", m, meta]),
      error: (m, meta) => calls.push(["error", m, meta]),
    };
  }

  it("redacts the secret in the message before forwarding", () => {
    const sink = spySink();
    const log = createRedactingLogger(sink, ["sk_live_secret"]);
    log.info("using sk_live_secret now");
    expect(sink.calls[0]).toEqual(["info", "using ***REDACTED*** now", undefined]);
  });

  it("masks MSISDNs in the message", () => {
    const sink = spySink();
    const log = createRedactingLogger(sink);
    log.warn("charged 94771234567");
    expect(sink.calls[0]?.[1]).toBe("charged *********67");
  });

  it("redacts secrets and MSISDNs in the meta object", () => {
    const sink = spySink();
    const log = createRedactingLogger(sink, ["sk_live_secret"]);
    log.error("failure", { apiKey: "sk_live_secret", user: "94771234567" });
    expect(sink.calls[0]?.[2]).toEqual({
      apiKey: "***REDACTED***",
      user: "*********67",
    });
  });

  it("forwards each level to the matching sink method", () => {
    const sink = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const log = createRedactingLogger(sink);
    log.debug("d");
    log.info("i");
    log.warn("w");
    log.error("e");
    expect(sink.debug).toHaveBeenCalledWith("d");
    expect(sink.info).toHaveBeenCalledWith("i");
    expect(sink.warn).toHaveBeenCalledWith("w");
    expect(sink.error).toHaveBeenCalledWith("e");
  });

  it("filters out empty-string secrets without masking everything", () => {
    const sink = spySink();
    const log = createRedactingLogger(sink, [""]);
    log.info("plain message");
    expect(sink.calls[0]?.[1]).toBe("plain message");
  });
});
