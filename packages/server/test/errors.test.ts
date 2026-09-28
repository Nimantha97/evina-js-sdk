/**
 * Error hierarchy tests — M1
 *
 * Verifies the typed error classes: correct names, instanceof chains,
 * statusCode on EvinaTransportError, codes arrays on Script/Check errors,
 * and that prototype chains survive transpilation.
 *
 * Satisfies: FR-27, NFR-SEC-2 (errors carry no secrets by construction).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  EvinaError,
  EvinaTransportError,
  EvinaConfigError,
  EvinaScriptError,
  EvinaCheckError,
} from "../src/errors";
import { httpPostForm } from "../src/transport";

describe("EvinaError (base)", () => {
  it("sets the correct name", () => {
    const e = new EvinaError("test");
    expect(e.name).toBe("EvinaError");
  });

  it("is an instance of Error", () => {
    expect(new EvinaError("x")).toBeInstanceOf(Error);
  });
});

describe("EvinaTransportError", () => {
  it("is instanceof EvinaError and Error", () => {
    const e = new EvinaTransportError("transport fail");
    expect(e).toBeInstanceOf(EvinaError);
    expect(e).toBeInstanceOf(Error);
  });

  it("sets statusCode when provided", () => {
    const e = new EvinaTransportError("fail", 503);
    expect(e.statusCode).toBe(503);
  });

  it("statusCode is undefined when not provided", () => {
    const e = new EvinaTransportError("fail");
    expect(e.statusCode).toBeUndefined();
  });

  it("sets the correct name", () => {
    expect(new EvinaTransportError("x").name).toBe("EvinaTransportError");
  });
});

describe("EvinaConfigError", () => {
  it("is instanceof EvinaError and Error", () => {
    const e = new EvinaConfigError("bad config");
    expect(e).toBeInstanceOf(EvinaError);
    expect(e).toBeInstanceOf(Error);
  });

  it("sets the correct name", () => {
    expect(new EvinaConfigError("x").name).toBe("EvinaConfigError");
  });
});

describe("EvinaScriptError", () => {
  it("is instanceof EvinaError and Error", () => {
    const e = new EvinaScriptError("script fail");
    expect(e).toBeInstanceOf(EvinaError);
    expect(e).toBeInstanceOf(Error);
  });

  it("stores error codes", () => {
    const e = new EvinaScriptError("fail", ["unknown-transaction-id"]);
    expect(e.codes).toEqual(["unknown-transaction-id"]);
  });

  it("defaults codes to empty array", () => {
    expect(new EvinaScriptError("fail").codes).toEqual([]);
  });

  it("sets the correct name", () => {
    expect(new EvinaScriptError("x").name).toBe("EvinaScriptError");
  });
});

describe("EvinaCheckError", () => {
  it("is instanceof EvinaError and Error", () => {
    const e = new EvinaCheckError("check fail");
    expect(e).toBeInstanceOf(EvinaError);
    expect(e).toBeInstanceOf(Error);
  });

  it("stores error codes", () => {
    const e = new EvinaCheckError("fail", ["expired-token"]);
    expect(e.codes).toEqual(["expired-token"]);
  });

  it("defaults codes to empty array", () => {
    expect(new EvinaCheckError("fail").codes).toEqual([]);
  });

  it("sets the correct name", () => {
    expect(new EvinaCheckError("x").name).toBe("EvinaCheckError");
  });
});

// ---------------------------------------------------------------------------
// Transport: null body path (line 221 in transport.ts)
// ---------------------------------------------------------------------------

describe("httpPostForm: null response body", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("handles a response with null body (returns empty string → JSON parse error)", async () => {
    // A Response with body: null — simulates a 200 with no body stream.
    const resp = new Response(null, { status: 200 });
    vi.mocked(fetch).mockResolvedValueOnce(resp);

    // Empty string is not valid JSON → EvinaTransportError
    const { EvinaTransportError: Err } = await import("../src/errors");
    await expect(
      httpPostForm(
        "https://api.dcbprotect.com/v1/script",
        { ti: "x" },
        { headers: {} },
      ),
    ).rejects.toBeInstanceOf(Err);
  });
});
