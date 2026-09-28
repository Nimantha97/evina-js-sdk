/**
 * Security test suite — M1 Transport
 *
 * These tests encode the security controls from the threat model and SRS §5
 * as executable, CI-enforced assertions. They are intentionally separate from
 * the unit tests so they can be run and reviewed as a distinct security gate.
 *
 * Controls verified:
 *  NFR-SEC-6 / T-T2 / T-E1   HTTPS-only + host allow-list + no SSRF redirect
 *  NFR-SEC-8 / T-D1           Timeout + response size cap
 *  NFR-SEC-2 / T-I1           Error messages never embed secrets
 *  T-E2                        Defensive JSON parsing
 *  ADR-006                     No runtime dependencies (structural check)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { httpPostForm, validateEvinaUrl, ALLOWED_EVINA_HOSTS } from "../src/transport";
import { EvinaTransportError } from "../src/errors";

const VALID_URL = "https://api.dcbprotect.com/v1/script";
const SECRET_KEY = "sk_live_SUPER_SECRET_KEY_12345";

// ---------------------------------------------------------------------------
// NFR-SEC-6 / T-T2 / T-E1 — HTTPS-only + host pinning + SSRF
// ---------------------------------------------------------------------------

describe("SEC: HTTPS-only enforcement (NFR-SEC-6, T-T2)", () => {
  it("rejects http:// scheme", () => {
    expect(() =>
      validateEvinaUrl("http://api.dcbprotect.com/v1/script"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects ftp:// scheme", () => {
    expect(() =>
      validateEvinaUrl("ftp://api.dcbprotect.com/v1/script"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects javascript: scheme", () => {
    // eslint-disable-next-line no-script-url
    expect(() => validateEvinaUrl("javascript:alert(1)")).toThrow(
      EvinaTransportError,
    );
  });

  it("rejects data: URI", () => {
    expect(() => validateEvinaUrl("data:text/html,<h1>x</h1>")).toThrow(
      EvinaTransportError,
    );
  });

  it("accepts both documented EVINA HTTPS hosts", () => {
    for (const host of ALLOWED_EVINA_HOSTS) {
      expect(() =>
        validateEvinaUrl(`https://${host}/v1/script`),
      ).not.toThrow();
    }
  });
});

describe("SEC: Host allow-list / pinning (NFR-SEC-6, T-E1)", () => {
  it("rejects an arbitrary external host", () => {
    expect(() =>
      validateEvinaUrl("https://attacker.example.com/steal"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects a subdomain of a valid EVINA host", () => {
    // Subdomain spoofing: evil.api.dcbprotect.com is NOT in the allow-list.
    expect(() =>
      validateEvinaUrl("https://evil.api.dcbprotect.com/v1/script"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects a host that merely contains the EVINA hostname as a substring", () => {
    expect(() =>
      validateEvinaUrl("https://api.dcbprotect.com.evil.com/v1/script"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects localhost", () => {
    expect(() =>
      validateEvinaUrl("https://localhost/v1/script"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects an IP address", () => {
    expect(() =>
      validateEvinaUrl("https://1.2.3.4/v1/script"),
    ).toThrow(EvinaTransportError);
  });
});

describe("SEC: SSRF redirect prevention (NFR-SEC-6, T-E1)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("passes redirect:error to fetch so the runtime never follows redirects", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    );

    await httpPostForm(VALID_URL, { ti: "x" }, { headers: {} });

    const [, init] = vi.mocked(fetch).mock.calls[0]!;
    expect((init as RequestInit).redirect).toBe("error");
  });

  it("throws EvinaTransportError (not a silent allow) when fetch throws on redirect", async () => {
    // Simulate what the runtime does when redirect:error and a redirect occurs.
    vi.mocked(fetch).mockRejectedValueOnce(
      new TypeError("Failed to fetch: redirect not allowed"),
    );

    await expect(
      httpPostForm(VALID_URL, { ti: "x" }, { headers: {} }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });
});

// ---------------------------------------------------------------------------
// NFR-SEC-8 / T-D1 — Timeout
// ---------------------------------------------------------------------------

describe("SEC: Request timeout (NFR-SEC-8, T-D1)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("aborts the request and throws EvinaTransportError on timeout", async () => {
    vi.mocked(fetch).mockImplementationOnce((_url, init) => {
      return new Promise((_resolve, reject) => {
        const signal = (init as RequestInit).signal as AbortSignal;
        signal.addEventListener("abort", () => {
          reject(new DOMException("Aborted", "AbortError"));
        });
      });
    });

    await expect(
      httpPostForm(VALID_URL, { ti: "x" }, { headers: {}, timeoutMs: 1 }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });

  it("passes an AbortSignal to fetch", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    );

    await httpPostForm(VALID_URL, { ti: "x" }, { headers: {} });

    const [, init] = vi.mocked(fetch).mock.calls[0]!;
    expect((init as RequestInit).signal).toBeInstanceOf(AbortSignal);
  });
});

// ---------------------------------------------------------------------------
// NFR-SEC-8 / T-D1 — Response size cap
// ---------------------------------------------------------------------------

describe("SEC: Response size cap (NFR-SEC-8, T-D1)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("rejects immediately when Content-Length header exceeds cap", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response("{}", {
        status: 200,
        headers: { "Content-Length": "10000000" },
      }),
    );

    await expect(
      httpPostForm(VALID_URL, { ti: "x" }, { headers: {}, maxBytes: 1024 }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });

  it("rejects when streamed body exceeds cap", async () => {
    const oversized = "A".repeat(4096);
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(oversized, { status: 200 }),
    );

    await expect(
      httpPostForm(VALID_URL, { ti: "x" }, { headers: {}, maxBytes: 512 }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });
});

// ---------------------------------------------------------------------------
// NFR-SEC-2 / T-I1 — Error messages must never embed secrets
// ---------------------------------------------------------------------------

describe("SEC: Secret-free error messages (NFR-SEC-2, T-I1)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("timeout error does not contain the API key", async () => {
    vi.mocked(fetch).mockImplementationOnce((_url, init) => {
      return new Promise((_resolve, reject) => {
        const signal = (init as RequestInit).signal as AbortSignal;
        signal.addEventListener("abort", () => {
          reject(new DOMException("Aborted", "AbortError"));
        });
      });
    });

    try {
      await httpPostForm(
        VALID_URL,
        { ti: "x" },
        { headers: { "X-EVINA-APIKEY": SECRET_KEY }, timeoutMs: 1 },
      );
    } catch (e) {
      expect((e as Error).message).not.toContain(SECRET_KEY);
    }
  });

  it("non-200 error does not contain the API key", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response("", { status: 403 }));

    try {
      await httpPostForm(
        VALID_URL,
        { ti: "x" },
        { headers: { "X-EVINA-APIKEY": SECRET_KEY } },
      );
    } catch (e) {
      expect((e as Error).message).not.toContain(SECRET_KEY);
    }
  });

  it("JSON parse error does not contain the API key", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response("not-json", { status: 200 }),
    );

    try {
      await httpPostForm(
        VALID_URL,
        { ti: "x" },
        { headers: { "X-EVINA-APIKEY": SECRET_KEY } },
      );
    } catch (e) {
      expect((e as Error).message).not.toContain(SECRET_KEY);
    }
  });

  it("host-pinning error does not contain the API key", () => {
    try {
      validateEvinaUrl("https://evil.com/steal");
    } catch (e) {
      expect((e as Error).message).not.toContain(SECRET_KEY);
    }
  });

  it("HTTPS rejection error does not contain the API key", () => {
    try {
      validateEvinaUrl("http://api.dcbprotect.com/v1/script");
    } catch (e) {
      expect((e as Error).message).not.toContain(SECRET_KEY);
    }
  });
});

// ---------------------------------------------------------------------------
// T-E2 — Defensive JSON parsing
// ---------------------------------------------------------------------------

describe("SEC: Defensive JSON parsing (T-E2)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws EvinaTransportError on HTML error page body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response("<!DOCTYPE html><html>error</html>", { status: 200 }),
    );

    await expect(
      httpPostForm(VALID_URL, { ti: "x" }, { headers: {} }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });

  it("throws EvinaTransportError on empty body", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response("", { status: 200 }));

    await expect(
      httpPostForm(VALID_URL, { ti: "x" }, { headers: {} }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });

  it("throws EvinaTransportError on truncated JSON", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response('{"t":"tok', { status: 200 }),
    );

    await expect(
      httpPostForm(VALID_URL, { ti: "x" }, { headers: {} }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });
});

// ---------------------------------------------------------------------------
// ADR-006 — Zero runtime dependencies (structural)
// ---------------------------------------------------------------------------

describe("ADR-006: Zero runtime dependencies", () => {
  it("transport module does not import any third-party module", async () => {
    // Read the source and assert no non-relative, non-node: imports exist.
    const fs = await import("node:fs/promises");
    const src = await fs.readFile(
      new URL("../src/transport.ts", import.meta.url),
      "utf8",
    );

    // Extract all import statements.
    const importLines = src
      .split("\n")
      .filter((l) => l.trimStart().startsWith("import "));

    for (const line of importLines) {
      // Allow: relative imports (./  ../) and node: built-ins.
      const isRelative = /from\s+["']\.\//u.test(line) || /from\s+["']\.\.\//u.test(line);
      const isNodeBuiltin = /from\s+["']node:/u.test(line);
      expect(
        isRelative || isNodeBuiltin,
        `Unexpected third-party import in transport.ts: ${line}`,
      ).toBe(true);
    }
  });
});
