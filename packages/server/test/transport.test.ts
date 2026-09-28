/**
 * Transport unit tests — M1
 *
 * Covers:
 *  FR-10   Percent-encoding correctness
 *  NFR-SEC-8 / T-D1   Timeout + response size cap
 *  FR-11 / FR-16       Non-200 → EvinaTransportError with statusCode
 *  T-E2                Non-JSON body → EvinaTransportError
 *  FR-27               Error types carry no secrets
 *
 * All fetch calls are intercepted via Vitest's `vi.stubGlobal` — no live
 * network traffic (NFR-MNT-2).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { httpPostForm, validateEvinaUrl } from "../src/transport";
import { EvinaTransportError } from "../src/errors";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_URL = "https://api.dcbprotect.com/v1/script";
const BASE_HEADERS = { "X-EVINA-APIKEY": "test-key" };

/** Build a minimal mock Response. */
function mockResponse(
  body: string,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// ---------------------------------------------------------------------------
// validateEvinaUrl — unit tests (pure, no fetch)
// ---------------------------------------------------------------------------

describe("validateEvinaUrl", () => {
  it("accepts the primary EVINA host over HTTPS", () => {
    expect(() =>
      validateEvinaUrl("https://api.dcbprotect.com/v1/script"),
    ).not.toThrow();
  });

  it("accepts the Cloudflare mirror host over HTTPS", () => {
    expect(() =>
      validateEvinaUrl("https://api.clfldcbprotect.com/v1/script"),
    ).not.toThrow();
  });

  it("rejects HTTP (non-HTTPS) URLs", () => {
    expect(() =>
      validateEvinaUrl("http://api.dcbprotect.com/v1/script"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects an unknown host (host-pinning)", () => {
    expect(() =>
      validateEvinaUrl("https://evil.example.com/v1/script"),
    ).toThrow(EvinaTransportError);
  });

  it("rejects a malformed URL", () => {
    expect(() => validateEvinaUrl("not-a-url")).toThrow(EvinaTransportError);
  });

  it("error message for HTTP does not contain the API key", () => {
    try {
      validateEvinaUrl("http://api.dcbprotect.com/v1/script");
    } catch (e) {
      expect(e).toBeInstanceOf(EvinaTransportError);
      expect((e as EvinaTransportError).message).not.toContain("test-key");
    }
  });
});

// ---------------------------------------------------------------------------
// httpPostForm — fetch-mocked tests
// ---------------------------------------------------------------------------

describe("httpPostForm", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // -------------------------------------------------------------------------
  // FR-10 — Percent-encoding
  // -------------------------------------------------------------------------

  describe("percent-encoding (FR-10)", () => {
    it("encodes special characters in param values", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse(JSON.stringify({ success: true })),
      );

      await httpPostForm(
        VALID_URL,
        { te: "#cta_button", ti: "abc 123" },
        { headers: BASE_HEADERS },
      );

      const [, init] = vi.mocked(fetch).mock.calls[0]!;
      const body = (init as RequestInit).body as string;
      // URLSearchParams encodes # as %23 and space as +
      expect(body).toContain("te=%23cta_button");
      expect(body).toContain("ti=abc+123");
    });

    it("sends Content-Type: application/x-www-form-urlencoded", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse(JSON.stringify({ ok: true })),
      );

      await httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS });

      const [, init] = vi.mocked(fetch).mock.calls[0]!;
      const headers = (init as RequestInit).headers as Record<string, string>;
      expect(headers["Content-Type"]).toBe(
        "application/x-www-form-urlencoded",
      );
    });

    it("forwards caller-supplied headers (e.g. X-EVINA-APIKEY)", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse(JSON.stringify({ ok: true })),
      );

      await httpPostForm(
        VALID_URL,
        { ti: "x" },
        { headers: { "X-EVINA-APIKEY": "my-secret-key" } },
      );

      const [, init] = vi.mocked(fetch).mock.calls[0]!;
      const headers = (init as RequestInit).headers as Record<string, string>;
      expect(headers["X-EVINA-APIKEY"]).toBe("my-secret-key");
    });
  });

  // -------------------------------------------------------------------------
  // Successful response
  // -------------------------------------------------------------------------

  describe("successful response", () => {
    it("returns parsed JSON on HTTP 200", async () => {
      const payload = { t: "token123", s: "<script>", success: true };
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse(JSON.stringify(payload)),
      );

      const result = await httpPostForm(
        VALID_URL,
        { ti: "abc" },
        { headers: BASE_HEADERS },
      );

      expect(result).toEqual(payload);
    });
  });

  // -------------------------------------------------------------------------
  // Non-200 responses (FR-11, FR-16)
  // -------------------------------------------------------------------------

  describe("non-200 responses", () => {
    it("throws EvinaTransportError with statusCode on HTTP 500", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(mockResponse("", 500));

      await expect(
        httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS }),
      ).rejects.toSatisfy(
        (e: unknown) =>
          e instanceof EvinaTransportError && e.statusCode === 500,
      );
    });

    it("throws EvinaTransportError on HTTP 401", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(mockResponse("", 401));

      await expect(
        httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS }),
      ).rejects.toBeInstanceOf(EvinaTransportError);
    });

    it("throws EvinaTransportError on HTTP 429", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(mockResponse("", 429));

      await expect(
        httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS }),
      ).rejects.toSatisfy(
        (e: unknown) =>
          e instanceof EvinaTransportError && e.statusCode === 429,
      );
    });
  });

  // -------------------------------------------------------------------------
  // Non-JSON body (T-E2)
  // -------------------------------------------------------------------------

  describe("non-JSON body (T-E2)", () => {
    it("throws EvinaTransportError when body is not valid JSON", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse("<html>error</html>", 200),
      );

      await expect(
        httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS }),
      ).rejects.toBeInstanceOf(EvinaTransportError);
    });

    it("error message mentions JSON, not the API key", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse("not-json", 200),
      );

      try {
        await httpPostForm(
          VALID_URL,
          { ti: "x" },
          { headers: { "X-EVINA-APIKEY": "super-secret" } },
        );
      } catch (e) {
        expect(e).toBeInstanceOf(EvinaTransportError);
        expect((e as EvinaTransportError).message).toContain("JSON");
        expect((e as EvinaTransportError).message).not.toContain(
          "super-secret",
        );
      }
    });
  });

  // -------------------------------------------------------------------------
  // Timeout (NFR-SEC-8, T-D1)
  // -------------------------------------------------------------------------

  describe("timeout (NFR-SEC-8)", () => {
    it("throws EvinaTransportError when fetch is aborted due to timeout", async () => {
      vi.mocked(fetch).mockImplementationOnce((_url, init) => {
        return new Promise((_resolve, reject) => {
          const signal = (init as RequestInit).signal as AbortSignal;
          signal.addEventListener("abort", () => {
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        });
      });

      await expect(
        httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS, timeoutMs: 1 }),
      ).rejects.toBeInstanceOf(EvinaTransportError);
    });

    it("timeout error message mentions the timeout duration", async () => {
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
          { headers: BASE_HEADERS, timeoutMs: 50 },
        );
      } catch (e) {
        expect(e).toBeInstanceOf(EvinaTransportError);
        expect((e as EvinaTransportError).message).toContain("50ms");
      }
    });
  });

  // -------------------------------------------------------------------------
  // Response size cap (NFR-SEC-8, T-D1)
  // -------------------------------------------------------------------------

  describe("response size cap (NFR-SEC-8)", () => {
    it("throws EvinaTransportError when Content-Length exceeds cap", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse(JSON.stringify({ ok: true }), 200, {
          "Content-Length": "999999999",
        }),
      );

      await expect(
        httpPostForm(
          VALID_URL,
          { ti: "x" },
          { headers: BASE_HEADERS, maxBytes: 1024 },
        ),
      ).rejects.toBeInstanceOf(EvinaTransportError);
    });

    it("throws EvinaTransportError when streamed body exceeds cap", async () => {
      // Build a body larger than the cap.
      const bigBody = "x".repeat(2048);
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(bigBody, { status: 200 }),
      );

      await expect(
        httpPostForm(
          VALID_URL,
          { ti: "x" },
          { headers: BASE_HEADERS, maxBytes: 512 },
        ),
      ).rejects.toBeInstanceOf(EvinaTransportError);
    });

    it("accepts a body exactly at the cap", async () => {
      const body = JSON.stringify({ ok: true }); // ~13 bytes
      vi.mocked(fetch).mockResolvedValueOnce(new Response(body, { status: 200 }));

      await expect(
        httpPostForm(
          VALID_URL,
          { ti: "x" },
          { headers: BASE_HEADERS, maxBytes: body.length },
        ),
      ).resolves.toEqual({ ok: true });
    });
  });

  // -------------------------------------------------------------------------
  // HTTPS / host-pinning guard (NFR-SEC-6, T-T2, T-E1)
  // -------------------------------------------------------------------------

  describe("URL security guards (NFR-SEC-6)", () => {
    it("throws before fetch when URL is HTTP", async () => {
      await expect(
        httpPostForm(
          "http://api.dcbprotect.com/v1/script",
          { ti: "x" },
          { headers: BASE_HEADERS },
        ),
      ).rejects.toBeInstanceOf(EvinaTransportError);

      expect(fetch).not.toHaveBeenCalled();
    });

    it("throws before fetch when host is not in the allow-list", async () => {
      await expect(
        httpPostForm(
          "https://attacker.example.com/v1/script",
          { ti: "x" },
          { headers: BASE_HEADERS },
        ),
      ).rejects.toBeInstanceOf(EvinaTransportError);

      expect(fetch).not.toHaveBeenCalled();
    });

    it("uses redirect:error to prevent SSRF via redirect", async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        mockResponse(JSON.stringify({ ok: true })),
      );

      await httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS });

      const [, init] = vi.mocked(fetch).mock.calls[0]!;
      expect((init as RequestInit).redirect).toBe("error");
    });
  });

  // -------------------------------------------------------------------------
  // Network failure
  // -------------------------------------------------------------------------

  describe("network failure", () => {
    it("wraps a network error in EvinaTransportError", async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error("ECONNREFUSED"));

      await expect(
        httpPostForm(VALID_URL, { ti: "x" }, { headers: BASE_HEADERS }),
      ).rejects.toBeInstanceOf(EvinaTransportError);
    });
  });
});

// ---------------------------------------------------------------------------
// Coverage edges (deferred tidy-up): non-Error rejection + null body
// ---------------------------------------------------------------------------

describe("httpPostForm — edge branches", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("wraps a non-Error rejection as a network failure (no crash)", async () => {
    // fetch rejects with a non-Error value → the `: 'network error'` branch.
    vi.mocked(fetch).mockRejectedValueOnce("socket exploded");
    await expect(
      httpPostForm(VALID_URL, { a: "b" }, { headers: BASE_HEADERS }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });

  it("handles a 200 response with a null body", async () => {
    // response.body === null → readBodyCapped returns "" → JSON.parse fails.
    vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 200 }));
    await expect(
      httpPostForm(VALID_URL, {}, { headers: BASE_HEADERS }),
    ).rejects.toBeInstanceOf(EvinaTransportError);
  });
});
