/**
 * Mock EVINA server for integration tests (MVP_PLAN §4 testing strategy).
 *
 * EVINA calls are intercepted at the `fetch` boundary rather than by running a
 * real local HTTP server. This is deliberate: the transport pins the host to
 * the two real EVINA hostnames and rejects anything else (NFR-SEC-6), so a
 * `localhost` server could never be reached without weakening that control.
 * Stubbing `fetch` lets tests exercise the full client → transport path against
 * the REAL EVINA URLs while returning canned, deterministic responses and never
 * touching the network (NFR-MNT-2 — never call live EVINA).
 */

import { vi } from "vitest";

/** A request captured by the mock, with the form body decoded to params. */
export interface CapturedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  params: Record<string, string>;
}

/** Handler that produces a `Response` for a captured request. */
export type MockHandler = (req: CapturedRequest) => Response | Promise<Response>;

export interface MockEvina {
  /** All requests captured, in order. */
  readonly requests: CapturedRequest[];
  /** The most recent captured request, or undefined if none. */
  last(): CapturedRequest | undefined;
  /** Restore the real global `fetch`. */
  restore(): void;
}

type FetchArgs = Parameters<typeof fetch>;

/** Build a JSON `Response` shaped like an EVINA reply. */
export function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

/**
 * Install a `fetch` stub driven by `handler`. Returns a {@link MockEvina} for
 * inspecting captured requests and restoring the global.
 */
export function installMockEvina(handler: MockHandler): MockEvina {
  const requests: CapturedRequest[] = [];

  const fetchMock = vi.fn(
    (input: FetchArgs[0], init: FetchArgs[1]): ReturnType<typeof fetch> => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      const method = init?.method ?? "GET";
      const bodyText = typeof init?.body === "string" ? init.body : "";
      const params = Object.fromEntries(new URLSearchParams(bodyText));
      const captured: CapturedRequest = {
        url,
        method,
        headers: normalizeHeaders(init?.headers),
        params,
      };
      requests.push(captured);
      return Promise.resolve(handler(captured));
    },
  );

  vi.stubGlobal("fetch", fetchMock);

  return {
    requests,
    last: () => requests[requests.length - 1],
    restore: () => {
      vi.unstubAllGlobals();
    },
  };
}

/** Normalize any HeadersInit form into a lower-cased key/value record. */
function normalizeHeaders(h: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (h === undefined || h === null) return out;

  if (typeof Headers !== "undefined" && h instanceof Headers) {
    h.forEach((value, key) => {
      out[key.toLowerCase()] = value;
    });
    return out;
  }

  if (Array.isArray(h)) {
    for (const pair of h as unknown[]) {
      if (Array.isArray(pair) && pair.length >= 2) {
        out[String(pair[0]).toLowerCase()] = String(pair[1]);
      }
    }
    return out;
  }

  if (typeof h === "object") {
    for (const [key, value] of Object.entries(h as Record<string, unknown>)) {
      out[key.toLowerCase()] = String(value);
    }
  }
  return out;
}
