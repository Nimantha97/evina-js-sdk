/**
 * Config unit tests — M2
 *
 * Covers:
 *  FR-1..4    Explicit config, required fields, fast-fail validation, defaults.
 *  NFR-SEC-6  HTTPS-only + host-pinned baseUrl.
 *  ADR-012    configFromEnv is an explicit, arg-driven helper.
 */

import { describe, it, expect } from "vitest";
import {
  validateConfig,
  resolveConfig,
  configFromEnv,
  ENV_VAR_NAMES,
  DEFAULT_BASE_URL,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_RETRIES,
  DEFAULT_FAIL_OPEN,
  type EvinaConfig,
} from "../src/config";
import { EvinaConfigError } from "../src/errors";
import type { Logger } from "../src/redact";
import { InMemoryTransactionStore } from "../src/store";
import type { TransactionStore } from "../src/types";

const VALID: EvinaConfig = { apiKey: "test-key", username: "test-user" };

describe("validateConfig — required fields (FR-2/4)", () => {
  it("accepts a minimal valid config", () => {
    expect(() => validateConfig({ ...VALID })).not.toThrow();
  });

  it("rejects a null config", () => {
    expect(() => validateConfig(null as unknown as EvinaConfig)).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a non-object (string) config", () => {
    expect(() => validateConfig("nope" as unknown as EvinaConfig)).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a missing apiKey", () => {
    // In v2 (default) mode, apiKey is required; { username } alone must fail.
    expect(() => validateConfig({ username: "u" })).toThrow(EvinaConfigError);
  });

  it("rejects an empty apiKey", () => {
    expect(() => validateConfig({ ...VALID, apiKey: "   " })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a missing username", () => {
    expect(() =>
      validateConfig({ apiKey: "k" } as unknown as EvinaConfig),
    ).toThrow(EvinaConfigError);
  });

  it("rejects an over-long credential", () => {
    expect(() =>
      validateConfig({ ...VALID, apiKey: "x".repeat(5000) }),
    ).toThrow(EvinaConfigError);
  });
});

describe("validateConfig — baseUrl (NFR-SEC-6)", () => {
  it("rejects a non-HTTPS baseUrl", () => {
    expect(() =>
      validateConfig({ ...VALID, baseUrl: "http://api.dcbprotect.com" }),
    ).toThrow(EvinaConfigError);
  });

  it("rejects an invalid URL", () => {
    expect(() => validateConfig({ ...VALID, baseUrl: "not-a-url" })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a disallowed host", () => {
    expect(() =>
      validateConfig({ ...VALID, baseUrl: "https://evil.example.com" }),
    ).toThrow(EvinaConfigError);
  });

  it("accepts the default EVINA host", () => {
    expect(() =>
      validateConfig({ ...VALID, baseUrl: "https://api.dcbprotect.com" }),
    ).not.toThrow();
  });

  it("accepts the Cloudflare mirror host", () => {
    expect(() =>
      validateConfig({ ...VALID, baseUrl: "https://api.clfldcbprotect.com" }),
    ).not.toThrow();
  });

  it("rejects an empty baseUrl string", () => {
    expect(() => validateConfig({ ...VALID, baseUrl: "" })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a non-string baseUrl", () => {
    expect(() =>
      validateConfig({ ...VALID, baseUrl: 123 as unknown as string }),
    ).toThrow(EvinaConfigError);
  });
});

describe("validateConfig — optional field bounds", () => {
  it("accepts a valid ISO country", () => {
    expect(() => validateConfig({ ...VALID, defaultCountry: "LK" })).not.toThrow();
  });

  it("rejects an invalid country", () => {
    expect(() => validateConfig({ ...VALID, defaultCountry: "LKA" })).toThrow(
      EvinaConfigError,
    );
  });

  it("accepts a 5-digit carrier", () => {
    expect(() => validateConfig({ ...VALID, defaultCarrier: "41302" })).not.toThrow();
  });

  it("accepts a 6-digit carrier", () => {
    expect(() => validateConfig({ ...VALID, defaultCarrier: "310010" })).not.toThrow();
  });

  it("rejects a non-numeric carrier", () => {
    expect(() => validateConfig({ ...VALID, defaultCarrier: "abcde" })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects timeoutMs of 0", () => {
    expect(() => validateConfig({ ...VALID, timeoutMs: 0 })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a negative timeoutMs", () => {
    expect(() => validateConfig({ ...VALID, timeoutMs: -1 })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a non-integer timeoutMs", () => {
    expect(() => validateConfig({ ...VALID, timeoutMs: 10.5 })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a timeoutMs above the ceiling", () => {
    expect(() => validateConfig({ ...VALID, timeoutMs: 999_999 })).toThrow(
      EvinaConfigError,
    );
  });

  it("accepts a valid timeoutMs", () => {
    expect(() => validateConfig({ ...VALID, timeoutMs: 5000 })).not.toThrow();
  });

  it("rejects negative retries", () => {
    expect(() => validateConfig({ ...VALID, retries: -1 })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects retries above the ceiling", () => {
    expect(() => validateConfig({ ...VALID, retries: 99 })).toThrow(
      EvinaConfigError,
    );
  });

  it("rejects a non-boolean failOpen", () => {
    expect(() =>
      validateConfig({ ...VALID, failOpen: "yes" as unknown as boolean }),
    ).toThrow(EvinaConfigError);
  });

  it("rejects a non-boolean useCloudflareForScript", () => {
    expect(() =>
      validateConfig({
        ...VALID,
        useCloudflareForScript: 1 as unknown as boolean,
      }),
    ).toThrow(EvinaConfigError);
  });

  it("rejects a non-function userIdTransform", () => {
    expect(() =>
      validateConfig({
        ...VALID,
        userIdTransform: "nope" as unknown as (raw: string) => string,
      }),
    ).toThrow(EvinaConfigError);
  });

  it("accepts a valid userIdTransform", () => {
    expect(() =>
      validateConfig({ ...VALID, userIdTransform: (r) => r }),
    ).not.toThrow();
  });

  it("rejects a logger missing methods", () => {
    expect(() =>
      validateConfig({
        ...VALID,
        logger: { debug: () => undefined } as unknown as Logger,
      }),
    ).toThrow(EvinaConfigError);
  });

  it("accepts a complete logger", () => {
    expect(() =>
      validateConfig({
        ...VALID,
        logger: {
          debug: () => undefined,
          info: () => undefined,
          warn: () => undefined,
          error: () => undefined,
        },
      }),
    ).not.toThrow();
  });

  it("rejects a store missing methods", () => {
    expect(() =>
      validateConfig({ ...VALID, store: {} as unknown as TransactionStore }),
    ).toThrow(EvinaConfigError);
  });

  it("rejects a non-object store", () => {
    expect(() =>
      validateConfig({ ...VALID, store: "nope" as unknown as TransactionStore }),
    ).toThrow(EvinaConfigError);
  });

  it("accepts a valid store", () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    expect(() => validateConfig({ ...VALID, store })).not.toThrow();
  });
});

describe("resolveConfig — defaults (FR-2)", () => {
  it("applies all defaults for a minimal config", () => {
    const r = resolveConfig({ ...VALID });
    expect(r.baseUrl).toBe(DEFAULT_BASE_URL);
    expect(r.useCloudflareForScript).toBe(false);
    expect(r.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(r.retries).toBe(DEFAULT_RETRIES);
    expect(r.failOpen).toBe(DEFAULT_FAIL_OPEN);
    expect(r.defaultCountry).toBeUndefined();
    expect(r.defaultCarrier).toBeUndefined();
  });

  it("defaults userIdTransform to identity", () => {
    const r = resolveConfig({ ...VALID });
    expect(r.userIdTransform("94771234567")).toBe("94771234567");
  });

  it("defaults logger to a working no-op", () => {
    const r = resolveConfig({ ...VALID });
    expect(() => r.logger.info("x")).not.toThrow();
  });

  it("preserves explicitly provided values", () => {
    const r = resolveConfig({
      ...VALID,
      baseUrl: "https://api.clfldcbprotect.com",
      useCloudflareForScript: true,
      timeoutMs: 3000,
      retries: 2,
      failOpen: false,
      defaultCountry: "US",
      defaultCarrier: "310010",
    });
    expect(r.baseUrl).toBe("https://api.clfldcbprotect.com");
    expect(r.useCloudflareForScript).toBe(true);
    expect(r.timeoutMs).toBe(3000);
    expect(r.retries).toBe(2);
    expect(r.failOpen).toBe(false);
    expect(r.defaultCountry).toBe("US");
    expect(r.defaultCarrier).toBe("310010");
  });

  it("throws on invalid config before resolving", () => {
    expect(() =>
      resolveConfig({ apiKey: "", username: "u" }),
    ).toThrow(EvinaConfigError);
  });
});

describe("configFromEnv (FR-3, ADR-012)", () => {
  it("builds a minimal config from required vars", () => {
    const cfg = configFromEnv({
      [ENV_VAR_NAMES.apiKey]: "k",
      [ENV_VAR_NAMES.username]: "u",
    });
    expect(cfg.apiKey).toBe("k");
    expect(cfg.username).toBe("u");
    expect(cfg.baseUrl).toBeUndefined();
  });

  it("throws when EVINA_API_KEY is missing", () => {
    expect(() => configFromEnv({ [ENV_VAR_NAMES.username]: "u" })).toThrow(
      EvinaConfigError,
    );
  });

  it("throws when EVINA_USERNAME is missing", () => {
    expect(() => configFromEnv({ [ENV_VAR_NAMES.apiKey]: "k" })).toThrow(
      EvinaConfigError,
    );
  });

  it("maps all optional vars", () => {
    const cfg = configFromEnv({
      [ENV_VAR_NAMES.apiKey]: "k",
      [ENV_VAR_NAMES.username]: "u",
      [ENV_VAR_NAMES.baseUrl]: "https://api.dcbprotect.com",
      [ENV_VAR_NAMES.defaultCountry]: "LK",
      [ENV_VAR_NAMES.defaultCarrier]: "41302",
      [ENV_VAR_NAMES.timeoutMs]: "5000",
      [ENV_VAR_NAMES.retries]: "2",
      [ENV_VAR_NAMES.failOpen]: "false",
      [ENV_VAR_NAMES.useCloudflareForScript]: "true",
    });
    expect(cfg.baseUrl).toBe("https://api.dcbprotect.com");
    expect(cfg.defaultCountry).toBe("LK");
    expect(cfg.defaultCarrier).toBe("41302");
    expect(cfg.timeoutMs).toBe(5000);
    expect(cfg.retries).toBe(2);
    expect(cfg.failOpen).toBe(false);
    expect(cfg.useCloudflareForScript).toBe(true);
  });

  it("parses boolean 1/0 forms", () => {
    const cfg = configFromEnv({
      [ENV_VAR_NAMES.apiKey]: "k",
      [ENV_VAR_NAMES.username]: "u",
      [ENV_VAR_NAMES.failOpen]: "1",
      [ENV_VAR_NAMES.useCloudflareForScript]: "0",
    });
    expect(cfg.failOpen).toBe(true);
    expect(cfg.useCloudflareForScript).toBe(false);
  });

  it("throws on a non-integer timeout", () => {
    expect(() =>
      configFromEnv({
        [ENV_VAR_NAMES.apiKey]: "k",
        [ENV_VAR_NAMES.username]: "u",
        [ENV_VAR_NAMES.timeoutMs]: "abc",
      }),
    ).toThrow(EvinaConfigError);
  });

  it("throws on an invalid boolean", () => {
    expect(() =>
      configFromEnv({
        [ENV_VAR_NAMES.apiKey]: "k",
        [ENV_VAR_NAMES.username]: "u",
        [ENV_VAR_NAMES.failOpen]: "maybe",
      }),
    ).toThrow(EvinaConfigError);
  });

  it("validates the assembled config (rejects a bad env baseUrl)", () => {
    expect(() =>
      configFromEnv({
        [ENV_VAR_NAMES.apiKey]: "k",
        [ENV_VAR_NAMES.username]: "u",
        [ENV_VAR_NAMES.baseUrl]: "http://api.dcbprotect.com",
      }),
    ).toThrow(EvinaConfigError);
  });
});
