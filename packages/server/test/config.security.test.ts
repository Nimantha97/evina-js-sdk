/**
 * Security test suite — M2 Config
 *
 * Controls verified:
 *  NFR-SEC-6 / AC-5   Non-HTTPS baseUrl rejected at construction; host pinned.
 *  NFR-SEC-2 / T-I1   Config validation errors never echo the apiKey/username.
 *  ADR-012            Core never reads process.env implicitly (helper is opt-in
 *                     and takes the env as an argument).
 */

import { describe, it, expect } from "vitest";
import { validateConfig, configFromEnv, ENV_VAR_NAMES, type EvinaConfig } from "../src/config";

const SECRET_KEY = "sk_live_SECRET_should_never_appear";
const SECRET_USER = "owner_secret_username";

describe("SEC: HTTPS-only + host pinning (NFR-SEC-6, AC-5)", () => {
  it("rejects a non-HTTPS baseUrl at validation time", () => {
    expect(() =>
      validateConfig({
        apiKey: "k",
        username: "u",
        baseUrl: "http://api.dcbprotect.com",
      }),
    ).toThrow(/HTTPS/i);
  });

  it("rejects a foreign host even over HTTPS (pinning)", () => {
    expect(() =>
      validateConfig({
        apiKey: "k",
        username: "u",
        baseUrl: "https://attacker.example.com",
      }),
    ).toThrow(/allowed EVINA host/i);
  });

  it("rejects a look-alike host that embeds the EVINA hostname", () => {
    expect(() =>
      validateConfig({
        apiKey: "k",
        username: "u",
        baseUrl: "https://api.dcbprotect.com.evil.com",
      }),
    ).toThrow(/allowed EVINA host/i);
  });
});

describe("SEC: validation errors are secret-free (NFR-SEC-2, T-I1)", () => {
  it("error for an over-long apiKey does not contain the key", () => {
    try {
      validateConfig({ apiKey: SECRET_KEY.repeat(200), username: "u" });
      throw new Error("expected validation to throw");
    } catch (e) {
      expect((e as Error).message).not.toContain(SECRET_KEY);
    }
  });

  it("error triggered by a later field does not leak apiKey/username", () => {
    try {
      validateConfig({
        apiKey: SECRET_KEY,
        username: SECRET_USER,
        defaultCountry: "INVALID",
      });
      throw new Error("expected validation to throw");
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).not.toContain(SECRET_KEY);
      expect(msg).not.toContain(SECRET_USER);
    }
  });

  it("configFromEnv error does not leak the secret value", () => {
    try {
      configFromEnv({
        [ENV_VAR_NAMES.apiKey]: SECRET_KEY,
        [ENV_VAR_NAMES.username]: SECRET_USER,
        [ENV_VAR_NAMES.timeoutMs]: "not-a-number",
      });
      throw new Error("expected configFromEnv to throw");
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).not.toContain(SECRET_KEY);
      expect(msg).not.toContain(SECRET_USER);
    }
  });
});

describe("SEC: configFromEnv is explicit / arg-driven (ADR-012)", () => {
  it("reads only from the provided env argument, not the real process.env", () => {
    // Provide a self-contained env; the real process.env has no EVINA_* vars in
    // CI, proving the core does not depend on ambient environment.
    const cfg: EvinaConfig = configFromEnv({
      [ENV_VAR_NAMES.apiKey]: "explicit-key",
      [ENV_VAR_NAMES.username]: "explicit-user",
    });
    expect(cfg.apiKey).toBe("explicit-key");
    expect(cfg.username).toBe("explicit-user");
  });
});
