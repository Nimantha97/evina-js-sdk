/**
 * Security test suite — M2 Redaction / PII
 *
 * Encodes the redaction controls as CI-enforced assertions, separate from the
 * behavioural unit tests so they can be reviewed as a distinct security gate
 * (NFR-SEC-13). These are the executable form of AC-4.
 *
 * Controls verified:
 *  NFR-SEC-2 / T-I1   Secrets never survive redaction (message + nested meta).
 *  NFR-SEC-4 / T-I3   Raw MSISDNs never survive redaction.
 *  NFR-SEC-5          Redaction is one-way masking, NOT reversible base64.
 *  T-E2               Redaction cannot be used to pollute prototypes.
 */

import { describe, it, expect } from "vitest";
import { redact, createRedactingLogger, type Logger } from "../src/redact";

const API_KEY = "sk_live_SUPER_SECRET_KEY_12345";
const USERNAME = "dcb_account_owner";
const MSISDN = "94771234567";

describe("SEC: secrets never survive redaction (NFR-SEC-2, AC-4)", () => {
  it("removes the api key from a flat string", () => {
    const out = redact(`Authorization ${API_KEY}`, [API_KEY]) as string;
    expect(out).not.toContain(API_KEY);
  });

  it("removes the api key and username from a deep object", () => {
    const payload = {
      level1: {
        headers: { "X-EVINA-APIKEY": API_KEY },
        account: USERNAME,
        list: [`prefix-${API_KEY}`, `owner:${USERNAME}`],
      },
    };
    const out = JSON.stringify(redact(payload, [API_KEY, USERNAME]));
    expect(out).not.toContain(API_KEY);
    expect(out).not.toContain(USERNAME);
  });

  it("removes the api key from an Error message", () => {
    const out = JSON.stringify(
      redact(new Error(`call failed with ${API_KEY}`), [API_KEY]),
    );
    expect(out).not.toContain(API_KEY);
  });
});

describe("SEC: raw MSISDNs never survive redaction (NFR-SEC-4, T-I3, AC-4)", () => {
  it("masks a MSISDN in a string", () => {
    const out = redact(`user ${MSISDN}`) as string;
    expect(out).not.toContain(MSISDN);
  });

  it("masks a MSISDN nested in metadata", () => {
    const out = JSON.stringify(redact({ user_id: MSISDN, arg1: MSISDN }));
    expect(out).not.toContain(MSISDN);
  });

  it("masks a MSISDN passed as a number", () => {
    const out = redact(Number(MSISDN));
    expect(String(out)).not.toContain(MSISDN);
  });
});

describe("SEC: redaction is not reversible encoding (NFR-SEC-5)", () => {
  it("does not base64-encode secrets (masking is destructive)", () => {
    const out = redact(API_KEY, [API_KEY]) as string;
    // A base64 of the key would decode back to the secret; masking must not.
    const b64 = Buffer.from(API_KEY, "utf8").toString("base64");
    expect(out).not.toContain(b64);
    expect(out).toBe("***REDACTED***");
  });
});

describe("SEC: redacting logger never leaks to the sink (NFR-SEC-2/4)", () => {
  it("sink receives no secret and no raw MSISDN", () => {
    let capturedMessage = "";
    let capturedMeta: object | undefined;
    const sink: Logger = {
      debug: () => undefined,
      info: (m, meta) => {
        capturedMessage = m;
        capturedMeta = meta;
      },
      warn: () => undefined,
      error: () => undefined,
    };

    const log = createRedactingLogger(sink, [API_KEY, USERNAME]);
    log.info(`charging ${MSISDN} with ${API_KEY}`, {
      apiKey: API_KEY,
      username: USERNAME,
      msisdn: MSISDN,
    });

    const serializedMeta = JSON.stringify(capturedMeta);
    expect(capturedMessage).not.toContain(API_KEY);
    expect(capturedMessage).not.toContain(MSISDN);
    expect(serializedMeta).not.toContain(API_KEY);
    expect(serializedMeta).not.toContain(USERNAME);
    expect(serializedMeta).not.toContain(MSISDN);
  });
});

describe("SEC: prototype pollution safety (T-E2)", () => {
  it("a __proto__ payload does not pollute Object.prototype", () => {
    const evil = JSON.parse('{"__proto__":{"pwned":1}}') as object;
    redact(evil);
    expect(({} as Record<string, unknown>)["pwned"]).toBeUndefined();
  });
});
