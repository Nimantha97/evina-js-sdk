/**
 * Typed error hierarchy for the EVINA server SDK.
 *
 * Rules (NFR-SEC-2, THREAT_MODEL T-I1):
 *  - No error message may embed the API key, username, or a raw MSISDN.
 *  - Errors are plain subclasses of Error so `instanceof` works across module
 *    boundaries and stack traces are preserved.
 *
 * Only EvinaTransportError is needed for M1. The remaining types are stubs
 * that will be fleshed out in M2 (Config), M4 (Script), and M5 (Check).
 * They are declared here so the full hierarchy lives in one place and
 * downstream milestones can import without circular deps.
 */

/** Base class — never thrown directly; catch with instanceof EvinaError. */
export class EvinaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    // Restore prototype chain for transpiled ES5 targets (safe no-op on ES2022).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a network-level or HTTP-level failure occurs while calling the
 * EVINA API: non-200 status, timeout, oversized/non-JSON response, SSRF guard
 * rejection, or host-pinning violation.
 *
 * Satisfies: FR-27, NFR-SEC-8, T-D1, T-T2, T-E1.
 */
export class EvinaTransportError extends EvinaError {
  /** HTTP status code, if the request reached the server. */
  readonly statusCode: number | undefined;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.statusCode = statusCode;
  }
}

/**
 * Thrown when the SDK is constructed with invalid or missing configuration.
 * Stub — fully implemented in M2.
 *
 * Satisfies: FR-4, NFR-SEC-6.
 */
export class EvinaConfigError extends EvinaError {}

/**
 * Thrown when `/v1/script` returns success:false or a non-200 status.
 * Stub — fully implemented in M4.
 *
 * Satisfies: FR-11, FR-27.
 */
export class EvinaScriptError extends EvinaError {
  readonly codes: string[];
  constructor(message: string, codes: string[] = []) {
    super(message);
    this.codes = codes;
  }
}

/**
 * Thrown when `/v1/check` returns a hard error (not a fraud verdict).
 * Stub — fully implemented in M5.
 *
 * Satisfies: FR-27.
 */
export class EvinaCheckError extends EvinaError {
  readonly codes: string[];
  constructor(message: string, codes: string[] = []) {
    super(message);
    this.codes = codes;
  }
}

/**
 * Thrown when `/v1/test_session` fails or returns a malformed response.
 *
 * Satisfies: FR-19, FR-27.
 */
export class EvinaTestSessionError extends EvinaError {
  readonly codes: string[];
  constructor(message: string, codes: string[] = []) {
    super(message);
    this.codes = codes;
  }
}
