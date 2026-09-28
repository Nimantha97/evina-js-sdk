/**
 * `@ideabiz/evina-browser` — thin browser helper. PHASE 2 (P2) stub.
 *
 * Intentionally empty in the MVP. When implemented it will inject the opaque
 * EVINA kit and communicate ONLY with the consumer's own backend — never with
 * EVINA directly, and never holding the API key or any secret
 * (ADR-003 / ADR-004, SRS FR-21..24, THREAT_MODEL T-I2 / B4).
 *
 * Hard rule: this package must never import from `@ideabiz/evina-sdk` or
 * otherwise reference server secrets. A build/lint guard enforces this in M7.
 */
export {};
