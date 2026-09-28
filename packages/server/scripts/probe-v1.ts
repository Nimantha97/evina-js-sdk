/**
 * Standalone EVINA v1-signature probe.
 * =====================================================================
 *
 * Purpose: confirm the EXACT v1 signature construction the live account accepts,
 * in a single run, BEFORE wiring v1 auth through the whole SDK. Because EVINA
 * doesn't publish the algorithm, the meaning of "queryString" in
 * `SHA-256(username + queryString + password)` is uncertain — this probe tries
 * several plausible variants against the real `/{username}/script` endpoint and
 * reports which one returns a script (success) vs `invalid-signature`.
 *
 * It makes REAL calls to EVINA. Run it directly (not part of the test suite):
 *
 *   # from packages/server, with EVINA_* in the repo-root .env or the env:
 *   node --import tsx/esm scripts/probe-v1.ts
 *
 * It reads EVINA_USERNAME, EVINA_PASSWORD, EVINA_BASE_URL, EVINA_DEFAULT_COUNTRY
 * from the environment. Nothing is logged except the variant label and the
 * EVINA response's success/error — never the password or the full signature.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadDotEnv(path: string): void {
  try {
    for (const line of readFileSync(path, "utf8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const eq = t.indexOf("=");
      if (eq === -1) continue;
      const k = t.slice(0, eq).trim();
      const v = t.slice(eq + 1).trim();
      if (k && !(k in process.env)) process.env[k] = v;
    }
  } catch {
    /* ignore */
  }
}

// packages/server/scripts -> repo root is ../../..
loadDotEnv(resolve(__dirname, "../../../.env"));
loadDotEnv(resolve(__dirname, "../.env"));

const USERNAME = process.env["EVINA_USERNAME"] ?? "";
const PASSWORD = process.env["EVINA_PASSWORD"] ?? "";
const BASE = (process.env["EVINA_BASE_URL"] ?? "https://api.dcbprotect.com").replace(/\/+$/, "");
const COUNTRY = process.env["EVINA_DEFAULT_COUNTRY"] ?? "LK";

if (!USERNAME || !PASSWORD) {
  console.error("Set EVINA_USERNAME and EVINA_PASSWORD (in .env or env) before running.");
  process.exit(1);
}

const sha256hex = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

/** Ordered mandatory params for /script (no signature). */
function scriptParams(): Array<[string, string]> {
  const ti = randomUUID();
  const ts = String(Math.floor(Date.now() / 1000));
  const pairs: Array<[string, string]> = [
    ["ti", ti],
    ["te", "#cta_button"],
    ["ts", ts],
    ["country", COUNTRY],
  ];
  // Mirror the SDK's buildScriptParams, which appends carrier from
  // EVINA_DEFAULT_CARRIER after the mandatory params. Set PROBE_WITH_CARRIER=1
  // to include it and reproduce the demo's exact request.
  const carrier = process.env["EVINA_DEFAULT_CARRIER"];
  if (process.env["PROBE_WITH_CARRIER"] === "1" && carrier) {
    pairs.push(["carrier", carrier]);
  }
  return pairs;
}

/** Encode ordered pairs to a query string (RFC-3986 via URLSearchParams). */
function encode(pairs: Array<[string, string]>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of pairs) usp.append(k, v);
  return usp.toString();
}

/**
 * Candidate signature variants. Each returns the signature input string that
 * gets hashed. We keep the query string identical across variants; only the
 * signed input differs. If none work, the algorithm/secret differs from the
 * audit's description and we must get the exact Java source.
 */
interface Variant {
  label: string;
  /** signature input, given the encoded (no-s) query string and raw pairs */
  sigInput: (encoded: string, pairs: Array<[string, string]>) => string;
}

const rawConcat = (pairs: Array<[string, string]>): string =>
  pairs.map(([k, v]) => `${k}=${v}`).join("&");

const VARIANTS: Variant[] = [
  {
    label: "A: username + encodedQuery + password",
    sigInput: (encoded) => `${USERNAME}${encoded}${PASSWORD}`,
  },
  {
    label: "B: username + rawQuery(unencoded) + password",
    sigInput: (_e, pairs) => `${USERNAME}${rawConcat(pairs)}${PASSWORD}`,
  },
  {
    label: "C: username + '?' + encodedQuery + password",
    sigInput: (encoded) => `${USERNAME}?${encoded}${PASSWORD}`,
  },
  {
    label: "D: password + encodedQuery + username",
    sigInput: (encoded) => `${PASSWORD}${encoded}${USERNAME}`,
  },
  {
    label: "E: username + password + encodedQuery",
    sigInput: (encoded) => `${USERNAME}${PASSWORD}${encoded}`,
  },
];

async function tryVariant(v: Variant): Promise<void> {
  const pairs = scriptParams();
  const encoded = encode(pairs);
  const s = sha256hex(v.sigInput(encoded, pairs));
  const url = `${BASE}/${encodeURIComponent(USERNAME)}/script?${encoded}&s=${s}`;

  try {
    const res = await fetch(url, { method: "GET", redirect: "error" });
    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text.slice(0, 200);
    }
    const body = parsed as { success?: boolean; e?: unknown; s?: unknown; t?: unknown };
    const hasScript = typeof body.s === "string" && body.t !== undefined;
    const verdict = hasScript
      ? "SUCCESS (script returned)"
      : `fail: ${JSON.stringify(body.e ?? body.success ?? parsed)}`;
    console.log(`[${v.label}] HTTP ${res.status} -> ${verdict}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "network error";
    console.log(`[${v.label}] request error: ${msg}`);
  }
}

async function main(): Promise<void> {
  console.log(`Probing EVINA v1 /script for user "${USERNAME}" at ${BASE}\n`);
  for (const v of VARIANTS) {
    await tryVariant(v);
  }
  console.log(
    "\nIf one variant shows SUCCESS, note its letter — that is the signature format to use.\n" +
      "If ALL fail with invalid-signature, the account secret or algorithm differs from the\n" +
      "audit's description; we then need the exact signing code from the old Java widget.",
  );
}

void main();
