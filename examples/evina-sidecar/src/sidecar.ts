/**
 * EVINA sidecar — the production integration path (Option 1).
 * =====================================================================
 *
 * The real `pin-auth` service is Java/Spring and cannot import a Node/TypeScript
 * library in-process. This sidecar exposes `@ideabiz/evina-sdk` over a tiny,
 * private REST API so the Java service can call EVINA DCB Protect for the two
 * operations it needs:
 *
 *   POST /evina/request-script   → SDK requestScriptHandler → { transactionId, script }
 *   POST /evina/verify           → SDK verifyHandler        → { allowed, category, reason }
 *
 * Trust model:
 *   - The EVINA API key/username live ONLY here (never in the Java app, never in
 *     the browser). The Java app holds only the sidecar's shared secret.
 *   - The sidecar is PRIVATE: bind it to localhost / an internal network only,
 *     and require the shared secret (X-Sidecar-Key). Never expose it publicly.
 *   - The EVINA token is never returned (the SDK handlers strip it); the verdict
 *     is computed server-side; raw MSISDNs are redacted in logs by the SDK.
 *
 * How pin-auth (Java) uses it:
 *   1. On PIN request (subscribe/verify/charge): POST /evina/request-script with
 *      { targetSelector, transactionId: <serverRef>, country, userId: <msisdn>,
 *        args: { arg6: <ip>, arg10: <userAgent> } }. Store the returned
 *      transactionId against serverRef (or use serverRef AS transactionId, FR-A6),
 *      and return `script` to the frontend to inject.
 *   2. On PIN submit: after validating the PIN, POST /evina/verify with
 *      { transactionId: <serverRef> }. Proceed to charge/subscribe only if
 *      `allowed` is true.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { timingSafeEqual } from "node:crypto";
import express from "express";
import {
  EvinaClient,
  configFromEnv,
  requestScriptHandler,
  verifyHandler,
  type RequestScriptInput,
  type VerifyInput,
} from "@ideabiz/evina-sdk";

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadDotEnv(path: string): void {
  try {
    for (const line of readFileSync(path, "utf8").split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim();
      if (key && !(key in process.env)) process.env[key] = val;
    }
  } catch {
    /* rely on the real environment */
  }
}

loadDotEnv(resolve(__dirname, "../.env"));
loadDotEnv(resolve(__dirname, "../../../.env"));

const client = new EvinaClient({
  ...configFromEnv(),
  logger: {
    debug: () => undefined,
    info: (m, meta) => console.log("[evina:info]", m, meta ?? ""),
    warn: (m, meta) => console.warn("[evina:warn]", m, meta ?? ""),
    error: (m, meta) => console.error("[evina:error]", m, meta ?? ""),
  },
});

const PORT = Number(process.env["PORT"] ?? 5005);
const SIDECAR_API_KEY = process.env["SIDECAR_API_KEY"] ?? "";

if (SIDECAR_API_KEY.length < 16) {
  console.error(
    "[sidecar] SIDECAR_API_KEY is missing or too short (min 16 chars). " +
      "Set a long random shared secret in .env before starting.",
  );
  process.exit(1);
}

const handleRequestScript = requestScriptHandler(client);
const handleVerify = verifyHandler(client);

// ---------------------------------------------------------------------------
// App + auth guard
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: "64kb" }));

type AsyncHandler = (req: express.Request, res: express.Response) => Promise<void>;
function asyncHandler(fn: AsyncHandler): express.RequestHandler {
  return (req, res, next) => {
    fn(req, res).catch(next);
  };
}

/** Constant-time comparison of the shared secret header. */
function authorized(req: express.Request): boolean {
  const provided = req.header("X-Sidecar-Key") ?? "";
  const a = Buffer.from(provided);
  const b = Buffer.from(SIDECAR_API_KEY);
  // timingSafeEqual requires equal lengths; guard first to avoid throwing.
  return a.length === b.length && timingSafeEqual(a, b);
}

// Require the shared secret on all /evina/* routes.
app.use("/evina", (req, res, next) => {
  if (!authorized(req)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
});

// ---------------------------------------------------------------------------
// Routes — thin pass-throughs to the SDK handlers
// ---------------------------------------------------------------------------

/** Health check (no auth needed). */
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

/**
 * POST /evina/request-script
 * Body: RequestScriptInput
 *   { targetSelector, transactionId?, country?, carrier?, service?, userId?, args? }
 * Returns: { transactionId, script }  (200) — token never included.
 */
app.post(
  "/evina/request-script",
  asyncHandler(async (req, res) => {
    const input = req.body as RequestScriptInput;
    const { status, body } = await handleRequestScript(input);
    res.status(status).json(body);
  }),
);

/**
 * POST /evina/verify
 * Body: VerifyInput  { transactionId, country?, carrier?, service?, userId?, args? }
 * Returns: { allowed, category, reason }  (200) — no ft/token/secrets.
 */
app.post(
  "/evina/verify",
  asyncHandler(async (req, res) => {
    const input = req.body as VerifyInput;
    const { status, body } = await handleVerify(input);
    res.status(status).json(body);
  }),
);

// ---------------------------------------------------------------------------
// Error handler (never leak internals)
// ---------------------------------------------------------------------------

app.use(
  (
    error: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    const msg = error instanceof Error ? error.message : "internal error";
    console.error("[sidecar] error:", msg);
    res.status(500).json({ error: "internal error" });
  },
);

// Bind to loopback by default — this service must stay private.
app.listen(PORT, "127.0.0.1", () => {
  console.log(`\nEVINA sidecar listening on http://127.0.0.1:${PORT} (private)`);
  console.log("Routes: POST /evina/request-script, POST /evina/verify, GET /health");
  console.log("Every /evina/* call requires the X-Sidecar-Key header.\n");
});
