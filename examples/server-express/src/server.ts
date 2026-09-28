/**
 * EVINA SDK — Express example server (M8)
 *
 * Demonstrates the full hosted-page flow end-to-end using /v1/test_session
 * to force a chosen ft code, so no real fraud is needed.
 *
 * Flow:
 *   1. POST /demo/start?ft=<code>
 *      Creates a test session that forces the given ft on the next /check.
 *      Returns { etsid, pageUrl, ft }.
 *   2. GET  /evina/script?selector=<css>&etsid=<etsid>
 *      Calls client.getScript via the handler factory.
 *      Returns { transactionId, script } — token is never returned.
 *   3. POST /evina/verify  body: { transactionId }
 *      Calls client.checkTransaction via the handler factory.
 *      Returns { allowed, category, reason } — ft/token/secrets never returned.
 *
 * Security reminders (enforced by the SDK):
 *   - The EVINA token is never returned to the browser.
 *   - The API key is never returned to the browser.
 *   - The verdict is computed server-side from EVINA's ft.
 */

import "node:process";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import {
  EvinaClient,
  configFromEnv,
  requestScriptHandler,
  verifyHandler,
  withEtsid,
} from "@ideabiz/evina-sdk";

// ---------------------------------------------------------------------------
// Helpers (defined first so loadDotEnv can be called before configFromEnv)
// ---------------------------------------------------------------------------

function loadDotEnv(path: string): void {
  try {
    const lines = readFileSync(path, "utf8").split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim();
      if (key && !(key in process.env)) {
        process.env[key] = val;
      }
    }
  } catch {
    // .env not present — rely on real environment variables.
  }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load .env before anything else — must happen before configFromEnv().
loadDotEnv(resolve(__dirname, "../.env"));

const client = new EvinaClient({
  ...configFromEnv(),
  logger: {
    debug: () => undefined,
    info:  (m, meta) => console.log("[evina:info]", m, meta ?? ""),
    warn:  (m, meta) => console.warn("[evina:warn]", m, meta ?? ""),
    error: (m, meta) => console.error("[evina:error]", m, meta ?? ""),
  },
});

const handleRequestScript = requestScriptHandler(client);
const handleVerify        = verifyHandler(client);

/**
 * Wrap an async Express handler so the returned promise is consumed here
 * (satisfies @typescript-eslint/no-misused-promises — Express ignores the
 * return value, so we must not hand it a promise directly). Any rejection is
 * forwarded to Express's error pipeline.
 */
type AsyncExpressHandler = (
  req: express.Request,
  res: express.Response,
) => Promise<void>;

function asyncHandler(fn: AsyncExpressHandler): express.RequestHandler {
  return (req, res, next) => {
    fn(req, res).catch(next);
  };
}

const app  = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const PORT = Number(process.env["PORT"] ?? 3000);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * Step 1 — Start a demo run by creating a test session.
 *
 * POST /demo/start?ft=<fraud-code>
 *
 * ft examples:
 *   1000 → authentic (allow)
 *   2100 → code injection (block)
 *   3100 → accidental click (block)
 *   4101 → kit expired (block)
 */
app.post("/demo/start", asyncHandler(async (req, res) => {
  const ftRaw = req.query["ft"] ?? (req.body as Record<string, unknown>)["ft"];
  const ft = Number(ftRaw);
  if (!Number.isInteger(ft)) {
    res.status(400).json({ error: "ft query param must be an integer, e.g. ?ft=1000" });
    return;
  }

  try {
    const session = await client.createTestSession(ft);
    const pageUrl = withEtsid(`http://localhost:${PORT}/demo/page`, session.etsid);
    console.log("\n--- Demo started ---");
    console.log(`Forced ft: ${session.ft}  etsid: ${session.etsid}`);
    console.log(`Open this URL in a browser: ${pageUrl}\n`);
    res.json({ etsid: session.etsid, ft: session.ft, pageUrl });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unknown error";
    res.status(502).json({ error: `createTestSession failed: ${msg}` });
  }
}));

/**
 * Step 2 — Request the EVINA script (the backend-contract endpoint).
 *
 * GET /evina/script?selector=%23subscribe&etsid=<etsid>
 *
 * Returns { transactionId, script }. Token is never returned.
 */
app.get("/evina/script", asyncHandler(async (req, res) => {
  const selector = (req.query["selector"] as string | undefined) ?? "#subscribe";

  const { status, body } = await handleRequestScript({
    targetSelector: selector,
  });
  res.status(status).json(body);
}));

/**
 * Step 3 — Verify the transaction (the backend-contract endpoint).
 *
 * POST /evina/verify
 * Body: { transactionId: string }
 *
 * Returns { allowed, category, reason }. ft/token/secrets never returned.
 */
app.post("/evina/verify", asyncHandler(async (req, res) => {
  const { status, body } = await handleVerify({
    transactionId: (req.body as { transactionId?: string }).transactionId ?? "",
  });
  res.status(status).json(body);
}));

/** Demo HTML page — simulates the consumer's subscription page. */
app.get("/demo/page", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(DEMO_PAGE_HTML);
});

/** Root — usage instructions. */
app.get("/", (_req, res) => {
  res.json({
    usage: {
      "1_start_demo": "POST /demo/start?ft=1000  (or ft=2100 to test block)",
      "2_get_script": "GET  /evina/script?selector=%23subscribe",
      "3_verify":     "POST /evina/verify  body: { transactionId }",
      "demo_page":    `GET  http://localhost:${PORT}/demo/page?etsid=<etsid>`,
    },
    ft_examples: {
      1000: "authentic → allow",
      2100: "code injection → block",
      3100: "accidental click → block",
      4101: "kit expired → block",
    },
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`\nEVINA SDK example server running on http://localhost:${PORT}`);
  console.log("Quick start:");
  console.log(`  curl -X POST "http://localhost:${PORT}/demo/start?ft=1000"`);
  console.log(`  curl -X POST "http://localhost:${PORT}/demo/start?ft=2100"\n`);
});

// ---------------------------------------------------------------------------
// Demo page HTML (inline — keeps the example self-contained)
// ---------------------------------------------------------------------------

const DEMO_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>EVINA SDK Demo</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
    button { padding: 12px 24px; font-size: 16px; cursor: pointer; }
    pre { background: #f4f4f4; padding: 12px; border-radius: 4px; overflow-x: auto; }
    .allow { color: green; } .block { color: red; } .err { color: orange; }
  </style>
</head>
<body>
  <h1>EVINA SDK Demo</h1>
  <p>Simulates a subscription page protected by EVINA DCB Protect.</p>
  <p id="status">Loading EVINA script\u2026</p>
  <button id="subscribe" disabled>Subscribe</button>
  <h2>Verdict</h2>
  <pre id="verdict">\u2014</pre>
  <script>
    (async () => {
      const etsid = new URLSearchParams(location.search).get('etsid') ?? '';
      const statusEl  = document.getElementById('status');
      const btn       = document.getElementById('subscribe');
      const verdictEl = document.getElementById('verdict');

      let transactionId;
      try {
        const params = new URLSearchParams({ selector: '#subscribe' });
        if (etsid) params.set('etsid', etsid);
        const r    = await fetch('/evina/script?' + params);
        const data = await r.json();
        if (!r.ok) throw new Error(data.error ?? 'script request failed');
        transactionId = data.transactionId;
        // Inject the opaque EVINA kit — consumer's responsibility (FR-A4).
        const s = document.createElement('script');
        s.textContent = data.script;
        document.head.appendChild(s);
        statusEl.textContent = 'EVINA kit loaded. Click Subscribe to test.';
        btn.disabled = false;
      } catch (e) {
        statusEl.textContent = 'Failed to load EVINA kit: ' + e.message;
        statusEl.className = 'err';
        return;
      }

      btn.addEventListener('click', async () => {
        btn.disabled = true;
        statusEl.textContent = 'Verifying\u2026';
        try {
          const r = await fetch('/evina/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ transactionId }),
          });
          const verdict = await r.json();
          verdictEl.textContent = JSON.stringify(verdict, null, 2);
          verdictEl.className = verdict.allowed ? 'allow' : 'block';
          statusEl.textContent = verdict.allowed
            ? '\u2705 Allowed \u2014 proceed to billing'
            : '\uD83D\uDEAB Blocked \u2014 ' + (verdict.reason ?? verdict.category);
        } catch (e) {
          verdictEl.textContent = e.message;
          verdictEl.className = 'err';
        }
      });
    })();
  </script>
</body>
</html>`;

