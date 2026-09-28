/**
 * EVINA SDK — pin-auth-style demo server
 * =====================================================================
 *
 * A LOCAL, runnable stand-in for the real (Java/Spring) `pin-auth` service,
 * built in Node so it can consume `@ideabiz/evina-sdk` in-process. It mirrors
 * the real pin-auth request/submit contract (see pin-auth/PIN-Subscription.md
 * and PIN-Verify.md) and layers EVINA DCB Protect anti-fraud on top, exactly as
 * the "Evina-protected PIN subscription flow" diagram describes.
 *
 * Actors in the diagram → this demo:
 *   Customer  = the browser (MSISDN entry page + PIN submit page)
 *   Vendor    = this server's PIN endpoints (subscribe / submitPin)
 *   Ideabiz   = this server too (single-account model — we own EVINA creds)
 *   Evina     = the real EVINA API, called via the SDK
 *
 * The flow (numbers match the diagram):
 *   1-2  Customer opens the page, enters MSISDN, requests PIN.
 *   3    POST /pin/subscribe/v1/subscribe {method, msisdn}
 *          → we generate an OTP (printed to the console, simulating SMS),
 *            call EVINA getScript (arg6=IP, arg10=User-Agent), store
 *            {serverRef, pin, msisdn, ti} and return {serverRef, script}.
 *   4    "SMS" delivered (console).
 *   5    Response carries the PIN ref (serverRef) + the EVINA kit (script).
 *   6    The browser injects the EVINA kit; it watches the real click.
 *   7    Customer submits the PIN.
 *   9-11 POST /pin/subscribe/v1/submitPin {pin, serverRef}
 *          → we validate the PIN AND call EVINA checkTransaction.
 *   12   SUBSCRIBED only if PIN correct AND EVINA verdict allowed.
 *
 * Correlation (FR-A6): the EVINA transaction id (`ti`) IS the pin-auth
 * `serverRef` — one id travels between the two steps, stored server-side.
 *
 * Security posture (unchanged from the SDK's guarantees):
 *   - The EVINA API key / username live only here, never reach the browser.
 *   - The EVINA token is never returned to the browser.
 *   - The verdict is computed server-side; the browser only sends `serverRef`.
 *   - Raw MSISDNs are not logged (the SDK's logger redacts them).
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import express from "express";
import { EvinaClient, configFromEnv, type Verdict } from "@ideabiz/evina-sdk";

// ---------------------------------------------------------------------------
// Bootstrap: load .env, build the EVINA client (Mode B — real EVINA)
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Minimal .env loader (no dotenv dependency). */
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
    /* no .env — rely on the real environment */
  }
}

// Prefer the demo's own .env; fall back to the repo-root .env (which holds the
// real EVINA credentials during development).
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

const PORT = Number(process.env["PORT"] ?? 4000);
/** Optional: force an EVINA ft via /v1/test_session for a deterministic demo. */
const DEMO_FORCE_FT = process.env["DEMO_FORCE_FT"]
  ? Number(process.env["DEMO_FORCE_FT"])
  : undefined;

// ---------------------------------------------------------------------------
// In-memory PIN transaction store (the demo's own state, NOT the SDK store)
// ---------------------------------------------------------------------------

interface PinTxn {
  serverRef: string; // = EVINA ti (FR-A6)
  msisdn: string; // normalised digits, e.g. "94777xxxxxx"
  method: string; // e.g. "ANC"
  pin: string; // the OTP we "SMS"ed
  attempts: number;
  status: "PENDING_AUTH" | "SUBSCRIBED" | "FAILED";
  createdAt: number;
}

const MAX_ATTEMPTS = 3;
const pinTxns = new Map<string, PinTxn>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** pin-auth's standard response wrapper. */
function ok(message: string | null, data: unknown): object {
  return { statusCode: "SUCCESS", message, data };
}
function err(message: string): object {
  return { statusCode: "ERROR", message, data: null };
}

/** Normalise "tel:+94..." / "+94..." / "0777..." to plain digits (demo-grade). */
function normaliseMsisdn(raw: string): string {
  return raw.replace(/^tel:/i, "").replace(/[^\d]/g, "");
}

/** Generate a 6-digit numeric OTP (SecureRandom-equivalent for the demo). */
function generatePin(): string {
  const n = Math.floor(100000 + Math.random() * 900000);
  return String(n);
}

type AsyncHandler = (req: express.Request, res: express.Response) => Promise<void>;
function asyncHandler(fn: AsyncHandler): express.RequestHandler {
  return (req, res, next) => {
    fn(req, res).catch(next);
  };
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ---- Step 3/5: PIN request (Vendor) — mirrors pin-auth subscribe ----------
//
// POST /pin/subscribe/v1/subscribe   body: { method, msisdn }
// Returns { status:"PENDING_AUTH", serverRef, msisdn, method, script }.
// The EVINA `script` (kit) is returned so the browser can inject it (step 6).
// The EVINA token is NEVER returned.
app.post(
  "/pin/subscribe/v1/subscribe",
  asyncHandler(async (req, res) => {
    const body = req.body as { method?: string; msisdn?: string; selector?: string };
    const method = body.method ?? "ANC";
    const rawMsisdn = body.msisdn ?? "";
    const msisdn = normaliseMsisdn(rawMsisdn);
    // CSS selector of the button the EVINA kit will watch (step 6).
    const targetSelector = body.selector ?? "#submit-pin";

    if (msisdn.length < 9) {
      res.status(400).json(err("Invalid MSISDN"));
      return;
    }

    // serverRef == EVINA ti (FR-A6): generate once, reuse in both steps.
    const serverRef = randomUUID();

    // --- EVINA getScript (diagram step 3: PIN request carries IP, UA, info) ---
    let script = "";
    let evinaProtected = false;
    let evinaError: string | undefined;
    try {
      // Minimal param set — matches the proven server-express demo. `country`
      // comes from config.defaultCountry (EVINA_DEFAULT_COUNTRY). Extra params
      // (userId/service/args) are intentionally omitted here to keep the live
      // /v1/script call identical to the shape that already works; add them back
      // once live auth is confirmed.
      const result = await client.getScript({
        targetSelector,
        transactionId: serverRef, // ti = serverRef
      });
      script = result.script;
      evinaProtected = true; // a real EVINA transaction now exists in the store
    } catch (e) {
      // getScript failed → NO EVINA transaction was stored. The PIN flow can
      // still run, but the fraud check at submit time will fail-open (allow),
      // which is NOT real fraud protection. We surface this loudly so a demo
      // reviewer never mistakes a fail-open for a genuine EVINA "allow".
      evinaError = e instanceof Error ? e.message : "unknown error";
      console.error(
        "\n[demo] !!! EVINA getScript FAILED:",
        evinaError,
        "\n[demo] !!! Fraud protection is NOT active for this transaction.",
        "\n[demo] !!! The submit step will FAIL-OPEN (allow) — this is not a real EVINA verdict.\n",
      );
    }

    // --- Generate + "send" the OTP (diagram step 4: SMS). Console = SMS. ---
    const pin = generatePin();
    pinTxns.set(serverRef, {
      serverRef,
      msisdn,
      method,
      pin,
      attempts: 0,
      status: "PENDING_AUTH",
      createdAt: Date.now(),
    });

    console.log("\n=== [SMS SIMULATION] ===============================");
    console.log(`  To    : +${msisdn}`);
    console.log(`  PIN   : ${pin}`);
    console.log(`  Ref   : ${serverRef}`);
    console.log("====================================================\n");

    res.json(
      ok(null, {
        status: "PENDING_AUTH",
        serverRef,
        msisdn: `tel:+${msisdn}`,
        method,
        script, // opaque EVINA kit — inject into the page (FR-A4)
        evinaProtected, // true only if getScript succeeded (real protection active)
        ...(evinaError !== undefined && { evinaError }),
      }),
    );
  }),
);

// ---- Optional deterministic demo helper -----------------------------------
//
// GET /demo/etsid  → creates an EVINA test session forcing DEMO_FORCE_FT and
// returns { etsid }. The page must append `?etsid=<value>` to its own URL and
// reload BEFORE the kit loads, so the next /check returns the forced ft
// (EVINA_API_FACTS §11). No-op (404) unless DEMO_FORCE_FT is configured.
app.get(
  "/demo/etsid",
  asyncHandler(async (_req, res) => {
    if (DEMO_FORCE_FT === undefined || !Number.isInteger(DEMO_FORCE_FT)) {
      res.status(404).json(err("DEMO_FORCE_FT not configured"));
      return;
    }
    try {
      const session = await client.createTestSession(DEMO_FORCE_FT);
      console.log(`[demo] Forcing EVINA ft=${session.ft} (etsid=${session.etsid})`);
      res.json(ok(null, { etsid: session.etsid, ft: session.ft }));
    } catch (e) {
      const msg = e instanceof Error ? e.message : "unknown error";
      res.status(502).json(err(`createTestSession failed: ${msg}`));
    }
  }),
);

// ---- Step 9-12: PIN submit (Vendor) — mirrors pin-auth submitPin ----------
//
// POST /pin/subscribe/v1/submitPin   body: { pin, serverRef }
// SUBSCRIBED only if the PIN is correct AND EVINA's verdict is `allowed`.
app.post(
  "/pin/subscribe/v1/submitPin",
  asyncHandler(async (req, res) => {
    const body = req.body as { pin?: string; serverRef?: string };
    const pin = body.pin ?? "";
    const serverRef = body.serverRef ?? "";

    const txn = pinTxns.get(serverRef);
    if (txn === undefined) {
      res.status(404).json(err("Unknown or expired serverRef"));
      return;
    }
    if (txn.status === "SUBSCRIBED") {
      res.json(ok("Subscription Status", publicTxn(txn)));
      return;
    }
    if (txn.attempts >= MAX_ATTEMPTS) {
      res.status(429).json(err("Max attempt exceeded"));
      return;
    }

    // --- Step 10: validate the PIN (pin-auth's own responsibility) ---------
    txn.attempts += 1;
    const pinCorrect = txn.pin === pin.trim();
    if (!pinCorrect) {
      res.status(400).json(err("Wrong PIN"));
      return;
    }

    // --- Step 11: EVINA verdict (checkTransaction, ti == serverRef) --------
    let verdict: Verdict;
    try {
      verdict = await client.checkTransaction({ transactionId: serverRef });
    } catch (e) {
      // checkTransaction resolves infra errors via the fail-open policy, so a
      // throw here is unexpected (e.g. invalid ti). Treat as a hard failure.
      const msg = e instanceof Error ? e.message : "unknown error";
      res.status(500).json(err(`Verification error: ${msg}`));
      return;
    }

    // --- Step 12: combine PIN result AND EVINA verdict ---------------------
    if (!verdict.allowed) {
      txn.status = "FAILED";
      // Do NOT leak ft / raw EVINA internals to the client (FR-29).
      res.status(403).json(
        err(`Blocked by anti-fraud (${verdict.category})`),
      );
      return;
    }

    txn.status = "SUBSCRIBED";

    // Best-effort charge notification to EVINA (never blocks the flow).
    void client.notifyTransaction({ transactionId: serverRef, purchaseId: serverRef });

    // Surface whether this "allow" came from a real EVINA verdict or fail-open,
    // so a demo reviewer can tell genuine protection from a degraded path.
    const evinaVerdict = verdict.failOpen === true ? "fail-open (NOT a real EVINA allow)" : "evina-allowed";
    res.json(
      ok("Subscription Status", { ...publicTxn(txn), evinaVerdict }),
    );
  }),
);

/** Public projection of a PIN txn — never exposes the PIN or EVINA internals. */
function publicTxn(txn: PinTxn): object {
  return {
    status: txn.status,
    serverRef: txn.serverRef,
    msisdn: `tel:+${txn.msisdn}`,
    method: txn.method,
  };
}

// ---------------------------------------------------------------------------
// Static demo pages
// ---------------------------------------------------------------------------

app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(PAGE_HTML);
});

app.listen(PORT, () => {
  console.log(`\npin-auth demo (EVINA-protected) running on http://localhost:${PORT}`);
  console.log("Open that URL, enter an MSISDN, request a PIN, then submit it.");
  if (DEMO_FORCE_FT !== undefined) {
    console.log(`Deterministic demo mode: forcing EVINA ft=${DEMO_FORCE_FT}.`);
  } else {
    console.log("Live mode: using the real EVINA verdict.");
  }
  console.log("");
});

// ---------------------------------------------------------------------------
// Demo page (MSISDN entry + PIN submit) — self-contained single page
// ---------------------------------------------------------------------------
//
// This is the "Customer" surface from the diagram. It runs the full flow:
//   1. Enter MSISDN → POST /pin/subscribe/v1/subscribe
//   2. Inject the returned EVINA kit (script) into the page (FR-A4)
//   3. Enter the OTP printed in the server console → POST .../submitPin
//   4. Show the combined result (PIN + EVINA verdict)
//
const PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EVINA-protected PIN subscription — demo</title>
  <style>
    :root { font-family: system-ui, sans-serif; }
    body { max-width: 560px; margin: 40px auto; padding: 0 20px; color: #1a1a2e; }
    h1 { font-size: 20px; }
    .card { border: 1px solid #e0e0e8; border-radius: 10px; padding: 20px; margin: 16px 0; }
    .card.disabled { opacity: 0.45; pointer-events: none; }
    label { display: block; font-size: 13px; color: #555; margin-bottom: 6px; }
    input { width: 100%; padding: 10px 12px; font-size: 16px; border: 1px solid #ccc;
            border-radius: 6px; box-sizing: border-box; }
    button { margin-top: 12px; padding: 11px 20px; font-size: 15px; border: 0;
             border-radius: 6px; background: #2d2d5f; color: #fff; cursor: pointer; }
    button:disabled { background: #b7b7c9; cursor: not-allowed; }
    .step { font-size: 12px; text-transform: uppercase; letter-spacing: .05em;
            color: #888; margin-bottom: 8px; }
    pre { background: #f5f5fa; padding: 12px; border-radius: 6px; overflow-x: auto;
          font-size: 13px; white-space: pre-wrap; word-break: break-word; }
    .allow { color: #137333; font-weight: 600; }
    .block { color: #c5221f; font-weight: 600; }
    .muted { color: #888; font-size: 12px; }
  </style>
</head>
<body>
  <h1>EVINA-protected PIN subscription</h1>
  <p class="muted">Demo of <code>@ideabiz/evina-sdk</code> wrapping a pin-auth-style
  subscribe / submitPin flow. Enter an MSISDN, request a PIN (printed in the server
  console), then submit it. Subscription succeeds only if the PIN is correct AND
  EVINA allows the transaction.</p>

  <div class="card" id="card-request">
    <div class="step">Step 1 — MSISDN entry</div>
    <label for="msisdn">Mobile number (MSISDN)</label>
    <input id="msisdn" placeholder="94777000000" value="94777000000" />
    <button id="btn-request">Request PIN</button>
    <p class="muted" id="request-status"></p>
  </div>

  <div class="card disabled" id="card-submit">
    <div class="step">Step 2 — Submit PIN</div>
    <label for="pin">Enter the PIN (see server console)</label>
    <input id="pin" placeholder="6-digit PIN" inputmode="numeric" />
    <button id="submit-pin">Submit PIN</button>
    <p class="muted" id="submit-status"></p>
  </div>

  <div class="card" id="card-result" style="display:none">
    <div class="step">Result</div>
    <pre id="result">—</pre>
  </div>

  <script>
    (function () {
      // Deterministic demo (DEMO_FORCE_FT set on the server): always fetch a
      // FRESH test-session etsid on each page load and reload once with it on
      // the URL, so the forced ft is honoured at /check time (EVINA_API_FACTS
      // §11). We use sessionStorage as a one-shot guard so we reload exactly
      // once per run and never loop — and never reuse a stale etsid from a
      // previous ft value.
      var justReloaded = sessionStorage.getItem('evina_etsid_done');
      if (justReloaded) {
        // consume the flag so the NEXT manual page load fetches a fresh etsid
        sessionStorage.removeItem('evina_etsid_done');
      } else {
        fetch('/demo/etsid')
          .then(function (r) { return r.ok ? r.json() : null; })
          .then(function (res) {
            if (res && res.data && res.data.etsid) {
              sessionStorage.setItem('evina_etsid_done', '1');
              var u = new URL(location.href);
              u.searchParams.set('etsid', res.data.etsid);
              location.replace(u.toString());
            }
            // If /demo/etsid 404s (DEMO_FORCE_FT not set), this is live mode —
            // do nothing, use the real verdict.
          })
          .catch(function () { /* live mode — no forced ft */ });
      }

      var serverRef = null;
      var msisdnEl = document.getElementById('msisdn');
      var pinEl = document.getElementById('pin');
      var btnRequest = document.getElementById('btn-request');
      var btnSubmit = document.getElementById('submit-pin');
      var reqStatus = document.getElementById('request-status');
      var subStatus = document.getElementById('submit-status');
      var cardSubmit = document.getElementById('card-submit');
      var cardResult = document.getElementById('card-result');
      var resultEl = document.getElementById('result');

      function show(el, text, cls) {
        el.textContent = text;
        el.className = cls || 'muted';
      }

      // Step 1: request the PIN + EVINA kit.
      btnRequest.addEventListener('click', function () {
        btnRequest.disabled = true;
        show(reqStatus, 'Requesting PIN…');
        fetch('/pin/subscribe/v1/subscribe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ method: 'ANC', msisdn: msisdnEl.value, selector: '#submit-pin' }),
        })
          .then(function (r) { return r.json(); })
          .then(function (res) {
            if (res.statusCode !== 'SUCCESS') { throw new Error(res.message || 'request failed'); }
            serverRef = res.data.serverRef;
            // Step 6: inject the opaque EVINA kit; it watches the #submit-pin button.
            if (res.data.script) {
              var s = document.createElement('script');
              s.textContent = res.data.script;
              document.head.appendChild(s);
            }
            var protectedMsg = res.data.evinaProtected
              ? 'EVINA protection active.'
              : '⚠ EVINA NOT active (' + (res.data.evinaError || 'no kit') +
                ') — submit will FAIL-OPEN, not a real verdict.';
            show(reqStatus,
              'PIN sent. Check the server console for the code. ' + protectedMsg,
              res.data.evinaProtected ? 'muted' : 'block');
            cardSubmit.classList.remove('disabled');
            pinEl.focus();
          })
          .catch(function (e) {
            show(reqStatus, 'Error: ' + e.message, 'block');
            btnRequest.disabled = false;
          });
      });

      // Step 2: submit the PIN → server validates PIN + EVINA verdict.
      btnSubmit.addEventListener('click', function () {
        if (!serverRef) { return; }
        btnSubmit.disabled = true;
        show(subStatus, 'Verifying…');
        fetch('/pin/subscribe/v1/submitPin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pin: pinEl.value, serverRef: serverRef }),
        })
          .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }); })
          .then(function (out) {
            cardResult.style.display = 'block';
            resultEl.textContent = JSON.stringify(out.body, null, 2);
            if (out.ok && out.body.statusCode === 'SUCCESS') {
              show(subStatus, '✅ SUBSCRIBED — PIN correct and EVINA allowed.', 'allow');
              resultEl.className = 'allow';
            } else {
              show(subStatus, '🚫 ' + (out.body.message || 'Failed'), 'block');
              resultEl.className = 'block';
              btnSubmit.disabled = false;
            }
          })
          .catch(function (e) {
            show(subStatus, 'Error: ' + e.message, 'block');
            btnSubmit.disabled = false;
          });
      });
    })();
  </script>
</body>
</html>`;
