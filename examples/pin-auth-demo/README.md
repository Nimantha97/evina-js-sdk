# pin-auth demo — EVINA-protected PIN subscription

A **local, runnable** stand-in for the real (Java/Spring) `pin-auth` service,
written in Node so it can consume `@ideabiz/evina-sdk` in-process. It reproduces
the *"Evina-protected PIN subscription flow"* end to end:

```
MSISDN entry → request PIN (+ EVINA getScript) → SMS (console) →
inject EVINA kit → submit PIN → validate PIN + EVINA checkTransaction →
SUBSCRIBED only if PIN correct AND EVINA allowed
```

> **Why a Node demo and not the real pin-auth?** The production `pin-auth` is a
> Java/Spring WAR — it cannot import a Node/TypeScript library in-process. This
> demo mirrors pin-auth's exact request/submit HTTP contract so the flow is
> faithful, and proves the SDK end-to-end against the **real EVINA API**. For the
> real Java service, the SDK is consumed as a small Node sidecar over HTTP (the
> same `subscribe`/`submitPin` shape shown here).

---

## Endpoints (mirror the real pin-auth)

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/pin/subscribe/v1/subscribe` | `{ method, msisdn }` | `{ status:"PENDING_AUTH", serverRef, msisdn, method, script }` |
| POST | `/pin/subscribe/v1/submitPin` | `{ pin, serverRef }` | `{ status:"SUBSCRIBED", ... }` on success |

Response wrapper matches pin-auth: `{ statusCode, message, data }`.

- `serverRef` **is** the EVINA transaction id (`ti`) — one id spans both steps
  (SRS FR-A6).
- The EVINA **token is never returned** to the browser; the **verdict is computed
  server-side**; **raw MSISDNs are not logged** (the SDK redacts them).

---

## Prerequisites

1. **Build the SDK first** (the demo consumes the compiled package):
   ```powershell
   # from the repo root
   npm install
   npm run build
   ```
2. **EVINA credentials.** The demo reads them via the SDK's `configFromEnv()`.
   It looks for a `.env` in this folder first, then falls back to the repo-root
   `.env`. Copy the example and fill in real sandbox credentials:
   ```powershell
   copy .env.example .env
   ```
   Required: `EVINA_API_KEY`, `EVINA_USERNAME`. Optional: `EVINA_BASE_URL`,
   `EVINA_DEFAULT_COUNTRY`, `EVINA_DEFAULT_CARRIER`, `PORT`, `DEMO_FORCE_FT`.

   > Never commit real credentials. `.env` is gitignored at the repo root.

---

## Run

```powershell
# from examples/pin-auth-demo
npm install
npm start
```

Then open <http://localhost:4000> and:

1. Enter an MSISDN (e.g. `94777000000`) and click **Request PIN**.
2. Read the PIN printed in the **server console** (this simulates the SMS).
3. Enter the PIN and click **Submit PIN**.
4. See the combined result: `SUBSCRIBED` only when the PIN is correct **and**
   EVINA's verdict is `allowed`.

---

## Prerequisite: EVINA auth must actually work

The demo now reports whether EVINA is genuinely engaged:

- After **Request PIN**, the status line says **"EVINA protection active"** only
  if `getScript` succeeded. If it says **"⚠ EVINA NOT active"**, EVINA rejected the
  call and the submit step will **fail-open** (allow) — which is **not** real fraud
  protection.
- After **Submit PIN**, the result includes `evinaVerdict`: either
  `"evina-allowed"` (a real verdict) or `"fail-open (NOT a real EVINA allow)"`.

### Auth mode (important for this account)

The `dialog_sl` account authenticates via **v1 signature**, not v2 API-key
(ADR-015). So the demo runs in `EVINA_AUTH_MODE=v1-signature` with
`EVINA_USERNAME` + `EVINA_PASSWORD`. This is already set in the repo-root `.env`.

If you ever see `EVINA getScript FAILED: ... invalid-signature`, the signature the
SDK computes isn't matching what EVINA expects. Confirm the exact format with the
one-shot probe (it tries several variants against the live API):

```powershell
# from packages/server
node --import tsx/esm scripts/probe-v1.ts
```

Whichever variant prints `SUCCESS (script returned)` is the correct signature
format; the SDK's default is variant A (`username + encodedQuery + password`). If
a different variant wins, adjust `packages/server/src/sign.ts` accordingly.

## Two run modes (once EVINA auth works)

### Live mode (default)
Leave `DEMO_FORCE_FT` empty. The real EVINA verdict decides allow/block. Because
this uses the real kit, a genuine human click on a real device is what EVINA
scores — so a normal click typically returns authentic (allow).

### Deterministic mode (force allow/block without real fraud)
Set `DEMO_FORCE_FT` in `.env` to an EVINA fraud code, then restart:

| `DEMO_FORCE_FT` | Meaning | Expected result |
|---|---|---|
| `1000` | authentic | SUBSCRIBED (allow) |
| `2100` | code injection (fraud) | Blocked by anti-fraud |
| `3100` | accidental click | Blocked by anti-fraud |

In this mode the page fetches a test-session `etsid` and reloads with
`?etsid=<value>` **before** the EVINA kit loads, so the next `/check` returns the
forced code (EVINA_API_FACTS §11). This is the recommended way to demo the
**block** path to a reviewer.

---

## How this maps to the flow diagram

| Diagram step | Here |
|---|---|
| 1–2 Customer enters MSISDN, requests PIN | Entry page → `POST /subscribe` |
| 3 PIN request carries IP, UA, info | `getScript` with `arg6`=IP, `arg10`=User-Agent |
| 4 SMS to customer | PIN printed to the server console |
| 5 Returns PIN ref (+ Evina param) | `{ serverRef, script }` |
| 6 Evina JS sends device info | Browser injects `script`; kit watches `#submit-pin` |
| 7 Submits PIN | `POST /submitPin` |
| 10 Validates PIN | Server compares PIN |
| 11 Verifies Evina ref | `checkTransaction(serverRef)` |
| 12 Ref matched → success | `SUBSCRIBED` iff PIN ok AND `verdict.allowed` |
