# @ideabiz/evina-sdk

Server-side TypeScript SDK for [EVINA / DCB Protect](https://docs.evina.com) — the Direct
Carrier Billing anti-fraud service. Wraps the four EVINA v2 endpoints, evaluates fraud
verdicts, manages transaction state, and exposes framework-agnostic HTTP handler factories
ready to mount on any backend.

> **Security first.** This SDK handles API keys and end-user MSISDNs (PII). The API key
> lives **only** on the server — it must never reach the browser. See [Security](#security).

---

## Requirements

- Node.js **≥ 20** (native `fetch`, `AbortController`, `node:crypto` — no polyfills needed)
- Your own EVINA account (`apiKey` + `username`)

---

## Installation

```bash
npm install @ideabiz/evina-sdk
```

Zero runtime dependencies.

---

## Quickstart

```ts
import { EvinaClient, configFromEnv } from "@ideabiz/evina-sdk";

const client = new EvinaClient(configFromEnv());

// 1. Get the EVINA JS kit for a transaction
const { transactionId, script } = await client.getScript({
  targetSelector: "#subscribe-button",
  country: "LK",
});
// Return { transactionId, script } to your frontend.
// Inject `script` into the page; the frontend must NOT receive the token.

// 2. After the user clicks, check the verdict
const verdict = await client.checkTransaction({ transactionId });
if (verdict.allowed) {
  // proceed to bill
} else {
  // block — verdict.category and verdict.reason explain why
}
```

---

## Configuration

Pass an explicit `EvinaConfig` object to the constructor. The core never reads
`process.env` implicitly (ADR-012); use the opt-in `configFromEnv()` helper or build
the object yourself.

```ts
import { EvinaClient } from "@ideabiz/evina-sdk";

const client = new EvinaClient({
  apiKey:   process.env.EVINA_API_KEY!,   // required — keep server-side only
  username: process.env.EVINA_USERNAME!,  // required

  // Optional
  baseUrl:                "https://api.dcbprotect.com", // default
  useCloudflareForScript: false,          // set true for lower /script latency
  defaultCountry:         "LK",          // ISO-3166 alpha-2
  defaultCarrier:         "41302",       // MCC-MNC
  timeoutMs:              10_000,        // default 10 s
  failOpen:               true,          // default — see Fail-open policy below
});
```

### Environment variables (opt-in helper)

```bash
# .env  — never commit real values; use .env.example as a template
EVINA_API_KEY=replace-with-your-evina-api-key
EVINA_USERNAME=replace-with-your-evina-username
EVINA_BASE_URL=https://api.dcbprotect.com
EVINA_DEFAULT_COUNTRY=LK
EVINA_TIMEOUT_MS=10000
EVINA_FAIL_OPEN=true
```

```ts
import { configFromEnv } from "@ideabiz/evina-sdk";
const client = new EvinaClient(configFromEnv());
```

---

## API

### `client.getScript(input)`

Calls `POST /v1/script`. Generates a UUID transaction id if none is supplied, persists
`{ ti, token, country, expiresAt }` to the store (6 h TTL), and returns:

```ts
{
  transactionId: string;  // share with your frontend; use on /check
  token:         string;  // EVINA internal token — server-side only, never send to browser
  script:        string;  // opaque EVINA JS kit — inject into the page
  raw:           unknown; // full EVINA response
}
```

**Input fields** (all optional except `targetSelector`):

| Field | EVINA param | Notes |
|---|---|---|
| `targetSelector` | `te` | CSS selector of the protected button, e.g. `"#subscribe"` |
| `transactionId` | `ti` | Generated (UUID) if absent |
| `country` | `country` | Falls back to `config.defaultCountry` |
| `carrier` | `carrier` | Falls back to `config.defaultCarrier` |
| `service` | `service` | Service name shown on the EVINA dashboard |
| `userId` | `user_id` | MSISDN or alias — passes through `userIdTransform` |
| `purchaseId` | `purchase_id` | Secondary business id |
| `args` | `arg1`–`arg10` | Free-form dashboard fields |
| `tck` | `tck` | Eyewitness replay-merging id |
| `cjv` | `cjv` | Eyewitness activation flag |

### `client.checkTransaction(input)`

Calls `POST /v1/check`. Loads the stored context by `transactionId`, applies the same
`userIdTransform`, and returns a `Verdict`:

```ts
{
  allowed:           boolean;       // true iff success && ft in [1000, 1999]
  ft:                number | null; // raw EVINA fraud code
  category:          FraudCategory; // "authentic" | "fraud" | "accidental" | "error" | "bot" | "custom" | "unknown"
  authenticityScore: number | null; // 0–100
  opinion:           0 | 1 | null;  // EVINA's simple allow/block signal
  success:           boolean;
  reason?:           string;        // human-readable, PII-safe
  failOpen?:         boolean;       // true when verdict came from the fail-open policy
  raw:               unknown;
}
```

### `client.createTestSession(ft)`

Calls `POST /v1/test_session`. Forces the next `/check` to return the given `ft` code,
enabling deterministic allow/block testing without real fraud.

```ts
const { etsid } = await client.createTestSession(2100); // force a fraud verdict
const pageUrl = withEtsid("https://your-page.example.com/subscribe", etsid);
// Load pageUrl in the browser, then run the normal getScript → click → checkTransaction flow.
```

### `client.notifyTransaction(input)`

Calls `POST /v1/transaction` (best-effort, never throws). Tells EVINA the user was
charged, improving dashboard accuracy.

```ts
await client.notifyTransaction({ transactionId, purchaseId: "order-123" });
```

---

## HTTP handler factories (framework-agnostic)

For backends that need ready-to-mount endpoints rather than raw SDK method calls, the
library provides two transport-agnostic handler factories. Each returns an async function
`(input) => { status, body }` — no web-framework dependency.

```ts
import { EvinaClient, requestScriptHandler, verifyHandler } from "@ideabiz/evina-sdk";

const client = new EvinaClient(/* config */);
const handleRequestScript = requestScriptHandler(client);
const handleVerify        = verifyHandler(client);

// Mount on any framework — example with Express:
app.get("/evina/script", async (req, res) => {
  const { status, body } = await handleRequestScript({
    targetSelector: req.query.selector as string,
    country: req.query.country as string | undefined,
  });
  res.status(status).json(body);
});

app.post("/evina/verify", async (req, res) => {
  const { status, body } = await handleVerify({
    transactionId: req.body.transactionId as string,
  });
  res.status(status).json(body);
});
```

**`requestScriptHandler` response** (HTTP 200):
```json
{ "transactionId": "...", "script": "..." }
```
The EVINA token is **never** included.

**`verifyHandler` response** (HTTP 200):
```json
{ "allowed": true, "category": "authentic", "reason": "authentic (ft=1000)" }
```
Raw `ft`, the token, and all secrets are **never** included.

**Error responses**: `400` for bad input, `502` for upstream EVINA errors, `500` for
unexpected errors. Error bodies are `{ "error": "<safe message>" }` — no secrets or PII.

---

## Fail-open policy

By default (`failOpen: true`) the SDK **allows** a transaction when EVINA is unreachable
(non-200, non-JSON, timeout, network error). This matches EVINA's official guidance: don't
block legitimate revenue during a transient outage.

Every fail-open decision is logged at `warn` level (PII-safe) so you can detect sustained
degradation.

For high-security deployments, set `failOpen: false` to block on infrastructure errors.

> **Important:** the default fail-open means a prolonged EVINA outage lets transactions
> through. Wire up the warn-level log to an alert.

---

## Transaction store

The default `InMemoryTransactionStore` is suitable for **single-instance / development**
deployments only. State is not shared across processes — a `/script` handled by one node
and a `/check` handled by another will not find the stored context.

For clustered deployments, inject a shared store:

```ts
import { EvinaClient, type TransactionStore } from "@ideabiz/evina-sdk";

class RedisTransactionStore implements TransactionStore {
  // implement save / get / delete with TTL
}

const client = new EvinaClient({
  apiKey: "...", username: "...",
  store: new RedisTransactionStore(),
});
```

---

## `user_id` / MSISDN handling

`userId` is passed through the optional `userIdTransform` hook before being sent to EVINA.
The **same transform is applied on both `/script` and `/check`** — if they differ, EVINA
cannot correlate the calls.

```ts
import { createHash } from "node:crypto";

const client = new EvinaClient({
  apiKey: "...", username: "...",
  userIdTransform: (msisdn) =>
    createHash("sha256").update(`salt:${msisdn}`).digest("hex"),
});
```

> **Never use base64** as a `userIdTransform` — it is reversible encoding with zero security
> value, not encryption.

---

## Observability

Plug in your own logger:

```ts
import { EvinaClient, type Logger } from "@ideabiz/evina-sdk";

const client = new EvinaClient({
  apiKey: "...", username: "...",
  logger: {
    debug: (m, meta) => myLogger.debug(m, meta),
    info:  (m, meta) => myLogger.info(m, meta),
    warn:  (m, meta) => myLogger.warn(m, meta),   // fail-open events appear here
    error: (m, meta) => myLogger.error(m, meta),
  },
});
```

The SDK's internal redacting wrapper ensures secrets and raw MSISDNs never reach the
logger sink, even if they accidentally appear in a log call.

---

## Security

| Rule | Detail |
|---|---|
| API key server-side only | Never pass `apiKey` to the browser or include it in any client-facing response |
| HTTPS only | `baseUrl` must be `https://`; non-HTTPS is rejected at construction |
| Host pinning | Only `api.dcbprotect.com` and `api.clfldcbprotect.com` are accepted |
| No raw MSISDNs in logs | The SDK redacts MSISDN-like digit runs from all log output |
| Token never to browser | `getScript` returns `token` — keep it server-side; the handler factories strip it automatically |
| Verdict server-side | `allowed` is computed from EVINA's `ft`; the client cannot influence it |
| Zero runtime deps | No supply-chain risk from transitive packages |

See `evina-js-sdk-docs/THREAT_MODEL.md` for the full STRIDE analysis and
`evina-js-sdk-docs/SRS.md` §8 for the security review checklist.

---

## Running the example

```bash
cd examples/server-express
cp .env.example .env          # fill in your EVINA test credentials
npm install
npm start
# Open http://localhost:3000 and follow the console instructions
```

See [`examples/server-express/README.md`](examples/server-express/README.md) for the
full walkthrough.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
