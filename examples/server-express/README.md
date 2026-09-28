# EVINA SDK — Express Example

End-to-end demo of `@ideabiz/evina-sdk` using Express. Drives the full hosted-page
flow with `/v1/test_session` to force any `ft` code — no real fraud needed.

## Prerequisites

- Node.js ≥ 20
- An EVINA test account (`apiKey` + `username`)

## Setup

```bash
cd examples/server-express
cp .env.example .env
# Edit .env and fill in your EVINA test credentials
npm install
npm start
```

The server starts on `http://localhost:3000`.

## Walkthrough

### 1. Start a demo run (force a verdict)

```bash
# Force an authentic verdict (ft=1000 → allowed)
curl -X POST "http://localhost:3000/demo/start?ft=1000"

# Force a fraud verdict (ft=2100 → blocked)
curl -X POST "http://localhost:3000/demo/start?ft=2100"
```

Response:
```json
{
  "etsid": "abc123...",
  "ft": 1000,
  "pageUrl": "http://localhost:3000/demo/page?etsid=abc123..."
}
```

### 2. Open the demo page

Open the `pageUrl` from step 1 in a browser. The page:
- Fetches the EVINA script from `/evina/script` (your backend contract endpoint)
- Injects the opaque EVINA kit into the page
- Enables the Subscribe button

### 3. Click Subscribe

The page calls `/evina/verify` with the `transactionId` and displays the verdict:

```json
{ "allowed": true, "category": "authentic", "reason": "authentic (ft=1000)" }
```

or for `ft=2100`:

```json
{ "allowed": false, "category": "fraud", "reason": "fraud (ft=2100)" }
```

## Useful ft codes

| ft | Category | Result |
|---|---|---|
| `1000` | authentic | allow |
| `2100` | code injection | block |
| `3100` | accidental click | block |
| `4101` | kit expired | block |
| `5101` | Google Bot | block |

## API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/demo/start?ft=<n>` | Create test session, get `etsid` + `pageUrl` |
| `GET` | `/evina/script?selector=<css>` | Get `{ transactionId, script }` |
| `POST` | `/evina/verify` | Verify `{ transactionId }` → `{ allowed, category, reason }` |
| `GET` | `/demo/page?etsid=<id>` | Interactive demo page |

## Security notes

- The EVINA API key is read from the environment and never sent to the browser.
- The EVINA token (`t`) is stored server-side and never included in any response.
- The verdict (`allowed`) is computed server-side from EVINA's `ft` — the browser
  cannot influence it.
- This example uses `tsx` for TypeScript execution in development only. In production,
  compile with `tsc` or `tsup` and run the compiled JS.
