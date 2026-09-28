# EVINA sidecar — production integration for the Java `pin-auth`

The real `pin-auth` is a **Java/Spring** service. It cannot import this
Node/TypeScript SDK in-process. The sidecar solves that: it runs the SDK as a
tiny **private HTTP service** that the Java app calls for the two EVINA
operations.

```
[Browser] → [pin-auth (Java)] → [EVINA sidecar (Node + SDK)] → [EVINA API]
                    │  X-Sidecar-Key                 X-EVINA-APIKEY (secret lives here only)
```

## Endpoints

| Method | Path | Auth | Body | Returns |
|---|---|---|---|---|
| GET | `/health` | none | — | `{ status: "ok" }` |
| POST | `/evina/request-script` | `X-Sidecar-Key` | `RequestScriptInput` | `{ transactionId, script }` |
| POST | `/evina/verify` | `X-Sidecar-Key` | `VerifyInput` | `{ allowed, category, reason }` |

- The EVINA **token is never returned**. The **verdict is computed server-side**.
- The EVINA **API key/username live only in the sidecar**; the Java app holds
  only the sidecar's shared secret.
- The sidecar binds to **127.0.0.1** and requires `X-Sidecar-Key` on every
  `/evina/*` call. Keep it on an internal network — never expose it publicly.

## Run

1. Build the SDK (repo root): `npm run build`.
2. `copy .env.example .env` here and fill in EVINA credentials + a long random
   `SIDECAR_API_KEY`.
3. `npm install` then `npm start`. It listens on `http://127.0.0.1:5005`.

> Note: `npm install` needs registry access. If you are behind a corporate TLS
> proxy, configure npm's CA (`npm config set cafile <corp-root-ca.pem>`) or use
> your internal registry first.

## Calling it (curl)

```bash
# Request the EVINA kit at PIN-request time. transactionId = your serverRef.
curl -s http://127.0.0.1:5005/evina/request-script \
  -H "Content-Type: application/json" \
  -H "X-Sidecar-Key: <your-shared-secret>" \
  -d '{
        "targetSelector": "#submit-pin",
        "transactionId": "<serverRef>",
        "country": "LK",
        "userId": "94777000000",
        "args": { "arg6": "203.0.113.7", "arg10": "Mozilla/5.0 ..." }
      }'
# → { "transactionId": "<serverRef>", "script": "<opaque EVINA JS>" }

# Verify at PIN-submit time (after the PIN itself checks out).
curl -s http://127.0.0.1:5005/evina/verify \
  -H "Content-Type: application/json" \
  -H "X-Sidecar-Key: <your-shared-secret>" \
  -d '{ "transactionId": "<serverRef>" }'
# → { "allowed": true, "category": "authentic", "reason": "authentic (ft=1000)" }
```

## Wiring into the Java `pin-auth`

Per `pin-auth/EVINA-INTEGRATION-AUDIT.md`, add an EVINA client class that calls
the sidecar with the existing `APICall` (`HttpURLConnection`) helper.

1. **Config** — add to `application.properties`:
   ```properties
   evina.sidecar.url=http://127.0.0.1:5005
   evina.sidecar.key=<shared-secret>
   ```
2. **PIN request** (in `PinRegController` / `PinChargeController` /
   `PinVerifyController`): after generating `serverRef`, POST to
   `${evina.sidecar.url}/evina/request-script` with `transactionId=serverRef`,
   `userId=<normalised msisdn>`, `args.arg6=<client IP>`, `args.arg10=<UA>`.
   Return the `script` in the step-1 response for the frontend to inject.
   (Optionally store `serverRef` in the new `EVINA_TI` column — see the audit's
   §7 — though using `serverRef` AS the `transactionId` needs no new column.)
3. **PIN submit** (in `submitPin()`): after the existing
   `pin.equalsIgnoreCase(...)` check passes, POST to
   `${evina.sidecar.url}/evina/verify` with `{ transactionId: serverRef }`.
   Proceed to the downstream charge/subscribe **only if** `allowed == true`;
   otherwise return an ERROR (blocked by anti-fraud).

This keeps pin-auth's existing flow intact and adds EVINA as a gate at submit
time, exactly as the flow diagram (steps 3, 6, 11, 12) describes.
