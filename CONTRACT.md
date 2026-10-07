# API contract (shared by backend, frontend, rules/samples)

Runs on **http://localhost:4000**, Node 24, **no npm dependencies, no build step**, ES modules.

Model: `gpt-oss-120b` on Cerebras (`https://api.cerebras.ai/v1`, OpenAI-compatible, key in `.env` as `CEREBRAS_API_KEY`).
The account has a low **tokens-per-minute quota** (HTTP 429 `token_quota_exceeded`). Keep live model calls rare during development, keep test scripts small, wait ~60 s after a 429.

## File ownership
- Backend agent: `server.js`, `lib/*.js` except `lib/static-scan.js`, `fixtures/*.ndjson`
- Frontend agent: `public/*`
- Rules/samples agent: `lib/static-scan.js`, `samples/*`, `samples/index.json`

## HTTP API

### `POST /api/analyze`
Request JSON: `{ "script": string, "source"?: string (URL/filename), "mock"?: string (fixture name), "nocache"?: boolean }`
Response: `application/x-ndjson`, one JSON object per line, in roughly this order:

```jsonc
{"type":"static", "stats":{"chars":1562,"lines":48,"minified":false,"sha256":"…"}, "domains":[{"domain":"api.x.io","count":2}],
 "findings":[{"id":"eval","severity":"high","category":"Code execution","title":"eval() call","count":1,
              "samples":[{"line":24,"offset":812,"code":"…snippet…"}]}],
 "localScore":78,           // 0-100 heuristic from static-scan
 "truncated":false}
{"type":"meta", "risk":"critical|high|medium|low|info", "score":0-100, "verdict":"one sentence", "vendor":"SupportBubble chat widget (unverified)" | null, "category":"skimmer|analytics|ads|chat|payments|library|tag-manager|unknown|…", "summary":"2-3 sentences"}
{"type":"behavior", "text":"Reads email/phone inputs on change"}          // 0..n
{"type":"flow", "data":"email, cookies, URL", "destination":"api.supportbubble.io/v2/identify", "method":"sendBeacon", "sensitivity":"critical|high|medium|low"}   // 0..n
{"type":"finding", "id":"f1", "severity":"critical|high|medium|low|info", "title":"…", "category":"…", "evidence":"code excerpt", "line":24|null, "impact":"…", "recommendation":"…", "cwe":"CWE-95"|null, "confidence":"high|medium|low"}   // 0..n, most severe first
{"type":"compliance", "pci":"PCI DSS 6.4.3 / 11.6.1 assessment", "privacy":"GDPR/CCPA assessment", "paymentPageSafe":false}
{"type":"recommendation", "priority":1, "action":"remove|sandbox|restrict|monitor|fix|keep", "text":"…"}   // 0..n
{"type":"csp", "policy":"script-src 'self' …; connect-src …", "notes":"…"}
{"type":"indicator", "kind":"domain|url|key|tracking-id|selector|other", "value":"…", "note":"…"}   // 0..n
{"type":"done", "ms":2050, "firstTokenMs":1428, "usage":{"prompt_tokens":1500,"completion_tokens":900}, "tokensPerSec":1850, "model":"gpt-oss-120b", "cached":false}
{"type":"error", "message":"human-readable", "code":"rate_limit|upstream|bad_request|…"}
```
Unknown types must be ignored by the frontend. Any field may be missing — render defensively.

### `GET /api/samples` → `[{ "id":"skimmer", "name":"Magecart skimmer", "description":"…", "expectedRisk":"critical", "source":"https://…/checkout.js" }]`
### `GET /api/samples/:id` → `{ "id", "name", "source", "script" }`
### `POST /api/fetch` `{ "url": "https://…/x.js" }` → `{ "script", "source", "bytes" }` or `{ "error" }` (server-side fetch; http/https only, SSRF-guarded: block private/loopback/link-local IPs after DNS resolution, 5 s timeout, 5 MB max)
### `GET /api/health` → `{ "ok": true, "model": "gpt-oss-120b" }`

## Frontend URL params (for presentation)
- `?sample=<id>` loads that sample and runs analysis automatically
- `&mock=<fixture>` forces fixture replay (no API call) — safety net if the network or quota fails on stage
