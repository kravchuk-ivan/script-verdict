# Script Verdict

Instant AI security verdicts for third-party JavaScript, powered by `gpt-oss-120b` on Cerebras.

Paste a script copied from the browser Network tab (or fetch it by URL) and get a full security analysis in about 2 seconds:

1. **Local pre-scan** (regex, ~10-25 ms): skimming/keylogging, sensitive-field access, exfiltration channels, DOM XSS sinks, eval/obfuscation, fingerprinting, hardcoded secrets, plus domain extraction (including base64-hidden URLs).
2. **LLM analysis** (streamed as structured events, rendered as a live dashboard): risk gauge and score, verdict, behaviors, data-flow diagram, evidence-backed findings with CWE and confidence, PCI DSS 6.4.3 / 11.6.1 and privacy assessment, recommended CSP, indicators of compromise, and first-token / tokens-per-second timing.

## Run

```sh
cp .env.example .env   # set CEREBRAS_API_KEY
npm start              # http://localhost:4000
```

Requires Node 21.7+. No dependencies, no build step.

## Deploy to Vercel

Import the repo with the **Other** framework preset. `vercel.json` serves `public/` as static files and routes `/api/*` to `api/index.js`, which re-exports the handler from `server.js`.

Set `CEREBRAS_API_KEY` in Project Settings → Environment Variables, then redeploy. Without it, the pre-scan and fixture replays still work, and live analysis returns an error.

The deployed app is public and uses your Cerebras key. Enable Vercel Deployment Protection if it should not be open to everyone.

## Config (.env)

| Var | Default | |
|---|---|---|
| `CEREBRAS_API_KEY` | — | required |
| `CEREBRAS_BASE_URL` | `https://api.cerebras.ai/v1` | any OpenAI-compatible endpoint |
| `MODEL` | `gpt-oss-120b` | |
| `REASONING_EFFORT` | `low` | `low` / `medium` / `high` — higher is slower but more thorough |
| `TEMPERATURE` | `0.1` | |
| `MAX_SCRIPT_CHARS` | `40000` | larger scripts are sent as head + tail; the pre-scan always covers the full file |
| `PORT` | `4000` | |

## Files

- `server.js` — request handler and local HTTP server; API (`/api/analyze`, `/api/samples`, `/api/fetch`, `/api/health`)
- `api/index.js`, `vercel.json` — Vercel entrypoint and config
- `lib/` — model client, prompt, static pre-scan rules, result cache, SSRF guard for URL fetch
- `public/` — dashboard UI
- `samples/` — demo scripts (Magecart skimmer, chat widget, analytics, obfuscated loader, benign widget)
- `fixtures/` — recorded model output for each sample, replayed on rate limit or with `&mock=<id>`
- `CONTRACT.md` — API and event-stream format
- `DEMO.md` — demo walkthrough

## Notes

- Binds to `127.0.0.1` only. The API key stays server-side.
- URL fetch is server-side and SSRF-guarded (private/loopback/link-local IPs blocked after DNS resolution, 5 s timeout, 5 MB max).
- Model output is rendered under a strict CSP, so script content echoed back by the model cannot execute in the page.
- The prompt tells the model to treat the script as untrusted data (prompt-injection resistance), but LLM output should still be reviewed before acting on it.
