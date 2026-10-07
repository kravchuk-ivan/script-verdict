# Script Verdict

Paste a JavaScript file copied from the browser Network tab and get a security analysis from `gpt-oss-120b` on Cerebras.

1. **Instant pre-scan** (local, ~1 ms): regex rules for skimming/keylogging, sensitive-field access, exfiltration channels, DOM XSS sinks, eval/obfuscation, fingerprinting, hardcoded secrets, plus domain extraction (including base64-hidden URLs).
2. **LLM analysis** (streamed, ~1-3 s): verdict and risk rating, behavior, data-flow table, evidence-backed findings, PCI DSS 6.4.3 / 11.6.1 and privacy impact, CSP/SRI recommendations, indicators.

## Run

```sh
cp .env.example .env   # set CEREBRAS_API_KEY
npm start              # http://localhost:3000
```

Requires Node 21.7+. No dependencies.

## Config (.env)

| Var | Default | |
|---|---|---|
| `CEREBRAS_API_KEY` | — | required |
| `CEREBRAS_BASE_URL` | `https://api.cerebras.ai/v1` | any OpenAI-compatible endpoint |
| `MODEL` | `gpt-oss-120b` | |
| `REASONING_EFFORT` | `low` | `low` / `medium` / `high` — higher is slower but more thorough |
| `MAX_SCRIPT_CHARS` | `40000` | larger scripts are sent as head + tail; the pre-scan always covers the full file |
| `PORT` | `3000` | |

## Files

- `server.js` — HTTP server, prompt, streaming proxy to the model (`POST /api/analyze`, NDJSON response)
- `static-scan.js` — pre-scan rules
- `public/` — UI

## Notes

- Binds to `127.0.0.1` only. The API key stays server-side.
- Model output is rendered through an escape-first Markdown renderer under a strict CSP, so script content echoed back by the model cannot execute in the page.
- The prompt tells the model to treat the script as untrusted data (prompt-injection resistance), but LLM output should still be reviewed before acting on it.
