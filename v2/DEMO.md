# Demo guide — Script Verdict v2

Open: http://localhost:4000   (v1 is still at http://localhost:3000, untouched)

## Fastest demo
1. On the landing page, click a sample card (e.g. **Magecart card skimmer**).
2. It runs a REAL gpt-oss-120b analysis on Cerebras — findings stream in live, ~2s.
3. Point out: risk gauge + score, severity counts, data-flow diagram, evidence-backed
   findings with CWE + confidence, PCI DSS verdict, recommended CSP, IOCs, speed strip
   (first-token + tokens/sec show Cerebras speed).

## Or paste your own
Paste any script from the Network tab into the box — analysis starts on paste.
"Fetch from URL" pulls a script server-side (SSRF-guarded) then analyzes it.

## Stage-safety net (if wifi/quota fails)
- Every sample has a recorded fixture. If a live call hits the Cerebras
  per-minute token limit (429), the server automatically replays the recorded
  result for that exact script — the demo still looks live.
- To force a no-API replay explicitly, add `&mock=<id>` to the URL, e.g.
  http://localhost:4000/?sample=magecart-skimmer&mock=magecart-skimmer
  Sample ids: magecart-skimmer, supportbubble-chat, sketchy-analytics,
  benign-widget, obfuscated-loader.
- `?devmock=1` runs a fully in-browser demo with no backend at all.

## Talking points
- Instant local pre-scan (regex, ~10-25ms) shown before the model, incl. base64-hidden domains.
- The model returns STRUCTURED events (not prose), rendered as a live dashboard.
- benign-widget rates LOW / "safe on payment pages: yes" — it doesn't cry wolf.
