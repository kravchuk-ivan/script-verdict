// Fast, local, dependency-free regex pre-scan for browser JavaScript.
// Runs in ~1ms, returns { stats, domains, findings, localScore } used by the
// contract's `static` event. Pure ES module, no npm deps.
//
// Design notes:
// - Every rule regex is bounded (no nested quantifiers over user input) to stay
//   safe against catastrophic backtracking on large minified files.
// - Each finding: { id, severity, category, title, count, samples[], confidence }.
// - localScore (0-100) is a weighted heuristic; skimmer+exfil combos score highest.

// severity: critical | high | medium | low | info
// conf: high | medium | low   (defaults to 'high' when omitted)
const RULES = [
  // ---- Code execution ----
  { id: 'eval', sev: 'high', cat: 'Code execution', title: 'eval() call', re: /\beval\s*\(/g },
  { id: 'new-function', sev: 'high', cat: 'Code execution', title: 'new Function() constructor', re: /\bnew\s+Function\s*\(/g },
  { id: 'string-timer', sev: 'medium', cat: 'Code execution', title: 'setTimeout/setInterval with string argument', re: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/g },
  { id: 'script-inject', sev: 'medium', cat: 'Code execution', title: 'Dynamic <script> injection', conf: 'medium', re: /createElement\s*\(\s*["'`]script["'`]\s*\)/g },
  { id: 'iframe-inject', sev: 'low', cat: 'Code execution', title: 'Dynamic <iframe> creation', conf: 'medium', re: /createElement\s*\(\s*["'`]iframe["'`]\s*\)/g },

  // ---- DOM XSS sinks ----
  { id: 'inner-html', sev: 'medium', cat: 'DOM XSS sink', title: 'innerHTML/outerHTML assignment', conf: 'medium', re: /\.(?:inner|outer)HTML\s*\+?=/g },
  { id: 'insert-adjacent', sev: 'medium', cat: 'DOM XSS sink', title: 'insertAdjacentHTML', conf: 'medium', re: /\.insertAdjacentHTML\s*\(/g },
  { id: 'document-write', sev: 'medium', cat: 'DOM XSS sink', title: 'document.write', re: /document\.write(?:ln)?\s*\(/g },
  { id: 'js-url', sev: 'medium', cat: 'DOM XSS sink', title: 'javascript: URL', conf: 'medium', re: /["'`]javascript:/gi },
  { id: 'srcdoc', sev: 'medium', cat: 'DOM XSS sink', title: 'iframe srcdoc assignment', re: /\.srcdoc\s*=/g },
  { id: 'document-domain', sev: 'medium', cat: 'DOM XSS sink', title: 'document.domain relaxation', re: /document\.domain\s*=/g },
  { id: 'dangerously-set-html', sev: 'medium', cat: 'DOM XSS sink', title: 'React dangerouslySetInnerHTML', re: /dangerouslySetInnerHTML/g },

  // ---- Data access ----
  { id: 'cookie', sev: 'medium', cat: 'Data access', title: 'document.cookie access', conf: 'medium', re: /document\.cookie/g },
  { id: 'storage', sev: 'low', cat: 'Data access', title: 'localStorage/sessionStorage access', conf: 'medium', re: /\b(?:local|session)Storage\b/g },
  { id: 'indexeddb', sev: 'low', cat: 'Data access', title: 'IndexedDB access', conf: 'medium', re: /\bindexedDB\b/g },
  { id: 'clipboard', sev: 'medium', cat: 'Data access', title: 'Clipboard API', re: /navigator\.clipboard/g },
  { id: 'geolocation', sev: 'medium', cat: 'Data access', title: 'Geolocation API', re: /navigator\.geolocation/g },
  { id: 'media', sev: 'high', cat: 'Data access', title: 'Camera/microphone access', re: /getUserMedia|getDisplayMedia/g },
  { id: 'battery', sev: 'low', cat: 'Data access', title: 'Battery Status API', re: /navigator\.getBattery\s*\(/g },

  // ---- Sensitive form data ----
  { id: 'password-field', sev: 'high', cat: 'Sensitive form data', title: 'Password field targeting', re: /type\s*=\s*\\?["']?password|\[type=\\?["']?password/gi },
  { id: 'card-field', sev: 'critical', cat: 'Sensitive form data', title: 'Payment card field targeting', re: /\b(?:cc-?(?:number|num|exp|csc)|card-?number|cardnum|cvv2?|cvc|security-?code|expiry|exp-?date)\b/gi },
  { id: 'autofill-cc', sev: 'high', cat: 'Sensitive form data', title: 'Autocomplete card/credential attribute targeting', re: /autocomplete\s*=\s*\\?["']?(?:cc-[a-z-]+|current-password|new-password)/gi },
  { id: 'input-value', sev: 'medium', cat: 'Sensitive form data', title: 'Reads form input values', conf: 'medium', re: /querySelector(?:All)?\s*\(\s*["'`][^"'`]*\b(?:input|form|select|textarea)\b/g },
  { id: 'key-listener', sev: 'high', cat: 'Sensitive form data', title: 'Keystroke / input event listener', conf: 'medium', re: /addEventListener\s*\(\s*["'`](?:keydown|keyup|keypress|input|change|paste)["'`]/g },
  { id: 'submit-listener', sev: 'medium', cat: 'Sensitive form data', title: 'Form submit listener', re: /addEventListener\s*\(\s*["'`]submit["'`]|\.onsubmit\s*=/g },
  { id: 'broad-form-capture', sev: 'high', cat: 'Sensitive form data', title: 'Document/window-level form capture (broad skimmer pattern)', re: /(?:document|window)\.addEventListener\s*\(\s*["'`](?:submit|change|input|keyup|keydown|paste)["'`]/g },

  // ---- Network / exfiltration ----
  { id: 'beacon', sev: 'medium', cat: 'Network', title: 'navigator.sendBeacon', re: /navigator\.sendBeacon|\bsendBeacon\s*\(/g },
  { id: 'fetch', sev: 'info', cat: 'Network', title: 'fetch()', conf: 'low', re: /\bfetch\s*\(/g },
  { id: 'xhr', sev: 'info', cat: 'Network', title: 'XMLHttpRequest', conf: 'low', re: /\bXMLHttpRequest\b/g },
  { id: 'websocket', sev: 'medium', cat: 'Network', title: 'WebSocket', re: /\bnew\s+WebSocket\s*\(/g },
  { id: 'image-beacon', sev: 'medium', cat: 'Network', title: 'Image pixel beacon', re: /new\s+Image\s*\([^)]{0,40}\)\s*\.src\s*=|\(new Image\)\.src|new\s+Image\s*\(\)\.src/g },
  { id: 'postmessage-star', sev: 'medium', cat: 'Network', title: 'postMessage with "*" target origin', re: /postMessage\s*\([^;]{0,200}?,\s*["'`]\*["'`]/g },
  { id: 'message-listener', sev: 'medium', cat: 'Network', title: 'message event listener (check origin validation)', conf: 'medium', re: /addEventListener\s*\(\s*["'`]message["'`]|\bonmessage\s*=/g },
  { id: 'http-url', sev: 'medium', cat: 'Network', title: 'Plain http:// URL (mixed content / MITM)', re: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|www\.w3\.org)[^"'`\s]+/g },

  // ---- Suspicious infrastructure ----
  { id: 'ip-literal-url', sev: 'high', cat: 'Suspicious infrastructure', title: 'URL points at a raw IP address', re: /\bhttps?:\/\/\d{1,3}(?:\.\d{1,3}){3}\b/g },
  { id: 'punycode', sev: 'medium', cat: 'Suspicious infrastructure', title: 'Punycode (xn--) domain (possible homograph)', re: /\bxn--[a-z0-9]+(?:-[a-z0-9]+)*\b/gi },
  { id: 'suspicious-tld', sev: 'medium', cat: 'Suspicious infrastructure', title: 'URL on a high-abuse TLD', conf: 'low', re: /\bhttps?:\/\/[a-z0-9.-]+\.(?:tk|top|gq|ml|cf|ga|cc|club|work|click|link|zip|mov|country|kim|loan|men|download|rest|xyz)\b/gi },

  // ---- Navigation ----
  { id: 'redirect', sev: 'low', cat: 'Navigation', title: 'Location change / redirect', conf: 'medium', re: /(?:\b(?:window|document|top|self|parent)\.location|^location|(?<![A-Za-z0-9_.])location)(?:\.href)?\s*=(?!=)|\blocation\.(?:replace|assign)\s*\(/gm },
  { id: 'window-open', sev: 'low', cat: 'Navigation', title: 'window.open', conf: 'medium', re: /window\.open\s*\(/g },

  // ---- Fingerprinting ----
  { id: 'canvas-fp', sev: 'medium', cat: 'Fingerprinting', title: 'Canvas readback (toDataURL/getImageData)', conf: 'medium', re: /\.toDataURL\s*\(|\.getImageData\s*\(/g },
  { id: 'webgl-fp', sev: 'medium', cat: 'Fingerprinting', title: 'WebGL renderer probing', re: /WEBGL_debug_renderer_info|UNMASKED_(?:VENDOR|RENDERER)/g },
  { id: 'audio-fp', sev: 'medium', cat: 'Fingerprinting', title: 'AudioContext fingerprinting', re: /OfflineAudioContext|createOscillator/g },
  { id: 'font-fp', sev: 'low', cat: 'Fingerprinting', title: 'Font enumeration / measurement', conf: 'low', re: /\.measureText\s*\(|\bfontFamily\b[\s\S]{0,40}?offsetWidth/g },
  { id: 'nav-fp', sev: 'low', cat: 'Fingerprinting', title: 'Navigator property enumeration', conf: 'medium', re: /navigator\.(?:plugins|hardwareConcurrency|deviceMemory|languages|platform|webdriver|maxTouchPoints|vendor)/g },

  // ---- Obfuscation ----
  { id: 'atob', sev: 'low', cat: 'Obfuscation', title: 'Base64 decoding (atob)', conf: 'medium', re: /\batob\s*\(/g },
  { id: 'fromcharcode', sev: 'low', cat: 'Obfuscation', title: 'String.fromCharCode', conf: 'medium', re: /String\.fromCharCode/g },
  { id: 'hex-escapes', sev: 'medium', cat: 'Obfuscation', title: 'Dense hex/unicode escape sequences', re: /(?:\\x[0-9a-f]{2}){8,}|(?:\\u[0-9a-f]{4}){6,}/gi },
  { id: 'obf-vars', sev: 'medium', cat: 'Obfuscation', title: 'Obfuscator-style identifiers (_0x...)', re: /\b_0x[0-9a-f]{4,}\b/g },
  { id: 'packer', sev: 'high', cat: 'Obfuscation', title: 'Dean Edwards packer signature', re: /eval\(function\(p,a,c,k,e,[dr]?\)/g },
  { id: 'string-array-rotate', sev: 'medium', cat: 'Obfuscation', title: 'String-array rotation (obfuscator.io)', re: /(?:\['push'\]|\.push)\s*\(\s*(?:\w+(?:\['shift'\]|\.shift)\s*\(\s*\))/g },
  { id: 'debugger', sev: 'low', cat: 'Obfuscation', title: 'debugger statement (anti-analysis)', conf: 'medium', re: /\bdebugger\b/g },

  // ---- Crypto-mining ----
  { id: 'crypto-mining', sev: 'high', cat: 'Crypto-mining', title: 'Crypto-mining signature', re: /\b(?:coinhive|coin-hive|cryptonight|coinimp|webminepool|deepminer|hashvault|jsecoin|minero\.cc|cryptoloot|crypto-loot)\b|stratum\+tcp:/gi },

  // ---- Prototype pollution ----
  { id: 'proto-pollution', sev: 'medium', cat: 'Prototype pollution', title: 'Prototype pollution pattern (__proto__ / constructor.prototype)', re: /\[\s*["'`]__proto__["'`]\s*\]|\.__proto__\s*=|constructor\s*\.\s*prototype\s*\[|constructor\s*\[\s*["'`]prototype["'`]\s*\]/g },

  // ---- Hardcoded secrets ----
  { id: 'aws-key', sev: 'critical', cat: 'Hardcoded secret', title: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'google-key', sev: 'medium', cat: 'Hardcoded secret', title: 'Google API key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { id: 'stripe-secret', sev: 'critical', cat: 'Hardcoded secret', title: 'Stripe secret key', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g },
  { id: 'jwt', sev: 'high', cat: 'Hardcoded secret', title: 'JWT token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { id: 'private-key', sev: 'critical', cat: 'Hardcoded secret', title: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { id: 'generic-secret', sev: 'medium', cat: 'Hardcoded secret', title: 'Possible hardcoded credential', conf: 'medium', re: /\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'`][^"'`\s]{8,}["'`]/gi },

  // ---- Known third-party vendors (informational, used to name the script) ----
  { id: 'vendor-ga', sev: 'info', cat: 'Third-party vendor', title: 'Google Analytics', conf: 'high', re: /google-analytics\.com|googletagmanager\.com\/gtag|\bgtag\s*\(|\bga\s*\(\s*["']|\bUA-\d{4,}-\d\b|\bG-[A-Z0-9]{8,}\b/g },
  { id: 'vendor-gtm', sev: 'info', cat: 'Third-party vendor', title: 'Google Tag Manager', conf: 'high', re: /googletagmanager\.com|\bGTM-[A-Z0-9]{4,}\b|dataLayer\.push/g },
  { id: 'vendor-fbpixel', sev: 'info', cat: 'Third-party vendor', title: 'Facebook Pixel', conf: 'high', re: /connect\.facebook\.net|\bfbq\s*\(/g },
  { id: 'vendor-hotjar', sev: 'info', cat: 'Third-party vendor', title: 'Hotjar', conf: 'high', re: /static\.hotjar\.com|\b_hjSettings\b|\bhj\s*\(/g },
  { id: 'vendor-segment', sev: 'info', cat: 'Third-party vendor', title: 'Segment', conf: 'high', re: /cdn\.segment\.com|analytics\.(?:track|identify|page|load)\s*\(/g },
];

// Data-flow (taint) heuristics: an untrusted source reaching a dangerous sink.
// Bounded lengths keep these linear-time on minified input.
const SOURCE = String.raw`location(?:\.(?:href|search|hash|pathname))?|document\.(?:referrer|URL)|URLSearchParams|(?:\b(?:e|ev|evt|event|msg|m)\.data\b)|window\.name|atob\s*\(`;
const TAINT_RULES = [
  {
    id: 'taint-eval', sev: 'critical', cat: 'Data flow', conf: 'medium',
    title: 'Untrusted source flows into eval()/new Function()',
    re: new RegExp(String.raw`(?:\beval\s*\(|\bnew\s+Function\s*\()\s*[^)]{0,180}?(?:${SOURCE})`, 'g'),
  },
  {
    id: 'taint-html', sev: 'high', cat: 'Data flow', conf: 'medium',
    title: 'Untrusted source flows into innerHTML/insertAdjacentHTML',
    re: new RegExp(String.raw`(?:\.(?:inner|outer)HTML\s*\+?=|insertAdjacentHTML\s*\([^,]{0,40},)\s*[^;\n]{0,180}?(?:${SOURCE})`, 'g'),
  },
  {
    id: 'taint-script-src', sev: 'high', cat: 'Data flow', conf: 'medium',
    title: 'Dynamic <script> src assigned from a variable / built URL',
    re: /createElement\s*\(\s*["'`]script["'`]\s*\)[\s\S]{0,220}?\.src\s*=\s*(?!["'`]https?:\/\/[a-z0-9.-]+\/[^"'`]*["'`]\s*;)[A-Za-z_$"'`]/gi,
  },
];

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const MAX_SAMPLES = 3;
const CONTEXT = 80;

function snippet(src, index, len) {
  const start = Math.max(0, index - CONTEXT);
  const end = Math.min(src.length, index + len + CONTEXT);
  return (start > 0 ? '…' : '') + src.slice(start, end).replace(/\s+/g, ' ') + (end < src.length ? '…' : '');
}

function lineOf(src, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (src.charCodeAt(i) === 10) line++;
  return line;
}

function extractDomains(src) {
  const counts = new Map();
  const re = /(?:https?:)?\/\/((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[\/:"'`?#\s)]|$)/gi;
  for (const m of src.matchAll(re)) {
    const d = m[1].toLowerCase();
    if (d === 'www.w3.org') continue;
    counts.set(d, (counts.get(d) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).map(([domain, count]) => ({ domain, count }));
}

const printable = (t) => /^[\x20-\x7e\s]+$/.test(t);
const looksInteresting = (t) => /https?:|\/\/|\.[a-z]{2,}\b/i.test(t);

// Decode obfuscated string literals so hidden endpoints surface as domains.
function decodeHidden(src) {
  const out = [];
  const seen = new Set();
  const add = (kind, encoded, text, index) => {
    if (!printable(text) || text.length < 4) return;
    const key = kind + ':' + index;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, encoded, text, index });
  };
  // atob("...") — use the platform's atob (global in Node 18+ and browsers) so
  // this module stays portable; Buffer would be undefined in a browser.
  const b64decode = typeof atob === 'function'
    ? (s) => atob(s)
    : (s) => Buffer.from(s, 'base64').toString('binary');
  for (const m of src.matchAll(/\batob\s*\(\s*["'`]([A-Za-z0-9+\/=]{8,})["'`]\s*\)/g)) {
    try { add('base64', m[1], b64decode(m[1]), m.index); } catch {}
  }
  // string literals made mostly of \xHH escapes
  for (const m of src.matchAll(/["'`]((?:\\x[0-9a-fA-F]{2}){4,})["'`]/g)) {
    try { add('hex', m[1], m[1].replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))), m.index); } catch {}
  }
  // String.fromCharCode(72,84,...)
  for (const m of src.matchAll(/String\.fromCharCode\s*\(\s*([0-9]{1,3}(?:\s*,\s*[0-9]{1,3}){3,})\s*\)/g)) {
    try {
      const text = m[1].split(',').map((n) => String.fromCharCode(parseInt(n.trim(), 10))).join('');
      add('charcode', m[1], text, m.index);
    } catch {}
  }
  return out;
}

// localScore: 0-100 heuristic. Severity/confidence weighted, saturating on count,
// plus domain-specific combo bonuses (skimmer + exfil scores highest).
const SEV_BASE = { critical: 42, high: 20, medium: 8, low: 3, info: 0 };
const CONF_MULT = { high: 1, medium: 0.6, low: 0.3 };
const COUNT_STEP = { critical: 4, high: 2, medium: 1, low: 0.3, info: 0 };

function computeScore(findings) {
  const ids = new Set(findings.map((f) => f.id));
  const cats = new Set(findings.map((f) => f.category));
  const has = (...xs) => xs.some((x) => ids.has(x));
  const hasCat = (c) => cats.has(c);

  let score = 0;
  for (const f of findings) {
    const base = SEV_BASE[f.severity] ?? 0;
    const mult = CONF_MULT[f.confidence] ?? 1;
    const countBonus = Math.min(f.count - 1, 5) * (COUNT_STEP[f.severity] ?? 0);
    score += base * mult + countBonus * mult;
  }

  const exfil = has('beacon', 'image-beacon', 'websocket', 'postmessage-star', 'xhr', 'fetch', 'http-url', 'ip-literal-url');
  const sensitive = has('card-field', 'autofill-cc', 'password-field');
  const capture = has('submit-listener', 'key-listener', 'broad-form-capture', 'input-value');

  // Classic Magecart skimmer: card/credential fields + form capture + exfil.
  if (sensitive && capture && exfil) score += 34;
  // Sensitive fields shipped off-origin at all.
  else if (has('card-field', 'autofill-cc') && exfil) score += 20;
  // Keystroke/paste capture combined with exfil.
  if (has('key-listener', 'broad-form-capture') && exfil) score += 12;

  // Taint: untrusted source into a code/HTML/script sink.
  if (has('taint-eval')) score += 24;
  if (has('taint-html')) score += 14;
  if (has('taint-script-src')) score += 12;

  // Obfuscation that hides an external endpoint.
  if (hasCat('Obfuscation') && exfil) score += 10;

  // Fingerprinting stack (2+ vectors) plus exfil = aggressive tracker.
  const fpCount = ['canvas-fp', 'webgl-fp', 'audio-fp', 'font-fp', 'nav-fp'].filter((x) => ids.has(x)).length;
  if (fpCount >= 2 && exfil) score += 12;
  if (fpCount >= 3) score += 6;

  if (has('crypto-mining')) score += 26;
  if (has('proto-pollution')) score += 8;
  if (hasCat('Hardcoded secret') && findings.some((f) => f.category === 'Hardcoded secret' && f.severity === 'critical')) score += 8;
  if (has('ip-literal-url')) score += 8;

  return Math.max(0, Math.min(100, Math.round(score)));
}

export function scan(src) {
  const findings = [];

  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    const matches = [...src.matchAll(rule.re)];
    if (!matches.length) continue;
    findings.push({
      id: rule.id,
      severity: rule.sev,
      category: rule.cat,
      title: rule.title,
      count: matches.length,
      confidence: rule.conf || 'high',
      samples: matches.slice(0, MAX_SAMPLES).map((m) => ({
        line: lineOf(src, m.index),
        offset: m.index,
        code: snippet(src, m.index, m[0].length),
      })),
    });
  }

  for (const rule of TAINT_RULES) {
    rule.re.lastIndex = 0;
    const matches = [...src.matchAll(rule.re)];
    if (!matches.length) continue;
    findings.push({
      id: rule.id,
      severity: rule.sev,
      category: rule.cat,
      title: rule.title,
      count: matches.length,
      confidence: rule.conf || 'medium',
      samples: matches.slice(0, MAX_SAMPLES).map((m) => ({
        line: lineOf(src, m.index),
        offset: m.index,
        code: snippet(src, m.index, m[0].length),
      })),
    });
  }

  const decoded = decodeHidden(src);
  if (decoded.length) {
    const hasUrl = decoded.some((d) => looksInteresting(d.text));
    findings.push({
      id: 'hidden-string',
      severity: hasUrl ? 'high' : 'medium',
      category: 'Obfuscation',
      title: 'Decoded hidden string literal (base64/hex/charcode)',
      count: decoded.length,
      confidence: 'high',
      samples: decoded.slice(0, MAX_SAMPLES).map((d) => ({
        line: lineOf(src, d.index),
        offset: d.index,
        code: `${d.kind}("${String(d.encoded).slice(0, 48)}…") → ${d.text.slice(0, 200)}`,
      })),
    });
  }

  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.count - a.count);

  const lines = src.split('\n');
  const avgLine = src.length / (lines.length || 1);

  return {
    stats: {
      chars: src.length,
      lines: lines.length,
      minified: avgLine > 500,
    },
    domains: extractDomains(src + '\n' + decoded.map((d) => d.text).join('\n')),
    findings,
    localScore: computeScore(findings),
  };
}
