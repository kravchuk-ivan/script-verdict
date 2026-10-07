// Fast regex-based pre-scan. Results are shown instantly and passed to the LLM as hints.

const RULES = [
  // Code execution
  { id: 'eval', sev: 'high', cat: 'Code execution', title: 'eval() call', re: /\beval\s*\(/g },
  { id: 'new-function', sev: 'high', cat: 'Code execution', title: 'new Function() constructor', re: /\bnew\s+Function\s*\(/g },
  { id: 'string-timer', sev: 'medium', cat: 'Code execution', title: 'setTimeout/setInterval with string argument', re: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/g },
  { id: 'script-inject', sev: 'medium', cat: 'Code execution', title: 'Dynamic <script> injection', re: /createElement\s*\(\s*["'`]script["'`]\s*\)/g },
  { id: 'iframe-inject', sev: 'low', cat: 'Code execution', title: 'Dynamic <iframe> creation', re: /createElement\s*\(\s*["'`]iframe["'`]\s*\)/g },

  // DOM XSS sinks
  { id: 'inner-html', sev: 'medium', cat: 'DOM XSS sink', title: 'innerHTML/outerHTML assignment', re: /\.(?:inner|outer)HTML\s*\+?=/g },
  { id: 'insert-adjacent', sev: 'medium', cat: 'DOM XSS sink', title: 'insertAdjacentHTML', re: /\.insertAdjacentHTML\s*\(/g },
  { id: 'document-write', sev: 'medium', cat: 'DOM XSS sink', title: 'document.write', re: /document\.write(?:ln)?\s*\(/g },
  { id: 'js-url', sev: 'medium', cat: 'DOM XSS sink', title: 'javascript: URL', re: /["'`]javascript:/gi },

  // Data access
  { id: 'cookie', sev: 'medium', cat: 'Data access', title: 'document.cookie access', re: /document\.cookie/g },
  { id: 'storage', sev: 'low', cat: 'Data access', title: 'localStorage/sessionStorage access', re: /\b(?:local|session)Storage\b/g },
  { id: 'indexeddb', sev: 'low', cat: 'Data access', title: 'IndexedDB access', re: /\bindexedDB\b/g },
  { id: 'password-field', sev: 'high', cat: 'Sensitive form data', title: 'Password field targeting', re: /type\s*=\s*\\?["']?password|\[type=\\?["']?password/gi },
  { id: 'card-field', sev: 'critical', cat: 'Sensitive form data', title: 'Payment card field targeting', re: /\b(?:cc-?(?:number|num|exp|csc)|card-?number|cardnum|cvv2?|cvc|security-?code|expiry|exp-?date)\b/gi },
  { id: 'input-value', sev: 'medium', cat: 'Sensitive form data', title: 'Reads form input values', re: /querySelectorAll?\s*\(\s*["'`][^"'`]*\b(?:input|form|select|textarea)\b/g },
  { id: 'key-listener', sev: 'high', cat: 'Sensitive form data', title: 'Keystroke / input event listener', re: /addEventListener\s*\(\s*["'`](?:keydown|keyup|keypress|input|change|paste)["'`]/g },
  { id: 'submit-listener', sev: 'medium', cat: 'Sensitive form data', title: 'Form submit listener', re: /addEventListener\s*\(\s*["'`]submit["'`]|\.onsubmit\s*=/g },
  { id: 'clipboard', sev: 'medium', cat: 'Data access', title: 'Clipboard API', re: /navigator\.clipboard/g },
  { id: 'geolocation', sev: 'medium', cat: 'Data access', title: 'Geolocation API', re: /navigator\.geolocation/g },
  { id: 'media', sev: 'high', cat: 'Data access', title: 'Camera/microphone access', re: /getUserMedia|getDisplayMedia/g },

  // Network / exfiltration
  { id: 'beacon', sev: 'medium', cat: 'Network', title: 'navigator.sendBeacon', re: /navigator\.sendBeacon|\bsendBeacon\s*\(/g },
  { id: 'fetch', sev: 'info', cat: 'Network', title: 'fetch()', re: /\bfetch\s*\(/g },
  { id: 'xhr', sev: 'info', cat: 'Network', title: 'XMLHttpRequest', re: /\bXMLHttpRequest\b/g },
  { id: 'websocket', sev: 'medium', cat: 'Network', title: 'WebSocket', re: /\bnew\s+WebSocket\s*\(/g },
  { id: 'image-beacon', sev: 'medium', cat: 'Network', title: 'Image pixel beacon', re: /new\s+Image\s*\([^)]*\)\s*\.src\s*=|\(new Image\)\.src/g },
  { id: 'postmessage-star', sev: 'medium', cat: 'Network', title: 'postMessage with "*" target origin', re: /postMessage\s*\([^;]{0,200}?,\s*["'`]\*["'`]/g },
  { id: 'message-listener', sev: 'medium', cat: 'Network', title: 'message event listener (check origin validation)', re: /addEventListener\s*\(\s*["'`]message["'`]|\bonmessage\s*=/g },
  { id: 'http-url', sev: 'medium', cat: 'Network', title: 'Plain http:// URL (mixed content / MITM)', re: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|www\.w3\.org)[^"'`\s]+/g },

  // Navigation
  { id: 'redirect', sev: 'low', cat: 'Navigation', title: 'Location change / redirect', re: /(?:window\.|document\.)?location(?:\.href)?\s*=(?!=)|location\.(?:replace|assign)\s*\(/g },
  { id: 'window-open', sev: 'low', cat: 'Navigation', title: 'window.open', re: /window\.open\s*\(/g },

  // Fingerprinting
  { id: 'canvas-fp', sev: 'medium', cat: 'Fingerprinting', title: 'Canvas readback (toDataURL/getImageData)', re: /\.toDataURL\s*\(|\.getImageData\s*\(/g },
  { id: 'webgl-fp', sev: 'medium', cat: 'Fingerprinting', title: 'WebGL renderer probing', re: /WEBGL_debug_renderer_info|UNMASKED_(?:VENDOR|RENDERER)/g },
  { id: 'audio-fp', sev: 'medium', cat: 'Fingerprinting', title: 'AudioContext fingerprinting', re: /OfflineAudioContext|createOscillator/g },
  { id: 'nav-fp', sev: 'low', cat: 'Fingerprinting', title: 'Navigator property enumeration', re: /navigator\.(?:plugins|hardwareConcurrency|deviceMemory|languages|platform|webdriver)/g },

  // Obfuscation
  { id: 'atob', sev: 'low', cat: 'Obfuscation', title: 'Base64 decoding (atob)', re: /\batob\s*\(/g },
  { id: 'fromcharcode', sev: 'low', cat: 'Obfuscation', title: 'String.fromCharCode', re: /String\.fromCharCode/g },
  { id: 'hex-escapes', sev: 'medium', cat: 'Obfuscation', title: 'Dense hex/unicode escape sequences', re: /(?:\\x[0-9a-f]{2}){8,}|(?:\\u[0-9a-f]{4}){6,}/gi },
  { id: 'obf-vars', sev: 'medium', cat: 'Obfuscation', title: 'Obfuscator-style identifiers (_0x...)', re: /\b_0x[0-9a-f]{4,}\b/g },
  { id: 'debugger', sev: 'low', cat: 'Obfuscation', title: 'debugger statement (anti-analysis)', re: /\bdebugger\b/g },

  // Secrets
  { id: 'aws-key', sev: 'critical', cat: 'Hardcoded secret', title: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'google-key', sev: 'medium', cat: 'Hardcoded secret', title: 'Google API key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { id: 'stripe-secret', sev: 'critical', cat: 'Hardcoded secret', title: 'Stripe secret key', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g },
  { id: 'jwt', sev: 'high', cat: 'Hardcoded secret', title: 'JWT token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { id: 'private-key', sev: 'critical', cat: 'Hardcoded secret', title: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { id: 'generic-secret', sev: 'medium', cat: 'Hardcoded secret', title: 'Possible hardcoded credential', re: /\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'`][^"'`\s]{8,}["'`]/gi },
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

// Decode atob("...") literals so hidden endpoints show up as domains and hits.
function decodeBase64Literals(src) {
  const decoded = [];
  for (const m of src.matchAll(/\batob\s*\(\s*["'`]([A-Za-z0-9+\/=]{8,})["'`]\s*\)/g)) {
    const text = Buffer.from(m[1], 'base64').toString('utf8');
    if (/^[\x20-\x7e\s]+$/.test(text)) decoded.push({ encoded: m[1], text });
  }
  return decoded;
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
      samples: matches.slice(0, MAX_SAMPLES).map((m) => ({
        line: lineOf(src, m.index),
        offset: m.index,
        code: snippet(src, m.index, m[0].length),
      })),
    });
  }
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.count - a.count);

  const decoded = decodeBase64Literals(src);
  if (decoded.length) {
    findings.unshift({
      id: 'hidden-string',
      severity: decoded.some((d) => /https?:|\/\//.test(d.text)) ? 'high' : 'medium',
      category: 'Obfuscation',
      title: 'Base64-hidden string literal',
      count: decoded.length,
      samples: decoded.slice(0, MAX_SAMPLES).map((d) => ({ line: lineOf(src, src.indexOf(d.encoded)), offset: src.indexOf(d.encoded), code: `atob("${d.encoded.slice(0, 60)}") → ${d.text.slice(0, 200)}` })),
    });
    findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.count - a.count);
  }

  const lines = src.split('\n');
  const avgLine = src.length / lines.length;
  return {
    stats: {
      chars: src.length,
      lines: lines.length,
      minified: avgLine > 500,
    },
    domains: extractDomains(src + '\n' + decoded.map((d) => d.text).join('\n')),
    findings,
  };
}
