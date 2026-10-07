import http from 'node:http';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scan } from './lib/static-scan.js';
import { PROMPT_VERSION } from './lib/prompt.js';
import { streamAnalysis } from './lib/model.js';
import { ResultCache, cacheKey, sha256 } from './lib/cache.js';
import { safeFetch } from './lib/fetch-guard.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
try { process.loadEnvFile(path.join(ROOT, '.env')); } catch {}

const CONFIG = {
  apiKey: process.env.CEREBRAS_API_KEY,
  baseUrl: (process.env.CEREBRAS_BASE_URL || 'https://api.cerebras.ai/v1').replace(/\/$/, ''),
  model: process.env.MODEL || 'gpt-oss-120b',
  reasoningEffort: process.env.REASONING_EFFORT || 'low',
  temperature: process.env.TEMPERATURE != null ? Number(process.env.TEMPERATURE) : 0.1,
  maxScriptChars: Number(process.env.MAX_SCRIPT_CHARS) || 40_000,
  responseFormat: null, // JSONL via prompt is preferred; keeps streaming progressive
};
const PORT = Number(process.env.PORT) || 4000;
const MAX_BODY_BYTES = 10 * 1024 * 1024;
const OVERALL_DEADLINE_MS = 90_000;

const PUBLIC_DIR = path.join(ROOT, 'public');
const SAMPLES_DIR = path.join(ROOT, 'samples');
const FIXTURES_DIR = path.join(ROOT, 'fixtures');
const CACHE_DIR = path.join(ROOT, '.cache');

const cache = new ResultCache(CACHE_DIR);

if (!CONFIG.apiKey) {
  console.error('CEREBRAS_API_KEY is not set. Put it in .env or the environment.');
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- security headers ----------
// Strict CSP: frontend uses no inline <script> and no inline style attributes,
// so 'self' is sufficient for both script-src and style-src.
const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
};

// ---------- helpers ----------
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Payload too large (max 10 MB)'), { status: 413 }));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...SECURITY_HEADERS,
    ...extraHeaders,
  });
  res.end(JSON.stringify(obj));
}

// Safely resolve `unsafe` inside `base`; returns null on traversal.
function safeJoin(base, unsafe) {
  const target = path.resolve(base, '.' + path.sep + String(unsafe));
  const root = path.resolve(base);
  if (target !== root && !target.startsWith(root + path.sep)) return null;
  return target;
}

// Build the static pre-scan event (with sha256 injected into stats per contract).
function staticEvent(script) {
  const result = scan(script);
  const stats = { ...result.stats, sha256: sha256(script) };
  return {
    event: {
      type: 'static',
      stats,
      domains: result.domains,
      findings: result.findings,
      localScore: result.localScore,
      truncated: script.length > CONFIG.maxScriptChars,
    },
    result,
  };
}

// ---------- sample sha256 -> id map (for 429 fixture fallback) ----------
let SAMPLE_HASHES = new Map();
async function loadSampleHashes() {
  const map = new Map();
  try {
    const list = await readSamplesIndex();
    for (const s of list) {
      if (!s.id) continue;
      const file = safeJoin(SAMPLES_DIR, s.file || `${s.id}.js`);
      if (!file) continue;
      try {
        const src = await fsp.readFile(file, 'utf8');
        map.set(sha256(src), s.id);
      } catch {}
    }
  } catch {}
  return map;
}

// ---------- replay ----------
async function replayLines(res, lines, { skipStatic = false, ensureDone = true } = {}) {
  let skipChecked = false;
  let sawDone = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (skipStatic && !skipChecked) {
      skipChecked = true;
      try { if (JSON.parse(trimmed).type === 'static') continue; } catch { /* not JSON, emit as-is */ }
    }
    try { if (JSON.parse(trimmed).type === 'done') sawDone = true; } catch { /* ignore */ }
    if (res.writableEnded || res.destroyed) return;
    res.write(trimmed + '\n');
    await sleep(30 + Math.random() * 30);
  }
  // Guarantee the stream terminates so the client UI never hangs on a fixture
  // that is missing its trailing done event.
  if (ensureDone && !sawDone && !res.writableEnded && !res.destroyed) {
    res.write(JSON.stringify({ type: 'done', ms: null, model: CONFIG.model, cached: true }) + '\n');
  }
}

async function replayCached(res, script, cached, extra = {}, { skipStatic = false } = {}) {
  if (!skipStatic) {
    const { event: staticEvt } = staticEvent(script);
    res.write(JSON.stringify(staticEvt) + '\n');
    await sleep(20);
  }
  for (const evt of cached.events) {
    if (res.writableEnded || res.destroyed) return;
    res.write(JSON.stringify(evt) + '\n');
    await sleep(30 + Math.random() * 30);
  }
  const done = {
    type: 'done',
    ms: cached.ms ?? null,
    firstTokenMs: cached.firstTokenMs ?? null,
    usage: cached.usage ?? null,
    tokensPerSec: cached.tokensPerSec ?? null,
    model: cached.model || CONFIG.model,
    cached: true,
    ...extra,
  };
  res.write(JSON.stringify(done) + '\n');
}

// ---------- POST /api/analyze ----------
async function handleAnalyze(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (err) {
    return sendJson(res, err.status || 400, { error: err.status ? err.message : 'Invalid JSON' });
  }
  const script = String(payload.script || '');
  const source = String(payload.source || '').slice(0, 2000);
  const mock = payload.mock ? String(payload.mock) : null;
  const nocache = payload.nocache === true;

  if (!mock && !script.trim()) return sendJson(res, 400, { error: 'Empty script' });

  res.writeHead(200, {
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'X-Content-Type-Options': 'nosniff',
    ...SECURITY_HEADERS,
  });
  const send = (obj) => { if (!res.writableEnded) res.write(JSON.stringify(obj) + '\n'); };
  const started = Date.now();

  // --- mock / fixture replay (no model call, stage-safety) ---
  if (mock) {
    const file = safeJoin(FIXTURES_DIR, `${mock}.ndjson`);
    if (!file || !fs.existsSync(file)) {
      send({ type: 'error', message: `Fixture not found: ${mock}`, code: 'bad_request' });
      return res.end();
    }
    const lines = (await fsp.readFile(file, 'utf8')).split('\n');
    await replayLines(res, lines);
    return res.end();
  }

  const key = cacheKey(script, CONFIG.model, PROMPT_VERSION, source);

  // --- cache replay ---
  if (!nocache) {
    const hit = cache.get(key);
    if (hit && Array.isArray(hit.events) && hit.events.length) {
      await replayCached(res, script, hit);
      return res.end();
    }
  }

  // --- static event, immediately, before the model call ---
  const { event: staticEvt, result } = staticEvent(script);
  send(staticEvt);

  const controller = new AbortController();
  res.on('close', () => controller.abort());

  // Hard deadline: if the upstream model stalls, abort and report a timeout rather
  // than holding the connection open indefinitely.
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; controller.abort(); }, OVERALL_DEADLINE_MS);

  const runModel = () => streamAnalysis({
    script,
    source,
    scanResult: result,
    config: CONFIG,
    signal: controller.signal,
    onEvent: (evt) => send(evt),
    log: (m) => console.error(m),
  });

  try {
    let out;
    try {
      out = await runModel();
    } catch (err) {
      if (err.status === 429) {
        const handled = await handle429(err, { res, send, script, source, controller, runModel, started });
        if (handled) return;
        // handle429 signalled a successful retry only by returning falsy with out set
      }
      if (!out) throw err;
    }

    if (controller.signal.aborted) {
      if (timedOut) send({ type: 'error', message: 'Analysis timed out.', code: 'timeout' });
      return;
    }
    if (!out || !out.events.length) {
      send({ type: 'error', message: 'Model returned no valid structured events.', code: 'upstream' });
      return;
    }

    const genMs = Math.max(1, (out.ms || 0) - (out.firstTokenMs || 0));
    const completion = out.usage?.completion_tokens || 0;
    const tokensPerSec = completion ? Math.round((completion / genMs) * 1000) : null;

    cache.set(key, {
      events: out.events,
      usage: out.usage || null,
      model: CONFIG.model,
      promptVersion: PROMPT_VERSION,
      tokensPerSec,
      firstTokenMs: out.firstTokenMs ?? null,
      ms: out.ms ?? null,
      createdAt: Date.now(),
    });

    send({
      type: 'done',
      ms: out.ms,
      firstTokenMs: out.firstTokenMs,
      usage: out.usage || null,
      tokensPerSec,
      model: CONFIG.model,
      cached: false,
    });
  } catch (err) {
    if (timedOut) {
      send({ type: 'error', message: 'Analysis timed out.', code: 'timeout' });
    } else if (!controller.signal.aborted) {
      const code = err.status === 429 ? 'rate_limit' : 'upstream';
      send({ type: 'error', message: (err.message || 'Analysis failed').slice(0, 300), code });
    }
  } finally {
    clearTimeout(deadline);
    if (!res.writableEnded) res.end();
  }
}

// Handle a 429. Returns true if it fully handled the response (caller ends).
// On a successful short retry it returns the model output by attaching to a shared
// object is avoided; instead we retry inline and, if it works, we throw/return via
// re-running. To keep flow simple: retry once here; on success we recurse into the
// normal finish by returning a special marker.
async function handle429(err, ctx) {
  const { res, send, script, source, controller, runModel, started } = ctx;
  const retryAfter = Number.isFinite(err.retryAfter) ? err.retryAfter : null;

  // short retry (retry-after <= 5s, and within overall deadline)
  if (retryAfter != null && retryAfter <= 5 && Date.now() + retryAfter * 1000 + 3000 < started + OVERALL_DEADLINE_MS) {
    send({ type: 'info', message: `Rate limited; retrying in ${retryAfter}s`, code: 'rate_limit' });
    await sleep(retryAfter * 1000);
    if (controller.signal.aborted) return true;
    try {
      const out = await runModel();
      // finish inline (mirror of the normal success path)
      if (out.events.length) {
        const genMs = Math.max(1, (out.ms || 0) - (out.firstTokenMs || 0));
        const completion = out.usage?.completion_tokens || 0;
        const tokensPerSec = completion ? Math.round((completion / genMs) * 1000) : null;
        cache.set(cacheKey(script, CONFIG.model, PROMPT_VERSION, source), {
          events: out.events, usage: out.usage || null, model: CONFIG.model,
          promptVersion: PROMPT_VERSION, tokensPerSec, firstTokenMs: out.firstTokenMs ?? null,
          ms: out.ms ?? null, createdAt: Date.now(),
        });
        send({ type: 'done', ms: out.ms, firstTokenMs: out.firstTokenMs, usage: out.usage || null, tokensPerSec, model: CONFIG.model, cached: false });
      } else {
        send({ type: 'error', message: 'Model returned no valid structured events.', code: 'upstream' });
      }
      return true;
    } catch (err2) {
      if (err2.status !== 429) {
        send({ type: 'error', message: (err2.message || 'Analysis failed').slice(0, 300), code: 'upstream' });
        return true;
      }
      // fall through to fixture/cache fallback
    }
  }

  // fallback: recorded fixture for this exact sample (match by sha256)
  const sampleId = SAMPLE_HASHES.get(sha256(script));
  if (sampleId) {
    const file = safeJoin(FIXTURES_DIR, `${sampleId}.ndjson`);
    if (file && fs.existsSync(file)) {
      send({ type: 'info', message: 'Rate limited; serving recorded fixture for this sample.', code: 'rate_limit' });
      const lines = (await fsp.readFile(file, 'utf8')).split('\n');
      await replayLines(res, lines, { skipStatic: true }); // static already sent before the model call
      return true;
    }
  }

  // fallback: any cached result for this script
  const hit = cache.get(cacheKey(script, CONFIG.model, PROMPT_VERSION, source));
  if (hit && Array.isArray(hit.events) && hit.events.length) {
    send({ type: 'info', message: 'Rate limited; serving cached result.', code: 'rate_limit' });
    await replayCached(res, script, hit, { fallback: true }, { skipStatic: true }); // static already sent
    return true;
  }

  send({ type: 'error', message: 'Rate limit exceeded and no cached result or fixture available. Wait ~60s and retry, or use mock mode.', code: 'rate_limit' });
  return true;
}

// ---------- samples ----------
async function readSamplesIndex() {
  const raw = await fsp.readFile(path.join(SAMPLES_DIR, 'index.json'), 'utf8');
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : parsed.samples || [];
}

async function handleSamplesList(res) {
  try {
    const list = await readSamplesIndex();
    sendJson(res, 200, list.map((s) => ({
      id: s.id,
      name: s.name || s.id,
      description: s.description || '',
      expectedRisk: s.expectedRisk || s.risk || 'unknown',
      source: s.source || '',
    })));
  } catch {
    sendJson(res, 200, []);
  }
}

async function handleSampleGet(res, id) {
  try {
    const list = await readSamplesIndex();
    const meta = list.find((s) => s.id === id);
    if (!meta) return sendJson(res, 404, { error: 'Sample not found' });
    const file = safeJoin(SAMPLES_DIR, meta.file || `${id}.js`);
    if (!file) return sendJson(res, 400, { error: 'Invalid sample id' });
    const script = await fsp.readFile(file, 'utf8');
    sendJson(res, 200, { id, name: meta.name || id, source: meta.source || '', script });
  } catch {
    sendJson(res, 404, { error: 'Sample not found' });
  }
}

// ---------- POST /api/fetch ----------
async function handleFetch(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (err) {
    return sendJson(res, err.status || 400, { error: err.status ? err.message : 'Invalid JSON' });
  }
  const url = String(payload.url || '').trim();
  if (!url) return sendJson(res, 400, { error: 'Missing url' });
  try {
    sendJson(res, 200, await safeFetch(url));
  } catch (err) {
    sendJson(res, 400, { error: err.message || 'Fetch failed' });
  }
}

// ---------- static files ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = safeJoin(PUBLIC_DIR, rel);
  if (!file) {
    res.writeHead(403, SECURITY_HEADERS);
    return res.end('Forbidden');
  }
  fs.stat(file, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, SECURITY_HEADERS);
      return res.end('Not found');
    }
    const type = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, ...SECURITY_HEADERS });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

// ---------- router ----------
const server = http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { res.writeHead(400); return res.end('Bad request'); }
  const { pathname } = url;
  try {
    if (req.method === 'POST' && pathname === '/api/analyze') return await handleAnalyze(req, res);
    if (req.method === 'POST' && pathname === '/api/fetch') return await handleFetch(req, res);
    if (req.method === 'GET' && pathname === '/api/health') return sendJson(res, 200, { ok: true, model: CONFIG.model });
    if (req.method === 'GET' && pathname === '/api/samples') return await handleSamplesList(res);
    if (req.method === 'GET' && pathname.startsWith('/api/samples/')) {
      const id = decodeURIComponent(pathname.slice('/api/samples/'.length));
      if (!id || id.includes('/')) return sendJson(res, 400, { error: 'Invalid sample id' });
      return await handleSampleGet(res, id);
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (pathname.startsWith('/api/')) return sendJson(res, 404, { error: 'Not found' });
      return serveStatic(req, res, pathname);
    }
    res.writeHead(405, SECURITY_HEADERS);
    res.end('Method not allowed');
  } catch (err) {
    console.error('[server] unhandled', err);
    if (!res.headersSent) sendJson(res, 500, { error: 'Internal error' });
    else if (!res.writableEnded) res.end();
  }
});

loadSampleHashes().then((m) => { SAMPLE_HASHES = m; console.log(`[samples] indexed ${m.size} sample hashes for 429 fallback`); });

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Script Verdict: http://127.0.0.1:${PORT}  (model: ${CONFIG.model}, prompt: ${PROMPT_VERSION})`);
});
