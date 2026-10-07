// Orchestration: landing input (paste / drop / URL / samples), URL params, the
// analyze stream (real backend or in-page dev mock), tabs, and export.

import { $, el, clear, show, hide, copyText } from './dom.js';
import { createDashboard } from './render.js';
import { playDevMock, DEVMOCK_SCRIPT } from './devmock.js';
import { toMarkdown, toJSON, download } from './export.js';

const params = new URLSearchParams(location.search);
const FORCE_DEVMOCK = params.get('devmock') === '1';

let controller = null;
let dash = null;
let current = { script: '', source: '', sampleId: null };
let backendUp = false;

const LOCAL_SAMPLES = [
  { id: 'chat-widget', name: 'SupportBubble chat widget', description: 'Third-party chat widget that harvests PII and eval()s postMessage code', expectedRisk: 'critical', source: 'https://cdn.supportbubble.io/widget.js' },
];

// ---------------- Analyze stream ----------------
async function streamAnalyze(script, source, mock, signal, emit) {
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ script, source, mock }),
    signal,
  });
  if (res.status === 429) {
    emit({ type: 'error', code: 'rate_limit', message: 'Cerebras token-per-minute quota exceeded. Wait ~60s or replay the demo result.' });
    return;
  }
  if (!res.ok || !res.body) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).error || msg; } catch { /* ignore */ }
    emit({ type: 'error', code: 'upstream', message: msg });
    return;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) { buf += decoder.decode(); break; } // flush any trailing multibyte char
    buf += decoder.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const raw = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!raw) continue;
      let evt;
      try { evt = JSON.parse(raw); } catch { continue; }
      emit(evt);
    }
  }
  if (buf.trim()) { try { emit(JSON.parse(buf.trim())); } catch { /* ignore */ } }
}

async function run(script, source, opts = {}) {
  if (!script || !script.trim()) return;
  controller?.abort();
  controller = new AbortController();
  const signal = controller.signal;
  current = { script, source: source || '', sampleId: opts.sampleId || null };

  showResults();
  dash.setSource(script, source || '');
  dash.reset();
  const emit = (evt) => dash.handleEvent(evt);

  const useMock = FORCE_DEVMOCK || opts.forceDevmock || (!backendUp && !opts.mock && opts.allowDevFallback);

  try {
    if (useMock) {
      await playDevMock(emit, signal);
    } else {
      await streamAnalyze(script, source || '', opts.mock, signal, emit);
    }
  } catch (err) {
    if (signal.aborted) return;
    emit({ type: 'error', code: err.code || 'upstream', message: err.message || 'Network error' });
  }
}

function replayCurrent() {
  if (FORCE_DEVMOCK || !backendUp) return run(current.script, current.source, { forceDevmock: true, sampleId: current.sampleId });
  return run(current.script, current.source, { mock: current.sampleId, sampleId: current.sampleId });
}
function canReplay() { return FORCE_DEVMOCK || !backendUp || !!current.sampleId; }

// ---------------- View switching ----------------
function showResults() {
  hide($('landing'));
  show($('results'));
  document.body.classList.add('has-results');
}
function showLanding() {
  controller?.abort();
  show($('landing'));
  hide($('results'));
  document.body.classList.remove('has-results');
  $('pasteInput').focus();
}

// ---------------- Samples ----------------
async function loadSamples() {
  let samples = LOCAL_SAMPLES;
  try {
    const res = await fetch('/api/samples');
    if (res.ok) { const j = await res.json(); if (Array.isArray(j) && j.length) samples = j; }
  } catch { /* backend down — use local */ }
  const mount = clear($('samplesMount'));
  samples.forEach((s) => {
    const btn = el('button.sample', { dataset: { id: s.id }, onclick: () => loadSample(s) }, [
      el('span.sample-risk', { dataset: { risk: s.expectedRisk || 'unknown' }, text: (s.expectedRisk || '?').toUpperCase() }),
      el('span.sample-body', null, [
        el('span.sample-name', { text: s.name || s.id }),
        el('span.sample-desc', { text: s.description || '' }),
      ]),
    ]);
    mount.appendChild(btn);
  });
  return samples;
}

async function loadSample(s, sampleOpts = {}) {
  // In devmock mode (or no backend) always use the built-in script + mock player.
  if (FORCE_DEVMOCK || !backendUp) {
    $('pasteInput').value = DEVMOCK_SCRIPT;
    return run(DEVMOCK_SCRIPT, s.source || s.id, { sampleId: s.id, forceDevmock: true });
  }
  try {
    const res = await fetch('/api/samples/' + encodeURIComponent(s.id));
    if (res.ok) {
      const j = await res.json();
      $('pasteInput').value = j.script || '';
      // mock: replay a server fixture instead of a live model call (presentation-safe)
      return run(j.script || '', j.source || s.source || s.id, { sampleId: s.id, mock: sampleOpts.mock || undefined });
    }
  } catch { /* fall through */ }
  return run(DEVMOCK_SCRIPT, s.source || s.id, { sampleId: s.id, forceDevmock: true });
}

// ---------------- URL fetch ----------------
async function fetchFromUrl() {
  const url = $('urlInput').value.trim();
  if (!url) return;
  const status = $('fetchStatus');
  status.textContent = 'Fetching…';
  status.className = 'fetch-status busy';
  try {
    const res = await fetch('/api/fetch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
    });
    const j = await res.json();
    if (!res.ok || j.error) throw new Error(j.error || `HTTP ${res.status}`);
    $('pasteInput').value = j.script || '';
    status.textContent = `Loaded ${(j.bytes || (j.script || '').length).toLocaleString()} bytes`;
    status.className = 'fetch-status ok';
    run(j.script || '', j.source || url, {});
  } catch (err) {
    status.textContent = backendUp ? ('Fetch failed: ' + err.message) : 'Fetch needs the backend (offline).';
    status.className = 'fetch-status err';
  }
}

// ---------------- Export ----------------
function doCopyMd(e) { copyText(toMarkdown(dash.getState()), e.currentTarget); }
function doDownloadJson() {
  const st = dash.getState();
  const name = 'script-analysis-' + (st.meta?.category || 'report') + '.json';
  download(name, toJSON(st));
}

// ---------------- Input wiring ----------------
function wireInputs() {
  const paste = $('pasteInput');
  let pasteT = null;
  paste.addEventListener('paste', () => { clearTimeout(pasteT); pasteT = setTimeout(() => run(paste.value, 'pasted script', { allowDevFallback: true }), 30); });

  $('analyzeBtn').addEventListener('click', () => run(paste.value, current.source || 'pasted script', { allowDevFallback: true }));
  $('urlInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') fetchFromUrl(); });
  $('fetchBtn').addEventListener('click', fetchFromUrl);
  $('newScanBtn').addEventListener('click', showLanding);
  $('rerunBtn').addEventListener('click', () => run(current.script, current.source, { sampleId: current.sampleId, allowDevFallback: true }));
  $('replayBtn').addEventListener('click', replayCurrent);

  $('btnCopyMd').addEventListener('click', doCopyMd);
  $('btnDownloadJson').addEventListener('click', doDownloadJson);
  $('btnPrint').addEventListener('click', () => window.print());

  // Source viewer controls
  $('btnPretty').addEventListener('click', (e) => {
    const on = !dash.source.isPretty();
    dash.source.setPretty(on);
    e.currentTarget.classList.toggle('active', on);
    e.currentTarget.textContent = on ? 'Pretty: on' : 'Pretty: off';
  });
  $('btnWrap').addEventListener('click', (e) => {
    const on = $('sourceMount').classList.toggle('wrap');
    e.currentTarget.classList.toggle('active', on);
    e.currentTarget.textContent = on ? 'Wrap: on' : 'Wrap: off';
  });

  // Tabs
  document.querySelectorAll('.tab-btn').forEach((b) => b.addEventListener('click', () => dash.switchTab(b.dataset.tab)));

  // Drag & drop a .js file onto the drop zone
  const dz = $('dropzone');
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); if (ev !== 'dragover') dz.classList.remove('drag'); }));
  dz.addEventListener('drop', async (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    const text = await file.text();
    paste.value = text;
    run(text, file.name, { allowDevFallback: true });
  });

  // ⌘/Ctrl+Enter re-runs
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      const script = document.body.classList.contains('has-results') ? current.script : paste.value;
      run(script, current.source || 'pasted script', { sampleId: current.sampleId, allowDevFallback: true });
    }
  });
}

// ---------------- Boot ----------------
async function boot() {
  dash = createDashboard({ onReplay: replayCurrent, canReplay });

  // health probe (never blocks)
  try {
    const res = await fetch('/api/health', { signal: AbortSignal.timeout(1500) });
    backendUp = res.ok;
  } catch { backendUp = false; }

  wireInputs();
  const samples = await loadSamples();

  if (FORCE_DEVMOCK) $('devmockBadge').classList.remove('hidden');

  // URL params: ?sample=<id>&mock=<fixture> , ?devmock=1
  const sampleId = params.get('sample');
  const mock = params.get('mock');
  if (sampleId) {
    const s = samples.find((x) => x.id === sampleId) || { id: sampleId, source: sampleId };
    loadSample(s, { mock });
  } else if (FORCE_DEVMOCK) {
    // demo the full dashboard immediately
    $('pasteInput').value = DEVMOCK_SCRIPT;
    run(DEVMOCK_SCRIPT, 'https://cdn.supportbubble.io/widget.js', { sampleId: 'chat-widget', forceDevmock: true });
  } else {
    $('pasteInput').focus();
  }
}

boot();
