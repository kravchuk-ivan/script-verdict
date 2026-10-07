// Cerebras streaming client + line-by-line JSONL parsing and normalization.
// The model is prompted to emit JSON Lines. We read the SSE stream, accumulate
// content deltas, and whenever a newline completes a line we try to parse and
// normalize one event, forwarding it immediately for progressive UI updates.

import { SYSTEM_PROMPT, buildUserMessage } from './prompt.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SENSITIVITIES = ['critical', 'high', 'medium', 'low'];
const RISKS = ['critical', 'high', 'medium', 'low', 'info'];
const EVENT_TYPES = new Set(['meta', 'behavior', 'flow', 'finding', 'compliance', 'recommendation', 'csp', 'indicator']);

function clampScore(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function oneOf(v, allowed, fallback) {
  if (typeof v !== 'string') return fallback;
  const s = v.trim().toLowerCase();
  if (allowed.includes(s)) return s;
  // common aliases
  if (s === 'informational' || s === 'information') return 'info';
  if (s === 'crit') return 'critical';
  return allowed.includes(fallback) ? fallback : allowed[allowed.length - 1];
}

function str(v) {
  if (v == null) return null;
  return String(v);
}

// Validate + normalize one parsed object. Returns a clean event or null to drop.
export function normalizeEvent(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const type = typeof obj.type === 'string' ? obj.type.trim().toLowerCase() : null;
  if (!type || !EVENT_TYPES.has(type)) return null;

  switch (type) {
    case 'meta':
      return {
        type: 'meta',
        risk: oneOf(obj.risk, RISKS, 'info'),
        score: clampScore(obj.score) ?? 0,
        verdict: str(obj.verdict) || '',
        vendor: obj.vendor == null ? null : str(obj.vendor),
        category: str(obj.category) || 'unknown',
        summary: str(obj.summary) || '',
      };
    case 'behavior': {
      const text = str(obj.text);
      if (!text) return null;
      return { type: 'behavior', text };
    }
    case 'flow':
      return {
        type: 'flow',
        data: str(obj.data) || '',
        destination: str(obj.destination) || '',
        method: str(obj.method) || 'unknown',
        sensitivity: oneOf(obj.sensitivity, SENSITIVITIES, 'medium'),
      };
    case 'finding': {
      const title = str(obj.title);
      if (!title) return null;
      let line = obj.line;
      line = Number.isFinite(Number(line)) ? Number(line) : null;
      return {
        type: 'finding',
        id: str(obj.id) || null,
        severity: oneOf(obj.severity, SEVERITIES, 'medium'),
        title,
        category: str(obj.category) || '',
        evidence: str(obj.evidence) || '',
        line,
        impact: str(obj.impact) || '',
        recommendation: str(obj.recommendation) || '',
        cwe: obj.cwe == null ? null : str(obj.cwe),
        confidence: oneOf(obj.confidence, ['high', 'medium', 'low'], 'medium'),
      };
    }
    case 'compliance':
      return {
        type: 'compliance',
        pci: str(obj.pci) || '',
        privacy: str(obj.privacy) || '',
        paymentPageSafe: typeof obj.paymentPageSafe === 'boolean' ? obj.paymentPageSafe : Boolean(obj.paymentPageSafe),
      };
    case 'recommendation': {
      const text = str(obj.text);
      if (!text) return null;
      const priority = Number.isFinite(Number(obj.priority)) ? Number(obj.priority) : null;
      return {
        type: 'recommendation',
        priority,
        action: oneOf(obj.action, ['remove', 'sandbox', 'restrict', 'monitor', 'fix', 'keep'], 'monitor'),
        text,
      };
    }
    case 'csp':
      return { type: 'csp', policy: str(obj.policy) || '', notes: str(obj.notes) || '' };
    case 'indicator': {
      const value = str(obj.value);
      if (!value) return null;
      return {
        type: 'indicator',
        kind: oneOf(obj.kind, ['domain', 'url', 'key', 'tracking-id', 'selector', 'other'], 'other'),
        value,
        note: obj.note == null ? '' : str(obj.note),
      };
    }
    default:
      return null;
  }
}

// Turn one raw text line from the model into a normalized event, or null.
// Tolerant: strips code fences, salvages leading/trailing junk around a JSON object.
export function parseLine(raw) {
  let line = raw.trim();
  if (!line) return null;
  // strip code-fence markers
  if (line.startsWith('```')) return null;
  if (line === '[DONE]') return null;
  let obj = null;
  try {
    obj = JSON.parse(line);
  } catch {
    // salvage: take substring from first { to last }
    const first = line.indexOf('{');
    const last = line.lastIndexOf('}');
    if (first !== -1 && last > first) {
      try {
        obj = JSON.parse(line.slice(first, last + 1));
      } catch {
        return null;
      }
    } else {
      return null;
    }
  }
  return normalizeEvent(obj);
}

// Calls Cerebras chat/completions with streaming and drives JSONL parsing.
// onEvent(normalizedEvent) is called for each valid event as its line completes.
// Returns { events, usage, firstTokenMs, ms, invalidLines }.
// Throws on HTTP errors; a 429 error carries { status:429, retryAfter, bodyText }.
export async function streamAnalysis({ script, source, scanResult, config, signal, onEvent, log }) {
  const { apiKey, baseUrl, model, reasoningEffort, temperature, maxScriptChars, responseFormat } = config;
  const started = Date.now();

  const body = {
    model,
    stream: true,
    temperature: temperature ?? 0.1,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: buildUserMessage(script, source, scanResult, maxScriptChars) },
    ],
    stream_options: { include_usage: true },
  };
  if (reasoningEffort) body.reasoning_effort = reasoningEffort;
  if (responseFormat) body.response_format = responseFormat;

  const upstream = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify(body),
    signal,
  });

  if (!upstream.ok) {
    const bodyText = await upstream.text().catch(() => '');
    const err = new Error(`Cerebras API ${upstream.status}: ${bodyText.slice(0, 400)}`);
    err.status = upstream.status;
    err.bodyText = bodyText;
    if (upstream.status === 429) {
      const ra = upstream.headers.get('retry-after');
      err.retryAfter = ra != null ? Number(ra) : null;
    }
    throw err;
  }

  const decoder = new TextDecoder();
  let sseBuffer = '';
  let jsonlBuffer = '';
  let firstTokenMs = null;
  let usage = null;
  const events = [];
  let invalidLines = 0;

  const handleJsonlLine = (rawLine) => {
    const evt = parseLine(rawLine);
    if (evt) {
      events.push(evt);
      onEvent(evt);
    } else if (rawLine.trim() && !rawLine.trim().startsWith('```')) {
      invalidLines++;
      log?.(`[jsonl] dropped invalid line: ${rawLine.trim().slice(0, 200)}`);
    }
  };

  const consumeContent = (text) => {
    firstTokenMs ??= Date.now() - started;
    jsonlBuffer += text;
    let nl;
    while ((nl = jsonlBuffer.indexOf('\n')) !== -1) {
      const rawLine = jsonlBuffer.slice(0, nl);
      jsonlBuffer = jsonlBuffer.slice(nl + 1);
      handleJsonlLine(rawLine);
    }
  };

  for await (const chunk of upstream.body) {
    sseBuffer += decoder.decode(chunk, { stream: true });
    let nl;
    while ((nl = sseBuffer.indexOf('\n')) !== -1) {
      const sseLine = sseBuffer.slice(0, nl).trim();
      sseBuffer = sseBuffer.slice(nl + 1);
      if (!sseLine.startsWith('data:')) continue;
      const data = sseLine.slice(5).trim();
      if (data === '[DONE]') continue;
      let evt;
      try { evt = JSON.parse(data); } catch { continue; }
      if (evt.error) {
        const err = new Error(evt.error.message || JSON.stringify(evt.error));
        err.status = evt.error.status || 'upstream';
        throw err;
      }
      if (evt.usage) usage = evt.usage;
      const delta = evt.choices?.[0]?.delta;
      if (delta?.content) consumeContent(delta.content);
    }
  }
  // flush any trailing partial line
  if (jsonlBuffer.trim()) handleJsonlLine(jsonlBuffer);

  return { events, usage, firstTokenMs, ms: Date.now() - started, invalidLines };
}
