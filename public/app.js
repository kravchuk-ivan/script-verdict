const $ = (id) => document.getElementById(id);
const scriptEl = $('script'), sourceEl = $('source'), reportEl = $('report'), staticEl = $('static');
const statusEl = $('status'), analyzeBtn = $('analyze');

let controller = null;

// ---------- Minimal, escape-first Markdown renderer ----------
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function inline(text) {
  const codes = [];
  let s = text.replace(/`([^`]+)`/g, (_, c) => `\u0000${codes.push(c) - 1}\u0000`);
  s = esc(s)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\s][^*]*?)\*(?!\*)/g, '$1<em>$2</em>')
    .replace(/&lt;br\s*\/?&gt;/g, '<br>');
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${esc(codes[i])}</code>`);
}

function sevClass(text) {
  const m = /\b(critical|high|medium|low|info(?:rmational)?)\b/i.exec(text);
  return m ? ` class="sev-${m[1].toLowerCase().startsWith('info') ? 'info' : m[1].toLowerCase()}"` : '';
}

const splitRow = (line) => line.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());

function renderMarkdown(md) {
  const lines = md.split('\n').map((l) => l.replace(/^\s*\*\*(#{1,4}\s+.*?)\*\*\s*$/, '$1'));
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push(`<pre><code>${esc(buf.join('\n'))}</code></pre>`);
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) {
      const level = h[1].length <= 2 ? 2 : 3;
      out.push(`<h${level}${level === 3 ? sevClass(h[2].slice(0, 20)) : ''}>${inline(h[2])}</h${level}>`);
      i++;
      continue;
    }
    if (/^\s*\|/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(splitRow(lines[i++]));
      out.push(`<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${rows
        .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`)
        .join('')}</tbody></table>`);
      continue;
    }
    const list = /^\s*([-*]|\d+\.)\s+/.exec(line);
    if (list) {
      const ordered = /\d/.test(list[1]);
      const items = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        items.push(inline(lines[i].replace(/^\s*([-*]|\d+\.)\s+/, '')));
        i++;
      }
      const tag = ordered ? 'ol' : 'ul';
      out.push(`<${tag}>${items.map((it) => `<li>${it}</li>`).join('')}</${tag}>`);
      continue;
    }
    if (!line.trim()) { i++; continue; }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^(```|#{1,4}\s|\s*\||\s*([-*]|\d+\.)\s)/.test(lines[i])) para.push(lines[i++]);
    if (para.length) out.push(`<p>${inline(para.join(' '))}</p>`);
    else i++;
  }
  return out.join('\n');
}

// ---------- Static pre-scan panel ----------
function renderStatic(r) {
  const chips = r.findings.length
    ? r.findings.map((f) => `<span class="chip sev-${f.severity}" title="${esc(f.category + '\n\n' + f.samples.map((s) => `line ${s.line}: ${s.code}`).join('\n\n'))}">${esc(f.title)}<b>${f.count}</b></span>`).join('')
    : '<span class="meta">No pattern hits.</span>';
  const domains = r.domains.length ? `<div class="domains">Domains: ${r.domains.map((d) => esc(d.domain)).join(' · ')}</div>` : '';
  staticEl.innerHTML = `
    <h2>Instant pre-scan</h2>
    <div class="meta">${r.stats.chars.toLocaleString()} chars · ${r.stats.lines.toLocaleString()} lines${r.stats.minified ? ' · minified' : ''}${r.truncated ? ' · truncated for model' : ''}</div>
    <div class="chips">${chips}</div>${domains}`;
  staticEl.classList.remove('hidden');
}

// ---------- Analysis ----------
function setStatus(text, busy) {
  statusEl.textContent = text;
  statusEl.classList.toggle('busy', !!busy);
}

async function analyze() {
  const script = scriptEl.value;
  if (!script.trim()) return;
  controller?.abort();
  controller = new AbortController();
  const signal = controller.signal;

  let md = '';
  let scheduled = false;
  const flush = () => { scheduled = false; reportEl.innerHTML = renderMarkdown(md); };
  const schedule = () => { if (!scheduled) { scheduled = true; requestAnimationFrame(flush); } };

  reportEl.innerHTML = '';
  staticEl.classList.add('hidden');
  setStatus('scanning…', true);
  analyzeBtn.disabled = true;

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ script, source: sourceEl.value.trim() }),
      signal,
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const evt = JSON.parse(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        if (evt.type === 'static') { renderStatic(evt); setStatus('analyzing…', true); }
        else if (evt.type === 'thinking') { if (!md) setStatus('reasoning…', true); }
        else if (evt.type === 'delta') { md += evt.text; setStatus('writing…', true); schedule(); }
        else if (evt.type === 'done') {
          const tok = evt.usage?.completion_tokens ? ` · ${evt.usage.completion_tokens} tokens` : '';
          setStatus(`${evt.model} · ${(evt.ms / 1000).toFixed(1)}s${tok}`);
        } else if (evt.type === 'error') throw new Error(evt.message);
      }
    }
    flush();
  } catch (err) {
    if (signal.aborted) return;
    flush();
    reportEl.insertAdjacentHTML('beforeend', `<p class="error">${esc(err.message)}</p>`);
    setStatus('error');
  } finally {
    if (!signal.aborted) analyzeBtn.disabled = false;
  }
}

analyzeBtn.addEventListener('click', analyze);
$('clear').addEventListener('click', () => {
  controller?.abort();
  scriptEl.value = '';
  sourceEl.value = '';
  reportEl.innerHTML = '<p class="empty">Results appear here.</p>';
  staticEl.classList.add('hidden');
  analyzeBtn.disabled = false;
  setStatus('');
  scriptEl.focus();
});
scriptEl.addEventListener('paste', () => {
  if ($('autorun').checked) setTimeout(analyze, 0);
});
document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') analyze();
});
scriptEl.focus();
