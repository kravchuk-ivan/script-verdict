// Report export: Markdown (clipboard), JSON (download), and print (PDF via the
// browser's print dialog + a print stylesheet).

function line(...parts) { return parts.filter((p) => p != null && p !== '').join(''); }

export function toMarkdown(state) {
  const s = state;
  const out = [];
  const meta = s.meta || {};
  out.push('# Script Security Analysis');
  if (s.source) out.push(line('**Source:** ', s.source));
  out.push('');
  out.push(line('**Risk:** ', (meta.risk || 'unknown').toUpperCase(), '  ', typeof meta.score === 'number' ? `(score ${meta.score}/100)` : ''));
  if (meta.category) out.push(line('**Category:** ', meta.category));
  if (meta.vendor) out.push(line('**Vendor:** ', meta.vendor));
  if (meta.verdict) out.push('', '> ' + meta.verdict);
  if (meta.summary) out.push('', meta.summary);

  if (s.static) {
    out.push('', '## Pre-scan', '');
    const st = s.static.stats || {};
    out.push(line('- ', (st.chars || 0).toLocaleString(), ' chars · ', (st.lines || 0).toLocaleString(), ' lines', st.minified ? ' · minified' : ''));
    if (typeof s.static.localScore === 'number') out.push(line('- Static score: ', s.static.localScore, '/100'));
    (s.static.findings || []).forEach((f) => out.push(line('- [', f.severity, '] ', f.title, ' ×', f.count)));
  }

  const counts = s.counts || {};
  out.push('', '## Severity', '');
  out.push(line('Critical ', counts.critical || 0, ' · High ', counts.high || 0, ' · Medium ', counts.medium || 0, ' · Low ', counts.low || 0));

  if (s.findings.length) {
    out.push('', '## Findings', '');
    s.findings.forEach((f, i) => {
      out.push(`### ${i + 1}. [${(f.severity || '').toUpperCase()}] ${f.title || ''}`);
      const bits = [f.category, f.cwe, f.confidence ? f.confidence + ' confidence' : null].filter(Boolean);
      if (bits.length) out.push('*' + bits.join(' · ') + '*');
      if (f.line) out.push(line('Line ', f.line));
      if (f.evidence) out.push('', '```js', f.evidence, '```');
      if (f.impact) out.push('', '**Impact:** ' + f.impact);
      if (f.recommendation) out.push('**Fix:** ' + f.recommendation);
      out.push('');
    });
  }

  if (s.flows.length) {
    out.push('## Data flows', '');
    s.flows.forEach((f) => out.push(line('- [', f.sensitivity, '] ', f.data, ' → ', f.destination, ' (', f.method, ')')));
    out.push('');
  }
  if (s.behaviors.length) {
    out.push('## Behaviors', '');
    s.behaviors.forEach((b) => out.push('- ' + b));
    out.push('');
  }
  if (s.compliance) {
    out.push('## Compliance', '');
    out.push(line('- Safe on payment pages: ', s.compliance.paymentPageSafe ? 'Yes' : 'No'));
    if (s.compliance.pci) out.push('- PCI: ' + s.compliance.pci);
    if (s.compliance.privacy) out.push('- Privacy: ' + s.compliance.privacy);
    out.push('');
  }
  if (s.recommendations.length) {
    out.push('## Recommendations', '');
    s.recommendations.forEach((r) => out.push(line((r.priority || '•') + '. ', '[', r.action, '] ', r.text)));
    out.push('');
  }
  if (s.csp) {
    out.push('## Content-Security-Policy', '', '```', s.csp.policy || '', '```');
    if (s.csp.notes) out.push('', s.csp.notes);
    out.push('');
  }
  if (s.indicators.length) {
    out.push('## Indicators (IOCs)', '', '| Kind | Value | Note |', '| --- | --- | --- |');
    s.indicators.forEach((i) => out.push(line('| ', i.kind, ' | `', i.value, '` | ', i.note || '', ' |')));
    out.push('');
  }
  if (s.done) {
    const d = s.done;
    out.push('---', line('Analyzed by ', d.model || 'model', ' in ', d.ms ? (d.ms / 1000).toFixed(2) + 's' : '—',
      d.tokensPerSec ? ' · ' + d.tokensPerSec + ' tok/s' : '',
      d.firstTokenMs ? ' · first token ' + d.firstTokenMs + 'ms' : ''));
  }
  return out.join('\n');
}

export function toJSON(state) {
  return JSON.stringify({
    source: state.source,
    meta: state.meta,
    static: state.static,
    findings: state.findings,
    flows: state.flows,
    behaviors: state.behaviors,
    compliance: state.compliance,
    recommendations: state.recommendations,
    csp: state.csp,
    indicators: state.indicators,
    done: state.done,
  }, null, 2);
}

export function download(filename, text, type = 'application/json') {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
