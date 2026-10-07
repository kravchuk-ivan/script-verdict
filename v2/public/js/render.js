// Dashboard controller. Owns every result section and fills them progressively as
// NDJSON events arrive. All script/model-derived text is inserted via el({text})
// or textContent — never string-interpolated into innerHTML.

import { $, el, clear, show, hide, copyText, fmtInt, fmtMs } from './dom.js';
import { createGauge } from './gauge.js';
import { createFlow } from './flow.js';
import { createSourceView } from './sourceview.js';
import { highlightInline } from './highlight.js';

const SEV = {
  critical: { rank: 0, label: 'Critical', varc: '--sev-critical' },
  high: { rank: 1, label: 'High', varc: '--sev-high' },
  medium: { rank: 2, label: 'Medium', varc: '--sev-medium' },
  low: { rank: 3, label: 'Low', varc: '--sev-low' },
  info: { rank: 4, label: 'Info', varc: '--sev-info' },
};
const sevOf = (s) => SEV[s] || SEV.info;
const cvar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export function createDashboard(opts = {}) {
  const state = freshState();
  const gauge = createGauge($('gaugeMount'));
  const flow = createFlow($('flowMount'));
  const source = createSourceView($('sourceMount'));
  let timerRaf = null;
  let startTs = 0;
  let liveFirstToken = null;

  function freshState() {
    return {
      source: '', script: '', static: null, meta: null, done: null, compliance: null, csp: null,
      findings: [], flows: [], behaviors: [], recommendations: [], indicators: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
  }

  // ---------- Speed strip ----------
  const tiles = {};
  function buildSpeedStrip() {
    const strip = clear($('speedStrip'));
    const defs = [
      ['timer', 'Elapsed', '0.00s'],
      ['prescan', 'Pre-scan', '—'],
      ['ttft', 'First token', '—'],
      ['total', 'Total time', '—'],
      ['tps', 'Tokens/sec', '—'],
      ['tokens', 'Tokens', '—'],
      ['model', 'Model', 'gpt-oss-120b'],
    ];
    for (const [key, label, val] of defs) {
      const valEl = el('div.sp-val', { text: val });
      const tile = el('div.sp-tile', null, [valEl, el('div.sp-label', { text: label })]);
      if (key === 'timer') tile.classList.add('sp-tile-accent');
      tiles[key] = valEl;
      strip.appendChild(tile);
    }
    const badge = el('div.sp-badge.hidden', { text: '' });
    tiles.badge = badge;
    strip.appendChild(badge);
  }

  buildSpeedStrip();

  function startTimer() {
    startTs = performance.now();
    cancelAnimationFrame(timerRaf);
    const tick = () => {
      const s = (performance.now() - startTs) / 1000;
      tiles.timer.textContent = s.toFixed(2) + 's';
      timerRaf = requestAnimationFrame(tick);
    };
    tick();
  }
  function stopTimer() { cancelAnimationFrame(timerRaf); }

  // ---------- Risk hero ----------
  function renderMeta(m) {
    state.meta = m;
    hide($('riskSkeleton'));
    show($('riskContent'));
    const sev = sevOf(m.risk);
    const color = cvar(sev.varc) || '#888';
    gauge.setScore(typeof m.score === 'number' ? m.score : 0, { color });
    const level = $('riskLevel');
    level.textContent = (sev.label || m.risk || 'Unknown').toUpperCase();
    level.style.color = color;
    level.style.borderColor = color;
    $('riskVerdict').textContent = m.verdict || '';
    const meta = clear($('riskMeta'));
    if (m.category) meta.appendChild(el('span.pill', { text: m.category }));
    if (m.vendor) meta.appendChild(el('span.pill.pill-muted', { text: m.vendor }));
    $('riskSummary').textContent = m.summary || '';
  }

  // ---------- Severity counters ----------
  function renderCounts() {
    const wrap = clear($('sevCounts'));
    for (const key of ['critical', 'high', 'medium', 'low']) {
      const n = state.counts[key];
      const tile = el('div.sev-count', { dataset: { sev: key } }, [
        el('div.sev-count-n', { text: String(n) }),
        el('div.sev-count-l', { text: SEV[key].label }),
      ]);
      if (!n) tile.classList.add('is-zero');
      wrap.appendChild(tile);
    }
  }

  // ---------- Findings ----------
  function severityBadge(sev) {
    const s = sevOf(sev);
    const b = el('span.sev-badge', { dataset: { sev: s === SEV.info ? 'info' : sev }, text: s.label });
    return b;
  }

  function findingCard(f, index) {
    const sev = sevOf(f.severity);
    const card = el('article.finding', { dataset: { sev: f.severity || 'info' } });
    card.style.setProperty('--edge', cvar(sev.varc) || '#888');

    const head = el('div.finding-head', null, [
      severityBadge(f.severity),
      el('h3.finding-title', { text: f.title || 'Finding' }),
    ]);
    const metaBits = el('div.finding-meta');
    if (f.category) metaBits.appendChild(el('span.tag', { text: f.category }));
    if (f.cwe) metaBits.appendChild(el('a.tag.tag-cwe', { text: f.cwe, title: 'Common Weakness Enumeration' }));
    if (f.confidence) metaBits.appendChild(el('span.tag.tag-conf', { text: f.confidence + ' confidence' }));
    if (f.line) {
      metaBits.appendChild(el('button.tag.tag-jump', {
        text: '↧ line ' + f.line,
        onclick: () => { switchTab('source'); source.gotoLine(f.line); },
      }));
    }
    head.appendChild(metaBits);
    card.appendChild(head);

    if (f.evidence) {
      const pre = el('pre.finding-evidence');
      pre.appendChild(highlightInline(f.evidence));
      card.appendChild(pre);
    }
    if (f.impact) {
      card.appendChild(el('div.finding-block', null, [
        el('span.finding-block-label', { text: 'Impact' }),
        el('p', { text: f.impact }),
      ]));
    }
    if (f.recommendation) {
      card.appendChild(el('div.finding-block.finding-fix', null, [
        el('span.finding-block-label', { text: 'Recommendation' }),
        el('p', { text: f.recommendation }),
      ]));
    }
    // staggered entrance
    card.style.animationDelay = Math.min(index, 8) * 40 + 'ms';
    card.classList.add('enter');
    return card;
  }

  function addFinding(f) {
    hide($('findingsSkeleton'));
    state.findings.push(f);
    const key = SEV[f.severity] ? f.severity : 'info';
    state.counts[key] = (state.counts[key] || 0) + 1;
    renderCounts();

    const list = $('findingsMount');
    const card = findingCard(f, state.findings.length - 1);
    // insert keeping severity order (contract sends most-severe-first, but be safe)
    const rank = sevOf(f.severity).rank;
    let placed = false;
    for (const existing of list.children) {
      if (sevOf(existing.dataset.sev).rank > rank) { list.insertBefore(card, existing); placed = true; break; }
    }
    if (!placed) list.appendChild(card);
    $('findingsCount').textContent = String(state.findings.length);
    if (f.line) source.addMarker(f.line, 'finding', (f.severity || '') + ': ' + (f.title || ''));
  }

  // ---------- Flows / behaviors ----------
  function addFlow(f) {
    state.flows.push(f);
    flow.add(f);
  }
  function addBehavior(text) {
    state.behaviors.push(text);
    const list = $('behaviorsMount');
    if (state.behaviors.length === 1) clear(list);
    const item = el('li.behavior.enter', null, [el('span.behavior-dot'), el('span', { text })]);
    list.appendChild(item);
    show($('behaviorsCard'));
  }

  // ---------- Compliance ----------
  function renderCompliance(c) {
    state.compliance = c;
    const mount = clear($('complianceMount'));
    const safe = c.paymentPageSafe === true;
    const banner = el('div.pci-banner', { dataset: { safe: safe ? 'yes' : 'no' } }, [
      el('span.pci-ico', { text: safe ? '✓' : '✕' }),
      el('div', null, [
        el('div.pci-q', { text: 'Safe on payment pages?' }),
        el('div.pci-a', { text: safe ? 'Yes' : 'No' }),
      ]),
    ]);
    mount.appendChild(banner);
    if (c.pci) mount.appendChild(el('div.comp-row', null, [el('span.comp-key', { text: 'PCI DSS 6.4.3 / 11.6.1' }), el('p', { text: c.pci })]));
    if (c.privacy) mount.appendChild(el('div.comp-row', null, [el('span.comp-key', { text: 'Privacy (GDPR / CCPA)' }), el('p', { text: c.privacy })]));
    show($('complianceCard'));
  }

  // ---------- Recommendations ----------
  function addRecommendation(r) {
    state.recommendations.push(r);
    const list = $('recsMount');
    if (state.recommendations.length === 1) clear(list);
    const item = el('li.rec.enter', null, [
      el('span.rec-num', { text: String(r.priority || state.recommendations.length) }),
      el('div.rec-body', null, [
        r.action ? el('span.rec-action', { dataset: { action: r.action }, text: r.action }) : null,
        el('span.rec-text', { text: r.text || '' }),
      ]),
    ]);
    list.appendChild(item);
    show($('recsCard'));
  }

  // ---------- CSP ----------
  function renderCsp(c) {
    state.csp = c;
    const mount = clear($('cspMount'));
    const pre = el('pre.csp-policy');
    pre.appendChild(el('code', { text: c.policy || '' }));
    const copyBtn = el('button.btn.btn-copy', { text: 'Copy', onclick: (e) => copyText(c.policy || '', e.currentTarget) });
    mount.appendChild(el('div.csp-head', null, [el('span.csp-label', { text: 'Recommended Content-Security-Policy' }), copyBtn]));
    mount.appendChild(pre);
    if (c.notes) mount.appendChild(el('p.csp-notes', { text: c.notes }));
    show($('cspCard'));
  }

  // ---------- Indicators ----------
  function addIndicator(i) {
    state.indicators.push(i);
    const tbody = $('iocBody');
    if (state.indicators.length === 1) clear(tbody);
    const valCell = el('td.ioc-val');
    valCell.appendChild(el('code', { text: i.value || '' }));
    const row = el('tr.enter', null, [
      el('td', null, [el('span.ioc-kind', { text: i.kind || 'other' })]),
      valCell,
      el('td', { text: i.note || '' }),
      el('td.ioc-actions', null, [el('button.btn.btn-mini', { text: 'Copy', onclick: (e) => copyText(i.value || '', e.currentTarget) })]),
    ]);
    tbody.appendChild(row);
    show($('iocCard'));
  }

  // ---------- Pre-scan ----------
  function renderStatic(r) {
    state.static = r;
    const st = r.stats || {};
    const mount = clear($('prescanMount'));
    const stats = el('div.prescan-stats', null, [
      statChip(fmtInt(st.chars), 'chars'),
      statChip(fmtInt(st.lines), 'lines'),
      statChip(st.minified ? 'yes' : 'no', 'minified'),
      typeof r.localScore === 'number' ? statChip(r.localScore + '/100', 'static score') : null,
      r.truncated ? statChip('yes', 'truncated for model') : null,
    ]);
    mount.appendChild(stats);

    if ((r.domains || []).length) {
      const dom = el('div.prescan-domains');
      dom.appendChild(el('span.prescan-sub', { text: 'Domains' }));
      r.domains.forEach((d) => dom.appendChild(el('span.chip.chip-domain', { text: `${d.domain}${d.count ? ' ×' + d.count : ''}` })));
      mount.appendChild(dom);
    }

    const hits = el('div.prescan-hits');
    if ((r.findings || []).length) {
      r.findings.forEach((f) => {
        const det = el('details.prescan-hit', { dataset: { sev: f.severity } });
        const sum = el('summary', null, [
          severityBadge(f.severity),
          el('span.prescan-hit-title', { text: f.title }),
          el('span.prescan-hit-count', { text: '×' + (f.count || (f.samples || []).length || 1) }),
        ]);
        det.appendChild(sum);
        (f.samples || []).forEach((s) => {
          const row = el('div.prescan-sample');
          if (s.line) {
            row.appendChild(el('button.tag.tag-jump', { text: 'line ' + s.line, onclick: () => { switchTab('source'); source.gotoLine(s.line); } }));
          }
          const code = el('pre.prescan-code');
          code.appendChild(highlightInline(s.code || ''));
          row.appendChild(code);
          det.appendChild(row);
          if (s.line) source.addMarker(s.line, 'static', f.title);
        });
        hits.appendChild(det);
      });
    } else {
      hits.appendChild(el('div.prescan-empty', { text: 'No regex pattern hits.' }));
    }
    mount.appendChild(hits);

    // provisional gauge from static score, before the model's meta arrives.
    // Reveal the risk content so the provisional gauge is actually visible during
    // the scan; renderMeta will overwrite it with the model's verdict.
    if (!state.meta && typeof r.localScore === 'number') {
      hide($('riskSkeleton'));
      show($('riskContent'));
      gauge.setScore(r.localScore, { color: cvar('--accent'), provisional: true });
      $('riskLevel').textContent = 'SCANNING…';
    }
    tiles.prescan.textContent = fmtMs(performance.now() - startTs);
    show($('prescanCard'));
  }
  function statChip(v, l) { return el('span.prescan-stat', null, [el('b', { text: String(v) }), ' ' + l]); }

  // ---------- Done / error ----------
  function renderDone(d) {
    state.done = d;
    stopTimer();
    // Analysis finished: clear the findings skeleton and, if the model reported
    // no findings, show an explicit clean-state message instead of shimmer.
    hide($('findingsSkeleton'));
    if (!state.findings.length && !$('findingsMount').childElementCount) {
      $('findingsMount').appendChild(el('div.findings-empty', { text: 'No security findings — the model flagged nothing in this script.' }));
    }
    tiles.total.textContent = fmtMs(d.ms);
    tiles.ttft.textContent = fmtMs(d.firstTokenMs ?? liveFirstToken);
    tiles.tps.textContent = typeof d.tokensPerSec === 'number' ? fmtInt(d.tokensPerSec) : '—';
    if (d.usage) {
      const p = d.usage.prompt_tokens, c = d.usage.completion_tokens;
      tiles.tokens.textContent = `${fmtInt(c)} out · ${fmtInt(p)} in`;
    }
    if (d.model) tiles.model.textContent = d.model;
    if (typeof d.ms === 'number') tiles.timer.textContent = (d.ms / 1000).toFixed(2) + 's';
    const badge = tiles.badge;
    if (d.cached || d.replay) {
      badge.textContent = d.cached ? 'CACHED' : 'REPLAY';
      badge.dataset.kind = d.cached ? 'cached' : 'replay';
      show(badge);
    } else hide(badge);
    $('speedStrip').classList.add('done');
  }

  function renderError(e) {
    stopTimer();
    const banner = $('errorBanner');
    clear(banner);
    banner.appendChild(el('span.err-ico', { text: '⚠' }));
    const body = el('div.err-body', null, [
      el('div.err-title', { text: e.code === 'rate_limit' ? 'Rate limit reached' : 'Analysis error' }),
      el('div.err-msg', { text: e.message || 'Something went wrong.' }),
    ]);
    banner.appendChild(body);
    if (e.code === 'rate_limit' && opts.onReplay && opts.canReplay && opts.canReplay()) {
      banner.appendChild(el('button.btn.btn-primary', { text: 'Replay demo result', onclick: () => opts.onReplay() }));
    }
    banner.dataset.code = e.code || 'error';
    show(banner);
  }

  // ---------- Tabs ----------
  function switchTab(name) {
    for (const btn of document.querySelectorAll('.tab-btn')) btn.classList.toggle('active', btn.dataset.tab === name);
    for (const panel of document.querySelectorAll('.tab-panel')) panel.classList.toggle('active', panel.dataset.tab === name);
    // The flow diagram lives in the analysis panel; redraw its connectors once the
    // panel is visible again (they measure real DOM geometry, which is 0 when hidden).
    if (name === 'analysis') requestAnimationFrame(() => flow.relayout && flow.relayout());
  }

  // ---------- Event dispatch ----------
  function handleEvent(evt) {
    if (!evt || typeof evt.type !== 'string') return;
    try {
      switch (evt.type) {
        case 'static': renderStatic(evt); break;
        case 'meta':
          if (liveFirstToken == null) { liveFirstToken = performance.now() - startTs; tiles.ttft.textContent = fmtMs(liveFirstToken); }
          renderMeta(evt); break;
        case 'behavior': addBehavior(evt.text || ''); break;
        case 'flow': addFlow(evt); break;
        case 'finding': addFinding(evt); break;
        case 'compliance': renderCompliance(evt); break;
        case 'recommendation': addRecommendation(evt); break;
        case 'csp': renderCsp(evt); break;
        case 'indicator': addIndicator(evt); break;
        case 'done': renderDone(evt); break;
        case 'error': renderError(evt); break;
        default: break; // ignore unknown types per contract
      }
    } catch (err) {
      // never let one bad event break the stream
      console.warn('render error for', evt.type, err);
    }
  }

  function setSource(script, sourceLabel) {
    state.script = script || '';
    state.source = sourceLabel || '';
    source.set(script || '');
    flow.set(state.flows, shortLabel(sourceLabel));
    $('sourceMeta').textContent = sourceLabel || 'pasted script';
  }

  function reset() {
    Object.assign(state, freshState());
    liveFirstToken = null;
    gauge.reset();
    flow.reset();
    source.setMarkers(new Map());
    renderCounts();
    clear($('findingsMount'));
    clear($('behaviorsMount'));
    clear($('recsMount'));
    clear($('iocBody'));
    clear($('prescanMount'));
    clear($('complianceMount'));
    clear($('cspMount'));
    $('findingsCount').textContent = '0';
    hide($('behaviorsCard')); hide($('recsCard')); hide($('iocCard'));
    hide($('complianceCard')); hide($('cspCard')); hide($('prescanCard'));
    hide($('errorBanner'));
    hide($('riskContent')); show($('riskSkeleton'));
    show($('findingsSkeleton'));
    $('speedStrip').classList.remove('done');
    hide(tiles.badge);
    buildSpeedStrip();
    $('riskLevel').textContent = 'SCANNING…';
    $('riskLevel').style.color = '';
    switchTab('analysis');
    startTimer();
  }

  return { handleEvent, reset, setSource, switchTab, getState: () => state, gauge, flow, source, stopTimer };
}

function shortLabel(src) {
  if (!src) return 'Script';
  try { const u = new URL(src); return u.pathname.split('/').pop() || u.host; }
  catch { return src.split('/').pop() || src; }
}
