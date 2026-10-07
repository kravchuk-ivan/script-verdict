// Source viewer: line numbers, JS syntax highlighting, markers on lines that have
// static hits or model findings, jump-to-line, and a pretty-print toggle for
// minified single-line scripts. Rendering is capped for very large files.

import { el, clear } from './dom.js';
import { tokenizeLines, renderLineTokens } from './highlight.js';
import { prettyPrint } from './prettyprint.js';

const MAX_LINES = 6000;
const MAX_CHARS = 400000;

export function createSourceView(container) {
  let rawScript = '';
  let pretty = false;
  let markers = new Map(); // line(1-based) -> {kind:'static'|'finding', title}
  const rows = new Map(); // line -> row element

  const codeWrap = el('div.sv-code');
  container.appendChild(codeWrap);

  function currentText() {
    if (!pretty) return rawScript;
    try { return prettyPrint(rawScript); } catch { return rawScript; }
  }

  function render() {
    clear(codeWrap);
    rows.clear();
    let text = currentText();
    let truncatedNote = null;
    if (text.length > MAX_CHARS) {
      text = text.slice(0, MAX_CHARS);
      truncatedNote = 'Output capped at ' + MAX_CHARS.toLocaleString() + ' characters.';
    }
    let lines = tokenizeLines(text);
    if (lines.length > MAX_LINES) {
      lines = lines.slice(0, MAX_LINES);
      truncatedNote = 'Showing first ' + MAX_LINES.toLocaleString() + ' lines.';
    }
    const usable = !pretty; // markers map to original line numbers only
    lines.forEach((ln, idx) => {
      const num = idx + 1;
      const row = el('div.sv-row', { dataset: { line: num } });
      const gutter = el('span.sv-gutter', { text: String(num) });
      const marker = el('span.sv-marker');
      const code = el('span.sv-line');
      code.appendChild(renderLineTokens(ln));
      if (ln.length === 0) code.appendChild(document.createTextNode('​'));
      row.append(marker, gutter, code);
      if (usable && markers.has(num)) {
        const mk = markers.get(num);
        row.classList.add('sv-hit', 'sv-hit-' + mk.kind);
        marker.title = mk.title || '';
      }
      codeWrap.appendChild(row);
      rows.set(num, row);
    });
    if (truncatedNote) codeWrap.appendChild(el('div.sv-note', { text: truncatedNote }));
    if (!rawScript.trim()) codeWrap.appendChild(el('div.sv-note', { text: 'No source loaded.' }));
  }

  function set(script) {
    rawScript = script || '';
    render();
  }
  function setMarkers(map) {
    markers = map || new Map();
    render();
  }
  function addMarker(line, kind, title) {
    if (!line) return;
    // Always record the marker so it survives a later Pretty toggle; the DOM rows
    // are keyed to original line numbers, so only skip the live row update in pretty mode.
    if (!markers.has(line)) { markers.set(line, { kind, title }); }
    if (pretty) return;
    const row = rows.get(line);
    if (row && !row.classList.contains('sv-hit')) {
      row.classList.add('sv-hit', 'sv-hit-' + kind);
      const mk = row.querySelector('.sv-marker');
      if (mk) mk.title = title || '';
    }
  }
  function setPretty(on) {
    pretty = !!on;
    render();
  }
  function isPretty() { return pretty; }
  function gotoLine(line) {
    if (pretty) return; // line numbers differ when pretty-printed
    const row = rows.get(line);
    if (!row) return;
    row.scrollIntoView({ block: 'center', behavior: 'smooth' });
    row.classList.add('sv-flash');
    setTimeout(() => row.classList.remove('sv-flash'), 1400);
  }

  return { set, setMarkers, addMarker, setPretty, isPretty, gotoLine };
}
