// Tiny, safe JavaScript tokenizer for syntax highlighting.
// Produces token objects only; the renderer builds DOM via textContent, so no
// script-derived text is ever interpreted as HTML.

const KEYWORDS = new Set([
  'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while', 'do',
  'switch', 'case', 'default', 'break', 'continue', 'new', 'delete', 'typeof',
  'instanceof', 'in', 'of', 'void', 'this', 'null', 'true', 'false', 'undefined',
  'try', 'catch', 'finally', 'throw', 'class', 'extends', 'super', 'import', 'export',
  'from', 'as', 'async', 'await', 'yield', 'static', 'get', 'set',
]);

// Regex vs. divide is ambiguous without a full parser; a good heuristic is
// "previous significant token was a value/closebracket → divide, else regex".
function regexAllowed(prev) {
  if (!prev) return true;
  if (prev.type === 'num' || prev.type === 'string' || prev.type === 'regex') return false;
  if (prev.type === 'name' && !KEYWORDS.has(prev.value)) return false;
  if (prev.type === 'punct' && (prev.value === ')' || prev.value === ']')) return false;
  return true;
}

export function tokenize(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;
  let prev = null;
  const push = (type, value) => { const t = { type, value }; tokens.push(t); if (type !== 'ws') prev = t; };

  while (i < n) {
    const c = src[i];

    // Whitespace (kept so we can rebuild lines faithfully)
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      let j = i + 1;
      while (j < n && /[ \t\r\n]/.test(src[j])) j++;
      push('ws', src.slice(i, j));
      i = j;
      continue;
    }
    // Line comment
    if (c === '/' && src[i + 1] === '/') {
      let j = i + 2;
      while (j < n && src[j] !== '\n') j++;
      push('comment', src.slice(i, j));
      i = j;
      continue;
    }
    // Block comment
    if (c === '/' && src[i + 1] === '*') {
      let j = i + 2;
      while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++;
      j = Math.min(n, j + 2);
      push('comment', src.slice(i, j));
      i = j;
      continue;
    }
    // Strings
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === c) { j++; break; }
        if (src[j] === '\n') break;
        j++;
      }
      push('string', src.slice(i, j));
      i = j;
      continue;
    }
    // Template literal (flat — no nested expression coloring, good enough)
    if (c === '`') {
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === '`') { j++; break; }
        j++;
      }
      push('string', src.slice(i, j));
      i = j;
      continue;
    }
    // Regex literal
    if (c === '/' && regexAllowed(prev)) {
      let j = i + 1;
      let inClass = false;
      let ok = false;
      while (j < n) {
        const d = src[j];
        if (d === '\\') { j += 2; continue; }
        if (d === '\n') break;
        if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) { j++; ok = true; break; }
        j++;
      }
      if (ok) {
        while (j < n && /[a-z]/i.test(src[j])) j++; // flags
        push('regex', src.slice(i, j));
        i = j;
        continue;
      }
    }
    // Numbers
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(src[i + 1]))) {
      let j = i + 1;
      while (j < n && /[0-9a-fA-FxXoObBeE._+-]/.test(src[j])) {
        // stop on a +/- that isn't part of an exponent
        if ((src[j] === '+' || src[j] === '-') && !/[eE]/.test(src[j - 1])) break;
        j++;
      }
      push('num', src.slice(i, j));
      i = j;
      continue;
    }
    // Identifiers / keywords
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$]/.test(src[j])) j++;
      const word = src.slice(i, j);
      let type = 'name';
      if (KEYWORDS.has(word)) type = 'kw';
      else if (/^[A-Z]/.test(word)) type = 'type';
      else if (src[j] === '(') type = 'fn';
      push(type, word);
      i = j;
      continue;
    }
    // Punctuation / operators
    push('punct', c);
    i++;
  }
  return tokens;
}

// Split token stream into per-line arrays (whitespace newlines split lines).
export function tokenizeLines(src) {
  const tokens = tokenize(src);
  const lines = [[]];
  for (const t of tokens) {
    if (t.value.indexOf('\n') === -1) {
      lines[lines.length - 1].push(t);
      continue;
    }
    const parts = t.value.split('\n');
    parts.forEach((part, idx) => {
      if (idx > 0) lines.push([]);
      if (part) lines[lines.length - 1].push({ type: t.type, value: part });
    });
  }
  return lines;
}

// Build a DOM fragment for a single line's token list (safe: textContent).
export function renderLineTokens(lineTokens) {
  const frag = document.createDocumentFragment();
  for (const t of lineTokens) {
    if (t.type === 'ws') {
      frag.appendChild(document.createTextNode(t.value));
      continue;
    }
    const span = document.createElement('span');
    span.className = 'tk-' + t.type;
    span.textContent = t.value;
    frag.appendChild(span);
  }
  return frag;
}

// Inline highlight for short evidence snippets → returns a <code> element.
export function highlightInline(code) {
  const wrap = document.createElement('code');
  wrap.className = 'hl';
  const lines = tokenizeLines(code);
  lines.forEach((ln, idx) => {
    if (idx > 0) wrap.appendChild(document.createTextNode('\n'));
    wrap.appendChild(renderLineTokens(ln));
  });
  return wrap;
}
