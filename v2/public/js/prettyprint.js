// Basic pretty-printer for minified single-line scripts. Inserts newlines after
// ; { } (and before }) while respecting string/template/regex/comment boundaries,
// then re-indents by brace depth. Intentionally simple — good enough to make a
// minified blob readable in the source viewer.

export function prettyPrint(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  let depth = 0;
  const NL = '\n';
  const pad = () => '  '.repeat(Math.max(0, depth));

  // Track the last non-space emitted char for regex/asi heuristics
  let lastSig = '';

  while (i < n) {
    const c = src[i];

    // Strings
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === quote) { j++; break; }
        if (quote !== '`' && src[j] === '\n') break;
        j++;
      }
      out += src.slice(i, j);
      lastSig = quote;
      i = j;
      continue;
    }
    // Comments
    if (c === '/' && src[i + 1] === '/') {
      let j = i + 2;
      while (j < n && src[j] !== '\n') j++;
      out += src.slice(i, j);
      i = j;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      let j = i + 2;
      while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++;
      j = Math.min(n, j + 2);
      out += src.slice(i, j);
      lastSig = '/';
      i = j;
      continue;
    }
    // Regex (heuristic: allowed after these chars)
    if (c === '/' && /[=(,:;{}[&|!?+\-*%^~<>]/.test(lastSig || '')) {
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
        while (j < n && /[a-z]/i.test(src[j])) j++;
        out += src.slice(i, j);
        lastSig = '/';
        i = j;
        continue;
      }
    }

    if (c === '{') {
      depth++;
      out = out.replace(/[ \t]+$/, '') + ' {' + NL + pad();
      lastSig = '{';
      i++;
      // swallow following whitespace
      while (i < n && /[ \t]/.test(src[i])) i++;
      continue;
    }
    if (c === '}') {
      depth = Math.max(0, depth - 1);
      out = out.replace(/[ \t]*$/, '');
      if (!out.endsWith(NL)) out += NL;
      out += pad() + '}';
      lastSig = '}';
      i++;
      // attach following ; or , then newline
      while (i < n && /[ \t]/.test(src[i])) i++;
      if (src[i] === ';' || src[i] === ',' || src[i] === ')') { out += src[i]; lastSig = src[i]; i++; }
      out += NL + pad();
      continue;
    }
    if (c === ';') {
      out += ';';
      lastSig = ';';
      i++;
      while (i < n && /[ \t]/.test(src[i])) i++;
      // don't break inside for(;;) — cheap check: if next non-space is ) skip newline
      if (src[i] !== ')') out += NL + pad();
      continue;
    }
    if (c === '\n' || c === '\r') {
      // collapse existing newlines; our own formatting drives layout
      i++;
      continue;
    }

    out += c;
    if (!/\s/.test(c)) lastSig = c;
    i++;
  }
  // tidy: collapse blank lines and trailing spaces
  return out
    .split('\n')
    .map((l) => l.replace(/[ \t]+$/, ''))
    .filter((l, idx, arr) => !(l === '' && arr[idx - 1] === ''))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
