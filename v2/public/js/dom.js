// Small DOM helpers. Everything model/script-derived goes through textContent
// or these builders — never string-concatenated innerHTML with untrusted data.

export const $ = (id) => document.getElementById(id);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/**
 * el('div.card#id', { attrs }, [children | strings])
 * Tag/class/id parsed from the selector. Strings become text nodes (safe).
 */
export function el(spec, attrs = null, children = null) {
  const m = /^([a-z0-9]+)?(#[\w-]+)?((?:\.[\w-]+)*)$/i.exec(spec) || [];
  const tag = m[1] || 'div';
  const node = document.createElement(tag);
  if (m[2]) node.id = m[2].slice(1);
  if (m[3]) node.className = m[3].split('.').filter(Boolean).join(' ');
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'text') node.textContent = v;
      else if (k === 'class') node.className = [node.className, v].filter(Boolean).join(' ');
      else if (k === 'html') node.innerHTML = v; // only ever called with our own trusted markup
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = dv;
      else node.setAttribute(k, v);
    }
  }
  if (children != null) {
    for (const c of [].concat(children)) {
      if (c == null || c === false) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
  }
  return node;
}

export function clear(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function svg(tag, attrs = {}) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) node.setAttribute(k, v);
  return node;
}

// SVG element with a text child (safe insert)
export function svgText(attrs, text) {
  const t = svg('text', attrs);
  t.textContent = text;
  return t;
}

export const show = (node) => node && node.classList.remove('hidden');
export const hide = (node) => node && node.classList.add('hidden');

// Copy-to-clipboard with a visual confirmation on the trigger button.
export async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for environments without async clipboard.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch { /* ignore */ }
    document.body.removeChild(ta);
  }
  if (btn) {
    const prev = btn.dataset.label || btn.textContent;
    btn.dataset.label = prev;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    clearTimeout(btn._copyT);
    btn._copyT = setTimeout(() => {
      btn.textContent = prev;
      btn.classList.remove('copied');
    }, 1200);
  }
}

export const fmtInt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : '—');
export const fmtMs = (n) => (typeof n === 'number' ? (n >= 1000 ? (n / 1000).toFixed(2) + 's' : Math.round(n) + 'ms') : '—');
