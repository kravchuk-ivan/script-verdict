// Data-flow visualization. Source (page + script) on the left, exfiltration
// destinations on the right, curved SVG connectors labeled with data + method and
// colored by sensitivity. Connectors are measured from real DOM positions so the
// diagram stays correct across widths; call relayout() on resize.

import { el, clear, svg } from './dom.js';

const SENS_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export function createFlow(container) {
  let flows = [];
  let sourceLabel = 'Script';

  const grid = el('div.flow-grid');
  const left = el('div.flow-col.flow-left');
  const right = el('div.flow-col.flow-right');
  const links = svg('svg', { class: 'flow-links' });
  grid.append(left, links, right);
  container.appendChild(grid);

  function build() {
    clear(left);
    clear(right);

    const sorted = [...flows].sort((a, b) => (SENS_ORDER[a.sensitivity] ?? 4) - (SENS_ORDER[b.sensitivity] ?? 4));

    const pageNode = el('div.flow-node.flow-node-page', null, [
      el('div.flow-node-ico', { text: '🌐' }),
      el('div.flow-node-body', null, [
        el('div.flow-node-title', { text: 'Host page' }),
        el('div.flow-node-sub', { text: 'DOM · inputs · cookies' }),
      ]),
    ]);
    const scriptNode = el('div.flow-node.flow-node-script', null, [
      el('div.flow-node-ico', { text: '📜' }),
      el('div.flow-node-body', null, [
        el('div.flow-node-title', { text: sourceLabel }),
        el('div.flow-node-sub', { text: 'analyzed script' }),
      ]),
    ]);
    scriptNode.dataset.anchor = 'src';
    left.append(pageNode, scriptNode);

    if (!sorted.length) {
      right.appendChild(el('div.flow-empty', { text: 'No outbound data flows detected yet.' }));
    }
    sorted.forEach((f, idx) => {
      const dest = el('div.flow-node.flow-dest', { dataset: { anchor: 'd' + idx, sens: f.sensitivity || 'low' } }, [
        el('div.flow-dest-top', null, [
          el('span.flow-sens-dot'),
          el('span.flow-dest-host', { text: hostOf(f.destination) }),
        ]),
        el('div.flow-dest-path', { text: pathOf(f.destination) }),
        el('div.flow-dest-meta', null, [
          el('span.flow-chip.flow-method', { text: f.method || 'request' }),
          el('span.flow-chip.flow-data', { text: f.data || 'data' }),
        ]),
      ]);
      right.appendChild(dest);
    });

    requestAnimationFrame(drawLinks);
  }

  function drawLinks() {
    // Don't wipe existing connectors if the container is hidden (0 size), e.g.
    // while the Source tab is active — keep them for when Analysis is shown again.
    const box = container.getBoundingClientRect();
    if (!box.width) return;
    clear(links);
    links.setAttribute('viewBox', `0 0 ${box.width} ${box.height}`);
    links.setAttribute('width', box.width);
    links.setAttribute('height', box.height);

    const src = left.querySelector('[data-anchor="src"]');
    if (!src) return;
    const sb = src.getBoundingClientRect();
    const sx = sb.right - box.left;
    const sy = sb.top + sb.height / 2 - box.top;

    const dests = right.querySelectorAll('.flow-dest');
    dests.forEach((d) => {
      const db = d.getBoundingClientRect();
      const dx = db.left - box.left;
      const dy = db.top + db.height / 2 - box.top;
      const mx = (sx + dx) / 2;
      const path = svg('path', {
        d: `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${dy}, ${dx} ${dy}`,
        fill: 'none',
        class: 'flow-link sens-' + (d.dataset.sens || 'low'),
        'stroke-width': 2.5,
      });
      links.appendChild(path);
      // endpoint dots
      links.appendChild(svg('circle', { cx: dx, cy: dy, r: 3.5, class: 'flow-link-dot sens-' + (d.dataset.sens || 'low') }));
    });
    links.appendChild(svg('circle', { cx: sx, cy: sy, r: 4, class: 'flow-link-dot sens-src' }));
  }

  function set(newFlows, label) {
    flows = newFlows || [];
    if (label) sourceLabel = label;
    build();
  }
  function add(flow) {
    flows.push(flow);
    build();
  }
  function reset() {
    flows = [];
    build();
  }

  window.addEventListener('resize', () => requestAnimationFrame(drawLinks));
  build();
  return { set, add, reset, relayout: drawLinks };
}

function hostOf(url) {
  if (!url) return 'unknown';
  try { return new URL(url.includes('://') ? url : 'https://' + url).host; }
  catch { return String(url).split('/')[0]; }
}
function pathOf(url) {
  if (!url) return '';
  try { const u = new URL(url.includes('://') ? url : 'https://' + url); return u.pathname + u.search; }
  catch { const i = String(url).indexOf('/'); return i >= 0 ? String(url).slice(i) : ''; }
}
