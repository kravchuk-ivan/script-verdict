// Animated SVG risk gauge — a 270° arc with an animated value sweep and a large
// numeric readout. Build once, then call setScore() to animate to new values.

import { svg, svgText } from './dom.js';

const R = 78;
const CX = 100;
const CY = 100;
const C = 2 * Math.PI * R;
const SWEEP = 0.75; // 270° of the circle is the track
const ARC = C * SWEEP;
const ROT = `rotate(135 ${CX} ${CY})`; // gap centered at the bottom

export function createGauge(container) {
  const s = svg('svg', { viewBox: '0 0 200 200', class: 'gauge-svg' });
  s.setAttribute('role', 'img');

  const track = svg('circle', {
    cx: CX, cy: CY, r: R, fill: 'none', class: 'gauge-track',
    'stroke-width': 14, 'stroke-linecap': 'round',
    'stroke-dasharray': `${ARC} ${C}`, transform: ROT,
  });

  const value = svg('circle', {
    cx: CX, cy: CY, r: R, fill: 'none', class: 'gauge-value',
    'stroke-width': 14, 'stroke-linecap': 'round',
    'stroke-dasharray': `0 ${C}`, transform: ROT,
  });

  const number = svgText({ x: CX, y: CY + 6, class: 'gauge-number', 'text-anchor': 'middle' }, '—');
  const outOf = svgText({ x: CX, y: CY + 30, class: 'gauge-outof', 'text-anchor': 'middle' }, '/ 100');

  s.append(track, value, number, outOf);
  container.appendChild(s);

  let current = 0;

  // Both the arc sweep and the numeric readout are set to the true target
  // synchronously; the arc sweep is animated by a CSS transition on
  // stroke-dasharray, which is reliable under throttled rAF / background tabs /
  // headless virtual-time. No rAF loop, so the gauge can never be left mid-frame.
  function paintArc(v) {
    const frac = Math.max(0, Math.min(100, v)) / 100;
    value.setAttribute('stroke-dasharray', `${ARC * frac} ${C}`);
  }

  function setColor(color) {
    value.style.stroke = color;
    number.style.fill = color;
  }

  function setScore(target, { color, provisional = false } = {}) {
    if (color) setColor(color);
    s.classList.toggle('provisional', provisional);
    const to = Math.max(0, Math.min(100, target || 0));
    current = to;
    paintArc(to);
    number.textContent = String(Math.round(to));
  }

  function reset() {
    current = 0;
    paintArc(0);
    number.textContent = '—';
    s.classList.remove('provisional');
    value.style.stroke = '';
    number.style.fill = '';
  }

  return { setScore, setColor, reset, node: s };
}
