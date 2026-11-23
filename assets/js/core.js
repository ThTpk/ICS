/* ============================================================
   ICS · Information & Computer Security
   core.js — isometric scene engine + lesson shell
   ไม่มี dependency ภายนอก เปิดจากไฟล์ตรงๆ ได้
   ============================================================ */
window.ICS = (function () {
'use strict';

const NS = 'http://www.w3.org/2000/svg';
const U = 36, OX = 395, OY = 120, C30 = Math.cos(Math.PI / 6);

/* ---------- isometric math + svg helpers ---------- */
const iso = (x, y, z = 0) => [OX + (x - y) * C30 * U, OY + (x + y) * 0.5 * U - z * U];
const pts = a => a.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
const dist = (a, b) => Math.hypot(b[0] - a[0], b[1] - a[1]);

function el(tag, attrs, parent) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}
const line = (a, b, cls, parent) => el('line', { x1: a[0], y1: a[1], x2: b[0], y2: b[1], class: cls }, parent);

/* rounded polygon path */
function rpath(P, r) {
  const n = P.length; let d = '';
  for (let i = 0; i < n; i++) {
    const p = P[i], a = P[(i - 1 + n) % n], b = P[(i + 1) % n];
    const la = Math.hypot(a[0] - p[0], a[1] - p[1]) || 1, lb = Math.hypot(b[0] - p[0], b[1] - p[1]) || 1;
    const ra = Math.min(r, la / 2), rb = Math.min(r, lb / 2);
    const s = [p[0] + (a[0] - p[0]) / la * ra, p[1] + (a[1] - p[1]) / la * ra];
    const e = [p[0] + (b[0] - p[0]) / lb * rb, p[1] + (b[1] - p[1]) / lb * rb];
    d += (i ? 'L' : 'M') + s[0].toFixed(1) + ',' + s[1].toFixed(1) + 'Q' + p[0].toFixed(1) + ',' + p[1].toFixed(1) + ' ' + e[0].toFixed(1) + ',' + e[1].toFixed(1);
  }
  return d + 'Z';
}

/* rounded isometric block: silhouette + top face + front edge */
function block(g, cx, cy, w, d, h, z0, side, top, r, cls = '') {
  const x0 = cx - w / 2, x1 = cx + w / 2, y0 = cy - d / 2, y1 = cy + d / 2, zt = z0 + h;
  el('path', { class: 'slab-side ' + (cls ? cls + '-side' : ''), fill: side, d: rpath([iso(x0, y0, zt), iso(x1, y0, zt), iso(x1, y0, z0), iso(x1, y1, z0), iso(x0, y1, z0), iso(x0, y1, zt)], r) }, g);
  line(iso(x1, y1, zt), iso(x1, y1, z0 + 0.04), 'edge', g);
  el('path', { class: 'slab-top ' + (cls ? cls + '-top' : ''), fill: top, d: rpath([iso(x0, y0, zt), iso(x1, y0, zt), iso(x1, y1, zt), iso(x0, y1, zt)], r) }, g);
  return { x0, x1, y0, y1, z0, zt, cx, cy };
}

const PAL = {
  sand:   ['#ecd9bf', '#f6e6c9'],
  orange: ['#f4c9a0', '#fcdcbd'],
  green:  ['#cfdcb8', '#e8efd9'],
  violet: ['#c4b4da', '#e7ddf5'],
  blue:   ['#bfd5ee', '#d6e5f6'],
  rose:   ['#f0b6ad', '#f8d5cf'],
  bone:   ['#e9dcc8', '#f9f2e8'],
  dark:   ['#4e453d', '#6a5f55'],
  grey:   ['#cfc6ba', '#e2dad0']
};

/* ---------- label pill (anchored to a scene point) ---------- */
function pill(parent, x, y, parts, anchor = 'middle') {
  const g = el('g', { class: 'pill' }, parent);
  const sh = el('rect', { class: 'pill-shadow', rx: 11, height: 23 }, g);
  const bg = el('rect', { class: 'pill-bg', rx: 11, height: 23 }, g);
  const t = el('text', { y: y + 4.5 }, g);
  const api = {
    g,
    set(ps) {
      const key = ps.join('|');
      if (key === api.key) return; api.key = key;
      t.textContent = '';
      ps.forEach((s, i) => { const ts = el('tspan', i ? { class: 'm', dx: 7 } : {}, t); ts.textContent = s; });
      const w = (t.getComputedTextLength() || ps.join('  ').length * 7) + 22;
      const left = anchor === 'middle' ? x - w / 2 : anchor === 'end' ? x - w : x;
      t.setAttribute('x', left + 11);
      [bg, sh].forEach(r => { r.setAttribute('width', w); r.setAttribute('y', y - 11.5); });
      bg.setAttribute('x', left); sh.setAttribute('x', left + 1.5); sh.setAttribute('y', y - 9);
    },
    tone(cls) { g.setAttribute('class', 'pill ' + (cls || '')); }
  };
  api.set(parts);
  return api;
}

/* ---------- flat info panel (HUD, logs, code boards) ---------- */
function panel(parent, o) {
  const x = o.x, y = o.y, w = o.w, rows = o.rows || 3, lh = o.lh || 16;
  const h = (o.title ? 22 : 10) + rows * lh + 6;
  const g = el('g', {}, parent);
  el('rect', { class: 'pn-shadow', x: x + 2, y: y + 3, width: w, height: h, rx: 9 }, g);
  el('rect', { class: 'pn-bg' + (o.dark ? ' dark' : ''), x, y, width: w, height: h, rx: 9 }, g);
  let t0 = null;
  if (o.title) { t0 = el('text', { class: 'pn-title', x: x + 10, y: y + 15 }, g); t0.textContent = o.title; }
  if (o.dark && t0) t0.setAttribute('fill', '#b9ada0');
  const base = (o.title ? 32 : 20) + y;
  const L = [];
  for (let i = 0; i < rows; i++) L.push(el('text', { class: 'pn-line', x: x + 10, y: base + i * lh }, g));
  return {
    g, x, y, w, h,
    set(i, text, cls) {
      const r = L[i]; if (!r) return;
      if (r.textContent !== text) r.textContent = text == null ? '' : text;
      const c = 'pn-line ' + (cls || '');
      if (r.getAttribute('class') !== c) r.setAttribute('class', c);
    },
    title(s) { if (t0) t0.textContent = s; },
    clear() { L.forEach((_, i) => this.set(i, '', '')); }
  };
}

/* ---------- status list with lamps (C/I/A style HUD) ---------- */
function statusList(parent, o) {
  const x = o.x, y = o.y, w = o.w, items = o.items, lh = 19;
  const h = 22 + items.length * lh + 6;
  const g = el('g', {}, parent);
  el('rect', { class: 'pn-shadow', x: x + 2, y: y + 3, width: w, height: h, rx: 9 }, g);
  el('rect', { class: 'pn-bg', x, y, width: w, height: h, rx: 9 }, g);
  const ttl = el('text', { class: 'pn-title', x: x + 10, y: y + 15 }, g);
  ttl.textContent = o.title || '';
  const rows = items.map((it, i) => {
    const cy = y + 32 + i * lh;
    const lamp = el('circle', { class: 'lamp idle', cx: x + 14, cy: cy - 4, r: 4.4 }, g);
    const lb = el('text', { class: 'pn-line', x: x + 25, y: cy }, g); lb.textContent = it;
    const vl = el('text', { class: 'pn-line dim', x: x + w - 10, y: cy, 'text-anchor': 'end' }, g);
    return { lamp, lb, vl };
  });
  return {
    g,
    set(i, state, value) {
      const r = rows[i]; if (!r) return;
      const c = 'lamp ' + state;
      if (r.lamp.getAttribute('class') !== c) r.lamp.setAttribute('class', c);
      const vc = 'pn-line ' + (state === 'bad' ? 'bad' : state === 'ok' ? 'ok' : 'dim');
      if (r.vl.getAttribute('class') !== vc) r.vl.setAttribute('class', vc);
      if (r.vl.textContent !== value) r.vl.textContent = value == null ? '' : value;
    }
  };
}

/* ---------- reusable actors ---------- */
const actor = {
  /* desk with monitor — a person / client */
  desk(g, x, y, palName = 'orange', scale = 1) {
    const p = PAL[palName];
    block(g, x, y, 1.15 * scale, 1.15 * scale, 0.2, 0, PAL.sand[0], PAL.sand[1], 7);
    block(g, x, y, 0.8 * scale, 0.8 * scale, 0.42 * scale, 0.2, p[0], p[1], 4);
    const zt = 0.2 + 0.42 * scale;
    el('path', {
      d: rpath([iso(x - 0.3, y + 0.4 * scale, zt + 0.08), iso(x + 0.3, y + 0.4 * scale, zt + 0.08),
                iso(x + 0.3, y + 0.4 * scale, zt + 0.42), iso(x - 0.3, y + 0.4 * scale, zt + 0.42)], 1.5),
      fill: '#fbf7f1', stroke: '#1d1b18', 'stroke-width': .9
    }, g);
    return { x, y, zt };
  },

  /* tall rack server with a load fill */
  server(g, x, y, palName = 'bone', h = 2.0) {
    const p = PAL[palName];
    block(g, x, y, 1.9, 1.9, 0.22, 0, PAL.green[0], PAL.green[1], 10);
    const b = block(g, x, y, 1.25, 1.25, h, 0.22, p[0], p[1], 5, 'body');
    for (let k = 1; k <= 4; k++) {
      const z = b.z0 + (b.zt - b.z0) * k / 5;
      line(iso(b.x1, b.y0 + 0.22, z), iso(b.x1, b.y1 - 0.22, z), 'slit', g);
    }
    const led = iso(b.x1, b.y0 + 0.2, b.zt - 0.18);
    el('circle', { cx: led[0], cy: led[1], r: 2.6, class: 'led' }, g);
    const fill = el('polygon', { class: 'loadfill', points: '' }, g);
    const c = iso(x, y, b.zt);
    line([c[0] - 9, c[1] - 5], [c[0] + 9, c[1] + 5], 'deadx', g);
    line([c[0] - 9, c[1] + 5], [c[0] + 9, c[1] - 5], 'deadx', g);
    return { box: b, fill, x, y };
  },

  /* appliance box (gateway, firewall, crypto engine) */
  box(g, x, y, o = {}) {
    const p = PAL[o.pal || 'violet'], w = o.w || 1.4, h = o.h || 0.6;
    block(g, x, y, w + 0.7, w + 0.7, 0.22, 0, p[0], p[1], 10);
    const b = block(g, x, y, w, w, h, 0.22, p[0], p[1], 5, 'body');
    if (o.glyph) o.glyph(g, iso(x, y, b.zt), b);
    return { box: b, x, y };
  },

  /* database: stacked platters */
  db(g, x, y, palName = 'blue') {
    const p = PAL[palName];
    block(g, x, y, 2.0, 2.0, 0.22, 0, PAL.grey[0], PAL.grey[1], 10);
    let z = 0.22; const slabs = [];
    for (let i = 0; i < 3; i++) { slabs.push(block(g, x, y, 1.45, 1.45, 0.34, z, p[0], p[1], 6)); z += 0.44; }
    return { x, y, slabs, zt: z - 0.1 };
  },

  /* attacker terminal: dark box, red screen */
  attacker(g, x, y) {
    block(g, x, y, 1.35, 1.35, 0.2, 0, PAL.dark[0], PAL.dark[1], 8);
    const b = block(g, x, y, 0.95, 0.95, 0.5, 0.2, PAL.dark[0], PAL.dark[1], 4);
    el('path', {
      d: rpath([iso(x - 0.34, y + 0.47, b.zt + 0.08), iso(x + 0.34, y + 0.47, b.zt + 0.08),
                iso(x + 0.34, y + 0.47, b.zt + 0.5), iso(x - 0.34, y + 0.47, b.zt + 0.5)], 1.5),
      fill: '#2a2320', stroke: '#1d1b18', 'stroke-width': 1
    }, g);
    const s = iso(x - 0.22, y + 0.47, b.zt + 0.38);
    for (let i = 0; i < 3; i++) {
      const a = iso(x - 0.24, y + 0.47, b.zt + 0.38 - i * 0.11), e = iso(x + (i === 1 ? 0.04 : 0.18), y + 0.47, b.zt + 0.38 - i * 0.11);
      el('line', { x1: a[0], y1: a[1], x2: e[0], y2: e[1], stroke: '#e5534b', 'stroke-width': 1.6, 'stroke-linecap': 'round' }, g);
    }
    void s;
    return { box: b, x, y };
  }
};

/* glyph painters for appliance tops */
const glyph = {
  split(g, c) {
    el('path', { class: 'glyph v', d: `M${c[0] - 13},${c[1]} h9 M${c[0] - 4},${c[1]} l10,-6 M${c[0] - 4},${c[1]} l10,6 M${c[0] - 4},${c[1]} h11` }, g);
  },
  lock(g, c) {
    el('rect', { class: 'glyph g', x: c[0] - 6, y: c[1] - 3, width: 12, height: 9, rx: 2, fill: '#e8efd9' }, g);
    el('path', { class: 'glyph g', d: `M${c[0] - 3.2},${c[1] - 3} v-2.6a3.2 3.2 0 0 1 6.4 0v2.6` }, g);
  },
  wall(g, c) {
    for (let i = 0; i < 2; i++) el('path', { class: 'glyph r', d: `M${c[0] - 12},${c[1] - 2 + i * 5} h24` }, g);
    el('path', { class: 'glyph r', d: `M${c[0] - 4},${c[1] - 7} v5 M${c[0] + 5},${c[1] - 7} v5 M${c[0]},${c[1] + 3} v5` }, g);
  },
  hash(g, c) {
    el('path', { class: 'glyph b', d: `M${c[0] - 7},${c[1] - 6} v12 M${c[0] + 1},${c[1] - 6} v12 M${c[0] - 11},${c[1] - 2} h16 M${c[0] - 11},${c[1] + 3} h16` }, g);
  },
  cert(g, c) {
    el('rect', { class: 'glyph v', x: c[0] - 8, y: c[1] - 7, width: 16, height: 12, rx: 2, fill: '#ebe3f1' }, g);
    el('path', { class: 'glyph v', d: `M${c[0] - 4},${c[1] - 3} h8 M${c[0] - 4},${c[1] + 1} h5` }, g);
  },
  db(g, c) {
    el('path', { class: 'glyph b', d: `M${c[0] - 8},${c[1] - 4} h16 M${c[0] - 8},${c[1]} h16 M${c[0] - 8},${c[1] + 4} h16` }, g);
  }
};

/* key icon: public = green/open, private = violet/toothed */
function keyIcon(parent, cx, cy, kind, scale = 1) {
  const g = el('g', {}, parent);
  const col = kind === 'private' ? '#8d6fd1' : '#7fc278';
  const s = scale;
  el('circle', { cx, cy, r: 5 * s, fill: col, stroke: '#1d1b18', 'stroke-width': 1.1 }, g);
  el('circle', { cx, cy, r: 2 * s, fill: '#fbf7f1', stroke: '#1d1b18', 'stroke-width': .8 }, g);
  el('path', { d: `M${cx + 4.5 * s},${cy} h${11 * s}`, stroke: '#1d1b18', 'stroke-width': 2.4 * s, 'stroke-linecap': 'round' }, g);
  if (kind === 'private') {
    el('path', { d: `M${cx + 10 * s},${cy} v${5 * s} M${cx + 13.5 * s},${cy} v${4 * s}`, stroke: '#1d1b18', 'stroke-width': 2 * s, 'stroke-linecap': 'round' }, g);
  } else {
    el('path', { d: `M${cx + 12 * s},${cy} v${4.5 * s}`, stroke: '#1d1b18', 'stroke-width': 2 * s, 'stroke-linecap': 'round' }, g);
  }
  return g;
}

/* ============================================================
   lesson registry + catalog
   ============================================================ */
/* โครงคอร์สตาม Course Outline ของรายวิชา 01076042 Information and Computer Security
   ผศ.ดร. ธนัญชัย ตรีภาค · คณะวิศวกรรมศาสตร์ สจล. */
const CATALOG = [
  { num: '01', name: 'Introduction',              color: '#f6e6c9', ids: ['timeline'] },
  { num: '02', name: 'IT Systems and Architecture', color: '#fcdcbd', ids: ['infosys'] },
  { num: '03', name: 'CIA / AAA / PDR',           color: '#cfe3b2', ids: ['cia', 'mfa', 'rbac'] },
  { num: '04', name: 'Computer Networking',       color: '#d6e5f6', ids: ['netdiagram'] },
  { num: '05', name: 'Network Attack',            color: '#f8d5cf', ids: ['netattack'] },
  { num: '06', name: 'Firewall and Policy',       color: '#e7ddf5', ids: ['firewall'] },
  { num: '07', name: 'Security Tools',            color: '#cfe3b2', ids: ['nettools'] },
  { num: '08', name: 'Incident Response',         color: '#f8d5cf', ids: ['incident'] },
  { num: '09', name: 'Web Security',              color: '#d6e5f6', ids: ['sqli', 'xss'] },
  { num: '10', name: 'Wireless LAN Security',     color: '#fde3a7', ids: ['wireless'] },
  { num: '11', name: 'IT Risk Management',        color: '#fcdcbd', ids: ['risk'] },
  { num: '12', name: 'Standards and Frameworks',  color: '#e7ddf5', ids: ['iso27001'] },
  { num: '13', name: 'Law and Compliance',        color: '#f8d5cf', ids: ['law'] },
  { num: '14', name: 'Business Continuity',       color: '#cfe3b2', ids: ['bcm'] },
  { num: 'T',  name: 'Toolbox: Cryptography',     color: '#ddd3c5', ids: ['symmetric', 'asymmetric', 'hashing', 'tls'] }
];
const SOON = {
  timeline: 'Security Timeline, 1975 to now',
  netdiagram: 'Networking and Network Diagrams',
  netattack: 'Network Attacks and Scanning',
  nettools: 'Monitoring, IDS and IPS',
  incident: 'Incident Response Playbook',
  wireless: 'Wireless LAN Security (802.11)',
  iso27001: 'ISO 27001 and NIST CSF 2.0',
  law: 'Thai IT Law and PDPA',
  bcm: 'Business Continuity and DR'
};
const GLOSSARY = [
  ['Information system', 'People, processes and technology working together to collect, process, store and deliver information, so an organisation can decide, coordinate, analyse and control.'],
  ['Enterprise Architecture', 'A blueprint that aligns business processes, applications, data and technology. TOGAF, Zachman, FEAF and Gartner are the common frameworks.'],
  ['BDAT layers', 'The four TOGAF architecture layers: Business, Data, Application and Technology. Every layer exists to support the one above it.'],
  ['Asset inventory', 'The register of everything the organisation owns and runs. Anything missing from it cannot be patched, monitored or defended.'],
  ['Shadow IT', 'Hardware or software running inside the organisation that the IT team never approved and does not track.'],
  ['CIA triad', 'Confidentiality, Integrity and Availability. The three properties that together decide whether a system is secure.'],
  ['AAA', 'Authentication (who are you), Authorization (what may you do) and Accounting (what did you actually do).'],
  ['PDR', 'Protection, Detection and Response. Assume protection will eventually fail, so you must also detect and respond.'],
  ['Threat / Vulnerability / Risk', 'What might harm you / the weakness inside your own system / likelihood multiplied by impact.'],
  ['Default deny', 'Start the firewall by rejecting everything, then write allow rules only for what is genuinely needed.'],
  ['Stateful firewall', 'A firewall that remembers open connections, so return traffic passes without opening extra holes.'],
  ['WAF', 'A filter that inspects application-layer content, complementing a firewall that only sees addresses and ports.'],
  ['SQL Injection', 'User input becomes part of an SQL statement, letting an attacker command the database. Fixed with parameterised queries.'],
  ['XSS', 'User input becomes script that runs in a victim browser. Fixed by escaping output for the context it lands in.'],
  ['MFA', 'Proving identity with factors of different kinds: something you know, something you have, something you are.'],
  ['RBAC', 'Permissions are attached to roles and people are placed into roles, so one change applies to everyone in that role.'],
  ['Least privilege', 'Grant only the access the job needs, for only as long as it is needed, so a breach stays contained.'],
  ['Defense in depth', 'Layer the controls, so that when one of them fails the next one still holds.']
];

const lessons = {};
const order = [];
function register(def) { lessons[def.id] = def; if (!order.includes(def.id)) order.push(def.id); }

/* ============================================================
   runtime
   ============================================================ */
const $ = id => document.getElementById(id);
const TAGS = { problem: 'Problem', technique: 'Fix', lab: 'Lab', concept: 'Concept', attack: 'Attack' };
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

let svg, lesson = null, stepIdx = 0, speed = 1;
const sim = { paused: reduced, t: 0 };
let ctx = null;

function store(k, v) { try { if (v === undefined) return localStorage.getItem('ics:' + k); localStorage.setItem('ics:' + k, v); } catch (e) { return null; } }

/* ---------- packets ---------- */
function makeCtx() {
  const c = {
    cfg: {}, stats: {}, packets: [], L: {}, S: {}, T: {}, _ft: {}, _fa: [], _floats: [], step: null, stepIdx: 0,
    iso, pts, el, line, rpath, block, pill, panel, statusList, actor, glyph, keyIcon, PAL, dist,
    rnd: (a, b) => a + Math.random() * (b - a),
    pick: arr => arr[Math.floor(Math.random() * arr.length)],
    layer(name) { return c.L[name] || (c.L[name] = el('g', {}, svg)); },
    bump(k, n = 1) { c.stats[k] = (c.stats[k] || 0) + n; },
    /* fires n times per period; returns how many times it fired this frame */
    timer(key, dt, period) {
      const T = c.T;
      T[key] = (T[key] === undefined ? period : T[key]) - dt;
      let n = 0;
      while (T[key] <= 0) { T[key] += period; if (++n > 4) { T[key] = period; break; } }
      return n;
    },
    /* poisson-ish spawner at given rate per second */
    rate(key, dt, perSec) {
      const T = c.T;
      T[key] = (T[key] === undefined ? 200 : T[key]) - dt;
      let n = 0;
      while (T[key] <= 0) { T[key] += -Math.log(1 - Math.random()) * (1000 / Math.max(.1, perSec)); if (++n > 4) break; }
      return n;
    },
    launch(path, kind, o = {}) {
      const segs = []; let len = 0;
      for (let i = 1; i < path.length; i++) { const l = dist(path[i - 1], path[i]); segs.push(l); len += l; }
      const lay = c.L.pk || (c.L.pk = el('g', {}, svg));
      let node, w = 0;
      if (o.label != null) {
        const g = el('g', { class: 'tile ' + kind }, lay);
        const bg = el('rect', { class: 'tile-bg', rx: 5, height: 17, y: -8.5 }, g);
        const t = el('text', { y: 3.5, 'text-anchor': 'middle' }, g);
        t.textContent = o.label;
        w = (t.getComputedTextLength() || String(o.label).length * 6.2) + 12;
        bg.setAttribute('width', w); bg.setAttribute('x', -w / 2);
        node = g;
      } else {
        node = el('circle', { r: o.r || 4.8, class: 'pkt ' + kind }, lay);
      }
      const p = {
        path, segs, len, d: 0, kind, meta: o.meta || {}, el: node, tile: o.label != null,
        speed: o.speed || 300, label: o.label, w, delay: o.delay || 0, onDone: o.onDone
      };
      place(p);
      c.packets.push(p);
      return p;
    },
    /* change a flying packet's look + label */
    morph(p, kind, label) {
      if (!p.tile) { p.el.setAttribute('class', 'pkt ' + kind); p.kind = kind; return; }
      p.el.setAttribute('class', 'tile ' + kind); p.kind = kind;
      if (label != null) {
        const t = p.el.querySelector('text'), bg = p.el.querySelector('rect');
        t.textContent = label; p.label = label;
        const w = (t.getComputedTextLength() || String(label).length * 6.2) + 12;
        bg.setAttribute('width', w); bg.setAttribute('x', -w / 2); p.w = w;
      }
    },
    puff(pt, cls = '') {
      const lay = c.L.fx || (c.L.fx = el('g', {}, svg));
      const e = el('circle', { cx: pt[0], cy: pt[1], r: 5, class: 'puff ' + cls }, lay);
      setTimeout(() => e.remove(), 760);
    },
    ring(pt, cls = '') {
      const lay = c.L.fx || (c.L.fx = el('g', {}, svg));
      const e = el('circle', { cx: pt[0], cy: pt[1], r: 12, class: 'ring ' + cls }, lay);
      setTimeout(() => e.remove(), 860);
    },
    float(pt, text, cls = 'bad') {
      /* กันป้ายเดิมซ้อนกันเป็นกองเมื่อเหตุการณ์เกิดถี่ */
      const key = text + '@' + Math.round(pt[0] / 24) + ',' + Math.round(pt[1] / 24);
      if (c._ft[key] !== undefined && sim.t - c._ft[key] < 900) return;
      c._ft[key] = sim.t;
      /* ป้ายคนละข้อความที่จุดเดียวกัน ให้เรียงซ้อนขึ้นแทนการทับกัน */
      c._fa = c._fa.filter(f => sim.t - f.t < 800);
      const near = c._fa.filter(f => Math.abs(f.x - pt[0]) < 34 && Math.abs(f.y - pt[1]) < 44).length;
      c._fa.push({ x: pt[0], y: pt[1], t: sim.t });
      const baseY = pt[1] - Math.min(near, 3) * 15;

      const lay = c.L.fx || (c.L.fx = el('g', {}, svg));
      const e = el('text', { x: pt[0], y: baseY, class: 'badge ' + cls, 'text-anchor': 'middle' }, lay);
      e.textContent = text;
      /* อายุของป้ายเดินด้วยเวลาจำลอง เหมือนทุกอย่างในฉาก */
      c._floats.push({ el: e, y: baseY, age: 0 });
      return e;
    },
    refreshControls() { renderControls(lesson.steps[stepIdx].controls); }
  };
  return c;
}

function place(p) {
  let d = Math.max(0, p.d), i = 0;
  while (i < p.segs.length - 1 && d > p.segs[i]) { d -= p.segs[i]; i++; }
  const a = p.path[i], b = p.path[i + 1] || p.path[i], t = p.segs[i] ? Math.min(1, d / p.segs[i]) : 0;
  const x = a[0] + (b[0] - a[0]) * t, y = a[1] + (b[1] - a[1]) * t;
  if (p.tile) p.el.setAttribute('transform', `translate(${x.toFixed(1)},${y.toFixed(1)})`);
  else { p.el.setAttribute('cx', x.toFixed(1)); p.el.setAttribute('cy', y.toFixed(1)); }
}

function driveFloats(dt) {
  const keep = [];
  for (const f of ctx._floats) {
    f.age += dt;
    const k = f.age / 750;
    if (k >= 1) { f.el.remove(); continue; }
    f.el.setAttribute('y', (f.y - k * 26).toFixed(1));
    f.el.setAttribute('opacity', (1 - k).toFixed(2));
    keep.push(f);
  }
  ctx._floats = keep;
}

function drivePackets(dt) {
  const keep = [];
  for (const p of ctx.packets) {
    if (p.delay > 0) { p.delay -= dt; keep.push(p); continue; }
    p.d += p.speed * dt / 1000;
    if (p.d >= p.len) {
      p.el.remove();
      if (p.onDone) p.onDone(ctx, p);
      if (lesson.arrive) lesson.arrive(ctx, p);
      continue;
    }
    place(p);
    keep.push(p);
  }
  ctx.packets = keep;
}

/* ---------- scene lifecycle ---------- */
function resetSim(keepCfg) {
  const cfg = keepCfg ? ctx.cfg : Object.assign({}, lesson.steps[stepIdx].cfg);
  svg.textContent = '';
  ctx = makeCtx();
  ctx.cfg = cfg;
  ctx.step = lesson.steps[stepIdx];
  ctx.stepIdx = stepIdx;
  ctx.layer('wires'); ctx.layer('ents'); ctx.layer('fx'); ctx.layer('pk'); ctx.layer('labels'); ctx.layer('hud');
  if (lesson.init) lesson.init(ctx);
  lesson.build(ctx);
  if (lesson.render) lesson.render(ctx);
  renderMetrics();
}

function renderMetrics() {
  const box = $('metrics');
  const defs = lesson.metrics || [];
  if (box.childElementCount !== defs.length) {
    box.textContent = '';
    defs.forEach(m => {
      const d = document.createElement('div');
      d.className = 'metric';
      d.innerHTML = `<span>${m.label}</span><b>0</b>`;
      box.appendChild(d);
    });
  }
  defs.forEach((m, i) => {
    const d = box.children[i], b = d.querySelector('b');
    const v = m.fmt ? m.fmt(ctx) : String(ctx.stats[m.key] || 0);
    if (b.textContent !== v) b.textContent = v;
    const tone = m.tone ? m.tone(ctx) : '';
    const cls = 'metric' + (m.bad ? ' bad' : '') + (tone ? ' ' + tone : '');
    if (d.className !== cls) d.className = cls;
  });
}

function renderLegend() {
  $('legend').innerHTML = (lesson.legend || []).map(([cls, text]) => `<span><i class="ld ${cls}"></i>${text}</span>`).join('');
}

/* ---------- controls ---------- */
function renderControls(list) {
  const box = $('controls'); box.textContent = '';
  (list || []).forEach(key => {
    const def = (lesson.controls || {})[key];
    if (!def) return;
    const after = () => {
      if (def.reset) resetSim(true); else if (lesson.render) lesson.render(ctx);
      if (def.refresh) renderControls(list);
      renderMetrics();
    };
    if (def.type === 'toggle') {
      const l = document.createElement('label');
      l.className = 'switch';
      l.innerHTML = `<input type="checkbox"><span>${def.label}<small>${def.hint || ''}</small></span>`;
      const inp = l.querySelector('input');
      inp.checked = !!def.get(ctx.cfg, ctx);
      inp.addEventListener('change', e => { def.set(ctx.cfg, e.target.checked, ctx); after(); });
      box.appendChild(l);
    } else if (def.type === 'seg') {
      const w = document.createElement('div');
      w.innerHTML = `<span class="ctl-label">${def.label}</span><div class="seg" role="group" aria-label="${def.label}"></div>`;
      const row = w.querySelector('.seg');
      const cur = def.get(ctx.cfg, ctx);
      (typeof def.options === 'function' ? def.options(ctx) : def.options).forEach(([val, text]) => {
        const b = document.createElement('button');
        b.type = 'button'; b.textContent = text;
        b.setAttribute('aria-pressed', String(val === cur));
        b.addEventListener('click', () => {
          row.querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', 'false'));
          b.setAttribute('aria-pressed', 'true');
          def.set(ctx.cfg, val, ctx); after();
        });
        row.appendChild(b);
      });
      box.appendChild(w);
    } else if (def.type === 'range') {
      const w = document.createElement('div');
      const v = def.get(ctx.cfg, ctx);
      w.innerHTML = `<label class="ctl-label">${def.label(v, ctx)}</label><input type="range" min="${def.min}" max="${def.max}" step="${def.step || 1}" value="${v}">`;
      const inp = w.querySelector('input'), lab = w.querySelector('label');
      inp.addEventListener('input', e => {
        def.set(ctx.cfg, +e.target.value, ctx);
        lab.textContent = def.label(+e.target.value, ctx);
        if (!def.reset && lesson.render) lesson.render(ctx);
        renderMetrics();
      });
      if (def.reset) inp.addEventListener('change', () => resetSim(true));
      box.appendChild(w);
    } else if (def.type === 'text') {
      const w = document.createElement('div');
      w.className = 'ctl-text';
      w.innerHTML = `<span class="ctl-label">${def.label}</span><input type="text" value="${String(def.get(ctx.cfg, ctx)).replace(/"/g, '&quot;')}" placeholder="${def.placeholder || ''}">` +
        (def.hint ? `<span class="hint">${def.hint}</span>` : '') +
        (def.presets ? `<div class="presets">${def.presets.map((p, i) => `<button type="button" data-i="${i}">${p[0]}</button>`).join('')}</div>` : '');
      const inp = w.querySelector('input');
      inp.addEventListener('input', e => { def.set(ctx.cfg, e.target.value, ctx); if (lesson.render) lesson.render(ctx); renderMetrics(); });
      w.querySelectorAll('.presets button').forEach(b => b.addEventListener('click', () => {
        const v = def.presets[+b.dataset.i][1];
        inp.value = v; def.set(ctx.cfg, v, ctx); if (lesson.render) lesson.render(ctx); renderMetrics();
      }));
      box.appendChild(w);
    } else if (def.type === 'buttons') {
      const w = document.createElement('div');
      w.innerHTML = `<span class="ctl-label">${def.label}</span><div class="seg" role="group" aria-label="${def.label}"></div>`;
      const row = w.querySelector('.seg');
      def.items(ctx).forEach(it => {
        const b = document.createElement('button');
        b.type = 'button'; b.textContent = it.text;
        if (it.on) b.className = 'off';
        b.setAttribute('aria-pressed', String(!!it.on));
        b.addEventListener('click', () => { it.click(ctx); renderControls(list); if (lesson.render) lesson.render(ctx); });
        row.appendChild(b);
      });
      box.appendChild(w);
    }
  });
}

/* ---------- step panel ---------- */
const NOTE_ICON = '<svg viewBox="0 0 16 16" fill="none" stroke="#24521c" stroke-width="1.5" stroke-linecap="round"><path d="M8 2.5a4 4 0 0 0-2.4 7.2c.5.4.7.9.7 1.5h3.4c0-.6.2-1.1.7-1.5A4 4 0 0 0 8 2.5zM6.5 13.5h3"/></svg>';

function goStep(i, noStore) {
  const n = lesson.steps.length;
  stepIdx = Math.max(0, Math.min(n - 1, i));
  const st = lesson.steps[stepIdx];
  $('stepNo').textContent = `Step ${stepIdx + 1} of ${n}`;
  const tag = $('stepTag'); tag.className = 'tag ' + st.tag; tag.textContent = TAGS[st.tag] || st.tag;
  $('stepTitle').textContent = st.title;
  $('stepBody').innerHTML = st.body.map(t => `<p>${t}</p>`).join('') +
    (st.note ? `<div class="note">${NOTE_ICON}<div><b>${st.note[0]}</b>${st.note[1]}</div></div>` : '') +
    ((st.changed && st.changed.length) ? `<div class="changed"><h3>What changed</h3><ul>${st.changed.map(c => `<li>${c}</li>`).join('')}</ul></div>` : '');
  svg.setAttribute('aria-label', 'Simulation: ' + st.title);
  resetSim(false);
  renderControls(st.controls);
  $('prev').disabled = stepIdx === 0;
  $('nextTxt').textContent = stepIdx === n - 1 ? 'Restart this lesson' : 'Next: ' + lesson.steps[stepIdx + 1].label;
  $('tlCount').textContent = `Step ${stepIdx + 1} of ${n}`;
  document.querySelectorAll('#tl button').forEach((b, k) => {
    if (k === stepIdx) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current');
    b.classList.toggle('done', k < stepIdx);
  });
  $('learn').innerHTML = (lesson.learn || []).map(([t, at]) =>
    `<li class="${stepIdx >= at ? 'ok' : ''}"><i>${stepIdx >= at ? '✓' : ''}</i>${t}</li>`).join('');
  $('progTxt').textContent = `${stepIdx + 1} / ${n}`;
  $('progBar').style.width = ((stepIdx + 1) / n * 100) + '%';
  if (!noStore) {
    store('step:' + lesson.id, stepIdx);
    if (stepIdx === n - 1) { store('done:' + lesson.id, '1'); renderTree(); renderDoneChip(); }
  }
}

function buildTimeline() {
  const tl = $('tl'); tl.textContent = '';
  tl.style.gridTemplateColumns = `repeat(${lesson.steps.length},1fr)`;
  lesson.steps.forEach((s, k) => {
    const li = document.createElement('li');
    li.innerHTML = `<button type="button" aria-label="Step ${k + 1}: ${s.title}"><i>${k + 1}</i>${s.label}</button>`;
    li.firstChild.addEventListener('click', () => goStep(k));
    tl.appendChild(li);
  });
}

/* ---------- lesson loading ---------- */
function openLesson(id, stepOverride) {
  const def = lessons[id];
  if (!def) { openLesson(order[0]); return; }
  lesson = def;
  svg.setAttribute('viewBox', def.view || '120 70 600 420');
  const mod = CATALOG.find(m => m.ids.includes(id)) || CATALOG[0];
  const pos = mod.ids.indexOf(id) + 1;
  $('crumb').textContent = `${mod.num}. ${mod.name}  /  Lesson ${pos} of ${mod.ids.length}`;
  $('lessonTitle').textContent = def.title;
  $('lessonSub').textContent = def.sub;
  $('lessonChips').innerHTML = [
    ['o', `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="6"/><path d="M8 4.5V8l2.5 1.5"/></svg>${def.minutes} min`],
    ['g', `<svg viewBox="0 0 16 16" fill="currentColor"><rect x="2" y="10" width="2" height="4"/><rect x="6" y="7" width="2" height="7"/><rect x="10" y="4" width="2" height="10" opacity=".35"/></svg>${def.level}`],
    ['v', `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M5 4h9M5 8h9M5 12h9"/><circle cx="2" cy="4" r=".8" fill="currentColor"/><circle cx="2" cy="8" r=".8" fill="currentColor"/><circle cx="2" cy="12" r=".8" fill="currentColor"/></svg>${def.steps.length} steps`]
  ].map(([c, h]) => `<span class="chip ${c}">${h}</span>`).join('');
  buildTimeline();
  renderLegend();
  $('metrics').textContent = '';
  const saved = stepOverride != null ? stepOverride : +(store('step:' + id) || 0);
  goStep(saved, stepOverride == null);
  renderTree();
  if (location.hash !== '#/' + id) history.replaceState(null, '', '#/' + id);
}

function renderTree() {
  const tree = $('tree');
  const cur = lesson ? lesson.id : null;
  const open = CATALOG.find(m => m.ids.includes(cur)) || CATALOG[0];
  tree.textContent = '';
  let built = 0, total = 0;
  CATALOG.forEach(m => {
    const li = document.createElement('li');
    const ready = m.ids.filter(id => lessons[id]);
    const done = m.ids.filter(id => store('done:' + id) === '1').length;
    built += ready.length; total += m.ids.length;
    const isOpen = m === open;
    li.innerHTML = `<button class="mod" type="button" aria-expanded="${isOpen}">
      <span class="caret">${isOpen ? '▾' : '▸'}</span>
      <span class="folder" style="background:${m.color}"></span>${m.num}. ${m.name}
      <span class="n">${done}/${m.ids.length}</span></button>`;
    const btn = li.firstElementChild;
    btn.addEventListener('click', () => {
      const first = m.ids.find(id => lessons[id]);
      if (first) openLesson(first); else { li.querySelector('.lessons')?.toggleAttribute('hidden'); }
    });
    if (isOpen) {
      const ul = document.createElement('ul');
      ul.className = 'lessons';
      m.ids.forEach(id => {
        const d = lessons[id];
        const li2 = document.createElement('li');
        const b = document.createElement('button');
        b.type = 'button';
        if (d) {
          b.innerHTML = `<span>${d.title}</span>` + (store('done:' + id) === '1' ? `<span class="tick">✓</span>` : '');
          if (id === cur) b.setAttribute('aria-current', 'page');
          b.addEventListener('click', () => openLesson(id));
        } else {
          b.disabled = true;
          b.innerHTML = `<span>${SOON[id] || id}</span><small>soon</small>`;
        }
        li2.appendChild(b); ul.appendChild(li2);
      });
      li.appendChild(ul);
    }
    tree.appendChild(li);
  });
  $('sideCount').textContent = `${CATALOG.length} modules · ${built}/${total} lessons`;
}

function renderDoneChip() {
  const n = Object.keys(lessons).filter(id => store('done:' + id) === '1').length;
  $('doneChip').textContent = `${n} lessons done`;
}

/* ---------- main loop ---------- */
function advance(dt) {
  if (!lesson || !ctx) return;
  sim.t += dt;
  try {
    if (lesson.tick) lesson.tick(ctx, dt);
    drivePackets(dt);
    driveFloats(dt);
    if (lesson.render) lesson.render(ctx);
    renderMetrics();
  } catch (e) {
    /* อย่าให้เฟรมเดียวที่พังทำให้ลูปตายทั้งหน้า */
    console.error('[ICS] frame error in lesson "' + lesson.id + '"', e);
  }
}

let last = performance.now();
function frame(now) {
  const dt = Math.min(50, now - last); last = now;
  if (!sim.paused && !document.hidden) advance(dt * speed);
  requestAnimationFrame(frame);
}

/* ---------- wiring ---------- */
const PAUSE_SVG = '<svg viewBox="0 0 16 16" fill="currentColor"><rect x="4" y="3" width="2.6" height="10" rx=".6"/><rect x="9.4" y="3" width="2.6" height="10" rx=".6"/></svg>Pause';
const PLAY_SVG = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M4.5 3v10l8.5-5z"/></svg>Play';

function start() {
  svg = $('scene');
  ctx = makeCtx();
  renderDoneChip();

  $('prev').addEventListener('click', () => goStep(stepIdx - 1));
  $('next').addEventListener('click', () => goStep(stepIdx === lesson.steps.length - 1 ? 0 : stepIdx + 1));
  $('replay').addEventListener('click', () => resetSim(true));

  const pb = $('pause');
  const syncPause = () => { pb.innerHTML = sim.paused ? PLAY_SVG : PAUSE_SVG; };
  pb.addEventListener('click', () => { sim.paused = !sim.paused; syncPause(); });
  syncPause();

  const SPEEDS = [1, 2, 0.5];
  let si = 0;
  $('speed').addEventListener('click', () => { si = (si + 1) % SPEEDS.length; speed = SPEEDS[si]; $('speed').textContent = speed + '×'; });

  document.addEventListener('keydown', e => {
    if (e.target.closest('input, button, [role=button], [role=dialog]')) return;
    if (e.key === 'ArrowRight') goStep(stepIdx + 1);
    if (e.key === 'ArrowLeft') goStep(stepIdx - 1);
    if (e.key === ' ') { e.preventDefault(); sim.paused = !sim.paused; syncPause(); }
  });

  /* glossary sheet */
  const gl = $('glossary');
  $('glossList').innerHTML = GLOSSARY.map(([t, d]) => `<dt>${t}</dt><dd>${d}</dd>`).join('');
  const closeGl = () => gl.hidden = true;
  $('glossaryBtn').addEventListener('click', () => gl.hidden = false);
  $('glossaryClose').addEventListener('click', closeGl);
  $('glossaryBack').addEventListener('click', closeGl);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeGl(); });

  window.addEventListener('hashchange', () => {
    const id = location.hash.replace('#/', '');
    if (id && lessons[id] && (!lesson || id !== lesson.id)) openLesson(id);
  });

  const startId = location.hash.replace('#/', '');
  openLesson(lessons[startId] ? startId : order[0]);

  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => resetSim(true));
  requestAnimationFrame(frame);
}

return {
  register, start, iso, el, line, rpath, block, pill, panel, statusList, actor, glyph, keyIcon, PAL, pts, U, dist,
  /* test seam: เดินการจำลองเองโดยไม่พึ่ง requestAnimationFrame */
  step(ms, times) { for (let i = 0; i < (times || 1); i++) advance(ms); },
  go(i) { goStep(i); },
  open(id) { openLesson(id); },
  state() { return { lesson: lesson && lesson.id, stepIdx, stats: ctx && ctx.stats, cfg: ctx && ctx.cfg, packets: ctx && ctx.packets.length }; }
};
})();
