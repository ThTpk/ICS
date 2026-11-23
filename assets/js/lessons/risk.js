/* ============================================================
   Lesson 11 — IT Risk Management
   อ้างอิงสไลด์ "10 ITRiskManagement" ของรายวิชา 01076042
   แกน: Risk Map 5×5 · ระดับความเสี่ยง = A × B · 4 กลยุทธ์ตอบสนอง
   ============================================================ */
(function () {
/* ---- ตาราง 5×5 ---- */
const CELL = 44, GX = 176, GY = 118;
const cx = b => GX + (b - 0.5) * CELL;              /* ความรุนแรง 1..5 ไปทางขวา */
const cy = a => GY + (5 - a + 0.5) * CELL;          /* โอกาส 5 อยู่บน 1 อยู่ล่าง */

/* ทะเบียนความเสี่ยง จัดวางตามตัวอย่างใน Risk Map ของสไลด์ */
const RISKS = [
  { id: 1, name: 'Server hardware fails', type: 'Technical', a: 3, b: 3,
    factor: 'Disks and PSUs wear out', hit: 'All services on that host',
    fix: { avoid: 'Move it to managed cloud', transfer: '4-hour replacement contract',
           reduce: 'Redundant disks, spare host', accept: 'Rebuild from backup if it fails' }, cost: 2 },
  { id: 2, name: 'Admin misconfiguration', type: 'Operator', a: 3, b: 2,
    factor: 'Manual changes in production', hit: 'Whichever service was touched',
    fix: { avoid: 'Remove direct prod access', transfer: 'Outsource operations',
           reduce: 'Change review and rollback', accept: 'Fix forward when it is noticed' }, cost: 2 },
  { id: 3, name: 'Ransomware', type: 'Technical', a: 4, b: 5,
    factor: 'Phishing and unpatched endpoints', hit: 'Every file that account reaches',
    fix: { avoid: 'Not realistic, email is needed', transfer: 'Cyber insurance covers part',
           reduce: 'Offline backups, MFA, patching', accept: 'Pay and hope, not a plan' }, cost: 4 },
  { id: 4, name: 'Power outage', type: 'Disaster', a: 5, b: 3,
    factor: 'One utility feed, no generator', hit: 'The whole server room',
    fix: { avoid: 'Stop running a server room', transfer: 'Colocation with a power SLA',
           reduce: 'UPS, generator, fuel contract', accept: 'Accept short outages' }, cost: 3 },
  { id: 5, name: 'Key staff leaves', type: 'Management', a: 5, b: 4,
    factor: 'One person holds the knowledge', hit: 'Every change and every incident',
    fix: { avoid: 'Cannot be avoided', transfer: 'Vendor support contract',
           reduce: 'Document and cross-train', accept: 'Carry the key-person risk' }, cost: 2 },
  { id: 6, name: 'Flood in the building', type: 'Disaster', a: 2, b: 5,
    factor: 'Server room on the ground floor', hit: 'Hardware and on-site storage',
    fix: { avoid: 'Move the room to an upper floor', transfer: 'Property insurance',
           reduce: 'Raised floor, water sensors', accept: 'Rare enough to live with' }, cost: 3 },
  { id: 7, name: 'Internet link fails', type: 'Technical', a: 1, b: 2,
    factor: 'One provider, one physical route', hit: 'External users only',
    fix: { avoid: 'Not possible online', transfer: 'SLA with service credits',
           reduce: 'Second provider, other route', accept: 'Already inside tolerance' }, cost: 1 }
];

const STRATS = {
  none:     { name: 'Not treated yet', short: 'none' },
  avoid:    { name: 'Avoid — stop the activity so the risk cannot occur', short: 'avoid' },
  transfer: { name: 'Transfer — move the loss to somebody else', short: 'transfer' },
  reduce:   { name: 'Reduce — lower the likelihood or the severity', short: 'reduce' },
  accept:   { name: 'Accept — keep it, but keep watching it', short: 'accept' }
};

/* ผลของกลยุทธ์ต่อ A และ B */
function treated(r, strat) {
  if (strat === 'avoid') return { a: 0, b: 0, gone: true, cost: r.cost + 2 };
  if (strat === 'transfer') return { a: r.a, b: Math.max(1, r.b - 2), cost: r.cost + 1 };
  if (strat === 'reduce') return { a: Math.max(1, r.a - 2), b: Math.max(1, r.b - 1), cost: r.cost };
  return { a: r.a, b: r.b, cost: 0 };
}
/* กลยุทธ์ใช้กับความเสี่ยงที่เกินเกณฑ์เท่านั้น ที่ผ่านเกณฑ์อยู่แล้วปล่อยไว้ */
function stateOf(cfg, r) {
  const inherent = r.a * r.b;
  if (cfg.strategy === 'none' || inherent <= cfg.tol) return { a: r.a, b: r.b, cost: 0, strat: 'none' };
  const t = treated(r, cfg.strategy);
  return { a: t.a, b: t.b, gone: t.gone, cost: t.cost, strat: cfg.strategy };
}
const score = s => s.gone ? 0 : s.a * s.b;
const band = v => v <= 9 ? '#e8efd9' : v <= 14 ? '#f6e6c9' : v <= 19 ? '#fcdcbd' : '#f8d5cf';

ICS.register({
  id: 'risk',
  title: 'IT Risk Management',
  sub: 'A problem has already happened. A risk might. Put a number on it, put it on a map, and then decide which of four things to do about it.',
  minutes: 14,
  level: 'Intermediate',

  legend: [
    ['res', 'Within tolerance'],
    ['bad', 'Above tolerance'],
    ['hollow', 'Where it moves after treatment'],
    ['req sq', 'Risk being reviewed']
  ],

  metrics: [
    { key: 'n', label: 'Risks on the register', fmt: () => String(RISKS.length) },
    { key: 'over', label: 'Above tolerance', bad: true,
      fmt: c => String(RISKS.filter(r => score(stateOf(c.cfg, r)) > c.cfg.tol).length),
      tone: c => RISKS.filter(r => score(stateOf(c.cfg, r)) > c.cfg.tol).length === 0 ? 'lit' : 'warn' },
    { key: 'total', label: 'Total risk score', fmt: c => String(RISKS.reduce((s, r) => s + score(stateOf(c.cfg, r)), 0)) },
    { key: 'worst', label: 'Worst remaining', fmt: c => String(Math.max.apply(null, RISKS.map(r => score(stateOf(c.cfg, r))))) },
    { key: 'budget', label: 'Budget used', fmt: c => RISKS.reduce((s, r) => s + stateOf(c.cfg, r).cost, 0) + ' units' }
  ],

  learn: [
    ['A risk might happen, a problem already has', 0],
    ['Likelihood and severity are each rated one to five', 1],
    ['Risk level is A × B, and the business sets the acceptable line', 2],
    ['Avoid, transfer, reduce and accept move a risk differently', 3],
    ['What is left afterwards is residual risk, and it is monitored', 5]
  ],

  steps: [
    {
      tag: 'concept', label: 'Risk vs problem', title: 'A risk is not a problem',
      body: [
        'A problem has already happened and you are dealing with it. A <code>risk</code> is something that has not happened yet but would hurt if it did. The two need completely different work: one needs a fix, the other needs a decision.',
        'Seven risks are on the register, cycling one at a time. Each one records what kind it is, what makes it likely, and who gets hurt. The slides group them as technical, operator, disaster and management, and the mix matters — a register full of only technical risks means nobody asked the other questions.'
      ],
      note: ['Where risks come from', 'Start from the target and the key success factors. A risk is anything that stands between them. That is why the register belongs to the business owner and not to the system administrator.'],
      changed: ['Register: 7 risks', 'Not assessed yet'],
      cfg: { show: { map: false, tol: false }, strategy: 'none', tol: 9 }
    },
    {
      tag: 'concept', label: 'Assessment', title: 'Rate likelihood and severity, one to five',
      body: [
        'Each risk gets two numbers. <code>A</code> is how likely it is, from 1 for very rare to 5 for very frequent. <code>B</code> is how bad it would be, from 1 for barely noticeable to 5 for severe. Both scales have to be written down and agreed, or two people will score the same risk differently.',
        'Plot them and the register becomes a map. Likelihood runs up the side, severity runs along the bottom. Now the risks can be compared with each other instead of argued about one at a time.'
      ],
      note: ['Scenario analysis', 'Severity is the harder number. Describing a concrete scenario — what exactly breaks, for how long, affecting whom — gets a far more consistent rating than asking people for a score in the abstract.'],
      changed: ['Showing the 5×5 risk map'],
      cfg: { show: { map: true, tol: false }, strategy: 'none', tol: 9 }
    },
    {
      tag: 'concept', label: 'A × B', title: 'Risk level is A × B, and the line is a decision',
      body: [
        'Multiply the two numbers and you get the risk level. The map is shaded by that product, so the top right corner is where the serious ones live. The slides use <code>A × B ≤ 9</code> as the acceptable threshold.',
        'That number is not a law of nature, it is a decision the organisation makes about its own appetite. Four risks sit above it here, and those four are the ones that need a response. The other three are already acceptable, and spending money on them would be waste.'
      ],
      note: ['Why multiply', 'It keeps rare-but-catastrophic and frequent-but-trivial in view at the same time. A flood scores 2 × 5 = 10 and a link failure scores 1 × 2 = 2, which is the ordering anybody would want.'],
      changed: ['Acceptance threshold A × B ≤ 9'],
      cfg: { show: { map: true, tol: true }, strategy: 'none', tol: 9 }
    },
    {
      tag: 'technique', label: 'Four responses', title: 'Avoid, transfer, reduce, accept',
      body: [
        'There are only four things you can do. <code>Avoid</code> stops the activity so the risk cannot arise. <code>Transfer</code> moves the loss to somebody else, usually insurance or a contract. <code>Reduce</code> lowers the likelihood or the severity. <code>Accept</code> keeps the risk deliberately and watches it.',
        'Switch between them below and watch where the dots go. Each one moves a risk in a different direction on the map, which is the clearest way to see that they are not interchangeable. Only risks above the line are treated; the acceptable ones are left where they are.'
      ],
      note: ['Transfer does not remove the risk', 'Insurance pays for some of the loss. It does not stop the outage, it does not restore your data, and it does not repair the reputation. The likelihood is untouched, which is exactly what the map shows.'],
      changed: ['Treating every risk above the line'],
      cfg: { show: { map: true, tol: true }, strategy: 'reduce', tol: 9 },
      controls: ['strategy']
    },
    {
      tag: 'technique', label: 'Action plan', title: 'Every response costs something',
      body: [
        'A response is not a decision, it is a plan: the activity, what it should achieve, the budget, who owns it, and by when. The budget line in the readout totals what the chosen strategy costs across every treated risk.',
        'Compare the strategies on cost as well as effect. Avoiding is thorough and expensive, and it usually means giving up something the business wanted. Accepting is free and sometimes right. The cheapest strategy that gets everything under the line is the correct answer, not the most thorough one.'
      ],
      note: ['The fields that get skipped', 'Owner and deadline are the two that get left blank, and they are the two that decide whether anything actually happens. A risk response with no name against it is a wish.'],
      changed: ['Showing cost per strategy'],
      cfg: { show: { map: true, tol: true }, strategy: 'transfer', tol: 9 },
      controls: ['strategy']
    },
    {
      tag: 'concept', label: 'Residual risk', title: 'What is left afterwards still has a number',
      body: [
        'Treatment moves a risk, it rarely deletes it. Whatever remains is <code>residual risk</code>, and it goes back on the register with its new score. The closing question in the slides is exactly this: after the activity, what should the risk look like?',
        'The honest answer is a smaller number, still written down, still owned, and reviewed on a schedule. A risk that was reduced in 2022 and never looked at again is not managed, it is forgotten — and the conditions that set its score have almost certainly changed.'
      ],
      note: ['Monitoring closes the loop', 'The last two COSO steps are communication and monitoring, and they are the ones that get dropped. Without them the register becomes a document that was true once.'],
      changed: ['Residual scores after treatment'],
      cfg: { show: { map: true, tol: true }, strategy: 'reduce', tol: 9 }
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: get everything under the line',
      body: [
        'Move the tolerance to what you think your own organisation would accept, then find the cheapest strategy that leaves nothing above it. Watch what happens to the count when the tolerance is tightened to 4 — risks that were comfortably fine become work.',
        'Then look at risk 5, the one about key staff. It cannot be avoided and it cannot really be insured. Some risks only respond to one of the four strategies, and recognising which is most of the skill.'
      ],
      note: ['The workshop this comes from', 'The assignment asks for five risks of your own with likelihood and severity tables you define, plotted on this map, each with a strategy and an action plan. This is that exercise with the register already filled in.'],
      changed: [],
      cfg: { show: { map: true, tol: true }, strategy: 'none', tol: 9 },
      controls: ['strategy', 'tol']
    }
  ],

  controls: {
    strategy: {
      type: 'seg', label: 'Response applied to every risk above the line',
      options: [['none', 'None'], ['reduce', 'Reduce'], ['transfer', 'Transfer'], ['avoid', 'Avoid'], ['accept', 'Accept']],
      get: c => c.strategy, set: (c, v) => { c.strategy = v; }
    },
    tol: {
      type: 'range', min: 4, max: 20, step: 1, get: c => c.tol, set: (c, v) => { c.tol = v; },
      label: v => `Acceptable risk level: <output>A × B ≤ ${v}</output>`
    }
  },

  /* ---------------- scene ---------------- */
  init(ctx) { ctx.S = { cur: 0 }; },

  build(ctx) {
    const S = ctx.S, L = ctx.L;
    const G = ctx.el('g', {}, L.hud);
    S.mapG = G;

    /* ช่องตาราง */
    S.cells = [];
    for (let a = 1; a <= 5; a++) for (let b = 1; b <= 5; b++) {
      const r = ctx.el('rect', {
        class: 'rm-cell', x: GX + (b - 1) * CELL, y: GY + (5 - a) * CELL,
        width: CELL, height: CELL, fill: band(a * b)
      }, G);
      const t = ctx.el('text', { class: 'rm-ax', x: GX + (b - 1) * CELL + 4, y: GY + (5 - a) * CELL + 12 }, G);
      t.textContent = a * b;
      S.cells.push({ a, b, r, t });
    }
    /* แกน */
    for (let b = 1; b <= 5; b++) {
      const t = ctx.el('text', { class: 'rm-ax', x: cx(b), y: GY + 5 * CELL + 14, 'text-anchor': 'middle' }, G);
      t.textContent = b;
    }
    for (let a = 1; a <= 5; a++) {
      const t = ctx.el('text', { class: 'rm-ax', x: GX - 8, y: cy(a) + 4, 'text-anchor': 'end' }, G);
      t.textContent = a;
    }
    const xs = ctx.el('text', { class: 'rm-ax', x: GX + 2.5 * CELL, y: GY + 5 * CELL + 30, 'text-anchor': 'middle' }, G);
    xs.textContent = 'SEVERITY  B  →';
    const ys = ctx.el('text', { class: 'rm-ax', x: GX, y: GY - 10 }, G);
    ys.textContent = 'LIKELIHOOD A ↑';

    /* จุดความเสี่ยง */
    S.dots = RISKS.map(r => {
      const g = ctx.el('g', {}, G);
      const c = ctx.el('circle', { class: 'risk-dot', cx: cx(r.b), cy: cy(r.a), r: 13, fill: '#fbf7f1', stroke: '#1d1b18', 'stroke-width': 1.4 }, g);
      const t = ctx.el('text', { class: 'risk-num', x: cx(r.b), y: cy(r.a) + 4, 'text-anchor': 'middle' }, g);
      t.textContent = r.id;
      return { g, c, t, r };
    });

    S.regP = ctx.panel(L.hud, { x: 420, y: 92, w: 296, rows: 9, lh: 16, title: 'Risk register' });
    S.detP = ctx.panel(L.hud, { x: 420, y: 288, w: 296, rows: 5, lh: 16, title: 'Risk under review' });
    S.sumP = ctx.panel(L.hud, { x: 140, y: 404, w: 576, rows: 2, title: 'Where this leaves us' });
  },

  tick(ctx, dt) {
    const S = ctx.S;
    if (ctx.timer('cycle', dt, 2600)) S.cur = (S.cur + 1) % RISKS.length;
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S, sh = cfg.show;

    S.mapG.setAttribute('display', sh.map ? 'inline' : 'none');

    /* เน้นช่องที่ยังอยู่ในเกณฑ์ */
    S.cells.forEach(c => {
      const v = c.a * c.b;
      const inTol = v <= cfg.tol;
      c.r.setAttribute('fill', sh.tol ? (inTol ? '#e8efd9' : band(v)) : '#f6eee3');
      c.r.setAttribute('stroke-width', sh.tol && inTol ? 1.6 : 0.8);
      c.r.setAttribute('stroke', sh.tol && inTol ? '#7fc278' : '#c6bbac');
      c.t.setAttribute('display', sh.tol ? 'inline' : 'none');
    });

    /* ตำแหน่งจุด เลื่อนตามผลของกลยุทธ์ */
    const used = {};
    S.dots.forEach(d => {
      const st = stateOf(cfg, d.r);
      if (st.gone) { d.g.setAttribute('display', 'none'); return; }
      d.g.setAttribute('display', 'inline');
      const key = st.a + ',' + st.b;
      const n = used[key] = (used[key] || 0) + 1;
      const off = (n - 1) * 13;
      const px = cx(st.b) - off * 0.5, py = cy(st.a) - off * 0.5;
      d.c.setAttribute('cx', px); d.c.setAttribute('cy', py);
      d.t.setAttribute('x', px); d.t.setAttribute('y', py + 4);
      const over = score(st) > cfg.tol;
      d.c.setAttribute('fill', !sh.tol ? '#fbf7f1' : over ? '#e5534b' : '#b2d491');
      d.c.setAttribute('stroke-width', d.r.id === RISKS[S.cur].id ? 3 : 1.4);
      d.t.setAttribute('fill', sh.tol && over ? '#fff' : '#1d1b18');
    });

    /* ทะเบียนความเสี่ยง */
    const pad = (s, n) => (String(s) + '                        ').slice(0, n);
    S.regP.set(0, '#  ' + pad('RISK', 23) + pad('TYPE', 12) + (sh.map ? 'A×B' : ''), 'dim');
    RISKS.forEach((r, i) => {
      const st = stateOf(cfg, r);
      const v = score(st);
      const line = r.id + '  ' + pad(r.name, 23) + pad(r.type, 12) +
        (sh.map ? (st.gone ? 'gone' : st.a + '×' + st.b + '=' + v) : '');
      const cur = i === S.cur;
      S.regP.set(i + 1, line, sh.tol && v > cfg.tol ? 'bad mono' : cur ? 'ok mono' : 'mono');
    });

    /* รายละเอียดความเสี่ยงที่กำลังทบทวน */
    const r = RISKS[S.cur], st = stateOf(cfg, r);
    S.detP.set(0, '#' + r.id + '  ' + r.name, 'ok');
    S.detP.set(1, 'Factor: ' + r.factor, 'dim');
    S.detP.set(2, 'Affects: ' + r.hit, 'dim');
    if (st.strat === 'none') {
      S.detP.set(3, sh.tol && r.a * r.b > cfg.tol ? 'Above the line — needs a response' : 'Within tolerance — no action needed',
        sh.tol && r.a * r.b > cfg.tol ? 'bad' : 'ok');
      S.detP.set(4, '', '');
    } else {
      S.detP.set(3, STRATS[st.strat].short + ': ' + r.fix[st.strat], 'mono');
      S.detP.set(4, r.a * r.b + ' → ' + (st.gone ? 'removed' : score(st)) + '   cost ' + st.cost + ' units',
        score(st) <= cfg.tol ? 'ok' : 'bad');
    }

    const over = RISKS.filter(x => score(stateOf(cfg, x)) > cfg.tol).length;
    const budget = RISKS.reduce((s, x) => s + stateOf(cfg, x).cost, 0);
    S.sumP.set(0, STRATS[cfg.strategy].name, cfg.strategy === 'none' ? 'dim' : 'ok');
    S.sumP.set(1, !sh.tol ? 'Set a tolerance to see which risks need a response'
      : over === 0 ? 'Everything is within A × B ≤ ' + cfg.tol + ', for ' + budget + ' units of budget'
      : over + ' risk(s) still above A × B ≤ ' + cfg.tol + ', ' + budget + ' units spent so far',
      !sh.tol ? 'dim' : over === 0 ? 'ok' : 'bad');
  }
});
})();
