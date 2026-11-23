/* ============================================================
   Lesson 14 — Business Continuity Management
   อ้างอิงสไลด์ "13 BCM" ของรายวิชา 01076042
   แกน: ตัวชี้วัด 5 ตัวบนแกนเวลาเดียว RTO · MTTR · RPO · WRT · MTD
   ============================================================ */
(function () {
const PRIMARY = [-1.65, 3.32];
const DR = [0.91, 0.75];

/* แกนเวลา: ชั่วโมง → พิกัดจอ */
const DX = 330, PXH = 376 / 72, X0 = 190, X1 = 706;
const tx = h => Math.max(X0, Math.min(X1, DX + h * PXH));

/* ค่าประจำแต่ละระดับของไซต์สำรอง ตามสไลด์ 23-26 */
const SITES = {
  cold: { rto: 48, wrt: 12, mttr: 60, rpo: 24, cost: 1,
          desc: 'Space and facilities only. No computers, no data.' },
  warm: { rto: 24, wrt: 8, mttr: 20, rpo: 12, cost: 4,
          desc: 'Machines ready to assemble, but no data copied over.' },
  hot:  { rto: 4, wrt: 2, mttr: 3, rpo: 1, cost: 12,
          desc: 'Whole system and data duplicated from the primary site.' }
};
const SITE_NAME = { cold: 'Cold site', warm: 'Warm site', hot: 'Hot site' };

function plan(cfg) {
  const s = Object.assign({}, SITES[cfg.site]);
  if (cfg.site === 'hot' && cfg.sync) { s.rpo = 0; s.cost = 18; }
  return s;
}
function fmtH(h) {
  if (h === 0) return '0';
  if (h < 1) return Math.round(h * 60) + ' min';
  if (h < 48) return h + ' h';
  return (h / 24) + ' days';
}

/* แถบบนแกนเวลา */
function bar(ctx, parent, y, h, fill, label) {
  const g = ctx.el('g', {}, parent);
  const r = ctx.el('rect', { x: DX, y: y, width: 0, height: h, rx: 3, fill: fill, stroke: '#1d1b18', 'stroke-width': 1 }, g);
  const t = ctx.el('text', { class: 'tl-key', x: X0 - 8, y: y + h - 4, 'text-anchor': 'end' }, g);
  t.textContent = label;
  const v = ctx.el('text', { class: 'tl-val', x: DX, y: y + h - 4 }, g);
  return {
    g,
    key(text) { if (t.textContent !== text) t.textContent = text; },
    set(hFrom, hTo, text, show) {
      g.setAttribute('display', show ? 'inline' : 'none');
      if (!show) return;
      const a = tx(hFrom), b = tx(hTo), x0 = Math.min(a, b), w = Math.max(2, Math.abs(b - a));
      r.setAttribute('x', x0); r.setAttribute('width', w);
      /* ค่าวางไว้ข้างในแถบ ถ้าแถบแคบเกินก็ไม่ต้องแสดง แผงด้านขวาบอกตัวเลขอยู่แล้ว */
      const fits = w > (text || '').length * 6.4 + 12;
      v.setAttribute('display', fits ? 'inline' : 'none');
      v.setAttribute('x', x0 + 6);
      if (v.textContent !== text) v.textContent = text;
    }
  };
}

ICS.register({
  id: 'bcm',
  title: 'Business Continuity Management',
  sub: 'A system is allowed to be down. The business is not allowed to stop. Five measurements on one time axis decide whether those two statements can both be true.',
  minutes: 14,
  level: 'Intermediate',

  legend: [
    ['req sq', 'Transaction written'],
    ['res', 'Replicated to the DR site'],
    ['bad', 'Lost in the disaster'],
    ['hollow', 'Inside business tolerance']
  ],

  metrics: [
    { key: 'written', label: 'Transactions written' },
    { key: 'lost', label: 'Lost in the outage', bad: true, tone: c => (c.stats.lost || 0) > 0 ? 'warn' : 'lit' },
    { key: 'rtoMet', label: 'MTTR < RTO', fmt: c => { const s = plan(c.cfg); return s.mttr < s.rto ? 'met' : 'missed'; },
      tone: c => { const s = plan(c.cfg); return s.mttr < s.rto ? 'lit' : 'warn'; } },
    { key: 'mtdMet', label: 'Within business MTD', fmt: c => { const s = plan(c.cfg); return (s.mttr + s.wrt) <= c.cfg.mtd ? 'yes' : 'no'; },
      tone: c => { const s = plan(c.cfg); return (s.mttr + s.wrt) <= c.cfg.mtd ? 'lit' : 'warn'; } },
    { key: 'cost', label: 'Relative cost', fmt: c => plan(c.cfg).cost + '×' }
  ],

  learn: [
    ['Downtime is acceptable, business impact is not', 0],
    ['RTO is the target, MTTR is what actually happens', 1],
    ['RPO is how much data you agree to lose', 2],
    ['MTD = RTO + WRT, and the business sets MTD', 3],
    ['The site level and the replication mode set all five', 5]
  ],

  steps: [
    {
      tag: 'concept', label: 'Downtime', title: 'Downtime is allowed. Impact is not.',
      body: [
        'Business continuity management does not promise that nothing ever breaks. It promises that when something breaks, the business keeps running. The system is allowed to be down for a while; what matters is whether that while is short enough to not hurt.',
        'Watch the loop. Transactions are written at the primary site and copied to the recovery site, then a disaster takes the primary site out. Everything after that is measured, and the measurements have names the business can argue about.'
      ],
      note: ['Where the numbers come from', 'None of these five values is a technical decision. The business decides how long it can be down and how much data it can afford to lose. IT then picks technology that meets those numbers, or says honestly that it cannot.'],
      changed: ['Primary site and a cold recovery site', 'Disaster every few seconds'],
      cfg: { site: 'cold', sync: false, mtd: 72, show: { rto: false, rpo: false, mtd: false } }
    },
    {
      tag: 'concept', label: 'RTO & MTTR', title: 'RTO is the target. MTTR is the fact.',
      body: [
        '<code>RTO</code>, recovery time objective, is the time you are aiming for to get the infrastructure back. It is a target, agreed in advance, written in a plan.',
        '<code>MTTR</code>, mean time to recovery, is how long it actually takes on average. The two bars are drawn separately on purpose. Right now the cold site takes longer in practice than the plan allows, so the darker bar runs past the target and the plan is fiction.'
      ],
      note: ['Closing the gap', 'When MTTR is longer than RTO there are only three honest moves: better tools, a different design, or extra process. Writing a smaller number in the plan is not one of them.'],
      changed: ['Showing RTO and MTTR'],
      cfg: { site: 'cold', sync: false, mtd: 72, show: { rto: true, rpo: false, mtd: false } }
    },
    {
      tag: 'concept', label: 'RPO', title: 'RPO is how much data you agree to lose',
      body: [
        'Recovery is not a time machine. When the system comes back it comes back to the state of the last copy, not to the instant before the disaster. <code>RPO</code> is the distance between those two points, measured backwards from the disaster.',
        'The bar now extends to the left of the disaster line. Every transaction written inside it is gone, and the counter shows how many. A bigger RPO costs less and loses more, which is the whole trade.'
      ],
      note: ['RPO picks the technology', 'A daily tape gives an RPO of a day. Hourly snapshots give an hour. Synchronous replication gives zero, because the write is not confirmed until both sites have it. The number comes first, the product comes second.'],
      changed: ['Showing RPO'],
      cfg: { site: 'cold', sync: false, mtd: 72, show: { rto: true, rpo: true, mtd: false } }
    },
    {
      tag: 'concept', label: 'WRT & MTD', title: 'MTD = RTO + WRT',
      body: [
        'Getting the servers running is not the same as being open for business. <code>WRT</code>, work recovery time, is the part spent restoring data, testing, and checking that the processes actually work. RTO covers the infrastructure; WRT covers everything after it.',
        'Added together they give <code>MTD</code>, the maximum tolerable downtime — the longest the business can be out before real damage starts. The pale bar is the tolerance the business set. If the dark bars run past its end, the strategy does not meet the requirement, no matter how good it looks on its own.'
      ],
      note: ['The order of the conversation', 'MTD comes from the business and everything else is designed to fit inside it. Teams that start from the technology and derive MTD afterwards end up with a number nobody agreed to.'],
      changed: ['Showing WRT and the business MTD'],
      cfg: { site: 'cold', sync: false, mtd: 72, show: { rto: true, rpo: true, mtd: true } }
    },
    {
      tag: 'technique', label: 'Site level', title: 'Cold, warm and hot sites',
      body: [
        'A <code>cold site</code> is space and power with no computers and no data. A <code>warm site</code> has machines ready but no copy of the data, so somebody has to configure and restore before it can serve. A <code>hot site</code> duplicates the system and the data continuously.',
        'Switch between them below. Every bar moves at once, because the site level sets all of them together, and so does the cost. This is the answer to the question the slides ask: build it yourself or buy it, staffed or standby, online or waiting.'
      ],
      note: ['The bars shrink unevenly', 'Going from cold to hot shortens RTO dramatically but shortens WRT much less. Restoring the infrastructure can be automated; checking that the business process really works still takes people and time.'],
      changed: ['Recovery site level is now adjustable'],
      cfg: { site: 'warm', sync: false, mtd: 36, show: { rto: true, rpo: true, mtd: true } },
      controls: ['site']
    },
    {
      tag: 'technique', label: 'Replication', title: 'Synchronous replication takes RPO to zero',
      body: [
        'With <code>asynchronous</code> replication the primary site confirms a write immediately and sends it on afterwards, so there is always a small backlog in flight. Whatever is in that backlog when the disaster strikes is lost.',
        'With <code>synchronous</code> replication the write is not confirmed until both sites have stored it. Nothing is ever only in one place, so <code>RPO</code> becomes zero and the lost counter stops moving. The cost is that every write now waits for the far site, which is why distance between sites turns into latency for users.'
      ],
      note: ['Zero RPO is not zero risk', 'Synchronous replication copies corruption and deletions just as faithfully as good data. It protects against a site being lost, not against a mistake or ransomware. That is why continuity plans still keep point-in-time backups.'],
      changed: ['Hot site with replication mode'],
      cfg: { site: 'hot', sync: false, mtd: 12, show: { rto: true, rpo: true, mtd: true } },
      controls: ['site', 'sync']
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: meet the business requirement',
      body: [
        'Set the tolerance the business will accept, then find the cheapest strategy that fits inside it with <code>MTTR</code> still under <code>RTO</code>. Notice that there is usually more than one answer, and that the cheapest acceptable one is the right one.',
        'Then ask the closing question from the slides for a system you actually know: what are its RTO, MTTR, RPO, WRT and MTD today? Most systems have never had those numbers written down, which means nobody has ever agreed what failure is allowed to look like.'
      ],
      note: ['Test the plan or it is not a plan', 'A recovery site that has never been failed over to is an assumption, not a capability. The measured MTTR in this lesson is the one you get from a real drill, not the one in the document.'],
      changed: [],
      cfg: { site: 'warm', sync: false, mtd: 36, show: { rto: true, rpo: true, mtd: true } },
      controls: ['site', 'sync', 'mtd']
    }
  ],

  controls: {
    site: {
      type: 'seg', label: 'Recovery site level',
      options: [['cold', 'Cold'], ['warm', 'Warm'], ['hot', 'Hot']],
      get: c => c.site, set: (c, v) => { c.site = v; }
    },
    sync: { type: 'toggle', label: 'Synchronous replication', hint: 'Confirm the write only when both sites hold it', get: c => c.sync, set: (c, v) => { c.sync = v; } },
    mtd: {
      type: 'range', min: 4, max: 72, step: 4, get: c => c.mtd, set: (c, v) => { c.mtd = v; },
      label: v => `Business tolerance (MTD): <output>${fmtH(v)}</output>`
    }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      phase: 'run', t: 0, pending: 0, sweep: 0,
      P: { p: iso(PRIMARY[0] + 0.7, PRIMARY[1], 0.7), d: iso(DR[0] - 0.7, DR[1], 0.7) }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, L = ctx.L;

    S.repWire = ctx.line(iso(PRIMARY[0], PRIMARY[1], 0.25), iso(DR[0], DR[1], 0.25), 'wire', L.wires);

    const pg = ctx.el('g', { class: 'node' }, L.ents);
    S.prim = ctx.actor.server(pg, PRIMARY[0], PRIMARY[1], 'bone', 1.5);
    S.primG = pg;
    S.primPill = ctx.pill(L.labels, iso(PRIMARY[0], PRIMARY[1] + 1.1, 0)[0], iso(PRIMARY[0], PRIMARY[1] + 1.1, 0)[1] + 14, ['Primary site', '']);

    const dg = ctx.el('g', { class: 'node' }, L.ents);
    S.dr = ctx.actor.server(dg, DR[0], DR[1], 'green', 1.5);
    S.drG = dg;
    S.drPill = ctx.pill(L.labels, iso(DR[0], DR[1] + 1.1, 0)[0], iso(DR[0], DR[1] + 1.1, 0)[1] + 14, ['Recovery site', '']);

    /* ---- แกนเวลา ---- */
    const T = ctx.el('g', {}, L.hud);
    ctx.el('line', { x1: X0, y1: 292, x2: X1, y2: 292, stroke: '#c6bbac', 'stroke-width': 1.2 }, T);
    S.disasterLine = ctx.el('line', { x1: DX, y1: 240, x2: DX, y2: 372, stroke: '#e5534b', 'stroke-width': 2, 'stroke-dasharray': '4 3' }, T);
    const dl = ctx.el('text', { class: 'tl-key', x: DX, y: 234, 'text-anchor': 'middle', fill: '#e5534b' }, T);
    dl.textContent = 'DISASTER';

    S.bRpo = bar(ctx, T, 250, 15, '#f8d5cf', 'RPO');
    S.bRto = bar(ctx, T, 300, 15, '#d6e5f6', 'RTO');
    S.bWrt = bar(ctx, T, 300, 15, '#e7ddf5', '');
    S.bMttr = bar(ctx, T, 320, 15, '#8b847a', 'MTTR');
    S.bMtd = bar(ctx, T, 346, 15, '#e8efd9', 'MTD');

    /* เส้นกวาดเวลาระหว่างกู้ระบบ */
    S.sweepLine = ctx.el('line', { x1: DX, y1: 244, x2: DX, y2: 368, stroke: '#5a43a6', 'stroke-width': 2 }, T);

    S.statP = ctx.panel(L.hud, { x: 468, y: 74, w: 248, rows: 6, lh: 16, title: 'Recovery metrics' });
    S.noteP = ctx.panel(L.hud, { x: 126, y: 382, w: 590, rows: 2, title: 'Where the time goes' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, s = plan(cfg);
    S.t += dt;

    if (S.phase === 'run') {
      /* เขียนธุรกรรมที่ไซต์หลัก แล้วส่งไปไซต์สำรองตามโหมดที่เลือก */
      if (ctx.timer('write', dt, 420)) {
        ctx.bump('written'); S.pending++;
        if (cfg.site === 'hot' && cfg.sync) {
          ctx.launch([P.p, P.d], 'res', { meta: { leg: 'rep', n: 1 }, speed: 300, r: 4 });
          S.pending--;
        }
      }
      if (!(cfg.site === 'hot' && cfg.sync) && ctx.timer('rep', dt, s.rpo >= 24 ? 4200 : s.rpo >= 12 ? 2600 : 1200)) {
        if (S.pending > 0) { ctx.launch([P.p, P.d], 'res', { meta: { leg: 'rep', n: S.pending }, speed: 300, r: 4 }); S.pending = 0; }
      }
      if (S.t > 7000) { S.phase = 'down'; S.t = 0; S.sweep = 0; S.lostNow = S.pending; ctx.bump('lost', S.pending); S.pending = 0; ctx.ring(P.p); ctx.float([P.p[0], P.p[1] - 34], 'disaster', 'bad'); }
      return;
    }

    /* ช่วงกู้ระบบ กวาดเส้นเวลาไปตาม MTTR แล้วต่อด้วย WRT */
    const total = s.mttr + s.wrt;
    S.sweep = Math.min(total, S.sweep + (total / 5000) * dt);
    if (S.sweep >= total) { S.phase = 'run'; S.t = 0; S.sweep = 0; }
  },

  arrive(ctx, p) { if (p.meta.leg === 'rep') ctx.puff(ctx.S.P.d, 'ok'); },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S, s = plan(cfg), sh = cfg.show;
    const down = S.phase === 'down';

    S.primG.classList.toggle('dead', down);
    S.primPill.set(['Primary site', down ? 'lost' : 'serving']);
    S.primPill.tone(down ? 'hot' : '');
    S.drPill.set([SITE_NAME[cfg.site], cfg.site === 'hot' ? (cfg.sync ? 'sync' : 'async') : '']);
    S.drPill.tone(cfg.site === 'hot' ? 'ok' : '');
    S.repWire.setAttribute('class', cfg.site === 'hot' && cfg.sync ? 'wire strong' : 'wire');

    S.bRpo.set(-s.rpo, 0, fmtH(s.rpo), !!sh.rpo);
    S.bRto.set(0, s.rto, fmtH(s.rto), !!sh.rto);
    S.bMttr.set(0, s.mttr, fmtH(s.mttr), !!sh.rto);
    S.bWrt.set(s.rto, s.rto + s.wrt, fmtH(s.wrt), !!sh.mtd);
    S.bMtd.set(0, cfg.mtd, 'tolerance ' + fmtH(cfg.mtd), !!sh.mtd);
    S.bMtd.key('MTD');
    S.bRto.key(sh.mtd ? 'RTO+WRT' : 'RTO');

    S.sweepLine.setAttribute('display', down ? 'inline' : 'none');
    if (down) { const x = tx(S.sweep); S.sweepLine.setAttribute('x1', x); S.sweepLine.setAttribute('x2', x); }

    S.statP.set(0, 'RPO   ' + fmtH(s.rpo) + (s.rpo === 0 ? '   nothing lost' : '   of data lost'), s.rpo === 0 ? 'ok mono' : 'bad mono');
    S.statP.set(1, 'RTO   ' + fmtH(s.rto) + '   target', 'mono');
    S.statP.set(2, 'MTTR  ' + fmtH(s.mttr) + '   actual', s.mttr < s.rto ? 'ok mono' : 'bad mono');
    S.statP.set(3, 'WRT   ' + fmtH(s.wrt) + '   data and checks', 'mono');
    S.statP.set(4, 'MTD   ' + fmtH(s.mttr + s.wrt) + ' of ' + fmtH(cfg.mtd) + ' allowed', (s.mttr + s.wrt) <= cfg.mtd ? 'ok mono' : 'bad mono');
    S.statP.set(5, s.mttr < s.rto ? 'Meets the recovery target' : 'Takes longer than the plan allows', s.mttr < s.rto ? 'ok' : 'bad');

    S.noteP.set(0, SITE_NAME[cfg.site] + ' — ' + SITES[cfg.site].desc, 'dim');
    S.noteP.set(1, down
      ? 'Recovering: ' + (S.sweep < s.mttr ? 'bringing the infrastructure back (RTO)' : 'restoring data and checking the process (WRT)')
      : 'Running normally. ' + (S.pending > 0 ? S.pending + ' write(s) not yet at the recovery site' : 'Everything written is already at the recovery site'),
      down ? 'bad' : S.pending > 0 ? 'bad' : 'ok');
  }
});
})();
