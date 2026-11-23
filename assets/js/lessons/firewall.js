/* ============================================================
   Lesson 06 — Firewall and Policy
   อ้างอิงสไลด์ "04-05 Firewall and Policy" ของรายวิชา 01076042
   แกน: ตารางกฎที่แก้ได้จริง · 3 โซน · ชนิดของ firewall เห็นฟิลด์ต่างกัน
   ============================================================ */
(function () {
/* ---- ผังฉาก: 3 โซนรอบ firewall ตัวเดียว (Multi-Leg) ---- */
const FW = [3.886, 3.726];
const ZONES = {
  untrust: { at: [1.208, 6.404], pal: 'rose',  name: 'UNTRUSTED', sub: 'internet' },
  dmz:     { at: [5.216, -0.494], pal: 'sand',  name: 'DMZ',       sub: 'public services' },
  trust:   { at: [7.383, 1.674], pal: 'green', name: 'TRUST',     sub: 'internal' }
};
const HOSTS = {
  untrust: [{ k: 'client', label: 'client', pal: 'orange' }, { k: 'atk', label: 'attacker', pal: 'dark' }],
  dmz:     [{ k: 'web', label: 'web :443', pal: 'bone' }, { k: 'mail', label: 'mail :25', pal: 'bone' }],
  trust:   [{ k: 'db', label: 'db :1433', pal: 'blue' }, { k: 'pc', label: 'staff pc', pal: 'violet' }]
};

/* ---- ทราฟฟิกทดสอบ ok=true คือทราฟฟิกที่ควรผ่านได้ ---- */
const FLOWS = [
  { n: 'web visit',      fz: 'untrust', fh: 'client', tz: 'dmz',     th: 'web',  port: 443,   proto: 'TCP',  flag: 'SYN', state: 'NEW',         app: 'HTTP',       ok: true },
  { n: 'DB probe',       fz: 'untrust', fh: 'atk',    tz: 'trust',   th: 'db',   port: 1433,  proto: 'TCP',  flag: 'SYN', state: 'NEW',         app: 'SQL',        ok: false },
  { n: 'SSH brute force',fz: 'untrust', fh: 'atk',    tz: 'dmz',     th: 'web',  port: 22,    proto: 'TCP',  flag: 'SYN', state: 'NEW',         app: 'SSH',        ok: false },
  { n: 'ICMP flood',     fz: 'untrust', fh: 'atk',    tz: 'dmz',     th: 'web',  port: 0,     proto: 'ICMP', flag: '-',   state: 'NEW',         app: 'ICMP',       ok: false },
  { n: 'staff browsing', fz: 'trust',   fh: 'pc',     tz: 'untrust', th: 'client', port: 443, proto: 'TCP',  flag: 'SYN', state: 'NEW',         app: 'HTTP',       ok: true },
  { n: 'facebook',       fz: 'trust',   fh: 'pc',     tz: 'untrust', th: 'client', port: 443, proto: 'TCP',  flag: 'SYN', state: 'NEW',         app: 'FACEBOOK',   ok: false },
  { n: 'bittorrent',     fz: 'trust',   fh: 'pc',     tz: 'untrust', th: 'client', port: 6881, proto: 'TCP', flag: 'SYN', state: 'NEW',         app: 'BITTORRENT', ok: false },
  { n: 'web reply',      fz: 'dmz',     fh: 'web',    tz: 'untrust', th: 'client', port: 51234, proto: 'TCP',flag: 'ACK', state: 'ESTABLISHED', app: 'HTTP',       ok: true },
  { n: 'app to DB',      fz: 'dmz',     fh: 'web',    tz: 'trust',   th: 'db',   port: 1433,  proto: 'TCP',  flag: 'SYN', state: 'NEW',         app: 'SQL',        ok: true }
];

/* ชนิดของ firewall เห็นฟิลด์ได้ไม่เท่ากัน — นี่คือแกนของบทนี้ */
const seesState = t => t === 'stateful' || t === 'proxy' || t === 'ngfw';
const seesApp = t => t === 'proxy' || t === 'ngfw';
const TYPE_NAME = {
  none: 'No firewall',
  packet: 'Packet filtering',
  stateful: 'Stateful inspection',
  proxy: 'Application proxy',
  ngfw: 'Next generation firewall'
};
const TYPE_SEES = {
  none: 'nothing',
  packet: 'addresses, ports, flags',
  stateful: 'ports, protocol and state',
  proxy: 'plus application service',
  ngfw: 'all ports, all the time'
};
const ZABBR = { untrust: 'UT', dmz: 'DMZ', trust: 'TR' };

/* ---- ตารางกฎ ---- */
function rules(cfg) {
  if (cfg.type === 'none') return null;
  const R = [];
  if (cfg.policy === 'allowAll') {
    R.push({ src: 'any', dst: 'any', port: 22, act: 'deny', note: 'block SSH' });
    R.push({ src: 'any', dst: 'any', app: 'BITTORRENT', act: 'deny', note: 'block torrents' });
    R.push({ src: 'any', dst: 'any', act: 'allow', note: 'default allow' });
    return R;
  }
  const broad = { src: 'trust', dst: 'any', act: 'allow', note: 'staff convenience rule' };
  if (cfg.badOrder) R.push(broad);
  if (seesApp(cfg.type)) {
    R.push({ src: 'trust', dst: 'any', app: 'BITTORRENT', act: 'deny', note: 'by application' });
    R.push({ src: 'trust', dst: 'any', app: 'FACEBOOK', act: 'deny', note: 'by application' });
  } else {
    R.push({ src: 'trust', dst: 'any', port: 6881, act: 'deny', note: 'torrent port' });
  }
  R.push({ src: 'untrust', dst: 'dmz', port: 443, act: 'allow', note: 'public web' });
  R.push({ src: 'dmz', dst: 'trust', port: 1433, act: 'allow', note: 'app to database' });
  if (!cfg.badOrder) R.push({ src: 'trust', dst: 'any', port: [80, 443], act: 'allow', note: 'staff browsing' });
  if (seesState(cfg.type)) R.push({ src: 'any', dst: 'any', state: 'ESTABLISHED', act: 'allow', note: 'replies to our own connections' });
  else if (cfg.wideOpen) R.push({ src: 'any', dst: 'any', high: true, act: 'allow', note: 'ports above 1023, for replies', risky: true });
  R.push({ src: 'any', dst: 'any', act: 'deny', note: 'default deny' });
  return R;
}

function hits(cfg, r, p) {
  if (r.src !== 'any' && r.src !== p.fz) return false;
  if (r.dst !== 'any' && r.dst !== p.tz) return false;
  if (r.port != null && [].concat(r.port).indexOf(p.port) < 0) return false;
  if (r.high && !(p.port > 1023)) return false;
  if (r.app) { if (!seesApp(cfg.type)) return false; if (r.app !== p.app) return false; }
  if (r.state) { if (!seesState(cfg.type)) return false; if (r.state !== p.state) return false; }
  return true;
}
function judge(cfg, p) {
  const R = rules(cfg);
  if (!R) return { allow: true, n: 0, note: 'no firewall' };
  for (let i = 0; i < R.length; i++) if (hits(cfg, R[i], p)) return { allow: R[i].act === 'allow', n: i + 1, note: R[i].note, rule: R[i] };
  return { allow: false, n: R.length, note: 'default deny' };
}
/* กฎที่ถูกกฎข้างบนบังจนไม่มีวันทำงาน */
function shadowed(cfg, i) {
  const R = rules(cfg); if (!R) return false;
  return FLOWS.every(p => { const j = judge(cfg, p); return j.n !== i + 1; }) && i < R.length - 1;
}

const pad = (s, n) => (String(s) + '                    ').slice(0, n);
function ruleLines(cfg) {
  const R = rules(cfg);
  if (!R) { const e = [['No rule table — every packet is forwarded', 'bad']]; while (e.length < 9) e.push(['', '']); return e; }
  const app = seesApp(cfg.type), st = seesState(cfg.type);
  const mids = app ? 'APP SERVICE' : st ? 'STATE' : null;
  const head = '#  ' + pad('SOURCE', 10) + pad('DEST', 10) + (mids ? pad(mids, 14) : '') + pad('PORT', 8) + 'ACTION';
  const out = [[head, 'dim']];
  R.forEach((r, i) => {
    /* มุมมอง app ยังต้องโชว์ ESTABLISHED ไม่งั้นกฎนั้นอ่านเหมือนอนุญาตทุกอย่าง */
    const mid = app ? (r.app || r.state || 'any') : st ? (r.state || 'any') : null;
    const port = r.high ? '>1023' : r.port != null ? [].concat(r.port).join(',') : 'any';
    const line = (i + 1) + '  ' + pad(r.src, 10) + pad(r.dst, 10) + (mid !== null ? pad(mid, 14) : '') + pad(port, 8) + r.act;
    const cls = r.act === 'allow' ? 'mono' : 'mono';
    out.push([line, r.risky ? 'bad mono' : cls, i]);
  });
  while (out.length < 9) out.push(['', '']);
  return out.slice(0, 9);
}

ICS.register({
  id: 'firewall',
  title: 'Firewall and Policy',
  sub: 'A firewall is a few lines in a table. Which lines, in which order, and which fields the firewall can even see, decide everything.',
  minutes: 15,
  level: 'Intermediate',

  legend: [
    ['req sq', 'Traffic being tested'],
    ['res', 'Allowed'],
    ['bad', 'Denied, or unwanted traffic'],
    ['hollow', 'Matched rule']
  ],

  metrics: [
    { key: 'pass', label: 'Allowed' },
    { key: 'deny', label: 'Denied' },
    { key: 'leak', label: 'Unwanted got through', bad: true, tone: c => (c.stats.leak || 0) > 0 ? 'warn' : '' },
    { key: 'over', label: 'Legitimate blocked', bad: true, tone: c => (c.stats.over || 0) > 0 ? 'warn' : '' },
    { key: 'sees', label: 'Firewall can see', fmt: c => c.cfg.type === 'none' ? '—' : seesApp(c.cfg.type) ? 'app service' : seesState(c.cfg.type) ? 'state' : 'port only' },
    { key: 'score', label: 'Correct decisions', fmt: c => { const t = (c.stats.pass || 0) + (c.stats.deny || 0); return t ? Math.round((t - (c.stats.leak || 0) - (c.stats.over || 0)) * 100 / t) + '%' : '–'; },
      tone: c => { const t = (c.stats.pass || 0) + (c.stats.deny || 0); return t > 6 && !(c.stats.leak || 0) && !(c.stats.over || 0) ? 'lit' : ''; } }
  ],

  learn: [
    ['A firewall decides from the header fields it can read', 0],
    ['Deny all then allow some beats allow all then deny some', 2],
    ['Rules are read top down, so order changes the outcome', 3],
    ['Without connection state you must open ports you did not want to', 5],
    ['Only an application-aware firewall sees what is inside port 443', 6]
  ],

  steps: [
    {
      tag: 'concept', label: 'No filter', title: 'What a firewall actually looks at',
      body: [
        'Three zones sit around one firewall: <code>UNTRUSTED</code> is the internet, <code>DMZ</code> holds the services the public must reach, and <code>TRUST</code> is the internal network. Every packet between zones has to cross the middle.',
        'Right now there is no rule table at all, so everything is forwarded. Watch what crosses: a database probe straight from the internet, an SSH brute force, an ICMP flood. A firewall decides using the header fields of each packet, so the first question is always which fields it can read.'
      ],
      note: ['Why zones first', 'Zoning comes before rules. Group networks by how exposed and how trusted they are, then put the firewall on the boundaries. Rules written without zones end up as a list of addresses nobody can review.'],
      changed: ['Zones: 3', 'Firewall: not filtering yet'],
      cfg: { type: 'none', policy: 'denyAll', badOrder: false, wideOpen: false, replies: false, tunnel: false }
    },
    {
      tag: 'problem', label: 'Allow all', title: 'Allow all, deny some',
      body: [
        'The first instinct is to let traffic flow and block the bad things as they come up. The table says deny SSH, deny torrents, allow everything else. It feels reasonable and it is how a lot of networks are actually configured.',
        'The trouble is the last line. Anything nobody thought of is allowed, so the database probe from the internet walks straight into the TRUST zone. Nobody wrote a rule for port 1433 because nobody imagined it being reachable.'
      ],
      note: ['The asymmetry again', 'To be safe this way you must think of every dangerous thing in advance. The attacker only has to find the one you missed. The same reasoning appears in input filtering and in least privilege.'],
      changed: ['Policy: allow all, deny some'],
      cfg: { type: 'packet', policy: 'allowAll', badOrder: false, wideOpen: false, replies: false, tunnel: false }
    },
    {
      tag: 'technique', label: 'Deny all', title: 'Deny all, allow some',
      body: [
        'Flip the last line to <code>deny</code> and list only what the business actually needs: the public web on 443, the application reaching its database, staff browsing out on 80 and 443.',
        'Everything unlisted now dies at the boundary, including the things nobody predicted. This is the same default-deny idea as least privilege, applied to packets instead of permissions.'
      ],
      note: ['The question from the slide', 'To stop an ICMP flood, what rule do you write? With default deny you do not write one at all — ICMP is simply not on the allow list, so it is already blocked. That is the point of the default.'],
      changed: ['Policy: deny all, allow some'],
      cfg: { type: 'packet', policy: 'denyAll', badOrder: false, wideOpen: false, replies: false, tunnel: false }
    },
    {
      tag: 'problem', label: 'Rule order', title: 'Rules are read top down',
      body: [
        'Somebody adds a broad <code>trust → any : allow</code> rule at the top so the staff stop complaining. It works, and it quietly kills every rule below it that mentions the trust zone.',
        'The torrent rule is still in the table. It is still spelled correctly. It will simply never run, because rule 1 matches first and the firewall stops at the first match. A rule that can never fire is worse than no rule, because the table says you are protected.'
      ],
      note: ['Order the table deliberately', 'Specific denies go above broad allows, and the broadest rules go last. When a table grows past a few dozen lines, this stops being something you can hold in your head, which is why shadowed-rule analysis is a standard audit tool.'],
      changed: ['Broad allow moved to the top'],
      cfg: { type: 'packet', policy: 'denyAll', badOrder: true, wideOpen: false, replies: false, tunnel: false },
      controls: ['badOrder']
    },
    {
      tag: 'problem', label: 'No state', title: 'Packet filtering cannot see a connection',
      body: [
        'Order is fixed, but look at the <code>web reply</code> flow. A packet filter judges each packet alone, so it has no idea this one is the answer to a request we allowed a moment ago. It arrives on a high random port, matches nothing, and is dropped. The site appears to hang.',
        'The usual workaround is the switch below: allow everything above port 1023 so replies get through. Turn it on and the replies work — and the database probe on 1433 and the torrent on 6881 now walk in too.'
      ],
      note: ['Why this matters historically', 'This is exactly the limitation that stateful inspection was invented to remove. Before it, firewall administrators genuinely did open whole port ranges and accept the consequences.'],
      changed: ['Watching return traffic'],
      cfg: { type: 'packet', policy: 'denyAll', badOrder: false, wideOpen: false, replies: true, tunnel: false },
      controls: ['wideOpen']
    },
    {
      tag: 'technique', label: 'Stateful', title: 'Stateful inspection remembers connections',
      body: [
        'The firewall now keeps a table of connections it has seen. The rule table gains a <code>STATE</code> column, and one line replaces the dangerous port range: allow anything whose state is <code>ESTABLISHED</code>.',
        'Replies flow because the firewall knows they belong to a connection it already approved. Nothing else gained anything, because an unsolicited packet from the internet has no matching entry in the state table.'
      ],
      note: ['What state costs', 'The firewall must hold an entry per connection, which is why stateful firewalls have a connection limit, and why connection-exhaustion attacks target it. There is no free lunch, only a better trade.'],
      changed: ['Type: stateful inspection', 'New column: STATE'],
      cfg: { type: 'stateful', policy: 'denyAll', badOrder: false, wideOpen: false, replies: true, tunnel: false }
    },
    {
      tag: 'problem', label: 'Inside 443', title: 'Everything hides inside port 443',
      body: [
        'Facebook and the torrent client both learned the same trick: run over port 443 and look like ordinary HTTPS. To a stateful firewall these packets are indistinguishable from the staff browsing we deliberately allowed.',
        'The torrent rule by port is useless once the port changes. Switch the firewall type below to an application proxy or a next generation firewall and the rule table gains an <code>APP SERVICE</code> column, which blocks by what the traffic is rather than where it is going.'
      ],
      note: ['Classify all traffic, all ports, all the time', 'That phrase from the slides is the whole marketing of NGFW, and it is accurate about what changed. The cost is that the firewall now has to look inside the payload, which means decrypting TLS, which brings its own privacy and performance questions.'],
      changed: ['Facebook and torrents moved onto 443'],
      cfg: { type: 'stateful', policy: 'denyAll', badOrder: false, wideOpen: false, replies: true, tunnel: true },
      controls: ['type']
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: write the policy yourself',
      body: [
        'The slide asks for a rule that lets students use the web and nothing else, but not Facebook and not Bittorrent. Work out which firewall type can even express that, then check your answer against the table.',
        'Then try the awkward ones. Can a firewall stop a virus arriving in an email? Can it stop an attack between two machines inside the same zone, which never crosses it? Both answers tell you where a firewall stops being the right tool.'
      ],
      note: ['The group activity', 'The assignment asks for at least six networks and three firewalls, with every rule written out and justified by the threat it stops. Build it here first with three zones; the reasoning scales, the table just gets longer.'],
      changed: [],
      cfg: { type: 'packet', policy: 'denyAll', badOrder: false, wideOpen: false, replies: true, tunnel: true },
      controls: ['type', 'policy', 'badOrder', 'wideOpen']
    }
  ],

  controls: {
    type: {
      type: 'seg', label: 'Firewall technology',
      options: [['none', 'None'], ['packet', 'Packet filter'], ['stateful', 'Stateful'], ['proxy', 'App proxy'], ['ngfw', 'NGFW']],
      get: c => c.type, set: (c, v) => { c.type = v; }
    },
    policy: {
      type: 'seg', label: 'Default policy',
      options: [['allowAll', 'Allow all, deny some'], ['denyAll', 'Deny all, allow some']],
      get: c => c.policy, set: (c, v) => { c.policy = v; }
    },
    badOrder: { type: 'toggle', label: 'Broad staff rule at the top', hint: 'Shadows every rule below it', get: c => c.badOrder, set: (c, v) => { c.badOrder = v; } },
    wideOpen: { type: 'toggle', label: 'Allow ports above 1023', hint: 'The workaround for missing state', get: c => c.wideOpen, set: (c, v) => { c.wideOpen = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso, P = { fw: iso(FW[0], FW[1], 1.05), h: {} };
    for (const z in ZONES) {
      const Z = ZONES[z].at;
      HOSTS[z].forEach((h, i) => {
        const o = (i - 0.5) * 1.0;
        P.h[z + '.' + h.k] = iso(Z[0] + o, Z[1] - o, 0.95);
      });
    }
    ctx.S = { P, log: [], idx: 0, last: null, hit: -1 };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, L = ctx.L, PAL = ctx.PAL;

    for (const z in ZONES) ctx.line(iso(ZONES[z].at[0], ZONES[z].at[1], 0.15), iso(FW[0], FW[1], 0.15), 'wire', L.wires);

    /* โซน วาดจากหลังมาหน้าตามความลึก */
    const items = [];
    for (const z in ZONES) {
      const Z = ZONES[z];
      items.push({ k: Z.at[0] + Z.at[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        const p = PAL[Z.pal];
        ctx.block(g, Z.at[0], Z.at[1], 2.0, 2.0, 0.2, 0, p[0], p[1], 10);
        HOSTS[z].forEach((h, i) => {
          const o = (i - 0.5) * 1.0;
          const hp = PAL[h.pal];
          ctx.block(g, Z.at[0] + o, Z.at[1] - o, 0.45, 0.45, 0.5, 0.2, hp[0], hp[1], 3);
        });
        /* ป้ายเดียวต่อโซน ป้ายรายเครื่องจะทับกันเองในพื้นที่แคบ */
        const lp = iso(Z.at[0] + 0.75, Z.at[1] + 0.75, 0.2);
        const t = ctx.el('text', { class: 'host-lbl', x: lp[0], y: lp[1] + 11 }, g);
        t.textContent = HOSTS[z].map(h => h.label).join('  ·  ');
      }});
    }
    items.push({ k: FW[0] + FW[1], draw: () => {
      const g = ctx.el('g', {}, L.ents);
      const b = ctx.actor.box(g, FW[0], FW[1], { w: 1.25, h: 0.8, pal: 'rose' });
      S.wallG = ctx.el('g', {}, g);
      ctx.glyph.wall(S.wallG, iso(FW[0], FW[1], b.box.zt));
    }});
    items.sort((a, b) => a.k - b.k).forEach(it => it.draw());

    S.zp = {};
    /* เลื่อนซ้ายให้พ้นพื้นหลังป้ายไฟร์วอลล์ ซึ่งกว้างขึ้นตามโหมดที่เลือก */
    S.zp.untrust = ctx.pill(L.labels, 210, 300, [ZONES.untrust.name, ZONES.untrust.sub]);
    S.zp.dmz = ctx.pill(L.labels, 636, 205, [ZONES.dmz.name], 'start');
    S.zp.trust = ctx.pill(L.labels, 636, 283, [ZONES.trust.name], 'start');
    S.fwPill = ctx.pill(L.labels, 400, 300, ['Firewall', '']);

    S.policyP = ctx.panel(L.hud, { x: 126, y: 74, w: 300, rows: 3, title: 'Policy in force' });
    S.logP = ctx.panel(L.hud, { x: 446, y: 74, w: 270, rows: 4, title: 'Decision log', dark: true });
    S.ruleP = ctx.panel(L.hud, { x: 126, y: 328, w: 590, rows: 9, lh: 14, title: 'Firewall rule table' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    if (!ctx.timer('flow', dt, 1100)) return;
    const pool = FLOWS.filter(x => cfg.replies || x.n !== 'web reply');
    const f = Object.assign({}, pool[S.idx++ % pool.length]);
    /* ขั้นท้ายๆ ทราฟฟิกย้ายมาซ่อนใน 443 กฎที่อิงพอร์ตจึงใช้ไม่ได้ */
    if (cfg.tunnel && f.app === 'BITTORRENT') f.port = 443;
    const from = P.h[f.fz + '.' + f.fh];
    ctx.launch([from, P.fw], f.ok ? 'plain' : 'bad',
      { label: f.n, meta: { leg: 'fw', f }, speed: 260 });
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    if (m.leg === 'fw') {
      const f = m.f, v = judge(cfg, f);
      S.last = { f, v };
      S.hit = v.n - 1;
      const tag = ZABBR[f.fz] + '→' + ZABBR[f.tz] + ' ' + (f.port ? ':' + f.port : f.proto) + '  ' + f.n;
      if (!v.allow) {
        ctx.bump('deny'); ctx.puff(P.fw, f.ok ? '' : 'ok');
        if (f.ok) { ctx.bump('over'); ctx.float([P.fw[0], P.fw[1] - 28], 'wrongly blocked', 'bad'); }
        S.log.unshift({ t: '✗ ' + tag, cls: f.ok ? 'term-bad' : 'term' });
        if (S.log.length > 4) S.log.length = 4;
        return;
      }
      ctx.bump('pass');
      S.log.unshift({ t: '✓ ' + tag + '  r' + v.n, cls: f.ok ? 'term' : 'term-bad' });
      if (S.log.length > 4) S.log.length = 4;
      ctx.launch([P.fw, P.h[f.tz + '.' + f.th]], f.ok ? 'plain' : 'bad',
        { label: f.n, meta: { leg: 'dst', f }, speed: 260 });
      return;
    }
    if (m.leg === 'dst') {
      const f = m.f, at = P.h[f.tz + '.' + f.th];
      if (!f.ok) { ctx.bump('leak'); ctx.ring(at); ctx.float([at[0], at[1] - 24], 'got through', 'bad'); }
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const on = cfg.type !== 'none';

    S.wallG.setAttribute('opacity', on ? 1 : 0.15);
    S.fwPill.set(['Firewall', on ? TYPE_NAME[cfg.type].replace('Next generation firewall', 'NGFW') : 'off']);
    S.fwPill.tone(!on ? 'hot' : seesApp(cfg.type) ? 'ok' : '');
    S.zp.untrust.tone('hot');
    S.zp.trust.tone('ok');

    S.policyP.set(0, TYPE_NAME[cfg.type], on ? 'ok' : 'bad');
    S.policyP.set(1, 'Sees ' + TYPE_SEES[cfg.type], 'dim');
    S.policyP.set(2, !on ? 'No rules are evaluated'
      : cfg.policy === 'allowAll' ? 'Default: allow anything not denied'
      : 'Default: deny anything not allowed', cfg.policy === 'allowAll' && on ? 'bad' : 'dim');

    const lines = ruleLines(cfg);
    lines.forEach((l, i) => {
      let cls = l[1];
      if (l.length > 2 && l[2] === S.hit) cls = 'rulehit mono';
      else if (l.length > 2 && shadowed(cfg, l[2])) cls = 'ruledead mono';
      S.ruleP.set(i, l[0], cls);
    });

    for (let i = 0; i < 4; i++) {
      const r = S.log[i];
      S.logP.set(i, r ? r.t : (i === 0 ? '— waiting for traffic —' : ''), r ? r.cls : 'term dim');
    }
  }
});
})();
