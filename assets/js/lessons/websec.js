/* ============================================================
   Lesson 09 — Web Security · OWASP Top 10 (2021)
   อ้างอิงสไลด์ "08 WebSecurity" + "08 OWASP-top-10 2021"
   แกน: สถาปัตยกรรมเว็บ 4 ชั้น · บอร์ด A01–A10 · เดโม A03
   ============================================================ */
(function () {
/* ---- สี่ชั้นตามสไลด์ Example Web Application ---- */
const LAYERS = [
  { at: [-3.24, 2.69], name: 'Browser',   tech: 'HTML, JavaScript',   zone: 'Internet',  pal: 'orange' },
  { at: [-1.80, 4.13], name: 'Web server', tech: 'Apache, IIS',        zone: 'DMZ',       pal: 'sand' },
  { at: [-0.35, 5.58], name: 'App server', tech: 'Java, PHP, ASP',     zone: 'Protected', pal: 'violet' },
  { at: [1.09, 7.02],  name: 'Database',   tech: 'Oracle, SQL Server', zone: 'Internal',  pal: 'blue' }
];

/* ---- OWASP Top 10 2021 · ตัวเลขจากเอกสารชุด 2021 ---- */
const CARDS = [
  { c: 'A01', n: 'Broken Access Control', cwe: 34, exp: 6.92, imp: 5.93, cves: 19013, layer: 2,
    top: 'CWE-200 exposure · CWE-352 CSRF',
    why: 'Found in 94% of the applications tested. Rose from fifth place to first.',
    atk: 'GET /invoice?id=99', def: 'Check ownership on the server for every request' },
  { c: 'A02', n: 'Cryptographic Failures', cwe: 29, exp: 7.29, imp: 6.81, cves: 3075, layer: 1,
    top: 'CWE-259 hard-coded password · CWE-327 broken crypto',
    why: 'Renamed from Sensitive Data Exposure, which was a symptom rather than a cause.',
    atk: 'read the session cookie on the wire', def: 'TLS everywhere, HttpOnly cookies, slow password hashing' },
  { c: 'A03', n: 'Injection', cwe: 33, exp: 7.25, imp: 7.15, cves: 32078, layer: 3,
    top: 'CWE-89 SQL injection · CWE-79 cross-site scripting',
    why: 'XSS was folded into Injection in 2021. Both are data becoming code.',
    atk: "' OR '1'='1", def: 'Parameterised queries, and escape output for its context' },
  { c: 'A04', n: 'Insecure Design', cwe: 40, exp: 6.46, imp: 6.78, cves: 2691, layer: 2,
    top: 'CWE-501 trust boundary · CWE-522 weak credential storage',
    why: 'New in 2021. Some flaws cannot be fixed in code because the design is wrong.',
    atk: 'book 200 group seats across branches', def: 'Threat modelling and business limits, before coding' },
  { c: 'A05', n: 'Misconfiguration', cwe: 20, exp: 8.12, imp: 6.56, cves: 789, layer: 1,
    top: 'CWE-16 configuration · CWE-611 XXE',
    why: 'The easiest category to exploit of all ten, at 8.12.',
    atk: 'GET /admin/ with default credentials', def: 'Harden defaults, remove samples, review every environment' },
  { c: 'A06', n: 'Outdated Components', cwe: 3, exp: null, imp: null, cves: 0, layer: 2,
    top: 'CWE-1104 unmaintained third-party components',
    why: 'The only category with no exploit or impact scores of its own.',
    atk: 'exploit a known bug in an old library', def: 'Keep an inventory and patch on a schedule' },
  { c: 'A07', n: 'Auth Failures', cwe: 22, exp: 7.40, imp: 6.50, cves: 3897, layer: 2,
    top: 'CWE-287 improper authentication · CWE-384 session fixation',
    why: 'Fell from second place as frameworks made good defaults easier.',
    atk: 'credential stuffing with leaked passwords', def: 'MFA, rate limiting, no default accounts' },
  { c: 'A08', n: 'Integrity Failures', cwe: 10, exp: 6.94, imp: 7.94, cves: 1152, layer: 2,
    top: 'CWE-502 deserialisation · CWE-494 download without integrity check',
    why: 'New in 2021. Highest impact of all ten. SolarWinds reached 18,000 orgs.',
    atk: 'a poisoned software update', def: 'Sign updates and verify the build pipeline' },
  { c: 'A09', n: 'Logging Failures', cwe: 4, exp: 6.87, imp: 4.99, cves: 242, layer: 2,
    top: 'CWE-778 insufficient logging · CWE-532 sensitive data in logs',
    why: 'One breach of 3.5 million health records went unnoticed from 2013.',
    atk: 'an attack that nobody sees', def: 'Log, alert, and actually review the alerts' },
  { c: 'A10', n: 'SSRF', cwe: 1, exp: 8.28, imp: 6.72, cves: 385, layer: 2,
    top: 'CWE-918 server-side request forgery',
    why: 'One CWE only, and it came from the community survey rather than the data.',
    atk: 'url=http://169.254.169.254/', def: 'Allow-list the outbound addresses the server may call' }
];

/* ---- เดโม A03: input เดียว ไปอยู่คนละภาษา ---- */
const SQL_A = "SELECT * FROM users WHERE name = '", SQL_B = "'";
const HTML_A = '<div class="comment">', HTML_B = '</div>';
const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&#39;');
const breaksSql = s => /'/.test(s);
const breaksHtml = s => /<\s*script|<\s*img|on\w+\s*=/i.test(s);

/* ---- บอร์ด ---- */
const BX = 406, BY = 80, BW = 310, ROW = 19.5, R0 = 126;
function order(cfg) {
  const ix = CARDS.map((c, i) => i);
  if (cfg.sort === 'exploit') ix.sort((a, b) => (CARDS[b].exp || -1) - (CARDS[a].exp || -1));
  else if (cfg.sort === 'impact') ix.sort((a, b) => (CARDS[b].imp || -1) - (CARDS[a].imp || -1));
  return ix;
}

ICS.register({
  id: 'websec',
  title: 'Web Security and the OWASP Top 10',
  sub: 'Ten categories, eight of them measured from real applications. Where each one lives in the stack, how easy it is to exploit, and how much it costs when it happens.',
  minutes: 16,
  level: 'Intermediate',

  legend: [
    ['req sq', 'Request crossing the stack'],
    ['bad', 'Attack reached its layer'],
    ['res', 'Blocked by the control'],
    ['hollow', 'Layer the category lives in']
  ],

  metrics: [
    { key: 'req', label: 'Requests' },
    { key: 'hit', label: 'Exploited', bad: true, tone: c => (c.stats.hit || 0) > 0 ? 'warn' : '' },
    { key: 'blocked', label: 'Blocked', tone: c => (c.stats.blocked || 0) > 0 ? 'lit' : '' },
    { key: 'exp', label: 'Exploit score', fmt: c => { const k = CARDS[c.cfg.card]; return k.exp == null ? '—' : k.exp.toFixed(2); } },
    { key: 'imp', label: 'Impact score', fmt: c => { const k = CARDS[c.cfg.card]; return k.imp == null ? '—' : k.imp.toFixed(2); } },
    { key: 'cve', label: 'CVEs mapped', fmt: c => CARDS[c.cfg.card].cves.toLocaleString('en-US') }
  ],

  learn: [
    ['A web request crosses four layers in three zones', 0],
    ['Eight categories come from measured data, two from a survey', 1],
    ['Injection is data becoming code, in SQL or in HTML', 2],
    ['Broken access control is now first, seen in 94% of apps', 3],
    ['Easy to exploit and expensive to suffer are different axes', 5]
  ],

  steps: [
    {
      tag: 'concept', label: 'The stack', title: 'A request crosses four layers and three zones',
      body: [
        'The slides draw a web application as four layers. The <code>browser</code> sits on the internet, the <code>web server</code> in the DMZ, the <code>application server</code> in a protected network, and the <code>database</code> deepest of all on the internal network.',
        'Every request walks down that chain and the answer walks back up. Knowing which layer a vulnerability lives in tells you who fixes it, which team owns it, and which control could possibly stop it. That is the first thing to establish about any entry on the list.'
      ],
      note: ['Zones were the firewall lesson', 'The three zones here are the same Untrusted, DMZ and Trust zones from the firewall topic. A firewall separates them; this lesson is about what gets through legitimately and is still dangerous.'],
      changed: ['Four layers, three zones'],
      cfg: { card: 2, defense: false, sort: 'rank', attack: false, payload: "' OR '1'='1" }
    },
    {
      tag: 'concept', label: 'The list', title: 'Where the Top 10 comes from',
      body: [
        'Eight of the ten categories are derived from data that organisations contributed about real applications. The other two come from a community survey, for risks practitioners see coming before the data catches up. <code>A10 SSRF</code> is one of those.',
        'Each category carries an incidence rate, an exploit score and an impact score, and maps to a set of CWE identifiers. The board on the right shows the two scores as bars. They are averages, not predictions about your application, but they are measured.'
      ],
      note: ['What the Top 10 is for', 'It is an awareness document. For coding standards, code review and testing, OWASP points to ASVS, the Application Security Verification Standard, instead. Using the Top 10 as a test checklist is the most common misuse of it.'],
      changed: ['Showing exploit and impact scores'],
      cfg: { card: 0, defense: false, sort: 'rank', attack: false, payload: "' OR '1'='1" }
    },
    {
      tag: 'attack', label: 'A03 Injection', title: 'A03: the same input, two different languages',
      body: [
        'In 2021 cross-site scripting stopped being its own category and was folded into <code>Injection</code>, because it is the same mistake: user data gets treated as code. Only the language changes — SQL at the database, HTML and JavaScript at the browser.',
        'Type into the box and watch one input land in both. A quote breaks out of the SQL string; a tag breaks out of the HTML text. The fix is the same shape in both places, and it is not filtering: keep data and code apart, with parameters for SQL and context-aware escaping for output.'
      ],
      note: ['Still the biggest by CVE count', 'Injection maps to 32,078 CVEs, more than twice any other category. It dropped from first to third not because it got rarer but because access control got worse.'],
      changed: ['Payload is editable'],
      cfg: { card: 2, defense: false, sort: 'rank', attack: true, payload: "' OR '1'='1" },
      controls: ['payload', 'defense']
    },
    {
      tag: 'concept', label: 'A01 first', title: 'A01: broken access control went to the top',
      body: [
        'Access control was fifth in 2017 and is first in 2021. It was found in <code>94%</code> of the applications tested, which makes it less an occasional bug than a default condition.',
        'It is the IDOR problem from the access control topic, at scale: the application knows who you are and checks that you may read invoices, but never checks that this invoice is yours. Turn the control on below and the same request is refused.'
      ],
      note: ['Why it is so common', 'Authentication has good libraries and authorisation does not, because the rule depends on your data model. Every endpoint has to be reasoned about separately, and one missed endpoint is the whole category.'],
      changed: ['Reviewing A01'],
      cfg: { card: 0, defense: false, sort: 'rank', attack: true, payload: "' OR '1'='1" },
      controls: ['defense']
    },
    {
      tag: 'concept', label: 'A04 design', title: 'A04: when no line of code is wrong',
      body: [
        'New in 2021. The cinema in the slides offers a group discount for fifteen people or more and does not take a deposit. An attacker books hundreds of discounted seats across branches, never pays, and the real customers find the screenings full.',
        'Review the code and every line is correct. The validation works, the payment works, nothing crashes. The flaw is in the design of the business rule, so no amount of secure coding would have caught it. That is why threat modelling happens before the code exists.'
      ],
      note: ['Insecure design versus misconfiguration', 'A missing control that was never designed is insecure design. A control that exists but was set up badly is misconfiguration. The distinction matters because they are fixed by different people at different times.'],
      changed: ['Reviewing A04'],
      cfg: { card: 3, defense: false, sort: 'rank', attack: true, payload: "' OR '1'='1" }
    },
    {
      tag: 'concept', label: 'Two axes', title: 'Easy to exploit is not the same as expensive',
      body: [
        'Sort the board by each score in turn. By exploitability <code>A10 SSRF</code> leads at 8.28 and <code>A05 Misconfiguration</code> follows at 8.12 — both are easy to attack once found. By impact the order changes: <code>A08 Integrity Failures</code> is worst at 7.94, the category that covers poisoned software updates.',
        'Neither ranking is the published order, because the real one also weighs how often the category appears. Which of the three orderings you should act on depends on whether you are worried about frequency, ease, or the size of the worst day.'
      ],
      note: ['A06 has no scores', 'Outdated Components is the only category with no exploit or impact figures of its own. Its severity is whatever the vulnerable component happens to have, which is exactly why it has to be tracked rather than rated.'],
      changed: ['Board can be reordered'],
      cfg: { card: 7, defense: false, sort: 'impact', attack: true, payload: "' OR '1'='1" },
      controls: ['sort']
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: pick a category and turn the control on',
      body: [
        'Step through all ten. For each one, name the layer it lives in, who in your team would own the fix, and whether the control that stops it is code, configuration, or a decision taken before any code was written.',
        'The slides ask the same question from three sides: what should a user be aware of, what should the system administrator, and what should the developer? Most of these ten have a different answer for each of the three.'
      ],
      note: ['Where to go next', 'The SQL injection and cross-site scripting lessons in this module are the detailed walkthroughs of A03. This board is the map; those two are the territory.'],
      changed: [],
      cfg: { card: 0, defense: false, sort: 'rank', attack: true, payload: "' OR '1'='1" },
      controls: ['pick', 'defense', 'sort']
    }
  ],

  controls: {
    pick: {
      type: 'seg', label: 'Category',
      options: CARDS.map((c, i) => [i, c.c]),
      get: c => c.card, set: (c, v) => { c.card = +v; }
    },
    defense: { type: 'toggle', label: 'Turn the control on', hint: 'The fix for the selected category', get: c => c.defense, set: (c, v) => { c.defense = v; } },
    sort: {
      type: 'seg', label: 'Order the board by',
      options: [['rank', 'Published rank'], ['exploit', 'Exploitability'], ['impact', 'Impact']],
      get: c => c.sort, set: (c, v) => { c.sort = v; }
    },
    payload: {
      type: 'text', label: 'User input', placeholder: 'hello',
      hint: 'A quote breaks SQL, a tag breaks HTML',
      get: c => c.payload, set: (c, v) => { c.payload = v; },
      presets: [
        ['plain', 'hello'],
        ['SQL', "' OR '1'='1"],
        ['XSS', '<script>steal()</script>'],
        ['both', "'><script>x()</script>"]
      ]
    }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = { P: LAYERS.map(l => iso(l.at[0], l.at[1], 0.85)) };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, L = ctx.L;

    for (let i = 0; i < 3; i++)
      ctx.line(iso(LAYERS[i].at[0], LAYERS[i].at[1], 0.2), iso(LAYERS[i + 1].at[0], LAYERS[i + 1].at[1], 0.2), 'wire', L.wires);

    S.layers = LAYERS.map((l, i) => {
      const g = ctx.el('g', {}, L.ents);
      const b = ctx.actor.box(g, l.at[0], l.at[1], { w: 1.3, h: 0.58, pal: l.pal });
      const p = iso(l.at[0] + 0.95, l.at[1] - 0.95, 0.3);
      const pill = ctx.pill(L.labels, p[0] + 18, p[1], [l.name], 'start');
      return { g, b, pill };
    });

    /* ---- บอร์ด OWASP ---- */
    const B = ctx.el('g', {}, L.hud);
    ctx.el('rect', { class: 'pn-shadow', x: BX + 2, y: BY + 3, width: BW, height: 236, rx: 9 }, B);
    ctx.el('rect', { class: 'pn-bg', x: BX, y: BY, width: BW, height: 236, rx: 9 }, B);
    const ttl = ctx.el('text', { class: 'pn-title', x: BX + 10, y: BY + 15 }, B);
    ttl.textContent = 'OWASP Top 10 · 2021';
    const hd = ctx.el('text', { class: 'rm-ax', x: BX + 8, y: BY + 26 }, B);
    hd.textContent = '#    CATEGORY';
    const he = ctx.el('text', { class: 'rm-ax', x: BX + 206, y: BY + 26 }, B);
    he.textContent = 'EXPLOIT';
    const hi = ctx.el('text', { class: 'rm-ax', x: BX + 256, y: BY + 26 }, B);
    hi.textContent = 'IMPACT';

    S.rows = CARDS.map((k, i) => {
      const g = ctx.el('g', { class: 'owasp-row' }, B);
      const sel = ctx.el('rect', { x: BX + 4, y: -14, width: BW - 8, height: 18, rx: 4, fill: '#e7ddf5', stroke: '#5a43a6', 'stroke-width': 1.2, display: 'none' }, g);
      const code = ctx.el('text', { class: 'ow-code', x: BX + 10, y: 0 }, g);
      code.textContent = k.c;
      const name = ctx.el('text', { class: 'ow-name', x: BX + 40, y: 0 }, g);
      name.textContent = k.n;
      const eb = ctx.el('rect', { x: BX + 206, y: -9, width: 0, height: 9, rx: 2, fill: '#f4c9a0', stroke: '#1d1b18', 'stroke-width': .8 }, g);
      const ib = ctx.el('rect', { x: BX + 256, y: -9, width: 0, height: 9, rx: 2, fill: '#bfd5ee', stroke: '#1d1b18', 'stroke-width': .8 }, g);
      if (k.exp != null) eb.setAttribute('width', k.exp / 10 * 42);
      if (k.imp != null) ib.setAttribute('width', k.imp / 10 * 42);
      return { g, sel, code, name, i };
    });

    S.detP = ctx.panel(L.hud, { x: 126, y: 320, w: 590, rows: 4, lh: 16, title: 'Category under review' });
    S.evP = ctx.panel(L.hud, { x: 126, y: 418, w: 590, rows: 2, title: 'What it looks like' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S;
    if (!ctx.timer('req', dt, 2000)) return;
    ctx.bump('req');
    ctx.launch([S.P[0], S.P[1]], 'plain', { label: 'request', meta: { leg: 'down', i: 1 }, speed: 220 });
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, m = p.meta, k = CARDS[cfg.card];
    if (m.leg === 'down') {
      if (cfg.attack && m.i === k.layer) {
        if (cfg.defense) { ctx.bump('blocked'); ctx.puff(S.P[m.i], 'ok'); ctx.float([S.P[m.i][0], S.P[m.i][1] - 26], 'blocked', 'ok'); }
        else { ctx.bump('hit'); ctx.ring(S.P[m.i]); ctx.float([S.P[m.i][0], S.P[m.i][1] - 26], k.c, 'bad'); }
      }
      if (m.i + 1 < LAYERS.length) {
        ctx.launch([S.P[m.i], S.P[m.i + 1]], cfg.attack && m.i >= k.layer && !cfg.defense ? 'bad' : 'plain',
          { label: cfg.attack && m.i + 1 === k.layer ? k.c : 'request', meta: { leg: 'down', i: m.i + 1 }, speed: 220 });
      } else {
        ctx.launch([S.P[3], S.P[2], S.P[1], S.P[0]], 'res', { meta: { leg: 'up' }, speed: 420 });
      }
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S, k = CARDS[cfg.card];

    S.layers.forEach((l, i) => {
      const here = i === k.layer;
      l.g.setAttribute('opacity', here ? 1 : 0.55);
      l.pill.set([LAYERS[i].name]);
      l.pill.tone(here ? (cfg.defense ? 'ok' : 'hot') : '');
    });

    /* เรียงแถวบนบอร์ดตามเกณฑ์ที่เลือก */
    const ix = order(cfg);
    S.rows.forEach(r => {
      const pos = ix.indexOf(r.i);
      r.g.setAttribute('transform', 'translate(0,' + (R0 + pos * ROW) + ')');
      const on = r.i === cfg.card;
      r.sel.setAttribute('display', on ? 'inline' : 'none');
      r.code.setAttribute('class', 'ow-code' + (on ? ' on' : ''));
      r.name.setAttribute('class', 'ow-name' + (on ? ' on' : ''));
    });

    S.detP.set(0, k.c + '  ' + k.n + '   ·   ' + k.cwe + ' CWEs   ·   ' + k.cves.toLocaleString('en-US') + ' CVEs', 'ok');
    S.detP.set(1, 'Lives at: ' + LAYERS[k.layer].name + ' (' + LAYERS[k.layer].zone + ')  ·  ' + LAYERS[k.layer].tech, 'dim');
    S.detP.set(2, k.top, 'mono dim');
    S.detP.set(3, k.why, 'dim');

    if (cfg.card === 2) {
      /* เดโม A03: input เดียวไปอยู่สองภาษา */
      const raw = cfg.payload || '';
      const shown = cfg.defense ? esc(raw) : raw;
      /* query แบบ parameterised ไม่มีเครื่องหมายคำพูดครอบ ค่าเดินทางแยกช่อง */
      const sql = cfg.defense ? 'SELECT * FROM users WHERE name = ?    ← value sent separately' : SQL_A + raw + SQL_B;
      const html = HTML_A + shown + HTML_B;
      const sqlBad = !cfg.defense && breaksSql(raw), htmlBad = !cfg.defense && breaksHtml(raw);
      S.evP.set(0, 'SQL   ' + (sql.length > 74 ? sql.slice(0, 74) + '…' : sql), sqlBad ? 'bad mono' : 'ok mono');
      S.evP.set(1, 'HTML  ' + (html.length > 74 ? html.slice(0, 74) + '…' : html), htmlBad ? 'bad mono' : 'ok mono');
    } else {
      S.evP.set(0, 'Attack:  ' + k.atk, cfg.defense ? 'mono dim' : 'bad mono');
      S.evP.set(1, 'Control: ' + k.def, cfg.defense ? 'ok' : 'dim');
    }
  }
});
})();
