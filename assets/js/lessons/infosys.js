/* ============================================================
   Lesson 01 — Information Systems
   อ้างอิงสไลด์ "01 Information Systems" ของรายวิชา 01076042
   คำถามหลัก: ผู้ดูแลระบบทะเบียนควรทราบรายละเอียดเกี่ยวกับอะไรบ้าง
   ============================================================ */
(function () {
const CX = 5.315, CY = 7.075, HALF = 1.3;
const OFF = 0.8;            /* ระยะห่างคอมโพเนนต์บนแผ่น */

/* ชั้นสถาปัตยกรรมตาม TOGAF เรียงจากบนลงล่าง */
const LAYERS = [
  { key: 'business', z: 5.1, name: 'Business', pal: 'sand', comp: 'orange',
    owner: 'Registrar staff',
    items: ['Enrol in a course', 'Pay tuition fees', 'Publish grades'],
    tags: ['Enrol', 'Pay', 'Grades'],
    about: 'What the organisation does.' },
  { key: 'application', z: 3.4, name: 'Application', pal: 'violet', comp: 'violet',
    owner: 'Software developers',
    items: ['Student Portal', 'Payment Service', 'Reporting Tool'],
    tags: ['Portal', 'Payment', 'Reports'],
    about: 'The programs that run each process.' },
  { key: 'data', z: 1.7, name: 'Data', pal: 'blue', comp: 'blue',
    owner: 'Data owners and DBAs',
    items: ['Student records', 'Course catalogue', 'Transcripts'],
    tags: ['Students', 'Courses', 'Transcripts'],
    about: 'What those programs read and write.' },
  { key: 'technology', z: 0, name: 'Technology', pal: 'green', comp: 'bone',
    owner: 'System and network admins',
    items: ['Web server', 'Database server', 'Network and firewall'],
    tags: ['Web', 'Database', 'Network'],
    about: 'The hardware it all runs on.' }
];

/* คำขอตัวอย่าง: ดัชนีของคอมโพเนนต์ที่ถูกเรียกในแต่ละชั้น */
const FLOWS = [
  { name: 'Enrol in a course', chain: [0, 0, 0, 1] },
  { name: 'Pay tuition fees', chain: [1, 1, 0, 1] },
  { name: 'Publish grades', chain: [2, 2, 2, 0] }
];

const SHADOW = [CX + 2.4, CY + 2.4];   /* เครื่องที่ไม่มีใครขึ้นทะเบียน */
const ATK = [4.895, 10.665];

ICS.register({
  id: 'infosys',
  title: 'Information Systems',
  sub: 'You cannot protect what you have never mapped. Before any control, learn to see the whole system — from the business process down to the hardware it runs on.',
  minutes: 12,
  level: 'Foundation',

  legend: [
    ['req sq', 'Business request'],
    ['res', 'Served successfully'],
    ['bad', 'Failed request / attack'],
    ['hollow', 'Asset on the inventory']
  ],

  metrics: [
    { key: 'ok', label: 'Requests served' },
    { key: 'failed', label: 'Requests failed', bad: true, tone: c => (c.stats.failed || 0) > 0 ? 'warn' : '' },
    { key: 'breach', label: 'Hits on unmanaged asset', bad: true, tone: c => (c.stats.breach || 0) > 0 ? 'warn' : '' },
    { key: 'blocked', label: 'Attacks blocked', tone: c => (c.stats.blocked || 0) > 0 ? 'lit' : '' },
    {
      key: 'inv', label: 'Assets inventoried',
      fmt: c => { const t = 12 + (c.cfg.shadow ? 1 : 0); return (12 + (c.cfg.shadow && c.cfg.mapped ? 1 : 0)) + ' / ' + t; },
      tone: c => (c.cfg.shadow && !c.cfg.mapped) ? 'warn' : 'lit'
    }
  ],

  learn: [
    ['An information system is people, process and technology together', 0],
    ['The four architecture layers: Business, Application, Data, Technology', 1],
    ['Every layer exists to support the layer above it', 2],
    ['One missing component breaks the business process above it', 3],
    ['An asset that is not on the inventory cannot be defended', 4]
  ],

  steps: [
    {
      tag: 'concept', label: 'One request', title: 'One click crosses the whole system',
      body: [
        'A student clicks <code>Enrol</code> on the registration site. That single click is not one thing happening in one place — it travels down through every layer of the system and comes back up again.',
        'Watch the token descend. The business process calls an application, the application reads and writes data, and the data lives on hardware somebody has to run. Each hop is a place where the request can be read, changed or stopped.'
      ],
      note: ['Why start here', 'Security work does not start with tools. It starts with being able to describe the system you are defending. If you cannot name what the request touches, you cannot say what happens when any part of it is attacked.'],
      changed: ['System: university registration', 'Layers: 4', 'Components: 12'],
      cfg: { detail: false, align: false, brk: 'none', shadow: false, mapped: false }
    },
    {
      tag: 'concept', label: 'Four layers', title: 'The four layers of enterprise architecture',
      body: [
        'Enterprise Architecture is the blueprint that keeps business and technology aligned. The TOGAF framework splits it into four layers: <code>Business</code> what the organisation does, <code>Application</code> the programs that do it, <code>Data</code> what they read and write, and <code>Technology</code> what it all runs on.',
        'Each layer now shows its components and the role responsible for it. Notice that the owners are different people with different skills — which is exactly why nobody sees the whole picture by accident.'
      ],
      note: ['Other frameworks', 'TOGAF is the most widely used. Zachman classifies artefacts by what, how, where, who, when and why. FEAF is used by US federal agencies, and the Gartner approach is lighter and business-driven.'],
      changed: ['Showing components and owners'],
      cfg: { detail: true, align: false, brk: 'none', shadow: false, mapped: false }
    },
    {
      tag: 'concept', label: 'Alignment', title: 'Alignment: each layer serves the one above',
      body: [
        'The vertical connectors are the point of the whole diagram. A layer is not valuable on its own — it exists to support the layer above it. An application nobody uses, or a server running nothing, is cost without purpose.',
        'Read it the other way and it becomes a security statement: every business process inherits the weaknesses of every layer underneath it. The registration process is only as trustworthy as the database server it ends up on.'
      ],
      note: ['The alignment question', 'For any component, ask upward "which business process would stop if this disappeared?" If no one can answer, you have either found something to decommission or something nobody understands. Both are worth knowing.'],
      changed: ['Showing alignment between layers'],
      cfg: { detail: true, align: true, brk: 'none', shadow: false, mapped: false }
    },
    {
      tag: 'problem', label: 'Broken link', title: 'One missing component stops the business',
      body: [
        'The database server is taken out — a failed disk, an expired certificate, a change nobody tested. The request now dies at the <code>Data</code> layer and never reaches the hardware.',
        'What the student sees is not "the database is down". They see that enrolment is broken. Use the control below to break a different layer and watch the same thing happen from a different cause.'
      ],
      note: ['Impact lives at the top', 'Incidents are reported in business language and diagnosed in technical language. The architecture map is what lets you translate between the two quickly, which is most of what incident response actually is.'],
      changed: ['Data layer: component unavailable'],
      cfg: { detail: true, align: true, brk: 'data', shadow: false, mapped: false },
      controls: ['brk']
    },
    {
      tag: 'problem', label: 'Off the map', title: 'The asset nobody wrote down',
      body: [
        'An old test server still sits on the network. It was built for a demo two years ago, it was never added to the inventory, and it is not on anybody\'s diagram. The business runs perfectly without it, so nobody notices it.',
        'An attacker scanning the network does notice it. It is unpatched because no patching job knows about it, unmonitored because no alert covers it, and connected to the same network as everything else. Look at the inventory panel: four layers are green, and there is still a red line.'
      ],
      note: ['Shadow IT', 'Unapproved and untracked systems appear in every organisation, usually for good reasons and in a hurry. The problem is not that someone built it, it is that the people responsible for defending the network do not know it exists.'],
      changed: ['Unmanaged asset found on the network'],
      cfg: { detail: true, align: true, brk: 'none', shadow: true, mapped: false }
    },
    {
      tag: 'technique', label: 'Inventory', title: 'Put it on the inventory, then it can be defended',
      body: [
        'Nothing clever happens here. The server is added to the asset register with an owner, a purpose and a lifecycle. Once it is on the list it falls inside patching, monitoring, backup and firewall policy automatically.',
        'The same attack now hits a managed asset and is stopped. This is why the very first control in almost every security standard is an inventory of assets, not a firewall.'
      ],
      note: ['What an inventory entry needs', 'Not just a hostname. It needs the owner, what business process it supports, what data it holds, and when it is due for review. Without the owner nobody will act on it, and without the data classification you cannot size the risk.'],
      changed: ['Asset registered, owner assigned', 'Covered by patching and monitoring'],
      cfg: { detail: true, align: true, brk: 'none', shadow: true, mapped: true }
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: what must the administrator know?',
      body: [
        'The guiding question for this topic is: to look after the registration system, what should the administrator know about it? Break each layer in turn and write down, in business words, what the user would report when it fails.',
        'Then go further than this diagram goes. A real map also carries the organisation\'s goals, its structure, its application portfolio, its data classification, its compliance obligations, its budget and its governance policies. The architecture is where those meet the servers.'
      ],
      note: ['Assignment 1 connects here', 'The EA exercise asks for an invented organisation described through TOGAF: business process, application, data, technology, plus a network diagram and a statement of what has to align between them. This lesson is that exercise in miniature.'],
      changed: [],
      cfg: { detail: true, align: true, brk: 'none', shadow: true, mapped: false },
      controls: ['brk', 'shadow', 'mapped']
    }
  ],

  controls: {
    brk: {
      type: 'seg', label: 'Make a layer unavailable',
      options: [['none', 'All healthy'], ['application', 'Application'], ['data', 'Data'], ['technology', 'Technology']],
      get: c => c.brk, set: (c, v) => { c.brk = v; }
    },
    shadow: { type: 'toggle', label: 'Unmanaged server on the network', hint: 'Shadow IT nobody tracks', get: c => c.shadow, set: (c, v) => { c.shadow = v; } },
    mapped: { type: 'toggle', label: 'Add it to the asset inventory', hint: 'Gives it an owner and a lifecycle', get: c => c.mapped, set: (c, v) => { c.mapped = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      trace: [], flow: 0, active: -1,
      P: {
        /* จุดบนคอมโพเนนต์แต่ละชิ้นของแต่ละชั้น */
        c: LAYERS.map(L => [0, 1, 2].map(i => {
          const o = (i - 1) * OFF;
          return iso(CX + o, CY - o, L.z + 0.25 + 0.5);
        })),
        shadow: iso(SHADOW[0], SHADOW[1], 0.55),
        atk: iso(ATK[0], ATK[1] - 0.4, 0.7)
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, L = ctx.L, PAL = ctx.PAL;

    /* เส้นเชื่อมแนวตั้งระหว่างชั้น วาดในชั้น fx เพื่อให้อยู่หน้าแผ่น ไม่งั้นโดนบังหมด */
    S.alignLines = [];
    for (let i = 0; i < LAYERS.length - 1; i++) {
      for (const o of [-OFF, 0, OFF]) {
        S.alignLines.push(ctx.line(
          iso(CX + o, CY - o, LAYERS[i].z + 0.25),
          iso(CX + o, CY - o, LAYERS[i + 1].z + 0.8), 'wire', L.fx));
      }
    }

    /* ชั้นสถาปัตยกรรม วาดจากล่างขึ้นบน */
    S.layers = LAYERS.slice().reverse().map(def => {
      const g = ctx.el('g', {}, L.ents);
      const pal = PAL[def.pal];
      ctx.block(g, CX, CY, HALF * 2, HALF * 2, 0.25, def.z, pal[0], pal[1], 12);
      const top = g.querySelector('.slab-top');
      const comps = [0, 1, 2].map(i => {
        const o = (i - 1) * OFF;
        const cg = ctx.el('g', {}, g);
        const cp = ctx.PAL[def.comp];
        ctx.block(cg, CX + o, CY - o, 0.78, 0.78, 0.5, def.z + 0.25, cp[0], cp[1], 4);
        return cg;
      });
      const edge = iso(CX - HALF, CY + HALF, def.z + 0.25);
      const pill = ctx.pill(L.labels, edge[0] - 10, edge[1], [def.name], 'end');
      return { def, g, top, comps, pill };
    }).reverse();

    /* เครื่องที่ไม่ได้ขึ้นทะเบียน + ผู้โจมตี */
    S.shadowG = ctx.el('g', {}, L.ents);
    ctx.block(S.shadowG, SHADOW[0], SHADOW[1], 1.0, 1.0, 0.22, 0, PAL.grey[0], PAL.grey[1], 7);
    S.shadowBox = ctx.el('g', {}, S.shadowG);
    ctx.block(S.shadowBox, SHADOW[0], SHADOW[1], 0.75, 0.75, 0.55, 0.22, PAL.dark[0], PAL.dark[1], 4);
    const sq = iso(SHADOW[0], SHADOW[1], 0.95);
    const qm = ctx.el('text', { class: 'slot-num', x: sq[0], y: sq[1] - 2 }, S.shadowG);
    qm.textContent = '?';
    S.shadowPill = ctx.pill(L.labels, iso(SHADOW[0], SHADOW[1] + 0.9, 0)[0], iso(SHADOW[0], SHADOW[1] + 0.9, 0)[1] + 14, ['Old test server', '']);
    S.shadowWire = ctx.line(iso(ATK[0], ATK[1], 0.2), iso(SHADOW[0], SHADOW[1], 0.2), 'wire tap', L.wires);

    S.atkG = ctx.el('g', {}, L.ents);
    ctx.actor.attacker(S.atkG, ATK[0], ATK[1]);
    S.atkPill = ctx.pill(L.labels, S.P.atk[0] - 4, iso(ATK[0], ATK[1] + 0.85, 0)[1] + 14, ['Scanner', '']);

    /* แผงด้านขวา */
    S.invP = ctx.statusList(L.hud, {
      x: 440, y: 84, w: 276, title: 'Asset inventory',
      items: LAYERS.map(l => l.name).concat(['Unmanaged'])
    });
    S.traceP = ctx.panel(L.hud, { x: 440, y: 220, w: 276, rows: 5, title: 'Request trace', dark: true });
    S.layerP = ctx.panel(L.hud, { x: 440, y: 340, w: 276, rows: 4, title: 'Layer detail' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;

    if (ctx.timer('req', dt, 2600)) {
      const f = FLOWS[S.flow++ % FLOWS.length];
      S.trace = [{ t: '› ' + f.name, cls: 'term' }];
      S.active = 0;
      ctx.launch([[P.c[0][f.chain[0]][0], P.c[0][f.chain[0]][1] - 46], P.c[0][f.chain[0]]], 'plain',
        { label: f.name.length > 15 ? f.name.slice(0, 15) + '…' : f.name, meta: { leg: 'layer', li: 0, f }, speed: 170 });
    }
    if (cfg.shadow && ctx.timer('scan', dt, 2100)) {
      ctx.launch([P.atk, P.shadow], 'bad', { label: 'scan', meta: { leg: 'scan' }, speed: 240 });
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;

    if (m.leg === 'scan') {
      if (cfg.mapped) {
        ctx.bump('blocked'); ctx.puff(P.shadow, 'ok');
        ctx.float([P.shadow[0], P.shadow[1] - 26], 'blocked', 'ok');
      } else {
        ctx.bump('breach'); ctx.ring(P.shadow);
        ctx.float([P.shadow[0], P.shadow[1] - 26], 'reached', 'bad');
      }
      return;
    }

    if (m.leg === 'layer') {
      const L = LAYERS[m.li];
      const idx = m.f.chain[m.li];
      S.active = m.li;

      if (cfg.brk === L.key) {
        ctx.bump('failed'); ctx.puff(P.c[m.li][idx]);
        ctx.float([P.c[m.li][idx][0], P.c[m.li][idx][1] - 24], 'unavailable', 'bad');
        S.trace.push({ t: '✗ ' + L.name + ' · ' + L.items[idx], cls: 'term-bad' });
        S.trace.push({ t: '  request fails, business stops', cls: 'term-bad' });
        S.active = -1;
        return;
      }
      S.trace.push({ t: '  ' + L.name + ' · ' + L.items[idx], cls: 'term' });

      if (m.li + 1 < LAYERS.length) {
        const nx = m.f.chain[m.li + 1];
        ctx.launch([P.c[m.li][idx], P.c[m.li + 1][nx]], 'plain',
          { label: LAYERS[m.li + 1].items[nx].length > 15 ? LAYERS[m.li + 1].items[nx].slice(0, 15) + '…' : LAYERS[m.li + 1].items[nx],
            meta: { leg: 'layer', li: m.li + 1, f: m.f }, speed: 170 });
      } else {
        ctx.launch([P.c[3][idx], P.c[0][m.f.chain[0]]], 'res', { meta: { leg: 'done' }, speed: 400 });
      }
      return;
    }

    if (m.leg === 'done') {
      ctx.bump('ok');
      S.trace.push({ t: '✓ served back to the student', cls: 'term' });
      S.active = -1;
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;

    S.layers.forEach((l, i) => {
      const broken = cfg.brk === l.def.key;
      l.comps.forEach(c => c.setAttribute('opacity', cfg.detail ? 1 : 0.25));
      l.top.setAttribute('opacity', broken ? 0.45 : 1);
      l.pill.set([l.def.name]);
      l.pill.tone(broken ? 'hot' : i === S.active ? 'ok' : cfg.detail ? '' : 'dead');
      S.invP.set(i, broken ? 'bad' : 'ok', broken ? 'unavailable' : '3 mapped');
    });

    S.alignLines.forEach(w => w.setAttribute('class', cfg.align ? 'wire strong' : 'wire off'));

    const show = cfg.shadow ? 'inline' : 'none';
    S.shadowG.setAttribute('display', show);
    S.atkG.setAttribute('display', show);
    S.shadowPill.g.setAttribute('display', show);
    S.atkPill.g.setAttribute('display', show);
    S.shadowWire.setAttribute('class', 'wire tap' + (cfg.shadow ? '' : ' off'));
    if (cfg.shadow) {
      S.shadowBox.setAttribute('opacity', cfg.mapped ? 1 : 0.85);
      S.shadowPill.set(['Old test server', cfg.mapped ? 'on the inventory' : 'not on any list']);
      S.shadowPill.tone(cfg.mapped ? 'ok' : 'hot');
      S.atkPill.set(['Scanner', cfg.mapped ? 'blocked' : 'got in']);
      S.atkPill.tone(cfg.mapped ? 'dead' : 'hot');
    }
    S.invP.set(4, !cfg.shadow ? 'ok' : cfg.mapped ? 'ok' : 'bad',
      !cfg.shadow ? 'none' : cfg.mapped ? 'now managed' : '1 unknown');

    for (let i = 0; i < 5; i++) {
      const r = S.trace[i];
      S.traceP.set(i, r ? r.t : (i === 0 ? '— waiting for a request —' : ''), r ? r.cls : 'term dim');
    }

    const L = S.active >= 0 ? LAYERS[S.active] : null;
    if (!L) {
      S.layerP.set(0, cfg.detail ? 'Four layers, twelve components' : 'Enterprise architecture', 'ok');
      S.layerP.set(1, cfg.detail ? 'Business, App, Data, Technology' : 'One request crosses every layer', 'dim');
      S.layerP.set(2, cfg.shadow && !cfg.mapped ? 'Plus one asset nobody wrote down' : '', cfg.shadow && !cfg.mapped ? 'bad' : 'dim');
      S.layerP.set(3, '', '');
    } else {
      S.layerP.set(0, L.name + ' architecture', 'ok');
      S.layerP.set(1, L.about, 'dim');
      S.layerP.set(2, 'Owner: ' + L.owner, 'dim');
      S.layerP.set(3, L.tags.join(' · '), 'mono');
    }
  }
});
})();
