/* ============================================================
   บทที่ 1.2 — ภัยคุกคาม ช่องโหว่ และความเสี่ยง
   asset · vulnerability · threat · risk = โอกาส × ผลกระทบ
   ============================================================ */
(function () {
/* ผู้ก่อภัยคุกคาม (ซ้าย) */
const THREATS = [
  { p: [-1.5, 3.7], name: 'บอตสแกนอัตโนมัติ', prefer: [1, 2] },
  { p: [0.3, 5.5], name: 'คนในที่มีสิทธิ์', prefer: [0] },
  { p: [2.1, 7.3], name: 'กลุ่มเรียกค่าไถ่', prefer: [0, 1, 2] }
];
/* ช่องโหว่ 4 ช่อง (กลาง) — ช่อง 0–2 เพิ่มโอกาสเกิด ช่อง 3 เพิ่มผลกระทบ */
const SLOTS = [
  { p: [1.9, 0.7], key: 'cPass', label: '1 รหัสผ่านอ่อนแอ', fix: 'บังคับรหัสแข็งแรง + MFA' },
  { p: [3.05, 1.85], key: 'cPatch', label: '2 ซอฟต์แวร์ไม่อัปเดต', fix: 'อัปเดตอัตโนมัติ' },
  { p: [4.2, 3.0], key: 'cPort', label: '3 เปิดพอร์ตจัดการ', fix: 'ปิดพอร์ต ใช้ VPN' },
  { p: [5.35, 4.15], key: 'cBackup', label: '4 ไม่มีสำรองข้อมูล', fix: 'สำรองข้อมูลนอกสถานที่' }
];
const ASSET = [5.7, 0.3];

const LIKELY = [1, 2, 4, 5];           // จากจำนวนช่องโหว่ที่ยังเปิด (0–3)
const LEVEL = [[4, 'ต่ำ', 'ok'], [9, 'ปานกลาง', ''], [14, 'สูง', 'bad'], [99, 'วิกฤต', 'bad']];
const cellFill = s => s <= 4 ? '#e8efd9' : s <= 9 ? '#f6e6c9' : s <= 14 ? '#fcdcbd' : '#f8d5cf';

function levelOf(score) { for (const l of LEVEL) if (score <= l[0]) return l; return LEVEL[3]; }
const openCount = cfg => SLOTS.slice(0, 3).filter(s => !cfg[s.key]).length;
const likelihood = cfg => LIKELY[openCount(cfg)];
const impact = cfg => cfg.cBackup ? 2 : 5;

/* ตารางความเสี่ยง 5×5 */
function riskMatrix(ctx, parent, x0, y0, cell) {
  const g = ctx.el('g', {}, parent);
  ctx.el('rect', { class: 'pn-shadow', x: x0 - 12, y: y0 - 24, width: cell * 5 + 24, height: cell * 5 + 54, rx: 9 }, g);
  ctx.el('rect', { class: 'pn-bg', x: x0 - 14, y: y0 - 27, width: cell * 5 + 24, height: cell * 5 + 54, rx: 9 }, g);
  const t = ctx.el('text', { class: 'pn-title', x: x0 - 4, y: y0 - 12 }, g); t.textContent = 'ตารางความเสี่ยง';
  for (let l = 1; l <= 5; l++) for (let i = 1; i <= 5; i++) {
    ctx.el('rect', {
      class: 'rm-cell', x: x0 + (l - 1) * cell, y: y0 + (5 - i) * cell,
      width: cell, height: cell, fill: cellFill(l * i)
    }, g);
  }
  const cap = ctx.el('text', { class: 'rm-ax', x: x0 - 4, y: y0 + cell * 5 + 16 }, g);
  cap.textContent = 'โอกาส →   ผลกระทบ ↑';
  const dot = ctx.el('circle', { class: 'rm-dot', r: 3.4, cx: x0, cy: y0 }, g);
  const ring = ctx.el('circle', { class: 'rm-mark', r: 9, cx: x0, cy: y0 }, g);
  return {
    at(l, i) {
      const cx = x0 + (l - 0.5) * cell, cy = y0 + (5 - i + 0.5) * cell;
      [dot, ring].forEach(e => { e.setAttribute('cx', cx.toFixed(1)); e.setAttribute('cy', cy.toFixed(1)); });
    }
  };
}

ICS.register({
  id: 'risk',
  title: 'ภัยคุกคาม ช่องโหว่ และความเสี่ยง',
  sub: 'คำสามคำที่คนใช้ปนกันตลอด แต่แยกให้ออกเมื่อไร การตัดสินใจว่าจะลงทุนป้องกันตรงไหนก็ง่ายขึ้นทันที',
  minutes: 11,
  level: 'พื้นฐาน',

  legend: [
    ['bad', 'การโจมตีที่พุ่งเข้าหาช่องโหว่'],
    ['res', 'ถูกบล็อกที่มาตรการควบคุม'],
    ['hollow', 'ช่องโหว่ที่ปิดแล้ว'],
    ['req sq', 'ทรัพย์สินที่ต้องปกป้อง']
  ],

  metrics: [
    { key: 'hit', label: 'ทะลุถึงทรัพย์สิน', bad: true, tone: c => (c.stats.hit || 0) > 0 ? 'warn' : '' },
    { key: 'blocked', label: 'ถูกบล็อก', tone: c => (c.stats.blocked || 0) > 0 ? 'lit' : '' },
    { key: 'loss', label: 'เสียหายกู้ไม่ได้', bad: true },
    { key: 'l', label: 'โอกาสเกิด', fmt: c => likelihood(c.cfg) + ' / 5' },
    { key: 'i', label: 'ผลกระทบ', fmt: c => impact(c.cfg) + ' / 5' },
    {
      key: 'lv', label: 'ระดับความเสี่ยง',
      fmt: c => { const s = likelihood(c.cfg) * impact(c.cfg); return levelOf(s)[1] + ' (' + s + ')'; },
      tone: c => { const lv = levelOf(likelihood(c.cfg) * impact(c.cfg)); return lv[2] === 'ok' ? 'lit' : lv[2] === 'bad' ? 'warn' : ''; }
    }
  ],

  learn: [
    ['ทรัพย์สินคือสิ่งที่เราปกป้อง ไม่ใช่เครื่องเซิร์ฟเวอร์', 0],
    ['ช่องโหว่คือจุดอ่อนที่มีอยู่ในระบบของเราเอง', 1],
    ['ภัยคุกคามที่ไม่มีช่องโหว่ให้ใช้ ไม่กลายเป็นความเสี่ยง', 2],
    ['ความเสี่ยง = โอกาสเกิด × ผลกระทบ', 3],
    ['มาตรการบางอย่างลดโอกาส บางอย่างลดผลกระทบ', 5]
  ],

  steps: [
    {
      tag: 'concept', label: 'ทรัพย์สิน', title: 'เริ่มจากถามว่าเรากำลังปกป้องอะไร',
      body: [
        'งานความปลอดภัยไม่ได้เริ่มที่เครื่องมือ แต่เริ่มที่การรู้ว่าอะไรมีค่าและมีค่าแค่ไหน สิ่งนั้นเรียกว่า <code>ทรัพย์สิน</code> ซึ่งไม่ใช่ตัวเซิร์ฟเวอร์ แต่คือข้อมูลลูกค้า ความต่อเนื่องของบริการ และชื่อเสียงที่อยู่ในนั้น',
        'กล่องขวามือคือระบบที่เก็บข้อมูลลูกค้าทั้งหมด ถ้าตอบไม่ได้ว่ามันมีค่าเท่าไร ก็ตอบไม่ได้ว่าควรจ่ายเท่าไรเพื่อปกป้องมัน'
      ],
      note: ['ทำไมต้องเริ่มตรงนี้', 'งบประมาณมีจำกัดเสมอ การจัดลำดับว่าจะปกป้องอะไรก่อนต้องอิงมูลค่า ไม่ใช่อิงว่าเทคโนโลยีไหนกำลังเป็นที่นิยม'],
      changed: ['ทรัพย์สิน: ฐานข้อมูลลูกค้า', 'ยังไม่ได้ประเมินอะไรทั้งนั้น'],
      cfg: { cPass: false, cPatch: false, cPort: false, cBackup: false, threats: 1, matrix: false }
    },
    {
      tag: 'concept', label: 'ช่องโหว่', title: 'ช่องโหว่คือจุดอ่อนที่อยู่ในบ้านเราเอง',
      body: [
        '<code>ช่องโหว่</code> คือสภาพของระบบเราที่เปิดให้ถูกทำร้ายได้ สังเกตแนวกั้นตรงกลางที่มีสี่ช่อง แต่ละช่องคือจุดอ่อนหนึ่งข้อ ตอนนี้เปิดโล่งทั้งสี่ช่อง',
        'จุดสำคัญคือช่องโหว่เป็นเรื่องของเรา ไม่ใช่ของผู้โจมตี เราควบคุมมันได้เองทั้งหมด และมันมีอยู่แม้ไม่มีใครมาโจมตีเลยสักคน'
      ],
      note: ['ช่องโหว่มาจากไหน', 'มาจากบั๊กในโค้ด การตั้งค่าที่หละหลวม ซอฟต์แวร์ที่หมดอายุ และกระบวนการทำงานที่ไม่รัดกุม สามอย่างหลังไม่ใช่เรื่องเทคนิคเลยด้วยซ้ำ'],
      changed: ['พบช่องโหว่ 4 ข้อ'],
      cfg: { cPass: false, cPatch: false, cPort: false, cBackup: false, threats: 1, matrix: false }
    },
    {
      tag: 'concept', label: 'ภัยคุกคาม', title: 'ภัยคุกคามคือสิ่งที่อยู่นอกการควบคุมของเรา',
      body: [
        '<code>ภัยคุกคาม</code> คือใครหรืออะไรที่อาจใช้ช่องโหว่ทำร้ายเรา ทางซ้ายมีสามแบบที่ต่างกันชัดเจน บอตที่ยิงมั่วทั้งอินเทอร์เน็ต คนในที่มีสิทธิ์อยู่แล้ว และกลุ่มที่ตั้งใจมาเรียกค่าไถ่',
        'เราสั่งให้ภัยคุกคามหายไปไม่ได้ สิ่งเดียวที่ทำได้คือปิดช่องโหว่ที่มันจะใช้ ลองจำประโยคนี้ไว้ ภัยคุกคามที่ไม่มีช่องโหว่ให้ใช้ จะไม่กลายเป็นความเสี่ยง'
      ],
      note: ['ภัยคุกคามไม่ได้มีแต่คน', 'ไฟไหม้ น้ำท่วม ไฟดับ ฮาร์ดดิสก์พัง และความผิดพลาดของพนักงานเองก็เป็นภัยคุกคาม และหลายครั้งทำความเสียหายมากกว่าแฮกเกอร์'],
      changed: ['ภัยคุกคาม: 3 แหล่ง'],
      cfg: { cPass: false, cPatch: false, cPort: false, cBackup: false, threats: 3, matrix: false }
    },
    {
      tag: 'concept', label: 'ความเสี่ยง', title: 'ความเสี่ยง = โอกาสเกิด × ผลกระทบ',
      body: [
        'เอาสองอย่างมาคูณกันถึงจะได้ <code>ความเสี่ยง</code> ซึ่งเป็นตัวเลขที่เอาไปเทียบลำดับความสำคัญได้ ตอนนี้ช่องโหว่เปิดครบสามข้อ โอกาสเกิดจึงสูงสุด และไม่มีสำรองข้อมูล ผลกระทบจึงสูงสุดเช่นกัน',
        'จุดดำในตารางมุมขวาล่างอยู่มุมขวาบน ซึ่งคือช่องวิกฤต ตารางนี้ไม่ได้มีไว้ให้สวย แต่มีไว้ตอบคำถามว่าเรื่องไหนต้องแก้ก่อน'
      ],
      note: ['เรื่องที่คนมองข้าม', 'ช่องโหว่ที่เจาะยากมากแต่ถ้าสำเร็จแล้วบริษัทล้ม อาจสำคัญกว่าช่องโหว่ที่เจาะง่ายแต่เสียหายแค่หลักร้อยบาท การคูณกันช่วยให้เห็นเรื่องนี้'],
      changed: ['เปิดการประเมินความเสี่ยง'],
      cfg: { cPass: false, cPatch: false, cPort: false, cBackup: false, threats: 3, matrix: true }
    },
    {
      tag: 'technique', label: 'ลดโอกาส', title: 'มาตรการควบคุมที่ลดโอกาสเกิด',
      body: [
        'ปิดช่องโหว่สามข้อแรกด้วยมาตรการที่ตรงกัน บังคับรหัสผ่านแข็งแรงพร้อม MFA อัปเดตซอฟต์แวร์อัตโนมัติ และปิดพอร์ตจัดการไม่ให้ออกสู่อินเทอร์เน็ต',
        'การโจมตีทุกครั้งถูกหยุดตั้งแต่แนวกั้น จุดดำเลื่อนไปทางซ้ายจนสุด แต่สังเกตให้ดีว่ามันยังอยู่แถวบน เพราะผลกระทบยังไม่ได้ถูกแตะต้องเลย'
      ],
      note: ['ลดไม่ได้แปลว่าหมด', 'ไม่มีมาตรการไหนทำให้โอกาสเป็นศูนย์ สิ่งที่เหลืออยู่เรียกว่าความเสี่ยงคงเหลือ ซึ่งต้องมีคนรับผิดชอบตัดสินใจว่ายอมรับได้ไหม'],
      changed: ['ปิดช่องโหว่ 1, 2, 3'],
      cfg: { cPass: true, cPatch: true, cPort: true, cBackup: false, threats: 3, matrix: true }
    },
    {
      tag: 'technique', label: 'ลดผลกระทบ', title: 'มาตรการที่ลดผลกระทบ ไม่ใช่โอกาส',
      body: [
        'การสำรองข้อมูลไม่ได้ทำให้ใครเจาะเราได้ยากขึ้นเลยแม้แต่นิดเดียว โอกาสเกิดเท่าเดิมเป๊ะ แต่ถ้าวันหนึ่งโดนเข้าจริง ความเสียหายต่างกันคนละเรื่อง',
        'จุดดำเลื่อนลงมาด้านล่าง ความเสี่ยงกลายเป็นระดับต่ำ นี่คือเหตุผลที่ต้องมีมาตรการทั้งสองชนิด ถ้ามีแต่ชนิดที่ลดโอกาส วันที่พลาดขึ้นมาจะเจ็บเต็มๆ'
      ],
      note: ['แผนสำรองที่ไม่เคยทดสอบ', 'สำรองข้อมูลที่ไม่เคยลองกู้คืนจริง นับว่าไม่มี องค์กรจำนวนมากค้นพบตอนโดนแรนซัมแวร์ว่าไฟล์สำรองของตัวเองก็ถูกเข้ารหัสไปด้วย'],
      changed: ['ปิดช่องโหว่ 4: สำรองข้อมูล'],
      cfg: { cPass: true, cPatch: true, cPort: true, cBackup: true, threats: 3, matrix: true }
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: เลือกว่าจะจ่ายกับอะไรก่อน',
      body: [
        'สมมติว่ามีงบพอปิดช่องโหว่ได้แค่สองข้อ ลองเปิดปิดดูว่าคู่ไหนทำให้ระดับความเสี่ยงต่ำที่สุด คำตอบอาจไม่ใช่สองข้อที่ดู "เทคนิคจ๋า" ที่สุด',
        'นอกจากการลดความเสี่ยงแล้ว ยังมีอีกสามทางเลือกที่ถูกต้องพอกัน <code>โอน</code> ด้วยการทำประกันหรือจ้างคนอื่นดูแล <code>เลี่ยง</code> ด้วยการเลิกเก็บข้อมูลที่ไม่จำเป็นตั้งแต่แรก และ <code>ยอมรับ</code> เมื่อค่าป้องกันแพงกว่าความเสียหายที่อาจเกิด'
      ],
      note: ['ข้อมูลที่ไม่ได้เก็บ รั่วไม่ได้', 'วิธีลดความเสี่ยงที่ถูกมองข้ามที่สุดคือการเลิกเก็บข้อมูลที่ไม่ได้ใช้จริง ไม่ต้องป้องกันสิ่งที่ไม่มีอยู่'],
      changed: [],
      cfg: { cPass: false, cPatch: true, cPort: false, cBackup: false, threats: 3, matrix: true },
      controls: ['cPass', 'cPatch', 'cPort', 'cBackup']
    }
  ],

  controls: {
    cPass: { type: 'toggle', label: 'บังคับรหัสแข็งแรง + MFA', hint: 'ปิดช่องโหว่ที่ 1 · ลดโอกาส', get: c => c.cPass, set: (c, v) => { c.cPass = v; } },
    cPatch: { type: 'toggle', label: 'อัปเดตซอฟต์แวร์อัตโนมัติ', hint: 'ปิดช่องโหว่ที่ 2 · ลดโอกาส', get: c => c.cPatch, set: (c, v) => { c.cPatch = v; } },
    cPort: { type: 'toggle', label: 'ปิดพอร์ตจัดการ ใช้ VPN', hint: 'ปิดช่องโหว่ที่ 3 · ลดโอกาส', get: c => c.cPort, set: (c, v) => { c.cPort = v; } },
    cBackup: { type: 'toggle', label: 'สำรองข้อมูลนอกสถานที่', hint: 'ปิดช่องโหว่ที่ 4 · ลดผลกระทบ', get: c => c.cBackup, set: (c, v) => { c.cBackup = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      P: {
        t: THREATS.map(t => iso(t.p[0], t.p[1] - 0.45, 0.7)),
        s: SLOTS.map(s => iso(s.p[0], s.p[1], 0.75)),
        a: iso(ASSET[0] - 0.7, ASSET[1], 0.8)
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    SLOTS.forEach(s => ctx.line(iso(s.p[0], s.p[1], 0.2), iso(ASSET[0], ASSET[1], 0.2), 'wire', L.wires));

    /* แนวกั้น 4 ช่อง */
    S.slots = SLOTS.map((s, i) => {
      const g = ctx.el('g', {}, L.ents);
      ctx.block(g, s.p[0], s.p[1], 1.05, 1.05, 0.18, 0, ctx.PAL.grey[0], ctx.PAL.grey[1], 7);
      const shield = ctx.el('g', {}, g);
      const b = ctx.block(shield, s.p[0], s.p[1], 0.78, 0.78, 0.95, 0.18, ctx.PAL.green[0], ctx.PAL.green[1], 4);
      ctx.glyph.lock(shield, iso(s.p[0], s.p[1], b.zt));
      const gap = ctx.el('g', {}, g);
      const c = iso(s.p[0], s.p[1], 0.3);
      ctx.line([c[0] - 9, c[1] - 5], [c[0] + 9, c[1] + 5], 'gap-x', gap);
      ctx.line([c[0] - 9, c[1] + 5], [c[0] + 9, c[1] - 5], 'gap-x', gap);
      const n = ctx.el('text', { class: 'slot-num', x: c[0], y: c[1] - 34 }, g);
      n.textContent = String(i + 1);
      return { shield, gap, g };
    });

    /* ผู้ก่อภัยคุกคาม */
    S.threats = THREATS.map((t, i) => {
      const g = ctx.el('g', {}, L.ents);
      Ac.attacker(g, t.p[0], t.p[1]);
      const pp = iso(t.p[0], t.p[1], 0);
      const pill = ctx.pill(L.labels, pp[0] - 4, pp[1] + 34, [t.name]);
      return { g, pill };
    });

    /* ทรัพย์สิน */
    const ag = ctx.el('g', { class: 'node' }, L.ents);
    Ac.server(ag, ASSET[0], ASSET[1], 'bone', 1.7);
    S.assetG = ag;
    S.assetPill = ctx.pill(L.labels, iso(ASSET[0] + 0.95, ASSET[1] + 0.95, 0)[0], iso(ASSET[0] + 0.95, ASSET[1] + 0.95, 0)[1] + 18, ['ฐานข้อมูลลูกค้า', '']);

    S.vuln = ctx.statusList(L.hud, {
      x: 126, y: 78, w: 256, title: 'ช่องโหว่ที่พบในระบบ',
      items: SLOTS.map(s => s.label)
    });
    S.matrixG = ctx.el('g', {}, L.hud);
    S.matrix = riskMatrix(ctx, S.matrixG, 548, 330, 24);
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    const n = cfg.threats;
    if (ctx.timer('atk', dt, n === 1 ? 2600 : 850)) {
      const ti = Math.floor(Math.random() * n);
      const pref = THREATS[ti].prefer;
      const si = pref[Math.floor(Math.random() * pref.length)];
      ctx.launch([P.t[ti], P.s[si]], 'bad', { meta: { leg: 'slot', si }, speed: 300, r: 4.6 });
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    if (m.leg === 'slot') {
      if (cfg[SLOTS[m.si].key] && Math.random() < 0.88) { ctx.bump('blocked'); ctx.puff(P.s[m.si], 'ok'); return; }
      /* ที่เหลือคือความเสี่ยงคงเหลือ ไม่มีมาตรการไหนกันได้ 100% */
      ctx.launch([P.s[m.si], P.a], 'bad', { meta: { leg: 'asset', residual: !!cfg[SLOTS[m.si].key] }, speed: 300, r: 4.6 });
      return;
    }
    if (m.leg === 'asset') {
      ctx.bump('hit'); ctx.ring(P.a);
      const top = [P.a[0], P.a[1] - 30];
      if (!cfg.cBackup) { ctx.bump('loss'); ctx.float(top, m.residual ? 'เล็ดลอดเข้ามา' : 'ข้อมูลหาย', 'bad'); }
      else ctx.float(top, 'กู้คืนได้', 'ok');
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;

    S.slots.forEach((s, i) => {
      const closed = !!cfg[SLOTS[i].key];
      s.shield.setAttribute('display', closed ? 'inline' : 'none');
      s.gap.setAttribute('display', closed ? 'none' : 'inline');
      S.vuln.set(i, closed ? 'ok' : 'bad', closed ? 'ปิดแล้ว' : 'เปิดอยู่');
    });

    S.threats.forEach((t, i) => {
      const on = i < cfg.threats;
      t.g.setAttribute('opacity', on ? 1 : 0.22);
      t.pill.tone(on ? 'hot' : 'dead');
    });

    const hit = ctx.stats.hit || 0;
    S.assetG.classList.toggle('hot', hit > 0 && !cfg.cBackup);
    S.assetPill.set(['ฐานข้อมูลลูกค้า', cfg.cBackup ? 'มีสำรอง' : 'ไม่มีสำรอง']);
    S.assetPill.tone(cfg.cBackup ? 'ok' : 'hot');

    S.matrixG.setAttribute('display', cfg.matrix ? 'inline' : 'none');
    if (cfg.matrix) S.matrix.at(likelihood(cfg), impact(cfg));
  }
});
})();
