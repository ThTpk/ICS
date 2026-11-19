/* ============================================================
   บทที่ 5.2 — การควบคุมสิทธิ์แบบ RBAC
   ให้สิทธิ์ตรงต่อคน → บทบาท → สิทธิ์สะสม → ตรวจความเป็นเจ้าของ
   ============================================================ */
(function () {
const USERS = [
  { id: 'ann', p: [-2.5, 2.5], team: 'ขาย', roles: ['sales'] },
  { id: 'bob', p: [-1.2, 3.8], team: 'ขาย (ย้ายมาจากบัญชี)', roles: ['sales', 'finance'], old: 'finance' },
  { id: 'cat', p: [0.05, 5.05], team: 'แอดมิน', roles: ['admin'] }
];
const POLICY = [1.6, 1.0];
const RES = [
  { p: [2.8, -2.8], name: 'ใบแจ้งหนี้', pal: 'blue' },
  { p: [4.05, -1.55], name: 'รายงานเงินเดือน', pal: 'sand' },
  { p: [5.3, -0.3], name: 'ตั้งค่าระบบ', pal: 'rose' }
];
const ROLE = {
  sales: ['invoice:read', 'invoice:write'],
  finance: ['invoice:read', 'payroll:read'],
  admin: ['invoice:read', 'payroll:read', 'settings:admin']
};
const DIRECT = {
  ann: ['invoice:read', 'invoice:write'],
  bob: ['invoice:read', 'invoice:write', 'payroll:read'],   // ตกค้างจากตอนอยู่ฝ่ายบัญชี
  cat: ['invoice:read', 'payroll:read', 'settings:admin']
};
/* คำขอที่ไล่เป็นรอบ ครอบคลุมทุกเคสที่บทเรียนอธิบาย: [ผู้ขอ, สิทธิ์, เจ้าของรายการเมื่อเปิดโหมดข้ามเจ้าของ] */
const CYCLE = [
  ['ann', 'invoice:read', null],
  ['bob', 'payroll:read', null],
  ['ann', 'invoice:read', 'bob'],
  ['cat', 'settings:admin', null],
  ['bob', 'invoice:write', null],
  ['ann', 'settings:admin', null],
  ['bob', 'invoice:read', 'ann'],
  ['cat', 'payroll:read', null]
];
const PERM_RES = { 'invoice:read': 0, 'invoice:write': 0, 'payroll:read': 1, 'settings:admin': 2 };
const SHORT = { 'invoice:read': 'invoice:r', 'invoice:write': 'invoice:w', 'payroll:read': 'payroll:r', 'settings:admin': 'settings' };

function permsOf(cfg, u) {
  if (cfg.mode === 'direct') return DIRECT[u.id];
  const roles = cfg.creep ? u.roles : u.roles.filter(r => r !== u.old);
  const out = [];
  roles.forEach(r => ROLE[r].forEach(p => { if (!out.includes(p)) out.push(p); }));
  return out;
}
function decide(cfg, u, req) {
  const P = permsOf(cfg, u);
  if (!P.includes(req.perm)) return { allow: false, why: 'ไม่มีสิทธิ์ ' + SHORT[req.perm] };
  if (req.owner && req.owner !== u.id && cfg.ownership) return { allow: false, why: 'ไม่ใช่เจ้าของรายการนี้' };
  return { allow: true, why: 'มีสิทธิ์ ' + SHORT[req.perm] };
}

function tableLines(cfg) {
  if (cfg.mode === 'direct') {
    return [
      ['ให้สิทธิ์ตรงต่อผู้ใช้ทีละคน ไม่มีบทบาท', 'dim'],
      ['ann  → invoice:read, invoice:write', 'mono'],
      ['bob  → invoice:read, invoice:write, payroll:read', 'bad mono'],
      ['cat  → invoice:read, payroll:read, settings:admin', 'mono'],
      ['เพิ่มคนใหม่ = ไล่ก๊อปทุกบรรทัดด้วยมือ', 'dim']
    ];
  }
  const b = cfg.creep ? 'ขาย + บัญชี' : 'ขาย';
  return [
    ['ผู้ใช้   บทบาท           สิทธิ์ที่ได้จากบทบาท', 'dim'],
    ['ann     ขาย             invoice:read / write', 'mono'],
    ['bob     ' + (b + '             ').slice(0, 15) + (cfg.creep ? 'invoice r/w + payroll:r' : 'invoice:read / write'), cfg.creep ? 'bad mono' : 'mono'],
    ['cat     แอดมิน          invoice:r, payroll:r, settings', 'mono'],
    [cfg.ownership ? 'ทุกคำขอถูกตรวจความเป็นเจ้าของอีกชั้น' : 'ยังไม่ตรวจว่ารายการนั้นเป็นของใคร',
      cfg.ownership ? 'ok' : 'bad']
  ];
}

ICS.register({
  id: 'rbac',
  title: 'การควบคุมสิทธิ์แบบ RBAC',
  sub: 'รู้ว่าเป็นใครแล้วยังไม่พอ ต้องตอบให้ได้ด้วยว่าคนนั้นทำอะไรกับของชิ้นไหนได้บ้าง',
  minutes: 12,
  level: 'ระดับกลาง',

  legend: [
    ['req sq', 'คำขอจากผู้ใช้'],
    ['res', 'อนุญาต'],
    ['bad', 'ปฏิเสธ / ใช้สิทธิ์เกิน'],
    ['hollow', 'ตรวจความเป็นเจ้าของ']
  ],

  metrics: [
    { key: 'allow', label: 'อนุญาต' },
    { key: 'deny', label: 'ปฏิเสธ', tone: c => (c.stats.deny || 0) > 0 ? 'lit' : '' },
    { key: 'over', label: 'ใช้สิทธิ์เกินหน้าที่', bad: true, tone: c => (c.stats.over || 0) > 0 ? 'warn' : '' },
    { key: 'idor', label: 'อ่านของคนอื่นได้', bad: true, tone: c => (c.stats.idor || 0) > 0 ? 'warn' : '' },
    { key: 'np', label: 'สิทธิ์ของ bob', fmt: c => permsOf(c.cfg, USERS[1]).length + ' ข้อ', tone: c => permsOf(c.cfg, USERS[1]).length > 2 ? 'warn' : 'lit' }
  ],

  learn: [
    ['ให้สิทธิ์ตรงต่อคนไม่สเกลและตรวจสอบยาก', 0],
    ['บทบาทรวมสิทธิ์ไว้ที่เดียว แก้ที่เดียวมีผลทุกคน', 1],
    ['ย้ายทีมแล้วไม่ถอนบทบาทเก่า = สิทธิ์สะสม', 2],
    ['มีสิทธิ์อ่าน ไม่ได้แปลว่าอ่านของทุกคนได้', 4],
    ['ต้องตรวจความเป็นเจ้าของทุกคำขอ', 5]
  ],

  steps: [
    {
      tag: 'problem', label: 'ให้ตรงต่อคน', title: 'ให้สิทธิ์ตรงต่อผู้ใช้ทีละคน',
      body: [
        'วิธีที่ง่ายที่สุดตอนระบบยังเล็กคือเขียนไว้ว่าใครทำอะไรได้บ้าง พอมีผู้ใช้สิบคนก็ยังไหว พอมีห้าร้อยคนและสิทธิ์สามสิบชนิด ตารางนี้จะกลายเป็นสิ่งที่ไม่มีใครกล้าแตะ',
        'ดูบรรทัดของ <code>bob</code> เขาเคยอยู่ฝ่ายบัญชีแล้วย้ายมาฝ่ายขาย สิทธิ์ <code>payroll:read</code> ติดมาด้วยและไม่มีใครจำได้ว่าเคยให้ไว้ตอนไหน เขาจึงยังเปิดรายงานเงินเดือนของทั้งบริษัทได้'
      ],
      note: ['ปัญหาที่แท้จริง', 'ไม่ใช่ว่าวิธีนี้ผิดทางเทคนิค แต่มันตอบคำถามว่า "ใครเข้าถึงเงินเดือนได้บ้าง" ไม่ได้ภายในเวลาอันสั้น และคำถามนี้คือสิ่งที่ผู้ตรวจสอบถามทุกปี'],
      changed: ['รูปแบบ: ให้สิทธิ์ตรงต่อคน', 'bob: มีสิทธิ์ตกค้าง 1 ข้อ'],
      cfg: { mode: 'direct', creep: false, ownership: false, cross: false }
    },
    {
      tag: 'technique', label: 'บทบาท', title: 'ยกสิทธิ์ขึ้นไปไว้ที่บทบาท',
      body: [
        'แทนที่จะผูกสิทธิ์กับคน ให้ผูกสิทธิ์กับ <code>บทบาท</code> แล้วค่อยใส่คนเข้าไปในบทบาท ตอนนี้ bob อยู่ในบทบาทฝ่ายขายอย่างเดียว สิทธิ์ตกค้างหายไปเองเพราะมันไม่เคยอยู่กับตัวเขา',
        'ข้อดีที่ใหญ่ที่สุดคือเวลาต้องแก้ เช่นตัดสินใจว่าฝ่ายขายไม่ควรลบใบแจ้งหนี้ได้อีกต่อไป เราแก้ที่บทบาทเดียวแล้วมีผลกับทุกคนทันที ไม่ต้องไล่แก้ทีละบัญชี'
      ],
      note: ['ตั้งชื่อบทบาทตามหน้าที่', 'ชื่อบทบาทควรสะท้อนงานที่ทำ ไม่ใช่สะท้อนระบบที่เข้าถึง บทบาทชื่อ "ฝ่ายขาย" อธิบายตัวเองได้ ส่วนบทบาทชื่อ "db-rw" จะกลายเป็นที่ทิ้งสิทธิ์ในอีกสองปี'],
      changed: ['รูปแบบ: บทบาท (RBAC)', 'bob: ฝ่ายขายเท่านั้น'],
      cfg: { mode: 'roles', creep: false, ownership: false, cross: false }
    },
    {
      tag: 'problem', label: 'สิทธิ์สะสม', title: 'ย้ายทีมแล้วไม่ถอนบทบาทเก่า',
      body: [
        'ในความเป็นจริง ตอน bob ย้ายทีมเขาต้องส่งงานเก่าต่ออีกสองเดือน จึงขอให้คงบทบาทฝ่ายบัญชีไว้ก่อน แล้วสองเดือนนั้นก็ไม่มีใครกลับมาถอน',
        'เรื่องนี้เกิดซ้ำทุกครั้งที่มีคนย้ายทีม สะสมไปเรื่อยๆ จนพนักงานอายุงานสิบปีกลายเป็นบัญชีที่เข้าถึงได้เกือบทุกอย่างโดยไม่มีใครตั้งใจ เรียกว่า privilege creep'
      ],
      note: ['ทำไมถึงอันตราย', 'ไม่ใช่เพราะกลัวว่า bob จะไม่ดี แต่เพราะถ้าบัญชีของ bob ถูกยึด ผู้โจมตีจะได้สิทธิ์ทั้งหมดที่สะสมไว้ไปด้วย ความเสียหายแปรผันตรงกับสิทธิ์ที่บัญชีนั้นถืออยู่'],
      changed: ['bob: ยังถือบทบาทฝ่ายบัญชีไว้'],
      cfg: { mode: 'roles', creep: true, ownership: false, cross: false }
    },
    {
      tag: 'technique', label: 'ทบทวนสิทธิ์', title: 'ถอนบทบาทเก่าและทบทวนเป็นรอบ',
      body: [
        'ทางแก้ไม่ใช่เทคโนโลยีใหม่ แต่เป็นกระบวนการ ผูกการถอนบทบาทเข้ากับการย้ายทีมในระบบบุคคล กำหนดวันหมดอายุให้สิทธิ์ที่ให้ชั่วคราว และทบทวนสิทธิ์ทั้งหมดเป็นรอบ',
        'สิทธิ์ของ bob กลับมาเหลือเท่าที่งานปัจจุบันต้องใช้ หลักการนี้ชื่อว่า least privilege ให้เท่าที่จำเป็น และให้นานเท่าที่จำเป็น'
      ],
      note: ['ให้แบบมีวันหมดอายุ', 'สิทธิ์ที่ขอเพิ่มชั่วคราวควรหมดอายุเองโดยอัตโนมัติ เพราะการพึ่งให้คนจำว่าต้องกลับมาถอน เป็นวิธีที่ล้มเหลวเสมอในระยะยาว'],
      changed: ['ถอนบทบาทฝ่ายบัญชีของ bob'],
      cfg: { mode: 'roles', creep: false, ownership: false, cross: false }
    },
    {
      tag: 'attack', label: 'IDOR', title: 'มีสิทธิ์อ่าน ไม่ได้แปลว่าอ่านของทุกคนได้',
      body: [
        'ann มีสิทธิ์ <code>invoice:read</code> อย่างถูกต้อง แต่ตอนนี้เธอขอเปิด <code>invoice#bob</code> ซึ่งเป็นใบแจ้งหนี้ของลูกค้าของ bob ระบบตรวจแค่ว่า "มีสิทธิ์อ่านใบแจ้งหนี้ไหม" คำตอบคือมี จึงเปิดให้',
        'ช่องโหว่นี้ชื่อ IDOR ผู้โจมตีแค่เปลี่ยนตัวเลขใน URL จาก 88 เป็น 89 ก็ไล่อ่านเอกสารของคนอื่นได้ทั้งระบบ โดยไม่ต้องเจาะอะไรเลยสักอย่าง'
      ],
      note: ['แยกสองคำถามให้ออก', 'การยืนยันตัวตนตอบว่าคุณคือใคร การให้สิทธิ์ตอบว่าคุณทำอะไรได้ แต่ยังเหลือคำถามที่สามที่คนลืมบ่อยที่สุด คือคุณทำกับของ "ชิ้นไหน" ได้'],
      changed: ['ผู้ใช้เริ่มขอเปิดรายการของคนอื่น'],
      cfg: { mode: 'roles', creep: false, ownership: false, cross: true }
    },
    {
      tag: 'technique', label: 'ตรวจเจ้าของ', title: 'ตรวจความเป็นเจ้าของทุกคำขอ',
      body: [
        'เพิ่มเงื่อนไขอีกชั้นหลังจากผ่านการตรวจสิทธิ์แล้ว ว่ารายการที่ขอเป็นของผู้ขอหรืออยู่ในขอบเขตที่เขาดูแลหรือไม่ คำขอข้ามเจ้าของถูกปฏิเสธที่ตัวตัดสินใจทันที',
        'จุดสำคัญคือการตรวจนี้ต้องอยู่ฝั่งเซิร์ฟเวอร์เสมอ การซ่อนปุ่มหรือซ่อนลิงก์บนหน้าเว็บไม่ใช่การควบคุมสิทธิ์ เพราะใครก็ยิงคำขอตรงไปที่ API ได้'
      ],
      note: ['ตรวจที่เดียว ไม่ใช่ทุกที่', 'ถ้าต้องเขียนเงื่อนไขนี้ซ้ำในทุก endpoint สักวันจะมีคนลืม ให้ย้ายไปไว้ที่ชั้นกลางหรือชั้นเข้าถึงข้อมูล เพื่อให้ปลอดภัยโดยค่าตั้งต้น'],
      changed: ['เปิดการตรวจความเป็นเจ้าของ'],
      cfg: { mode: 'roles', creep: false, ownership: true, cross: true }
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: ดูสิทธิ์ของ bob ขยับ',
      body: [
        'เปิดสิทธิ์สะสมพร้อมกับปิดการตรวจเจ้าของ แล้วดูว่าในสิบวินาทีมีคำขอที่ไม่ควรผ่านกี่ครั้ง จากนั้นเปิดการตรวจเจ้าของอย่างเดียวโดยยังปล่อยให้สิทธิ์สะสมอยู่ เพื่อดูว่ามันแก้คนละปัญหากัน',
        'ปิดท้ายคอร์สด้วยคำถามที่ใช้ได้กับทุกระบบ ใครอ่านข้อมูลนี้ได้บ้าง ใครแก้มันได้บ้าง อะไรทำให้มันหยุดให้บริการได้ และคนที่มีสิทธิ์อยู่ตอนนี้ ยังจำเป็นต้องมีอยู่จริงหรือเปล่า'
      ],
      note: ['ขั้นต่อไปของ RBAC', 'เมื่อเงื่อนไขซับซ้อนขึ้น เช่นต้องดูแผนก เวลา หรือสถานที่ประกอบกัน จะมี ABAC ที่ตัดสินจากคุณสมบัติหลายอย่าง และ ReBAC ที่ตัดสินจากความสัมพันธ์ระหว่างผู้ใช้กับของชิ้นนั้น'],
      changed: [],
      cfg: { mode: 'roles', creep: true, ownership: false, cross: true },
      controls: ['mode', 'creep', 'ownership', 'cross']
    }
  ],

  controls: {
    mode: {
      type: 'seg', label: 'วิธีจัดการสิทธิ์',
      options: [['direct', 'ให้ตรงต่อคน'], ['roles', 'ใช้บทบาท (RBAC)']],
      get: c => c.mode, set: (c, v) => { c.mode = v; }
    },
    creep: { type: 'toggle', label: 'bob ยังถือบทบาทฝ่ายบัญชี', hint: 'จำลองสิทธิ์สะสมจากการย้ายทีม', get: c => c.creep, set: (c, v) => { c.creep = v; } },
    ownership: { type: 'toggle', label: 'ตรวจความเป็นเจ้าของ', hint: 'กัน IDOR', get: c => c.ownership, set: (c, v) => { c.ownership = v; } },
    cross: { type: 'toggle', label: 'ผู้ใช้ขอเปิดรายการของคนอื่น', hint: 'เปลี่ยนเลขใน URL', get: c => c.cross, set: (c, v) => { c.cross = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      log: [], last: null,
      P: {
        u: USERS.map(u => iso(u.p[0], u.p[1], 0.75)),
        pol: iso(POLICY[0], POLICY[1], 1.0),
        r: RES.map(r => iso(r.p[0] - 0.7, r.p[1], 0.75))
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    USERS.forEach(u => ctx.line(iso(u.p[0], u.p[1], 0.2), iso(POLICY[0], POLICY[1], 0.2), 'wire', L.wires));
    RES.forEach(r => ctx.line(iso(POLICY[0], POLICY[1], 0.2), iso(r.p[0], r.p[1], 0.2), 'wire', L.wires));

    const items = [];
    USERS.forEach((u, i) => items.push({
      k: u.p[0] + u.p[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        Ac.desk(g, u.p[0], u.p[1], i === 2 ? 'violet' : 'orange', 1.05);
        const pp = iso(u.p[0], u.p[1], 0.2);
        S['uP' + i] = ctx.pill(L.labels, pp[0] - 34, pp[1] + 2, [u.id, ''], 'end');
      }
    }));
    RES.forEach((r, i) => items.push({
      k: r.p[0] + r.p[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        Ac.box(g, r.p[0], r.p[1], { w: 1.15, h: 0.62, pal: r.pal, glyph: (p, c) => ctx.glyph.db(p, c) });
        const pp = iso(r.p[0] + 0.85, r.p[1], 0.2);
        S['rP' + i] = ctx.pill(L.labels, pp[0] + 14, pp[1] + 2, [r.name], 'start');
      }
    }));
    items.push({
      k: POLICY[0] + POLICY[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        const b = Ac.box(g, POLICY[0], POLICY[1], { w: 1.45, h: 0.78, pal: 'green' });
        S.own = ctx.el('g', {}, g);
        ctx.glyph.lock(S.own, iso(POLICY[0], POLICY[1], b.box.zt));
        S.polPill = ctx.pill(L.labels, iso(POLICY[0], POLICY[1] + 1.2, 0)[0], iso(POLICY[0], POLICY[1] + 1.2, 0)[1] + 14, ['ตัวตัดสินสิทธิ์', '']);
      }
    });
    items.sort((a, b) => a.k - b.k).forEach(it => it.draw());

    S.tableP = ctx.panel(ctx.L.hud, { x: 126, y: 268, w: 348, rows: 5, lh: 15, title: 'ใครได้สิทธิ์อะไรบ้าง' });
    S.logP = ctx.panel(ctx.L.hud, { x: 486, y: 268, w: 230, rows: 5, lh: 15, title: 'การตัดสินล่าสุด', dark: true });
    S.reqP = ctx.panel(ctx.L.hud, { x: 126, y: 392, w: 590, rows: 2, title: 'คำขอที่กำลังถูกตัดสิน' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    if (!ctx.timer('req', dt, 1500)) return;
    const plan = CYCLE[(S.n = (S.n || 0) + 1) % CYCLE.length];
    const ui = USERS.findIndex(x => x.id === plan[0]);
    const u = USERS[ui];
    const perm = plan[1];
    let owner = null;
    if (perm.indexOf('invoice') === 0) owner = (cfg.cross && plan[2]) ? plan[2] : u.id;
    const label = SHORT[perm] + (owner && owner !== u.id ? ' #' + owner : '');
    ctx.launch([P.u[ui], P.pol], 'plain', { label, meta: { leg: 'pol', ui, perm, owner, label }, speed: 250 });
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    const push = (t, cls) => { S.log.unshift({ t, cls }); if (S.log.length > 5) S.log.length = 5; };

    if (m.leg === 'pol') {
      const u = USERS[m.ui];
      const d = decide(cfg, u, m);
      S.last = { u: u.id, label: m.label, d, perm: m.perm, owner: m.owner };
      if (!d.allow) {
        ctx.bump('deny'); ctx.puff(P.pol, 'ok');
        push('✗ ' + u.id + ' → ' + m.label, 'ok');
        return;
      }
      const over = m.perm === 'payroll:read' && u.id === 'bob';
      const idor = m.owner && m.owner !== u.id;
      ctx.launch([P.pol, P.r[PERM_RES[m.perm]]], (over || idor) ? 'bad' : 'ok',
        { label: m.label, meta: { leg: 'res', ri: PERM_RES[m.perm], over, idor, uid: u.id }, speed: 260 });
      push('✓ ' + u.id + ' → ' + m.label, (over || idor) ? 'bad' : 'ok');
      return;
    }

    if (m.leg === 'res') {
      ctx.bump('allow');
      const top = [P.r[m.ri][0], P.r[m.ri][1] - 26];
      if (m.idor) { ctx.bump('idor'); ctx.ring(P.r[m.ri]); ctx.float(top, 'ของคนอื่น', 'bad'); }
      else if (m.over) { ctx.bump('over'); ctx.ring(P.r[m.ri]); ctx.float(top, 'เกินหน้าที่', 'bad'); }
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;

    USERS.forEach((u, i) => {
      const n = permsOf(cfg, u).length;
      const creepy = u.id === 'bob' && n > 2;
      S['uP' + i].set([u.id, String(n)]);
      S['uP' + i].tone(creepy ? 'hot' : '');
    });
    RES.forEach((r, i) => S['rP' + i].set([r.name]));

    S.own.setAttribute('opacity', cfg.ownership ? 1 : 0.18);
    S.polPill.set(['ตัวตัดสินสิทธิ์', cfg.mode === 'direct' ? 'รายชื่อรายคน' : cfg.ownership ? 'บทบาท + เจ้าของ' : 'บทบาทอย่างเดียว']);
    S.polPill.tone(cfg.ownership ? 'ok' : cfg.mode === 'direct' ? 'hot' : '');

    tableLines(cfg).forEach((l, i) => S.tableP.set(i, l[0], l[1]));

    const L = S.last;
    if (!L) {
      S.reqP.set(0, 'กำลังรอคำขอแรก…', 'dim'); S.reqP.set(1, '', '');
    } else {
      S.reqP.set(0, L.u + '  ขอ  ' + L.label + (L.owner && L.owner !== L.u ? '   (รายการของ ' + L.owner + ')' : ''),
        L.d.allow ? 'mono' : 'bad mono');
      S.reqP.set(1, (L.d.allow ? 'อนุญาต · ' : 'ปฏิเสธ · ') + L.d.why +
        (L.d.allow && L.owner && L.owner !== L.u ? '   ← ไม่ได้ตรวจว่าเป็นของใคร' : ''),
        L.d.allow ? (L.owner && L.owner !== L.u ? 'bad' : 'ok') : 'ok');
    }

    for (let i = 0; i < 5; i++) {
      const r = S.log[i];
      S.logP.set(i, r ? r.t : (i === 0 ? '— รอคำขอ —' : ''), r ? (r.cls === 'bad' ? 'term-bad' : 'term') : 'term dim');
    }
  }
});
})();
