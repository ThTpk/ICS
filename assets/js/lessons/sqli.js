/* ============================================================
   บทที่ 4.1 — SQL Injection
   ดูคำสั่งที่ถูกประกอบขึ้นจริง แล้วดูว่าทำไมมันถึงพัง
   ============================================================ */
(function () {
const U   = [0.3, 4.3];
const APP = [3.0, 1.6];
const DB  = [5.8, -1.2];

const TABLE = [
  { u: 'ann', h: '5f4dcc3b', r: 'admin' },
  { u: 'bob', h: 'e10adc39', r: 'user' },
  { u: 'cat', h: '8d969eef', r: 'user' }
];
const TPL_A = "SELECT * FROM users WHERE name = '";
const TPL_B = "' AND pass = '****'";
const TPL_P = "SELECT * FROM users WHERE name = ? AND pass = ?";

function filterInput(s) {
  return s.replace(/--/g, '').replace(/\bOR\b/g, '').replace(/;/g, '');
}
const isInj = s => /'\s*or\s*'?\s*1\s*'?\s*=\s*'?\s*1/i.test(s) || /'\s*or\s*1\s*=\s*1/i.test(s);
const isUni = s => /union\s+select/i.test(s);
const isDrop = s => /drop\s+table/i.test(s);

function run(cfg) {
  const raw = cfg.input || '';
  if (cfg.defense === 'prepared') {
    const hit = TABLE.filter(r => r.u === raw.trim());
    return { sql: TPL_P, param: raw, rows: hit, kind: hit.length ? 'login' : 'none', safe: true };
  }
  let inp = raw, stripped = false;
  if (cfg.defense === 'filter') { const b = inp; inp = filterInput(inp); stripped = b !== inp; }
  const sql = TPL_A + inp + TPL_B;
  const still = isInj(inp) || isUni(inp) || isDrop(inp);
  if (stripped && !still) return { sql, rows: [], kind: 'error', note: 'ตัวกรองตัดคำออก คำสั่งผิดรูป ฐานข้อมูลคืน error' };
  if (isDrop(inp)) {
    if (cfg.priv === 'readonly') return { sql, rows: [], kind: 'denied' };
    return { sql, rows: [], kind: 'dropped' };
  }
  if (isUni(inp)) return { sql, rows: TABLE, kind: 'union' };
  if (isInj(inp)) return { sql, rows: TABLE, kind: 'bypass' };
  const hit = TABLE.filter(r => r.u === inp.trim());
  return { sql, rows: hit, kind: hit.length ? 'login' : 'none' };
}

/* ตัดบรรทัดคำสั่ง SQL ให้พอดีความกว้างของแผง */
function wrap(str, n) {
  if (str.length <= n) return [str, ''];
  let cut = str.lastIndexOf(' ', n);
  if (cut < n * 0.6) cut = n;
  const rest = str.slice(cut).trim();
  return [str.slice(0, cut), rest.length > n ? rest.slice(0, n - 1) + '…' : rest];
}

const KIND_TEXT = {
  login: ['ล็อกอินสำเร็จตามปกติ', 'ok'],
  none: ['ไม่พบผู้ใช้ ล็อกอินไม่ผ่าน', 'dim'],
  bypass: ['ล็อกอินผ่านเป็น admin โดยไม่รู้รหัส', 'bad'],
  union: ['ดึงชื่อและแฮชออกไปทั้งตาราง', 'bad'],
  dropped: ['ตาราง users ถูกลบทิ้ง', 'bad'],
  denied: ['ถูกปฏิเสธ: บัญชีนี้ไม่มีสิทธิ์ลบตาราง', 'ok'],
  error: ['คำสั่งผิดรูป ฐานข้อมูลคืน error', 'dim']
};

ICS.register({
  id: 'sqli',
  title: 'SQL Injection',
  sub: 'ช่องโหว่ที่อยู่ในสิบอันดับแรกมาเกือบยี่สิบปี เพราะรากของมันคือการเอาข้อมูลไปต่อเป็นคำสั่ง',
  minutes: 14,
  level: 'ระดับกลาง',

  legend: [
    ['req sq', 'สิ่งที่ผู้ใช้พิมพ์'],
    ['hash sq', 'คำสั่ง SQL ที่ประกอบแล้ว'],
    ['res', 'ผลลัพธ์ปกติ'],
    ['bad', 'ข้อมูลที่ไม่ควรหลุด']
  ],

  metrics: [
    { key: 'rows', label: 'แถวที่คืนกลับ', fmt: c => c.S.res ? c.S.res.rows.length : 0, tone: c => c.S.res && c.S.res.rows.length > 1 ? 'warn' : '' },
    { key: 'bypass', label: 'ล็อกอินโดยไม่รู้รหัส', bad: true },
    { key: 'leaked', label: 'แฮชที่หลุด', bad: true },
    { key: 'dropped', label: 'ตารางที่ถูกลบ', bad: true },
    { key: 'blocked', label: 'โจมตีที่ถูกกัน', tone: c => (c.stats.blocked || 0) > 0 ? 'lit' : '' }
  ],

  learn: [
    ['ช่องกรอกของผู้ใช้กลายเป็นคำสั่งได้อย่างไร', 1],
    ['UNION SELECT ดึงข้อมูลข้ามตารางได้', 2],
    ['การกรองคำต้องห้ามถูกเลี่ยงได้เสมอ', 4],
    ['prepared statement แยกคำสั่งออกจากข้อมูล', 5],
    ['สิทธิ์น้อยที่สุดจำกัดความเสียหาย', 6]
  ],

  steps: [
    {
      tag: 'concept', label: 'ค่าปกติ', title: 'ระบบล็อกอินที่ต่อคำสั่งด้วยการบวกสตริง',
      body: [
        'โค้ดฝั่งเซิร์ฟเวอร์เอาสิ่งที่ผู้ใช้พิมพ์มาต่อเข้ากับคำสั่ง SQL ตรงๆ ตอนนี้ผู้ใช้พิมพ์ <code>ann</code> คำสั่งที่ได้จึงถูกต้องสวยงาม ฐานข้อมูลคืนมาหนึ่งแถว ล็อกอินผ่าน',
        'ดูแผง "คำสั่งที่ส่งถึงฐานข้อมูล" ให้ดี สิ่งที่ผู้ใช้พิมพ์ถูกวางลงไประหว่างเครื่องหมายคำพูดสองตัว ตรงนี้คือจุดที่ทุกอย่างจะพังในขั้นถัดไป'
      ],
      note: ['รากของปัญหาคืออะไร', 'ฐานข้อมูลได้รับสตริงมาก้อนเดียวแล้วต้องแยกเองว่าส่วนไหนคือคำสั่งส่วนไหนคือข้อมูล เมื่อเส้นแบ่งอยู่แค่เครื่องหมายคำพูด ใครพิมพ์เครื่องหมายคำพูดได้ก็ข้ามเส้นได้'],
      changed: ['input: ann', 'การป้องกัน: ไม่มี'],
      cfg: { input: 'ann', defense: 'none', priv: 'admin' }
    },
    {
      tag: 'attack', label: 'ทะลุคำพูด', title: 'พิมพ์เครื่องหมายคำพูดเข้าไปหนึ่งตัว',
      body: [
        'ผู้โจมตีพิมพ์ <code class="danger">\' OR \'1\'=\'1</code> เครื่องหมายคำพูดตัวแรกไปปิดสตริงที่โปรแกรมเปิดค้างไว้ ที่เหลือจึงกลายเป็นคำสั่งจริงที่ฐานข้อมูลเอาไปทำตาม',
        'เงื่อนไขกลายเป็น "ชื่อว่าง หรือ 1 เท่ากับ 1" ซึ่งเป็นจริงเสมอ ฐานข้อมูลจึงคืนทุกแถวในตาราง ระบบเห็นว่ามีผลลัพธ์ก็ให้ล็อกอินผ่านเป็นแถวแรกคือ <code>admin</code>'
      ],
      note: ['ไม่ต้องรู้รหัสผ่านเลย', 'การโจมตีนี้ไม่ได้เดารหัส แต่ทำให้คำถามเปลี่ยนไปเลย จากถามว่า "รหัสถูกไหม" กลายเป็นบอกว่า "ยังไงก็ถูก"'],
      changed: ['input: \' OR \'1\'=\'1'],
      cfg: { input: "' OR '1'='1", defense: 'none', priv: 'admin' }
    },
    {
      tag: 'attack', label: 'UNION', title: 'UNION SELECT: ดึงข้อมูลที่ไม่ได้ขอ',
      body: [
        'การล็อกอินผ่านเป็นแค่จุดเริ่ม ด้วย <code class="danger">UNION SELECT</code> ผู้โจมตีต่อผลลัพธ์ของคำสั่งที่ตัวเองเขียนเข้ากับผลลัพธ์เดิม จะดึงคอลัมน์ไหนจากตารางไหนก็ได้',
        'ผลที่ได้คือชื่อผู้ใช้และค่าแฮชทั้งตารางไหลออกมาทางหน้าเว็บที่ควรจะแสดงแค่ว่า "ล็อกอินสำเร็จ" และจากตรงนี้ก็ต่อยอดไปบทเรื่องการเจาะแฮชได้ทันที'
      ],
      note: ['ข้อมูลรั่วระดับล้านรายการ', 'เหตุข้อมูลรั่วขนาดใหญ่หลายครั้งในประวัติศาสตร์เริ่มจากช่องกรอกเดียวแบบนี้ เพราะเมื่อสั่งฐานข้อมูลได้ ก็อ่านได้ทุกตารางที่บัญชีนั้นมีสิทธิ์'],
      changed: ['input: UNION SELECT …'],
      cfg: { input: "' UNION SELECT name,pass FROM users --", defense: 'none', priv: 'admin' }
    },
    {
      tag: 'technique', label: 'กรองคำ', title: 'วิธีที่ดูเหมือนจะแก้ได้: กรองคำต้องห้าม',
      body: [
        'ทางแก้แรกที่คนส่วนใหญ่คิดถึงคือไล่ลบคำอันตรายออกจาก input เช่นตัดคำว่า <code>OR</code> ตัด <code>--</code> และตัด <code>;</code> ทิ้ง',
        'ลองดูผล คำสั่งเดิมที่เคยทะลุตอนนี้ถูกตัดจนผิดรูป ฐานข้อมูลคืน error ออกมา ดูเผินๆ เหมือนปัญหาจบแล้ว'
      ],
      note: ['บัญชีดำกับบัญชีขาว', 'การไล่ห้ามสิ่งที่ "คิดว่าอันตราย" เรียกว่าบัญชีดำ ซึ่งต้องเดาให้ครบทุกกรณีจึงจะปลอดภัย ส่วนการอนุญาตเฉพาะสิ่งที่รู้ว่าปลอดภัยเรียกว่าบัญชีขาว ซึ่งแข็งแรงกว่ามาก'],
      changed: ['การป้องกัน: กรองคำต้องห้าม'],
      cfg: { input: "' OR '1'='1", defense: 'filter', priv: 'admin' }
    },
    {
      tag: 'attack', label: 'เลี่ยงตัวกรอง', title: 'ตัวกรองถูกเลี่ยงด้วยการเปลี่ยนตัวพิมพ์',
      body: [
        'ตัวกรองมองหาคำว่า <code>OR</code> ตัวใหญ่ ผู้โจมตีจึงพิมพ์ <code class="danger">\' oR \'1\'=\'1</code> แทน ฐานข้อมูลไม่สนตัวพิมพ์เล็กใหญ่อยู่แล้ว คำสั่งจึงทำงานเหมือนเดิมทุกประการ',
        'ยังมีทางเลี่ยงอีกนับไม่ถ้วน ทั้งการแทรกคอมเมนต์ การเข้ารหัสอักขระ และการซ้อนคำ ทุกครั้งที่อุดรูหนึ่ง ก็มีรูใหม่โผล่มาเสมอ เพราะเรากำลังแก้ปลายเหตุ'
      ],
      note: ['ทำไมบัญชีดำถึงแพ้เสมอ', 'ฝ่ายป้องกันต้องคิดให้ครบทุกกรณี แต่ฝ่ายโจมตีขอแค่หาเจอกรณีเดียวที่หลุด ความไม่เท่าเทียมนี้ทำให้การกรองคำไม่เคยเป็นคำตอบ'],
      changed: ['input: \' oR \'1\'=\'1'],
      cfg: { input: "' oR '1'='1", defense: 'filter', priv: 'admin' }
    },
    {
      tag: 'technique', label: 'Prepared', title: 'วิธีที่แก้ถูกจุด: แยกคำสั่งออกจากข้อมูล',
      body: [
        'Prepared statement ส่งโครงคำสั่งที่มี <code>?</code> เป็นช่องว่างไปให้ฐานข้อมูลก่อน ฐานข้อมูลแปลคำสั่งและวางแผนเสร็จเรียบร้อย แล้วค่อยรับค่าพารามิเตอร์ตามมาทีหลังแยกช่องกัน',
        'ค่าที่ส่งตามมาจึงเป็น "ข้อมูล" เสมอ ไม่มีทางกลายเป็นคำสั่งได้อีก ลองดู ผู้โจมตีพิมพ์เพย์โหลดเดิมเป๊ะ แต่ระบบตีความว่าเขากำลังหาผู้ใช้ที่ชื่อว่า <code>\' oR \'1\'=\'1</code> จริงๆ ซึ่งไม่มี'
      ],
      note: ['ไม่ใช่แค่กับ SQL', 'หลักเดียวกันใช้กับทุกที่ที่เอาข้อมูลไปต่อเป็นคำสั่ง ทั้งคำสั่งเชลล์ เทมเพลต HTML และ LDAP แยกคำสั่งกับข้อมูลออกจากกันเสมอ อย่าต่อสตริง'],
      changed: ['การป้องกัน: prepared statement'],
      cfg: { input: "' oR '1'='1", defense: 'prepared', priv: 'admin' }
    },
    {
      tag: 'technique', label: 'สิทธิ์น้อยสุด', title: 'ชั้นสุดท้าย: จำกัดสิทธิ์ของบัญชีฐานข้อมูล',
      body: [
        'สมมติว่าวันหนึ่งโค้ดส่วนอื่นพลาดแล้วถูกฉีดจนได้ คำสั่ง <code class="danger">\'; DROP TABLE users --</code> จะลบตารางทิ้งทั้งตารางถ้าแอปเชื่อมฐานข้อมูลด้วยบัญชี admin',
        'แต่ถ้าแอปใช้บัญชีที่มีสิทธิ์เท่าที่จำเป็น เช่นอ่านและเขียนแถวได้แต่ลบตารางไม่ได้ คำสั่งเดียวกันจะถูกปฏิเสธที่ฐานข้อมูล ลองสลับสิทธิ์ด้านล่างดูความต่าง'
      ],
      note: ['สมมติว่าด่านแรกจะพลาด', 'การป้องกันที่ดีไม่ได้หวังให้ทุกด่านสมบูรณ์ แต่ออกแบบให้ความเสียหายถูกจำกัดเมื่อด่านใดด่านหนึ่งพลาด นี่คือหัวใจของ defense in depth'],
      changed: ['input: \'; DROP TABLE users --', 'สิทธิ์: จำกัด'],
      cfg: { input: "'; DROP TABLE users --", defense: 'none', priv: 'readonly' },
      controls: ['priv']
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: พิมพ์อะไรก็ได้ลงช่อง username',
      body: [
        'พิมพ์เองหรือกดปุ่มตัวอย่างด้านล่าง แล้วดูว่าคำสั่งที่ประกอบออกมาหน้าตาเป็นอย่างไรและฐานข้อมูลคืนอะไรกลับมา',
        'ลองเปิด prepared statement แล้วยิงทุกเพย์โหลดซ้ำอีกรอบ คุณจะเห็นว่าไม่มีอันไหนทำงานได้เลย เพราะมันแก้ที่รากของปัญหา ไม่ใช่ไล่อุดอาการ'
      ],
      note: ['ตรวจโค้ดตัวเองยังไง', 'ไล่หาทุกที่ที่คำสั่ง SQL ถูกสร้างด้วยการบวกสตริงหรือใส่ตัวแปรลงใน template string ทุกจุดนั้นคือจุดที่ต้องเปลี่ยนเป็น parameterized query'],
      changed: [],
      cfg: { input: "' OR '1'='1", defense: 'none', priv: 'admin' },
      controls: ['input', 'defense', 'priv']
    }
  ],

  controls: {
    input: {
      type: 'text', label: 'ช่อง username', placeholder: 'ann',
      hint: 'ลองใส่เครื่องหมายคำพูดเดี่ยวแล้วดูคำสั่งที่ประกอบออกมา',
      get: c => c.input, set: (c, v) => { c.input = v; },
      presets: [
        ['ปกติ', 'ann'],
        ['คลาสสิก', "' OR '1'='1"],
        ['เลี่ยงตัวกรอง', "' oR '1'='1"],
        ['UNION', "' UNION SELECT name,pass FROM users --"],
        ['DROP', "'; DROP TABLE users --"]
      ]
    },
    defense: {
      type: 'seg', label: 'การป้องกันฝั่งแอป',
      options: [['none', 'ไม่มี'], ['filter', 'กรองคำ'], ['prepared', 'Prepared']],
      get: c => c.defense, set: (c, v) => { c.defense = v; }
    },
    priv: {
      type: 'seg', label: 'สิทธิ์ของบัญชีฐานข้อมูล',
      options: [['admin', 'admin (ทำได้ทุกอย่าง)'], ['readonly', 'จำกัดสิทธิ์']],
      get: c => c.priv, set: (c, v) => { c.priv = v; }
    }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      res: null, lastKind: null, dropped: false,
      P: { u: iso(U[0], U[1], 0.78), app: iso(APP[0], APP[1], 0.92), db: iso(DB[0], DB[1], 1.0) }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    ctx.line(iso(U[0], U[1], 0.22), iso(APP[0], APP[1], 0.22), 'wire', L.wires);
    ctx.line(iso(APP[0], APP[1], 0.22), iso(DB[0], DB[1], 0.22), 'wire', L.wires);

    const ug = ctx.el('g', {}, L.ents);
    Ac.desk(ug, U[0], U[1], 'orange', 1.1);
    S.uPill = ctx.pill(L.labels, S.P.u[0], iso(U[0], U[1] + 0.95, 0)[1] + 14, ['ผู้ใช้', '']);

    const ag = ctx.el('g', {}, L.ents);
    const ab = Ac.box(ag, APP[0], APP[1], { w: 1.35, h: 0.68, pal: 'green' });
    S.shieldG = ctx.el('g', {}, ag);
    ctx.glyph.lock(S.shieldG, iso(APP[0], APP[1], ab.box.zt));
    S.appPill = ctx.pill(L.labels, iso(APP[0], APP[1] + 1.1, 0)[0], iso(APP[0], APP[1] + 1.1, 0)[1] + 14, ['เว็บแอป', '']);

    S.dbG = ctx.el('g', {}, L.ents);
    Ac.db(S.dbG, DB[0], DB[1], 'blue');
    S.dbPill = ctx.pill(L.labels, iso(DB[0], DB[1] + 1.15, 0)[0], iso(DB[0], DB[1] + 1.15, 0)[1] + 14, ['ฐานข้อมูล', '']);

    S.inP = ctx.panel(L.hud, { x: 126, y: 78, w: 322, rows: 2, title: 'สิ่งที่ผู้ใช้พิมพ์ในช่อง username' });
    S.status = ctx.statusList(L.hud, { x: 500, y: 76, w: 216, title: 'ผลลัพธ์', items: ['การล็อกอิน', 'ข้อมูลที่หลุด', 'ความเสียหาย'] });
    S.qP = ctx.panel(L.hud, { x: 130, y: 256, w: 564, rows: 4, title: 'คำสั่งที่ส่งถึงฐานข้อมูล' });
    S.rP = ctx.panel(L.hud, { x: 130, y: 356, w: 564, rows: 4, title: 'แถวที่ฐานข้อมูลคืนกลับมา' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    if (ctx.timer('go', dt, 2700)) {
      const raw = cfg.input || '';
      ctx.launch([P.u, P.app], 'plain', { label: raw.length > 18 ? raw.slice(0, 18) + '…' : (raw || '(ว่าง)'), meta: { leg: 'app' }, speed: 220 });
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    if (p.meta.leg === 'app') {
      const res = run(cfg);
      S.res = res;
      const lbl = res.safe ? 'SQL + ค่าแยกช่อง' : 'SQL ที่ประกอบแล้ว';
      ctx.launch([P.app, P.db], res.safe ? 'ok' : (res.kind === 'login' || res.kind === 'none' || res.kind === 'error' || res.kind === 'denied') ? 'hashd' : 'bad',
        { label: lbl, meta: { leg: 'db', res }, speed: 220 });
      return;
    }
    if (p.meta.leg === 'db') {
      const res = p.meta.res;
      const n = res.rows.length;
      if (res.kind === 'bypass') { ctx.bump('bypass'); ctx.ring(P.db); }
      if (res.kind === 'union') { ctx.bump('leaked', TABLE.length); ctx.ring(P.db); }
      if (res.kind === 'dropped') { ctx.bump('dropped'); ctx.ring(P.db); ctx.float([P.db[0], P.db[1] - 30], 'DROP TABLE', 'bad'); }
      if (res.kind === 'denied' || res.kind === 'error' || (res.safe && n === 0 && (cfg.input || '').includes("'"))) {
        ctx.bump('blocked'); ctx.puff(P.db, 'ok');
      }
      ctx.launch([P.db, P.app, P.u],
        (res.kind === 'bypass' || res.kind === 'union' || res.kind === 'dropped') ? 'bad' : 'res',
        { label: n ? n + ' แถว' : (res.kind === 'denied' ? 'denied' : res.kind === 'error' ? 'error' : '0 แถว'), meta: { leg: 'back' }, speed: 300 });
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const raw = cfg.input || '';
    const attack = /'/.test(raw);

    S.uPill.set(['ผู้ใช้', attack ? 'กำลังโจมตี' : 'ปกติ']);
    S.uPill.tone(attack ? 'hot' : '');
    S.shieldG.setAttribute('opacity', cfg.defense === 'prepared' ? 1 : cfg.defense === 'filter' ? 0.5 : 0.15);
    S.appPill.set(['เว็บแอป', cfg.defense === 'prepared' ? 'prepared statement' : cfg.defense === 'filter' ? 'กรองคำต้องห้าม' : 'ต่อสตริงตรงๆ']);
    S.appPill.tone(cfg.defense === 'prepared' ? 'ok' : cfg.defense === 'none' ? 'hot' : '');
    S.dbPill.set(['ฐานข้อมูล', cfg.priv === 'readonly' ? 'สิทธิ์จำกัด' : 'บัญชี admin']);
    S.dbPill.tone(cfg.priv === 'readonly' ? 'ok' : '');

    S.inP.set(0, raw || '(ว่าง)', attack ? 'bad mono' : 'mono');
    S.inP.set(1, attack ? 'มีเครื่องหมายคำพูดเดี่ยวอยู่ใน input' : 'เป็นข้อความธรรมดา', attack ? 'bad' : 'dim');

    const res = S.res;
    if (!res) {
      S.qP.set(0, 'กำลังรอคำขอแรก…', 'dim'); S.qP.set(1, '', ''); S.qP.set(2, '', ''); S.qP.set(3, '', '');
      S.rP.set(0, '', ''); S.rP.set(1, '', ''); S.rP.set(2, '', ''); S.rP.set(3, '', '');
      return;
    }

    if (res.safe) {
      S.qP.set(0, TPL_P, 'ok mono');
      S.qP.set(1, 'พารามิเตอร์ 1 = ' + (res.param || '(ว่าง)'), 'mono dim');
      S.qP.set(2, 'ค่านี้ถูกส่งแยกช่อง จึงเป็นข้อมูลเสมอ ไม่มีทางกลายเป็นคำสั่ง', 'ok');
      S.qP.set(3, '', '');
    } else {
      const ln = wrap(res.sql, 76);
      S.qP.set(0, ln[0], attack ? 'bad mono' : 'mono');
      S.qP.set(1, ln[1], attack ? 'bad mono' : 'mono');
      S.qP.set(2, cfg.defense === 'filter' ? 'ตัวกรองตัดคำว่า OR (ตัวใหญ่), -- และ ; ออกก่อน' : 'input ถูกวางลงระหว่างเครื่องหมายคำพูดโดยตรง', 'dim');
      S.qP.set(3, KIND_TEXT[res.kind][0], KIND_TEXT[res.kind][1]);
    }

    if (res.kind === 'dropped') {
      S.rP.set(0, 'ตาราง users ไม่มีอยู่อีกแล้ว', 'bad');
      S.rP.set(1, 'ข้อมูลผู้ใช้ทั้งหมดหายไปในคำสั่งเดียว', 'bad');
      S.rP.set(2, ''); S.rP.set(3, '');
    } else if (res.rows.length === 0) {
      S.rP.set(0, res.kind === 'denied' ? 'ERROR: permission denied for table users'
        : res.kind === 'error' ? 'ERROR: syntax error at or near "1"'
        : '(ไม่มีแถวที่ตรง)', res.kind === 'denied' ? 'ok' : 'dim');
      S.rP.set(1, res.kind === 'denied' ? 'บัญชีนี้ลบตารางไม่ได้ ความเสียหายถูกจำกัด'
        : res.safe ? 'ระบบมองหาผู้ใช้ชื่อนี้จริงๆ แล้วไม่พบ' : '', res.kind === 'denied' ? 'ok' : 'dim');
      S.rP.set(2, ''); S.rP.set(3, '');
    } else {
      res.rows.slice(0, 3).forEach((r, i) => {
        S.rP.set(i, (r.u + '      ').slice(0, 6) + '| ' + r.h + ' | ' + r.r, res.rows.length > 1 ? 'bad mono' : 'ok mono');
      });
      for (let i = res.rows.length; i < 3; i++) S.rP.set(i, '', '');
      S.rP.set(3, res.rows.length > 1
        ? 'คืนมา ' + res.rows.length + ' แถว ทั้งที่ควรได้อย่างมากแถวเดียว'
        : 'ถูกต้องตามที่ควรเป็น', res.rows.length > 1 ? 'bad' : 'ok');
    }

    const k = res.kind;
    S.status.set(0, k === 'bypass' || k === 'union' ? 'bad' : k === 'login' ? 'ok' : 'idle',
      k === 'bypass' ? 'ผ่านแบบปลอม' : k === 'login' ? 'ผ่านปกติ' : k === 'union' ? 'ผ่านแบบปลอม' : 'ไม่ผ่าน');
    S.status.set(1, k === 'union' ? 'bad' : (k === 'bypass' ? 'bad' : 'ok'),
      k === 'union' ? TABLE.length + ' แฮช' : k === 'bypass' ? 'ทั้งตาราง' : 'ไม่มี');
    S.status.set(2, k === 'dropped' ? 'bad' : k === 'denied' ? 'ok' : 'idle',
      k === 'dropped' ? 'ตารางหาย' : k === 'denied' ? 'ถูกกันไว้' : 'ไม่มี');
  }
});
})();
