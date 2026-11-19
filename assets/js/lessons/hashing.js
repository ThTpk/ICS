/* ============================================================
   บทที่ 2.3 — ฟังก์ชันแฮชและการเก็บรหัสผ่าน
   plaintext → hash → rainbow table → salt → แฮชช้า
   ============================================================ */
(function () {
const U   = [0.2, 5.4];
const APP = [2.6, 3.0];
const DB  = [5.4, 0.2];
const ATK = [6.2, 4.0];

const USERS = [
  { u: 'ann', p: '123456',      common: true,  salt: 'k9x2' },
  { u: 'bee', p: 'password',    common: true,  salt: '7mqa' },
  { u: 'cat', p: 'Tr0ub4dor&3', common: false, salt: 'p3vv' },
  { u: 'dan', p: '123456',      common: true,  salt: 'z1rt' }
];
const DICT = 1e7;        // จำนวนรหัสผ่านยอดนิยมในพจนานุกรม
const SPACE = 1.6e20;    // ช่องว่างของรหัสผ่านที่แข็งแรง
const THRESH = 3600;     // ถือว่า "เจาะได้" ถ้าใช้เวลาไม่เกิน 1 ชั่วโมง

const HEXC = '0123456789abcdef';
function h32(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h; }
function hexOf(s, n) { let h = h32(s), o = ''; for (let i = 0; i < n; i++) { h = (Math.imul(h, 1103515245) + 12345) >>> 0; o += HEXC[(h >>> 28) & 15]; } return o; }

const SUP = '⁰¹²³⁴⁵⁶⁷⁸⁹';
function sci(n) {
  if (n < 1e4) return Math.round(n).toLocaleString('en-US');
  const e = Math.floor(Math.log10(n)), m = (n / Math.pow(10, e)).toFixed(1);
  return m + '×10' + String(e).split('').map(d => SUP[+d]).join('');
}
function fmtTime(s) {
  if (s <= 0.05) return 'ทันที';
  if (s < 60) return s.toFixed(s < 1 ? 3 : 1) + ' วินาที';
  if (s < 3600) return (s / 60).toFixed(1) + ' นาที';
  if (s < 86400) return (s / 3600).toFixed(1) + ' ชั่วโมง';
  if (s < 3.15e7) return (s / 86400).toFixed(1) + ' วัน';
  const y = s / 3.15e7;
  return (y < 1e4 ? Math.round(y).toLocaleString('en-US') : sci(y)) + ' ปี';
}

const ALGO_NAME = { none: 'ไม่แฮชเลย (เก็บดิบ)', md5: 'MD5 (เร็วมาก)', sha256: 'SHA-256 (เร็ว)', bcrypt: 'bcrypt (ออกแบบให้ช้า)' };
function rateOf(cfg) {
  if (cfg.algo === 'none') return Infinity;
  if (cfg.algo === 'md5') return 2.0e10;
  if (cfg.algo === 'sha256') return 7.0e9;
  return 5.9e6 / Math.pow(2, cfg.cost);
}
/* เวลาที่ผู้โจมตีต้องใช้ต่อหนึ่งบัญชี */
function crackTime(cfg, user) {
  if (cfg.algo === 'none') return 0;
  const r = rateOf(cfg);
  if (user.common) return cfg.salt ? DICT / r : 0;  // ไม่ใส่ salt = เปิดตารางสำเร็จรูปได้เลย
  return SPACE / r;
}
function stored(cfg, user) {
  if (cfg.algo === 'none') return user.p;
  if (!cfg.salt) return hexOf(user.p + cfg.algo, 10);
  return user.salt + ':' + hexOf(user.salt + user.p + cfg.algo, 8);
}

ICS.register({
  id: 'hashing',
  title: 'แฮชและการเก็บรหัสผ่าน',
  sub: 'ฐานข้อมูลรั่วเป็นเรื่องที่เกิดขึ้นเสมอ คำถามจริงคือวันที่มันรั่ว ผู้โจมตีจะได้อะไรติดมือไปบ้าง',
  minutes: 14,
  level: 'ระดับกลาง',

  legend: [
    ['req sq', 'รหัสผ่านที่ผู้ใช้พิมพ์'],
    ['hash sq', 'ค่าแฮชที่เก็บจริง'],
    ['res', 'ล็อกอินผ่าน'],
    ['bad', 'ข้อมูลที่ถูกขโมย']
  ],

  metrics: [
    { key: 'logins', label: 'ล็อกอินสำเร็จ' },
    { key: 'cracked', label: 'บัญชีที่ถูกเจาะ', bad: true, fmt: c => (c.stats.cracked || 0) + ' / ' + USERS.length, tone: c => (c.stats.cracked || 0) === 0 && c.S.dumped ? 'lit' : (c.stats.cracked || 0) > 0 ? 'warn' : '' },
    { key: 'r', label: 'ความเร็วการเดา', fmt: c => c.cfg.algo === 'none' ? 'ไม่ต้องเดา' : sci(rateOf(c.cfg)) + '/วิ' },
    { key: 'tw', label: 'เวลาเจาะรหัสยอดนิยม', fmt: c => fmtTime(crackTime(c.cfg, USERS[0])) },
    { key: 'ts', label: 'เวลาเจาะรหัสที่แข็งแรง', fmt: c => fmtTime(crackTime(c.cfg, USERS[2])) }
  ],

  learn: [
    ['ห้ามเก็บรหัสผ่านเป็นข้อความธรรมดาเด็ดขาด', 0],
    ['แฮชเป็นฟังก์ชันทางเดียว แก้ 1 ตัวผลเปลี่ยนหมด', 1],
    ['รหัสเดียวกันให้แฮชเดียวกัน จึงเจาะพร้อมกันได้', 2],
    ['salt ทำให้ตารางสำเร็จรูปใช้ไม่ได้', 3],
    ['แฮชสำหรับรหัสผ่านต้องช้าโดยตั้งใจ', 5]
  ],

  steps: [
    {
      tag: 'problem', label: 'เก็บดิบ', title: 'เก็บรหัสผ่านเป็นข้อความธรรมดา',
      body: [
        'ระบบรับรหัสผ่านมาแล้วเก็บลงฐานข้อมูลตรงๆ ตอนผู้ใช้ล็อกอินก็เทียบตัวอักษรกัน ใช้งานได้ปกติทุกอย่าง จนถึงวันที่ฐานข้อมูลรั่ว',
        'ดูตารางมุมขวาล่าง ผู้โจมตีดึงไฟล์ออกไปครั้งเดียวก็ได้รหัสผ่านจริงของทุกคนทันที ไม่ต้องเดาอะไรเลยสักตัว และคนส่วนใหญ่ใช้รหัสซ้ำกับธนาคารและอีเมล'
      ],
      note: ['ทำไมเรื่องนี้ร้ายแรงกว่าที่คิด', 'ความเสียหายไม่ได้จบที่ระบบของเรา รหัสที่หลุดจะถูกเอาไปลองกับเว็บอื่นทันที เรียกว่า credential stuffing ซึ่งได้ผลสูงมากเพราะคนใช้รหัสซ้ำ'],
      changed: ['การเก็บ: ข้อความธรรมดา', 'ผู้โจมตี: ขโมยฐานข้อมูลสำเร็จ'],
      cfg: { algo: 'none', salt: false, cost: 12, breach: true }
    },
    {
      tag: 'technique', label: 'แฮช', title: 'แฮช: คำนวณไปข้างหน้าได้ ย้อนกลับไม่ได้',
      body: [
        'เปลี่ยนมาเก็บค่าแฮชแทน ฟังก์ชันแฮชรับข้อมูลยาวเท่าไรก็ได้แล้วคืนค่าความยาวคงที่ คำนวณไปข้างหน้าเร็วมาก แต่ย้อนจากค่าแฮชกลับไปหาต้นฉบับทำไม่ได้',
        'ตอนล็อกอินระบบก็แฮชสิ่งที่ผู้ใช้พิมพ์แล้วเทียบค่า ไม่จำเป็นต้องรู้รหัสจริงเลย ดูแผงซ้ายบน รหัสที่ต่างกันแค่ตัวเดียวให้ผลลัพธ์ที่ไม่เหลือเค้าเดิม เรียกว่า avalanche effect'
      ],
      note: ['แฮชไม่ใช่การเข้ารหัส', 'การเข้ารหัสถอดกลับได้ถ้ามีกุญแจ แต่แฮชตั้งใจให้ถอดไม่ได้เลย เลยเหมาะกับรหัสผ่านที่เราไม่ควรรู้ค่าจริงตั้งแต่แรก'],
      changed: ['การเก็บ: SHA-256'],
      cfg: { algo: 'sha256', salt: false, cost: 12, breach: false }
    },
    {
      tag: 'attack', label: 'ตารางสำเร็จรูป', title: 'แฮชอย่างเดียวยังเจาะได้ด้วยตารางสำเร็จรูป',
      body: [
        'ผู้โจมตีไม่ต้องย้อนแฮช เขาแค่แฮชรหัสผ่านยอดนิยมสิบล้านตัวเก็บเป็นตารางไว้ล่วงหน้า แล้วเปิดเทียบ ค่าที่ตรงกันคือเฉลยทันที เรียกว่า rainbow table',
        'ที่แย่กว่านั้นคือดูแถว <code>ann</code> กับ <code>dan</code> ในตาราง ทั้งคู่ใช้รหัสเดียวกันจึงได้ค่าแฮชเหมือนกันเป๊ะ ผู้โจมตีเห็นได้ทันทีว่าใครใช้รหัสซ้ำกับใคร และเจาะทีเดียวได้ทั้งคู่'
      ],
      note: ['ทำไมเจาะได้ทั้งฐาน', 'ถ้าไม่มี salt ตารางหนึ่งชุดใช้ได้กับทุกคนและทุกเว็บ ต้นทุนการคำนวณจ่ายครั้งเดียวแล้วใช้ซ้ำได้ตลอดไป'],
      changed: ['ผู้โจมตี: เปิดตาราง rainbow'],
      cfg: { algo: 'sha256', salt: false, cost: 12, breach: true }
    },
    {
      tag: 'technique', label: 'Salt', title: 'ใส่ salt ให้ทุกบัญชีไม่ซ้ำกัน',
      body: [
        'เติมค่าสุ่มประจำบัญชีเข้าไปก่อนแฮช แล้วเก็บค่าสุ่มนั้นไว้ข้างๆ แบบเปิดเผย ตอนนี้ <code>ann</code> กับ <code>dan</code> ที่ใช้รหัสเดียวกันเก็บค่าคนละค่าแล้ว',
        'ตารางสำเร็จรูปใช้ไม่ได้อีกต่อไป เพราะต้องสร้างตารางใหม่ทีละบัญชี แต่สังเกตช่อง "เวลาเจาะรหัสยอดนิยม" ให้ดี มันยังเร็วอยู่มาก งานยังไม่จบ'
      ],
      note: ['salt ไม่ใช่ความลับ', 'เก็บไว้ในตารางเดียวกับแฮชได้เลย หน้าที่ของมันคือทำให้ผู้โจมตีคำนวณซ้ำกับทุกคนไม่ได้ ไม่ใช่การปกปิด'],
      changed: ['เติม salt ประจำบัญชี'],
      cfg: { algo: 'sha256', salt: true, cost: 12, breach: true }
    },
    {
      tag: 'problem', label: 'เร็วเกินไป', title: 'ปัญหาคือแฮชพวกนี้เร็วเกินไป',
      body: [
        'SHA-256 กับ MD5 ถูกออกแบบมาให้เร็ว เพราะต้องใช้แฮชไฟล์ขนาดกิกะไบต์ แต่ความเร็วนั้นเข้าทางผู้โจมตีเต็มๆ การ์ดจอหนึ่งใบเดาได้ระดับหมื่นล้านครั้งต่อวินาที',
        'ลองดูด้วย MD5 ซึ่งเร็วกว่าอีก ต่อให้ใส่ salt แล้ว การไล่พจนานุกรมสิบล้านคำก็ยังจบในเสี้ยววินาทีต่อบัญชี salt กันตารางสำเร็จรูปได้ แต่กันความเร็วไม่ได้'
      ],
      note: ['ของดีผิดงาน', 'SHA-256 ไม่ได้อ่อนแอ มันแค่เป็นเครื่องมือผิดประเภทสำหรับงานนี้ งานตรวจความถูกต้องของไฟล์ต้องการความเร็ว งานเก็บรหัสผ่านต้องการความช้า'],
      changed: ['เปลี่ยนเป็น MD5 เพื่อเทียบความเร็ว'],
      cfg: { algo: 'md5', salt: true, cost: 12, breach: true }
    },
    {
      tag: 'technique', label: 'bcrypt', title: 'ใช้แฮชที่ตั้งใจให้ช้า',
      body: [
        'bcrypt, scrypt และ Argon2 ออกแบบมาให้ช้าโดยตั้งใจ และปรับความช้าได้ด้วยค่า work factor ทุกครั้งที่เพิ่มค่านี้ขึ้นหนึ่ง เวลาที่ใช้จะเป็นสองเท่า',
        'ที่ค่า 12 ความเร็วการเดาร่วงจากหมื่นล้านเหลือหลักพันต่อวินาที บัญชีที่เคยแตกในเสี้ยววินาทีกลับกลายเป็นหลายชั่วโมงต่อหนึ่งบัญชี ฝั่งผู้ใช้จริงเสียเวลาแค่ครั้งละไม่กี่ร้อยมิลลิวินาทีตอนล็อกอิน'
      ],
      note: ['ความไม่สมมาตรที่เราต้องการ', 'ผู้ใช้แฮชครั้งเดียวต่อการล็อกอิน แต่ผู้โจมตีต้องแฮชเป็นพันล้านครั้ง ต้นทุนที่เพิ่มเท่ากันจึงเจ็บกับผู้โจมตีมากกว่ามหาศาล'],
      changed: ['เปลี่ยนเป็น bcrypt work factor 12'],
      cfg: { algo: 'bcrypt', salt: true, cost: 12, breach: true }
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: ปรับแล้วดูเวลาที่ผู้โจมตีต้องใช้',
      body: [
        'ลากค่า work factor ขึ้นลงแล้วดูช่อง "เวลาเจาะรหัสยอดนิยม" มันเพิ่มเป็นสองเท่าทุกหนึ่งขั้นจริงหรือไม่ แล้วลองปิด salt ขณะใช้ bcrypt ดูว่าเกิดอะไรขึ้นกับบัญชีที่ใช้รหัสซ้ำกัน',
        'ข้อสังเกตสำคัญ ไม่ว่าจะตั้งค่าดีแค่ไหน บัญชีที่ใช้รหัส <code>123456</code> ก็ยังเสี่ยงกว่าบัญชีที่ใช้รหัสยาวเสมอ การเก็บที่ดีช่วยซื้อเวลา ไม่ได้ซื้อความปลอดภัยแทนผู้ใช้'
      ],
      note: ['นอกจากแฮชแล้วควรมีอะไรอีก', 'จำกัดจำนวนครั้งที่ลองผิด บังคับความยาวขั้นต่ำ ตรวจรหัสกับรายการที่เคยรั่ว และเปิดการยืนยันตัวตนสองชั้น ทั้งหมดนี้ทำงานคนละชั้นกัน'],
      changed: [],
      cfg: { algo: 'bcrypt', salt: true, cost: 12, breach: true },
      controls: ['algo', 'salt', 'cost']
    }
  ],

  controls: {
    algo: {
      type: 'seg', label: 'วิธีเก็บรหัสผ่าน',
      options: [['none', 'เก็บดิบ'], ['md5', 'MD5'], ['sha256', 'SHA-256'], ['bcrypt', 'bcrypt']],
      get: c => c.algo, set: (c, v) => { c.algo = v; }, reset: true
    },
    salt: { type: 'toggle', label: 'เติม salt ประจำบัญชี', hint: 'กันตารางสำเร็จรูปและการเทียบรหัสซ้ำ', get: c => c.salt, set: (c, v) => { c.salt = v; }, reset: true },
    cost: {
      type: 'range', min: 4, max: 16, get: c => c.cost, set: (c, v) => { c.cost = v; }, reset: true,
      label: (v, c) => `work factor ของ bcrypt: <output>${v}</output>${c.cfg && c.cfg.algo !== 'bcrypt' ? ' (ใช้เมื่อเลือก bcrypt)' : ''}`
    }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      rows: null, dumped: false, clock: 0, logs: [], demo: 0,
      P: { u: iso(U[0], U[1], 0.78), app: iso(APP[0], APP[1], 0.9), db: iso(DB[0], DB[1], 1.0), atk: iso(ATK[0], ATK[1] - 0.5, 0.72) }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    ctx.line(iso(U[0], U[1], 0.22), iso(APP[0], APP[1], 0.22), 'wire', L.wires);
    ctx.line(iso(APP[0], APP[1], 0.22), iso(DB[0], DB[1], 0.22), 'wire', L.wires);
    S.atkWire = ctx.line(iso(ATK[0], ATK[1], 0.22), iso(DB[0], DB[1], 0.22), 'wire tap', L.wires);

    const ug = ctx.el('g', {}, L.ents);
    Ac.desk(ug, U[0], U[1], 'orange');
    ctx.pill(L.labels, S.P.u[0], iso(U[0], U[1] + 0.9, 0)[1] + 14, ['ผู้ใช้', 'ล็อกอิน']);

    const ag = ctx.el('g', {}, L.ents);
    const ab = Ac.box(ag, APP[0], APP[1], { w: 1.35, h: 0.66, pal: 'green' });
    S.hashGlyph = ctx.el('g', {}, ag);
    ctx.glyph.hash(S.hashGlyph, iso(APP[0], APP[1], ab.box.zt));
    S.appPill = ctx.pill(L.labels, iso(APP[0], APP[1] + 1.05, 0)[0], iso(APP[0], APP[1] + 1.05, 0)[1] + 14, ['เซิร์ฟเวอร์', '']);

    const dg = ctx.el('g', {}, L.ents);
    Ac.db(dg, DB[0], DB[1], 'blue');
    S.dbPill = ctx.pill(L.labels, iso(DB[0], DB[1] + 1.1, 0)[0], iso(DB[0], DB[1] + 1.1, 0)[1] + 14, ['ฐานข้อมูล', USERS.length + ' บัญชี']);

    S.atkG = ctx.el('g', {}, L.ents);
    Ac.attacker(S.atkG, ATK[0], ATK[1]);
    S.atkPill = ctx.pill(L.labels, iso(ATK[0], ATK[1] + 0.85, 0)[0] - 6, iso(ATK[0], ATK[1] + 0.85, 0)[1] + 14, ['ผู้โจมตี', '']);

    S.hashP = ctx.panel(L.hud, { x: 126, y: 80, w: 252, rows: 3, title: 'ฟังก์ชันแฮชทำงานอย่างไร' });
    S.dbP = ctx.panel(L.hud, { x: 448, y: 350, w: 268, rows: 5, title: 'สิ่งที่เก็บจริงในฐานข้อมูล' });
    S.atkP = ctx.panel(L.hud, { x: 126, y: 352, w: 296, rows: 3, title: 'เครื่องเจาะรหัสของผู้โจมตี', dark: true });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;

    if (ctx.timer('login', dt, 2100)) {
      const user = ctx.pick(USERS);
      ctx.launch([P.u, P.app], 'plain', { label: user.p.length > 9 ? user.p.slice(0, 9) + '…' : user.p, meta: { leg: 'app', user }, speed: 200 });
    }
    if (cfg.breach && ctx.timer('dump', dt, 7000)) {
      ctx.launch([P.db, P.atk], 'bad', { label: 'DUMP ' + USERS.length + ' แถว', meta: { leg: 'dump' }, speed: 210 });
    }
    if (ctx.timer('demo', dt, 2400)) S.demo ^= 1;

    /* ไล่เจาะทีละบัญชีตามเวลาที่คำนวณได้ */
    if (S.rows) {
      S.clock += dt;
      S.rows.forEach(r => {
        if (r.cracked || r.time > THRESH) return;
        if (S.clock >= r.at) {
          r.cracked = true; ctx.bump('cracked'); ctx.ring(P.atk);
          S.logs.unshift('เจาะได้ ' + r.u + ' = ' + r.p);
          if (S.logs.length > 2) S.logs.length = 2;
        }
      });
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    if (m.leg === 'app') {
      ctx.puff(P.app, 'v');
      const label = cfg.algo === 'none' ? m.user.p : stored(cfg, m.user).slice(0, 12);
      ctx.launch([P.app, P.db], cfg.algo === 'none' ? 'plain' : 'hashd', { label, meta: { leg: 'db' }, speed: 210 });
    } else if (m.leg === 'db') {
      ctx.bump('logins');
      ctx.launch([P.db, P.app, P.u], 'res', { meta: { leg: 'done' }, speed: 360 });
    } else if (m.leg === 'dump') {
      S.dumped = true;
      ctx.stats.cracked = 0;
      S.clock = 0; S.logs = [];
      S.rows = USERS.map(u => {
        const t = crackTime(cfg, u);
        return { u: u.u, p: u.p, time: t, cracked: false, at: 350 + 900 * Math.log10(1 + t) };
      });
      ctx.ring(P.atk);
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const hashing = cfg.algo !== 'none';

    S.hashGlyph.setAttribute('opacity', hashing ? 1 : 0.18);
    S.appPill.set(['เซิร์ฟเวอร์', hashing ? ALGO_NAME[cfg.algo].split(' ')[0] + (cfg.salt ? ' + salt' : '') : 'เก็บดิบ']);
    S.appPill.tone(hashing ? (cfg.algo === 'bcrypt' ? 'ok' : '') : 'hot');

    S.atkWire.setAttribute('class', 'wire tap' + (cfg.breach ? '' : ' off'));
    S.atkG.setAttribute('opacity', cfg.breach ? 1 : 0.32);
    const ck = ctx.stats.cracked || 0;
    S.atkPill.set(['ผู้โจมตี', !cfg.breach ? 'ยังเข้าไม่ถึง' : ck ? 'เจาะได้ ' + ck + '/' + USERS.length : 'กำลังไล่เดา']);
    S.atkPill.tone(ck ? 'hot' : cfg.breach ? '' : 'dead');

    /* แผงอธิบายแฮช */
    if (!hashing) {
      S.hashP.set(0, 'ไม่มีการแฮช', 'bad');
      S.hashP.set(1, 'เก็บสิ่งที่ผู้ใช้พิมพ์ลงไปตรงๆ', 'dim');
      S.hashP.set(2, 'รั่วเมื่อไรคือได้รหัสจริงทันที', 'dim');
    } else {
      const a = 'password1', b = 'password2';
      const src = S.demo ? b : a;
      S.hashP.set(0, ALGO_NAME[cfg.algo], 'ok');
      S.hashP.set(1, src + '  →  ' + hexOf(src + cfg.algo, 12), 'mono');
      S.hashP.set(2, 'ต่างกัน 1 ตัว ผลลัพธ์ต่างกันทั้งหมด', 'dim');
    }

    /* ตารางในฐานข้อมูล */
    const dup = {};
    USERS.forEach(u => { const v = stored(cfg, u); dup[v] = (dup[v] || 0) + 1; });
    USERS.forEach((u, i) => {
      const v = stored(cfg, u);
      const row = S.rows && S.rows[i];
      const mark = row && row.cracked ? '  ✗' : '';
      S.dbP.set(i, (u.u + '    ').slice(0, 5) + v + mark,
        (row && row.cracked) ? 'bad mono' : (dup[v] > 1 ? 'bad mono' : 'mono'));
    });
    S.dbP.set(4, !hashing ? 'อ่านรหัสจริงได้ทุกแถว'
      : dup[stored(cfg, USERS[0])] > 1 ? 'ann กับ dan ได้ค่าเดียวกัน = ใช้รหัสซ้ำ'
      : 'ทุกแถวต่างกัน แม้รหัสจะซ้ำกัน', dup[stored(cfg, USERS[0])] > 1 || !hashing ? 'bad' : 'ok');

    /* จอของผู้โจมตี */
    if (!cfg.breach || !S.rows) {
      S.atkP.set(0, cfg.breach ? '> รอดึงข้อมูล…' : '— ยังไม่มีข้อมูลรั่ว —', 'term dim');
      S.atkP.set(1, '', ''); S.atkP.set(2, '', '');
    } else {
      S.atkP.set(0, '> ความเร็ว ' + (cfg.algo === 'none' ? 'ไม่ต้องเดาเลย' : sci(rateOf(cfg)) + ' รหัส/วินาที'), 'term');
      S.atkP.set(1, S.logs[0] ? '> ' + S.logs[0] : '> กำลังไล่พจนานุกรม…', S.logs[0] ? 'term-bad' : 'term dim');
      const left = S.rows.filter(r => !r.cracked);
      S.atkP.set(2, left.length === 0 ? '> เจาะครบทุกบัญชี'
        : '> เหลือ ' + left.length + ' บัญชี · ต้องใช้อีก ' + fmtTime(Math.min.apply(null, left.map(r => r.time))),
        left.length === 0 ? 'term-bad' : 'term dim');
    }
  }
});
})();
