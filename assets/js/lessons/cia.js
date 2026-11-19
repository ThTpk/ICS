/* ============================================================
   บทที่ 1.1 — CIA Triad
   ความลับ · ความถูกต้อง · ความพร้อมใช้ พังได้ทีละเสา
   ============================================================ */
(function () {
const CAP = 8, SERVICE = 1000;
const CY = [2, 3.5, 5];
const JX = 1.9, JY = 3.5;
const GX = 3.9, GY = 3.5;
const SX = 7.3, SY = 3.5;
const AX = 5.0, AY = 7.0;

const PAYLOADS = ['user=ann', 'pass=1234', 'bal=52,100', 'otp=774213', 'card=4111', 'to=acc-882'];
const HEX = '0123456789abcdef';
function cipherOf(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  let s = '';
  for (let i = 0; i < 8; i++) { h = (Math.imul(h, 1103515245) + 12345) >>> 0; s += HEX[(h >>> 28) & 15]; }
  return s;
}

ICS.register({
  id: 'cia',
  title: 'CIA Triad',
  sub: 'ความปลอดภัยไม่ใช่เรื่องเดียว แต่เป็นสามเสาหลักที่พังแยกกันได้ แล้วแต่ละเสาก็ต้องใช้เครื่องมือต่างกัน',
  minutes: 12,
  level: 'พื้นฐาน',

  legend: [
    ['req', 'คำขอของผู้ใช้'],
    ['res', 'คำตอบ'],
    ['bad', 'ถูกแก้ไข / ถูกปฏิเสธ'],
    ['cipher sq', 'สำเนาที่ถูกดักไป'],
    ['hollow', 'ถูกกรองทิ้ง']
  ],

  metrics: [
    { key: 'ok', label: 'ตอบสำเร็จ' },
    { key: 'leak', label: 'อ่านได้ (C)', bad: true, tone: c => c.cfg.eaves && !c.cfg.encrypt ? 'warn' : (c.cfg.encrypt && c.cfg.eaves ? 'lit' : '') },
    { key: 'tampered', label: 'ถูกแก้สำเร็จ (I)', bad: true, tone: c => c.cfg.tamper && !c.cfg.sign ? 'warn' : (c.cfg.sign && c.cfg.tamper ? 'lit' : '') },
    { key: 'blocked', label: 'ปฏิเสธ 503 (A)', bad: true, tone: c => c.cfg.flood && !c.cfg.limit ? 'warn' : '' },
    { key: 'caught', label: 'ตรวจจับได้' },
    {
      key: 'rateSucc', label: 'อัตราสำเร็จ',
      fmt: c => { const t = (c.stats.ok || 0) + (c.stats.blocked || 0); return t ? Math.round((c.stats.ok || 0) * 100 / t) + '%' : '–'; },
      tone: c => { const t = (c.stats.ok || 0) + (c.stats.blocked || 0); return t > 8 && (c.stats.ok || 0) / t >= 0.97 ? 'lit' : ''; }
    }
  ],

  learn: [
    ['ความปลอดภัยมีสามเสา: C, I, A', 0],
    ['การดักฟังไม่ทำให้อะไรพัง แต่ความลับหายไปแล้ว', 1],
    ['เข้ารหัสแล้วข้อมูลยังถูกแก้กลางทางได้', 2],
    ['การทำให้ระบบล่มก็นับเป็นการเจาะความปลอดภัย', 3],
    ['แต่ละเสาต้องแก้ด้วยเครื่องมือต่างชนิดกัน', 6]
  ],

  steps: [
    {
      tag: 'concept', label: 'สามเสาหลัก', title: 'ความปลอดภัยคือสามเสาหลัก',
      body: [
        'ระบบหนึ่งปลอดภัยหรือไม่ ต้องวัดสามเรื่องพร้อมกัน <code>C</code> ความลับ ข้อมูลต้องไม่ถึงคนที่ไม่ควรเห็น <code>I</code> ความถูกต้อง ข้อมูลต้องไม่ถูกแก้ระหว่างทาง <code>A</code> ความพร้อมใช้ ระบบต้องให้บริการได้ตอนที่ผู้ใช้ต้องการ',
        'ตอนนี้ยังไม่มีการโจมตี คำขอวิ่งจากผู้ใช้เข้าชุมสาย ผ่านเกตเวย์ ไปถึงเซิร์ฟเวอร์ที่รับงานพร้อมกันได้ 5 งาน ไฟทั้งสามดวงมุมขวาบนจึงเขียวหมด'
      ],
      note: ['สามเสาขัดกันเองได้', 'ยิ่งล็อกแน่นเพื่อความลับ ระบบก็ยิ่งใช้ยากและเสี่ยงล่ม งานออกแบบจริงคือหาจุดสมดุล ไม่ใช่ดันสุดทางใดทางเดียว'],
      changed: ['ผู้ใช้ 3 คน', 'เซิร์ฟเวอร์: รับพร้อมกัน 5 งาน', 'ผู้โจมตี: ยังไม่ลงมือ'],
      cfg: { rate: 3, eaves: false, tamper: false, flood: false, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'problem', label: 'ดักฟัง', title: 'C พัง: มีคนดักฟังอยู่บนสาย',
      body: [
        'ผู้โจมตีต่อสายเข้าที่ชุมสาย แล้วคัดลอกทุกแพ็กเก็ตที่วิ่งผ่าน ข้อมูลยังถึงเซิร์ฟเวอร์ครบถ้วน ระบบจึงดูเหมือนทำงานปกติดีทุกอย่าง',
        'แต่ดูกล่องดำมุมขวาล่าง มันอ่าน <code>pass=1234</code> และ <code>card=4111</code> ได้หมด นี่คือการเสีย Confidentiality ไม่มีอะไรพัง แต่ความลับหายไปแล้ว'
      ],
      note: ['ทำไมจับยาก', 'การดักฟังเป็นการโจมตีแบบ passive ไม่แก้ ไม่ลบ ไม่ทำให้ช้าลง จึงไม่ทิ้งร่องรอยในล็อกให้ใครเห็น'],
      changed: ['ผู้โจมตี: ดักฟังที่ชุมสาย'],
      cfg: { rate: 3, eaves: true, tamper: false, flood: false, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'attack', label: 'แก้ข้อมูล', title: 'I พัง: แก้ข้อมูลกลางทาง',
      body: [
        'คราวนี้ผู้โจมตีไม่ได้แค่ดู แต่แก้ค่าก่อนปล่อยผ่าน เช่นเปลี่ยนเลขบัญชีผู้รับหรือยอดเงิน เซิร์ฟเวอร์ได้รับคำขอที่รูปแบบถูกต้องทุกอย่าง จึงทำตามอย่างซื่อๆ',
        'แพ็กเก็ตที่เปลี่ยนเป็นสีแดงคือคำขอที่ถูกแก้แล้ว นับอยู่ในช่อง "ถูกแก้สำเร็จ" ผู้ใช้ไม่รู้ตัว และเซิร์ฟเวอร์ก็ไม่รู้ตัว'
      ],
      note: ['เข้ารหัสเพียวๆ ไม่พอ', 'การเข้ารหัสทำให้อ่านไม่ออก แต่ไม่ได้บอกว่าข้อมูลถูกแก้หรือยัง สองเรื่องนี้แยกกัน จึงต้องมีค่าตรวจสอบมาคู่กันเสมอ'],
      changed: ['ผู้โจมตี: แก้ข้อมูลกลางทางด้วย'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: false, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'attack', label: 'ยิงถล่ม', title: 'A พัง: ยิงคำขอจนไม่มีที่ว่าง',
      body: [
        'ผู้โจมตีเปลี่ยนวิธี ยิงคำขอขยะเข้ามาเป็นชุด ช่องว่างทั้ง 5 ของเซิร์ฟเวอร์ถูกจองโดยงานขยะ คำขอของผู้ใช้จริงจึงถูกปฏิเสธด้วย <code>503</code>',
        'ข้อมูลไม่รั่วเพิ่มและไม่ถูกแก้เพิ่ม แต่ผู้ใช้ใช้งานไม่ได้ ดูช่อง "อัตราสำเร็จ" ที่ร่วงลง นี่คือความปลอดภัยที่พังไปอีกหนึ่งเสา'
      ],
      note: ['DoS กับ DDoS', 'ยิงจากเครื่องเดียวคือ DoS กรองไอพีเดียวก็จบ ยิงจากเครื่องที่ถูกยึดเป็นหมื่นเครื่องพร้อมกันคือ DDoS ซึ่งแยกออกจากผู้ใช้จริงยากกว่ามาก'],
      changed: ['ผู้โจมตี: ยิงคำขอถล่ม 10 ครั้ง/วินาที'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'technique', label: 'เข้ารหัส', title: 'กู้ C ด้วยการเข้ารหัส',
      body: [
        'เปิดการเข้ารหัส สายสื่อสารเปลี่ยนเป็นเส้นทึบสีเขียว ผู้โจมตียังคัดลอกแพ็กเก็ตได้เท่าเดิมทุกใบ แต่สิ่งที่ได้กลายเป็นกองอักขระที่ไม่มีความหมาย',
        'สังเกตว่าจำนวนที่ดักได้ไม่ลดลงเลย ที่ลดคือจำนวนที่ "อ่านได้" ไฟดวง C กลับมาเขียว แต่ I และ A ยังแดงอยู่ทั้งคู่'
      ],
      note: ['เข้ารหัสที่ไหน', 'TLS เข้ารหัสตอนข้อมูลเดินทาง (in transit) ส่วนข้อมูลที่นอนอยู่ในดิสก์ต้องเข้ารหัสอีกชั้นหนึ่ง (at rest) เป็นคนละมาตรการกัน'],
      changed: ['เปิดเข้ารหัสช่องทางสื่อสาร'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: true, sign: false, limit: false }
    },
    {
      tag: 'technique', label: 'ลายเซ็น', title: 'กู้ I ด้วยค่าตรวจสอบ',
      body: [
        'ผู้ส่งคำนวณค่าตรวจสอบจากเนื้อข้อมูลบวกกุญแจลับ แล้วแนบไปกับคำขอ ปลายทางคำนวณซ้ำแล้วเทียบกัน ถ้าไม่ตรงก็รู้ทันทีว่าถูกแก้',
        'แพ็กเก็ตสีแดงยังมาถึงเหมือนเดิม แต่ถูกปฏิเสธที่ประตู นับเข้าช่อง "ตรวจจับได้" แทน ผู้โจมตีแก้ข้อมูลได้ แต่ทำให้เซิร์ฟเวอร์เชื่อไม่ได้แล้ว'
      ],
      note: ['แก้ไม่ได้ กับ แก้แล้วรู้', 'ไม่มีใครห้ามคนกลางแก้บิตบนสายได้จริง สิ่งที่ทำได้คือทำให้ "แก้แล้วต้องรู้" ซึ่งเพียงพอ เพราะเราทิ้งข้อมูลใบนั้นได้'],
      changed: ['แนบ MAC ไปกับทุกคำขอ'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: true, sign: true, limit: false }
    },
    {
      tag: 'technique', label: 'จำกัดอัตรา', title: 'กู้ A ด้วยการกรองหน้าประตู',
      body: [
        'เกตเวย์เริ่มนับจำนวนคำขอต่อต้นทาง ต้นทางที่ยิงเกินโควตาถูกตัดทิ้งตรงนั้น ไม่ปล่อยให้เข้าไปกินช่องว่างของเซิร์ฟเวอร์',
        'ไฟครบสามดวงเขียวแล้ว ที่น่าสังเกตคือเราไม่ได้แก้โค้ดที่เซิร์ฟเวอร์เลย แค่เพิ่มชั้นกรองไว้ด้านหน้า นี่คือแนวคิด defense in depth ป้องกันเป็นชั้นๆ'
      ],
      note: ['คำถามชวนคิด', 'ถ้าผู้โจมตีกระจายยิงจากหนึ่งหมื่นไอพี ไอพีละ 2 ครั้งต่อวินาที การจำกัดอัตราต่อไอพีจะยังช่วยได้ไหม แล้วต้องใช้อะไรเพิ่ม'],
      changed: ['เกตเวย์: จำกัดอัตราต่อต้นทาง'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: true, sign: true, limit: true }
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: หาจุดที่ระบบแตก',
      body: [
        'เปิดปิดการโจมตีและการป้องกันได้อิสระ ลองตอบสองข้อนี้ หนึ่ง ถ้าเปิดเฉพาะการเข้ารหัสแต่ไม่แนบลายเซ็น ไฟดวงไหนยังแดง สอง ถ้าดันปริมาณคำขอขึ้นสูงสุดโดยไม่มีผู้โจมตีเลย ระบบจะพังที่เสาไหน'
      ],
      note: ['เกณฑ์ตรวจระบบแบบเร็ว', 'เวลาประเมินระบบใดก็ตาม ไล่ถามสามข้อ ใครอ่านข้อมูลนี้ได้บ้าง ใครแก้มันได้บ้าง และอะไรทำให้มันหยุดให้บริการได้บ้าง'],
      changed: [],
      cfg: { rate: 4, eaves: true, tamper: false, flood: false, encrypt: false, sign: false, limit: false },
      controls: ['rate', 'eaves', 'tamper', 'flood', 'encrypt', 'sign', 'limit']
    }
  ],

  controls: {
    rate: {
      type: 'range', min: 1, max: 14, get: c => c.rate, set: (c, v) => { c.rate = v; },
      label: v => `ปริมาณคำขอจริง: <output>${v}</output> ครั้งต่อวินาที`
    },
    eaves: { type: 'toggle', label: 'ผู้โจมตี: ดักฟังสาย', hint: 'คัดลอกทุกแพ็กเก็ตที่ชุมสาย', get: c => c.eaves, set: (c, v) => { c.eaves = v; } },
    tamper: { type: 'toggle', label: 'ผู้โจมตี: แก้ข้อมูลกลางทาง', hint: 'แก้ค่าก่อนปล่อยผ่าน', get: c => c.tamper, set: (c, v) => { c.tamper = v; } },
    flood: { type: 'toggle', label: 'ผู้โจมตี: ยิงคำขอถล่ม', hint: 'จองช่องว่างของเซิร์ฟเวอร์', get: c => c.flood, set: (c, v) => { c.flood = v; } },
    encrypt: { type: 'toggle', label: 'ป้องกัน: เข้ารหัสช่องทาง', hint: 'แก้ที่เสา C', get: c => c.encrypt, set: (c, v) => { c.encrypt = v; } },
    sign: { type: 'toggle', label: 'ป้องกัน: แนบลายเซ็น (MAC)', hint: 'แก้ที่เสา I', get: c => c.sign, set: (c, v) => { c.sign = v; } },
    limit: { type: 'toggle', label: 'ป้องกัน: จำกัดอัตราที่เกตเวย์', hint: 'แก้ที่เสา A', get: c => c.limit, set: (c, v) => { c.limit = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      active: 0, jobs: [], log: [],
      P: {
        cli: CY.map(y => iso(0, y, 0.78)),
        junc: iso(JX, JY, 0.62),
        gate: iso(GX, GY, 0.92),
        srv: iso(SX - 0.72, SY, 0.68),
        atk: iso(AX, AY - 0.55, 0.72)
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, A = ctx.actor;
    const W = ctx.L.wires, E = ctx.L.ents, LB = ctx.L.labels, H = ctx.L.hud;

    /* --- wires --- */
    S.trunk = CY.map(y => ctx.line(iso(0, y, 0.25), iso(JX, JY, 0.25), 'wire', W));
    S.trunk.push(ctx.line(iso(JX, JY, 0.25), iso(GX, GY, 0.25), 'wire', W));
    S.trunk.push(ctx.line(iso(GX, GY, 0.25), iso(SX, SY, 0.25), 'wire', W));
    S.tapWire = ctx.line(iso(AX, AY, 0.25), iso(JX, JY, 0.25), 'wire tap', W);
    S.floodWire = ctx.line(iso(AX, AY, 0.25), iso(GX, GY, 0.25), 'wire tap', W);

    /* --- actors, back to front (x+y order) --- */
    CY.forEach((y, i) => {
      const g = ctx.el('g', {}, E);
      A.desk(g, 0, y, i === 1 ? 'orange' : 'sand');
    });
    const lp = iso(-0.5, CY[0] - 0.4, 0.3);
    ctx.pill(LB, lp[0], lp[1] - 6, ['ผู้ใช้', CY.length + ' คน']);

    const jg = ctx.el('g', {}, E);
    A.box(jg, JX, JY, { w: 0.62, h: 0.34, pal: 'grey' });
    const jpos = iso(JX, JY + 0.6, 0);
    ctx.pill(LB, jpos[0], jpos[1] + 16, ['ชุมสาย']);

    const gg = ctx.el('g', { class: 'node' }, E);
    const gate = A.box(gg, GX, GY, { w: 1.35, h: 0.58, pal: 'violet' });
    const gc = iso(GX, GY, gate.box.zt);
    S.gateSplit = ctx.el('g', {}, gg); ctx.glyph.split(S.gateSplit, gc);
    S.gateWall = ctx.el('g', {}, gg); ctx.glyph.wall(S.gateWall, gc);
    const gpos = iso(GX, GY + 1.15, 0);
    S.gatePill = ctx.pill(LB, gpos[0], gpos[1] + 16, ['เกตเวย์', '']);

    const sg = ctx.el('g', { class: 'node' }, E);
    S.srv = A.server(sg, SX, SY, 'bone', 2.0);
    S.srvG = sg;
    const spos = iso(SX + 0.95, SY + 0.95, 0);
    S.srvPill = ctx.pill(LB, spos[0], spos[1] + 20, ['เซิร์ฟเวอร์', '0/' + CAP]);

    S.atkG = ctx.el('g', {}, E);
    A.attacker(S.atkG, AX, AY);
    const apos = iso(AX - 0.9, AY + 0.9, 0);
    S.atkPill = ctx.pill(LB, apos[0] + 10, apos[1] + 16, ['ผู้โจมตี', ''], 'middle');

    /* --- HUD --- */
    S.hud = ctx.statusList(H, {
      x: 518, y: 78, w: 198, title: 'สถานะความปลอดภัย',
      items: ['ความลับ C', 'ความถูกต้อง I', 'พร้อมใช้ A']
    });
    S.logPanel = ctx.panel(H, { x: 498, y: 392, w: 212, rows: 3, title: 'สิ่งที่ผู้โจมตีดักได้', dark: true });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;

    for (let n = ctx.rate('spawn', dt, cfg.rate); n > 0; n--) {
      const ci = Math.floor(Math.random() * CY.length);
      ctx.launch([P.cli[ci], P.junc], 'req', { meta: { leg: 'trunk', ci, payload: ctx.pick(PAYLOADS) }, speed: 300 });
    }
    if (cfg.flood) {
      for (let n = ctx.rate('flood', dt, 10); n > 0; n--)
        ctx.launch([P.atk, P.gate], 'flood', { meta: { leg: 'fg' }, speed: 360, r: 4 });
    }

    S.jobs = S.jobs.filter(j => {
      j.t -= dt;
      if (j.t > 0) return true;
      S.active--;
      if (!j.flood) {
        ctx.bump('ok');
        ctx.launch([P.srv, P.gate, P.junc, P.cli[j.ci]], 'res', { meta: { leg: 'res' }, speed: 340 });
      }
      return false;
    });
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    switch (m.leg) {
      case 'trunk': {
        if (cfg.eaves) {
          const readable = !cfg.encrypt;
          const text = readable ? m.payload : cipherOf(m.payload);
          ctx.launch([P.junc, P.atk], readable ? 'plain' : 'cipher',
            { label: text, meta: { leg: 'tap', readable, text }, speed: 250 });
        }
        const tampered = cfg.tamper && Math.random() < 0.5;
        if (tampered) ctx.ring(P.junc);
        ctx.launch([P.junc, P.gate], tampered ? 'bad' : 'req',
          { meta: { leg: 'gate', ci: m.ci, tampered }, speed: 320 });
        break;
      }
      case 'gate':
        ctx.launch([P.gate, P.srv], m.tampered ? 'bad' : 'req',
          { meta: { leg: 'srv', ci: m.ci, tampered: m.tampered }, speed: 320 });
        break;
      case 'fg':
        if (cfg.limit) { ctx.bump('filtered'); ctx.puff(P.gate, 'ok'); }
        else ctx.launch([P.gate, P.srv], 'flood', { meta: { leg: 'srv', flood: true }, speed: 360, r: 4 });
        break;
      case 'srv': {
        const top = [P.srv[0], P.srv[1] - 16];
        if (m.tampered) {
          if (cfg.sign) { ctx.bump('caught'); ctx.puff(P.srv, 'ok'); ctx.float(top, 'ไม่ผ่าน', 'ok'); }
          else { ctx.bump('tampered'); ctx.ring(P.srv); ctx.float(top, 'เชื่อแล้ว', 'bad'); }
          return;
        }
        if (S.active >= CAP) {
          if (!m.flood) { ctx.bump('blocked'); ctx.puff(P.srv); ctx.float(top, '503', 'bad'); }
          return;
        }
        S.active++;
        S.jobs.push({ t: SERVICE, ci: m.ci, flood: m.flood });
        break;
      }
      case 'tap':
        if (m.readable) { ctx.bump('leak'); ctx.ring(P.atk); }
        else ctx.bump('noise');
        S.log.unshift({ text: m.text, safe: !m.readable });
        if (S.log.length > 3) S.log.length = 3;
        break;
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S, iso = ctx.iso;

    /* server load bar */
    const b = S.srv.box, f = Math.min(S.active / CAP, 1), ins = 0.14;
    const z0 = b.z0 + 0.12, zh = (b.zt - b.z0 - 0.24) * f;
    S.srv.fill.setAttribute('points', f > 0 ? ctx.pts([
      iso(b.x0 + ins, b.y1, z0), iso(b.x1 - ins, b.y1, z0),
      iso(b.x1 - ins, b.y1, z0 + zh), iso(b.x0 + ins, b.y1, z0 + zh)
    ]) : '');
    const hot = S.active >= CAP;
    S.srvG.classList.toggle('hot', hot);
    S.srvPill.tone(hot ? 'hot' : '');
    S.srvPill.set(['เซิร์ฟเวอร์', S.active + '/' + CAP]);

    /* wires */
    const wcls = cfg.encrypt ? 'wire strong' : 'wire';
    S.trunk.forEach(w => { if (w.getAttribute('class') !== wcls) w.setAttribute('class', wcls); });
    const tap = 'wire tap' + (cfg.eaves || cfg.tamper ? '' : ' off');
    if (S.tapWire.getAttribute('class') !== tap) S.tapWire.setAttribute('class', tap);
    const fw = 'wire tap' + (cfg.flood ? '' : ' off');
    if (S.floodWire.getAttribute('class') !== fw) S.floodWire.setAttribute('class', fw);

    /* gateway face */
    S.gateSplit.setAttribute('display', cfg.limit ? 'none' : 'inline');
    S.gateWall.setAttribute('display', cfg.limit ? 'inline' : 'none');
    S.gatePill.set(['เกตเวย์', cfg.limit ? 'จำกัดอัตรา' : 'ส่งผ่าน']);
    S.gatePill.tone(cfg.limit ? 'ok' : '');

    /* attacker dimming + label */
    const busy = cfg.eaves || cfg.tamper || cfg.flood;
    S.atkG.setAttribute('opacity', busy ? 1 : 0.32);
    const acts = [];
    if (cfg.eaves) acts.push('ดักฟัง');
    if (cfg.tamper) acts.push('แก้ข้อมูล');
    if (cfg.flood) acts.push('ยิงถล่ม');
    S.atkPill.set(['ผู้โจมตี', acts.length ? acts.join(' + ') : 'ยังไม่ลงมือ']);
    S.atkPill.tone(busy ? 'hot' : 'dead');

    /* three pillars */
    const leak = ctx.stats.leak || 0, tam = ctx.stats.tampered || 0, blk = ctx.stats.blocked || 0;
    if (!cfg.eaves) S.hud.set(0, 'ok', 'ปกติ');
    else if (cfg.encrypt) S.hud.set(0, 'ok', 'เข้ารหัสแล้ว');
    else S.hud.set(0, 'bad', 'รั่ว ' + leak);

    if (!cfg.tamper) S.hud.set(1, 'ok', 'ปกติ');
    else if (cfg.sign) S.hud.set(1, 'ok', 'จับได้ ' + (ctx.stats.caught || 0));
    else S.hud.set(1, 'bad', 'เชื่อปลอม ' + tam);

    if (!cfg.flood) S.hud.set(2, blk > 0 ? 'bad' : 'ok', blk > 0 ? 'ล้น ' + blk : 'รับไหว');
    else if (cfg.limit) S.hud.set(2, blk > 0 ? 'bad' : 'ok', blk > 0 ? 'ล้น ' + blk : 'กรองแล้ว');
    else S.hud.set(2, 'bad', '503 ' + blk);

    /* attacker log */
    for (let i = 0; i < 3; i++) {
      const row = S.log[i];
      if (!row) { S.logPanel.set(i, i === 0 && !cfg.eaves ? '— ไม่มีข้อมูล —' : '', 'dim term'); continue; }
      S.logPanel.set(i, (row.safe ? '? ' : '> ') + row.text, row.safe ? 'term dim' : 'term-bad');
    }
  }
});
})();
