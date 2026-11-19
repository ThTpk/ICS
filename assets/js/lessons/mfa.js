/* ============================================================
   บทที่ 5.1 — การยืนยันตัวตนหลายชั้น (MFA)
   รหัสผ่าน → OTP ทาง SMS → แอป TOTP → Passkey
   แต่ละชั้นกันอะไรได้ และกันอะไรไม่ได้
   ============================================================ */
(function () {
const USR = [-0.8, 4.2];
const ATK = [1.5, 6.5];
const GATE = [[2.45, 3.25], [4.05, 1.65], [5.65, 0.05]];
const ACCT = [7.05, -1.35];

const ATTACKS = {
  stuffing: 'ใช้รหัสที่รั่วจากเว็บอื่น',
  simswap: 'ย้ายเบอร์มือถือ (SIM swap)',
  phish: 'หน้าเว็บปลอมถามรหัสสดๆ'
};
const FACTOR_NAME = {
  pass: 'รหัสผ่านอย่างเดียว',
  sms: 'รหัสผ่าน + OTP ทาง SMS',
  totp: 'รหัสผ่าน + แอป TOTP',
  passkey: 'Passkey (อุปกรณ์ + ชีวมิติ)'
};
const activeGates = cfg => cfg.factors === 'pass' ? [0] : cfg.factors === 'passkey' ? [2] : [0, 1];
const gateName = (cfg, i) => i === 0 ? 'รหัสผ่าน' : i === 1 ? (cfg.factors === 'sms' ? 'OTP ทาง SMS' : 'แอป TOTP') : 'Passkey';

/* ประตูนี้หยุดการโจมตีแบบนี้ได้หรือไม่ */
function blocks(cfg, gate, attack) {
  if (gate === 0) return false;                                   // รหัสผ่านรั่วไปแล้ว ผ่านได้เสมอ
  if (gate === 1) {
    if (cfg.factors === 'sms') return attack === 'stuffing';      // SIM swap และฟิชชิ่งยังผ่าน
    return attack === 'stuffing' || attack === 'simswap';         // TOTP กัน SIM swap ได้ แต่ฟิชชิ่งยังผ่าน
  }
  return true;                                                    // Passkey ผูกกับโดเมน กันได้ทั้งหมด
}

ICS.register({
  id: 'mfa',
  title: 'การยืนยันตัวตนหลายชั้น (MFA)',
  sub: 'เพิ่มปัจจัยที่สองช่วยได้มหาศาล แต่ไม่ใช่ทุกปัจจัยที่สองจะกันการโจมตีแบบเดียวกัน',
  minutes: 12,
  level: 'ระดับกลาง',

  legend: [
    ['res', 'ผู้ใช้ตัวจริง'],
    ['bad', 'ผู้โจมตี'],
    ['hollow', 'ประตูที่บล็อกได้'],
    ['key sq', 'ปัจจัยที่เปิดใช้']
  ],

  metrics: [
    { key: 'ok', label: 'ผู้ใช้จริงเข้าได้' },
    { key: 'breach', label: 'ผู้โจมตียึดบัญชี', bad: true, tone: c => (c.stats.breach || 0) > 0 ? 'warn' : '' },
    { key: 'blocked', label: 'ถูกบล็อก', tone: c => (c.stats.blocked || 0) > 0 ? 'lit' : '' },
    {
      key: 'rate', label: 'อัตราที่ผู้โจมตีทะลุ',
      fmt: c => { const t = (c.stats.breach || 0) + (c.stats.blocked || 0); return t ? Math.round((c.stats.breach || 0) * 100 / t) + '%' : '–'; },
      tone: c => { const t = (c.stats.breach || 0) + (c.stats.blocked || 0); return t > 3 && !(c.stats.breach || 0) ? 'lit' : (c.stats.breach || 0) ? 'warn' : ''; }
    },
    { key: 'f', label: 'ปัจจัยที่ใช้', fmt: c => FACTOR_NAME[c.cfg.factors].split(' (')[0] }
  ],

  learn: [
    ['รหัสผ่านเดี่ยวแพ้การใช้รหัสที่รั่วมาจากที่อื่น', 0],
    ['ปัจจัยสามแบบ: สิ่งที่รู้ สิ่งที่มี สิ่งที่เป็น', 1],
    ['OTP ทาง SMS ผูกกับเบอร์ ไม่ใช่กับตัวคุณ', 2],
    ['TOTP กัน SIM swap ได้ แต่ยังถูกฟิชชิ่งสดได้', 4],
    ['Passkey ผูกกับโดเมน ฟิชชิ่งจึงใช้ไม่ได้', 5]
  ],

  steps: [
    {
      tag: 'problem', label: 'รหัสเดี่ยว', title: 'รหัสผ่านอย่างเดียวไม่พออีกต่อไป',
      body: [
        'ประตูมีบานเดียวคือรหัสผ่าน ผู้โจมตีไม่ได้เดาสุ่มด้วยซ้ำ เขาเอารหัสที่รั่วจากเว็บอื่นมาลองตรงๆ เพราะคนส่วนใหญ่ใช้รหัสซ้ำกันหลายเว็บ วิธีนี้เรียกว่า credential stuffing',
        'ผู้ใช้ตัวจริงกับผู้โจมตีถือกุญแจดอกเดียวกันเป๊ะ ระบบจึงแยกไม่ออกเลยว่าใครเป็นใคร ดูช่อง "อัตราที่ผู้โจมตีทะลุ" ที่ขึ้นไปถึงร้อยเปอร์เซ็นต์'
      ],
      note: ['เชื่อมกับบทแฮช', 'นี่คือเหตุผลที่การเก็บรหัสผ่านให้ดีเป็นเรื่องของทั้งอุตสาหกรรม ไม่ใช่ของเว็บใดเว็บหนึ่ง เพราะรหัสที่รั่วจากเว็บหนึ่งถูกเอาไปลองกับทุกเว็บที่เหลือ'],
      changed: ['ปัจจัย: รหัสผ่านอย่างเดียว', 'ผู้โจมตี: ใช้รหัสที่รั่วมา'],
      cfg: { factors: 'pass', attack: 'stuffing' }
    },
    {
      tag: 'technique', label: 'OTP SMS', title: 'เพิ่มปัจจัยที่สอง: รหัสที่ส่งทาง SMS',
      body: [
        'ปัจจัยในการยืนยันตัวตนมีสามแบบ <code>สิ่งที่รู้</code> เช่นรหัสผ่าน <code>สิ่งที่มี</code> เช่นโทรศัพท์หรือกุญแจฮาร์ดแวร์ และ <code>สิ่งที่เป็น</code> เช่นลายนิ้วมือ การใช้สองแบบที่ต่างชนิดกันเรียกว่า MFA',
        'เพิ่มประตูที่สองเป็นรหัสหกหลักที่ส่งไปยังเบอร์ของเจ้าของบัญชี ผู้โจมตีมีรหัสผ่านก็จริง แต่ไม่มีโทรศัพท์เครื่องนั้น จึงถูกหยุดที่ประตูที่สองทุกครั้ง'
      ],
      note: ['สองรหัสผ่านไม่ใช่ MFA', 'ถามรหัสผ่านแล้วถามคำถามลับต่อ ยังเป็น "สิ่งที่รู้" ทั้งคู่ ซึ่งรั่วไปพร้อมกันได้ ปัจจัยที่เพิ่มต้องเป็นคนละชนิดจึงจะมีความหมาย'],
      changed: ['เพิ่มปัจจัย: OTP ทาง SMS'],
      cfg: { factors: 'sms', attack: 'stuffing' }
    },
    {
      tag: 'attack', label: 'SIM swap', title: 'ย้ายเบอร์มือถือมาที่ซิมของตัวเอง',
      body: [
        'จุดอ่อนของ SMS คือมันผูกกับหมายเลขโทรศัพท์ ไม่ได้ผูกกับตัวคุณ ผู้โจมตีจึงโทรไปหาผู้ให้บริการ อ้างว่าทำซิมหาย แล้วขอย้ายเบอร์มาที่ซิมใหม่ของตัวเอง',
        'ตั้งแต่วินาทีนั้น OTP ทุกข้อความวิ่งไปที่เครื่องของผู้โจมตี ประตูที่สองเปิดให้เขาเดินผ่านอย่างถูกต้องตามระบบทุกประการ'
      ],
      note: ['ยังดีกว่าไม่มี', 'ถึงจะมีช่องโหว่นี้ แต่ OTP ทาง SMS ก็ยังหยุดการโจมตีอัตโนมัติจำนวนมหาศาลได้ ถ้าเลือกได้ระหว่างไม่มีอะไรเลยกับ SMS ให้เลือก SMS เสมอ'],
      changed: ['ผู้โจมตี: ย้ายเบอร์มือถือสำเร็จ'],
      cfg: { factors: 'sms', attack: 'simswap' }
    },
    {
      tag: 'technique', label: 'แอป TOTP', title: 'ย้ายรหัสมาสร้างในเครื่อง ไม่ต้องส่งผ่านเครือข่าย',
      body: [
        'แอปอย่าง Google Authenticator เก็บความลับร่วมไว้ในเครื่อง แล้วคำนวณรหัสหกหลักใหม่ทุกสามสิบวินาทีจากความลับนั้นบวกเวลาปัจจุบัน ไม่มีอะไรถูกส่งผ่านเครือข่ายให้ดักได้',
        'เบอร์โทรศัพท์จึงไม่เกี่ยวข้องอีกต่อไป การย้ายซิมไม่ช่วยอะไรผู้โจมตีเลย เขาถูกหยุดที่ประตูที่สองอีกครั้ง'
      ],
      note: ['ข้อควรระวังของ TOTP', 'ความลับร่วมอยู่ในเครื่อง ถ้าทำเครื่องหายโดยไม่มีรหัสสำรองก็เข้าบัญชีไม่ได้ และถ้าสกรีนช็อต QR ตอนตั้งค่าแล้วเก็บไว้ในคลาวด์ ความลับนั้นก็รั่วไปพร้อมคลาวด์ได้'],
      changed: ['เปลี่ยนปัจจัยที่สองเป็นแอป TOTP'],
      cfg: { factors: 'totp', attack: 'simswap' }
    },
    {
      tag: 'attack', label: 'ฟิชชิ่งสด', title: 'หน้าเว็บปลอมที่ส่งรหัสต่อแบบเรียลไทม์',
      body: [
        'ผู้โจมตีทำหน้าล็อกอินปลอมที่เหมือนของจริงทุกพิกเซล เหยื่อกรอกรหัสผ่านและรหัสหกหลักลงไป หน้าปลอมส่งต่อให้เว็บจริงทันทีภายในไม่กี่วินาที ก่อนรหัสจะหมดอายุ',
        'รหัส TOTP ถูกต้องจริงทุกหลัก ประตูที่สองจึงเปิดให้ ปัญหาไม่ได้อยู่ที่ความแข็งแรงของรหัส แต่อยู่ที่ไม่มีใครตรวจว่าเหยื่อกำลังกรอกให้ "เว็บไหน"'
      ],
      note: ['ชื่อของเทคนิคนี้', 'เรียกว่า adversary-in-the-middle มีชุดเครื่องมือสำเร็จรูปขายกันทั่วไป ทำให้การฟิชชิ่งผ่าน MFA แบบรหัสหกหลักกลายเป็นเรื่องธรรมดาไปแล้ว'],
      changed: ['ผู้โจมตี: ฟิชชิ่งแบบส่งต่อสดๆ'],
      cfg: { factors: 'totp', attack: 'phish' }
    },
    {
      tag: 'technique', label: 'Passkey', title: 'Passkey: ปัจจัยที่รู้ว่ากำลังคุยกับเว็บไหน',
      body: [
        'Passkey คือกุญแจคู่จากบทที่ 2.2 ที่เก็บ private key ไว้ในชิปของอุปกรณ์ และปลดล็อกด้วยลายนิ้วมือหรือใบหน้า การล็อกอินคือการเซ็นข้อความที่เว็บส่งมา ไม่มีรหัสอะไรให้พิมพ์หรือให้บอกใคร',
        'ที่สำคัญที่สุดคือลายเซ็นนั้นผูกกับชื่อโดเมนที่ขอมาด้วย หน้าเว็บปลอมที่อยู่คนละโดเมนจึงไม่ได้ลายเซ็นที่ใช้ได้เลย ฟิชชิ่งหยุดทำงานไปเองโดยไม่ต้องอาศัยความระวังของผู้ใช้'
      ],
      note: ['ทำไมถึงเป็นสองปัจจัยในตัวเดียว', 'มันรวม "สิ่งที่มี" คืออุปกรณ์ที่ถือ กับ "สิ่งที่เป็น" คือลายนิ้วมือหรือใบหน้าที่ใช้ปลดล็อกไว้ด้วยกัน จึงแทนทั้งรหัสผ่านและ OTP ได้พร้อมกัน'],
      changed: ['เปลี่ยนมาใช้ Passkey'],
      cfg: { factors: 'passkey', attack: 'phish' }
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: จับคู่ปัจจัยกับการโจมตี',
      body: [
        'ไล่สลับทุกคู่ดูว่าช่องไหนกันช่องไหนได้บ้าง จะเห็นตารางในหัวชัดขึ้นว่า SMS กันได้แค่การโจมตีอัตโนมัติ TOTP เพิ่มการกัน SIM swap และมีเพียง Passkey เท่านั้นที่กันฟิชชิ่งได้',
        'ข้อสรุปที่ใช้ได้จริง ถ้าเลือกได้ให้เปิด Passkey ถ้ายังไม่มีให้ใช้แอป TOTP และถ้ามีแค่ SMS ก็ยังควรเปิด เพราะดีกว่าไม่มีอะไรเลยมาก'
      ],
      note: ['อย่าลืมทางหนีไฟ', 'ช่องทางกู้บัญชีเมื่อทำอุปกรณ์หาย มักเป็นจุดที่อ่อนที่สุดของระบบทั้งหมด ถ้ากู้บัญชีได้ด้วยการตอบคำถามลับ MFA ที่แข็งแรงแค่ไหนก็ถูกข้ามได้ตรงนั้น'],
      changed: [],
      cfg: { factors: 'sms', attack: 'phish' },
      controls: ['factors', 'attack']
    }
  ],

  controls: {
    factors: {
      type: 'seg', label: 'ปัจจัยที่บัญชีนี้เปิดใช้',
      options: [['pass', 'รหัสผ่าน'], ['sms', '+ OTP SMS'], ['totp', '+ แอป TOTP'], ['passkey', 'Passkey']],
      get: c => c.factors, set: (c, v) => { c.factors = v; }, reset: true
    },
    attack: {
      type: 'seg', label: 'วิธีที่ผู้โจมตีใช้',
      options: [['stuffing', 'รหัสที่รั่วมา'], ['simswap', 'SIM swap'], ['phish', 'ฟิชชิ่งสด']],
      get: c => c.attack, set: (c, v) => { c.attack = v; }, reset: true
    }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      log: [],
      P: {
        u: iso(USR[0], USR[1], 0.78),
        a: iso(ATK[0], ATK[1], 0.72),
        g: GATE.map(g => iso(g[0], g[1], 0.95)),
        acct: iso(ACCT[0] - 0.6, ACCT[1], 0.8)
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    ctx.line(iso(USR[0], USR[1], 0.2), iso(GATE[0][0], GATE[0][1], 0.2), 'wire', L.wires);
    ctx.line(iso(ATK[0], ATK[1], 0.2), iso(GATE[0][0], GATE[0][1], 0.2), 'wire tap', L.wires);
    ctx.line(iso(ATK[0], ATK[1], 0.2), iso(GATE[2][0], GATE[2][1], 0.2), 'wire tap', L.wires);
    for (let i = 0; i < 2; i++) ctx.line(iso(GATE[i][0], GATE[i][1], 0.2), iso(GATE[i + 1][0], GATE[i + 1][1], 0.2), 'wire', L.wires);
    ctx.line(iso(GATE[2][0], GATE[2][1], 0.2), iso(ACCT[0], ACCT[1], 0.2), 'wire', L.wires);

    const ug = ctx.el('g', {}, L.ents);
    Ac.desk(ug, USR[0], USR[1], 'orange', 1.1);
    ctx.pill(L.labels, S.P.u[0] - 4, iso(USR[0], USR[1] + 0.95, 0)[1] + 14, ['ผู้ใช้ตัวจริง', 'ann']);

    const ag = ctx.el('g', {}, L.ents);
    Ac.attacker(ag, ATK[0], ATK[1]);
    S.aPill = ctx.pill(L.labels, S.P.a[0] - 4, iso(ATK[0], ATK[1] + 0.9, 0)[1] + 14, ['ผู้โจมตี', '']);

    S.gates = GATE.map((g, i) => {
      const gg = ctx.el('g', {}, L.ents);
      const b = Ac.box(gg, g[0], g[1], { w: 1.2, h: 0.72, pal: i === 0 ? 'sand' : i === 1 ? 'blue' : 'green' });
      const c = iso(g[0], g[1], b.box.zt);
      const face = ctx.el('g', {}, gg);
      if (i === 0) ctx.glyph.lock(face, c);
      else if (i === 1) {
        for (let k = 0; k < 4; k++)
          ctx.el('rect', { class: 'glyph b', x: c[0] - 13 + k * 7, y: c[1] - 4, width: 5, height: 9, rx: 1.5, fill: '#d6e5f6' }, face);
      } else ctx.keyIcon(face, c[0] - 8, c[1], 'private', .95);
      const pill = ctx.pill(L.labels, iso(g[0], g[1] + 1.05, 0)[0], iso(g[0], g[1] + 1.05, 0)[1] + 14, ['']);
      return { g: gg, pill };
    });

    const cg = ctx.el('g', {}, L.ents);
    Ac.box(cg, ACCT[0], ACCT[1], { w: 1.3, h: 0.9, pal: 'violet', glyph: (p, c) => ctx.glyph.cert(p, c) });
    S.acctPill = ctx.pill(L.labels, iso(ACCT[0], ACCT[1] + 1.2, 0)[0], iso(ACCT[0], ACCT[1] + 1.2, 0)[1] + 14, ['บัญชีของ ann', '']);

    S.setP = ctx.statusList(L.hud, {
      x: 486, y: 74, w: 230, title: 'ปัจจัยที่เปิดใช้',
      items: ['สิ่งที่รู้ · รหัสผ่าน', 'สิ่งที่มี · อุปกรณ์', 'สิ่งที่เป็น · ชีวมิติ']
    });
    S.atkP = ctx.panel(L.hud, { x: 126, y: 76, w: 310, rows: 2, title: 'วิธีที่ผู้โจมตีใช้' });
    S.logP = ctx.panel(L.hud, { x: 126, y: 334, w: 342, rows: 4, title: 'บันทึกการล็อกอิน', dark: true });
    S.sumP = ctx.panel(L.hud, { x: 482, y: 334, w: 234, rows: 4, title: 'ปัจจัยนี้กันอะไรได้' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    const gs = activeGates(cfg);
    const first = P.g[gs[0]];
    if (ctx.timer('user', dt, 3400))
      ctx.launch([P.u, first], 'ok', { label: 'ann', meta: { leg: 'gate', gi: 0, gs, who: 'user' }, speed: 250 });
    if (ctx.timer('atk', dt, 2100))
      ctx.launch([P.a, first], 'bad', { label: 'ผู้โจมตี', meta: { leg: 'gate', gi: 0, gs, who: 'atk' }, speed: 250 });
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    const push = (t, cls) => { S.log.unshift({ t, cls }); if (S.log.length > 4) S.log.length = 4; };

    if (m.leg === 'gate') {
      const gi = m.gs[m.gi];
      if (m.who === 'atk' && blocks(cfg, gi, cfg.attack)) {
        ctx.bump('blocked'); ctx.puff(P.g[gi], 'ok');
        ctx.float([P.g[gi][0], P.g[gi][1] - 26], 'บล็อก', 'ok');
        push('✗ ผู้โจมตี ถูกหยุดที่ ' + gateName(cfg, gi), 'ok');
        return;
      }
      if (m.gi + 1 < m.gs.length) {
        ctx.launch([P.g[gi], P.g[m.gs[m.gi + 1]]], m.who === 'atk' ? 'bad' : 'ok',
          { label: m.who === 'atk' ? 'ผู้โจมตี' : 'ann', meta: { leg: 'gate', gi: m.gi + 1, gs: m.gs, who: m.who }, speed: 250 });
        return;
      }
      ctx.launch([P.g[gi], P.acct], m.who === 'atk' ? 'bad' : 'ok',
        { label: m.who === 'atk' ? 'ผู้โจมตี' : 'ann', meta: { leg: 'acct', who: m.who }, speed: 250 });
      return;
    }

    if (m.leg === 'acct') {
      if (m.who === 'atk') {
        ctx.bump('breach'); ctx.ring(P.acct);
        ctx.float([P.acct[0], P.acct[1] - 30], 'ยึดบัญชี', 'bad');
        push('⚠ ผู้โจมตี ผ่านครบทุกชั้น — ยึดบัญชีได้', 'bad');
      } else {
        ctx.bump('ok'); ctx.puff(P.acct, 'ok');
        push('✓ ann ผ่านครบ ' + m_count(cfg) + ' ชั้น', 'ok');
      }
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const gs = activeGates(cfg);

    S.gates.forEach((g, i) => {
      const on = gs.includes(i);
      g.g.setAttribute('opacity', on ? 1 : 0.22);
      g.pill.set([on ? gateName(cfg, i) : '(ไม่ใช้)']);
      g.pill.tone(on ? (blocks(cfg, i, cfg.attack) ? 'ok' : i === 0 ? '' : 'hot') : 'dead');
    });

    S.aPill.set(['ผู้โจมตี', ATTACKS[cfg.attack].split(' (')[0]]);
    S.aPill.tone('hot');
    const breached = (ctx.stats.breach || 0) > 0;
    S.acctPill.set(['บัญชีของ ann', breached ? 'ถูกยึดแล้ว' : 'ปลอดภัย']);
    S.acctPill.tone(breached ? 'hot' : 'ok');

    S.setP.set(0, cfg.factors === 'passkey' ? 'idle' : 'ok', cfg.factors === 'passkey' ? 'ไม่ใช้แล้ว' : 'ใช้อยู่');
    S.setP.set(1, cfg.factors === 'pass' ? 'idle' : 'ok', cfg.factors === 'pass' ? 'ไม่มี' : cfg.factors === 'sms' ? 'เบอร์มือถือ' : cfg.factors === 'totp' ? 'แอป TOTP' : 'อุปกรณ์');
    S.setP.set(2, cfg.factors === 'passkey' ? 'ok' : 'idle', cfg.factors === 'passkey' ? 'ลายนิ้วมือ' : 'ไม่มี');

    S.atkP.set(0, ATTACKS[cfg.attack], 'bad');
    S.atkP.set(1, cfg.attack === 'stuffing' ? 'มีรหัสผ่านที่ถูกต้องอยู่ในมือแล้ว'
      : cfg.attack === 'simswap' ? 'รับ SMS ของเหยื่อได้ทุกข้อความ'
      : 'ส่งรหัสที่เหยื่อกรอกต่อให้เว็บจริงทันที', 'dim');

    const rows = [
      ['รหัสที่รั่วมา', cfg.factors !== 'pass'],
      ['SIM swap', cfg.factors === 'totp' || cfg.factors === 'passkey'],
      ['ฟิชชิ่งสด', cfg.factors === 'passkey']
    ];
    rows.forEach((r, i) => S.sumP.set(i, (r[1] ? '✓ กันได้   ' : '✗ กันไม่ได้  ') + r[0], r[1] ? 'ok' : 'bad'));
    S.sumP.set(3, FACTOR_NAME[cfg.factors], 'dim');

    for (let i = 0; i < 4; i++) {
      const r = S.log[i];
      S.logP.set(i, r ? r.t : (i === 0 ? '— รอการล็อกอิน —' : ''), r ? (r.cls === 'bad' ? 'term-bad' : 'term') : 'term dim');
    }
  }
});

function m_count(cfg) { return cfg.factors === 'pass' ? 1 : cfg.factors === 'passkey' ? 1 : 2; }
})();
