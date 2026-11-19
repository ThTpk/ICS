/* ============================================================
   บทที่ 3.2 — Firewall และการกรองทราฟฟิก
   default deny · จำกัดต้นทาง · stateful · ข้อจำกัดที่ชั้นแอป
   ============================================================ */
(function () {
const OFFICE = '10.0.0.5', NET = '203.0.113.9';
const SRC = [
  { p: [0.15, 5.35], ip: OFFICE, name: 'สำนักงาน' },
  { p: [2.15, 7.35], ip: NET, name: 'อินเทอร์เน็ต' }
];
const FW = [3.95, 3.55];
const SRV = [
  { p: [4.85, -0.75], port: 443, name: 'เว็บ', pal: 'blue' },
  { p: [6.35, 0.75], port: 22, name: 'SSH', pal: 'bone' },
  { p: [7.85, 2.25], port: 5432, name: 'ฐานข้อมูล', pal: 'green' }
];
const PORT_IX = { 443: 0, 22: 1, 5432: 2 };

function rules(cfg) {
  if (cfg.mode === 'open') return null;
  const r = [{ src: '*', port: 443, act: 'allow' }];
  if (cfg.mode === 'sshOpen') r.push({ src: '*', port: 22, act: 'allow' });
  if (cfg.mode === 'sshOffice') r.push({ src: OFFICE, port: 22, act: 'allow' });
  r.push({ src: '*', port: '*', act: 'deny' });
  return r;
}
function decide(cfg, pkt) {
  const R = rules(cfg);
  if (!R) return { allow: true, n: 0, why: 'ไม่มีไฟร์วอลล์' };
  for (let i = 0; i < R.length; i++) {
    const r = R[i];
    if ((r.src === '*' || r.src === pkt.ip) && (r.port === '*' || r.port === pkt.port))
      return { allow: r.act === 'allow', n: i + 1, why: 'กฎ ' + (i + 1) };
  }
  return { allow: false, n: R.length, why: 'กฎสุดท้าย' };
}
function ruleLines(cfg) {
  if (cfg.mode === 'open') return [['ไม่มีไฟร์วอลล์', 'bad'], ['ทุกพอร์ตเปิดสู่อินเทอร์เน็ตโดยตรง', 'dim'], ['', ''], ['', ''], ['', '']];
  const R = rules(cfg);
  const out = [['#   ต้นทาง          ปลายทาง     การกระทำ', 'dim']];
  R.forEach((r, i) => {
    const src = r.src === '*' ? 'ใครก็ได้' : r.src;
    const dst = r.port === '*' ? 'ทุกพอร์ต' : ':' + r.port;
    const act = r.act === 'allow' ? 'อนุญาต' : 'ปฏิเสธ';
    out.push([(i + 1) + '   ' + (src + '              ').slice(0, 14) + (dst + '          ').slice(0, 11) + act,
      r.act === 'allow' ? 'mono' : 'mono dim']);
  });
  while (out.length < 5) out.push(['', '']);
  return out;
}

ICS.register({
  id: 'firewall',
  title: 'Firewall และการกรองทราฟฟิก',
  sub: 'กฎไม่กี่บรรทัดที่ตัดสินว่าแพ็กเก็ตไหนเข้าได้ และเส้นที่มันมองไม่ทะลุ',
  minutes: 12,
  level: 'ระดับกลาง',

  legend: [
    ['req sq', 'แพ็กเก็ตขาเข้า'],
    ['res', 'คำตอบขากลับ'],
    ['bad', 'ถูกปฏิเสธ / เป็นการโจมตี'],
    ['hollow', 'กฎที่อนุญาต']
  ],

  metrics: [
    { key: 'pass', label: 'ผ่านเข้าไปได้' },
    { key: 'deny', label: 'ถูกปฏิเสธ', tone: c => (c.stats.deny || 0) > 0 ? 'lit' : '' },
    { key: 'brute', label: 'เดารหัส SSH ได้', bad: true, tone: c => (c.stats.brute || 0) > 0 ? 'warn' : '' },
    { key: 'dbhit', label: 'ถึงฐานข้อมูลตรงๆ', bad: true, tone: c => (c.stats.dbhit || 0) > 0 ? 'warn' : '' },
    { key: 'appHit', label: 'โจมตีผ่าน :443', bad: true, tone: c => (c.stats.appHit || 0) > 0 ? 'warn' : '' },
    { key: 'dropresp', label: 'คำตอบที่ถูกตัดทิ้ง', bad: true }
  ],

  learn: [
    ['ไม่มีไฟร์วอลล์แปลว่าทุกพอร์ตคือประตูหน้าบ้าน', 0],
    ['ตั้งค่าเริ่มต้นเป็นปฏิเสธ แล้วเปิดเฉพาะที่จำเป็น', 1],
    ['กฎต้องจำกัดทั้งพอร์ตและต้นทาง', 3],
    ['stateful ทำให้คำตอบขากลับผ่านได้เองโดยไม่ต้องเปิดรูเพิ่ม', 4],
    ['ไฟร์วอลล์ไม่เห็นเนื้อข้างใน :443', 5]
  ],

  steps: [
    {
      tag: 'problem', label: 'ไม่มีกำแพง', title: 'เซิร์ฟเวอร์ที่ต่อตรงกับอินเทอร์เน็ต',
      body: [
        'ทุกบริการบนเครื่องถูกเปิดให้โลกทั้งใบเรียกถึงได้ ไม่ใช่แค่เว็บที่พอร์ต <code>443</code> แต่รวมถึง <code>22</code> ที่ใช้เข้าเครื่อง และ <code>5432</code> ที่เป็นฐานข้อมูลด้วย',
        'บอตที่สแกนทั้งอินเทอร์เน็ตเจอเครื่องแบบนี้ภายในไม่กี่นาที ดูช่อง "ถึงฐานข้อมูลตรงๆ" ที่ไม่ควรมีค่ามากกว่าศูนย์เลยแม้แต่ครั้งเดียว'
      ],
      note: ['เร็วกว่าที่คิดมาก', 'เครื่องใหม่ที่เปิดพอร์ตทิ้งไว้บนคลาวด์ มักเจอการพยายามล็อกอินครั้งแรกภายในเวลาไม่ถึงชั่วโมง โดยไม่ต้องมีใครรู้จักคุณเลย'],
      changed: ['ไฟร์วอลล์: ไม่มี', 'พอร์ตที่เปิด: ทั้งหมด'],
      cfg: { mode: 'open', stateful: true, waf: false, appAttack: false }
    },
    {
      tag: 'technique', label: 'ปฏิเสธก่อน', title: 'ตั้งค่าเริ่มต้นเป็นปฏิเสธ แล้วเปิดทีละข้อ',
      body: [
        'กฎสุดท้ายในตารางคือ <code>ปฏิเสธทุกอย่าง</code> แล้วเราค่อยเขียนกฎอนุญาตไว้ข้างบนเฉพาะสิ่งที่จำเป็นจริงๆ ตอนนี้มีข้อเดียวคือเว็บที่พอร์ต 443',
        'ไฟร์วอลล์อ่านกฎจากบนลงล่างแล้วหยุดที่ข้อแรกที่ตรง แพ็กเก็ตที่ยิงไปพอร์ต 22 และ 5432 จึงตกไปถึงกฎสุดท้ายและถูกตัดทิ้งที่กำแพง'
      ],
      note: ['ทำไมต้องปฏิเสธเป็นค่าตั้งต้น', 'ถ้าตั้งเป็นอนุญาตก่อนแล้วไล่ห้ามทีละอย่าง เราต้องเดาให้ครบทุกสิ่งที่อันตราย ซึ่งเป็นไปไม่ได้ การปฏิเสธก่อนทำให้สิ่งที่เราลืมคิดถึงปลอดภัยโดยอัตโนมัติ'],
      changed: ['ไฟร์วอลล์: เปิดใช้งาน', 'กฎ: อนุญาตเฉพาะ :443'],
      cfg: { mode: 'deny', stateful: true, waf: false, appAttack: false }
    },
    {
      tag: 'problem', label: 'เปิด 22', title: 'แต่แอดมินก็ต้องเข้าเครื่องได้',
      body: [
        'ทีมงานบ่นว่าเข้า SSH ไม่ได้ วิธีที่เร็วที่สุดคือเพิ่มกฎอนุญาตพอร์ต 22 ซึ่งแก้ปัญหาได้ทันทีจริงๆ แต่กฎนั้นเขียนว่า <code>ใครก็ได้</code>',
        'บอตจากอินเทอร์เน็ตจึงเข้าได้ด้วยเหมือนกัน และมันไม่ได้มาทำงาน มันมาไล่เดารหัสผ่านทีละชุด ดูช่อง "เดารหัส SSH ได้" ที่เริ่มขยับ'
      ],
      note: ['กฎที่กว้างเกินจำเป็น', 'ช่องโหว่ส่วนใหญ่ของไฟร์วอลล์ไม่ได้เกิดจากซอฟต์แวร์มีบั๊ก แต่เกิดจากกฎที่เขียนกว้างไว้ก่อนเพื่อให้งานเดิน แล้วไม่มีใครกลับมาแคบมันลง'],
      changed: ['เพิ่มกฎ: ใครก็ได้ → :22 อนุญาต'],
      cfg: { mode: 'sshOpen', stateful: true, waf: false, appAttack: false }
    },
    {
      tag: 'technique', label: 'จำกัดต้นทาง', title: 'กฎที่ดีต้องระบุทั้งพอร์ตและต้นทาง',
      body: [
        'แก้กฎข้อที่สองจาก "ใครก็ได้" เป็นไอพีของสำนักงาน <code>10.0.0.5</code> เท่านั้น แอดมินยังทำงานได้เหมือนเดิมทุกอย่าง แต่บอตจากอินเทอร์เน็ตตกกฎสุดท้ายและถูกตัดทิ้ง',
        'หลักการนี้ชื่อว่า least exposure เปิดให้น้อยที่สุด เปิดให้คนน้อยที่สุด และเปิดนานน้อยที่สุดเท่าที่งานจะเดินได้'
      ],
      note: ['ดีกว่านั้นได้อีก', 'ไม่เปิดพอร์ต 22 ออกสู่อินเทอร์เน็ตเลย แล้วให้แอดมินต่อ VPN เข้ามาก่อน จะเหลือพื้นที่ให้โจมตีน้อยกว่าการเปิดไว้แล้วกรองไอพี'],
      changed: ['แก้กฎ 2: เฉพาะ 10.0.0.5 → :22'],
      cfg: { mode: 'sshOffice', stateful: true, waf: false, appAttack: false }
    },
    {
      tag: 'concept', label: 'Stateful', title: 'คำตอบขากลับผ่านได้เพราะไฟร์วอลล์จำสถานะ',
      body: [
        'กฎทั้งหมดที่เขียนมาเป็นกฎขาเข้า แล้วคำตอบที่เซิร์ฟเวอร์ส่งกลับออกไปล่ะ ถ้าไฟร์วอลล์ดูทีละแพ็กเก็ตแบบไม่จำอะไรเลย มันจะไม่รู้ว่าแพ็กเก็ตนั้นเป็นคำตอบของอะไร',
        'ลองปิดสวิตช์ด้านล่าง คำตอบจะถูกตัดทิ้งที่กำแพงทั้งหมด เว็บค้างทั้งที่คำขอเข้าไปถึงแล้ว ไฟร์วอลล์แบบ stateful แก้เรื่องนี้ด้วยการจำว่าใครเปิดการเชื่อมต่อไว้บ้าง แล้วปล่อยคำตอบของการเชื่อมต่อนั้นผ่านเอง'
      ],
      note: ['อย่าแก้ด้วยการเปิดรูเพิ่ม', 'ทางแก้ที่ผิดคือเขียนกฎอนุญาตพอร์ตสูงทั้งช่วงเพื่อให้คำตอบผ่าน ซึ่งเท่ากับเปิดประตูถาวรให้สิ่งอื่นด้วย ไฟร์วอลล์ยุคนี้เป็น stateful หมดแล้ว'],
      changed: ['เพิ่มการติดตามสถานะการเชื่อมต่อ'],
      cfg: { mode: 'sshOffice', stateful: true, waf: false, appAttack: false },
      controls: ['stateful']
    },
    {
      tag: 'problem', label: 'มองไม่ทะลุ', title: 'สิ่งที่ไฟร์วอลล์มองไม่เห็น',
      body: [
        'ไฟร์วอลล์ตัดสินจากไอพีและพอร์ต มันจึงตอบได้แค่ว่า "แพ็กเก็ตนี้ไปพอร์ต 443 ซึ่งเราอนุญาต" แต่ตอบไม่ได้ว่าข้างในแพ็กเก็ตนั้นเป็นคำขอดูหน้าแรก หรือเป็น SQL injection',
        'ตอนนี้ผู้โจมตีเลิกยุ่งกับพอร์ต 22 แล้วหันมาส่งการโจมตีผ่านพอร์ต 443 ที่เปิดอยู่อย่างถูกกฎทุกประการ กำแพงปล่อยผ่านหมด เปิด WAF ด้านล่างเพื่อให้มีคนอ่านเนื้อข้างใน'
      ],
      note: ['คนละชั้นกัน', 'ไฟร์วอลล์ทำงานที่ชั้นเครือข่าย ส่วน WAF ทำงานที่ชั้นแอปพลิเคชัน ทั้งคู่จำเป็นและแทนกันไม่ได้ แต่ WAF ก็เป็นแค่ตัวกรองที่ถูกเลี่ยงได้ การแก้โค้ดให้ถูกยังสำคัญกว่า'],
      changed: ['ผู้โจมตี: ย้ายมาโจมตีผ่าน :443'],
      cfg: { mode: 'sshOffice', stateful: true, waf: false, appAttack: true },
      controls: ['waf']
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: แก้ตารางกฎแล้วดูผล',
      body: [
        'ลองสลับกลับไปใช้กฎที่เปิดพอร์ต 22 ให้ทุกคน แล้วดูว่าภายในสิบวินาทีมีการเดารหัสกี่ครั้ง จากนั้นลองปิด stateful ขณะที่ทุกกฎยังถูกต้อง เพื่อดูว่าระบบที่ตั้งค่าถูกแต่ขาดการจำสถานะก็ใช้งานไม่ได้เหมือนกัน',
        'คำถามปิดท้าย ถ้าผู้โจมตียึดเครื่องในสำนักงานได้สำเร็จ กฎที่กรองด้วยไอพีของสำนักงานจะยังช่วยอะไรได้บ้าง'
      ],
      note: ['อย่าไว้ใจแค่ขอบนอก', 'การคิดว่า "อยู่ในวงเน็ตเวิร์กเราแล้วปลอดภัย" คือรากของปัญหา แนวคิด zero trust จึงบอกว่าให้ตรวจตัวตนและสิทธิ์ทุกครั้ง ไม่ว่าคำขอจะมาจากที่ไหน'],
      changed: [],
      cfg: { mode: 'sshOffice', stateful: true, waf: true, appAttack: true },
      controls: ['mode', 'stateful', 'waf']
    }
  ],

  controls: {
    mode: {
      type: 'seg', label: 'ชุดกฎที่ใช้',
      options: [['open', 'ไม่มีไฟร์วอลล์'], ['deny', 'เฉพาะ :443'], ['sshOpen', '+ :22 ทุกคน'], ['sshOffice', '+ :22 เฉพาะออฟฟิศ']],
      get: c => c.mode, set: (c, v) => { c.mode = v; }
    },
    stateful: { type: 'toggle', label: 'ติดตามสถานะการเชื่อมต่อ', hint: 'ปล่อยคำตอบขากลับผ่านเอง', get: c => c.stateful, set: (c, v) => { c.stateful = v; } },
    waf: { type: 'toggle', label: 'เปิด WAF อ่านเนื้อใน :443', hint: 'ตรวจถึงชั้นแอปพลิเคชัน', get: c => c.waf, set: (c, v) => { c.waf = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      log: [],
      P: {
        s: SRC.map(s => iso(s.p[0], s.p[1], 0.75)),
        fw: iso(FW[0], FW[1], 1.0),
        v: SRV.map(s => iso(s.p[0] - 0.7, s.p[1], 0.7))
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    SRC.forEach(s => ctx.line(iso(s.p[0], s.p[1], 0.2), iso(FW[0], FW[1], 0.2), 'wire', L.wires));
    SRV.forEach(s => ctx.line(iso(FW[0], FW[1], 0.2), iso(s.p[0], s.p[1], 0.2), 'wire', L.wires));

    /* วาดจากหลังไปหน้าตามความลึก x+y */
    const items = [];
    SRV.forEach((s, i) => items.push({
      k: s.p[0] + s.p[1], draw: () => {
        const g = ctx.el('g', { class: 'node' }, L.ents);
        Ac.server(g, s.p[0], s.p[1], s.pal, 1.25);
        const pp = iso(s.p[0] + 0.95, s.p[1] + 0.95, 0);
        S['pill' + i] = ctx.pill(L.labels, pp[0], pp[1] + 16, [s.name + ' :' + s.port, '']);
        S['srv' + i] = g;
      }
    }));
    SRC.forEach((s, i) => items.push({
      k: s.p[0] + s.p[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        if (i === 0) Ac.desk(g, s.p[0], s.p[1], 'orange', 1.1); else Ac.attacker(g, s.p[0], s.p[1]);
        const pp = iso(s.p[0], s.p[1], 0);
        S['src' + i] = ctx.pill(L.labels, pp[0] - 6, pp[1] + 30, [s.name, s.ip]);
      }
    }));
    items.push({
      k: FW[0] + FW[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        const b = Ac.box(g, FW[0], FW[1], { w: 1.45, h: 0.75, pal: 'rose' });
        S.wallG = ctx.el('g', {}, g);
        ctx.glyph.wall(S.wallG, iso(FW[0], FW[1], b.box.zt));
        S.fwPill = ctx.pill(L.labels, iso(FW[0], FW[1] + 1.15, 0)[0], iso(FW[0], FW[1] + 1.15, 0)[1] + 16, ['ไฟร์วอลล์', '']);
      }
    });
    items.sort((a, b) => a.k - b.k).forEach(it => it.draw());

    S.ruleP = ctx.panel(L.hud, { x: 126, y: 72, w: 360, rows: 5, lh: 15, title: 'ตารางกฎของไฟร์วอลล์' });
    S.logP = ctx.panel(L.hud, { x: 126, y: 378, w: 352, rows: 4, title: 'บันทึกการตัดสินใจล่าสุด', dark: true });
    S.svcP = ctx.statusList(L.hud, {
      x: 500, y: 378, w: 216, title: 'การเปิดบริการ',
      items: SRV.map(s => s.name + ' :' + s.port)
    });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;

    /* แอดมินจากสำนักงาน */
    if (ctx.timer('office', dt, 2600))
      ctx.launch([P.s[0], P.fw], 'plain', { label: ':22', meta: { leg: 'fw', ip: OFFICE, port: 22, si: 0 }, speed: 270 });

    /* ทราฟฟิกจากอินเทอร์เน็ต */
    if (ctx.timer('net', dt, 900)) {
      const pool = cfg.appAttack
        ? [[443, 0], [443, 0], [443, 1], [22, 0], [5432, 0]]
        : [[443, 0], [443, 0], [22, 0], [22, 0], [5432, 0]];
      const pick = ctx.pick(pool);
      ctx.launch([P.s[1], P.fw], pick[1] ? 'bad' : 'plain', {
        label: ':' + pick[0] + (pick[1] ? ' SQLi' : ''),
        meta: { leg: 'fw', ip: NET, port: pick[0], si: 1, attack: !!pick[1] }, speed: 270
      });
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;

    if (m.leg === 'fw') {
      const d = decide(cfg, m);
      const wafBlock = d.allow && m.attack && cfg.waf;
      const tag = (m.ip === OFFICE ? OFFICE : NET) + ' → :' + m.port + (m.attack ? ' (SQLi)' : '');
      if (!d.allow || wafBlock) {
        ctx.bump('deny'); ctx.puff(P.fw, 'ok');
        S.log.unshift({ t: '✗ ' + tag + '   ' + (wafBlock ? 'WAF ตรวจเจอ' : d.why), ok: false });
        if (S.log.length > 4) S.log.length = 4;
        return;
      }
      const vi = PORT_IX[m.port];
      ctx.bump('pass');
      S.log.unshift({ t: '✓ ' + tag + '   ' + d.why, ok: true });
      if (S.log.length > 4) S.log.length = 4;
      ctx.launch([P.fw, P.v[vi]], m.attack ? 'bad' : 'plain',
        { label: m.attack ? 'SQLi' : ':' + m.port, meta: { leg: 'srv', vi, si: m.si, attack: m.attack, ip: m.ip }, speed: 280 });
      return;
    }

    if (m.leg === 'srv') {
      const top = [P.v[m.vi][0], P.v[m.vi][1] - 26];
      if (m.attack) { ctx.bump('appHit'); ctx.ring(P.v[m.vi]); ctx.float(top, 'ถูกโจมตี', 'bad'); }
      else if (m.vi === 2) { ctx.bump('dbhit'); ctx.ring(P.v[m.vi]); ctx.float(top, 'เข้าถึง DB', 'bad'); }
      else if (m.vi === 1 && m.ip === NET) { ctx.bump('brute'); ctx.ring(P.v[m.vi]); ctx.float(top, 'เดารหัส', 'bad'); }
      ctx.launch([P.v[m.vi], P.fw], 'res', { meta: { leg: 'back', si: m.si }, speed: 320 });
      return;
    }

    if (m.leg === 'back') {
      if (!cfg.stateful) {
        ctx.bump('dropresp'); ctx.puff(P.fw);
        S.log.unshift({ t: '✗ คำตอบขากลับ   ไม่มีกฎรองรับ', ok: false });
        if (S.log.length > 4) S.log.length = 4;
        return;
      }
      ctx.launch([P.fw, P.s[m.si]], 'res', { meta: { leg: 'done' }, speed: 340 });
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const on = cfg.mode !== 'open';

    S.wallG.setAttribute('opacity', on ? 1 : 0.18);
    S.fwPill.set(['ไฟร์วอลล์', !on ? 'ไม่มี' : cfg.waf ? 'กฎ + WAF' : 'กรองตามพอร์ต']);
    S.fwPill.tone(!on ? 'hot' : cfg.waf ? 'ok' : '');

    SRV.forEach((s, i) => {
      const d = decide(cfg, { ip: NET, port: s.port });
      const dOffice = decide(cfg, { ip: OFFICE, port: s.port });
      /* :443 ที่เปิดให้ทุกคนคือสิ่งที่ตั้งใจ ส่วน :22 และ :5432 ที่เปิดคือปัญหา */
      const state = (d.allow && s.port !== 443) ? 'bad' : 'ok';
      const val = d.allow ? 'เปิดให้ทุกคน' : dOffice.allow ? 'เฉพาะสำนักงาน' : 'ปิด';
      S.svcP.set(i, state, val);
      S['pill' + i].set([s.name + ' :' + s.port, val]);
      S['pill' + i].tone(d.allow && s.port !== 443 ? 'hot' : d.allow ? '' : 'ok');
    });

    S.src0.set(['สำนักงาน', OFFICE]);
    S.src1.set(['อินเทอร์เน็ต', NET]);
    S.src1.tone('hot');

    ruleLines(cfg).forEach((l, i) => S.ruleP.set(i, l[0], l[1]));
    for (let i = 0; i < 4; i++) {
      const r = S.log[i];
      S.logP.set(i, r ? r.t : (i === 0 ? '— รอทราฟฟิก —' : ''), r ? (r.ok ? 'term' : 'term-bad') : 'term dim');
    }
  }
});
})();
