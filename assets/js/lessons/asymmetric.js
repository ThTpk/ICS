/* ============================================================
   บทที่ 2.2 — การเข้ารหัสแบบอสมมาตร + ลายเซ็นดิจิทัล
   public/private key · MITM · ใบรับรองจาก CA
   ============================================================ */
(function () {
const A  = [0.2, 5.4];    // Alice
const J  = [3.4, 2.2];    // จุดที่สายถูกดัก
const B  = [6.8, -1.2];   // Bob
const M  = [5.7, 4.5];    // Mallory
const CA = [0.1, -0.7];    // Certificate Authority

const MSGS = ['PAY 500', 'MEET AT 8', 'SEND FILE', 'LOGIN OK'];
const HEXC = '0123456789abcdef';
function h32(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h; }
function hexOf(s, n) { let h = h32(s), o = ''; for (let i = 0; i < n; i++) { h = (Math.imul(h, 1103515245) + 12345) >>> 0; o += HEXC[(h >>> 28) & 15]; } return o; }

ICS.register({
  id: 'asymmetric',
  title: 'กุญแจคู่และลายเซ็นดิจิทัล',
  sub: 'กุญแจคนละดอกสำหรับเข้าและถอด แก้ปัญหาการแลกกุญแจได้ แต่เปิดช่องใหม่ที่ต้องมีคนกลางที่เชื่อถือได้มาปิด',
  minutes: 15,
  level: 'ระดับกลาง',

  legend: [
    ['key sq', 'public key (แจกได้)'],
    ['cipher sq', 'ข้อความที่เข้ารหัสแล้ว'],
    ['bad', 'กุญแจปลอม / Mallory อ่านได้'],
    ['res', 'ตรวจสอบผ่าน']
  ],

  metrics: [
    { key: 'dist', label: 'แจก public key' },
    { key: 'sent', label: 'ส่งทั้งหมด' },
    { key: 'read', label: 'Mallory อ่านได้', bad: true, tone: c => (c.stats.read || 0) > 0 ? 'warn' : (c.stats.sent > 2 ? 'lit' : '') },
    { key: 'swapped', label: 'กุญแจถูกสลับ', bad: true },
    { key: 'rejected', label: 'กุญแจปลอมถูกปฏิเสธ', tone: c => (c.stats.rejected || 0) > 0 ? 'lit' : '' },
    { key: 'verified', label: 'ลายเซ็นผ่าน' }
  ],

  learn: [
    ['public key แจกได้ private key ห้ามออกจากเครื่อง', 0],
    ['เข้ารหัสด้วย public ถอดได้ด้วย private เท่านั้น', 1],
    ['ลายเซ็นดิจิทัลใช้กุญแจสลับทิศกับการเข้ารหัส', 2],
    ['ถ้าสลับ public key ได้ ทุกอย่างพังโดยไม่มีใครรู้', 3],
    ['CA คือคนกลางที่ทำให้เชื่อ public key ได้', 4]
  ],

  steps: [
    {
      tag: 'concept', label: 'กุญแจคู่', title: 'กุญแจคู่: ดอกหนึ่งแจก ดอกหนึ่งเก็บ',
      body: [
        'Bob สร้างกุญแจขึ้นมาพร้อมกันสองดอกที่ผูกกันทางคณิตศาสตร์ ดอกสีเขียวคือ <code>public key</code> แจกให้ใครก็ได้ ดอกสีม่วงคือ <code>private key</code> ห้ามออกจากเครื่องเด็ดขาด',
        'ดูกุญแจสีเขียวที่วิ่งจาก Bob ไปหา Alice Mallory คว้าสำเนาไปด้วยก็ได้ ไม่เสียหายอะไรเลย เพราะมันตั้งใจให้เป็นของสาธารณะอยู่แล้ว นี่คือจุดที่ต่างจากบทที่แล้วอย่างสิ้นเชิง'
      ],
      note: ['ผูกกันยังไง', 'อาศัยปัญหาคณิตศาสตร์ที่คำนวณไปข้างหน้าง่ายแต่ย้อนกลับยากมาก เช่นการแยกตัวประกอบจำนวนเฉพาะขนาดใหญ่ใน RSA รู้ public แล้วคำนวณหา private ไม่ไหวในทางปฏิบัติ'],
      changed: ['Bob: สร้างกุญแจคู่', 'แจก public key ออกไป'],
      cfg: { dist: true, msg: false, sign: false, swap: false, cert: false }
    },
    {
      tag: 'technique', label: 'เข้ารหัส', title: 'เข้ารหัสด้วย public ถอดด้วย private',
      body: [
        'Alice ใช้ public key ของ Bob เข้ารหัสข้อความ ผลที่ได้มีแค่ private key ของ Bob เท่านั้นที่ถอดได้ แม้แต่ Alice เองที่เพิ่งเข้ารหัสไปก็ถอดกลับไม่ได้',
        'Mallory มี public key ของ Bob อยู่ในมือเต็มๆ เพราะมันแจกกันทั่วไป แต่เธอทำอะไรไม่ได้เลย ปัญหาการส่งกุญแจลับข้ามสายที่ค้างจากบทที่แล้วหายไปเอง'
      ],
      note: ['ทำไมไม่ใช้อันนี้อย่างเดียว', 'การเข้ารหัสแบบกุญแจคู่ช้ากว่า AES หลายร้อยเท่า ระบบจริงจึงใช้มันแค่ตอนตกลงกุญแจลับร่วมกันตอนต้น แล้วสลับไปใช้ AES กับข้อมูลจริง'],
      changed: ['Alice: เข้ารหัสด้วย PUB-BOB'],
      cfg: { dist: true, msg: true, sign: false, swap: false, cert: false }
    },
    {
      tag: 'technique', label: 'ลายเซ็น', title: 'ลายเซ็นดิจิทัล: ใช้กุญแจสลับทิศ',
      body: [
        'การเข้ารหัสตอบคำถามว่า "ใครอ่านได้" ส่วนลายเซ็นตอบคำถามว่า "ใครเป็นคนส่ง และข้อมูลถูกแก้หรือยัง" Alice จึงเซ็นด้วย <code>private key ของตัวเอง</code> แล้ว Bob ตรวจด้วย <code>public key ของ Alice</code>',
        'สังเกตว่าทิศทางการใช้กุญแจกลับกันกับตอนเข้ารหัสพอดี ป้าย <code>SIG</code> ที่วิ่งตามข้อความคือค่าลายเซ็น ถ้ามีใครแก้ข้อความแม้แต่ตัวอักษรเดียว ค่านี้จะไม่ตรงทันที'
      ],
      note: ['ปฏิเสธไม่ได้ (non-repudiation)', 'เพราะมีแค่ Alice ที่ถือ private key ของเธอ ลายเซ็นที่ตรวจผ่านจึงเป็นหลักฐานว่าเธอเป็นคนส่งจริง จะมาปฏิเสธทีหลังไม่ได้ ต่างจาก MAC ที่ทั้งสองฝ่ายใช้กุญแจเดียวกัน'],
      changed: ['Alice: เซ็นด้วย private key ของตัวเอง'],
      cfg: { dist: true, msg: true, sign: true, swap: false, cert: false }
    },
    {
      tag: 'attack', label: 'สลับกุญแจ', title: 'MITM: สลับ public key ตั้งแต่ต้นทาง',
      body: [
        'ช่องโหว่ไม่ได้อยู่ที่คณิตศาสตร์ แต่อยู่ที่คำถามง่ายๆ ว่า Alice รู้ได้ยังไงว่ากุญแจสีเขียวที่ได้มาเป็นของ Bob จริง Mallory จึงดักกุญแจของ Bob แล้วยัดกุญแจของตัวเองใส่มือ Alice แทน',
        'ต่อจากนี้ Alice เข้ารหัสถึง Mallory โดยไม่รู้ตัว Mallory ถอดอ่าน แล้วเข้ารหัสใหม่ด้วยกุญแจจริงของ Bob ส่งต่อไป ทั้งสองฝั่งคุยกันได้ปกติทุกอย่าง ไม่มีใครเอะใจเลย'
      ],
      note: ['รากของปัญหา', 'การเข้ารหัสรับประกันว่า "คนที่ถือ private key คู่กันเท่านั้นที่อ่านได้" แต่ไม่ได้รับประกันว่า "คนนั้นคือคนที่คุณตั้งใจจะคุยด้วย" สองเรื่องนี้ต้องแยกแก้'],
      changed: ['Mallory: สลับ public key กลางทาง'],
      cfg: { dist: true, msg: true, sign: true, swap: true, cert: false }
    },
    {
      tag: 'technique', label: 'ใบรับรอง', title: 'ใบรับรองจาก CA ปิดช่องสุดท้าย',
      body: [
        'Bob ไปให้ Certificate Authority เซ็นรับรองว่า "กุญแจดอกนี้เป็นของ Bob จริง" กุญแจจึงเดินทางมาพร้อมใบรับรองที่มีลายเซ็นของ CA ติดมาด้วย',
        'Alice มี public key ของ CA ติดตั้งมาอยู่แล้วในเครื่อง เธอจึงตรวจลายเซ็นบนใบรับรองได้เอง กุญแจของ Mallory ไม่มีลายเซ็นที่ตรวจผ่าน จึงถูกตีกลับตั้งแต่ประตู ดูช่อง "กุญแจปลอมถูกปฏิเสธ"'
      ],
      note: ['นี่คือแถบล็อกในเบราว์เซอร์', 'เวลาเห็นรูปกุญแจข้าง URL แปลว่าเบราว์เซอร์ตรวจใบรับรองของเว็บนั้นกับ CA ที่มันเชื่อถือแล้วผ่าน หน้าเตือน "ใบรับรองไม่ถูกต้อง" คือเหตุการณ์ที่คุณเพิ่งเห็นในขั้นที่แล้ว'],
      changed: ['Bob: แนบใบรับรองจาก CA', 'Alice: ตรวจลายเซ็นของ CA'],
      cfg: { dist: true, msg: true, sign: true, swap: true, cert: true }
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: ปิดทีละอย่างแล้วดูว่าใครพัง',
      body: [
        'ลองปิดใบรับรองขณะที่ Mallory ยังสลับกุญแจอยู่ แล้วดูว่าลายเซ็นดิจิทัลช่วยได้หรือไม่ คำตอบจะอธิบายว่าทำไม HTTPS ถึงต้องมีทั้งการเข้ารหัส ลายเซ็น และใบรับรองพร้อมกันทั้งสามอย่าง',
        'บทถัดไปจะเอาสามอย่างนี้มาต่อกันเป็นการจับมือของ TLS ที่ทำงานจริงทุกครั้งที่คุณเปิดเว็บ'
      ],
      note: ['ลองคิดดู', 'ถ้า CA ถูกเจาะหรือถูกบังคับให้ออกใบรับรองปลอม จะเกิดอะไรขึ้นกับทั้งระบบ และนี่คือเหตุผลที่มีระบบอย่าง Certificate Transparency ขึ้นมาคอยตรวจสอบ CA อีกชั้น'],
      changed: [],
      cfg: { dist: true, msg: true, sign: true, swap: true, cert: true },
      controls: ['swap', 'cert', 'sign']
    }
  ],

  controls: {
    swap: { type: 'toggle', label: 'Mallory: สลับ public key', hint: 'โจมตีแบบ man-in-the-middle', get: c => c.swap, set: (c, C) => { c.swap = C; }, reset: true },
    cert: { type: 'toggle', label: 'ใช้ใบรับรองจาก CA', hint: 'ให้ Alice ตรวจที่มาของกุญแจ', get: c => c.cert, set: (c, C) => { c.cert = C; }, reset: true },
    sign: { type: 'toggle', label: 'Alice เซ็นข้อความ', hint: 'ยืนยันผู้ส่งและความถูกต้อง', get: c => c.sign, set: (c, C) => { c.sign = C; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      aliceKey: 'BOB', log: [], bobLine: 'รอข้อความแรก', bobState: '', idx: 0,
      P: {
        a: iso(A[0], A[1], 0.78), j: iso(J[0], J[1], 0.5), b: iso(B[0], B[1], 0.78),
        m: iso(M[0], M[1] - 0.5, 0.72), ca: iso(CA[0], CA[1], 0.9)
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;
    ctx.T.pub = 400;   // แจก public key ครั้งแรกทันที ไม่ต้องรอครบคาบ

    ctx.line(iso(A[0], A[1], 0.22), iso(J[0], J[1], 0.22), 'wire', L.wires);
    ctx.line(iso(J[0], J[1], 0.22), iso(B[0], B[1], 0.22), 'wire', L.wires);
    S.tapWire = ctx.line(iso(M[0], M[1], 0.22), iso(J[0], J[1], 0.22), 'wire tap', L.wires);
    S.caWire = ctx.line(iso(CA[0], CA[1], 0.22), iso(A[0], A[1], 0.22), 'wire', L.wires);

    /* CA (หลังสุด) */
    S.caG = ctx.el('g', {}, L.ents);
    const cab = Ac.box(S.caG, CA[0], CA[1], { w: 1.3, h: 0.66, pal: 'violet' });
    ctx.glyph.cert(S.caG, iso(CA[0], CA[1], cab.box.zt));
    S.caPill = ctx.pill(L.labels, iso(CA[0], CA[1] + 1.0, 0)[0], iso(CA[0], CA[1] + 1.0, 0)[1] + 14, ['CA', 'ผู้ออกใบรับรอง']);

    /* Alice */
    const ag = ctx.el('g', {}, L.ents);
    Ac.desk(ag, A[0], A[1], 'orange');
    S.aliceKeyIcon = ctx.el('g', {}, ag);
    ctx.pill(L.labels, S.P.a[0], iso(A[0], A[1] + 0.9, 0)[1] + 14, ['Alice', 'ผู้ส่ง']);

    /* junction */
    const jg = ctx.el('g', {}, L.ents);
    Ac.box(jg, J[0], J[1], { w: 0.6, h: 0.3, pal: 'grey' });

    /* Bob */
    const bg = ctx.el('g', {}, L.ents);
    const bb = Ac.box(bg, B[0], B[1], { w: 1.3, h: 0.7, pal: 'blue' });
    const bk = iso(B[0], B[1], bb.box.zt + 0.55);
    ctx.keyIcon(bg, bk[0] - 20, bk[1], 'public', .8);
    ctx.keyIcon(bg, bk[0] + 4, bk[1], 'private', .8);
    ctx.pill(L.labels, S.P.b[0], iso(B[0], B[1] + 1.0, 0)[1] + 14, ['Bob', 'ผู้รับ']);

    /* Mallory */
    S.mG = ctx.el('g', {}, L.ents);
    Ac.attacker(S.mG, M[0], M[1]);
    S.mPill = ctx.pill(L.labels, iso(M[0], M[1] + 0.85, 0)[0] - 6, iso(M[0], M[1] + 0.85, 0)[1] + 14, ['Mallory', '']);

    S.aliceP = ctx.panel(L.hud, { x: 124, y: 78, w: 228, rows: 2, title: 'กุญแจที่ Alice ถืออยู่' });
    S.bobP = ctx.panel(L.hud, { x: 488, y: 78, w: 228, rows: 2, title: 'ฝั่ง Bob' });
    S.mP = ctx.panel(L.hud, { x: 298, y: 372, w: 272, rows: 3, title: 'จอของ Mallory', dark: true });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    if (cfg.dist && ctx.timer('pub', dt, cfg.msg ? 5000 : 2600)) {
      ctx.bump('dist');
      ctx.launch([P.b, P.j], 'key', { label: 'PUB-BOB' + (cfg.cert ? '+CERT' : ''), meta: { leg: 'pubwire', owner: 'BOB' }, speed: 200 });
    }
    if (cfg.msg && ctx.timer('msg', dt, 2300)) {
      const text = MSGS[S.idx++ % MSGS.length];
      const forKey = S.aliceKey;
      ctx.bump('sent');
      ctx.launch([P.a, P.j], 'cipher', {
        label: hexOf(text + forKey, 8), meta: { leg: 'msgwire', text, forKey, signed: cfg.sign }, speed: 200
      });
      if (cfg.sign) ctx.launch([P.a, P.j], 'key', { label: 'SIG', meta: { leg: 'sig' }, speed: 200, delay: 330 });
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    switch (m.leg) {
      case 'pubwire': {
        ctx.launch([P.j, P.m], 'key', { label: 'PUB-BOB', meta: { leg: 'mkey' }, speed: 180 });
        if (cfg.swap) {
          ctx.bump('swapped'); ctx.ring(P.j);
          ctx.launch([P.j, P.a], cfg.cert ? 'bad' : 'key',
            { label: cfg.cert ? 'PUB-MAL (ปลอม)' : 'PUB-MAL', meta: { leg: 'pubarrive', owner: 'MAL', bogus: cfg.cert }, speed: 200 });
        } else {
          ctx.launch([P.j, P.a], 'key', { label: m.owner === 'BOB' ? 'PUB-BOB' : 'PUB-MAL', meta: { leg: 'pubarrive', owner: m.owner }, speed: 200 });
        }
        break;
      }
      case 'pubarrive':
        if (m.bogus) {
          ctx.bump('rejected'); ctx.puff(P.a, 'ok');
          ctx.float([P.a[0], P.a[1] - 22], 'ใบรับรองไม่ผ่าน', 'ok');
        } else {
          S.aliceKey = m.owner;
          ctx.puff(P.a, m.owner === 'BOB' ? 'ok' : '');
        }
        break;
      case 'sig': ctx.launch([P.j, P.b], 'key', { label: 'SIG', meta: { leg: 'sigend' }, speed: 200 }); break;
      case 'sigend': break;
      case 'msgwire': {
        const malReads = cfg.swap && m.forKey === 'MAL';
        ctx.launch([P.j, P.m], malReads ? 'bad' : 'cipher',
          { label: malReads ? m.text : p.label, meta: { leg: 'mread', read: malReads, text: malReads ? m.text : p.label }, speed: 180 });
        if (malReads) {
          /* Mallory เข้ารหัสใหม่ด้วยกุญแจจริงของ Bob แล้วส่งต่อ ไม่มีใครรู้ */
          ctx.launch([P.j, P.b], 'cipher', { label: hexOf(m.text + 'BOB', 8), meta: { leg: 'bob', text: m.text, ok: true, relayed: true, signed: m.signed }, speed: 200 });
        } else {
          ctx.launch([P.j, P.b], 'cipher', { label: p.label, meta: { leg: 'bob', text: m.text, ok: m.forKey === 'BOB', signed: m.signed }, speed: 200 });
        }
        break;
      }
      case 'mread':
        if (m.read) { ctx.bump('read'); ctx.ring(P.m); }
        S.log.unshift({ text: m.text, read: m.read });
        if (S.log.length > 3) S.log.length = 3;
        break;
      case 'mkey':
        S.log.unshift({ text: 'เก็บ PUB-BOB ไว้', read: false, note: true });
        if (S.log.length > 3) S.log.length = 3;
        break;
      case 'bob':
        if (m.ok) {
          S.bobLine = m.text;
          S.bobState = m.signed ? 'ถอดรหัสได้ · ลายเซ็นผ่าน' : 'ถอดรหัสได้';
          if (m.signed) ctx.bump('verified');
          ctx.puff(P.b, 'ok');
        } else {
          S.bobLine = '??????';
          S.bobState = 'ถอดรหัสไม่ได้';
          ctx.puff(P.b);
        }
        break;
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;

    S.caG.setAttribute('opacity', cfg.cert ? 1 : 0.3);
    S.caWire.setAttribute('class', cfg.cert ? 'wire strong' : 'wire off');
    S.caPill.set(['CA', cfg.cert ? 'ใช้งานอยู่' : 'ยังไม่ใช้']);
    S.caPill.tone(cfg.cert ? 'ok' : 'dead');

    S.tapWire.setAttribute('class', 'wire tap' + (cfg.swap ? '' : ' off'));
    S.mG.setAttribute('opacity', cfg.swap ? 1 : 0.45);
    S.mPill.set(['Mallory', cfg.swap ? (cfg.cert ? 'ถูกจับได้' : 'อ่านได้ทุกข้อความ') : 'ได้แต่ดู']);
    S.mPill.tone(cfg.swap && !cfg.cert ? 'hot' : cfg.swap ? '' : 'dead');

    /* กุญแจที่ Alice ถือ */
    const bad = S.aliceKey === 'MAL';
    if (S.lastKeyState !== S.aliceKey) {
      S.lastKeyState = S.aliceKey;
      S.aliceKeyIcon.textContent = '';
      const k = ctx.iso(A[0], A[1], 1.25);
      ctx.keyIcon(S.aliceKeyIcon, k[0] - 8, k[1], bad ? 'private' : 'public', .9);
    }
    S.aliceP.set(0, bad ? 'PUB-MAL — กุญแจของผู้โจมตี' : 'PUB-BOB — ของ Bob จริง', bad ? 'bad' : 'ok');
    S.aliceP.set(1, cfg.cert ? 'ตรวจลายเซ็นของ CA ทุกครั้ง' : 'ไม่มีการตรวจที่มาของกุญแจ', cfg.cert ? 'dim' : 'bad');

    S.bobP.set(0, S.bobLine, S.bobState === 'ถอดรหัสไม่ได้' ? 'bad mono' : 'ok mono');
    S.bobP.set(1, S.bobState || 'รอข้อความแรก', 'dim');

    for (let i = 0; i < 3; i++) {
      const r = S.log[i];
      if (!r) { S.mP.set(i, i === 0 ? '— รอข้อมูล —' : '', 'term dim'); continue; }
      S.mP.set(i, (r.read ? '> ' : r.note ? '+ ' : '? ') + r.text, r.read ? 'term-bad' : 'term dim');
    }
  }
});
})();
