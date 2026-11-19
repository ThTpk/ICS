/* ============================================================
   บทที่ 3.1 — TLS / HTTPS Handshake
   ลำดับการจับมือ ทีละข้อความ จนได้ช่องทางที่เข้ารหัส
   ============================================================ */
(function () {
const C   = [0.5, 5.0];
const SV  = [6.5, -1.0];
const CAp = [0.6, -0.7];
const MA  = [5.0, 3.5];

function script(cfg) {
  const s = [];
  if (cfg.phase === 'http') {
    s.push({ d: 'cs', l: 'GET /login', k: 'plain', log: 'ส่งคำขอแบบไม่เข้ารหัส', open: true });
    s.push({ d: 'sc', l: 'user=ann pass=1234', k: 'plain', log: 'ตอบกลับแบบเปิดเผย', open: true });
    return s;
  }
  s.push({ d: 'cs', l: 'ClientHello', k: 'req', log: 'เสนอเวอร์ชัน TLS และชุดรหัสที่รองรับ', open: true });
  s.push({ d: 'sc', l: 'ServerHello', k: 'req', log: 'เลือกชุดรหัสที่จะใช้ร่วมกัน', open: true });
  if (cfg.phase === 'hello') return s;
  s.push({ d: 'sc', l: 'Certificate', k: 'key', log: 'ส่งใบรับรอง + public key ของเซิร์ฟเวอร์', verify: true, open: true });
  if (cfg.phase === 'cert') return s;
  s.push({ d: 'cs', l: 'Key Share', k: 'keyp', log: 'ส่งค่าสาธารณะฝั่งเบราว์เซอร์', open: true });
  s.push({ d: 'sc', l: 'Key Share', k: 'keyp', log: 'ส่งค่าสาธารณะฝั่งเซิร์ฟเวอร์ แล้วต่างฝ่ายต่างคำนวณกุญแจเอง', derive: true, open: true });
  if (cfg.phase === 'key') return s;
  s.push({ d: 'cs', l: 'Finished', k: 'cipher', log: 'ยืนยันว่าการจับมือทั้งหมดไม่ถูกแก้', seal: true });
  s.push({ d: 'sc', l: 'Finished', k: 'cipher', log: 'ยืนยันกลับ ช่องทางพร้อมใช้งาน' });
  s.push({ d: 'cs', l: 'POST /login', k: 'cipher', log: 'ข้อมูลจริงเริ่มไหล โดยเข้ารหัสทั้งหมด', app: true, plain: 'user=ann pass=1234' });
  s.push({ d: 'sc', l: '200 OK', k: 'cipher', log: 'ตอบกลับแบบเข้ารหัส', app: true, plain: 'session=9f3a…' });
  return s;
}

ICS.register({
  id: 'tls',
  title: 'TLS: การจับมือของ HTTPS',
  sub: 'ทุกครั้งที่ขึ้นรูปกุญแจข้าง URL มีการจับมือสิบกว่าข้อความเกิดขึ้นใน 50 มิลลิวินาที นี่คือสิ่งที่มันทำ',
  minutes: 13,
  level: 'ระดับกลาง',

  legend: [
    ['req', 'ข้อความจับมือ (เปิดเผย)'],
    ['key sq', 'ใบรับรอง / ค่ากุญแจ'],
    ['cipher sq', 'ข้อมูลที่เข้ารหัสแล้ว'],
    ['bad', 'ใบรับรองปลอม / อ่านได้']
  ],

  metrics: [
    { key: 'rounds', label: 'จับมือครบรอบ' },
    { key: 'verified', label: 'ใบรับรองผ่าน', tone: c => (c.stats.verified || 0) > 0 ? 'lit' : '' },
    { key: 'read', label: 'Mallory อ่านได้', bad: true, tone: c => (c.stats.read || 0) > 0 ? 'warn' : '' },
    { key: 'blocked', label: 'หยุดด้วยคำเตือน', tone: c => (c.stats.blocked || 0) > 0 ? 'lit' : '' },
    { key: 'pos', label: 'ขั้นที่กำลังทำ', fmt: c => c.S.seq ? (Math.min(c.S.i + 1, c.S.seq.length)) + ' / ' + c.S.seq.length : '–' }
  ],

  learn: [
    ['HTTP ธรรมดาเปิดเผยทุกอย่างบนสาย', 0],
    ['ClientHello / ServerHello ใช้ตกลงชุดรหัส', 1],
    ['ใบรับรองคือสิ่งที่ยืนยันว่าคุยกับเซิร์ฟเวอร์ตัวจริง', 2],
    ['กุญแจของเซสชันถูกคำนวณขึ้น ไม่เคยถูกส่งข้ามสาย', 3],
    ['คำเตือนใบรับรองคือด่านสุดท้ายจริงๆ', 5]
  ],

  steps: [
    {
      tag: 'problem', label: 'HTTP', title: 'HTTP ธรรมดา: ทุกอย่างอยู่บนสาย',
      body: [
        'ไม่มีการจับมือ ไม่มีการตรวจตัวตน เบราว์เซอร์ยิงคำขอออกไปแล้วเซิร์ฟเวอร์ตอบกลับมาตรงๆ Mallory ที่นั่งอยู่กลางทางอ่านรหัสผ่านและคุกกี้ได้ครบ',
        'ที่แย่กว่าการอ่านคือเธอแก้เนื้อหาที่ตอบกลับมาได้ด้วย เช่นแทรกสคริปต์ลงในหน้าเว็บ ผู้ใช้จะไม่มีทางรู้เลยว่าหน้าที่เห็นไม่ใช่ของจริง'
      ],
      note: ['ทำไมถึงเลิกใช้กันแล้ว', 'เบราว์เซอร์ยุคนี้ขึ้นป้าย "ไม่ปลอดภัย" กับ HTTP ทุกหน้า และฟีเจอร์ใหม่ๆ เช่นกล้อง ไมค์ ตำแหน่ง ถูกปิดกั้นไม่ให้ใช้บน HTTP เลย'],
      changed: ['โปรโตคอล: HTTP ธรรมดา'],
      cfg: { phase: 'http', mitm: false, ignore: false }
    },
    {
      tag: 'technique', label: 'Hello', title: 'ขั้นที่ 1: ทักทายและตกลงชุดรหัส',
      body: [
        'การจับมือเริ่มด้วย <code>ClientHello</code> เบราว์เซอร์บอกว่ารองรับ TLS เวอร์ชันไหนและใช้อัลกอริทึมอะไรได้บ้าง พร้อมแนบค่าสุ่มของฝั่งตัวเองไปด้วย',
        'เซิร์ฟเวอร์ตอบ <code>ServerHello</code> โดยเลือกชุดที่จะใช้จริงหนึ่งชุด สองข้อความนี้ยังเป็นข้อความเปิดเผย Mallory อ่านได้ แต่อ่านแล้วก็ไม่ได้อะไร เพราะยังไม่มีความลับอยู่ในนั้นเลย'
      ],
      note: ['ทำไมต้องตกลงกันก่อน', 'ไคลเอนต์กับเซิร์ฟเวอร์มีอายุและรุ่นต่างกันมาก การเจรจาทำให้ทั้งคู่ลงตัวที่อัลกอริทึมที่แข็งแรงที่สุดที่ทั้งสองฝ่ายรองรับ'],
      changed: ['เริ่มใช้ TLS', 'ขั้นตอน: Hello 2 ข้อความ'],
      cfg: { phase: 'hello', mitm: false, ignore: false }
    },
    {
      tag: 'technique', label: 'ใบรับรอง', title: 'ขั้นที่ 2: พิสูจน์ว่าเป็นเซิร์ฟเวอร์ตัวจริง',
      body: [
        'เซิร์ฟเวอร์ส่งใบรับรองที่บรรจุ public key ของตัวเองและลายเซ็นของ CA เบราว์เซอร์ตรวจลายเซ็นนั้นด้วย public key ของ CA ที่ติดตั้งมากับเครื่องอยู่แล้ว',
        'ถ้าชื่อโดเมนบนใบรับรองตรงกับที่เรากำลังเปิด ลายเซ็นถูกต้อง และยังไม่หมดอายุ ไฟดวงแรกจึงเปลี่ยนเป็นเขียว นี่คือการแก้ปัญหา MITM จากบทที่แล้วโดยตรง'
      ],
      note: ['ใบรับรองไม่ได้แปลว่าเว็บดี', 'มันยืนยันแค่ว่าคุณคุยกับเจ้าของโดเมนนั้นจริง เว็บหลอกลวงก็ขอใบรับรองฟรีได้เหมือนกัน รูปกุญแจจึงไม่ใช่เครื่องหมายว่าเว็บน่าเชื่อถือ'],
      changed: ['เพิ่มขั้นตอน: Certificate + ตรวจกับ CA'],
      cfg: { phase: 'cert', mitm: false, ignore: false }
    },
    {
      tag: 'technique', label: 'แลกกุญแจ', title: 'ขั้นที่ 3: ได้กุญแจร่วมโดยไม่เคยส่งกุญแจ',
      body: [
        'ทั้งสองฝ่ายส่ง "ค่าสาธารณะ" ของตัวเองข้ามไปมา แล้วต่างฝ่ายต่างเอาค่าของอีกฝ่ายมารวมกับความลับของตัวเองเพื่อคำนวณกุญแจออกมา ผลที่ได้เท่ากันทั้งสองฝั่ง',
        'จุดสำคัญคือตัวกุญแจไม่เคยวิ่งผ่านสายเลยสักครั้ง Mallory เก็บทุกข้อความไว้ครบก็คำนวณกุญแจออกมาไม่ได้ วิธีนี้เรียกว่า Diffie-Hellman'
      ],
      note: ['Forward secrecy', 'เพราะสร้างกุญแจใหม่ทุกเซสชัน ต่อให้วันหนึ่ง private key ของเซิร์ฟเวอร์หลุด ทราฟฟิกเก่าที่ถูกดักเก็บไว้ก็ยังถอดไม่ได้'],
      changed: ['เพิ่มขั้นตอน: Key Share สองทาง'],
      cfg: { phase: 'key', mitm: false, ignore: false }
    },
    {
      tag: 'technique', label: 'ช่องเข้ารหัส', title: 'ขั้นที่ 4: ปิดท้ายแล้วส่งข้อมูลจริง',
      body: [
        'ข้อความ <code>Finished</code> ของทั้งสองฝั่งคือค่าตรวจสอบของทุกข้อความที่ผ่านมาในการจับมือ ถ้ามีใครแก้อะไรระหว่างทางแม้แต่ไบต์เดียว ค่านี้จะไม่ตรงและการเชื่อมต่อจะถูกตัด',
        'จากจุดนี้ไปข้อมูลจริงทั้งหมดวิ่งในช่องที่เข้ารหัสด้วยกุญแจร่วม ดูจอของ Mallory เธอยังเห็นว่ามีแพ็กเก็ตวิ่ง เห็นขนาดและจังหวะ แต่ไม่เห็นเนื้อหา'
      ],
      note: ['สิ่งที่ TLS ไม่ได้ซ่อน', 'ชื่อโดเมนปลายทาง ขนาดและจังหวะของแพ็กเก็ตยังมองเห็นได้ การวิเคราะห์ทราฟฟิกจึงยังบอกได้คร่าวๆ ว่าคุณกำลังทำอะไรอยู่'],
      changed: ['ครบทั้งการจับมือ', 'ข้อมูลจริง: เข้ารหัสทั้งหมด'],
      cfg: { phase: 'full', mitm: false, ignore: false }
    },
    {
      tag: 'attack', label: 'ใบรับรองปลอม', title: 'ถ้ามีคนยื่นใบรับรองปลอมให้',
      body: [
        'Mallory ตั้งตัวเป็นเซิร์ฟเวอร์ปลอมแล้วยื่นใบรับรองที่เธอเซ็นเอง เบราว์เซอร์ตรวจแล้วไม่พบลายเซ็นของ CA ที่เชื่อถือ จึงหยุดและขึ้นหน้าเตือนสีแดง การเชื่อมต่อไม่เกิดขึ้น',
        'เปิดสวิตช์ "ผู้ใช้กดข้ามคำเตือน" แล้วดูสิ่งที่ตามมา การจับมือเดินต่อจนครบ ไฟขึ้นเขียวสองดวง รูปกุญแจขึ้นปกติ แต่กุญแจที่ใช้เป็นของ Mallory เธออ่านได้ทุกอย่าง'
      ],
      note: ['คำเตือนนี้คือด่านสุดท้าย', 'คณิตศาสตร์ทั้งหมดของ TLS ทำงานถูกต้องอยู่ แต่มันพังได้ด้วยการคลิกเดียวของผู้ใช้ นี่คือเหตุผลที่เบราว์เซอร์ทำให้หน้าเตือนข้ามยากขึ้นเรื่อยๆ'],
      changed: ['Mallory: ยื่นใบรับรองที่เซ็นเอง'],
      cfg: { phase: 'full', mitm: true, ignore: false },
      controls: ['ignore']
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: ถอดขั้นตอนออกทีละขั้น',
      body: [
        'เลือกว่าจะให้การจับมือหยุดที่ขั้นไหน แล้วดูว่าไฟสถานะดวงไหนยังไม่ติด ลองถามตัวเองว่าถ้าข้ามขั้นตอนใบรับรองไปแต่ยังแลกกุญแจ เราจะได้ช่องที่เข้ารหัสกับ "ใคร" กันแน่',
        'คำตอบคือได้ช่องที่เข้ารหัสจริง แต่ไม่รู้ว่าปลายทางเป็นใคร การเข้ารหัสที่ไม่มีการยืนยันตัวตนจึงกันคนดูได้ แต่กันคนปลอมตัวไม่ได้'
      ],
      note: ['TLS 1.3 เร็วกว่าเดิมมาก', 'เวอร์ชันเก่าต้องวิ่งไปกลับสองรอบก่อนส่งข้อมูลได้ TLS 1.3 เหลือรอบเดียว และตัดอัลกอริทึมเก่าที่มีช่องโหว่ออกทั้งหมด'],
      changed: [],
      cfg: { phase: 'full', mitm: false, ignore: false },
      controls: ['phase', 'mitm', 'ignore']
    }
  ],

  controls: {
    phase: {
      type: 'seg', label: 'ให้การจับมือไปถึงขั้นไหน',
      options: [['http', 'HTTP เปล่า'], ['hello', 'แค่ Hello'], ['cert', '+ ใบรับรอง'], ['key', '+ แลกกุญแจ'], ['full', 'ครบทุกขั้น']],
      get: c => c.phase, set: (c, v) => { c.phase = v; }, reset: true
    },
    mitm: { type: 'toggle', label: 'Mallory ยื่นใบรับรองปลอม', hint: 'ตั้งตัวเป็นเซิร์ฟเวอร์ปลอม', get: c => c.mitm, set: (c, v) => { c.mitm = v; }, reset: true },
    ignore: { type: 'toggle', label: 'ผู้ใช้กดข้ามคำเตือน', hint: 'กด "ไปต่อแบบไม่ปลอดภัย"', get: c => c.ignore, set: (c, v) => { c.ignore = v; }, reset: true }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    const c = iso(C[0], C[1], 0.8), s = iso(SV[0], SV[1], 0.95);
    ctx.S = {
      i: 0, gap: 600, pending: false, seq: script(ctx.cfg),
      auth: 'idle', keys: 'idle', enc: 'idle', mitmOn: false, log: [], eve: [],
      P: { c, s, ca: iso(CAp[0], CAp[1], 0.95), m: iso(MA[0], MA[1] - 0.5, 0.72), mid: [(c[0] + s[0]) / 2, (c[1] + s[1]) / 2] }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    S.mainWire = ctx.line(iso(C[0], C[1], 0.22), iso(SV[0], SV[1], 0.22), 'wire', L.wires);
    S.caWire = ctx.line(iso(CAp[0], CAp[1], 0.22), iso(C[0], C[1], 0.22), 'wire', L.wires);
    S.mWire = ctx.line(iso(MA[0], MA[1], 0.22), iso(2.95, 1.55, 0.22), 'wire tap', L.wires);

    S.caG = ctx.el('g', {}, L.ents);
    const cab = Ac.box(S.caG, CAp[0], CAp[1], { w: 1.25, h: 0.66, pal: 'violet' });
    ctx.glyph.cert(S.caG, iso(CAp[0], CAp[1], cab.box.zt));
    S.caPill = ctx.pill(L.labels, iso(CAp[0], CAp[1] + 1.0, 0)[0], iso(CAp[0], CAp[1] + 1.0, 0)[1] + 14, ['CA ที่เครื่องเชื่อถือ']);

    const cg = ctx.el('g', {}, L.ents);
    Ac.desk(cg, C[0], C[1], 'orange', 1.15);
    S.cPill = ctx.pill(L.labels, S.P.c[0], iso(C[0], C[1] + 1.0, 0)[1] + 14, ['เบราว์เซอร์', '']);

    S.mG = ctx.el('g', {}, L.ents);
    Ac.attacker(S.mG, MA[0], MA[1]);
    S.mPill = ctx.pill(L.labels, iso(MA[0], MA[1] + 0.85, 0)[0] - 4, iso(MA[0], MA[1] + 0.85, 0)[1] + 14, ['Mallory', '']);

    const sg = ctx.el('g', { class: 'node' }, L.ents);
    Ac.server(sg, SV[0], SV[1], 'bone', 1.4);
    S.sPill = ctx.pill(L.labels, iso(SV[0] + 0.95, SV[1] + 0.95, 0)[0], iso(SV[0] + 0.95, SV[1] + 0.95, 0)[1] + 18, ['เซิร์ฟเวอร์', 'bank.example']);

    S.status = ctx.statusList(L.hud, {
      x: 512, y: 74, w: 204, title: 'สถานะการเชื่อมต่อ',
      items: ['ยืนยันตัวตน', 'กุญแจร่วม', 'ช่องเข้ารหัส']
    });
    S.logP = ctx.panel(L.hud, { x: 126, y: 326, w: 316, rows: 4, title: 'ลำดับการจับมือ' });
    S.eveP = ctx.panel(L.hud, { x: 452, y: 326, w: 264, rows: 4, title: 'จอของ Mallory', dark: true });
  },

  tick(ctx, dt) {
    const S = ctx.S, cfg = ctx.cfg;
    if (S.pending) return;
    S.gap -= dt;
    if (S.gap > 0) return;

    if (S.i >= S.seq.length) {
      ctx.bump('rounds');
      S.i = 0; S.gap = 1200;
      S.auth = 'idle'; S.keys = 'idle'; S.enc = 'idle'; S.mitmOn = false;
      S.log = [];
      return;
    }
    const m = S.seq[S.i];
    const from = m.d === 'cs' ? S.P.c : S.P.s;
    const to = m.d === 'cs' ? S.P.s : S.P.c;
    let label = m.l, kind = m.k;
    if (m.verify && cfg.mitm) { label = 'Certificate (เซ็นเอง)'; kind = 'bad'; }
    if (m.app && S.mitmOn) kind = 'bad';

    const speed = 560;
    ctx.launch([from, to], kind, { label, meta: { leg: 'step', m, kind }, speed });

    /* สำเนาที่ Mallory ดักได้ ออกจากกลางสาย */
    let eLabel, eKind, eRead;
    if (cfg.phase === 'http') { eLabel = m.l; eKind = 'bad'; eRead = true; }
    else if (m.app) {
      if (S.mitmOn) { eLabel = m.plain; eKind = 'bad'; eRead = true; }
      else { eLabel = '········'; eKind = 'cipher'; eRead = false; }
    } else if (m.k === 'cipher') { eLabel = '········'; eKind = 'cipher'; eRead = false; }
    else { eLabel = label; eKind = 'plain'; eRead = false; }

    const half = ctx.dist(from, to) / 2;
    ctx.launch([S.P.mid, S.P.m], eKind, {
      label: eLabel, meta: { leg: 'eve', readable: eRead },
      speed: 300, delay: (half / speed) * 1000
    });
    S.pending = true;
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, m = p.meta.m;
    if (p.meta.leg === 'eve') {
      if (p.meta.readable) { ctx.bump('read'); ctx.ring(S.P.m); }
      S.eve.unshift({ t: p.label, read: p.meta.readable });
      if (S.eve.length > 4) S.eve.length = 4;
      return;
    }
    S.pending = false;
    S.log.unshift({ t: (S.i + 1) + '. ' + m.log, bad: false });
    if (S.log.length > 4) S.log.length = 4;

    if (m.verify) {
      if (cfg.mitm) {
        if (cfg.ignore) {
          S.mitmOn = true; S.auth = 'bad';
          S.log.unshift({ t: '⚠ ผู้ใช้กดข้ามคำเตือน — คุยกับ Mallory อยู่', bad: true });
          ctx.float([S.P.c[0], S.P.c[1] - 26], 'ข้ามคำเตือน', 'bad');
        } else {
          S.auth = 'bad';
          ctx.bump('blocked'); ctx.puff(S.P.c);
          ctx.float([S.P.c[0], S.P.c[1] - 26], 'หยุดการเชื่อมต่อ', 'ok');
          S.log.unshift({ t: '✗ ใบรับรองไม่ผ่าน — เบราว์เซอร์ตัดการเชื่อมต่อ', bad: true });
          S.i = S.seq.length; S.gap = 1600;
          return;
        }
      } else {
        S.auth = 'ok'; ctx.bump('verified'); ctx.ring(S.P.ca, 'ok'); ctx.puff(S.P.c, 'ok');
      }
    }
    if (m.derive) { S.keys = 'ok'; ctx.puff(S.P.c, 'v'); ctx.puff(S.P.s, 'v'); }
    if (m.seal) S.enc = S.mitmOn ? 'bad' : 'ok';

    S.i++;
    S.gap = 180;
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const sealed = S.enc !== 'idle';

    S.mainWire.setAttribute('class', sealed && !S.mitmOn ? 'wire strong' : 'wire');
    S.caG.setAttribute('opacity', cfg.phase === 'http' || cfg.phase === 'hello' ? 0.3 : 1);
    S.caWire.setAttribute('class', cfg.phase === 'http' || cfg.phase === 'hello' ? 'wire off' : 'wire');
    S.mG.setAttribute('opacity', cfg.mitm ? 1 : 0.4);
    S.mWire.setAttribute('class', 'wire tap' + (cfg.mitm ? '' : ' off'));

    S.cPill.set(['เบราว์เซอร์', cfg.phase === 'http' ? 'ไม่ปลอดภัย' : S.mitmOn ? 'กุญแจของ Mallory' : sealed ? 'เชื่อมต่อปลอดภัย' : 'กำลังจับมือ']);
    S.cPill.tone(cfg.phase === 'http' || S.mitmOn ? 'hot' : sealed ? 'ok' : '');
    S.mPill.set(['Mallory', !cfg.mitm ? 'ได้แต่ดู' : S.mitmOn ? 'อ่านได้ทุกอย่าง' : 'ถูกปฏิเสธ']);
    S.mPill.tone(S.mitmOn ? 'hot' : cfg.mitm ? '' : 'dead');
    S.caPill.tone(cfg.phase === 'http' || cfg.phase === 'hello' ? 'dead' : 'v');

    S.status.set(0, S.auth, S.auth === 'ok' ? 'ผ่าน' : S.auth === 'bad' ? 'ไม่ผ่าน' : 'ยังไม่ตรวจ');
    S.status.set(1, S.keys, S.keys === 'ok' ? 'ได้แล้ว' : 'ยังไม่มี');
    S.status.set(2, S.enc === 'bad' ? 'bad' : S.enc, S.enc === 'ok' ? 'เข้ารหัสอยู่' : S.enc === 'bad' ? 'ของ Mallory' : 'ยังเปิดเผย');

    for (let i = 0; i < 4; i++) {
      const r = S.log[i];
      S.logP.set(i, r ? r.t : (i === 0 ? 'กำลังเริ่มการจับมือ…' : ''), r ? (r.bad ? 'bad' : i === 0 ? 'ok' : 'dim') : 'dim');
    }
    for (let i = 0; i < 4; i++) {
      const r = S.eve[i];
      S.eveP.set(i, r ? (r.read ? '> ' : '? ') + r.t : (i === 0 ? '— รอข้อมูล —' : ''), r && r.read ? 'term-bad' : 'term dim');
    }
  }
});
})();
