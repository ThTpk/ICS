/* ============================================================
   บทที่ 2.1 — การเข้ารหัสแบบสมมาตร (Symmetric encryption)
   plaintext → ciphertext → ปัญหาการแลกกุญแจ
   ============================================================ */
(function () {
const A  = [0.2, 5.4];   // Alice
const E1 = [1.9, 3.7];   // เครื่องเข้ารหัส
const J  = [3.4, 2.2];   // จุดที่สายถูกดัก
const D1 = [5.1, 0.5];   // เครื่องถอดรหัส
const B  = [6.8, -1.2];  // Bob
const EV = [5.7, 4.5];   // Eve

const VARIED = ['MEET AT 8', 'PAY 500', 'LOGIN OK', 'BUY 100', 'SEND NOW', 'CALL ME'];
const REPEAT = ['PAY 500', 'MEET AT 8', 'PAY 500', 'PAY 500', 'MEET AT 8', 'PAY 500'];

const HEXC = '0123456789abcdef';
function h32(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h; }
function hexOf(s, n) { let h = h32(s), o = ''; for (let i = 0; i < n; i++) { h = (Math.imul(h, 1103515245) + 12345) >>> 0; o += HEXC[(h >>> 28) & 15]; } return o; }
const caesar = (t, k) => t.replace(/[A-Z]/g, c => String.fromCharCode((c.charCodeAt(0) - 65 + k + 26) % 26 + 65));

function encrypt(cfg, text, iv) {
  if (cfg.mode === 'none') return text;
  if (cfg.mode === 'caesar') return caesar(text, cfg.key);
  if (cfg.mode === 'ecb') return hexOf(text + '|' + cfg.key, 10);
  return hexOf(text + '|' + cfg.key + '|' + iv, 10);
}
const KEYSPACE = { none: '—', caesar: '25 แบบ', ecb: '3.4×10³⁸', cbc: '3.4×10³⁸' };
const MODE_NAME = { none: 'ไม่เข้ารหัส', caesar: 'Caesar (เลื่อนตัวอักษร)', ecb: 'AES-128 โหมด ECB', cbc: 'AES-128 โหมด CBC + IV' };

ICS.register({
  id: 'symmetric',
  title: 'การเข้ารหัสแบบสมมาตร',
  sub: 'กุญแจดอกเดียวใช้ทั้งเข้าและถอดรหัส เร็วและแข็งแรง แต่ติดปัญหาใหญ่ข้อเดียวที่แก้ไม่ได้ด้วยตัวมันเอง',
  minutes: 14,
  level: 'ระดับกลาง',

  legend: [
    ['req sq', 'ข้อความต้นฉบับ (plaintext)'],
    ['cipher sq', 'ข้อความที่เข้ารหัสแล้ว (ciphertext)'],
    ['key sq', 'กุญแจลับ'],
    ['bad', 'Eve อ่านออก']
  ],

  metrics: [
    { key: 'sent', label: 'ส่งทั้งหมด' },
    { key: 'read', label: 'Eve อ่านออก', bad: true, tone: c => (c.stats.read || 0) > 0 ? 'warn' : (c.stats.sent > 2 ? 'lit' : '') },
    { key: 'repeat', label: 'ciphertext ซ้ำ', bad: true, tone: c => (c.stats.repeat || 0) > 1 ? 'warn' : '' },
    { key: 'ks', label: 'กุญแจที่ต้องลอง', fmt: c => KEYSPACE[c.cfg.mode] },
    { key: 'got', label: 'Eve ได้กุญแจ', fmt: c => c.S.hasKey ? 'ได้แล้ว' : 'ยังไม่ได้', tone: c => c.S.hasKey ? 'warn' : '' }
  ],

  learn: [
    ['plaintext กับ ciphertext ต่างกันอย่างไร', 0],
    ['รหัสแบบเลื่อนตัวอักษรเจาะได้ด้วยการลองทุกกุญแจ', 2],
    ['ความยาวกุญแจทำให้การเดาสุ่มเป็นไปไม่ได้', 3],
    ['ECB ทำให้เห็นรูปแบบ ต้องใช้ IV ช่วย', 5],
    ['ปัญหาที่แท้จริงคือการแลกกุญแจ', 6]
  ],

  steps: [
    {
      tag: 'problem', label: 'ส่งแบบเปิด', title: 'ส่งข้อความแบบเปิด',
      body: [
        'Alice ส่งข้อความถึง Bob โดยไม่เข้ารหัสอะไรเลย ข้อความวิ่งผ่านสายที่ Eve ต่อคาไว้ ทุกคำที่ Alice พิมพ์จึงไปโผล่ที่จอของ Eve ครบถ้วน',
        'นี่คือสภาพของ HTTP ธรรมดา ไวไฟสาธารณะ หรืออีเมลที่ไม่เข้ารหัส ใครก็ตามที่อยู่ระหว่างทางอ่านได้หมด'
      ],
      note: ['ระหว่างทางมีใครบ้าง', 'จากเครื่องคุณถึงเซิร์ฟเวอร์ ข้อมูลผ่านเราเตอร์ ผู้ให้บริการเน็ต และอุปกรณ์กลางทางอีกหลายสิบจุด ทุกจุดคือที่ที่ Eve ยืนได้'],
      changed: ['การเข้ารหัส: ไม่มี'],
      cfg: { mode: 'none', key: 3, crack: false, sendKey: false, pool: 'varied', gap: 2000 }
    },
    {
      tag: 'technique', label: 'Caesar', title: 'เข้ารหัสด้วยการเลื่อนตัวอักษร',
      body: [
        'วิธีที่เก่าแก่ที่สุดวิธีหนึ่ง เลื่อนตัวอักษรทุกตัวไปข้างหน้าเท่าๆ กัน ด้วยกุญแจ <code>k = 3</code> คำว่า <code>PAY</code> จะกลายเป็น <code>SDB</code> ฝั่ง Bob เลื่อนกลับ 3 ตัวก็ได้ข้อความเดิม',
        'กุญแจดอกเดียวกันใช้ทั้งเข้ารหัสและถอดรหัส นี่คือความหมายของคำว่า symmetric ตอนนี้สิ่งที่ Eve เห็นเริ่มอ่านไม่รู้เรื่องแล้ว'
      ],
      note: ['หลักการของ Kerckhoffs', 'ความปลอดภัยต้องอยู่ที่กุญแจเท่านั้น ไม่ใช่ที่การปิดบังวิธีการ ถ้าระบบจะปลอดภัยก็ต้องปลอดภัยแม้ผู้โจมตีรู้อัลกอริทึมทั้งหมด'],
      changed: ['เข้ารหัส: Caesar, กุญแจ = 3'],
      cfg: { mode: 'caesar', key: 3, crack: false, sendKey: false, pool: 'varied', gap: 2000 }
    },
    {
      tag: 'attack', label: 'เจาะ Caesar', title: 'เจาะด้วยการลองทุกกุญแจ',
      body: [
        'Caesar มีกุญแจที่เป็นไปได้แค่ 25 แบบ Eve จึงไม่ต้องฉลาดอะไรเลย แค่ลองเลื่อนกลับทีละค่าจนกว่าจะเจอคำที่อ่านออก คอมพิวเตอร์ทำครบ 25 แบบในเวลาไม่ถึงวินาที',
        'ดูที่จอของ Eve มันกำลังไล่ <code>k=1, 2, 3…</code> อยู่ การโจมตีแบบนี้เรียกว่า brute force คือลองทุกความเป็นไปได้'
      ],
      note: ['ช่องว่างกุญแจ (keyspace)', 'ความแข็งแรงของรหัสลับขึ้นกับจำนวนกุญแจที่เป็นไปได้ 25 แบบคือเล่นๆ แต่ 2²⁵⁶ แบบคือมากกว่าจำนวนอะตอมในจักรวาลที่สังเกตได้'],
      changed: ['Eve: ลองทุกกุญแจ'],
      cfg: { mode: 'caesar', key: 7, crack: true, sendKey: false, pool: 'varied', gap: 2200 }
    },
    {
      tag: 'technique', label: 'AES', title: 'AES กับกุญแจ 128 บิต',
      body: [
        'เปลี่ยนมาใช้ AES ซึ่งเป็นมาตรฐานที่ใช้จริงทุกวันนี้ กุญแจยาว 128 บิต หมายความว่ามีกุญแจที่เป็นไปได้ราว <code>3.4×10³⁸</code> แบบ',
        'ถ้าลองได้พันล้านกุญแจต่อวินาที ก็ยังต้องใช้เวลามากกว่าอายุของจักรวาลหลายเท่า การ brute force จึงตายไปเอง จอของ Eve ได้แต่แสดงเลขฐานสิบหกที่ไม่มีความหมาย'
      ],
      note: ['ทำไมไม่ใช้กุญแจยาวๆ ไปเลย', 'ยิ่งยาวยิ่งช้าลงและไม่ได้ปลอดภัยเพิ่มอย่างมีความหมาย เพราะ 128 บิตก็เกินกำลังเครื่องทุกเครื่องบนโลกรวมกันแล้ว'],
      changed: ['เข้ารหัส: AES-128'],
      cfg: { mode: 'ecb', key: 'a71f', crack: true, sendKey: false, pool: 'varied', gap: 2000 }
    },
    {
      tag: 'problem', label: 'รูปแบบซ้ำ', title: 'ใช้ AES แล้วยังรั่วได้ถ้าใช้ผิดโหมด',
      body: [
        'Alice ส่งข้อความซ้ำๆ กัน เช่นคำสั่งโอนเงินยอดเดิม ในโหมด ECB ข้อความเดียวกันบวกกุญแจเดียวกันให้ ciphertext เดียวกันเสมอ',
        'Eve ยังถอดรหัสไม่ได้ แต่เธอเห็นว่าค่าตัวนี้ซ้ำแล้วซ้ำอีก เธอจึงเดาได้ว่า "นี่คือคำสั่งเดิม" และถ้ารู้ครั้งเดียวว่ามันแปลว่าอะไร ก็รู้ทุกครั้งที่เหลือ'
      ],
      note: ['รูปเพนกวิน ECB', 'ถ้าเข้ารหัสภาพด้วย AES โหมด ECB จะยังเห็นเค้าโครงรูปเดิมอยู่ชัดเจน เป็นตัวอย่างคลาสสิกว่าอัลกอริทึมดีแต่ใช้ผิดโหมดก็พังได้'],
      changed: ['ข้อความ: ส่งซ้ำบ่อย', 'โหมด: ECB'],
      cfg: { mode: 'ecb', key: 'a71f', crack: true, sendKey: false, pool: 'repeat', gap: 1700 }
    },
    {
      tag: 'technique', label: 'IV', title: 'เติมค่าสุ่ม IV ให้ทุกข้อความต่างกัน',
      body: [
        'โหมด CBC เติมค่าสุ่มที่เรียกว่า IV (initialization vector) เข้าไปก่อนเข้ารหัสทุกครั้ง ข้อความเดิมเป๊ะที่ส่งสองครั้งจึงได้ ciphertext คนละค่า',
        'ดูช่อง "ciphertext ซ้ำ" ที่หยุดเพิ่ม Eve หมดทางเทียบรูปแบบแล้ว ทั้งที่กุญแจยังเป็นดอกเดิมและอัลกอริทึมยังเป็น AES ตัวเดิม'
      ],
      note: ['IV ไม่ใช่ความลับ', 'IV ส่งไปพร้อมข้อความแบบเปิดเผยได้ ขอแค่อย่าซ้ำและอย่าเดาได้ หน้าที่ของมันคือทำให้ผลลัพธ์ต่างกัน ไม่ใช่ปกปิด'],
      changed: ['โหมด: CBC + IV สุ่มทุกครั้ง'],
      cfg: { mode: 'cbc', key: 'a71f', crack: true, sendKey: false, pool: 'repeat', gap: 1700 }
    },
    {
      tag: 'problem', label: 'แลกกุญแจ', title: 'ปัญหาที่เหลืออยู่: แล้วส่งกุญแจกันยังไง',
      body: [
        'Alice กับ Bob ต้องถือกุญแจดอกเดียวกัน แต่ถ้าทั้งคู่ยังไม่เคยเจอกัน Alice ก็ต้องส่งกุญแจผ่านสายเส้นเดิม ซึ่งเป็นเส้นที่ Eve คาอยู่',
        'ดูสิ่งที่เกิดขึ้น พอ Eve คว้ากุญแจไปได้ AES ที่แข็งแรงที่สุดในโลกก็ไร้ความหมายทันที เธอถอดรหัสทุกข้อความได้เหมือนไม่เคยเข้ารหัสเลย'
      ],
      note: ['ปัญหาใหญ่กว่าที่คิด', 'ถ้ามีผู้ใช้ n คนที่ต้องคุยกันทุกคู่ ต้องมีกุญแจ n(n-1)/2 ดอก ผู้ใช้หนึ่งพันคนคือเกือบห้าแสนดอก ซึ่งจัดการไม่ไหวในทางปฏิบัติ'],
      changed: ['Alice: ส่งกุญแจผ่านสายเดียวกัน'],
      cfg: { mode: 'cbc', key: 'a71f', crack: true, sendKey: true, pool: 'varied', gap: 1900 }
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: เปลี่ยนวิธีแล้วดูจอของ Eve',
      body: [
        'พิมพ์ข้อความเอง เลือกโหมด และลองส่งข้อความเดิมซ้ำหลายครั้งในโหมด ECB เทียบกับ CBC ว่าสิ่งที่ Eve เห็นต่างกันอย่างไร',
        'คำถามปิดท้าย ถ้าการเข้ารหัสแบบสมมาตรดีขนาดนี้แต่ติดเรื่องการแลกกุญแจ บทต่อไปจะแก้ด้วยการใช้กุญแจ "คนละดอก" สำหรับเข้าและถอด'
      ],
      note: ['ใช้จริงแล้วเป็นแบบไหน', 'ระบบจริงใช้ทั้งสองแบบผสมกัน ใช้กุญแจคู่ตกลงกุญแจลับร่วมก่อน แล้วค่อยใช้ AES เข้ารหัสข้อมูลจริง เพราะ AES เร็วกว่ามาก'],
      changed: [],
      cfg: { mode: 'ecb', key: 'a71f', crack: true, sendKey: false, pool: 'custom', custom: 'PAY 500', gap: 1600 },
      controls: ['mode', 'msg', 'sendKey']
    }
  ],

  controls: {
    mode: {
      type: 'seg', label: 'วิธีเข้ารหัส',
      options: [['none', 'ไม่เข้ารหัส'], ['caesar', 'Caesar'], ['ecb', 'AES-ECB'], ['cbc', 'AES-CBC']],
      get: c => c.mode, set: (c, v) => { c.mode = v; }, reset: true
    },
    msg: {
      type: 'text', label: 'ข้อความที่ Alice ส่งซ้ำๆ', placeholder: 'PAY 500',
      hint: 'ใช้ A–Z และตัวเลข เพื่อให้เห็นผลของ Caesar ชัด',
      get: c => c.custom || 'PAY 500',
      set: (c, v) => { c.custom = (v || '').toUpperCase().slice(0, 14) || 'PAY 500'; c.pool = 'custom'; },
      presets: [['PAY 500', 'PAY 500'], ['MEET AT 8', 'MEET AT 8'], ['ATTACK NOW', 'ATTACK NOW']]
    },
    sendKey: { type: 'toggle', label: 'Alice ส่งกุญแจผ่านสายเดียวกัน', hint: 'ดูว่าเกิดอะไรขึ้นเมื่อ Eve ได้กุญแจ', get: c => c.sendKey, set: (c, v) => { c.sendKey = v; }, reset: true }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      hasKey: false, seen: {}, log: [], trying: null, lastPlain: '—', lastState: '',
      msgIdx: 0,
      P: {
        a: iso(A[0], A[1], 0.75), e1: iso(E1[0], E1[1], 0.85), j: iso(J[0], J[1], 0.5),
        d1: iso(D1[0], D1[1], 0.85), b: iso(B[0], B[1], 0.75), ev: iso(EV[0], EV[1] - 0.5, 0.72)
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;
    const lane = [A, E1, J, D1, B];
    for (let i = 0; i < lane.length - 1; i++)
      S['w' + i] = ctx.line(iso(lane[i][0], lane[i][1], 0.22), iso(lane[i + 1][0], lane[i + 1][1], 0.22), 'wire', L.wires);
    S.tapWire = ctx.line(iso(EV[0], EV[1], 0.22), iso(J[0], J[1], 0.22), 'wire tap', L.wires);

    const mk = (pos, fn) => { const g = ctx.el('g', {}, L.ents); fn(g); return g; };

    mk(A, g => Ac.desk(g, A[0], A[1], 'orange'));
    ctx.pill(L.labels, S.P.a[0], iso(A[0], A[1] + 0.9, 0)[1] + 14, ['Alice', 'ผู้ส่ง']);

    S.encG = mk(E1, g => {
      const bx = Ac.box(g, E1[0], E1[1], { w: 1.25, h: 0.62, pal: 'green' });
      S.encGlyph = ctx.el('g', {}, g);
      ctx.glyph.lock(S.encGlyph, iso(E1[0], E1[1], bx.box.zt));
      const ke = iso(E1[0], E1[1], bx.box.zt + 0.62); ctx.keyIcon(g, ke[0] - 8, ke[1], 'public', .9);
    });
    S.encPill = ctx.pill(L.labels, iso(E1[0], E1[1] + 1.0, 0)[0], iso(E1[0], E1[1] + 1.0, 0)[1] + 14, ['เข้ารหัส', '']);

    mk(J, g => Ac.box(g, J[0], J[1], { w: 0.6, h: 0.3, pal: 'grey' }));

    S.decG = mk(D1, g => {
      const bx = Ac.box(g, D1[0], D1[1], { w: 1.25, h: 0.62, pal: 'green' });
      S.decGlyph = ctx.el('g', {}, g);
      ctx.glyph.lock(S.decGlyph, iso(D1[0], D1[1], bx.box.zt));
      const kd = iso(D1[0], D1[1], bx.box.zt + 0.62); ctx.keyIcon(g, kd[0] - 8, kd[1], 'public', .9);
    });
    S.decPill = ctx.pill(L.labels, iso(D1[0], D1[1] + 1.0, 0)[0], iso(D1[0], D1[1] + 1.0, 0)[1] + 14, ['ถอดรหัส', '']);

    mk(B, g => Ac.desk(g, B[0], B[1], 'blue'));
    ctx.pill(L.labels, S.P.b[0], iso(B[0], B[1] + 0.9, 0)[1] + 14, ['Bob', 'ผู้รับ']);

    S.evG = mk(EV, g => Ac.attacker(g, EV[0], EV[1]));
    S.evPill = ctx.pill(L.labels, iso(EV[0], EV[1] + 0.85, 0)[0] - 6, iso(EV[0], EV[1] + 0.85, 0)[1] + 14, ['Eve', 'ดักฟัง']);

    S.keyPanel = ctx.panel(L.hud, { x: 126, y: 80, w: 212, rows: 2, title: 'การตั้งค่าการเข้ารหัส' });
    S.bobPanel = ctx.panel(L.hud, { x: 498, y: 80, w: 216, rows: 2, title: 'Bob ได้รับ' });
    S.evePanel = ctx.panel(L.hud, { x: 296, y: 368, w: 274, rows: 3, title: 'จอของ Eve', dark: true });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;

    if (ctx.timer('msg', dt, cfg.gap)) {
      const pool = cfg.pool === 'custom' ? [cfg.custom || 'PAY 500'] : cfg.pool === 'repeat' ? REPEAT : VARIED;
      const text = pool[S.msgIdx++ % pool.length];
      ctx.bump('sent');
      ctx.launch([P.a, P.e1], 'plain', { label: text, meta: { leg: 'enc', text }, speed: 180 });
    }
    if (cfg.sendKey && !S.hasKey && ctx.timer('key', dt, 4200)) {
      ctx.launch([P.a, P.e1], 'key', { label: 'KEY=' + cfg.key, meta: { leg: 'enc', isKey: true, text: 'KEY=' + cfg.key }, speed: 190 });
    }

    /* Eve ไล่ลองกุญแจของ Caesar */
    if (S.trying) {
      if (ctx.timer('crack', dt, 110)) {
        S.trying.k++;
        if (S.trying.k >= cfg.key || S.trying.k > 25) {
          S.log.unshift({ text: 'k=' + cfg.key + ' → ' + S.trying.plain, read: true });
          if (S.log.length > 3) S.log.length = 3;
          ctx.bump('read'); ctx.ring(P.ev);
          S.trying = null;
        }
      }
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    switch (m.leg) {
      case 'enc': {
        if (m.isKey) { ctx.launch([P.e1, P.j], 'key', { label: m.text, meta: { leg: 'wire', isKey: true, text: m.text, plain: m.text }, speed: 190 }); break; }
        const iv = Math.floor(Math.random() * 99999);
        const ct = encrypt(cfg, m.text, iv);
        ctx.puff(P.e1, 'v');
        ctx.launch([P.e1, P.j], cfg.mode === 'none' ? 'plain' : 'cipher',
          { label: ct, meta: { leg: 'wire', text: ct, plain: m.text }, speed: 190 });
        break;
      }
      case 'wire': {
        /* Eve คัดลอกสำเนาลงมา */
        ctx.launch([P.j, P.ev], m.isKey ? 'key' : (cfg.mode === 'none' ? 'plain' : 'cipher'),
          { label: m.text, meta: { leg: 'eve', text: m.text, plain: m.plain, isKey: m.isKey }, speed: 170 });
        ctx.launch([P.j, P.d1], m.isKey ? 'key' : (cfg.mode === 'none' ? 'plain' : 'cipher'),
          { label: m.text, meta: { leg: 'dec', text: m.text, plain: m.plain, isKey: m.isKey }, speed: 190 });
        break;
      }
      case 'dec': {
        if (m.isKey) break;
        ctx.puff(P.d1, 'ok');
        ctx.launch([P.d1, P.b], 'plain', { label: m.plain, meta: { leg: 'bob', plain: m.plain }, speed: 180 });
        break;
      }
      case 'bob':
        S.lastPlain = m.plain; S.lastState = 'ถอดรหัสสำเร็จ';
        break;
      case 'eve': {
        if (m.isKey) {
          S.hasKey = true;
          S.log.unshift({ text: 'ได้กุญแจ ' + m.text, read: true });
          ctx.ring(P.ev); ctx.float([P.ev[0], P.ev[1] - 20], 'ได้กุญแจ!', 'bad');
        } else {
          const open = cfg.mode === 'none' || S.hasKey;
          if (open) {
            ctx.bump('read');
            S.log.unshift({ text: m.plain, read: true });
          } else if (cfg.mode === 'caesar' && cfg.crack) {
            S.trying = { raw: m.text, plain: m.plain, k: 0 };
            S.log.unshift({ text: m.text, read: false });
          } else {
            if (S.seen[m.text]) { ctx.bump('repeat'); S.log.unshift({ text: m.text, read: false, dup: S.seen[m.text] + 1 }); }
            else S.log.unshift({ text: m.text, read: false });
            S.seen[m.text] = (S.seen[m.text] || 0) + 1;
          }
        }
        if (S.log.length > 3) S.log.length = 3;
        break;
      }
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const on = cfg.mode !== 'none';

    const wc = on && !S.hasKey ? 'wire strong' : 'wire';
    for (let i = 0; i < 4; i++) { const w = S['w' + i]; if (w && w.getAttribute('class') !== wc) w.setAttribute('class', wc); }

    S.encG.setAttribute('opacity', on ? 1 : 0.3);
    S.decG.setAttribute('opacity', on ? 1 : 0.3);
    S.encPill.set(['เข้ารหัส', on ? String(cfg.key) : 'ปิด']);
    S.encPill.tone(on ? 'ok' : 'dead');
    S.decPill.set(['ถอดรหัส', on ? String(cfg.key) : 'ปิด']);
    S.decPill.tone(on ? 'ok' : 'dead');
    S.evPill.set(['Eve', S.hasKey ? 'ถอดได้หมด' : on ? 'ได้แต่ขยะ' : 'อ่านได้หมด']);
    S.evPill.tone(S.hasKey || !on ? 'hot' : '');

    S.keyPanel.set(0, MODE_NAME[cfg.mode], on ? 'ok' : 'bad');
    S.keyPanel.set(1, 'ต้องลองกุญแจ ' + (KEYSPACE[cfg.mode] === '—' ? 'ไม่ต้องเลย' : KEYSPACE[cfg.mode] + ' แบบ'), 'dim');

    S.bobPanel.set(0, S.lastPlain, 'ok mono');
    S.bobPanel.set(1, S.lastState || 'รอข้อความแรก', 'dim');

    if (S.trying) {
      S.evePanel.set(0, '> กำลังลอง k=' + S.trying.k + ' …', 'term');
      S.evePanel.set(1, '  ' + caesar(S.trying.raw, -S.trying.k), 'term dim');
      S.evePanel.set(2, '  brute force 25 แบบ', 'term dim');
    } else {
      for (let i = 0; i < 3; i++) {
        const r = S.log[i];
        if (!r) { S.evePanel.set(i, i === 0 ? '— รอข้อมูล —' : '', 'term dim'); continue; }
        if (r.read) S.evePanel.set(i, '> ' + r.text, 'term-bad');
        else S.evePanel.set(i, '? ' + r.text + (r.dup ? '   (ซ้ำครั้งที่ ' + r.dup + ')' : ''), r.dup ? 'term-bad' : 'term dim');
      }
    }
  }
});
})();
