/* ============================================================
   บทที่ 4.2 — Cross-site Scripting (XSS)
   คอมเมนต์ของผู้โจมตี กลายเป็นสคริปต์ที่รันในเบราว์เซอร์เหยื่อ
   ============================================================ */
(function () {
const ATK = [0.2, 4.4];
const SRV = [3.0, 1.6];
const VIC = [5.8, -1.2];
const COOKIE = 'session=a9f2c1';

function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function wrap(str, n) {
  if (str.length <= n) return [str, ''];
  let cut = str.lastIndexOf(' ', n);
  if (cut < n * 0.6) cut = n;
  const rest = str.slice(cut).trim();
  return [str.slice(0, cut), rest.length > n ? rest.slice(0, n - 1) + '…' : rest];
}

function run(cfg) {
  const raw = cfg.comment || '';
  const shown = cfg.escape ? esc(raw) : raw;
  const html = cfg.context === 'attr'
    ? '<img src="avatar.png" alt="' + shown + '">'
    : '<div class="comment">' + shown + '</div>';

  const byTag = /<script/i.test(shown);
  const byAttr = cfg.context === 'attr' && /"\s*on\w+\s*=/i.test(shown);
  let runs = byTag || byAttr, blockedBy = null;
  if (runs && cfg.csp) { runs = false; blockedBy = 'CSP'; }

  const kind = /changeemail/i.test(raw) ? 'act' : /cookie/i.test(raw) ? 'steal' : byTag || byAttr ? 'noop' : 'none';

  let result = 'safe';
  if (runs) {
    if (kind === 'steal') result = cfg.httpOnly ? 'emptyCookie' : 'stolen';
    else if (kind === 'act') result = 'acted';
    else result = 'ran';
  } else if (kind !== 'none') result = blockedBy ? 'csp' : 'escaped';

  return { raw, shown, html, runs, kind, result, via: byAttr ? 'attr' : byTag ? 'tag' : null };
}

const RESULT_TEXT = {
  safe: ['คอมเมนต์ธรรมดา แสดงผลตามปกติ', 'dim'],
  escaped: ['แท็กถูกแปลงเป็นข้อความ สคริปต์ไม่รัน', 'ok'],
  csp: ['CSP บล็อกไม่ให้สคริปต์ทำงาน', 'ok'],
  emptyCookie: ['สคริปต์รันได้ แต่อ่านคุกกี้ไม่ได้', 'ok'],
  ran: ['สคริปต์แปลกปลอมรันในหน้าเว็บเรา', 'bad'],
  stolen: ['ขโมยคุกกี้เซสชันออกไปได้', 'bad'],
  acted: ['สั่งงานแทนเหยื่อได้โดยตรง', 'bad']
};

ICS.register({
  id: 'xss',
  title: 'Cross-site Scripting (XSS)',
  sub: 'ถ้า SQL injection คือข้อมูลที่กลายเป็นคำสั่งของฐานข้อมูล XSS ก็คือข้อมูลที่กลายเป็นคำสั่งของเบราว์เซอร์',
  minutes: 13,
  level: 'ระดับกลาง',

  legend: [
    ['req sq', 'คอมเมนต์ที่ถูกโพสต์'],
    ['hash sq', 'HTML ที่ส่งให้เหยื่อ'],
    ['bad', 'สคริปต์ของผู้โจมตี / คุกกี้ที่ถูกขโมย'],
    ['res', 'ถูกกันไว้ได้']
  ],

  metrics: [
    { key: 'posts', label: 'หน้าที่เหยื่อเปิด' },
    { key: 'stolen', label: 'คุกกี้ถูกขโมย', bad: true, tone: c => (c.stats.stolen || 0) > 0 ? 'warn' : '' },
    { key: 'acted', label: 'ถูกสั่งงานแทน', bad: true, tone: c => (c.stats.acted || 0) > 0 ? 'warn' : '' },
    { key: 'stopped', label: 'สคริปต์ที่ถูกกัน', tone: c => (c.stats.stopped || 0) > 0 ? 'lit' : '' },
    { key: 'st', label: 'ผลล่าสุด', fmt: c => c.S.res ? RESULT_TEXT[c.S.res.result][0].slice(0, 18) : '–' }
  ],

  learn: [
    ['ข้อมูลของผู้ใช้กลายเป็น HTML ได้อย่างไร', 1],
    ['XSS ไม่ได้มีแค่การขโมยคุกกี้', 2],
    ['escape ตอนแสดงผลคือทางแก้หลัก', 3],
    ['escape ต้องดูบริบทที่ค่าไปอยู่ด้วย', 4],
    ['HttpOnly กับ CSP คือตาข่ายรองชั้นถัดไป', 5]
  ],

  steps: [
    {
      tag: 'concept', label: 'คอมเมนต์ปกติ', title: 'เว็บบอร์ดที่เอาคอมเมนต์ไปต่อเป็น HTML',
      body: [
        'ผู้ใช้พิมพ์คอมเมนต์ เซิร์ฟเวอร์เก็บลงฐานข้อมูล แล้วตอนใครเปิดหน้านี้ก็เอาข้อความนั้นมาต่อเข้ากับ HTML ส่งไปให้เบราว์เซอร์ ฟีเจอร์พื้นฐานที่ทุกเว็บมี',
        'ดูแผงกลางที่ชื่อ "HTML ที่ส่งให้เบราว์เซอร์เหยื่อ" ข้อความของผู้ใช้ถูกวางลงไปตรงกลางแท็ก <code>div</code> พอดี จุดนี้คือจุดเดียวกับที่ input ถูกวางลงในคำสั่ง SQL ในบทที่แล้ว'
      ],
      note: ['รูปแบบเดิม ปัญหาเดิม', 'ทุกครั้งที่เอาข้อมูลจากผู้ใช้ไปต่อกับภาษาอะไรก็ตาม ไม่ว่าจะ SQL, HTML, คำสั่งเชลล์ หรือเทมเพลต โอกาสที่ข้อมูลจะข้ามเส้นไปเป็นคำสั่งจะเกิดขึ้นเสมอ'],
      changed: ['คอมเมนต์: ข้อความธรรมดา', 'การป้องกัน: ยังไม่มี'],
      cfg: { comment: 'สวัสดีครับ บทความนี้ดีมาก', escape: false, httpOnly: false, csp: false, context: 'text' }
    },
    {
      tag: 'attack', label: 'ขโมยคุกกี้', title: 'โพสต์คอมเมนต์ที่เป็นสคริปต์',
      body: [
        'ผู้โจมตีโพสต์ <code class="danger">&lt;script&gt;send(document.cookie)&lt;/script&gt;</code> ซึ่งถูกเก็บลงฐานข้อมูลเหมือนคอมเมนต์ทั่วไป และถูกส่งไปให้ทุกคนที่เปิดหน้านี้',
        'เบราว์เซอร์ของเหยื่อไม่มีทางรู้ว่าสคริปต์ก้อนไหนเป็นของเว็บจริงและก้อนไหนเป็นของผู้โจมตี มันจึงรันให้ทั้งหมด คุกกี้เซสชันของเหยื่อวิ่งกลับไปหาผู้โจมตีทันที'
      ],
      note: ['stored XSS', 'แบบนี้เรียก stored XSS เพราะเพย์โหลดถูกเก็บไว้ในระบบ ใครเปิดหน้านั้นก็โดนหมด ส่วน reflected XSS จะสะท้อนกลับมาจาก URL ซึ่งต้องหลอกให้เหยื่อกดลิงก์ก่อน'],
      changed: ['คอมเมนต์: แท็ก script'],
      cfg: { comment: '<script>send(document.cookie)</script>', escape: false, httpOnly: false, csp: false, context: 'text' }
    },
    {
      tag: 'attack', label: 'สวมรอย', title: 'XSS ไม่ได้มีแค่การขโมยคุกกี้',
      body: [
        'สคริปต์ที่รันอยู่ในหน้าเว็บของเรา มีสิทธิ์เท่ากับโค้ดของเราเองทุกประการ มันเรียก API ในชื่อของเหยื่อได้ อ่านหน้าจอที่เหยื่อเห็นได้ และแก้สิ่งที่แสดงผลได้',
        'คราวนี้สคริปต์ไม่แตะคุกกี้เลย แต่สั่งเปลี่ยนอีเมลของบัญชีเหยื่อเป็นของผู้โจมตีแทน จากนั้นก็กดลืมรหัสผ่านเพื่อยึดบัญชีได้สบายๆ โดยไม่ต้องรู้รหัสเดิม'
      ],
      note: ['ทำไมเรื่องนี้สำคัญ', 'หลายคนคิดว่าแก้ XSS ด้วยการตั้งคุกกี้เป็น HttpOnly ก็พอ แต่การสวมรอยแบบนี้ไม่ต้องอ่านคุกกี้เลยสักนิด เพราะเบราว์เซอร์แนบคุกกี้ไปให้เองอยู่แล้ว'],
      changed: ['คอมเมนต์: สคริปต์สั่งเปลี่ยนอีเมล'],
      cfg: { comment: '<script>changeEmail("evil@x.com")</script>', escape: false, httpOnly: false, csp: false, context: 'text' }
    },
    {
      tag: 'technique', label: 'Escape', title: 'ทางแก้หลัก: แปลงอักขระพิเศษตอนแสดงผล',
      body: [
        'ก่อนเอาข้อความของผู้ใช้ไปวางใน HTML ให้แปลง <code>&lt;</code> เป็น <code>&amp;lt;</code> และ <code>&gt;</code> เป็น <code>&amp;gt;</code> เบราว์เซอร์จะเห็นว่านี่คือ "ตัวอักษรน้อยกว่า" ไม่ใช่ "จุดเริ่มต้นของแท็ก"',
        'เหยื่อจะเห็นข้อความ <code>&lt;script&gt;send(document.cookie)&lt;/script&gt;</code> ปรากฏเป็นตัวหนังสือบนหน้าจอ ซึ่งเป็นสิ่งที่ถูกต้อง เพราะผู้ใช้พิมพ์ข้อความนี้มาจริงๆ'
      ],
      note: ['ใช้ของที่มีอยู่แล้ว', 'เฟรมเวิร์กสมัยใหม่อย่าง React, Vue หรือเทมเพลตเอนจินส่วนใหญ่ escape ให้อัตโนมัติ ช่องโหว่มักเกิดตอนที่เราไปเรียกทางลัดอย่าง innerHTML หรือ dangerouslySetInnerHTML เอง'],
      changed: ['เปิด escape ตอนแสดงผล'],
      cfg: { comment: '<script>send(document.cookie)</script>', escape: true, httpOnly: false, csp: false, context: 'text' }
    },
    {
      tag: 'problem', label: 'ผิดบริบท', title: 'escape ที่ไม่ดูบริบท ยังหลุดได้',
      body: [
        'คราวนี้ค่าของผู้ใช้ไม่ได้ไปอยู่ระหว่างแท็ก แต่ไปอยู่ใน <code>attribute</code> ของรูปภาพ การแปลงเฉพาะ <code>&lt;</code> กับ <code>&gt;</code> จึงไม่ช่วยอะไรเลย เพราะผู้โจมตีไม่ต้องใช้แท็กใหม่',
        'เขาแค่พิมพ์เครื่องหมายคำพูดเพื่อปิด attribute เดิม แล้วเติม <code class="danger">onerror=</code> เข้าไปแทน พอรูปโหลดไม่สำเร็จ เบราว์เซอร์ก็เรียกโค้ดนั้นให้เอง'
      ],
      note: ['escape ต้องรู้ว่าจะไปอยู่ตรงไหน', 'ค่าที่ไปอยู่ใน HTML, ใน attribute, ใน URL และในโค้ด JavaScript ต้องใช้วิธีแปลงคนละแบบ นี่คือเหตุผลที่ควรใช้ไลบรารีของเฟรมเวิร์กแทนการเขียนฟังก์ชัน escape เอง'],
      changed: ['ตำแหน่งที่ค่าไปอยู่: attribute', 'คอมเมนต์: ปิด attribute แล้วเติม onerror'],
      cfg: { comment: '" onerror="send(document.cookie)', escape: true, httpOnly: false, csp: false, context: 'attr' }
    },
    {
      tag: 'technique', label: 'ตาข่ายรอง', title: 'HttpOnly และ CSP: ชั้นที่รับไว้เมื่อด่านแรกพลาด',
      body: [
        'คุกกี้ที่ตั้งเป็น <code>HttpOnly</code> จะถูกซ่อนจาก JavaScript ทั้งหมด สคริปต์ยังรันได้ แต่อ่าน <code>document.cookie</code> แล้วได้ค่าว่าง ส่วน <code>CSP</code> บอกเบราว์เซอร์ว่าให้รันสคริปต์จากแหล่งที่ระบุไว้เท่านั้น',
        'ลองเปิดทีละอัน จะเห็นว่า HttpOnly หยุดการขโมยคุกกี้ได้ แต่ถ้าสลับกลับไปใช้เพย์โหลดสวมรอยจะพบว่ามันไม่ช่วยเลย ส่วน CSP กันได้ตั้งแต่ต้นเพราะสคริปต์ไม่ได้รันด้วยซ้ำ'
      ],
      note: ['ยังไงก็ต้องแก้ที่ต้นเหตุ', 'ทั้งสองอย่างนี้คือ defense in depth ไม่ใช่ตัวแทนของการ escape ถ้าสคริปต์ของผู้โจมตีรันได้ แปลว่าเรามีช่องโหว่อยู่ดี เพียงแต่ความเสียหายถูกจำกัดลง'],
      changed: ['คุกกี้: HttpOnly', 'ส่งหัวข้อ CSP'],
      cfg: { comment: '" onerror="send(document.cookie)', escape: true, httpOnly: true, csp: true, context: 'attr' },
      controls: ['httpOnly', 'csp']
    },
    {
      tag: 'lab', label: 'ลองเอง', title: 'ลองเอง: พิมพ์คอมเมนต์เอง',
      body: [
        'ลองสองอย่างนี้ หนึ่ง เปิด HttpOnly อย่างเดียวแล้วใช้เพย์โหลด "สวมรอย" ดูว่ามันกันได้หรือไม่ สอง เปิด escape ขณะที่ค่าไปอยู่ใน attribute ดูว่าทำไมถึงยังหลุด',
        'สิ่งที่อยากให้จำกลับไปคือลำดับความสำคัญ แก้ให้ข้อมูลไม่กลายเป็นคำสั่งก่อนเสมอ แล้วค่อยวางตาข่ายรองไว้ข้างล่าง ไม่ใช่กลับกัน'
      ],
      note: ['ตรวจโค้ดตัวเองยังไง', 'ไล่หาทุกจุดที่เขียนลง DOM ด้วย innerHTML, outerHTML, document.write หรือการประกอบ HTML เป็นสตริง ทุกจุดนั้นคือจุดที่ต้องตรวจว่าค่ามาจากผู้ใช้หรือเปล่า'],
      changed: [],
      cfg: { comment: '<script>send(document.cookie)</script>', escape: false, httpOnly: false, csp: false, context: 'text' },
      controls: ['comment', 'context', 'escape', 'httpOnly', 'csp']
    }
  ],

  controls: {
    comment: {
      type: 'text', label: 'คอมเมนต์ที่ผู้โจมตีโพสต์', placeholder: 'สวัสดีครับ',
      hint: 'ลองใส่แท็กหรือเครื่องหมายคำพูดดู',
      get: c => c.comment, set: (c, v) => { c.comment = v; },
      presets: [
        ['ปกติ', 'สวัสดีครับ บทความนี้ดีมาก'],
        ['ขโมยคุกกี้', '<script>send(document.cookie)</script>'],
        ['สวมรอย', '<script>changeEmail("evil@x.com")</script>'],
        ['ผ่าน attribute', '" onerror="send(document.cookie)']
      ]
    },
    context: {
      type: 'seg', label: 'ค่าของผู้ใช้ไปอยู่ตรงไหนใน HTML',
      options: [['text', 'ระหว่างแท็ก'], ['attr', 'ใน attribute']],
      get: c => c.context, set: (c, v) => { c.context = v; }
    },
    escape: { type: 'toggle', label: 'escape ตอนแสดงผล', hint: 'แปลง < และ > เป็นข้อความ', get: c => c.escape, set: (c, v) => { c.escape = v; } },
    httpOnly: { type: 'toggle', label: 'คุกกี้เป็น HttpOnly', hint: 'ซ่อนคุกกี้จาก JavaScript', get: c => c.httpOnly, set: (c, v) => { c.httpOnly = v; } },
    csp: { type: 'toggle', label: 'ส่งหัวข้อ CSP', hint: 'ห้ามรันสคริปต์ที่ไม่ได้อนุญาต', get: c => c.csp, set: (c, v) => { c.csp = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      res: null, got: [],
      P: { a: iso(ATK[0], ATK[1], 0.78), s: iso(SRV[0], SRV[1], 0.92), v: iso(VIC[0], VIC[1], 0.8) }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    ctx.line(iso(ATK[0], ATK[1], 0.2), iso(SRV[0], SRV[1], 0.2), 'wire', L.wires);
    ctx.line(iso(SRV[0], SRV[1], 0.2), iso(VIC[0], VIC[1], 0.2), 'wire', L.wires);
    S.steal = ctx.line(iso(VIC[0], VIC[1], 0.2), iso(ATK[0], ATK[1], 0.2), 'wire tap', L.wires);

    const ag = ctx.el('g', {}, L.ents);
    Ac.attacker(ag, ATK[0], ATK[1]);
    S.aPill = ctx.pill(L.labels, S.P.a[0] - 4, iso(ATK[0], ATK[1] + 0.9, 0)[1] + 14, ['ผู้โจมตี', '']);

    const sg = ctx.el('g', {}, L.ents);
    const sb = Ac.box(sg, SRV[0], SRV[1], { w: 1.4, h: 0.7, pal: 'green' });
    S.shield = ctx.el('g', {}, sg);
    ctx.glyph.lock(S.shield, iso(SRV[0], SRV[1], sb.box.zt));
    S.sPill = ctx.pill(L.labels, iso(SRV[0], SRV[1] + 1.15, 0)[0], iso(SRV[0], SRV[1] + 1.15, 0)[1] + 14, ['เว็บบอร์ด', '']);

    const vg = ctx.el('g', {}, L.ents);
    Ac.desk(vg, VIC[0], VIC[1], 'blue', 1.15);
    S.vPill = ctx.pill(L.labels, S.P.v[0], iso(VIC[0], VIC[1] + 1.0, 0)[1] + 14, ['เหยื่อ', '']);

    S.inP = ctx.panel(L.hud, { x: 126, y: 76, w: 322, rows: 2, title: 'คอมเมนต์ที่ถูกโพสต์' });
    S.defP = ctx.statusList(L.hud, {
      x: 486, y: 74, w: 230, title: 'การป้องกันที่เปิดอยู่',
      items: ['escape ตอนแสดงผล', 'คุกกี้ HttpOnly', 'หัวข้อ CSP']
    });
    S.htmlP = ctx.panel(L.hud, { x: 126, y: 252, w: 566, rows: 3, title: 'HTML ที่ส่งให้เบราว์เซอร์เหยื่อ' });
    S.browP = ctx.panel(L.hud, { x: 126, y: 346, w: 330, rows: 3, title: 'สิ่งที่เกิดขึ้นในเบราว์เซอร์เหยื่อ' });
    S.gotP = ctx.panel(L.hud, { x: 468, y: 346, w: 224, rows: 3, title: 'ผู้โจมตีได้รับ', dark: true });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    if (ctx.timer('post', dt, 3000)) {
      const raw = cfg.comment || '';
      ctx.launch([P.a, P.s], /[<"]/.test(raw) ? 'bad' : 'plain',
        { label: raw.length > 16 ? raw.slice(0, 16) + '…' : (raw || '(ว่าง)'), meta: { leg: 'srv' }, speed: 230 });
    }
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;

    if (m.leg === 'srv') {
      const res = run(cfg);
      S.res = res;
      ctx.launch([P.s, P.v], res.runs && res.kind !== 'none' ? 'bad' : 'hashd',
        { label: 'HTML', meta: { leg: 'vic', res }, speed: 240 });
      return;
    }

    if (m.leg === 'vic') {
      const res = m.res;
      ctx.bump('posts');
      const top = [P.v[0], P.v[1] - 28];
      if (res.result === 'stolen') {
        ctx.bump('stolen'); ctx.ring(P.v);
        ctx.launch([P.v, P.a], 'bad', { label: COOKIE, meta: { leg: 'atk', text: COOKIE }, speed: 260 });
      } else if (res.result === 'acted') {
        ctx.bump('acted'); ctx.ring(P.v);
        ctx.float(top, 'เปลี่ยนอีเมล', 'bad');
        ctx.launch([P.v, P.a], 'bad', { label: 'email ถูกเปลี่ยน', meta: { leg: 'atk', text: 'ยึดบัญชีเหยื่อแล้ว' }, speed: 260 });
      } else if (res.result === 'emptyCookie') {
        ctx.bump('stopped'); ctx.puff(P.v, 'ok');
        ctx.launch([P.v, P.a], 'plain', { label: 'cookie = ว่าง', meta: { leg: 'atk', text: '(ว่าง) — HttpOnly', empty: true }, speed: 260 });
      } else if (res.result === 'ran') {
        ctx.ring(P.v);
      } else if (res.result !== 'safe') {
        ctx.bump('stopped'); ctx.puff(P.v, 'ok'); ctx.float(top, 'กันไว้ได้', 'ok');
      }
      return;
    }

    if (m.leg === 'atk') {
      S.got.unshift({ t: m.text, empty: !!m.empty });
      if (S.got.length > 3) S.got.length = 3;
      if (!m.empty) ctx.ring(P.a);
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const raw = cfg.comment || '';
    const dangerous = /[<"]/.test(raw);

    S.aPill.set(['ผู้โจมตี', dangerous ? 'โพสต์เพย์โหลด' : 'โพสต์ปกติ']);
    S.aPill.tone(dangerous ? 'hot' : 'dead');
    S.shield.setAttribute('opacity', cfg.escape ? 1 : 0.15);
    S.sPill.set(['เว็บบอร์ด', cfg.escape ? 'escape ก่อนแสดง' : 'ต่อสตริงตรงๆ']);
    S.sPill.tone(cfg.escape ? 'ok' : 'hot');
    S.steal.setAttribute('class', 'wire tap' + ((ctx.stats.stolen || ctx.stats.acted) ? '' : ' off'));

    S.defP.set(0, cfg.escape ? 'ok' : 'bad', cfg.escape ? 'เปิด' : 'ปิด');
    S.defP.set(1, cfg.httpOnly ? 'ok' : 'bad', cfg.httpOnly ? 'เปิด' : 'ปิด');
    S.defP.set(2, cfg.csp ? 'ok' : 'bad', cfg.csp ? 'เปิด' : 'ปิด');

    S.inP.set(0, raw || '(ว่าง)', dangerous ? 'bad mono' : 'mono');
    S.inP.set(1, /<script/i.test(raw) ? 'มีแท็ก script อยู่ข้างใน'
      : /"/.test(raw) ? 'มีเครื่องหมายคำพูดที่ใช้ปิด attribute ได้'
      : 'เป็นข้อความธรรมดา', dangerous ? 'bad' : 'dim');

    const res = S.res;
    if (!res) {
      [0, 1, 2].forEach(i => { S.htmlP.set(i, i === 0 ? 'กำลังรอคอมเมนต์แรก…' : '', 'dim'); S.browP.set(i, '', ''); });
    } else {
      const ln = wrap(res.html, 78);
      const bad = res.runs && res.kind !== 'none';
      S.htmlP.set(0, ln[0], bad ? 'bad mono' : 'mono');
      S.htmlP.set(1, ln[1], bad ? 'bad mono' : 'mono');
      S.htmlP.set(2, cfg.context === 'attr'
        ? 'ค่าของผู้ใช้ถูกวางใน attribute ชื่อ alt'
        : 'ค่าของผู้ใช้ถูกวางระหว่างแท็ก div', 'dim');

      S.vPill.set(['เหยื่อ', bad ? 'สคริปต์กำลังรัน' : 'ปลอดภัย']);
      S.vPill.tone(bad ? 'hot' : 'ok');

      S.browP.set(0, 'แสดงผล: ' + (res.runs ? '(สคริปต์ถูกเรียกทำงาน)' : res.shown.slice(0, 32)),
        res.runs ? 'bad' : 'mono dim');
      S.browP.set(1, 'สคริปต์: ' + (res.runs ? 'รันแล้ว · เข้าทาง ' + (res.via === 'attr' ? 'attribute' : 'แท็ก script')
        : res.result === 'csp' ? 'ถูก CSP บล็อก' : res.result === 'escaped' ? 'ไม่รัน เพราะถูกแปลงเป็นข้อความ' : 'ไม่มีสคริปต์'),
        res.runs ? 'bad' : 'ok');
      S.browP.set(2, RESULT_TEXT[res.result][0], RESULT_TEXT[res.result][1]);
    }

    for (let i = 0; i < 3; i++) {
      const g = S.got[i];
      S.gotP.set(i, g ? (g.empty ? '? ' : '> ') + g.t : (i === 0 ? '— ยังไม่ได้อะไร —' : ''),
        g ? (g.empty ? 'term dim' : 'term-bad') : 'term dim');
    }
  }
});
})();
