/* ============================================================
   Lesson 03 — CIA Triad (หัวข้อ CIA / AAA / PDR)
   อ้างอิงสไลด์ "02 CIAAAAPDR" ของรายวิชา 01076042
   บทนี้ครอบคลุมเฉพาะ CIA ส่วน AAA อยู่ที่บท MFA/RBAC และ PDR ยังไม่ได้ทำ
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
  title: 'The CIA Triad',
  sub: 'Security is not one property. It is three, they break independently, and each one needs a different kind of control to put right.',
  minutes: 12,
  level: 'Foundation',

  legend: [
    ['req', 'User request'],
    ['res', 'Reply'],
    ['bad', 'Tampered or refused'],
    ['cipher sq', 'Copy taken off the wire'],
    ['hollow', 'Filtered out']
  ],

  metrics: [
    { key: 'ok', label: 'Served' },
    { key: 'leak', label: 'Readable (C)', bad: true, tone: c => c.cfg.eaves && !c.cfg.encrypt ? 'warn' : (c.cfg.encrypt && c.cfg.eaves ? 'lit' : '') },
    { key: 'tampered', label: 'Tampered (I)', bad: true, tone: c => c.cfg.tamper && !c.cfg.sign ? 'warn' : (c.cfg.sign && c.cfg.tamper ? 'lit' : '') },
    { key: 'blocked', label: 'Refused 503 (A)', bad: true, tone: c => c.cfg.flood && !c.cfg.limit ? 'warn' : '' },
    { key: 'caught', label: 'Detected' },
    {
      key: 'rateSucc', label: 'Success rate',
      fmt: c => { const t = (c.stats.ok || 0) + (c.stats.blocked || 0); return t ? Math.round((c.stats.ok || 0) * 100 / t) + '%' : '–'; },
      tone: c => { const t = (c.stats.ok || 0) + (c.stats.blocked || 0); return t > 8 && (c.stats.ok || 0) / t >= 0.97 ? 'lit' : ''; }
    }
  ],

  learn: [
    ['Security has three properties: C, I and A', 0],
    ['Eavesdropping breaks nothing, and the secret is still gone', 1],
    ['Encrypted data can still be altered in transit', 2],
    ['Making a system unavailable is a security failure too', 3],
    ['Each property needs a different kind of control', 6]
  ],

  steps: [
    {
      tag: 'concept', label: 'Three pillars', title: 'Security is three properties at once',
      body: [
        'Whether a system is secure is three questions, not one. <code>C</code> confidentiality, that information is not disclosed to anyone unauthorised. <code>I</code> integrity, that data stays accurate and unaltered over its whole life. <code>A</code> availability, that the service is there when an authorised user needs it.',
        'Nobody is attacking yet. Requests travel from the users through the trunk, past the gateway, into a server that can run eight jobs at once. All three lamps in the top right are green.'
      ],
      note: ['The three pull against each other', 'Lock something down hard enough for confidentiality and it becomes harder to use and easier to break. Real design is finding the balance, not maximising one of the three.'],
      changed: ['Users: 3', 'Server: 8 concurrent jobs', 'Attacker: not acting yet'],
      cfg: { rate: 3, eaves: false, tamper: false, flood: false, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'problem', label: 'Eavesdrop', title: 'C breaks: somebody is listening on the wire',
      body: [
        'The attacker taps the trunk and copies every packet passing through. The data still reaches the server intact, the service still answers normally, and every metric about uptime looks perfect.',
        'But look at the black panel. <code>pass=1234</code> and <code>card=4111</code> are readable. This is a loss of confidentiality: nothing is broken, and the secret is already gone.'
      ],
      note: ['Why it is hard to catch', 'Eavesdropping is passive. It alters nothing, deletes nothing, slows nothing down, so it leaves no trace in any log for anyone to find.'],
      changed: ['Attacker: tapping the trunk'],
      cfg: { rate: 3, eaves: true, tamper: false, flood: false, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'attack', label: 'Tamper', title: 'I breaks: the data is changed in transit',
      body: [
        'Now the attacker does more than watch. Values are edited before being passed on — an account number, an amount. The server receives a request that is correctly formed in every way, so it does exactly what it is told.',
        'Packets that turn red were altered on the way. They are counted under "Tampered". The user does not know, and neither does the server.'
      ],
      note: ['Encryption alone is not enough', 'Encryption makes data unreadable. It says nothing about whether the data was changed. The two are separate properties, which is why a check value always has to travel with the data.'],
      changed: ['Attacker: also altering data'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: false, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'attack', label: 'Flood', title: 'A breaks: every slot is taken',
      body: [
        'The attacker changes tactics and sends junk requests in bulk. All of the server\'s slots fill with work nobody wants, so requests from real users are refused with <code>503</code>.',
        'Nothing extra leaked and nothing extra was altered, but the users cannot work. Watch the success rate fall. This is one of the three pillars gone, and the system is no less broken for it.'
      ],
      note: ['DoS and DDoS', 'From one machine it is a DoS and blocking one address ends it. From tens of thousands of compromised machines at once it is a DDoS, and telling those apart from real users is a far harder problem.'],
      changed: ['Attacker: flooding at 10 requests/second'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: false, sign: false, limit: false }
    },
    {
      tag: 'technique', label: 'Encrypt', title: 'Restore C with encryption',
      body: [
        'Turn encryption on and the wire becomes a solid green line. The attacker still copies exactly as many packets as before, but what arrives is a block of characters with no meaning.',
        'Notice that the number captured does not drop at all. What drops is the number that are readable. Lamp C is green again; I and A are both still red.'
      ],
      note: ['In transit and at rest', 'TLS protects data while it moves. Data sitting on a disk needs its own encryption. They are separate controls and having one says nothing about the other.'],
      changed: ['Encryption on the channel'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: true, sign: false, limit: false }
    },
    {
      tag: 'technique', label: 'Sign', title: 'Restore I with a check value',
      body: [
        'The sender computes a check value over the content together with a secret key and attaches it. The receiver recomputes it and compares. If they differ, the data was altered.',
        'Red packets still arrive, but they are now refused at the door and counted as "Detected" instead. The attacker can still change bits on the wire; what they can no longer do is make the server believe them.'
      ],
      note: ['Not prevention, but detection', 'Nobody can stop a party in the middle from flipping bits on a cable. What you can do is guarantee that any change is noticed, which is enough, because then the message is simply discarded.'],
      changed: ['MAC attached to every request'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: true, sign: true, limit: false }
    },
    {
      tag: 'technique', label: 'Rate limit', title: 'Restore A by filtering at the door',
      body: [
        'The gateway starts counting requests per source and drops anything from a source that exceeds its quota, before it can occupy a slot on the server.',
        'All three lamps are green. Worth noticing: not one line of the server changed. A filtering layer was added in front of it. That is defence in depth — controls in layers, so that one failure is not the end.'
      ],
      note: ['Something to think about', 'If the attacker spreads the flood across ten thousand addresses at two requests per second each, does per-address rate limiting still help? What else would you need?'],
      changed: ['Gateway: per-source rate limit'],
      cfg: { rate: 3, eaves: true, tamper: true, flood: true, encrypt: true, sign: true, limit: true }
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: find where the system breaks',
      body: [
        'Switch attacks and controls independently. Two questions to answer. First: with encryption on but no signature, which lamp is still red? Second: with no attacker at all, push the request rate to maximum — which pillar fails?',
        'The slides map threats onto the principle they violate. A power cut maps to availability. Unauthorised use maps to authentication. Try that with any threat you can think of; if it maps to nothing, you have probably not understood the threat yet.'
      ],
      note: ['A quick way to assess any system', 'Ask three questions of anything you are reviewing. Who can read this? Who can change it? What can stop it serving? CIA is the whole checklist, and the next lessons add AAA and PDR to it.'],
      changed: [],
      cfg: { rate: 4, eaves: true, tamper: false, flood: false, encrypt: false, sign: false, limit: false },
      controls: ['rate', 'eaves', 'tamper', 'flood', 'encrypt', 'sign', 'limit']
    }
  ],

  controls: {
    rate: {
      type: 'range', min: 1, max: 14, get: c => c.rate, set: (c, v) => { c.rate = v; },
      label: v => `Real request rate: <output>${v}</output> per second`
    },
    eaves: { type: 'toggle', label: 'Attacker: tap the wire', hint: 'Copy every packet at the trunk', get: c => c.eaves, set: (c, v) => { c.eaves = v; } },
    tamper: { type: 'toggle', label: 'Attacker: alter data in transit', hint: 'Edit values before passing them on', get: c => c.tamper, set: (c, v) => { c.tamper = v; } },
    flood: { type: 'toggle', label: 'Attacker: flood with requests', hint: 'Occupy the server slots', get: c => c.flood, set: (c, v) => { c.flood = v; } },
    encrypt: { type: 'toggle', label: 'Control: encrypt the channel', hint: 'Fixes pillar C', get: c => c.encrypt, set: (c, v) => { c.encrypt = v; } },
    sign: { type: 'toggle', label: 'Control: attach a MAC', hint: 'Fixes pillar I', get: c => c.sign, set: (c, v) => { c.sign = v; } },
    limit: { type: 'toggle', label: 'Control: rate limit at the gateway', hint: 'Fixes pillar A', get: c => c.limit, set: (c, v) => { c.limit = v; } }
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
    ctx.pill(LB, lp[0], lp[1] - 6, ['Users', String(CY.length)]);

    const jg = ctx.el('g', {}, E);
    A.box(jg, JX, JY, { w: 0.62, h: 0.34, pal: 'grey' });
    const jpos = iso(JX, JY + 0.6, 0);
    ctx.pill(LB, jpos[0], jpos[1] + 16, ['Trunk']);

    const gg = ctx.el('g', { class: 'node' }, E);
    const gate = A.box(gg, GX, GY, { w: 1.35, h: 0.58, pal: 'violet' });
    const gc = iso(GX, GY, gate.box.zt);
    S.gateSplit = ctx.el('g', {}, gg); ctx.glyph.split(S.gateSplit, gc);
    S.gateWall = ctx.el('g', {}, gg); ctx.glyph.wall(S.gateWall, gc);
    const gpos = iso(GX, GY + 1.15, 0);
    S.gatePill = ctx.pill(LB, gpos[0], gpos[1] + 16, ['Gateway', '']);

    const sg = ctx.el('g', { class: 'node' }, E);
    S.srv = A.server(sg, SX, SY, 'bone', 2.0);
    S.srvG = sg;
    const spos = iso(SX + 0.95, SY + 0.95, 0);
    S.srvPill = ctx.pill(LB, spos[0], spos[1] + 20, ['Server', '0/' + CAP]);

    S.atkG = ctx.el('g', {}, E);
    A.attacker(S.atkG, AX, AY);
    const apos = iso(AX - 0.9, AY + 0.9, 0);
    S.atkPill = ctx.pill(LB, apos[0] + 10, apos[1] + 16, ['Attacker', ''], 'middle');

    /* --- HUD --- */
    S.hud = ctx.statusList(H, {
      x: 490, y: 78, w: 226, title: 'Security status',
      items: ['Confidentiality', 'Integrity', 'Availability']
    });
    S.logPanel = ctx.panel(H, { x: 498, y: 392, w: 212, rows: 3, title: 'What the attacker captured', dark: true });
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
          if (cfg.sign) { ctx.bump('caught'); ctx.puff(P.srv, 'ok'); ctx.float(top, 'rejected', 'ok'); }
          else { ctx.bump('tampered'); ctx.ring(P.srv); ctx.float(top, 'accepted', 'bad'); }
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
    S.srvPill.set(['Server', S.active + '/' + CAP]);

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
    S.gatePill.set(['Gateway', cfg.limit ? 'rate limited' : 'passing all']);
    S.gatePill.tone(cfg.limit ? 'ok' : '');

    /* attacker dimming + label */
    const busy = cfg.eaves || cfg.tamper || cfg.flood;
    S.atkG.setAttribute('opacity', busy ? 1 : 0.32);
    const acts = [];
    if (cfg.eaves) acts.push('sniff');
    if (cfg.tamper) acts.push('tamper');
    if (cfg.flood) acts.push('flood');
    S.atkPill.set(['Attacker', acts.length ? acts.join(' + ') : 'idle']);
    S.atkPill.tone(busy ? 'hot' : 'dead');

    /* three pillars */
    const leak = ctx.stats.leak || 0, tam = ctx.stats.tampered || 0, blk = ctx.stats.blocked || 0;
    if (!cfg.eaves) S.hud.set(0, 'ok', 'normal');
    else if (cfg.encrypt) S.hud.set(0, 'ok', 'encrypted');
    else S.hud.set(0, 'bad', 'leaked ' + leak);

    if (!cfg.tamper) S.hud.set(1, 'ok', 'normal');
    else if (cfg.sign) S.hud.set(1, 'ok', 'caught ' + (ctx.stats.caught || 0));
    else S.hud.set(1, 'bad', 'faked ' + tam);

    if (!cfg.flood) S.hud.set(2, blk > 0 ? 'bad' : 'ok', blk > 0 ? 'refused ' + blk : 'serving');
    else if (cfg.limit) S.hud.set(2, blk > 0 ? 'bad' : 'ok', blk > 0 ? 'refused ' + blk : 'filtered');
    else S.hud.set(2, 'bad', '503 ' + blk);

    /* attacker log */
    for (let i = 0; i < 3; i++) {
      const row = S.log[i];
      if (!row) { S.logPanel.set(i, i === 0 && !cfg.eaves ? '— nothing captured —' : '', 'dim term'); continue; }
      S.logPanel.set(i, (row.safe ? '? ' : '> ') + row.text, row.safe ? 'term dim' : 'term-bad');
    }
  }
});
})();
