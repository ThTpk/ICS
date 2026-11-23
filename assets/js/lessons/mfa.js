/* ============================================================
   Lesson 3.2 — Multi-Factor Authentication
   password -> SMS OTP -> TOTP app -> passkey
   what each factor stops, and what it does not
   ============================================================ */
(function () {
const USR = [-0.8, 4.2];
const ATK = [1.5, 6.5];
const GATE = [[2.45, 3.25], [4.05, 1.65], [5.65, 0.05]];
const ACCT = [7.05, -1.35];

const ATTACKS = {
  stuffing: 'Passwords leaked from another site',
  simswap: 'SIM swap, the number moved',
  phish: 'Live phishing page'
};
/* ป้ายสั้นสำหรับติดบนตัวผู้โจมตี ส่วนประโยคเต็มอยู่ใน ATTACKS */
const ATTACK_SHORT = { stuffing: 'leaked passwords', simswap: 'SIM swap', phish: 'live phishing' };
const FACTOR_NAME = {
  pass: 'Password only',
  sms: 'Password + SMS OTP',
  totp: 'Password + TOTP app',
  passkey: 'Passkey (device + biometric)'
};
const activeGates = cfg => cfg.factors === 'pass' ? [0] : cfg.factors === 'passkey' ? [2] : [0, 1];
const gateName = (cfg, i) => i === 0 ? 'Password' : i === 1 ? (cfg.factors === 'sms' ? 'SMS OTP' : 'TOTP app') : 'Passkey';

/* does this gate stop this attack? */
function blocks(cfg, gate, attack) {
  if (gate === 0) return false;                                   // the password already leaked, always passes
  if (gate === 1) {
    if (cfg.factors === 'sms') return attack === 'stuffing';      // SIM swap and phishing still get through
    return attack === 'stuffing' || attack === 'simswap';         // TOTP stops SIM swap, phishing still gets through
  }
  return true;                                                    // a passkey is bound to the domain, stops all three
}

ICS.register({
  id: 'mfa',
  title: 'Multi-Factor Authentication',
  sub: 'Authentication answers one question: are you really who you claim to be? Adding a second factor helps enormously, but not every second factor stops the same attack.',
  minutes: 12,
  level: 'Intermediate',

  legend: [
    ['res', 'The real user'],
    ['bad', 'The attacker'],
    ['hollow', 'Gate that blocks'],
    ['key sq', 'Factor in use']
  ],

  metrics: [
    { key: 'ok', label: 'Real user got in' },
    { key: 'breach', label: 'Account taken over', bad: true, tone: c => (c.stats.breach || 0) > 0 ? 'warn' : '' },
    { key: 'blocked', label: 'Attacker blocked', tone: c => (c.stats.blocked || 0) > 0 ? 'lit' : '' },
    {
      key: 'rate', label: 'Attacker success rate',
      fmt: c => { const t = (c.stats.breach || 0) + (c.stats.blocked || 0); return t ? Math.round((c.stats.breach || 0) * 100 / t) + '%' : '–'; },
      tone: c => { const t = (c.stats.breach || 0) + (c.stats.blocked || 0); return t > 3 && !(c.stats.breach || 0) ? 'lit' : (c.stats.breach || 0) ? 'warn' : ''; }
    },
    { key: 'f', label: 'Factors in use', fmt: c => FACTOR_NAME[c.cfg.factors].split(' (')[0] }
  ],

  learn: [
    ['A password alone loses to passwords leaked elsewhere', 0],
    ['Three kinds of factor: know, have, are', 1],
    ['An SMS code is tied to a number, not to you', 2],
    ['TOTP stops SIM swap but not live phishing', 4],
    ['A passkey is bound to the domain, so phishing fails', 5]
  ],

  steps: [
    {
      tag: 'problem', label: 'Password only', title: 'A password on its own is no longer enough',
      body: [
        'One gate, one password. The attacker is not guessing: they are replaying passwords leaked from some other site, because most people reuse them. This is called credential stuffing and it works often enough to be automated.',
        'The real user and the attacker are holding exactly the same key, so the system has no way to tell them apart. Watch the attacker success rate sit at one hundred percent.'
      ],
      note: ['This is why password storage matters', 'A leak at one site becomes an attack on every other site. That is an industry-wide consequence of how one organisation stored its passwords, which is the subject of the hashing lesson.'],
      changed: ['Factors: password only', 'Attacker: using leaked passwords'],
      cfg: { factors: 'pass', attack: 'stuffing' }
    },
    {
      tag: 'technique', label: 'SMS OTP', title: 'Add a second factor: a code sent by SMS',
      body: [
        'Authentication factors come in three kinds. <code>Something you know</code>, like a password. <code>Something you have</code>, like a phone or a hardware token. <code>Something you are</code>, like a fingerprint. Using two of different kinds is what makes it multi-factor.',
        'The second gate is a six digit code sent to the account holder\'s number. The attacker has the password but not that phone, so they are stopped at the second gate every time.'
      ],
      note: ['Two passwords are not MFA', 'A password followed by a security question is still two things you know, and both leak together. The added factor has to be a different kind to mean anything.'],
      changed: ['Added factor: SMS OTP'],
      cfg: { factors: 'sms', attack: 'stuffing' }
    },
    {
      tag: 'attack', label: 'SIM swap', title: 'Move the phone number to a new SIM',
      body: [
        'The weakness of SMS is that it is tied to a telephone number, not to you. The attacker calls the mobile operator, claims the SIM was lost, and has the number moved to a SIM in their possession.',
        'From that moment every code arrives on the attacker\'s device. The second gate opens for them, correctly, according to the rules the system was given.'
      ],
      note: ['Still better than nothing', 'Despite this weakness, SMS codes stop an enormous volume of automated attacks. Given a choice between nothing and SMS, take SMS every time.'],
      changed: ['Attacker: SIM swap succeeded'],
      cfg: { factors: 'sms', attack: 'simswap' }
    },
    {
      tag: 'technique', label: 'TOTP app', title: 'Generate the code on the device instead',
      body: [
        'An authenticator app holds a shared secret on the device and computes a fresh six digit code every thirty seconds from that secret plus the current time. Nothing travels over the network to be intercepted.',
        'The phone number is now irrelevant, so moving the SIM gains the attacker nothing. They are stopped at the second gate again.'
      ],
      note: ['What TOTP costs', 'The shared secret lives on the device. Lose the device without recovery codes and you are locked out, and a screenshot of the setup QR code stored in the cloud leaks the secret with the cloud.'],
      changed: ['Second factor is now a TOTP app'],
      cfg: { factors: 'totp', attack: 'simswap' }
    },
    {
      tag: 'attack', label: 'Live phishing', title: 'A fake page that relays the code in real time',
      body: [
        'The attacker builds a login page identical to the real one. The victim types their password and the six digit code, and the fake page forwards both to the real site within seconds, before the code expires.',
        'The TOTP code is completely genuine. The second gate opens because it should. The problem was never the strength of the code: nothing ever checked which site the victim was typing it into.'
      ],
      note: ['The name for this', 'Adversary-in-the-middle. Ready-made toolkits for it are sold openly, which is what turned phishing through six-digit MFA from a notable attack into a routine one.'],
      changed: ['Attacker: live relay phishing'],
      cfg: { factors: 'totp', attack: 'phish' }
    },
    {
      tag: 'technique', label: 'Passkey', title: 'A factor that knows which site it is talking to',
      body: [
        'A passkey is the key pair from the asymmetric lesson, with the private key held in the device\'s secure chip and unlocked by a fingerprint or face. Logging in means signing a challenge from the site. There is no code to type and none to tell anyone.',
        'The crucial part is that the signature is bound to the domain that asked for it. A fake page on a different domain cannot obtain a usable signature, so phishing stops working without relying on the user being careful.'
      ],
      note: ['Why it counts as two factors', 'It combines something you have, the device, with something you are, the biometric that unlocks it. That is why it can replace both the password and the one-time code at once.'],
      changed: ['Switched to passkeys'],
      cfg: { factors: 'passkey', attack: 'phish' }
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: match the factor against the attack',
      body: [
        'Work through every pair and the table in your head becomes clear: SMS stops only the automated attacks, TOTP adds protection against SIM swap, and only a passkey stops phishing.',
        'The practical conclusion: turn on passkeys where they are offered, use an authenticator app where they are not, and if all that exists is SMS then still turn it on, because it is far better than nothing.'
      ],
      note: ['Do not forget the back door', 'Account recovery, for when the device is lost, is usually the weakest part of the whole system. If an account can be recovered by answering a security question, every one of these factors can be stepped around right there.'],
      changed: [],
      cfg: { factors: 'sms', attack: 'phish' },
      controls: ['factors', 'attack']
    }
  ],

  controls: {
    factors: {
      type: 'seg', label: 'Factors this account uses',
      options: [['pass', 'Password'], ['sms', '+ SMS OTP'], ['totp', '+ TOTP app'], ['passkey', 'Passkey']],
      get: c => c.factors, set: (c, v) => { c.factors = v; }, reset: true
    },
    attack: {
      type: 'seg', label: 'Attack the adversary uses',
      options: [['stuffing', 'Leaked passwords'], ['simswap', 'SIM swap'], ['phish', 'Live phishing']],
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
    ctx.pill(L.labels, S.P.u[0] - 4, iso(USR[0], USR[1] + 0.95, 0)[1] + 14, ['Real user', 'ann']);

    const ag = ctx.el('g', {}, L.ents);
    Ac.attacker(ag, ATK[0], ATK[1]);
    S.aPill = ctx.pill(L.labels, S.P.a[0] - 4, iso(ATK[0], ATK[1] + 0.9, 0)[1] + 14, ['Attacker', '']);

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
    /* ป้ายบัญชีอยู่ต่ำลงมาหนึ่งแถว ไม่งั้นพื้นหลังจะไปทับป้ายของประตูสุดท้าย */
    S.acctPill = ctx.pill(L.labels, iso(ACCT[0], ACCT[1] + 1.2, 0)[0], iso(ACCT[0], ACCT[1] + 1.2, 0)[1] + 42, ['Account', '']);

    S.setP = ctx.statusList(L.hud, {
      x: 470, y: 74, w: 246, title: 'Factors in use',
      items: ['Something you know', 'Something you have', 'Something you are']
    });
    S.atkP = ctx.panel(L.hud, { x: 126, y: 76, w: 310, rows: 2, title: 'Attack in use' });
    S.logP = ctx.panel(L.hud, { x: 126, y: 334, w: 342, rows: 4, title: 'Login log', dark: true });
    S.sumP = ctx.panel(L.hud, { x: 482, y: 334, w: 234, rows: 4, title: 'What this stops' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    const gs = activeGates(cfg);
    const first = P.g[gs[0]];
    if (ctx.timer('user', dt, 3400))
      ctx.launch([P.u, first], 'ok', { label: 'ann', meta: { leg: 'gate', gi: 0, gs, who: 'user' }, speed: 250 });
    if (ctx.timer('atk', dt, 2100))
      ctx.launch([P.a, first], 'bad', { label: 'attacker', meta: { leg: 'gate', gi: 0, gs, who: 'atk' }, speed: 250 });
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    const push = (t, cls) => { S.log.unshift({ t, cls }); if (S.log.length > 4) S.log.length = 4; };

    if (m.leg === 'gate') {
      const gi = m.gs[m.gi];
      if (m.who === 'atk' && blocks(cfg, gi, cfg.attack)) {
        ctx.bump('blocked'); ctx.puff(P.g[gi], 'ok');
        ctx.float([P.g[gi][0], P.g[gi][1] - 26], 'blocked', 'ok');
        push('✗ attacker stopped at ' + gateName(cfg, gi), 'ok');
        return;
      }
      if (m.gi + 1 < m.gs.length) {
        ctx.launch([P.g[gi], P.g[m.gs[m.gi + 1]]], m.who === 'atk' ? 'bad' : 'ok',
          { label: m.who === 'atk' ? 'attacker' : 'ann', meta: { leg: 'gate', gi: m.gi + 1, gs: m.gs, who: m.who }, speed: 250 });
        return;
      }
      ctx.launch([P.g[gi], P.acct], m.who === 'atk' ? 'bad' : 'ok',
        { label: m.who === 'atk' ? 'attacker' : 'ann', meta: { leg: 'acct', who: m.who }, speed: 250 });
      return;
    }

    if (m.leg === 'acct') {
      if (m.who === 'atk') {
        ctx.bump('breach'); ctx.ring(P.acct);
        ctx.float([P.acct[0], P.acct[1] - 30], 'taken over', 'bad');
        push('⚠ attacker passed every gate', 'bad');
      } else {
        ctx.bump('ok'); ctx.puff(P.acct, 'ok');
        push('✓ ann passed ' + m_count(cfg) + ' factor(s)', 'ok');
      }
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;
    const gs = activeGates(cfg);

    S.gates.forEach((g, i) => {
      const on = gs.includes(i);
      g.g.setAttribute('opacity', on ? 1 : 0.22);
      g.pill.set([on ? gateName(cfg, i) : '(not used)']);
      g.pill.tone(on ? (blocks(cfg, i, cfg.attack) ? 'ok' : i === 0 ? '' : 'hot') : 'dead');
    });

    S.aPill.set(['Attacker', ATTACK_SHORT[cfg.attack]]);
    S.aPill.tone('hot');
    const breached = (ctx.stats.breach || 0) > 0;
    S.acctPill.set(['Account', breached ? 'taken' : 'safe']);
    S.acctPill.tone(breached ? 'hot' : 'ok');

    S.setP.set(0, cfg.factors === 'passkey' ? 'idle' : 'ok', cfg.factors === 'passkey' ? 'not used' : 'in use');
    S.setP.set(1, cfg.factors === 'pass' ? 'idle' : 'ok', cfg.factors === 'pass' ? 'none' : cfg.factors === 'sms' ? 'phone number' : cfg.factors === 'totp' ? 'TOTP app' : 'device');
    S.setP.set(2, cfg.factors === 'passkey' ? 'ok' : 'idle', cfg.factors === 'passkey' ? 'fingerprint' : 'none');

    S.atkP.set(0, ATTACKS[cfg.attack], 'bad');
    S.atkP.set(1, cfg.attack === 'stuffing' ? 'Already holds a valid password'
      : cfg.attack === 'simswap' ? 'Receives every SMS sent to the victim'
      : 'Relays the typed code to the real site', 'dim');

    const rows = [
      ['Leaked passwords', cfg.factors !== 'pass'],
      ['SIM swap', cfg.factors === 'totp' || cfg.factors === 'passkey'],
      ['Live phishing', cfg.factors === 'passkey']
    ];
    rows.forEach((r, i) => S.sumP.set(i, (r[1] ? '✓ stops   ' : '✗ misses  ') + r[0], r[1] ? 'ok' : 'bad'));
    S.sumP.set(3, FACTOR_NAME[cfg.factors], 'dim');

    for (let i = 0; i < 4; i++) {
      const r = S.log[i];
      S.logP.set(i, r ? r.t : (i === 0 ? '— waiting for a login —' : ''), r ? (r.cls === 'bad' ? 'term-bad' : 'term') : 'term dim');
    }
  }
});

function m_count(cfg) { return cfg.factors === 'pass' ? 1 : cfg.factors === 'passkey' ? 1 : 2; }
})();
