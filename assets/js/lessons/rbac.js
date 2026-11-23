/* ============================================================
   Lesson 3.3 — Authorization with RBAC
   direct grants -> roles -> privilege creep -> ownership checks
   ============================================================ */
(function () {
const USERS = [
  { id: 'ann', p: [-2.5, 2.5], team: 'Sales', roles: ['sales'] },
  { id: 'bob', p: [-1.2, 3.8], team: 'Sales (moved from Finance)', roles: ['sales', 'finance'], old: 'finance' },
  { id: 'cat', p: [0.05, 5.05], team: 'Admin', roles: ['admin'] }
];
const POLICY = [1.6, 1.0];
const RES = [
  { p: [2.8, -2.8], name: 'Invoices', pal: 'blue' },
  { p: [4.05, -1.55], name: 'Payroll', pal: 'sand' },
  { p: [5.3, -0.3], name: 'Settings', pal: 'rose' }
];
const ROLE = {
  sales: ['invoice:read', 'invoice:write'],
  finance: ['invoice:read', 'payroll:read'],
  admin: ['invoice:read', 'payroll:read', 'settings:admin']
};
const DIRECT = {
  ann: ['invoice:read', 'invoice:write'],
  bob: ['invoice:read', 'invoice:write', 'payroll:read'],   // left over from the Finance days
  cat: ['invoice:read', 'payroll:read', 'settings:admin']
};
/* requests cycled in order, covering every case the lesson explains: [who asks, permission, record owner when cross-owner mode is on] */
const CYCLE = [
  ['ann', 'invoice:read', null],
  ['bob', 'payroll:read', null],
  ['ann', 'invoice:read', 'bob'],
  ['cat', 'settings:admin', null],
  ['bob', 'invoice:write', null],
  ['ann', 'settings:admin', null],
  ['bob', 'invoice:read', 'ann'],
  ['cat', 'payroll:read', null]
];
const PERM_RES = { 'invoice:read': 0, 'invoice:write': 0, 'payroll:read': 1, 'settings:admin': 2 };
const SHORT = { 'invoice:read': 'invoice:r', 'invoice:write': 'invoice:w', 'payroll:read': 'payroll:r', 'settings:admin': 'settings' };

function permsOf(cfg, u) {
  if (cfg.mode === 'direct') return DIRECT[u.id];
  const roles = cfg.creep ? u.roles : u.roles.filter(r => r !== u.old);
  const out = [];
  roles.forEach(r => ROLE[r].forEach(p => { if (!out.includes(p)) out.push(p); }));
  return out;
}
function decide(cfg, u, req) {
  const P = permsOf(cfg, u);
  if (!P.includes(req.perm)) return { allow: false, why: 'no ' + SHORT[req.perm] + ' permission' };
  if (req.owner && req.owner !== u.id && cfg.ownership) return { allow: false, why: 'not the owner of this record' };
  return { allow: true, why: 'has ' + SHORT[req.perm] + ' permission' };
}

function tableLines(cfg) {
  if (cfg.mode === 'direct') {
    return [
      ['Granted straight to each user, no roles', 'dim'],
      ['ann  → invoice:read, invoice:write', 'mono'],
      ['bob  → invoice:read, invoice:write, payroll:read', 'bad mono'],
      ['cat  → invoice:read, payroll:read, settings:admin', 'mono'],
      ['A new hire means copying every line by hand', 'dim']
    ];
  }
  const b = cfg.creep ? 'Sales+Finance' : 'Sales';
  return [
    ['USER    ROLE            PERMISSIONS GRANTED', 'dim'],
    ['ann     Sales           invoice:read / write', 'mono'],
    ['bob     ' + (b + '                ').slice(0, 16) + (cfg.creep ? 'invoice r/w + payroll:r' : 'invoice:read / write'), cfg.creep ? 'bad mono' : 'mono'],
    ['cat     Admin           inv:r, payroll:r, settings', 'mono'],
    [cfg.ownership ? 'Every request is checked for ownership' : 'Nothing checks who owns the record',
      cfg.ownership ? 'ok' : 'bad']
  ];
}

ICS.register({
  id: 'rbac',
  title: 'Role-Based Access Control',
  sub: 'Authentication established who you are. Authorization answers the next question: now that I know who you are, what access do you get, and to which records?',
  minutes: 13,
  level: 'Intermediate',

  legend: [
    ['req sq', 'Request from a user'],
    ['res', 'Allowed'],
    ['bad', 'Denied or over-privileged'],
    ['hollow', 'Ownership check']
  ],

  metrics: [
    { key: 'allow', label: 'Allowed' },
    { key: 'deny', label: 'Denied', tone: c => (c.stats.deny || 0) > 0 ? 'lit' : '' },
    { key: 'over', label: 'Beyond the job', bad: true, tone: c => (c.stats.over || 0) > 0 ? 'warn' : '' },
    { key: 'idor', label: 'Read someone else', bad: true, tone: c => (c.stats.idor || 0) > 0 ? 'warn' : '' },
    { key: 'np', label: 'Permissions bob holds', fmt: c => permsOf(c.cfg, USERS[1]).length + '', tone: c => permsOf(c.cfg, USERS[1]).length > 2 ? 'warn' : 'lit' }
  ],

  learn: [
    ['Direct grants do not scale and cannot be audited', 0],
    ['A role collects permissions in one place', 1],
    ['Changing team without losing the old role piles them up', 2],
    ['Read permission does not mean read everyone', 4],
    ['Check ownership on every single request', 5]
  ],

  steps: [
    {
      tag: 'problem', label: 'Direct grants', title: 'Permissions written straight onto each user',
      body: [
        'The easiest thing to do while a system is small is to write down what each person may do. With ten users it is fine. With five hundred users and thirty kinds of permission the table becomes something nobody dares to touch.',
        'Look at the row for <code>bob</code>. He used to work in Finance and moved to Sales, and the <code>payroll:read</code> permission came with him. Nobody remembers granting it, and he can still open the payroll report for the whole company.'
      ],
      note: ['The real problem', 'Nothing here is technically wrong. The problem is that it cannot answer "who can reach payroll?" in any reasonable time, and that is the question an auditor asks every year.'],
      changed: ['Model: direct grants', 'bob: 1 leftover permission'],
      cfg: { mode: 'direct', creep: true, ownership: false, cross: false }
    },
    {
      tag: 'technique', label: 'Roles', title: 'Lift the permissions up into roles',
      body: [
        'Instead of tying permissions to people, tie them to a <code>role</code> and then put people into roles. bob is now only in the Sales role, and the leftover permission disappears on its own because it was never attached to him in the first place.',
        'The real gain shows when something has to change. Decide that Sales should no longer delete invoices and you edit one role, which takes effect for everyone at once, instead of working through accounts one by one.'
      ],
      note: ['Name roles after the job', 'A role name should describe the work, not the system it reaches. A role called "Sales" explains itself; a role called "db-rw" becomes a dumping ground for permissions within two years.'],
      changed: ['Model: roles (RBAC)', 'bob: Sales only'],
      cfg: { mode: 'roles', creep: false, ownership: false, cross: false }
    },
    {
      tag: 'problem', label: 'Privilege creep', title: 'Changing team without giving up the old role',
      body: [
        'In reality, when bob changed team he had to finish handing over his old work for two more months, so his Finance role was left in place for the time being. Those two months passed and nobody came back to remove it.',
        'This happens on every transfer and it accumulates. A ten-year employee ends up with an account that reaches almost everything, which nobody ever decided to allow. The name for it is privilege creep.'
      ],
      note: ['Why it matters', 'The concern is not that bob would misuse it. It is that if his account is taken over, the attacker inherits everything it has collected. The damage is proportional to what the account holds.'],
      changed: ['bob: still holds the Finance role'],
      cfg: { mode: 'roles', creep: true, ownership: false, cross: false }
    },
    {
      tag: 'technique', label: 'Least privilege', title: 'Remove old roles and review on a schedule',
      body: [
        'The fix is not a new technology, it is a process. Tie role removal to the transfer in the HR system, give temporary grants an expiry date, and review every permission on a fixed cycle.',
        'bob is back to what his current job needs. The principle is called least privilege: grant only what is needed, and only for as long as it is needed.'
      ],
      note: ['Grant with an expiry', 'A permission requested for a short task should expire by itself. Relying on a human to remember to come back and remove it is an approach that fails every time over a long enough period.'],
      changed: ['Removed bob\'s Finance role'],
      cfg: { mode: 'roles', creep: false, ownership: false, cross: false }
    },
    {
      tag: 'attack', label: 'IDOR', title: 'Read permission does not mean read everyone',
      body: [
        'ann holds <code>invoice:read</code> entirely legitimately. What she is asking for now is <code>invoice#bob</code>, an invoice belonging to one of bob\'s customers. The system checks only "may this person read invoices?", the answer is yes, and it hands the record over.',
        'This is IDOR, an insecure direct object reference. The attacker changes a number in the URL from 88 to 89 and walks through other people\'s documents, without breaking anything at all.'
      ],
      note: ['Three questions, not two', 'Authentication asks who you are. Authorization asks what you may do. The third question is the one most often forgotten: which record may you do it to?'],
      changed: ['Users start asking for other people\'s records'],
      cfg: { mode: 'roles', creep: false, ownership: false, cross: true }
    },
    {
      tag: 'technique', label: 'Ownership', title: 'Check ownership on every request',
      body: [
        'Add one more condition after the permission check has passed: is the requested record owned by the requester, or inside the scope they are responsible for? Cross-owner requests are now refused at the decision point.',
        'The crucial part is that this check lives on the server, always. Hiding a button or a link in the interface is not access control, because anyone can send the request straight to the API.'
      ],
      note: ['Check in one place, not everywhere', 'If this condition has to be written again in every endpoint, one day somebody will forget. Move it into the middleware or the data access layer so the safe behaviour is the default.'],
      changed: ['Ownership checking enabled'],
      cfg: { mode: 'roles', creep: false, ownership: true, cross: true }
    },
    {
      tag: 'lab', label: 'Try it', title: 'Try it: watch what bob is allowed to do',
      body: [
        'Turn privilege creep on with ownership checking off, and count how many requests get through that should not have. Then turn ownership checking on while leaving the creep in place, to see that the two settings solve genuinely different problems.',
        'Close with the questions that work on any system at all. Who can read this data? Who can change it? What can stop it serving anyone? And does everyone who holds access today still actually need it?'
      ],
      note: ['Where RBAC goes next', 'When the conditions get more complicated, involving department and time and location together, ABAC decides from a set of attributes, and ReBAC decides from the relationship between the user and that particular object.'],
      changed: [],
      cfg: { mode: 'roles', creep: true, ownership: false, cross: true },
      controls: ['mode', 'creep', 'ownership', 'cross']
    }
  ],

  controls: {
    mode: {
      type: 'seg', label: 'How permissions are managed',
      options: [['direct', 'Direct to user'], ['roles', 'Roles (RBAC)']],
      get: c => c.mode, set: (c, v) => { c.mode = v; }, reset: true
    },
    creep: { type: 'toggle', label: 'bob still holds the Finance role', hint: 'privilege creep after a transfer', get: c => c.creep, set: (c, v) => { c.creep = v; } },
    ownership: { type: 'toggle', label: 'Check ownership', hint: 'stops IDOR', get: c => c.ownership, set: (c, v) => { c.ownership = v; } },
    cross: { type: 'toggle', label: 'Users ask for other people\'s records', hint: 'changing the number in the URL', get: c => c.cross, set: (c, v) => { c.cross = v; } }
  },

  /* ---------------- scene ---------------- */
  init(ctx) {
    const iso = ctx.iso;
    ctx.S = {
      log: [], last: null,
      P: {
        u: USERS.map(u => iso(u.p[0], u.p[1], 0.75)),
        pol: iso(POLICY[0], POLICY[1], 1.0),
        r: RES.map(r => iso(r.p[0] - 0.7, r.p[1], 0.75))
      }
    };
  },

  build(ctx) {
    const S = ctx.S, iso = ctx.iso, Ac = ctx.actor, L = ctx.L;

    USERS.forEach(u => ctx.line(iso(u.p[0], u.p[1], 0.2), iso(POLICY[0], POLICY[1], 0.2), 'wire', L.wires));
    RES.forEach(r => ctx.line(iso(POLICY[0], POLICY[1], 0.2), iso(r.p[0], r.p[1], 0.2), 'wire', L.wires));

    const items = [];
    USERS.forEach((u, i) => items.push({
      k: u.p[0] + u.p[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        Ac.desk(g, u.p[0], u.p[1], i === 2 ? 'violet' : 'orange', 1.05);
        const pp = iso(u.p[0], u.p[1], 0.2);
        S['uP' + i] = ctx.pill(L.labels, pp[0] - 34, pp[1] + 2, [u.id, ''], 'end');
      }
    }));
    RES.forEach((r, i) => items.push({
      k: r.p[0] + r.p[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        Ac.box(g, r.p[0], r.p[1], { w: 1.15, h: 0.62, pal: r.pal, glyph: (p, c) => ctx.glyph.db(p, c) });
        const pp = iso(r.p[0] + 0.85, r.p[1], 0.2);
        S['rP' + i] = ctx.pill(L.labels, pp[0] + 14, pp[1] + 2, [r.name], 'start');
      }
    }));
    items.push({
      k: POLICY[0] + POLICY[1], draw: () => {
        const g = ctx.el('g', {}, L.ents);
        const b = Ac.box(g, POLICY[0], POLICY[1], { w: 1.45, h: 0.78, pal: 'green' });
        S.own = ctx.el('g', {}, g);
        ctx.glyph.lock(S.own, iso(POLICY[0], POLICY[1], b.box.zt));
        S.polPill = ctx.pill(L.labels, iso(POLICY[0], POLICY[1] + 1.2, 0)[0], iso(POLICY[0], POLICY[1] + 1.2, 0)[1] + 14, ['Policy engine', '']);
      }
    });
    items.sort((a, b) => a.k - b.k).forEach(it => it.draw());

    S.tableP = ctx.panel(ctx.L.hud, { x: 126, y: 268, w: 348, rows: 5, lh: 15, title: 'Who gets what' });
    S.logP = ctx.panel(ctx.L.hud, { x: 486, y: 268, w: 230, rows: 5, lh: 15, title: 'Recent decisions', dark: true });
    S.reqP = ctx.panel(ctx.L.hud, { x: 126, y: 392, w: 590, rows: 2, title: 'Request being decided' });
  },

  tick(ctx, dt) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P;
    if (!ctx.timer('req', dt, 1500)) return;
    const plan = CYCLE[(S.n = (S.n || 0) + 1) % CYCLE.length];
    const ui = USERS.findIndex(x => x.id === plan[0]);
    const u = USERS[ui];
    const perm = plan[1];
    let owner = null;
    if (perm.indexOf('invoice') === 0) owner = (cfg.cross && plan[2]) ? plan[2] : u.id;
    const label = SHORT[perm] + (owner && owner !== u.id ? ' #' + owner : '');
    ctx.launch([P.u[ui], P.pol], 'plain', { label, meta: { leg: 'pol', ui, perm, owner, label }, speed: 250 });
  },

  arrive(ctx, p) {
    const cfg = ctx.cfg, S = ctx.S, P = S.P, m = p.meta;
    const push = (t, cls) => { S.log.unshift({ t, cls }); if (S.log.length > 5) S.log.length = 5; };

    if (m.leg === 'pol') {
      const u = USERS[m.ui];
      const d = decide(cfg, u, m);
      S.last = { u: u.id, label: m.label, d, perm: m.perm, owner: m.owner };
      if (!d.allow) {
        ctx.bump('deny'); ctx.puff(P.pol, 'ok');
        push('✗ ' + u.id + ' → ' + m.label, 'ok');
        return;
      }
      const over = m.perm === 'payroll:read' && u.id === 'bob';
      const idor = m.owner && m.owner !== u.id;
      ctx.launch([P.pol, P.r[PERM_RES[m.perm]]], (over || idor) ? 'bad' : 'ok',
        { label: m.label, meta: { leg: 'res', ri: PERM_RES[m.perm], over, idor, uid: u.id }, speed: 260 });
      push('✓ ' + u.id + ' → ' + m.label, (over || idor) ? 'bad' : 'ok');
      return;
    }

    if (m.leg === 'res') {
      ctx.bump('allow');
      const top = [P.r[m.ri][0], P.r[m.ri][1] - 26];
      if (m.idor) { ctx.bump('idor'); ctx.ring(P.r[m.ri]); ctx.float(top, 'not theirs', 'bad'); }
      else if (m.over) { ctx.bump('over'); ctx.ring(P.r[m.ri]); ctx.float(top, 'beyond job', 'bad'); }
    }
  },

  render(ctx) {
    const cfg = ctx.cfg, S = ctx.S;

    USERS.forEach((u, i) => {
      const n = permsOf(cfg, u).length;
      const creepy = u.id === 'bob' && n > 2;
      S['uP' + i].set([u.id, String(n)]);
      S['uP' + i].tone(creepy ? 'hot' : '');
    });
    RES.forEach((r, i) => S['rP' + i].set([r.name]));

    S.own.setAttribute('opacity', cfg.ownership ? 1 : 0.18);
    S.polPill.set(['Policy engine', cfg.mode === 'direct' ? 'per-user list' : cfg.ownership ? 'roles + owner' : 'roles only']);
    S.polPill.tone(cfg.ownership ? 'ok' : cfg.mode === 'direct' ? 'hot' : '');

    tableLines(cfg).forEach((l, i) => S.tableP.set(i, l[0], l[1]));

    const L = S.last;
    if (!L) {
      S.reqP.set(0, 'Waiting for the first request…', 'dim'); S.reqP.set(1, '', '');
    } else {
      S.reqP.set(0, L.u + '  asks for  ' + L.label + (L.owner && L.owner !== L.u ? '   (record owned by ' + L.owner + ')' : ''),
        L.d.allow ? 'mono' : 'bad mono');
      S.reqP.set(1, (L.d.allow ? 'allow · ' : 'deny · ') + L.d.why +
        (L.d.allow && L.owner && L.owner !== L.u ? '   <- ownership never checked' : ''),
        L.d.allow ? (L.owner && L.owner !== L.u ? 'bad' : 'ok') : 'ok');
    }

    for (let i = 0; i < 5; i++) {
      const r = S.log[i];
      S.logP.set(i, r ? r.t : (i === 0 ? '— waiting —' : ''), r ? (r.cls === 'bad' ? 'term-bad' : 'term') : 'term dim');
    }
  }
});
})();
