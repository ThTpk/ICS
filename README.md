# Information and Computer Security — interactive course

An interactive companion to **01076042 Information and Computer Security**
(ผศ.ดร. ธนัญชัย ตรีภาค · Faculty of Engineering, KMITL).

Every concept is explained with an animated isometric simulation the learner can drive:
packets really move, data really leaks, and every control can be switched off to see what it was holding up.

Static site — no backend, no build step, no external libraries.
Visual design follows `System-Design_LoadBalancing_v2.html`.

## Running it

```bash
node tools/serve.cjs
```

Then open `http://localhost:5173`. Opening `index.html` directly also works, since the page uses
no ES modules and no `fetch`.

## Course structure

The fourteen topics come from [`content/ICS-CONTENT.md`](content/ICS-CONTENT.md), which summarises
the course slides topic by topic and is the reference this structure is checked against.

| # | Topic | Lessons | Status |
|---|---|---|---|
| 01 | Introduction | Security Timeline, 1975 to now | ⏳ |
| 02 | IT Systems and Architecture | Information Systems | ✅ built |
| 03 | CIA / AAA / PDR ⭐ | CIA Triad · MFA · RBAC | ⚠ built, Thai text |
| 04 | Computer Networking | Networking and Network Diagrams | ⏳ |
| 05 | Network Attack | Network Attacks and Scanning | ⏳ |
| 06 | Firewall and Policy ⭐ | Firewall and Policy | ✅ built |
| 07 | Security Tools | Monitoring, IDS and IPS | ⏳ |
| 08 | Incident Response | Incident Response Playbook | ⏳ |
| 09 | Web Security ⭐ | SQL Injection · XSS | ⚠ built, Thai text |
| 10 | Wireless LAN Security | Wireless LAN Security (802.11) | ⏳ |
| 11 | IT Risk Management ⭐ | IT Risk Management | ✅ built |
| 12 | Standards and Frameworks | ISO 27001 and NIST CSF 2.0 | ⏳ |
| 13 | Law and Compliance | Thai IT Law and PDPA | ⏳ |
| 14 | Business Continuity ⭐ | Business Continuity Management | ✅ built |
| T | Toolbox: Cryptography | Symmetric · Asymmetric · Hashing · TLS | ⚠ built, Thai text |

⭐ marks the topics the content reference calls the core of the subject.

**Lesson 02 — Information Systems** follows the `01 Information Systems` slides: the four TOGAF
architecture layers (Business, Application, Data, Technology), alignment between them, and why an
asset missing from the inventory cannot be defended. It answers the topic's guiding question —
*to look after the registration system, what should the administrator know about it?*

Cryptography is not a topic of its own in this course. The four crypto lessons are kept as a
toolbox that topics 03, 09 and 10 draw on — Confidentiality and Integrity, Heartbleed and TLS,
and WPA2.

### Known gaps

- Nine lessons still carry Thai body text and are converted one at a time. Several of them have
  labels that collide once the simulation has been running a while; those are fixed as each lesson
  is rewritten, since the text changes anyway.
- `sqli.js` and `xss.js` should merge into a single **A03 Injection** card, since OWASP Top 10 2021
  folded XSS into Injection, and then grow into the full A01–A10 set.
- Next on the content reference list: the OWASP Top 10 2021 board, which also merges the SQL
  injection and XSS lessons into a single A03 Injection card, as the 2021 set does.

## Using the site

- **← →** change step, **Space** pause/play
- **Restart** resets the simulation, **1× / 2× / 0.5×** changes speed
- The last step of each lesson is a lab with free controls
- Progress is remembered in `localStorage`
- **Glossary** in the top bar covers the whole course

## Code layout

```
index.html              shell: top bar · contents · stage · step panel
assets/css/app.css      the whole design system
assets/js/core.js       engine: isometric projection, packets, steps, controls, router
assets/js/lessons/*.js  one file per lesson
tools/serve.cjs         static dev server
```

Each lesson registers itself through `ICS.register({...})`, telling the core:

- `steps[]` — the text of each step plus the `cfg` that seeds the simulation
- `metrics[]` — the readouts above the stage
- `controls{}` — lab controls (toggle / seg / range / text / buttons)
- `build(ctx)` draws the scene once · `tick(ctx, dt)` advances it · `arrive(ctx, p)` handles a packet
  reaching its destination · `render(ctx)` refreshes whatever changed

Adding a lesson means writing one file in `lessons/`, adding its `<script>` to `index.html`,
and putting its id into `CATALOG` in `core.js`.

### Testing hook

`core.js` can step the simulation without `requestAnimationFrame`, which is how the lessons are
checked (and is needed when the window is not painting):

```js
ICS.open('infosys'); ICS.go(3); ICS.step(32, 300); ICS.state()
```

## A note on the numbers

Figures in the cryptography and hashing lessons are **teaching models, not measurements**.
Guess rates, key-space sizes and crack times are set to the right order of magnitude so the
comparisons hold (bcrypt versus SHA-256, for example), not so the values can be quoted.

Ciphertext shown on screen does not come from real AES either. It comes from a small hash in the
lesson file that has the properties the teaching needs: same input gives the same output, a one
character change alters everything, and an IV makes repeats differ.
