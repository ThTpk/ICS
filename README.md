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

Modules follow the course outline (slides `00 Course Outline`).

| # | Module | Lessons | Status |
|---|---|---|---|
| 01 | Information Systems | Information Systems | ✅ built |
| 02 | Security Principles | CIA Triad · MFA · RBAC | ⚠ built, Thai text |
| 03 | Computer Networking | Network Diagrams and Attacks | ⏳ |
| 04 | Firewall and Policy | Firewall and Traffic Filtering | ⚠ built, Thai text |
| 05 | Network Security Tools | Network Security Tools | ⏳ |
| 06 | Incident and Response | Incident Response | ⏳ |
| 07 | Web Technology Security | SQL Injection · XSS | ⚠ built, Thai text |
| 08 | Wireless LAN Security | Wireless LAN Security (802.11) | ⏳ |
| 09 | IT Risk Management | Threat, Vulnerability and Risk | ⚠ built, Thai text |
| 10 | Standards and Procedures | ISO/IEC 27001 and Procedures | ⏳ |
| 11 | Law and Compliance | Computer Law and PDPA | ⏳ |
| 12 | Business Continuity | Business Continuity and DR | ⏳ |
| A | Appendix: Cryptography | Symmetric · Asymmetric · Hashing · TLS | ⚠ built, Thai text |

**Lesson 01 — Information Systems** follows the `01 Information Systems` slides: the four TOGAF
architecture layers (Business, Application, Data, Technology), alignment between them, and why an
asset missing from the inventory cannot be defended. It answers the topic's guiding question —
*to look after the registration system, what should the administrator know about it?*

The cryptography lessons are not a topic in the course outline, so they were moved to an appendix
rather than deleted. They still support the TLS and web-security material.

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
