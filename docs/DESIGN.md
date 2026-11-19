# Jarvis Galaxy — design

> **I built my own Jarvis — and locked it down like a vault.**
> A voice-driven personal AI butler for Windows, with a 3D galaxy of your notes as its brain and security designed in from the first line.

Status: design, before any code. This repo stays **private** until the release checklist at the bottom is done.

---

## 1. What this is, and what it isn't

**It is** an open-source template people can run on their own Windows PC: a local web HUD with a 3D knowledge galaxy, a butler that answers by voice, and an optional security toolkit, all behind a password + 2FA lock.

**It isn't** a copy of anyone's personal assistant. This project is written fresh, feature by feature, with nothing carried over that belongs to a real person: no notes, no history, no settings, no names, no paths.

**The brain** is the [Claude Code](https://claude.com/claude-code) CLI on the user's own Claude account. Every user needs their own; the project never ships, proxies or shares a key.

**Not affiliated with Marvel.** "Jarvis" is used as a generic word for a butler AI. No Marvel names beyond that, no logos, no images.

---

## 2. Principles

1. **Security first, visibly.** Locked by default (password + authenticator code). Secrets encrypted at rest. Nothing listens beyond `127.0.0.1` unless the user deliberately turns a module on.
2. **Off by default.** The core works on its own; every module is opt-in in `config.json`, with what it reads, sends and stores written next to its switch.
3. **Say what leaves the PC.** Every feature documents exactly what goes to which outside service. Private mode keeps everything on the machine.
4. **Hard limits in code, not just in prompts.** Only the user's own devices, sites and lab targets; nothing that pays, deletes, enters passwords or sends unseen; anything leaving the PC waits for an explicit button press.
5. **Demo mode is first-class.** `--demo` runs everything on a fictional company's data, so screenshots and first impressions need no real accounts.
6. **Honest about limits.** Each tool's docs say what it can't catch.
7. **Windows only, for v1.** Said plainly in the README. Other platforms are a later question.

---

## 3. Architecture

```
 Browser (viewer/)                    Local server (127.0.0.1:4747)                 Outside world
 ┌─────────────────────┐   HTTP      ┌──────────────────────────────┐
 │ HUD + 3D galaxy     │ ──────────► │ core/server: routes, lock,   │ ──► Claude Code CLI (the brain)
 │ voice in/out        │  (session   │ sessions, Do-It gate         │ ──► Ollama on 127.0.0.1 (private mode)
 │ drawers, Do-It gate │   cookie)   │ core/: notes, vault, auth... │
 └─────────────────────┘             │ modules/: opt-in features ───┼──► only what each module documents
                                     └──────────────────────────────┘     (Google, OSINT registries, HIBP prefix...)
```

- One process, standard-library Python where possible; optional extras per module.
- The browser never sees secrets; it gets only what each view needs.
- Every brain call goes through one gateway, which applies private mode, expert mode and the language rule.

---

## 4. Folder layout

```
jarvis-galaxy/
├── core/                 the part everyone runs
│   ├── server.py         HTTP routes, the gate, the brain gateway
│   ├── auth.py           password + TOTP lock, sessions, recovery codes
│   ├── vault.py          DPAPI encryption for secrets and state
│   ├── notes.py          the notes index and galaxy builder
│   ├── modes.py          demo, expert/lab and private mode
│   └── ...
├── modules/              opt-in features, one folder each, each with its own README
│   ├── workspace/        Google Gmail + Calendar, Apple Calendar
│   ├── security/         score, alerts, tripwires, network, Wi-Fi, ports, phishing, breach, file check
│   ├── osint/            domain/IP recon, metadata check
│   ├── private_brain/    Ollama
│   └── phone/            phone access (levels 1-2, see section 8)
├── viewer/               the HUD (HTML/JS), no build step
├── demo/                 the fictional company: notes and fixtures
├── docs/                 setup, architecture, security, one page per module, this file
├── tests/                the self-checks (what "preflight" does today, as tests)
├── setup.py              first-run wizard
├── config.example.json   every setting, with comments in docs/configuration.md
└── LICENSE, README.md
```

---

## 5. What ships

### Core (always on)
| Feature | Notes |
|---|---|
| Knowledge galaxy | Notes folder (works as an Obsidian vault) shown as a 3D graph; answers cite the notes they used |
| Chat and voice | Typed or spoken; wake word optional; replies spoken aloud; 16 languages |
| "Remember that…" | Files a new note and links it into the galaxy |
| Web research | Live web via the brain, sources in a side drawer |
| Lock | Password + authenticator (TOTP), recovery codes, lockout, idle timeout, Lock button |
| Vault | Secrets and state encrypted with the Windows login (DPAPI) |
| Modes | Demo, expert/lab, private |
| Activity log, reminders | Grouped by day; reminders spoken or shown as a Windows notification |

### Modules (opt-in, off by default)
| Module | Contents | Leaves the PC |
|---|---|---|
| workspace | Gmail triage, morning briefing, calendar, drafts behind Do It | Google / Apple APIs |
| security | Security score + HUD gauge, alerts, tripwires, network devices, Wi-Fi, connections, open ports, PC check, phishing, breach, file check, website audit | Registry age lookups, HIBP hash prefix, optional malware-hash lookups |
| osint | WHOIS/RDAP, DNS, TLS, IP intel, file metadata check | Public registries, DNS |
| private_brain | Ollama for private mode and offline fallback | Nothing |
| phone | See section 8 | Push service (level 1) / Tailscale (level 2) |

### Not in v1
- **Take over (driving the PC)**: too risky to hand to strangers in a first release.
- **Teardown**: depends on an external reverse-engineering kit.
- **Legal module**: legal-advice liability.
- **Screen guide**, **Time Machine diary**: later, once the core is stable.

---

## 6. Setup flow

1. Install Python 3.12+ and the Claude Code CLI; log in to Claude Code once.
2. `git clone`, then `python setup.py`: checks the requirements, creates `config.json` from the example, runs the lock setup (password + authenticator), and asks which modules to enable.
3. `python -m core.server` (or `--demo` to look around first) and open `http://localhost:4747`.
4. Optional per module: `python -m modules.workspace.login`, `ollama pull ...`, and so on, each documented on its module page.

---

## 7. Security design (documented in docs/security.md)

- **Lock**: scrypt-hashed password, TOTP (RFC 6238) with replay protection, 8 one-time recovery codes, 5-try lockout that doubles, 30-minute idle timeout, sessions in memory only, HttpOnly + SameSite=Strict cookie, Host and Origin checks against DNS rebinding.
- **At rest**: secrets and state files encrypted with DPAPI; backups encrypted as a whole; recommended: the whole project on an encrypted drive (VeraCrypt or BitLocker).
- **Network**: binds to `127.0.0.1` only. Modules that reach out say where, and why.
- **Private mode**: nothing goes to the brain; anything that would need the internet is declined, not quietly sent.
- **Hard limits** (section 2.4) enforced in code, with tests.
- **What it can't protect against**: malware already running as the user can read what the user can. Said plainly.

---

## 8. Phone access (module, off by default)

| Level | What | Risk | Ships |
|---|---|---|---|
| 1. Alerts only | Security alerts and notices pushed to the phone; message text carries no details ("Jarvis: 1 security alert") | Low: the push service sees only that there was an alert | v1 |
| 2. Read-only dashboard | Score, alerts, devices, calendar over Tailscale, passkey login, nothing can be changed from the phone | Medium: Jarvis becomes reachable from the tailnet; the Tailscale account becomes a key; the encrypted drive must stay mounted | v1.x |
| 3. Full control | Chat, Do-It approvals, desktop control from the phone | High | Documented as not recommended; not built |

The docs page lists every risk (exposure beyond localhost, the Tailscale account, both login factors on one phone, the encrypted drive staying open, https certificates publishing the machine name) and how each level handles it.

---

## 9. Testing

- `tests/` runs offline by default (no accounts needed), the way preflight does today: routing patterns shared between server and viewer, the lock, the vault, every module's self-test, demo mode leaving real data untouched.
- Live tests run against a throwaway server with a throwaway lock, never the user's own.

---

## 10. Docs plan

- **README**: the headline, a demo GIF recorded in demo mode, the feature list, quick start, the security promise, the Claude-account note, the Marvel disclaimer.
- **docs/**: setup, configuration, architecture, security, one page per module, phone access and its risks, "How I built my own Jarvis" (the build story and what I learned).

---

## 11. Roadmap

1. **Design** (this file) and the private repo.
2. **Core**: server, lock, vault, notes galaxy, chat, voice, modes, setup wizard, tests.
3. **Modules**: security, osint, private_brain, workspace, phone level 1.
4. **Docs and demo GIF.**
5. **Release checklist**, then public.

---

## 12. Release checklist (before making the repo public)

- [ ] Every file written for this repo; nothing copied over from a personal install
- [ ] No personal data anywhere: names, e-mail addresses, Apple ID, user names in paths, site names, Wi-Fi names, device names
- [ ] Secret scan of the whole history (e.g. gitleaks) comes back clean
- [ ] Commits use the GitHub no-reply address only
- [ ] `config.example.json` holds placeholders only
- [ ] Demo data is fictional (Ember & Oak) and contains nothing real
- [ ] Third-party licences checked (three.js, 3d-force-graph: MIT)
- [ ] Every module off by default; each module page says what leaves the PC
- [ ] Tests pass on a clean machine
- [ ] README: headline, GIF, Claude-account note, Marvel disclaimer, MIT licence
- [ ] Issues: decide on or off, and a SECURITY.md saying how to report a vulnerability privately
