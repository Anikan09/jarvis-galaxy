# Jarvis Galaxy — design

> **I built my own Jarvis — and locked it down like a vault.**
> A voice-driven personal AI butler for Windows, with a 3D galaxy of your notes as its brain and security designed in from the first line.

Status: version 1 (core + the security, osint, workspace and phone modules). This file started as the plan; it now describes what was built, with the not-yet-built parts marked as such.

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
4. **Hard limits in code, not just in prompts.** Only the user's own devices, sites and lab targets. Version 1 never pays, deletes, enters passwords or sends anything on the user's behalf: the workspace module is read-only.
5. **Demo mode is first-class.** `--demo` runs everything on a fictional company's data, so screenshots and first impressions need no real accounts.
6. **Honest about limits.** Each tool's docs say what it can't catch.
7. **Windows only, for v1.** Said plainly in the README. Other platforms are a later question.

---

## 3. Architecture

```
 Browser (viewer/)                    Local server (127.0.0.1:4747)                 Outside world
 ┌─────────────────────┐   HTTP      ┌──────────────────────────────┐
 │ HUD + 3D galaxy     │ ──────────► │ core/server: routes, lock,   │ ──► Claude Code CLI (the brain)
 │ voice in/out        │  (session   │ sessions                     │ ──► Ollama on 127.0.0.1 (private mode)
 │ drawers             │   cookie)   │ core/: notes, vault, auth... │
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
│   ├── server.py         HTTP routes and the lock check
│   ├── brain.py          the brain gateway (Claude Code CLI)
│   ├── localbrain.py     the private brain (Ollama on this PC)
│   ├── auth.py           password + TOTP lock, sessions, recovery codes
│   ├── vault.py          DPAPI encryption for secrets and state
│   ├── notes.py          the notes index and galaxy builder
│   ├── modes.py          demo, expert/lab and private mode
│   └── ...
├── modules/              opt-in features, one folder each, each with its own page in docs/modules/
│   ├── workspace/        Google Gmail + Calendar, Apple Calendar
│   ├── security/         score, alerts, tripwires, network, Wi-Fi, ports, phishing, breach, file check
│   ├── osint/            domain/IP recon, metadata check
│   └── phone/            phone alerts (level 1, see section 8)
├── viewer/               the HUD (HTML/JS), no build step
├── demo/                 the fictional company: notes and fixtures
├── docs/                 setup, FAQ, configuration, security, private brain, one page per module, this file
├── tests/                the offline self-checks
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
| Chat and voice | Typed, or spoken with the MIC button; replies spoken aloud; reply language, voice and microphone set by `language` |
| "Remember that…" | Files a new note and links it into the galaxy |
| Web research | Live web via the brain, sources in a side drawer |
| Lock | Password + authenticator (TOTP), recovery codes, lockout, idle timeout, Lock button |
| Vault | Secrets and state encrypted with the Windows login (DPAPI) |
| Modes | Demo, expert/lab, private |
| Activity log, reminders | Grouped by day; reminders spoken or shown as a Windows notification |

### Modules (opt-in, off by default)
| Module | Contents | Leaves the PC |
|---|---|---|
| workspace | Gmail triage, morning briefing, calendar; read-only | Google / Apple APIs |
| security | Security score + HUD gauge, alerts, tripwires, network devices, Wi-Fi, connections, open ports, PC check, phishing, breach, file check, website audit | Registry age lookups, HIBP hash prefix, optional malware-hash lookups |
| osint | WHOIS/RDAP, DNS, TLS, IP intel, file metadata check | Public registries, DNS |
| phone | Content-free alerts to your phone, see section 8 | The push service (ntfy) |

The **private brain** (Ollama, for private mode and offline fallback) is part of the core, `core/localbrain.py`, switched on by having Ollama running: see `docs/private-brain.md`. Nothing leaves the PC.

### Not in v1
- **Take over (driving the PC)**: too risky to hand to strangers in a first release.
- **Teardown**: depends on an external reverse-engineering kit.
- **Legal module**: legal-advice liability.
- **Screen guide**, **Time Machine diary**, **wake word**, **encrypted backups**: later, once the core is stable.
- **Phone level 2** (read-only dashboard over Tailscale): v1.x at the earliest, see section 8.

---

## 6. Setup flow

1. Install Python 3.11+ and the Claude Code CLI; log in to Claude Code once.
2. `git clone`, then `python setup.py`: checks the requirements, creates `config.json` from the example and the notes folder, and runs the lock setup (password + authenticator, QR code with `pip install qrcode`). Modules are switched on afterwards in `config.json`.
3. `python -m core.server` (or `--demo` to look around first) and open `http://localhost:4747`.
4. Optional per module: `python -m modules.workspace.google client_secret.json`, `python -m modules.phone setup`, `ollama pull ...`, each documented on its page.

---

## 7. Security design (documented in docs/security.md)

- **Lock**: scrypt-hashed password, TOTP (RFC 6238) with replay protection, 8 one-time recovery codes, 5-try lockout that doubles, 30-minute idle timeout, sessions in memory only, HttpOnly + SameSite=Strict cookie, Host and Origin checks against DNS rebinding.
- **At rest**: secrets and state files encrypted with DPAPI; recommended: the whole project on an encrypted drive (VeraCrypt or BitLocker).
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
| 3. Full control | Chat and desktop control from the phone | High | Documented as not recommended; not built |

The docs page lists every risk (exposure beyond localhost, the Tailscale account, both login factors on one phone, the encrypted drive staying open, https certificates publishing the machine name) and how each level handles it.

---

## 9. Testing

- `python -m unittest discover -s tests` runs offline (no accounts needed): routing, the lock, the vault, every module against fakes, demo mode leaving real data untouched, and a privacy scan of the repo itself.
- Google, Apple and ntfy are tested against fakes; the live services aren't part of the suite.

---

## 10. Docs plan

- **README**: the headline, a demo GIF recorded in demo mode, the feature list, quick start, the security promise, the Claude-account note, the Marvel disclaimer.
- **docs/**: setup, FAQ, configuration, security, private brain, one page per module (the phone page lists the risks of each level).
- Later: "How I built my own Jarvis", the build story and what I learned.

---

## 11. Roadmap

1. **Design** (this file) and the private repo.
2. **Core**: server, lock, vault, notes galaxy, chat, voice, modes, setup wizard, tests.
3. **Modules**: security, osint, workspace, phone level 1; the private brain in the core.
4. **Docs and demo GIF.**
5. **Release checklist**, then public.

---

## 12. Release checklist (before making the repo public)

Run on 2026-11-19 against a fresh clone and the full git history.

- [x] Every file written for this repo; nothing copied over from a personal install
- [x] No personal data anywhere, in any commit (names, e-mail addresses, user names in paths, Wi-Fi and device names): scanned
- [x] No secret-looking strings in the history (API keys, tokens, private keys, app passwords): scanned with patterns
- [x] A dedicated secret scanner over the whole history: gitleaks, no leaks found
- [x] Commits use the GitHub no-reply address only
- [x] No config, key, database or data/ file was ever committed
- [x] `config.example.json` holds placeholders only; every module off by default
- [x] Demo data is fictional (Ember & Oak, example.com addresses); screenshots and the GIF carry no metadata
- [x] Third-party licences: three.js and 3d-force-graph, both MIT, credited in the README
- [x] Each module page says what leaves the PC
- [x] Tests pass on a fresh clone (57 offline tests); a fresh clone without a lock serves nothing but the set-up page
- [x] `python setup.py` tried on a fresh clone by a first-time user (2026-11-20): two problems found and fixed (the authenticator key, the voice language)
- [x] README: headline, demo GIF, Claude-account note, Marvel disclaimer, MIT licence
- [x] SECURITY.md: private vulnerability reporting
- [x] Issues on, with templates and an FAQ link
- [ ] After publishing: Settings → Advanced Security → turn on *Private vulnerability reporting*, *Secret scanning* and *Push protection*; protect `main` against force-pushes and deletion
- [ ] **Your call**: Settings → General → Change visibility → Public
