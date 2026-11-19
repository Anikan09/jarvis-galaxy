# Security design

Jarvis holds your notes and talks to an AI on your behalf, so it's built like something worth breaking into.

## The lock

- **Password + authenticator code** (TOTP, RFC 6238) before anything works, the HUD's own files included. Only the login page is open.
- The password is stored only as a salted **scrypt** hash. Each 6-digit code works **once** (replays are refused).
- **8 one-time recovery codes** for a lost phone, stored hashed.
- **Lockout**: after 5 wrong attempts the door shuts for 30 seconds, doubling each time up to 15 minutes. A wrong password
  and a wrong code count the same, so a guess reveals nothing.
- **Sessions** live in memory only: a restart logs everyone out. They end after 30 idle minutes (background refreshes
  don't count as activity) and after 12 hours regardless. "Lock Jarvis" ends one at once.
- **Cookie**: HttpOnly (scripts can't read it) and SameSite=Strict (other sites can't send it).
- **Fails closed**: without a lock set up, nothing is served but a "set up first" page.

## The server

- Listens on **127.0.0.1 only**. Nothing on your network, let alone the internet, can reach it.
- Every request must be addressed to `localhost:<port>` by name (stops DNS-rebinding tricks) and, for anything that
  changes something, come from Jarvis's own page (Origin check).
- **Content-Security-Policy**: only Jarvis's own scripts and two pinned libraries run; no inline scripts, no frames.
- The two 3D libraries load from jsdelivr with **Subresource Integrity** hashes: a tampered file is refused by the browser.
- Errors never echo internals; the console doesn't log request paths.

## At rest

- Everything in `data/` (the lock, activity, reminders, secrets) is encrypted with **Windows DPAPI**: only your Windows
  login can read it. Copied to another PC or account, it's ciphertext.
- Recommended: keep the whole project on an encrypted drive (BitLocker or VeraCrypt), so the notes are covered too.

## The brain

- Claude Code runs with **no tools** unless a feature needs one (web research uses search only: no page fetching,
  files or shell), no MCP servers, none of your Claude Code settings or hooks, and no saved session, in a neutral folder.
- The prompt goes in on stdin, never on the command line. API keys in the environment are dropped.
- Notes, search results and web pages are treated as **data, never instructions**: every prompt says so.
- **Private mode** keeps everything on the PC and declines what can't be done locally.

## Modes never lower the limits

Expert and lab mode change the style (technical, exact commands) and, in lab mode, allow full walkthroughs for the
`lab_targets` you list. They switch themselves off after a while, on Lock, and on restart.

## What this can't protect against

Malware already running as you can read whatever you can, including the decrypted data while Jarvis runs. Keep
Windows and Defender up to date, and don't run things you don't trust. The lock protects Jarvis from other people and
other programs reaching it; it can't make an already-compromised PC safe.

## Reporting a vulnerability

Please don't open a public issue. See [SECURITY.md](../SECURITY.md).
