# Setup

Jarvis Galaxy v1 runs on **Windows 10/11**.

## 1. What you need

- **Python 3.11 or newer**: [python.org/downloads](https://www.python.org/downloads/). Tick "Add python.exe to PATH" in the installer.
- **Claude Code**, logged in to your own Claude account: install it ([docs.claude.com/claude-code](https://docs.claude.com/en/docs/claude-code)), then run `claude` once in a terminal and log in. Jarvis's answers run on that account; nothing is shared.
- **An authenticator app** on your phone: Microsoft Authenticator, Google Authenticator, 2FAS, Aegis...
- **Chrome or Edge**, for the voice input.

## 2. Install

```powershell
git clone https://github.com/<you>/jarvis-galaxy
cd jarvis-galaxy
python setup.py
```

Tip: `pip install qrcode` first, and setup shows a QR code to scan instead of a 32-character key to type.

`setup.py` checks the requirements, creates `config.json` and your notes folder, and sets up the lock: a password
(at least 12 characters) and your authenticator app. Write down the recovery codes it shows, somewhere that isn't this PC.
Run it in PowerShell or Windows Terminal: the password prompt hides what you type there.

## 3. Run

```powershell
python -m core.server
```

Open <http://localhost:4747/>, unlock with your password and the 6-digit code, and ask away.

Want a look around first? `python -m core.server --demo` runs Jarvis on the notes of a made-up coffee roaster. Before
you've set up the lock, the demo runs unlocked (it's fake data, on this PC only); after that it uses your lock too.

## 4. Your notes

Every `.md` file in your notes folder (`notes/` by default, or `notes_folder` in `config.json`) becomes a star.
Link notes with `[[double brackets]]`. The folder works as an [Obsidian](https://obsidian.md) vault, if you use Obsidian.

Things to try:

- "What do my notes say about …?"
- "Remember that the dentist moved to Friday"
- "Research the best standing desks"
- "Remind me in 20 minutes to check the oven"
- "Expert mode on" / "normal mode"
- "Answer this offline: …" (needs the [private brain](private-brain.md))
- "Lock Jarvis"

## Troubleshooting

| Symptom | Fix |
|---|---|
| "The claude command wasn't found" | Install Claude Code and open a new terminal, so the PATH updates. |
| "Claude Code error: … log in" | Run `claude` in a terminal and use `/login`. |
| The app says "illegal character" | Type the key without spaces. It only uses A–Z and 2–7: a 0 is the letter O, a 1 is I, an 8 is B. Or `pip install qrcode` and run setup again to scan a QR code. |
| Codes from the app never match | Delete the entry in the app, run `python -m core.auth --reset` (or delete `data/auth.json` and run setup again), and check the phone's clock is set automatically. |
| Forgot the password and lost the recovery codes | Delete `data/auth.json` and run `python setup.py`. Only someone who can already open the project folder can do that. |
| The galaxy doesn't appear | The 3D libraries load from cdn.jsdelivr.net with a pinned hash: check the internet connection. |
| Port 4747 is taken | Set `"port"` in `config.json`. |
