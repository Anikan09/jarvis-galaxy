# FAQ

## Making it yours

### How do I change the colours and the look?
Everything visual lives in `viewer/`, with no build step: edit, save, reload the page (Ctrl+F5).

- **The HUD's colours** are the variables at the top of `viewer/style.css`:
  ```css
  :root {
    --bg: #02070d;      /* background */
    --cyan: #5ee7ff;    /* the main accent: headings, buttons, the gauge */
    --orange: #ffb36b;  /* warnings */
    --ok: #3dffa8;      /* all-good */
    --text: #e8f6ff;  --body: #bcd6e2;  --muted: #7fa6b8;
    --panel: rgba(8, 22, 34, .78);  --border: rgba(94, 231, 255, .22);
  }
  ```
  Change `--cyan` alone and the whole HUD changes accent.
- **The galaxy's star colours** (one per notes folder) are the `COLORS` list near the top of the galaxy section in `viewer/app.js`.
- **Fonts**: `--mono` and `--sans` in the same `:root` block. The page's security policy only loads files from Jarvis itself, so use fonts installed on Windows (Consolas, Segoe UI, Cascadia Mono...).
- **Layout**: `viewer/index.html` (what's there) and `viewer/style.css` (where it sits).

### Can I rename it, or have it call me something other than "sir"?
Yes, in `config.json`:
```json
"assistant_name": "Friday",
"address_user_as": "boss"
```
The name appears in the HUD, the login page, notifications and the persona.

### Can it have a different personality?
The persona is the `persona()` function in `core/brain.py`: a few lines of plain English (dry, polite, British, a light wit). Rewrite them however you like. Keep the rules about plain text and never inventing facts; the rest is yours.

### How do I change the voice?
Set `"voice"` in `config.json` to the start of a voice name your browser has, e.g. `"Google UK English Male"` in Chrome or `"Microsoft Ryan"` in Edge (Edge's online voices sound the most natural). The voice and the microphone follow `"language"`; override with `"voice_locale"`, e.g. `"en-US"`. See [configuration](configuration.md).

### Can it answer in another language?
Set `"language"` in `config.json`, e.g. `"German"`. Replies, the voice and the microphone all follow it.

### Can I use my existing Obsidian vault?
Yes: point `"notes_folder"` in `config.json` at the vault's folder. Every `.md` file becomes a star, and `[[links]]` become the lines between them. "Remember that…" writes new notes into a `captures/` folder inside it.

## Using it

### What does it cost?
Jarvis itself is free (MIT). Its answers run on **your own Claude account** through the Claude Code CLI, so they count towards your Claude plan. Private mode runs on your PC and costs nothing.

### Does my data leave my PC?
Only when a feature needs it, and each one says exactly what, in its docs. Your questions and the relevant notes go to Claude to be answered; private mode keeps even that on the PC. Everything Jarvis stores (the lock, activity, reminders, keys) is encrypted with your Windows login. Details in [security](security.md).

### Can I use it without Claude?
Partly. With the [private brain](private-brain.md) (Ollama) and private mode on, questions about your notes are answered on your PC. Web research and the live-web parts of the modules need Claude.

### Mac or Linux?
Not in version 1. The vault (DPAPI), the voice and the security checks rely on Windows. The core is mostly portable Python, so it's a possible future step.

### Can I use it from my phone?
Only for alerts, deliberately: the [phone module](modules/phone.md) pushes "something happened" to your phone, and Jarvis itself stays reachable from your PC only. That page explains the risks of going further.

### How do I update?
```powershell
git pull
```
Your settings, notes and `data/` aren't part of the repository, so an update never touches them. Then restart the server.

### How do I uninstall?
Stop the server and delete the folder. If your notes folder is elsewhere, it stays. Remove the "Jarvis Galaxy" entry from your authenticator app.

## Trouble

### I forgot my password and lost my recovery codes.
Delete `data/auth.json` and run `python setup.py` again. Only someone who can already open the project folder can do that, which is why it's allowed.

### More problems?
See the troubleshooting table in [setup](setup.md#troubleshooting). Still stuck? Open an issue, using the template, and never paste your `config.json`, anything from `data/`, or personal details. For a security problem, use [private reporting](../SECURITY.md) instead.

## Extending it

### Can I add my own feature?
Yes, as a module. A module is a folder in `modules/` that can claim requests (`route(text)`), add endpoints behind the lock, run in the background, and send alerts. `modules/__init__.py` documents the interface; `modules/osint/` is a small, readable example. Add your module's name to `KNOWN` in `modules/__init__.py` and switch it on in `config.json`. Keep its docs page honest about what it sends off the PC.
