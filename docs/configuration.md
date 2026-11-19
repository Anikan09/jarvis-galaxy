# Configuration

`config.json` (created by `python setup.py` from `config.example.json`) holds the settings you edit by hand. It's
re-read when it changes, so most settings apply without a restart. It never holds secrets: those live in `data/`,
encrypted (`python -m core.vault set <name>`).

| Setting | Default | What it does |
|---|---|---|
| `assistant_name` | `"Jarvis"` | The name in the HUD, the login page and the persona. |
| `address_user_as` | `"sir"` | How the butler addresses you (at most once per reply). |
| `language` | `"English"` | The language replies are written in. |
| `model` | `""` | A Claude model for the CLI (`--model`); empty uses Claude Code's default. |
| `notes_folder` | `"notes"` | The notes folder, relative to the project or absolute. Works as an Obsidian vault. |
| `port` | `4747` | The local port. The server only ever listens on 127.0.0.1. |
| `idle_minutes` | `30` | A session ends after this long without a request from you. Sessions also end after 12 hours. |
| `expert_hours` | `2` | Expert/lab mode switches itself off after this long. |
| `lab_targets` | `[]` | Machines you're allowed to test, for lab mode: ranges like `"10.10.0.0/16"` or names like `"box.htb"`. Ranges wider than a private /8 or a public /16 are ignored. |
| `voice` | `""` | The start of a browser voice name for spoken replies, e.g. `"Microsoft Ryan"`; empty picks a British voice. |
| `private_brain.url` | `http://127.0.0.1:11434` | Ollama's address. Anything not on this PC is refused. |
| `private_brain.model` | `qwen2.5:7b` | The local model for private mode. |
| `private_brain.fallback` | `true` | When Claude can't be reached, simple questions go to the local model (and say so). |
| `modules.security` | `false` | The [security module](modules/security.md): checks, alerts, tripwires and the score gauge. |
| `modules.*` (others) | `false` | Further modules, coming in later versions. |

## Where things are kept

| Path | What | Committed to git? |
|---|---|---|
| `config.json` | Your settings | No |
| `notes/` | Your notes | No |
| `data/` | The lock, activity, reminders, secrets: all encrypted with your Windows login | No |
| `data/demo/` | Demo mode's working copy (delete it to reset the demo) | No |
| `demo/notes/` | The made-up demo company | Yes |
