#!/usr/bin/env python3
"""First run: checks what's needed, creates config.json and the notes folder, and sets up the lock.

  python setup.py

Run it in PowerShell or Windows Terminal (the password prompt hides what you type there). Safe to run again: it never
overwrites your config, notes or lock; it only fills in what's missing.
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def step(ok, text, fix=""):
    print(f"  {'OK ' if ok else '-- '} {text}" + (f"\n      {fix}" if fix and not ok else ""))
    return ok


def main():
    print("Jarvis Galaxy setup\n")
    good = step(sys.version_info >= (3, 11), f"Python {sys.version.split()[0]}", "Python 3.11 or newer is needed: python.org/downloads")
    good &= step(os.name == "nt", "Windows", "Version 1 is Windows only (the vault and the voice rely on it).")
    claude = shutil.which("claude")
    step(bool(claude), "Claude Code CLI found" if claude else "Claude Code CLI",
         "Install it (docs.claude.com/claude-code), then run  claude  once and log in. Jarvis's answers use your own Claude account.")
    if claude:
        try:
            out = subprocess.run([claude, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
            step(True, f"Claude Code {out}")
        except (OSError, subprocess.TimeoutExpired):
            step(False, "Claude Code didn't answer", "Run  claude  in a terminal to finish its setup.")
    if not good:
        sys.exit("\nFix the items above, then run setup again.")

    from core import auth, config
    if not os.path.exists(config.CONFIG_PATH):
        shutil.copyfile(config.EXAMPLE_PATH, config.CONFIG_PATH)
        step(True, "Created config.json from config.example.json (edit it any time; see docs/configuration.md)")
    else:
        step(True, "config.json already there (left as it is)")
    notes = config.notes_dir()
    if not os.path.isdir(notes):
        os.makedirs(os.path.join(notes, "captures"), exist_ok=True)
        with open(os.path.join(notes, "Welcome.md"), "w", encoding="utf-8") as f:
            f.write("# Welcome\n\nThis is your notes folder. Every .md file in it becomes a star in the galaxy; link notes with "
                    "[[double brackets]]. Say \"remember that ...\" and a new note lands in captures/.\n")
        step(True, f"Created your notes folder: {notes}")
    else:
        step(True, f"Notes folder: {notes}")
    os.makedirs(config.DATA_DIR, exist_ok=True)

    if auth.configured():
        step(True, "The lock is set up (python -m core.auth --reset to change it)")
    else:
        print("\nNow the lock: a password, and a code from an authenticator app on your phone.\n")
        auth.setup()
    print(f"\nAll set. Start it with:\n\n    python -m core.server\n\nthen open http://localhost:{config.get('port')}/"
          "\nWant a look around first?  python -m core.server --demo")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nCancelled. Run python setup.py again whenever you like.")
