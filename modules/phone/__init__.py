"""Phone access, level 1: alerts pushed to your phone, with no details in them. Jarvis itself stays unreachable.

  python -m modules.phone setup      make a random private topic (stored encrypted) and send a test
  python -m modules.phone test       send a test again

Pushes go through ntfy (ntfy.sh, or your own server: config.json "phone": {"ntfy_server": "https://..."}). The topic
name is a long random string: on a public ntfy server, whoever knows the topic can read it, so it's kept in the vault
like a password. Messages say only that something happened ("Jarvis: 1 security alert. Open Jarvis to see it."),
never what, so the push service learns nothing about your PC. At most one push every 5 minutes; anything in between
is counted into the next.

Levels 2 (a read-only dashboard over Tailscale) and 3 (full control) are documented in docs/modules/phone.md with
their risks; level 3 is deliberately not built. Off until config.json "modules": {"phone": true}.
"""
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request

import modules
from core import config, vault

NAME = "phone"
GAP = 300
_state = {"last": 0.0, "pending": {}, "timer": None}
_lock = threading.Lock()
WORDS = {"alert": ("security alert", "security alerts"), "notice": ("notice", "notices"), "reminder": ("reminder", "reminders")}


def route(text):
    return None                                   # nothing to ask: it only sends


def server():
    s = str((config.get("phone") or {}).get("ntfy_server") or "https://ntfy.sh").rstrip("/")
    if not s.startswith("https://"):
        raise modules.ModuleError("phone.ntfy_server must be an https:// address.")
    return s


def topic():
    t = vault.secret("phone_topic")
    if not t:
        raise modules.ModuleError("No phone topic yet: python -m modules.phone setup")
    return t


def message(counts):
    """Content-free text: how many of what, never what they say."""
    parts = [f"{n} {WORDS[k][0] if n == 1 else WORDS[k][1]}" for k, n in sorted(counts.items()) if n]
    name = str(config.get("assistant_name") or "Jarvis")
    return f"{name}: " + " and ".join(parts) + f". Open {name} to see {'it' if sum(counts.values()) == 1 else 'them'}."


def push(text, priority="high", opener=urllib.request.urlopen):
    req = urllib.request.Request(f"{server()}/{topic()}", data=text.encode("utf-8"),
                                 headers={"Title": str(config.get("assistant_name") or "Jarvis"), "Priority": priority, "Tags": "shield"})
    try:
        with opener(req, timeout=10) as r:
            return 200 <= r.status < 300
    except (urllib.error.URLError, OSError):
        return False


def _flush():
    with _lock:
        counts, _state["pending"], _state["timer"] = dict(_state["pending"]), {}, None
        _state["last"] = time.time()
    if counts:
        push(message(counts))


def notify(kind, now=None):
    """Called for every alert/notice another module delivers. Batches, so the phone buzzes at most every 5 minutes."""
    if kind not in WORDS or config.demo():
        return
    now = now or time.time()
    with _lock:
        _state["pending"][kind] = _state["pending"].get(kind, 0) + 1
        wait = _state["last"] + GAP - now
        if _state["timer"] is not None:
            return
        if wait <= 0:
            _state["timer"] = True
        else:
            _state["timer"] = threading.Timer(wait, _flush)
            _state["timer"].daemon = True
            _state["timer"].start()
            return
    _flush()


def main(argv):
    try:
        if argv[:1] == ["setup"]:
            if not vault.secret("phone_topic"):
                vault.put("phone_topic", "jg-" + secrets.token_hex(16))
            print(f"In the ntfy app (Android or iOS), subscribe to:\n\n   server: {server()}\n   topic:  {topic()}\n\n"
                  "Treat the topic like a password: don't share it or put it in a screenshot.")
        if argv[:1] in (["setup"], ["test"]):
            ok = push(message({"alert": 1}).replace("1 security alert", "a test alert"), priority="default")
            print("Test sent. Did your phone buzz?" if ok else "The push didn't go through: check the internet connection and phone.ntfy_server.")
        else:
            print(__doc__)
    except modules.ModuleError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main(sys.argv[1:])
