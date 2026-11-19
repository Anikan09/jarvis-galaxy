"""The activity log the HUD shows, grouped by day: what was asked, remembered, researched. Kept encrypted (vault), last 300."""
import threading
import time

from . import config, vault

KEEP = 300
_lock = threading.Lock()


def _path():
    return config.data_path("activity.json")


def log(kind, text=""):
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind, "text": str(text).replace("\n", " ")[:90]}
    with _lock:
        items = vault.read_json(_path(), []) or []
        items = (items + [entry])[-KEEP:]
        vault.write_json(_path(), items)


def recent(n=40):
    """Newest first, each with its date and time for the HUD's day headings."""
    with _lock:
        items = vault.read_json(_path(), []) or []
    return [{"date": e["ts"][:10], "at": e["ts"][11:16], "ts": e["ts"], "text": f"{e['kind']} · {e['text']}" if e["text"] else e["kind"]}
            for e in reversed(items[-n:])]
