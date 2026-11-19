"""Reminders: "remind me in 20 minutes to check the oven", "remind me at 5 to call the bank", "remind me tomorrow at 9:30 to …".

Parsed locally (no brain call). An open HUD tab speaks a due reminder; with no tab open, the server shows a Windows
notification instead, so a closed browser doesn't swallow it. Each is delivered once. Stored encrypted (vault).
"""
import datetime as dt
import os
import re
import secrets
import subprocess
import threading

from . import config, vault

_lock = threading.Lock()
NUMBERS = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "ten": 10, "fifteen": 15, "twenty": 20,
           "thirty": 30, "forty": 40, "forty-five": 45, "fifty": 50, "sixty": 60, "ninety": 90, "half an": 30, "a couple of": 2}
REQUEST_RE = re.compile(r"^\s*(?:(?:please|jarvis)[\s,]+)?remind\s+me\b", re.I)
IN_RE = re.compile(r"\bin\s+(\d+|a couple of|half an|an?|[a-z-]+)\s+(minutes?|mins?|hours?|hrs?|days?)\b", re.I)
AT_RE = re.compile(r"\b(?:(today|tomorrow|tonight)\s+)?at\s+(\d{1,2})(?:[:.](\d{2}))?\s*(am|pm)?\b(?:\s+(today|tomorrow))?", re.I)
WHAT_RE = re.compile(r"\bto\s+(.+)$|\babout\s+(.+)$|\bthat\s+(.+)$", re.I)


def is_request(text):
    return bool(REQUEST_RE.search(text or ""))


def parse(text, now=None):
    """(when, what) or None."""
    now = now or dt.datetime.now()
    body = REQUEST_RE.sub("", text, count=1).strip()
    when = None
    m = IN_RE.search(body)
    if m:
        raw = m.group(1).lower()
        n = int(raw) if raw.isdigit() else NUMBERS.get(raw)
        if n:
            unit = m.group(2).lower()
            when = now + (dt.timedelta(hours=n) if unit.startswith(("hour", "hr")) else dt.timedelta(days=n) if unit.startswith("day")
                          else dt.timedelta(minutes=n))
            body = (body[:m.start()] + body[m.end():]).strip()
    if when is None:
        m = AT_RE.search(body)
        if m:
            day, hour, minute, ampm, day2 = m.groups()
            hour, minute = int(hour), int(minute or 0)
            if ampm:
                hour = hour % 12 + (12 if ampm.lower() == "pm" else 0)
            elif hour < 8 and (day or day2 or "").lower() != "tomorrow":
                hour += 12                                   # "at 5" means the afternoon
            if hour > 23 or minute > 59:
                return None
            when = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if (day or day2 or "").lower() == "tomorrow":
                when += dt.timedelta(days=1)
            elif when <= now:
                when += dt.timedelta(days=1)
            body = (body[:m.start()] + body[m.end():]).strip()
    if when is None:
        return None
    w = WHAT_RE.search(body)
    what = next((g for g in (w.groups() if w else ()) if g), body).strip(" .!?") or "the thing you asked about"
    return when, what[:200]


def _path():
    return config.data_path("reminders.json")


def add(what, when):
    item = {"id": secrets.token_hex(4), "text": what, "due": when.timestamp(), "done": False}
    with _lock:
        items = vault.read_json(_path(), []) or []
        vault.write_json(_path(), items + [item])
    return item


def due(now=None):
    now = (now or dt.datetime.now()).timestamp()
    with _lock:
        return [r for r in vault.read_json(_path(), []) or [] if not r["done"] and r["due"] <= now]


def ack(ids):
    """Mark delivered; returns the reminders that were still pending (so two tabs never both speak one)."""
    with _lock:
        items = vault.read_json(_path(), []) or []
        done = [r for r in items if r["id"] in ids and not r["done"]]
        for r in done:
            r["done"] = True
        cutoff = dt.datetime.now().timestamp() - 30 * 86400
        vault.write_json(_path(), [r for r in items if not r["done"] or r["due"] > cutoff])
    return done


def when_text(ts):
    d = dt.datetime.fromtimestamp(ts)
    today = dt.date.today()
    day = "today" if d.date() == today else "tomorrow" if d.date() == today + dt.timedelta(days=1) else d.strftime("%A %d %B")
    return f"{day} at {d:%H:%M}"


def toast(title, body):
    """A Windows notification through PowerShell's built-in WinRT bindings. True if shown."""
    if os.name != "nt":
        return False
    esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")
    xml = f"<toast><visual><binding template='ToastGeneric'><text>{esc(title)}</text><text>{esc(body)}</text></binding></visual></toast>"
    script = ("[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
              "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null;"
              "$x = New-Object Windows.Data.Xml.Dom.XmlDocument; $x.LoadXml($env:JG_TOAST);"
              "$t = New-Object Windows.UI.Notifications.ToastNotification $x;"
              "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Microsoft.Windows.Computer').Show($t)")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], env={**os.environ, "JG_TOAST": xml},
                           capture_output=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
