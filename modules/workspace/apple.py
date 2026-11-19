"""Apple iCloud Calendar over CalDAV, read-only, with an app-specific password (never your Apple ID password).

  config.json:  "workspace": {"apple_id": "you@icloud.com", "apple_calendar": ""}     (empty calendar = all of them)
  password:     python -m core.vault set apple_app_password      (make one at account.apple.com → App-Specific Passwords)

Needs: pip install caldav
"""
import datetime as dt

import modules
from core import config, vault

URL = "https://caldav.icloud.com/"


def configured():
    return bool((config.get("workspace") or {}).get("apple_id")) and bool(vault.secret("apple_app_password"))


def today():
    try:
        import caldav
    except ImportError:
        raise modules.ModuleError("Apple Calendar needs one package: pip install caldav")
    ws = config.get("workspace") or {}
    try:
        client = caldav.DAVClient(url=URL, username=ws.get("apple_id"), password=vault.secret("apple_app_password"))
        cals = client.principal().calendars()
    except Exception:
        raise modules.ModuleError("Apple Calendar refused the sign-in. Check apple_id, and make a new app-specific password.")
    wanted = str(ws.get("apple_calendar") or "").lower()
    start = dt.datetime.combine(dt.date.today(), dt.time())
    out = []
    for cal in cals:
        if wanted and (cal.name or "").lower() != wanted:
            continue
        for ev in cal.search(start=start, end=start + dt.timedelta(days=1), event=True, expand=True):
            c = ev.icalendar_component
            s, e = c.get("dtstart"), c.get("dtend")
            fmt = lambda v: v.dt.astimezone().strftime("%H:%M") if v is not None and isinstance(v.dt, dt.datetime) else "all day"
            out.append({"title": str(c.get("summary") or "(no title)"), "start": fmt(s), "end": fmt(e), "calendar": "apple"})
    return out
