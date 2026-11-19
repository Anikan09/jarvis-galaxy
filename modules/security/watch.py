"""What runs in the background while Jarvis is up: security alerts, tripwires, and the security score.

Alerts (every 5 minutes): Defender detections, Defender or the firewall switched off, new services, new start-up
programs, new scheduled tasks outside Microsoft's folder, and repeated failed logins. The first check only takes stock.
Tripwires (every 30 seconds): decoy files ("Passwords.txt") in Downloads; when anyone opens one the normal way, Windows
adds it to Recent items, and that's an alert. Editing or deleting it counts too. Local only.
Score (hourly): 0-100 from the other checks, with its history, for the HUD gauge and "what's my security score?".

Everything is kept encrypted in data/ (vault). Alerts reach you through deliver(): spoken in an open tab, or a
Windows notification.
"""
import datetime as dt
import os
import re
import secrets
import threading
import time

import modules
from core import config, vault

from .common import as_list, clean, finding, first_sentence, ps, report, row, startup_items

_lock = threading.Lock()
KEEP_ALERTS = 100


def _load(name, default):
    return vault.read_json(config.data_path(name), default) or default


def _save(name, data):
    vault.write_json(config.data_path(name), data)


def _alert(level, text, at=None):
    return {"level": level, "text": clean(text, 300), "at": at or time.strftime("%Y-%m-%d %H:%M:%S")}


# ---------- Alerts ----------

EVENTS_SCRIPT = r"""
$since = [DateTime]::Parse('{since}')
$q = @(@{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1006,1116,1117,5001,5010,5012; StartTime=$since},
       @{LogName='System'; Id=7045; StartTime=$since}, @{LogName='Security'; Id=4625,4740; StartTime=$since})
$out = foreach ($f in $q) { try { Get-WinEvent -FilterHashtable $f -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = [ordered]@{}; foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
  [ordered]@{ log = $_.LogName; id = $_.Id; at = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); rid = $_.RecordId; data = $d } } } catch {} }
@($out) | ConvertTo-Json -Depth 4 -Compress
"""
STATUS_SCRIPT = r"""
$o = [ordered]@{}
try { $m = Get-MpComputerStatus -ErrorAction Stop; $o.realtime = [bool]$m.RealTimeProtectionEnabled; $o.passive = ([string]$m.AMRunningMode) -match 'passive' } catch { $o.realtime = $null }
try { $o.firewall_off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name }) } catch { $o.firewall_off = $null }
try { $o.tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { $_.TaskPath + $_.TaskName }) } catch { $o.tasks = $null }
$o | ConvertTo-Json -Depth 3 -Compress
"""


def event_alerts(events, state):
    out, failed = [], []
    seen, services = set(state.setdefault("seen", [])), set(state.setdefault("services", []))
    for e in sorted(events, key=lambda e: (e.get("at", ""), e.get("rid", 0))):
        key = f"{e.get('log')}#{e.get('rid')}"
        if key in seen:
            continue
        seen.add(key)
        d, eid, at = e.get("data") or {}, e.get("id"), e.get("at")
        if eid in (1116, 1006):
            out.append(_alert("high", f"Microsoft Defender found {d.get('Threat Name') or 'a threat'}. Windows Security → Protection history shows what it did.", at))
        elif eid == 1117:
            out.append(_alert("medium", f"Microsoft Defender acted against {d.get('Threat Name') or 'a threat'}.", at))
        elif eid in (5001, 5010, 5012):
            out.append(_alert("high", "Microsoft Defender's protection was switched off. If that wasn't you, turn it back on now.", at))
        elif eid == 7045:
            name = d.get("ServiceName") or "?"
            if name.lower() not in services:                 # once per service name, so updaters reinstalling drivers don't nag
                services.add(name.lower())
                out.append(_alert("medium", f"A new service was installed: {name} ({clean(d.get('ImagePath') or '', 120)}). Fine if you just installed something.", at))
        elif eid == 4625:
            failed.append(e)
        elif eid == 4740:
            out.append(_alert("high", "A Windows account was locked out after too many wrong passwords.", at))
    if len(failed) >= 3:
        out.append(_alert("high" if len(failed) >= 10 else "medium", f"{len(failed)} failed Windows logins. If that wasn't you mistyping, someone is guessing.",
                          failed[-1].get("at")))
    state["seen"], state["services"] = sorted(seen)[-2000:], sorted(services)
    return out


def status_alerts(status, state):
    out, before = [], state.get("status") or {}
    if status.get("realtime") is False and before.get("realtime") is not False and not status.get("passive"):
        out.append(_alert("high", "Microsoft Defender's real-time protection is off. Windows Security → Virus & threat protection."))
    newly = sorted(set(status.get("firewall_off") or []) - set(before.get("firewall_off") or []))
    if newly:
        out.append(_alert("high", f"The firewall was turned off for {', '.join(newly)} networks."))
    if before.get("startup") is not None:
        for item in sorted(set(status.get("startup") or []) - set(before["startup"])):
            out.append(_alert("medium", f"Something new starts with Windows: {clean(item, 160)}. Fine if you just installed it; otherwise look it up."))
    if before.get("tasks") is not None and status.get("tasks") is not None:
        for t in sorted(set(status["tasks"]) - set(before["tasks"])):
            out.append(_alert("medium", f"A new scheduled task appeared: {clean(t, 120)}."))
    for k in ("realtime", "passive", "firewall_off", "startup", "tasks"):
        if status.get(k) is not None:
            before[k] = status[k]
    state["status"] = before
    return out


def check_alerts(read_events=None, read_status=None):
    """One look. The first ever run only takes stock. Returns the new alerts."""
    with _lock:
        state = _load("security_watch.json", {})
        first = not state
        since = state.get("since") or (dt.datetime.now() - dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
        events = (read_events or (lambda s: as_list(ps(EVENTS_SCRIPT.replace("{since}", s), 60))))(since)
        status = (read_status or (lambda: {**(ps(STATUS_SCRIPT, 60) or {}), "startup": [f"{n} = {c}" for n, c in startup_items()]}))()
        alerts = event_alerts(events, state) + status_alerts(status, state)
        if first:
            alerts = []
        state["since"] = dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        state["alerts"] = ((state.get("alerts") or []) + alerts)[-KEEP_ALERTS:]
        _save("security_watch.json", state)
        return alerts


def record_alert(level, text):
    with _lock:
        state = _load("security_watch.json", {})
        state["alerts"] = ((state.get("alerts") or []) + [_alert(level, text)])[-KEEP_ALERTS:]
        _save("security_watch.json", state)


def recent_alerts(n=20):
    return list(reversed((_load("security_watch.json", {}).get("alerts") or [])[-n:]))


def alerts_report():
    alerts = recent_alerts()
    f = [finding(a["level"], a["text"]) for a in alerts[:5] if a["level"] in ("high", "medium")]
    answer = (f"{len(alerts)} recent security alert{'s' if len(alerts) != 1 else ''}. The latest: {alerts[0]['text']}" if alerts
              else "All quiet. Nothing has needed your attention.")
    return report("alerts", "Security alerts", "This PC", "recent alerts" if alerts else "all quiet",
                  [{"title": "Watching", "rows": [row("Checks", "every 5 minutes while Jarvis runs"),
                                                  row("Watching", "Defender detections, Defender/firewall switched off, new services, start-up programs, "
                                                                  "scheduled tasks, failed logins, tripwires")]},
                   {"title": f"Recent alerts ({len(alerts)})", "rows": [row(a["at"][:16], a["text"], a["level"]) for a in alerts]
                    or [row("None", "nothing has needed your attention")]}], f, answer, badge="WATCHING")


# ---------- Tripwires ----------

RECENT = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
DOWNLOADS = os.path.join(os.path.expanduser("~"), "Downloads")
MARK = "jg-decoy-"
DECOYS = {
    "passwords": ("Passwords.txt", "Passwords (keep safe!)\n\nemail    j.summers.home@example.com    Summer2019!\nbank     login 40182277            Bluebird#77\n"
                                   "amazon   j.summers.home@example.com    Prime-4-Life\nrouter   admin                         Home-Router-55\n"),
    "bank": ("Bank details.txt", "Bank details\n\nIBAN: XX00 0000 0000 0000 0000 00\nOnline banking login: 40182277\nPIN: 4471\n"),
    "crypto": ("Wallet recovery phrase.txt", "Wallet recovery phrase - DO NOT SHARE\n\n1 orbit  2 candle  3 meadow  4 thunder\n5 velvet  6 harbor  "
                                             "7 silent  8 copper\n9 lantern  10 drift  11 maple  12 voyage\n"),
}


def _stem(name):
    return os.path.splitext(os.path.basename(name))[0].lower()


def _recent_links(recent=None):
    out = {}
    try:
        names = os.listdir(recent or RECENT)
    except OSError:
        return out
    for n in names:
        p = os.path.join(recent or RECENT, n)
        if n.lower().endswith(".lnk") and os.path.isfile(p):
            try:
                out[_stem(n)] = (os.path.getmtime(p), p)
            except OSError:
                pass
    return out


def _mentions(link, name):
    try:
        with open(link, "rb") as f:
            data = f.read(64_000)
    except OSError:
        return False
    return name.encode("utf-16-le") in data or name.encode("latin-1", "ignore") in data


def set_tripwire(kind="passwords", folder=None, recent=None):
    name, body = DECOYS[kind]
    folder = folder or DOWNLOADS
    target = os.path.join(folder, name)
    with _lock:
        data = _load("tripwires.json", {})
        wires = data.setdefault("wires", {})
        if any(w["name"] == name for w in wires.values()):
            raise modules.ModuleError(f"There's already a tripwire called {name}.")
        if os.path.exists(target):
            raise modules.ModuleError(f"There's already a file called {name} in {folder}; I won't overwrite it.")
        if _stem(name) in _recent_links(recent):
            raise modules.ModuleError(f"You've opened a file called {name} before, so a decoy with that name would cry wolf. Try another kind.")
        wid = secrets.token_hex(4)
        with open(target, "w", encoding="utf-8", newline="\r\n") as f:
            f.write(body + f"\nref {MARK}{wid}\n")
        wires[wid] = {"name": name, "path": target, "armed": dt.datetime.now().isoformat(timespec="seconds"), "seen": 0.0,
                      "mtime": os.path.getmtime(target), "hits": [], "gone": False}
        _save("tripwires.json", data)
        return wires[wid]


def remove_tripwire(kind):
    name = DECOYS.get(kind, ("",))[0]
    with _lock:
        data = _load("tripwires.json", {})
        for wid, w in list(data.get("wires", {}).items()):
            if not name or w["name"] == name:
                deleted = False
                try:
                    with open(w["path"], encoding="utf-8", errors="replace") as f:
                        mine = f"{MARK}{wid}" in f.read()
                    if mine:                                  # only Jarvis's own decoy, never a file of yours
                        os.remove(w["path"])
                        deleted = True
                except OSError:
                    pass
                del data["wires"][wid]
                _save("tripwires.json", data)
                return w["name"], deleted
    raise modules.ModuleError("There's no such tripwire.")


def check_tripwires(recent=None):
    out = []
    with _lock:
        data = _load("tripwires.json", {})
        wires = data.get("wires", {})
        if not wires:
            return out
        links, changed = _recent_links(recent), False
        for w in wires.values():
            hit = links.get(_stem(w["name"]))
            if hit and hit[0] > w.get("seen", 0) and hit[0] > dt.datetime.fromisoformat(w["armed"]).timestamp() and _mentions(hit[1], w["name"]):
                when = dt.datetime.fromtimestamp(hit[0])
                out.append(("high", f"Someone opened your decoy file {w['name']} at {when:%H:%M}. If that wasn't you, someone is going through your files."))
                w["seen"] = hit[0]
                w["hits"] = (w.get("hits") or []) + [when.isoformat(timespec="seconds")]
                changed = True
            try:
                m = os.path.getmtime(w["path"])
                if abs(m - w["mtime"]) > 1:
                    out.append(("high", f"Your decoy file {w['name']} was changed: someone opened and saved it."))
                    w["mtime"], changed = m, True
                if w.get("gone"):
                    w["gone"], changed = False, True
            except OSError:
                if not w.get("gone"):
                    out.append(("medium", f"Your decoy file {w['name']} has gone. If you moved it, fine: it's watched by name."))
                    w["gone"], changed = True, True
        if changed:
            _save("tripwires.json", data)
    return out


def tripwire_report(answer=None):
    wires = _load("tripwires.json", {}).get("wires", {})
    rows = [row(w["name"], f"{clean(os.path.dirname(w['path']), 50)} · armed {w['armed'][:10]} · "
                + (f"opened {w['hits'][-1].replace('T', ' ')[:16]}" if w.get("hits") else "never opened"), "high" if w.get("hits") else "") for w in wires.values()]
    f = [finding("high", f"{w['name']} was opened {len(w['hits'])} time(s).") for w in wires.values() if w.get("hits")]
    v = "triggered" if f else "armed" if wires else "none set"
    answer = answer or (f"{len(wires)} tripwire{'s' if len(wires) != 1 else ''} armed." + (" One has gone off." if f else "") if wires
                        else "No tripwires yet. Say set a tripwire, and I'll lay a decoy file.")
    return report("tripwire", "Tripwires", f"{len(wires)} decoy file(s)", v, [{"title": "Tripwires", "rows": rows or [row("None", "say set a tripwire")],
                  "note": "Checked every 30 seconds through Windows' Recent items. Local only. Never open a decoy yourself."}], f, answer, badge="LOCAL ONLY")


# ---------- The score ----------

POINTS = {"high": 15, "medium": 6, "low": 2}
AREAS = (("windows", "Windows", 45), ("wifi", "Wi-Fi", 20), ("network", "Network", 15), ("alerts", "Alerts", 30), ("programs", "Programs", 15))


def grade(score):
    return "excellent" if score >= 90 else "good" if score >= 75 else "fair" if score >= 60 else "at risk"


def score(found):
    lost, areas = 0, {}
    for key, label, cap in AREAS:
        items = found.get(key)
        if items is None:
            areas[key] = {"label": label, "lost": 0, "max": cap, "checked": False, "findings": []}
            continue
        serious = [x for x in items if x.get("level") in POINTS]
        n = min(cap, sum(POINTS[x["level"]] for x in serious))
        areas[key] = {"label": label, "lost": n, "max": cap, "checked": True, "findings": serious[:6]}
        lost += n
    return max(0, 100 - lost), areas


def _gather():
    from . import pc

    def safe(fn):
        try:
            return fn()["findings"]
        except Exception:
            return None
    week = (dt.datetime.now() - dt.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    return {"windows": safe(pc.pc_check), "wifi": safe(pc.wifi), "programs": safe(pc.connections),
            "alerts": [finding(a["level"], a["text"]) for a in _load("security_watch.json", {}).get("alerts") or [] if a["at"] >= week],
            "network": None}


def refresh_score(found=None, now=None):
    value, areas = score(found if found is not None else _gather())
    now = now or time.time()
    with _lock:
        data = _load("security_score.json", {})
        hist = [h for h in data.get("history", []) if now - h["t"] < 90 * 86400]
        point = {"t": now, "score": value, "areas": {k: a["lost"] for k, a in areas.items()}}
        if hist and now - hist[-1]["t"] < 1800:
            hist[-1] = point
        else:
            hist.append(point)
        data.update(history=hist, latest={"t": now, "score": value, "grade": grade(value), "areas": areas})
        _save("security_score.json", data)
    return data["latest"]


def change(data, hours=24):
    hist = data.get("history") or []
    if len(hist) < 2:
        return None, ""
    now, target = hist[-1], hist[-1]["t"] - hours * 3600
    then = min(hist[:-1], key=lambda h: abs(h["t"] - target))
    if abs(then["t"] - target) > hours * 3600 * 0.75:
        return None, ""
    moved = max(((k, now["areas"].get(k, 0) - then["areas"].get(k, 0)) for k in now["areas"]), key=lambda kv: abs(kv[1]), default=("", 0))
    return now["score"] - then["score"], dict((k, l) for k, l, _ in AREAS).get(moved[0], "") if moved[1] else ""


def summary():
    """GET /api/security: what the HUD gauge needs."""
    data = _load("security_score.json", {})
    latest = data.get("latest")
    if not latest:
        return {"score": None}
    delta, why = change(data)
    issues = sorted((x for a in latest["areas"].values() for x in a["findings"]), key=lambda x: 0 if x["level"] == "high" else 1)
    return {"score": latest["score"], "grade": latest["grade"], "at": time.strftime("%H:%M", time.localtime(latest["t"])), "change": delta,
            "change_why": why, "top": [x["text"] for x in issues[:3]], "history": [h["score"] for h in (data.get("history") or [])[-48:]]}


def score_report(fresh=False):
    data = _load("security_score.json", {})
    latest = refresh_score() if fresh or not data.get("latest") else data["latest"]
    s = summary()
    f = [x for a in latest["areas"].values() for x in a["findings"]]
    rows = [row(a["label"], (f"-{a['lost']} of {a['max']}" if a["lost"] else "full marks") if a["checked"] else "couldn't be checked",
                "high" if a["lost"] >= a["max"] * 0.6 else "medium" if a["lost"] else "") for a in latest["areas"].values()]
    answer = f"Your security score is {latest['score']} out of 100, {latest['grade']}."
    if s.get("change"):
        answer += f" That's {'up' if s['change'] > 0 else 'down'} {abs(s['change'])} since yesterday" + (f", mostly {s['change_why']}." if s.get("change_why") else ".")
    if first_sentence(f):
        answer += f" The biggest gain: {first_sentence(f)}"
    return report("score", "Security score", f"{latest['score']}/100", latest["grade"], [{"title": "Where the points went", "rows": rows,
                  "note": "High findings cost 15 points, medium 6, low 2; each area can only lose so much."}], f, answer, badge="THIS PC")


# ---------- Background ----------

def start(deliver):
    if config.demo() or os.name != "nt":
        return                                                # demo mode never watches the real PC

    def alerts_loop():
        time.sleep(20)
        while True:
            try:
                for a in check_alerts():
                    deliver(a["text"], "alert")
            except Exception as e:
                print(f"Security alerts: {type(e).__name__}")
            time.sleep(300)

    def tripwire_loop():
        time.sleep(15)
        while True:
            try:
                for level, text in check_tripwires():
                    deliver(text, "alert")
                    record_alert(level, text)
            except Exception as e:
                print(f"Tripwires: {type(e).__name__}")
            time.sleep(30)

    def score_loop():
        time.sleep(60)
        while True:
            try:
                refresh_score()
            except Exception as e:
                print(f"Security score: {type(e).__name__}")
            time.sleep(3600)

    for fn in (alerts_loop, tripwire_loop, score_loop):
        threading.Thread(target=fn, name=fn.__name__, daemon=True).start()
