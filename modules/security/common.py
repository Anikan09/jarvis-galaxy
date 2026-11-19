"""Shared helpers for the security module: the report shape the HUD drawer draws, PowerShell and registry reads."""
import json
import os
import re
import subprocess

NO_WINDOW = 0x08000000 if os.name == "nt" else 0
LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def row(k, v, risk=""):
    return {"k": str(k), "v": str(v), "risk": risk}


def finding(level, text):
    return {"level": level, "text": text}


def report(kind, title, target, verdict, sections, findings, answer, facts=None, badge="READ-ONLY"):
    """What the HUD draws in its drawer (kind "report") and says aloud (answer)."""
    findings = sorted(findings, key=lambda f: LEVEL_ORDER.get(f["level"], 9))
    return {"kind": "report", "tool": kind, "title": title, "target": target, "verdict": verdict, "badge": badge,
            "sections": sections, "findings": findings, "answer": answer, "facts": facts or {}}


def verdict(findings, labels=("clean", "check", "danger")):
    levels = {f["level"] for f in findings}
    return labels[2] if "high" in levels else labels[1] if "medium" in levels else labels[0]


def first_sentence(findings):
    serious = [f for f in sorted(findings, key=lambda f: LEVEL_ORDER.get(f["level"], 9)) if f["level"] in ("high", "medium")]
    return re.split(r"(?<=[.!?])\s", serious[0]["text"], maxsplit=1)[0] if serious else ""


def clean(v, limit=200):
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", " ", str(v)).strip()
    return s[:limit] + ("…" if len(s) > limit else "")


def ps(script, timeout=60):
    """Run a PowerShell script that prints JSON; the parsed result, or None."""
    if os.name != "nt":
        return None
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script],
                           capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        out = r.stdout.decode("utf-8", "replace").strip()
        return json.loads(out) if out else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def as_list(value):
    return [] if value is None else [value] if isinstance(value, dict) else list(value)


def reg(root, path, name):
    """A registry value (HKLM or HKCU), read-only; None when it isn't there."""
    try:
        import winreg
        hive = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[root]
        with winreg.OpenKey(hive, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except (OSError, ImportError, KeyError):
        return None


def reg_exists(root, path):
    try:
        import winreg
        hive = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[root]
        winreg.OpenKey(hive, path).Close()
        return True
    except (OSError, ImportError, KeyError):
        return False


def reg_values(root, path):
    try:
        import winreg
        hive = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[root]
        out = []
        with winreg.OpenKey(hive, path) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                except OSError:
                    return out
                out.append((name, str(value)))
                i += 1
    except (OSError, ImportError, KeyError):
        return []


def startup_items():
    items = []
    for root in ("HKCU", "HKLM"):
        for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
            items += reg_values(root, sub)
    for folder in (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp")):
        try:
            items += [(os.path.splitext(n)[0], os.path.join(folder, n)) for n in os.listdir(folder) if n.lower() != "desktop.ini"]
        except OSError:
            pass
    return items
