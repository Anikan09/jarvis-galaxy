"""Modes: demo, expert, lab and private. Expert/lab/private live in memory only, so a restart always comes back normal.

- Demo (python -m core.server --demo): made-up data from demo/, real data untouched. Set before anything starts.
- Expert ("expert mode on"): technical answers, exact commands and raw figures; never fewer limits. Ends by itself
  after config "expert_hours", on Lock, and on restart.
- Lab ("lab mode on", includes expert): full walkthroughs for config "lab_targets" (machines you may test).
- Private ("private mode on"): every brain call goes to the local model; anything needing the internet is declined.
"""
import ipaddress
import os
import re
import threading
import time

from . import config

_state = {"expert": False, "lab": False, "until": 0.0, "private": False}
_lock = threading.Lock()

EXPERT_PATTERN = r"""^\s*(?:(?:please|jarvis)[\s,]+)?(?:(?:switch|turn|go)\s+(?:on\s+|off\s+|into\s+|to\s+|back\s+to\s+)?)?(?:(expert|lab|normal|standard)\s+mode(?:\s+(on|off))?|(?:switch|turn)\s+(on|off)\s+(expert|lab)\s+mode|(?:leave|exit|end|stop)\s+(expert|lab)\s+mode)[\s.!]*$"""
PRIVATE_PATTERN = r"""^\s*(?:(?:please|jarvis)[\s,]+)?(?:(?:switch|turn|go)\s+(?:on\s+|off\s+|into\s+|to\s+)?)?(?:(private|offline)\s+mode(?:\s+(on|off))?|(?:switch|turn)\s+(on|off)\s+(private|offline)\s+mode|(?:leave|exit|end|stop)\s+(private|offline)\s+mode)[\s.!]*$"""
EXPERT_RE, PRIVATE_RE = re.compile(EXPERT_PATTERN, re.I), re.compile(PRIVATE_PATTERN, re.I)

EXPERT_RULE = """

EXPERT MODE is on: the user is technically experienced. Skip basics and caveats they already know. Give exact commands with their flags, paths, versions and raw figures. Spoken sentences stay short; detail goes in the written part. Expert mode changes your style, never your limits: only the user's own systems and the lab targets they may test."""
LAB_RULE = """
LAB MODE is on: for these lab targets the user is allowed to test ({targets}), full walkthroughs and working exploit steps are fine, as in a CTF write-up. Everything else keeps the usual limits."""


def demo():
    return config.demo()


def _expire():
    if _state["expert"] and time.time() > _state["until"]:
        _state.update(expert=False, lab=False, until=0.0)


def expert():
    with _lock:
        _expire()
        return _state["expert"]


def lab():
    with _lock:
        _expire()
        return _state["expert"] and _state["lab"]


def private():
    return _state["private"]


def set_private(value):
    _state["private"] = bool(value)


def set_expert(on, lab_on=False, now=None):
    with _lock:
        if on:
            hours = max(0.25, min(float(config.get("expert_hours", 2) or 2), 12.0))
            _state.update(expert=True, lab=bool(lab_on), until=(now or time.time()) + hours * 3600)
        else:
            _state.update(expert=False, lab=False, until=0.0)


def state():
    with _lock:
        _expire()
        return {"demo": demo(), "expert": _state["expert"], "lab": _state["expert"] and _state["lab"], "private": _state["private"],
                "until": time.strftime("%H:%M", time.localtime(_state["until"])) if _state["expert"] else ""}


def lab_targets():
    """Ranges and host names from config; ranges wider than a private /8 or a public /16 are ignored."""
    out = []
    for t in config.get("lab_targets") or []:
        t = str(t).strip().lower()
        try:
            net = ipaddress.ip_network(t, strict=False)
            if (not net.is_global and net.prefixlen >= 8) or net.prefixlen >= 16:
                out.append(net)
        except ValueError:
            if re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]+", t):
                out.append(t)
    return out


def in_lab(host):
    if not lab():
        return False
    host = str(host or "").strip().lower()
    for t in lab_targets():
        if isinstance(t, str):
            if host == t or host.endswith("." + t):
                return True
        else:
            try:
                if ipaddress.ip_address(host) in t:
                    return True
            except ValueError:
                pass
    return False


def rule():
    """Appended to every system prompt while expert or lab mode is on."""
    if not expert():
        return ""
    text = EXPERT_RULE
    if lab():
        text += LAB_RULE.replace("{targets}", ", ".join(map(str, lab_targets())) or "none listed")
    return text


def handle(text):
    """{"answer"} for a mode switch, or None."""
    m = EXPERT_RE.search(text or "")
    if m:
        which = (m.group(1) or m.group(4) or m.group(5) or "").lower()
        word = (m.group(2) or m.group(3) or "").lower()
        leaving = bool(m.group(5)) or word == "off" or which in ("normal", "standard") or bool(re.search(r"\bback\s+to\b", text, re.I))
        if leaving and (which != "lab" or not expert()):
            set_expert(False)
            return {"answer": "Expert mode off. Back to full explanations."}
        if leaving:
            set_expert(True, False)
            return {"answer": "Lab mode off. Expert mode stays on."}
        set_expert(True, which == "lab")
        targets = ", ".join(map(str, lab_targets()))
        if which == "lab":
            return {"answer": f"Lab mode on until {state()['until']}. Full walkthroughs for " + (targets or "nothing yet: add lab_targets to config.json") + "."}
        return {"answer": f"Expert mode on until {state()['until']}. Short words, long reports. The limits stay where they are."}
    m = PRIVATE_RE.search(text or "")
    if m:
        leaving = bool(m.group(5)) or (m.group(2) or m.group(3) or "").lower() == "off"
        set_private(not leaving)
        if leaving:
            return {"answer": "Private mode off. Claude is back on duty."}
        from . import localbrain
        ready = localbrain.status()["model_ready"]
        return {"answer": "Private mode on: answers come from the model on this PC, and nothing goes to Claude."
                          + ("" if ready else " The local model isn't ready yet, so I'll have to decline questions until it is (see docs/private-brain.md).")}
    return None
