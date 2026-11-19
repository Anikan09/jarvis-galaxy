"""The security module: your PC, your network and your files, checked and watched. Off until config.json
"modules": {"security": true}. Everything is read-only, stays within what's yours, and says what leaves the PC.
See docs/modules/security.md.
"""
import re

import modules
from core import config

from . import demo_data
from .common import report, row

NAME = "security"

PATTERNS = {
    "label": r"""(?:name|call|label)\s+(?:the\s+)?device\s+(?:at\s+)?(\S+?)[,:]?\s+(?:as\s+|to\s+)?["“']?(.+?)["”']?[.!]?\s*$""",
    "tripwire": r"""\b(?:trip-?wires?|decoy\s+files?|honey-?(?:pots?|tokens?))\b""",
    "score": r"""\b(?:(?:my\s+|the\s+)?security\s+(?:score|rating|grade)|how\s+secure\s+am\s+i)\b""",
    "wifi": r"""\b(?:(?:is\s+)?my\s+wi-?fi\s+(?:secure|safe|encrypted)|how\s+(?:secure|safe)\s+is\s+my\s+wi-?fi|wi-?fi\s+security|check\s+(?:my\s+)?wi-?fi|evil\s+twins?)\b""",
    "ports": r"""\b(?:open\s+(?:ports?|doors)\s+on\s+(?:my\s+|the\s+)?(?:router|devices?|network|\d{1,3}(?:\.\d{1,3}){3})|port\s+(?:check|scan)|(?:check|scan)\s+(?:the\s+)?ports?\s+(?:on|of)\s+)""",
    "connections": r"""\b(?:what(?:'s|’s|\s+is)\s+(?:my|this)\s+(?:pc|computer|laptop)\s+(?:talking|connected|connecting)\s+to|(?:which|what)\s+(?:programs?|apps?)\s+(?:are\s+)?(?:online|connected|using\s+the\s+internet)|(?:show|list|check)\s+(?:my\s+)?(?:network\s+|active\s+)?connections)\b""",
    "network": r"""\b(?:(?:what|which|who)(?:'s|’s|\s+is|\s+are)?\s+(?:devices?\s+)?(?:(?:is|are)\s+)?(?:on|connected\s+to)\s+(?:my|the|our)\s+(?:home\s+)?(?:wi-?fi|network|router)|devices?\s+on\s+(?:my|the|our)\s+(?:wi-?fi|network)|(?:scan|look\s+at)\s+(?:my|the|our)\s+(?:home\s+)?(?:wi-?fi|network))""",
    "alerts": r"""\b(?:security\s+(?:alerts?|events?|warnings?)|(?:any|show(?:\s+me)?|list|recent)\s+(?:the\s+)?(?:security\s+)?alerts?|what\s+(?:has|did)\s+defender\s+(?:found|find|detect(?:ed)?))\b""",
    "breach": r"""\b(?:my\s+(?:password|e-?mail(?:\s+address)?)\b.{0,80}?\b(?:leaked|breached|pwned|compromised|exposed|in\s+a\s+breach)|have\s+i\s+been\s+pwned|been\s+(?:pwned|breached)|breach\s+check|check\s+my\s+password)\b""",
    "file": r"""\b(?:(?:check|scan|inspect|verify)\s+(?:this\s+|the\s+|my\s+|that\s+)?(?:file|download|program|installer|exe|attachment)|is\s+(?:this|the|that)\s+(?:file|download|program|installer|exe|attachment)\s+(?:safe|malware|malicious|a\s+virus|legit\w*|clean)|virus\s*(?:check|scan)|scan\s+.{1,200}?\s+for\s+(?:viruses|malware))\b""",
    "link": r"""\b(?:phish\w*|scam\s+link|suspicious\s+(?:link|url)|is\s+(?:this|that|the)\s+(?:link|url|website|site)\b.{0,40}?\b(?:safe|legit\w*|real|a\s+scam|fake|dangerous)|(?:check|scan|inspect)\s+(?:this|that|the)\s+(?:link|url))\b""",
    "pc": r"""\b(?:(?:pc|computer|laptop|windows)\s+security(?:\s+check)?|security\s+check\s+(?:of|on|for)\s+(?:my|this)\s+(?:pc|computer|laptop)|is\s+my\s+(?:pc|computer|laptop)\s+(?:secure|safe|protected)|check\s+(?:my\s+)?defender)\b""",
}
RES = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'`]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s<>"'`]*)?""", re.I)
PATH_RE = re.compile(r"""["']?((?:[A-Za-z]:[\\/]|\\\\|~[\\/]|%\w+%[\\/])[^"'<>|?*\r\n]*?\.[A-Za-z0-9]{1,8})["']?(?=$|[\s,;!?)])""")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def route(text):
    """(handler, arg) when the security module should take this request, else None."""
    m = RES["label"].search(text)
    if m:
        return _label, (m.group(1), m.group(2))
    for tool in ("tripwire", "score", "wifi"):
        if RES[tool].search(text):
            return _run, (tool, text)
    if RES["ports"].search(text):
        ip = IP_RE.search(text)
        return _run, ("ports", ip.group(0) if ip else ("router" if re.search(r"\brouter\b", text, re.I) else None))
    for tool in ("connections", "network", "alerts"):
        if RES[tool].search(text):
            return _run, (tool, text)
    if RES["breach"].search(text):
        e = EMAIL_RE.search(text)
        return (_run, ("breach_email", e.group(0))) if e else (_breach_box, None)
    if RES["file"].search(text):
        p = PATH_RE.search(text)
        if p:
            return _run, ("file", p.group(1).strip())
    if RES["link"].search(text):
        u = URL_RE.search(re.sub(r"\s+dot\s+", ".", text, flags=re.I))
        if u and not EMAIL_RE.search(u.group(0)):
            return _run, ("link", u.group(0).rstrip(".,;:!?)\"'"))
        return None                                           # "explain phishing": a question, not a check
    if RES["pc"].search(text):
        return _run, ("pc", text)
    return None


def _breach_box(arg, text):
    """A password may be in the request: it's never logged, remembered or sent anywhere. The HUD opens its own box."""
    return {"kind": "panel", "panel": "breach", "private": True,
            "answer": "Type it into the box on the right. It never leaves this browser tab: only the first five characters of its fingerprint go out."}


def _label(arg, text):
    if config.demo():
        return {"kind": "answer", "answer": f"Very good. That one is “{arg[1].strip(' .')}” from now on. (Demo data: nothing was saved.)", "nodes": []}
    from . import network
    network.label_device(*arg)
    return {"kind": "answer", "answer": f"Very good. That one is “{arg[1].strip(' .')}” from now on.", "nodes": [], "activity": "Named a device"}


def _run(arg, text):
    tool, value = arg
    if config.demo() and tool in demo_data.TOOLS:
        result = demo_data.TOOLS[tool]()
    else:
        result = _real(tool, value, text)
    result["activity"] = f"Security · {result['title']}"
    return result


def _real(tool, value, text):
    from . import files, network, pc, watch, web
    if tool == "pc":
        return pc.pc_check()
    if tool == "wifi":
        return pc.wifi()
    if tool == "connections":
        return pc.connections()
    if tool == "network":
        return network.devices(bool(re.search(r"\b(?:look\s+harder|harder|full\s+scan|thorough|everything)\b", value, re.I)))
    if tool == "ports":
        return network.ports(value)
    if tool == "link":
        return web.check_link(value)
    if tool == "breach_email":
        return web.breach_email(value)
    if tool == "file":
        return files.check_file(value)
    if tool == "alerts":
        return watch.alerts_report()
    if tool == "score":
        return watch.score_report(fresh=bool(re.search(r"\b(?:now|again|fresh|update)\b", value, re.I)))
    if tool == "tripwire":
        kind = "bank" if re.search(r"\bbank", value, re.I) else "crypto" if re.search(r"\b(?:crypto|wallet|seed)", value, re.I) else "passwords"
        if re.search(r"\b(?:remove|delete|disarm|take\s+down)\b", value, re.I):
            name, deleted = watch.remove_tripwire(kind if re.search(r"\b(?:bank|crypto|wallet|seed|password)", value, re.I) else "")
            return watch.tripwire_report(f"The {name} tripwire is disarmed" + (" and the decoy deleted." if deleted else "."))
        if re.search(r"\b(?:set|lay|create|make|add|plant|arm)\b", value, re.I):
            w = watch.set_tripwire(kind)
            return watch.tripwire_report(f"Tripwire set: {w['name']} is waiting in your Downloads folder. Move it to your Desktop or Documents if "
                                         "you like, and don't open it yourself. If anyone does, you'll hear about it.")
        return watch.tripwire_report()
    raise modules.ModuleError("Which check? Your PC, Wi-Fi, network, a link, a file, or your password.")


def _summary():
    if config.demo():
        return demo_data.summary()
    from . import watch
    return watch.summary()


def _breach_range(payload):
    from . import web
    return web.pwned_range(payload)


def start(deliver):
    from . import watch
    watch.start(deliver)


GET_ROUTES = {"/api/security": _summary}
POST_ROUTES = {"/api/security/breach-range": _breach_range}
