"""The local model (Ollama) behind private mode. Only ever on this PC: a configured address anywhere else is refused."""
import json
import threading
import urllib.error
import urllib.parse
import urllib.request

from . import config

TIMEOUT = 180
_local = threading.local()


class LocalError(Exception):
    """Safe to show."""


def _cfg():
    return config.get("private_brain") or {}


def url():
    u = str(_cfg().get("url") or "http://127.0.0.1:11434").rstrip("/")
    if (urllib.parse.urlsplit(u).hostname or "") not in ("127.0.0.1", "localhost", "::1"):
        raise LocalError("private_brain.url must point at this PC (127.0.0.1).")
    return u


def model():
    return str(_cfg().get("model") or "qwen2.5:7b")


def fallback_enabled():
    return _cfg().get("fallback", True) is not False


def _req(path, body=None, timeout=5):
    req = urllib.request.Request(url() + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
        return json.loads(r.read(20_000_000) or b"{}")


def status():
    try:
        names = [m.get("name", "") for m in _req("/api/tags", timeout=3).get("models") or []]
    except (urllib.error.URLError, OSError, ValueError, LocalError):
        return {"running": False, "model": model(), "model_ready": False}
    want = model()
    return {"running": True, "model": want, "model_ready": any(n == want or n == want + ":latest" for n in names)}


def ask(prompt, system="", timeout=TIMEOUT):
    s = status()
    if not s["running"]:
        raise LocalError("The private brain isn't running. Start Ollama, then ask again.")
    if not s["model_ready"]:
        raise LocalError(f"The private brain has no {s['model']} model yet: ollama pull {s['model']}")
    body = {"model": s["model"], "stream": False, "options": {"temperature": 0.3},
            "messages": ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]}
    try:
        reply = _req("/api/chat", body, timeout=timeout)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise LocalError(f"The private brain didn't answer ({type(e).__name__}).")
    _local.used = True
    return str((reply.get("message") or {}).get("content") or "").strip()


def consume_used():
    used = getattr(_local, "used", False)
    _local.used = False
    return used
