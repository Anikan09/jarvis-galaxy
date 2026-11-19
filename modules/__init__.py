"""Optional modules. Each is a package here, off until switched on in config.json "modules", and exposes:

  NAME                      its config key
  route(text) -> None | (handler, arg)
                            claims a request (the core tries enabled modules before answering from notes);
                            handler(arg, text) returns a dict for the HUD ({"kind": "report", ...} draws in the drawer)
  GET_ROUTES  {path: fn}    extra GET endpoints behind the lock, e.g. "/api/security"
  POST_ROUTES {path: fn}    extra POST endpoints behind the lock; fn(payload) -> dict
  start(deliver)            background work; deliver(text, kind="alert") sends a spoken line / Windows notification

A module that fails to import is reported once and skipped, so one broken module never takes the core down.
"""
import importlib

from core import config

KNOWN = ("security",)


class ModuleError(Exception):
    """A refusal or failure that's safe to show and speak (the server answers 422)."""


_loaded = {}


def enabled():
    flags = config.get("modules") or {}
    out = []
    for name in KNOWN:
        if not flags.get(name):
            continue
        if name not in _loaded:
            try:
                _loaded[name] = importlib.import_module(f"modules.{name}")
            except Exception as e:                    # report once, keep the core alive
                print(f"Module {name} couldn't load: {type(e).__name__}: {e}")
                _loaded[name] = None
        if _loaded[name] is not None:
            out.append(_loaded[name])
    return out


def route(text):
    for mod in enabled():
        hit = mod.route(text)
        if hit:
            return hit
    return None


def get_route(path):
    for mod in enabled():
        fn = getattr(mod, "GET_ROUTES", {}).get(path)
        if fn:
            return fn
    return None


def post_route(path):
    for mod in enabled():
        fn = getattr(mod, "POST_ROUTES", {}).get(path)
        if fn:
            return fn
    return None


def start_all(deliver):
    for mod in enabled():
        if hasattr(mod, "start"):
            mod.start(deliver)
