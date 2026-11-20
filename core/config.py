"""Settings and paths. Everything a running Jarvis writes lives in data/ (git-ignored); config.json holds the settings
you edit by hand (copy config.example.json to start). Missing settings fall back to the defaults below."""
import copy
import json
import os
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT, "config.json")
EXAMPLE_PATH = os.path.join(ROOT, "config.example.json")
DATA_DIR = os.path.join(ROOT, "data")
VIEWER_DIR = os.path.join(ROOT, "viewer")
DEMO_DIR = os.path.join(ROOT, "demo")

DEFAULTS = {
    "assistant_name": "Jarvis",
    "address_user_as": "sir",
    "language": "English",
    "model": "",
    "notes_folder": "notes",
    "port": 4747,
    "idle_minutes": 30,
    "expert_hours": 2,
    "lab_targets": [],
    "voice": "",
    "voice_locale": "",
    "private_brain": {"url": "http://127.0.0.1:11434", "model": "qwen2.5:7b", "fallback": True},
    "modules": {"workspace": False, "security": False, "osint": False, "phone": False},
}

_cache = {"mtime": None, "data": None}
_lock = threading.Lock()


def _merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        out[k] = _merge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out


def load():
    """The settings, re-read whenever config.json changes on disk."""
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        mtime = None
    with _lock:
        if _cache["data"] is None or mtime != _cache["mtime"]:
            data = {}
            if mtime is not None:
                try:
                    with open(CONFIG_PATH, encoding="utf-8") as f:
                        data = json.load(f)
                except (OSError, ValueError):
                    data = {}
            _cache.update(mtime=mtime, data=_merge(DEFAULTS, data if isinstance(data, dict) else {}))
        return _cache["data"]


def get(key, default=None):
    return load().get(key, default)


LOCALES = {"english": "en-GB", "british english": "en-GB", "american english": "en-US", "german": "de-DE", "deutsch": "de-DE",
           "spanish": "es-ES", "french": "fr-FR", "italian": "it-IT", "portuguese": "pt-PT", "dutch": "nl-NL", "polish": "pl-PL",
           "turkish": "tr-TR", "swedish": "sv-SE", "danish": "da-DK", "norwegian": "nb-NO", "japanese": "ja-JP", "korean": "ko-KR",
           "chinese": "zh-CN", "russian": "ru-RU", "arabic": "ar-SA", "hindi": "hi-IN"}


def locale():
    """The voice and microphone language: config "voice_locale" if set, else the one that goes with "language"."""
    return str(get("voice_locale") or LOCALES.get(str(get("language") or "English").strip().lower(), "en-GB"))


def demo():
    return os.environ.get("JARVIS_DEMO") == "1"


def data_path(name):
    """A file in data/ (or data/demo/ in demo mode, so a demo never touches real state)."""
    folder = os.path.join(DATA_DIR, "demo") if demo() else DATA_DIR
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, name)


def notes_dir():
    if demo():                       # a working copy, so "remember that" in a demo never edits the shipped demo notes
        work = os.path.join(DATA_DIR, "demo", "notes")
        if not os.path.isdir(work):
            import shutil
            shutil.copytree(os.path.join(DEMO_DIR, "notes"), work)
        return work
    name = str(get("notes_folder") or "notes")
    return name if os.path.isabs(name) else os.path.join(ROOT, name)
