"""Secrets and state, encrypted at rest with Windows DPAPI.

Files written through here hold a "JGALAXY-DPAPI-1" line and then base64 ciphertext. Windows ties the key to your
Windows login: another account, or the files copied to another PC, can't read them. A program running as you still
can (that's how Jarvis reads them too), so this protects against theft, stray uploads and accidental sharing, not
against malware already running as you. On other systems the files are written as plain text, and say so.

Named secrets (API keys) live in data/secrets.json:  python -m core.vault set <name>   (typed hidden, never echoed)
"""
import base64
import json
import os
import sys

from . import config

MAGIC = b"JGALAXY-DPAPI-1\n"
ENTROPY = b"Jarvis Galaxy vault v1"     # a second key part: another program calling DPAPI as you still needs this


class VaultError(Exception):
    """Safe to show."""


def available():
    return os.name == "nt"


def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b):
        buf = ctypes.create_string_buffer(b, len(b))
        return Blob(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    src, _keep1 = blob(data)
    ent, _keep2 = blob(ENTROPY)
    out = Blob()
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out))   # 0x1: no UI
    if not ok:
        raise VaultError("Windows couldn't " + ("encrypt" if protect else "decrypt") + " that (a different Windows login?).")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def encrypt(data):
    if not available():
        return data
    return MAGIC + base64.b64encode(_dpapi(data, True)) + b"\n"


def decrypt(raw):
    """Plaintext of a file's bytes; plain files come back unchanged."""
    if not raw.startswith(MAGIC):
        return raw
    if not available():
        raise VaultError("This file is encrypted with Windows DPAPI and can only be read on Windows.")
    return _dpapi(base64.b64decode(raw[len(MAGIC):].strip()), False)


def is_encrypted(path):
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def read_text(path):
    with open(path, "rb") as f:
        return decrypt(f.read()).decode("utf-8")


def write_text(path, text):
    """Encrypted (where DPAPI exists), written atomically."""
    data = encrypt(text.encode("utf-8"))
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def read_json(path, default=None):
    try:
        return json.loads(read_text(path))
    except FileNotFoundError:
        return default
    except (ValueError, UnicodeDecodeError):
        raise VaultError(f"{os.path.basename(path)} is damaged.")


def write_json(path, obj):
    write_text(path, json.dumps(obj, indent=1, ensure_ascii=False))


# ---------- Named secrets ----------

def _secrets_path():
    return config.data_path("secrets.json")


def secret(name):
    data = read_json(_secrets_path(), {}) or {}
    return str(data.get(name) or "").strip()


def put(name, value):
    data = read_json(_secrets_path(), {}) or {}
    data[name] = value
    write_json(_secrets_path(), data)


def main(argv):
    if argv[:1] == ["set"] and len(argv) == 2:
        import getpass
        value = getpass.getpass(f"{argv[1]} (hidden): ").strip()
        if not value:
            sys.exit("Nothing typed; nothing saved.")
        put(argv[1], value)
        print(f"Saved {argv[1]}" + (" (encrypted)." if available() else " (plain text: DPAPI needs Windows)."))
    elif argv[:1] == ["list"]:
        print("\n".join(sorted(read_json(_secrets_path(), {}) or {})) or "No secrets stored.")
    else:
        print("python -m core.vault set <name>   |   python -m core.vault list")


if __name__ == "__main__":
    main(sys.argv[1:])
