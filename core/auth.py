"""The lock: a password plus a 6-digit code from an authenticator app (TOTP) before anything works.

data/auth.json (encrypted by the vault) holds the password as a salted scrypt hash, the TOTP secret, and hashed
one-time recovery codes. Without it the server serves only a "set up first" page: it fails closed.

  python -m core.auth --setup    password, authenticator, recovery codes (run it in PowerShell or Windows Terminal)
  python -m core.auth --reset    change both (asks for the current password and a code)
  python -m core.auth --status

Sessions live in memory only (a restart logs everyone out), end after config "idle_minutes" without a request you
made (background refreshes don't count) and after 12 hours regardless. Five wrong tries lock the door for 30 seconds,
doubling each time up to 15 minutes. Each code works once.
"""
import argparse
import base64
import hashlib
import hmac
import secrets
import struct
import sys
import threading
import time

from . import config, vault

COOKIE = "jgalaxy_session"
ISSUER = "Jarvis Galaxy"
MIN_PASSWORD = 12
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
STEP, DRIFT = 30, 1
ABSOLUTE = 12 * 60 * 60
MAX_SESSIONS = 20
FREE_TRIES, LOCK_BASE, LOCK_MAX = 5, 30, 15 * 60
RECOVERY_CODES = 8


class AuthError(Exception):
    """Safe to show on the login page."""


def path():
    return config.data_path("auth.json")


# ---------- Primitives ----------

def hash_password(password, salt=None, params=None):
    salt = salt or secrets.token_bytes(16)
    p = params or SCRYPT
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=p["n"], r=p["r"], p=p["p"], maxmem=128 * 1024 * 1024, dklen=32)
    return {"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(digest).decode(), **p}


def check_password(password, record):
    again = hash_password(password, base64.b64decode(record["salt"]), {k: record[k] for k in ("n", "r", "p")})
    return hmac.compare_digest(again["hash"], record["hash"])


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp(secret, step):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[o:o + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def match_totp(secret, code, now=None, last_step=-1):
    """The time step the code belongs to, or None. A step at or before last_step is a replay."""
    code = "".join(c for c in str(code) if c.isdigit())
    if len(code) != 6:
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for step in range(current - DRIFT, current + DRIFT + 1):
        if step > last_step and hmac.compare_digest(totp(secret, step), code):
            return step
    return None


def _recovery_hash(code):
    return hashlib.sha256(code.strip().lower().replace(" ", "").encode()).hexdigest()


def new_recovery_codes():
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = ["".join(secrets.choice(alphabet) for _ in range(5)) + "-" + "".join(secrets.choice(alphabet) for _ in range(5))
             for _ in range(RECOVERY_CODES)]
    return codes, [_recovery_hash(c) for c in codes]


def otpauth_uri(secret):
    from urllib.parse import quote
    return f"otpauth://totp/{quote(ISSUER)}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits=6&period={STEP}"


def load(p=None):
    try:
        data = vault.read_json(p or path())
    except vault.VaultError:
        return None
    return data if isinstance(data, dict) and data.get("password") and data.get("totp_secret") else None


def save(record, p=None):
    vault.write_json(p or path(), record)


def configured():
    return load() is not None


def idle_seconds():
    try:
        return int(max(5.0, min(float(config.get("idle_minutes", 30)), ABSOLUTE / 60)) * 60)
    except (TypeError, ValueError):
        return 30 * 60


# ---------- The door ----------

class Gate:
    def __init__(self, p=None, clock=time.time):
        self.path, self.clock = p, clock
        self.lock = threading.Lock()
        self.sessions = {}
        self.failures, self.locked_until = 0, 0.0

    def login(self, password, code):
        """(token, notice) or AuthError. Every failure counts toward the lockout, whichever part was wrong."""
        with self.lock:
            now = self.clock()
            if now < self.locked_until:
                raise AuthError(f"Too many wrong attempts. Try again in {int(self.locked_until - now) + 1} seconds.")
            record = load(self.path)
            if record is None:
                raise AuthError("Not set up yet: run  python -m core.auth --setup")
            good_pw = check_password(str(password or "")[:1024], record["password"])
            code = str(code or "").strip()[:64]
            step = recovery = None
            if good_pw:
                if "-" in code or len(code.replace(" ", "")) == 10:
                    h = _recovery_hash(code)
                    recovery = next((x for x in record.get("recovery", []) if hmac.compare_digest(x, h)), None)
                else:
                    step = match_totp(record["totp_secret"], code, now, record.get("last_step", -1))
            if not good_pw or (step is None and recovery is None):
                self.failures += 1
                if self.failures >= FREE_TRIES:
                    self.locked_until = now + min(LOCK_MAX, LOCK_BASE * 2 ** (self.failures - FREE_TRIES))
                raise AuthError("That password or code isn't right.")
            if step is not None:
                record["last_step"] = step
            else:
                record["recovery"] = [x for x in record["recovery"] if x != recovery]
            save(record, self.path)
            self.failures, self.locked_until = 0, 0.0
            token = secrets.token_urlsafe(32)
            if len(self.sessions) >= MAX_SESSIONS:
                del self.sessions[min(self.sessions, key=lambda k: self.sessions[k]["last"])]
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {"created": now, "last": now}
            left = len(record.get("recovery", []))
            return token, (f"Recovery code used: {left} left. Run python -m core.auth --reset if your phone is gone." if recovery else "")

    def check(self, token, touch=False):
        if not token:
            return False
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            s = self.sessions.get(key)
            now = self.clock()
            if not s:
                return False
            if now - s["last"] > idle_seconds() or now - s["created"] > ABSOLUTE:
                del self.sessions[key]
                return False
            if touch:
                s["last"] = now
            return True

    def logout(self, token):
        if token:
            with self.lock:
                self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)


def token_from(cookie_header):
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE and value:
            return value
    return ""


def cookie(token, max_age=ABSOLUTE):
    return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"


# ---------- Pages ----------

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name} · Locked</title><style nonce="{nonce}">
:root{--bg:#040a12;--cyan:#5ee7ff;--text:#e8f6ff;--muted:#7d97a8;--bad:#ffb36b}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:radial-gradient(ellipse at 50% 30%,#0b2236,var(--bg) 70%);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.card{width:min(360px,100%);padding:28px 26px;border-radius:14px;background:rgba(10,24,38,.85);border:1px solid rgba(94,231,255,.25)}
.orb{width:34px;height:34px;margin:0 auto 14px;border-radius:50%;background:radial-gradient(circle,#fff 0 18%,#bff6ff 30%,var(--cyan) 55%,rgba(94,231,255,.15) 72%);box-shadow:0 0 18px rgba(94,231,255,.8)}
h1{margin:0 0 4px;text-align:center;font:700 17px/1.2 Consolas,monospace;letter-spacing:5px;text-transform:uppercase}
p.sub{margin:0 0 22px;text-align:center;color:var(--muted);font:500 11px/1.4 Consolas,monospace;letter-spacing:1.5px;text-transform:uppercase}
label{display:block;margin:0 0 6px;color:var(--muted);font:600 10.5px/1 Consolas,monospace;letter-spacing:1.4px;text-transform:uppercase}
input{width:100%;margin:0 0 16px;padding:11px 12px;border-radius:8px;border:1px solid rgba(94,231,255,.3);background:rgba(0,0,0,.35);color:var(--text);font:15px Consolas,monospace}
input:focus{outline:2px solid var(--cyan);outline-offset:1px}
button{width:100%;padding:12px;border:0;border-radius:8px;cursor:pointer;background:var(--cyan);color:#032029;font:700 12px Consolas,monospace;letter-spacing:3px}
#msg{min-height:20px;margin:12px 0 0;color:var(--bad);font-size:13px;text-align:center}.hint{color:var(--muted);font-size:12px;text-align:center}code{color:var(--cyan)}
</style></head><body>{body}</body></html>"""
LOGIN = """<form class="card" id="f"><div class="orb"></div><h1>{name}</h1><p class="sub">Locked · identify yourself</p>
<label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" required autofocus>
<label for="code">Authenticator code</label><input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required>
<button>UNLOCK</button><p id="msg" role="alert"></p><p class="hint">Lost your phone? Type a recovery code instead.</p></form>
<script nonce="{nonce}">
document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault(); const msg = document.getElementById('msg'); msg.textContent = '';
  try {
    const r = await fetch('/auth/login', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({password: document.getElementById('pw').value, code: document.getElementById('code').value})});
    const d = await r.json().catch(() => ({}));
    if (r.ok) { if (d.notice) sessionStorage.setItem('auth-notice', d.notice); location.replace('/'); return; }
    msg.textContent = d.error || 'That didn’t work.'; document.getElementById('code').value = '';
  } catch (err) { msg.textContent = 'Can’t reach the server.'; }
});
</script>"""
SETUP = """<div class="card"><div class="orb"></div><h1>{name}</h1><p class="sub">Not set up yet</p>
<p>Everything stays locked until there's a password and an authenticator. In the project folder, run:</p>
<p><code>python setup.py</code></p><p class="hint">Then reload this page.</p></div>"""


def page(kind="login"):
    nonce = secrets.token_urlsafe(16)
    name = str(config.get("assistant_name") or "Jarvis")
    body = (LOGIN if kind == "login" else SETUP).replace("{nonce}", nonce).replace("{name}", name)
    return PAGE.replace("{nonce}", nonce).replace("{name}", name).replace("{body}", body).encode("utf-8"), nonce


# ---------- Setup from the terminal ----------

def _ask(prompt):
    import getpass
    return getpass.getpass(prompt)


def _show_qr(uri):
    try:
        import qrcode
    except ImportError:
        return False
    q = qrcode.QRCode(border=2)
    q.add_data(uri)
    q.print_ascii(invert=True)
    return True


def setup(reset=False):
    record = load()
    if record and not reset:
        sys.exit("There's already a lock. Use  python -m core.auth --reset  to change it.")
    if reset:
        if not record:
            sys.exit("No lock to reset yet: run  python -m core.auth --setup")
        pw, code = _ask("Current password: "), input("Current authenticator code (or a recovery code): ").strip()
        if not check_password(pw, record["password"]) or (match_totp(record["totp_secret"], code) is None
                                                           and _recovery_hash(code) not in record.get("recovery", [])):
            sys.exit("That isn't right. Nothing changed.")
    while True:
        pw = _ask(f"Choose a password (at least {MIN_PASSWORD} characters; a few random words work well): ")
        if len(pw) < MIN_PASSWORD:
            print(f"That's {len(pw)} characters. At least {MIN_PASSWORD}, please.")
        elif pw != _ask("Type it again: "):
            print("Those didn't match. Once more.")
        else:
            break
    secret = new_secret()
    print("\nNow add it to your authenticator app (Microsoft Authenticator, Google Authenticator, 2FAS, Aegis...).\n")
    if _show_qr(otpauth_uri(secret)):
        print("Scan the QR code above with the app (make this window bigger if it won't scan), or enter the key below by hand.")
    else:
        print("In the app, choose 'Enter a setup key' (or 'Enter code manually') and type the key below.")
        print("Easier: press Ctrl+C, run  pip install qrcode , then  python setup.py  again, and scan a QR code instead.")
    print(f"\n   Account: {ISSUER}\n   Key:     {secret}\n            (all {len(secret)} characters, without spaces)\n   Type:    time-based\n")
    print(f"   The same key in groups, to check what you typed:  {' '.join(secret[i:i + 4] for i in range(0, len(secret), 4))}")
    print("   It only uses the letters A-Z and the digits 2-7: a 0 is the letter O, a 1 is the letter I, an 8 is the letter B.\n")
    for _ in range(3):
        step = match_totp(secret, input("Type the 6-digit code the app shows now: ").strip())
        if step is not None:
            break
        print("No match. Check the key (no 0, 1, 8 or 9 in it), and that the phone's clock is automatic.")
    else:
        sys.exit("Three misses, so nothing was saved. Delete the entry in your app and run it again.")
    codes, hashes = new_recovery_codes()
    save({"version": 1, "created": time.strftime("%Y-%m-%d %H:%M"), "password": hash_password(pw), "totp_secret": secret,
          "last_step": step, "recovery": hashes})
    print("\nRecovery codes: each works once instead of the 6-digit code if you lose your phone.")
    print("Keep them somewhere that isn't this PC. They won't be shown again.\n")
    print("\n".join("   " + c for c in codes))
    print("\nDone.")


def main():
    p = argparse.ArgumentParser(description="The lock: a password and an authenticator code.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--setup", action="store_true")
    g.add_argument("--reset", action="store_true")
    g.add_argument("--status", action="store_true")
    args = p.parse_args()
    if args.setup or args.reset:
        try:
            setup(reset=args.reset)
        except (KeyboardInterrupt, EOFError):
            sys.exit("\nCancelled. Nothing was saved.")
        return
    r = load()
    print(f"Locked since {r.get('created', '?')}, {len(r.get('recovery', []))} recovery codes left." if r else "No lock yet: python setup.py")


if __name__ == "__main__":
    main()
