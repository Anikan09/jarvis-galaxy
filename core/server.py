"""The local server: http://localhost:4747, on 127.0.0.1 only. Everything behind the lock except the login page.

  python -m core.server            your Jarvis
  python -m core.server --demo     the made-up demo company (unlocked only while no lock has been set up yet)

GET  /login                      the login page (or "set up first")
GET  /, /app.js, ...             the HUD (viewer/), behind the lock
GET  /api/graph                  the galaxy: {"nodes", "links", "version"}
GET  /api/activity               recent activity, newest first
GET  /api/mode                   {"demo", "expert", "lab", "private", "until", "name", "voice"}
GET  /api/reminders/due          reminders that are due (an open tab speaks them)
POST /auth/login, /auth/logout
POST /chat        {"text", "session"}  ->  {"kind": "answer"|"capture"|"reminder"|"research"|"mode", "answer", ...}
POST /reminders/ack {"ids": [...]}
"""
import functools
import http.server
import json
import os
import re
import sys
import threading
import time

if "--demo" in sys.argv[1:]:
    os.environ["JARVIS_DEMO"] = "1"           # before anything reads a path

from . import activity, auth, brain, chat, config, modes, notes, reminders  # noqa: E402
import modules  # noqa: E402

GATE = auth.Gate()
LAST_TAB = {"at": 0.0}
TAB_GRACE = 150
MAX_BODY = 16_384
CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; media-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def port():
    try:
        return int(config.get("port", 4747))
    except (TypeError, ValueError):
        return 4747


def own_hosts():
    return {f"localhost:{port()}", f"127.0.0.1:{port()}"}


def unlocked_demo():
    """Demo mode before any lock exists: try it out first, on made-up data, from this PC only."""
    return config.demo() and not auth.configured()


class Handler(http.server.SimpleHTTPRequestHandler):
    server_version = "JarvisGalaxy"
    sys_version = ""

    def log_message(self, fmt, *args):            # no request lines with paths in the console
        pass

    def list_directory(self, path):
        self.send_error(404)
        return None

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def send_json(self, status, obj, cookie=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _token(self):
        return auth.token_from(self.headers.get("Cookie", ""))

    def _authed(self, touch=False):
        return unlocked_demo() or GATE.check(self._token(), touch)

    def _page(self, kind):
        body, nonce = auth.page(kind)
        self.send_response(200 if kind == "login" else 503)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
                                                    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, where):
        self.send_response(302)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---------- GET ----------
    def do_HEAD(self):
        self.send_error(405)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if self.headers.get("Host", "") not in own_hosts():
            return self.send_json(403, {"error": "Forbidden host."})
        if path == "/login":
            if unlocked_demo():
                return self._redirect("/")
            if not auth.configured():
                return self._page("setup")
            return self._redirect("/") if GATE.check(self._token()) else self._page("login")
        page = path in ("/", "/index.html")
        if not unlocked_demo() and not auth.configured():
            return self._page("setup") if page else self.send_json(503, {"error": "Not set up yet: python setup.py", "login": True})
        if not self._authed(touch=page):
            return self._redirect("/login") if page or path.endswith(".html") else self.send_json(401, {"error": "Locked.", "login": True})
        try:
            if path == "/api/graph":
                return self.send_json(200, notes.graph())
            if path == "/api/activity":
                return self.send_json(200, {"entries": activity.recent()})
            if path == "/api/mode":
                return self.send_json(200, {**modes.state(), "name": config.get("assistant_name"), "voice": config.get("voice"),
                                            "language": config.get("language"), "locale": config.locale(), "locked": not unlocked_demo()})
            if path == "/api/reminders/due":
                LAST_TAB["at"] = time.time()
                return self.send_json(200, {"due": [{"id": r["id"], "text": r["text"], "kind": r.get("kind", "reminder")} for r in reminders.due()]})
            if path == "/api/modules":
                return self.send_json(200, {"enabled": [m.NAME for m in modules.enabled()]})
            fn = modules.get_route(path)
            if fn:
                return self.send_json(200, fn())
        except (ConnectionError, BrokenPipeError):
            return
        if page:
            self.path = "/index.html"
        if path.endswith(".html") or page:
            self._csp = True
        super().do_GET()

    def send_response(self, code, message=None):
        super().send_response(code, message)
        if getattr(self, "_csp", False):
            self.send_header("Content-Security-Policy", CSP)
            self._csp = False

    # ---------- POST ----------
    def do_POST(self):
        route = self.path.split("?", 1)[0]
        if route not in ("/auth/login", "/auth/logout", "/chat", "/reminders/ack") and not modules.post_route(route):
            return self.send_error(404)
        if self.headers.get("Host", "") not in own_hosts():
            return self.send_json(403, {"error": "Forbidden host."})
        origin = self.headers.get("Origin")
        if origin and origin not in {f"http://{h}" for h in own_hosts()}:
            return self.send_json(403, {"error": "Forbidden origin."})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self.send_json(415, {"error": "Expected application/json."})
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if not 0 <= length <= MAX_BODY:
            return self.send_json(413, {"error": "Too large."})
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}") if length else {}
        except (ValueError, UnicodeDecodeError):
            return self.send_json(400, {"error": "Invalid JSON."})
        payload = payload if isinstance(payload, dict) else {}

        if route == "/auth/login":
            try:
                token, notice = GATE.login(payload.get("password", ""), payload.get("code", ""))
            except auth.AuthError as e:
                activity.log("Failed login attempt")
                return self.send_json(401, {"error": str(e)})
            activity.log("Unlocked")
            return self.send_json(200, {"ok": True, "notice": notice}, cookie=auth.cookie(token))
        if route == "/auth/logout":
            GATE.logout(self._token())
            modes.set_expert(False)                   # locking ends expert mode; private mode stays (it only protects)
            return self.send_json(200, {"ok": True}, cookie=auth.cookie("", 0))
        if not unlocked_demo() and not auth.configured():
            return self.send_json(503, {"error": "Not set up yet: python setup.py", "login": True})
        if not self._authed(touch=True):
            return self.send_json(401, {"error": "Locked.", "login": True})
        try:
            if route == "/reminders/ack":
                ids = {i for i in payload.get("ids") or [] if isinstance(i, str)}
                return self.send_json(200, {"delivered": [{"id": r["id"], "text": r["text"], "kind": r.get("kind", "reminder")}
                                                          for r in reminders.ack(ids)]})
            fn = modules.post_route(route)
            if fn:
                return self.send_json(200, fn(payload))
            session = re.sub(r"[^A-Za-z0-9-]", "", str(payload.get("session", "")))[:64] or "default"
            return self.send_json(200, chat.handle(str(payload.get("text", ""))[:2000], session))
        except brain.BrainError as e:
            return self.send_json(e.status, {"error": str(e)})
        except modules.ModuleError as e:
            return self.send_json(422, {"error": str(e)})
        except (ConnectionError, BrokenPipeError):
            return
        except Exception as e:                        # keep the server alive, say nothing internal
            print(f"{route} failed: {type(e).__name__}")
            return self.send_json(500, {"error": "Something went wrong on the server."})


def _reminder_loop():
    """With no HUD tab listening, due reminders become Windows notifications."""
    while True:
        time.sleep(30)
        try:
            if time.time() - LAST_TAB["at"] < TAB_GRACE:
                continue
            for r in reminders.ack({x["id"] for x in reminders.due()}):
                name = str(config.get("assistant_name") or "Jarvis")
                reminders.toast(f"{name} security alert" if r.get("kind") == "alert" else name, r["text"])
        except Exception as e:
            print(f"Reminders: {type(e).__name__}")


def main():
    notes.all_notes()
    threading.Thread(target=_reminder_loop, name="reminders", daemon=True).start()
    import datetime
    def deliver(text, kind="alert"):
        reminders.add(text, datetime.datetime.now(), kind)       # spoken in an open tab, or a Windows notification
        modules.notify(kind)                                     # and, with the phone module, a content-free push
    modules.start_all(deliver)
    handler = functools.partial(Handler, directory=config.VIEWER_DIR)
    with http.server.ThreadingHTTPServer(("127.0.0.1", port()), handler) as httpd:
        print(f"{config.get('assistant_name')}: http://localhost:{port()}/")
        if config.demo():
            print("DEMO MODE: made-up data from demo/. " + ("Unlocked, because no lock is set up yet." if unlocked_demo() else "Behind your lock."))
        elif not auth.configured():
            print("NOT SET UP: everything stays locked until you run  python setup.py")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
