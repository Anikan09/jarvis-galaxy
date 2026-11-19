"""Core self-checks. Offline: no accounts, no brain calls, no real data touched.

    python -m unittest discover -s tests -v
"""
import base64
import datetime as dt
import http.client
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from core import auth, brain, chat, config, modes, notes, reminders, research, server, vault

ROOT = config.ROOT


class TempDir(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="jg-test-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class VaultTests(TempDir):
    def test_round_trip_and_encrypted_on_disk(self):
        p = os.path.join(self.dir, "x.json")
        vault.write_json(p, {"secret": "hunter2"})
        self.assertEqual(vault.read_json(p), {"secret": "hunter2"})
        with open(p, "rb") as f:
            raw = f.read()
        if vault.available():
            self.assertTrue(raw.startswith(vault.MAGIC))
            self.assertNotIn(b"hunter2", raw)

    def test_missing_file_gives_default(self):
        self.assertEqual(vault.read_json(os.path.join(self.dir, "none.json"), []), [])


class AuthTests(TempDir):
    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.dir, "auth.json")
        self.secret = auth.new_secret()
        self.codes, hashes = auth.new_recovery_codes()
        auth.save({"password": auth.hash_password("a long test password", params={"n": 2 ** 10, "r": 8, "p": 1}),
                   "totp_secret": self.secret, "last_step": -1, "recovery": hashes}, self.path)
        self.clock = [1_900_000_000.0]
        self.gate = auth.Gate(self.path, clock=lambda: self.clock[0])

    def code(self):
        return auth.totp(self.secret, int(self.clock[0] // auth.STEP))

    def test_rfc6238_vectors(self):
        key = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(auth.totp(key, 59 // 30), "287082")
        self.assertEqual(auth.totp(key, 1111111109 // 30), "081804")

    def test_login_replay_and_logout(self):
        token, _ = self.gate.login("a long test password", self.code())
        self.assertTrue(self.gate.check(token))
        with self.assertRaises(auth.AuthError):
            self.gate.login("a long test password", self.code())          # the same code twice
        self.gate.logout(token)
        self.assertFalse(self.gate.check(token))

    def test_wrong_password_with_right_code_fails(self):
        with self.assertRaises(auth.AuthError):
            self.gate.login("wrong password!!", self.code())

    def test_lockout_after_five(self):
        for _ in range(auth.FREE_TRIES):
            with self.assertRaises(auth.AuthError):
                self.gate.login("nope nope nope", "000000")
        self.clock[0] += 1
        with self.assertRaisesRegex(auth.AuthError, "Try again in"):
            self.gate.login("a long test password", self.code())

    def test_recovery_code_works_once(self):
        token, notice = self.gate.login("a long test password", self.codes[0])
        self.assertIn("7 left", notice)
        with self.assertRaises(auth.AuthError):
            self.gate.login("a long test password", self.codes[0])

    def test_background_polls_dont_keep_a_session_alive(self):
        token, _ = self.gate.login("a long test password", self.code())
        self.clock[0] += auth.idle_seconds() - 5
        self.assertTrue(self.gate.check(token))                           # a poll: touch=False
        self.clock[0] += 10
        self.assertFalse(self.gate.check(token))

    def test_cookie_flags(self):
        self.assertIn("HttpOnly", auth.cookie("x"))
        self.assertIn("SameSite=Strict", auth.cookie("x"))


class ModeTests(unittest.TestCase):
    def tearDown(self):
        modes.set_expert(False)
        modes.set_private(False)

    def test_toggles(self):
        self.assertIsNotNone(modes.handle("expert mode on"))
        self.assertTrue(modes.expert())
        self.assertIn("EXPERT MODE", modes.rule())
        modes.handle("normal mode")
        self.assertFalse(modes.expert())
        self.assertEqual(modes.rule(), "")
        self.assertIsNone(modes.handle("what is expert mode?"))

    def test_expert_mode_ends_by_itself(self):
        modes.set_expert(True, now=time.time() - 3 * 3600)
        self.assertFalse(modes.expert())

    def test_lab_targets_and_wide_ranges(self):
        with mock.patch.object(config, "get", lambda k, d=None: ["10.10.0.0/16", "0.0.0.0/0", "box.htb"] if k == "lab_targets" else 2):
            modes.set_expert(True, True)
            self.assertTrue(modes.in_lab("10.10.4.20"))
            self.assertTrue(modes.in_lab("x.box.htb"))
            self.assertFalse(modes.in_lab("8.8.8.8"))
            self.assertNotIn("0.0.0.0/0", [str(t) for t in modes.lab_targets()])
            modes.set_expert(False)
            self.assertFalse(modes.in_lab("10.10.4.20"))

    def test_private_mode_declines_tools_instead_of_sending(self):
        modes.set_private(True)
        with self.assertRaises(brain.BrainError) as e:
            brain.call("x", tools="WebSearch")
        self.assertEqual(e.exception.status, 409)
        with self.assertRaises(brain.BrainError):
            research.research("tidal power")


class NotesTests(TempDir):
    def setUp(self):
        super().setUp()
        for rel, body in {"a/Alpha.md": "# Alpha\n\nThe green bean contract with Finca Aurora. See [[Beta]].\n",
                          "b/Beta.md": "# Beta\n\nPriya decides the green bean contract by Friday.\n",
                          "c/Gamma.md": "# Gamma\n\nLatte art workshop on Saturday evenings.\n"}.items():
            os.makedirs(os.path.dirname(os.path.join(self.dir, rel)), exist_ok=True)
            with open(os.path.join(self.dir, rel), "w", encoding="utf-8") as f:
                f.write(body)
        self.patch = mock.patch.object(config, "notes_dir", lambda: self.dir)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        super().tearDown()

    def test_rank_finds_the_right_notes(self):
        self.assertEqual(notes.rank("who decides the bean contract?")[0]["title"], "Beta")

    def test_graph_has_wikilinks(self):
        g = notes.graph()
        self.assertEqual(len(g["nodes"]), 3)
        self.assertIn("link", {l["kind"] for l in g["links"]})

    def test_remember_writes_a_linked_note(self):
        title, related = notes.remember("the latte workshop moves to Sundays from January")
        self.assertTrue(title.startswith("Latte workshop"))
        self.assertEqual(related, "Gamma")
        self.assertTrue(any(f.startswith("Latte workshop") for f in os.listdir(os.path.join(self.dir, "captures"))))


class ParsingTests(unittest.TestCase):
    def test_reminders(self):
        now = dt.datetime(2026, 11, 19, 14, 0)
        self.assertEqual(reminders.parse("remind me in 20 minutes to check the oven", now),
                         (dt.datetime(2026, 11, 19, 14, 20), "check the oven"))
        self.assertEqual(reminders.parse("remind me at 5 to call the bank", now)[0], dt.datetime(2026, 11, 19, 17, 0))
        self.assertEqual(reminders.parse("remind me tomorrow at 9:30 to send it", now)[0], dt.datetime(2026, 11, 20, 9, 30))
        self.assertIsNone(reminders.parse("remind me to breathe", now))

    def test_research_intent_and_unsafe_sources(self):
        self.assertEqual(research.topic("research solid state batteries"), "solid state batteries")
        self.assertIsNone(research.topic("what do my notes say about batteries"))
        answer, sources = research.parse('{"answer": "Hi.", "sources": [{"url": "javascript:alert(1)"}, {"url": "https://ok.example/a"}]}')
        self.assertEqual([s["url"] for s in sources], ["https://ok.example/a"])


class ServerTests(TempDir):
    """A throwaway server on a free port with a throwaway lock. Never the real one."""

    def setUp(self):
        super().setUp()
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.auth_path = os.path.join(self.dir, "auth.json")
        self.secret = auth.new_secret()
        auth.save({"password": auth.hash_password("a long test password", params={"n": 2 ** 10, "r": 8, "p": 1}),
                   "totp_secret": self.secret, "last_step": -1, "recovery": []}, self.auth_path)
        self.patches = [mock.patch.object(server, "port", lambda: self.port), mock.patch.object(auth, "path", lambda: self.auth_path),
                        mock.patch.object(server, "GATE", auth.Gate(self.auth_path)),
                        mock.patch.object(config, "data_path", lambda name: os.path.join(self.dir, name))]
        for p in self.patches:
            p.start()
        import functools
        import http.server
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), functools.partial(server.Handler, directory=config.VIEWER_DIR))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.cookie = ""

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        for p in self.patches:
            p.stop()
        super().tearDown()

    def req(self, method, path, body=None, host=None, origin=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        headers = {"Host": host or f"localhost:{self.port}", "Content-Type": "application/json",
                   "Origin": origin or f"http://localhost:{self.port}", **({"Cookie": self.cookie} if self.cookie else {})}
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def login(self):
        status, headers, _ = self.req("POST", "/auth/login", {"password": "a long test password",
                                                              "code": auth.totp(self.secret, int(time.time() // auth.STEP))})
        self.assertEqual(status, 200)
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]

    def test_everything_is_locked_without_a_session(self):
        status, headers, _ = self.req("GET", "/")
        self.assertEqual((status, headers.get("Location")), (302, "/login"))
        for path in ("/api/graph", "/api/activity", "/api/mode", "/app.js"):
            self.assertEqual(self.req("GET", path)[0], 401, path)
        self.assertEqual(self.req("POST", "/chat", {"text": "hi"})[0], 401)
        self.assertEqual(self.req("GET", "/login")[0], 200)

    def test_foreign_host_and_origin_are_refused(self):
        self.assertEqual(self.req("GET", "/login", host="evil.example")[0], 403)
        self.assertEqual(self.req("POST", "/auth/login", {}, origin="http://evil.example")[0], 403)

    def test_a_session_opens_the_app_and_lock_closes_it(self):
        self.login()
        status, headers, _ = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("script-src 'self' https://cdn.jsdelivr.net", headers.get("Content-Security-Policy", ""))
        self.assertEqual(self.req("GET", "/api/mode")[0], 200)
        status, _, body = self.req("POST", "/chat", {"text": "expert mode on", "session": "t"})
        self.assertEqual((status, json.loads(body)["kind"]), (200, "mode"))
        self.req("POST", "/auth/logout", {})
        self.assertFalse(modes.expert())                               # locking ends expert mode
        self.assertEqual(self.req("GET", "/api/graph")[0], 401)


class PrivacyTests(unittest.TestCase):
    """Nothing in the repo may carry a personal path, address or secret."""

    def test_no_personal_paths_or_addresses(self):
        bad = []
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "data", "__pycache__", "notes")]
            for f in files:
                if not f.endswith((".py", ".js", ".html", ".css", ".md", ".json", ".txt")):
                    continue
                p = os.path.join(root, f)
                with open(p, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                if re.search(r"[A-Za-z]:\\\\?Users\\\\?[A-Za-z]", text) and f != "test_core.py":
                    bad.append((p, "a user folder path"))
                for addr in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}", text):
                    if not re.search(r"(example\.(com|org)|users\.noreply\.github\.com|anthropic\.com)$", addr):
                        bad.append((p, addr))
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
