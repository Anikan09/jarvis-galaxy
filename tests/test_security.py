"""Security module self-checks. Offline: no network lookups, no real PC state touched."""
import datetime as dt
import ipaddress
import os
import re
import shutil
import socket
import tempfile
import time
import unittest
from unittest import mock

import modules
import modules.security as sec
from core import chat, config, modes, vault
from modules.security import demo_data, files, network, watch, web


class TempData(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="jg-sec-")
        self.patch = mock.patch.object(config, "data_path", lambda name: os.path.join(self.dir, name))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


class RoutingTests(unittest.TestCase):
    CASES = {
        "Is my PC secure?": ("_run", "pc"), "What devices are on my Wi-Fi?": ("_run", "network"), "Any security alerts?": ("_run", "alerts"),
        "What's my PC talking to?": ("_run", "connections"), "Is my Wi-Fi secure?": ("_run", "wifi"), "Any open ports on my router?": ("_run", "ports"),
        "What's my security score?": ("_run", "score"), "Set a tripwire": ("_run", "tripwire"), "Has my password been leaked?": ("_breach_box", None),
        "is my password hunter2 leaked": ("_breach_box", None), "have I been pwned me@example.com": ("_run", "breach_email"),
        r"Is this file safe? C:\x\setup.exe": ("_run", "file"), "Is this link safe? https://paypa1-login.com/x": ("_run", "link"),
        "Name the device 192.168.1.23 Kitchen speaker": ("_label", None)}

    def test_requests_reach_the_right_check(self):
        for text, (handler, tool) in self.CASES.items():
            hit = sec.route(text)
            self.assertIsNotNone(hit, text)
            self.assertEqual(hit[0].__name__, handler, text)
            if tool:
                self.assertEqual(hit[1][0], tool, text)

    def test_questions_stay_questions(self):
        for text in ("explain phishing", "What do my notes say about the launch?", "research batteries", "What ports are open?"):
            self.assertIsNone(sec.route(text), text)

    def test_a_module_that_is_off_takes_nothing(self):
        with mock.patch.object(config, "get", lambda k, d=None: {} if k == "modules" else d):
            self.assertIsNone(modules.route("Is my PC secure?"))


class BreachTests(unittest.TestCase):
    def test_password_box_is_private(self):
        hit = sec.route("is my password hunter2 leaked")
        result = hit[0](hit[1], "is my password hunter2 leaked")
        self.assertTrue(result["private"])
        self.assertNotIn("hunter2", repr(result))

    def test_chat_never_logs_or_remembers_a_password_request(self):
        with mock.patch.object(modules, "route", sec.route), mock.patch.object(chat.activity, "log") as log:
            result = chat.handle("is my password hunter2 leaked", "breach-test")
        self.assertEqual(result["panel"], "breach")
        log.assert_not_called()
        self.assertEqual(chat.SESSIONS.get("breach-test")["history"], [])

    def test_range_takes_only_a_prefix(self):
        for bad in ("hunter2", "5BAA61", "", "zzzzz"):
            with self.assertRaises(modules.ModuleError):
                web.pwned_range({"prefix": bad})


class LinkTests(unittest.TestCase):
    def test_lookalikes(self):
        for host, brand in {"paypa1-login.com": "paypal", "paypal-secure.net": "paypal", "arnazon.de": "amazon",
                            "paypal.com.verify-id.xyz": "paypal", "paypal.com": "", "accounts.google.com": "", "example.com": ""}.items():
            self.assertEqual(web.lookalike(host), brand, host)

    def test_tricks_are_caught_without_opening(self):
        r = web.check_link("http://paypal.com@203.0.113.9/login", age_lookup=False)
        self.assertEqual(r["verdict"], "likely phishing")
        self.assertEqual(web.check_link("https://bit.ly/abc", age_lookup=False)["verdict"], "suspicious")
        self.assertEqual(web.check_link("https://www.wikipedia.org/wiki/Phishing", age_lookup=False)["verdict"], "no red flags")
        self.assertTrue(any("international" in f["text"] for f in web.check_link("https://xn--pypal-4ve.com/", age_lookup=False)["findings"]))

    def test_registered_domain(self):
        self.assertEqual(web.registered_domain("a.b.example.co.uk"), "example.co.uk")


class FileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="jg-files-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_disguised_programs(self):
        with mock.patch.object(files, "signature", lambda p: {}):
            r = files.check_file(self.write("invoice.pdf.exe", b"MZ" + b"\0" * 200), scan=False)
            self.assertEqual(r["verdict"], "dangerous")
            r = files.check_file(self.write("photo.jpg", b"MZ" + b"\0" * 200), scan=False)
            self.assertTrue(any("really a Windows program" in f["text"] for f in r["findings"]))
        self.assertEqual(files.check_file(self.write("notes.txt", b"just text"), scan=False)["verdict"], "looks clean")

    @unittest.skipUnless(os.name == "nt", "download marks are an NTFS feature")
    def test_download_mark(self):
        p = self.write("a.txt", b"x")
        with open(p + ":Zone.Identifier", "w") as f:
            f.write("[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.com/a.txt\n")
        self.assertEqual(files.motw(p).get("HostUrl"), "https://example.com/a.txt")


class NetworkTests(TempData):
    def test_port_check_stays_on_your_own_network(self):
        home = [(ipaddress.ip_network("192.168.178.0/24"), {"gateway": "192.168.178.1"})]
        self.assertEqual(network.allowed("192.168.178.20", home), "192.168.178.20")
        for ip in ("8.8.8.8", "192.168.1.5", "10.0.0.1"):
            with self.assertRaises(modules.ModuleError):
                network.allowed(ip, home)
        with mock.patch.object(config, "get", lambda k, d=None: ["10.10.0.0/16"] if k == "lab_targets" else 2):
            modes.set_expert(True, True)
            try:
                self.assertEqual(network.allowed("10.10.4.20", home), "10.10.4.20")      # lab mode, a listed target
            finally:
                modes.set_expert(False)

    def test_new_devices_and_names(self):
        p = os.path.join(self.dir, "known.json")
        _, new, first = network.remember("r1", {"A4:83:E7:12:34:56": {"ip": "192.168.1.20"}}, path=p)
        self.assertTrue(first and not new)
        _, new, _ = network.remember("r1", {"A4:83:E7:12:34:56": {"ip": "192.168.1.20"}, "B8:27:EB:00:00:01": {"ip": "192.168.1.66"}}, path=p)
        self.assertEqual(new, ["B8:27:EB:00:00:01"])
        self.assertEqual(network.label_device("192.168.1.66", "Raspberry Pi", path=p), "B8:27:EB:00:00:01")

    def test_makers(self):
        table = {"A483E7": "Apple, Inc."}
        self.assertEqual(network.maker("A4:83:E7:12:34:56", table), "Apple, Inc.")
        self.assertTrue(network.maker("DA:A1:19:00:00:01", table).startswith("private address"))

    def test_open_port_seen(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self.assertTrue(network._open("127.0.0.1", s.getsockname()[1]))
        s.close()


class WatchTests(TempData):
    BASE = {"realtime": True, "passive": False, "firewall_off": [], "startup": ["OneDrive = onedrive.exe"], "tasks": ["\\Updater"]}
    OLD = [{"log": "System", "id": 7045, "rid": 1, "at": "2026-11-01 10:00:00", "data": {"ServiceName": "VendorDriver"}}]

    def test_first_run_takes_stock_then_changes_alert_once(self):
        self.assertEqual(watch.check_alerts(lambda s: self.OLD, lambda: dict(self.BASE)), [])
        bad = dict(self.BASE, realtime=False, startup=self.BASE["startup"] + ["Evil = C:\\Temp\\e.exe"], tasks=self.BASE["tasks"] + ["\\SysHelper"])
        events = self.OLD + [
            {"log": "System", "id": 7045, "rid": 2, "at": "2026-11-19 10:00:00", "data": {"ServiceName": "VendorDriver"}},
            {"log": "System", "id": 7045, "rid": 3, "at": "2026-11-19 10:01:00", "data": {"ServiceName": "EvilSvc"}},
            {"log": "Microsoft-Windows-Windows Defender/Operational", "id": 1116, "rid": 9, "at": "2026-11-19 10:02:00",
             "data": {"Threat Name": "Trojan:Win32/Test"}}] + [
            {"log": "Security", "id": 4625, "rid": 100 + i, "at": "2026-11-19 10:03:00", "data": {}} for i in range(4)]
        texts = " | ".join(a["text"] for a in watch.check_alerts(lambda s: events, lambda: dict(bad)))
        for expected in ("Trojan:Win32/Test", "EvilSvc", "Evil = ", "SysHelper", "real-time protection is off", "4 failed Windows logins"):
            self.assertIn(expected, texts)
        self.assertNotIn("VendorDriver", texts)                               # known services don't alert again
        self.assertEqual(watch.check_alerts(lambda s: events, lambda: dict(bad)), [])

    def test_tripwire(self):
        downloads, recent = os.path.join(self.dir, "Downloads"), os.path.join(self.dir, "Recent")
        os.makedirs(downloads)
        os.makedirs(recent)
        with mock.patch.object(watch, "RECENT", recent):
            w = watch.set_tripwire("passwords", downloads, recent)
            w_data = watch._load("tripwires.json", {})
            for v in w_data["wires"].values():
                v["armed"] = (dt.datetime.now() - dt.timedelta(minutes=5)).isoformat(timespec="seconds")
            watch._save("tripwires.json", w_data)
            self.assertEqual(watch.check_tripwires(recent), [])
            with open(os.path.join(recent, "Passwords.lnk"), "wb") as f:
                f.write("C:\\x\\Passwords.txt".encode("utf-16-le"))
            hits = watch.check_tripwires(recent)
            self.assertTrue(hits and hits[0][0] == "high")
            self.assertEqual(watch.check_tripwires(recent), [])
            name, deleted = watch.remove_tripwire("passwords")
            self.assertTrue(deleted and not os.path.exists(w["path"]))

    def test_score(self):
        v, areas = watch.score({"windows": [{"level": "medium", "text": "x"}, {"level": "low", "text": "y"}, {"level": "info", "text": "z"}],
                                "wifi": [], "network": None, "alerts": [], "programs": []})
        self.assertEqual(v, 92)
        self.assertFalse(areas["network"]["checked"])
        self.assertEqual(watch.score({"windows": [{"level": "high", "text": "x"}] * 10})[0], 55)
        watch.refresh_score({"windows": []}, now=1_900_000_000)
        watch.refresh_score({"windows": [], "network": [{"level": "medium", "text": "n"}] * 2}, now=1_900_000_000 + 86400)
        s = watch.summary()
        self.assertEqual((s["score"], s["change"], s["change_why"]), (88, -12, "Network"))


class DemoTests(unittest.TestCase):
    def test_every_demo_result_has_a_verdict_the_hud_colours(self):
        with open(os.path.join(config.VIEWER_DIR, "app.js"), encoding="utf-8") as f:
            js = f.read()
        known = set(re.findall(r"'([a-z ]+)'", js[js.index("const GOOD"):js.index("function reportDrawer")]))
        for name, fn in demo_data.TOOLS.items():
            r = fn()
            self.assertEqual(r["kind"], "report", name)
            self.assertTrue(r["verdict"] in known or r["verdict"] in ("needs attention", "suspicious", "be careful", "worth a look",
                                                                       "new devices", "recent alerts", "fair", "none set"), (name, r["verdict"]))


if __name__ == "__main__":
    unittest.main()
