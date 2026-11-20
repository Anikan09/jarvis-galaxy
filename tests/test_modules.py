"""OSINT, workspace and phone module self-checks. Offline: no lookups, no Google, no pushes."""
import os
import re
import unittest
import zlib
from unittest import mock

import modules
import modules.osint as osint
import modules.phone as phone
import modules.workspace as workspace
from core import config, vault
from modules.osint import meta, recon
from modules.workspace import google


class OsintTests(unittest.TestCase):
    def test_routing(self):
        cases = {"whois example.com": ("domain", "example.com"), "who hosts example dot com?": ("domain", "example.com"),
                 "IP reputation 8.8.8.8": ("ip", "8.8.8.8"), r"check the metadata of C:\x\cv.pdf": ("file", r"C:\x\cv.pdf"),
                 r"is C:\p\beach.jpg safe to share?": ("file", r"C:\p\beach.jpg")}
        for text, want in cases.items():
            self.assertEqual(osint.route(text)[1], want, text)
        for text in ("what is whois?", "metadata of notes.md", "tell me about DNS"):
            self.assertIsNone(osint.route(text), text)

    def test_private_addresses_never_leave(self):
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("no lookups for a private address")), \
                mock.patch("socket.gethostbyaddr", side_effect=AssertionError("no reverse DNS either")):
            r = recon.ip("10.1.2.3")
        self.assertEqual(r["verdict"], "local")

    def test_local_names_refused(self):
        for bad in ("localhost", "printer.local", "intranet"):
            with self.assertRaises(modules.ModuleError):
                recon.check_domain(bad)

    def test_registrant_contacts_never_shown(self):
        fake = {"events": [{"eventAction": "registration", "eventDate": "2001-02-03T00:00:00Z"}],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Good Registrar Inc."]]]},
                             {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Jane Private"], ["email", {}, "text", "jane@home.example"],
                                                                             ["adr", {"cc": "GB"}, "text", ["", "", "1 Secret Lane"]]]]}]}
        with mock.patch.object(recon, "_json", lambda url: fake):
            reg = recon.registration("example.com")
        self.assertEqual((reg["registrar"], reg["country"], reg["created"]), ("Good Registrar Inc.", "GB", "2001-02-03"))
        self.assertFalse(re.search("Jane|jane@|Secret", repr(reg)))

    def test_pdf_metadata(self):
        pdf = (b"%PDF-1.4\n1 0 obj\n<< /Author (Jane Q. Example) /Producer (Acrobat \\(R\\)) /CreationDate (D:20240102030405)"
               b" /Title (C:\\\\Users\\\\jdoe\\\\Desktop\\\\draft.docx) >>\nendobj\n%%EOF\n%%EOF\n")
        _, rows = meta.pdf_rows(pdf)
        got = {r["k"]: r["v"] for r in rows + meta._user_folders(rows)}
        self.assertEqual(got["Author"], "Jane Q. Example")
        self.assertEqual(got["Producer"], "Acrobat (R)")
        self.assertIn("Saved revisions", got)
        self.assertEqual(got["User folder in a path"], "jdoe")
        packed = b"%PDF-1.7\n<< /Filter /FlateDecode >>\nstream\n" + zlib.compress(b"<< /Author (Hidden In Stream) >>") + b"\nendstream\n%%EOF\n"
        self.assertEqual({r["k"]: r["v"] for r in meta.pdf_rows(packed)[1]}["Author"], "Hidden In Stream")


class WorkspaceTests(unittest.TestCase):
    def test_routing(self):
        self.assertEqual(workspace.route("Good morning")[1], "briefing")
        self.assertEqual(workspace.route("What needs me?")[1], "triage")
        self.assertEqual(workspace.route("What's on my calendar today?")[1], "calendar")
        self.assertIsNone(workspace.route("Was the morning meeting moved?"))

    def test_categories(self):
        base = {"list_unsubscribe": False, "precedence": "", "auto_submitted": "", "from_addr": "priya@example.com", "snippet": ""}
        self.assertEqual(google.categorize({**base, "subject": "Lunch on Friday?"})[0], "needs_reply")
        self.assertEqual(google.categorize({**base, "subject": "Invoice 2211 due"})[0], "action")
        self.assertEqual(google.categorize({**base, "subject": "Weekly news", "list_unsubscribe": True})[0], "fyi")
        self.assertEqual(google.categorize({**base, "from_addr": "no-reply@example.com", "subject": "Verify your account"})[0], "action")

    def test_only_metadata_is_ever_requested(self):
        calls = []

        class Exec:
            def __init__(self, value):
                self.value = value

            def execute(self):
                return self.value

        class Fake:
            def users(self):
                return self

            def getProfile(self, **kw):
                return Exec({"emailAddress": "me@example.com"})

            def messages(self):
                return self

            def list(self, **kw):
                return Exec({"messages": [{"id": "1"}]})

            def get(self, **kw):
                calls.append(kw)
                return Exec({"internalDate": "0", "snippet": "Hi &amp; hello",
                             "payload": {"headers": [{"name": "From", "value": "Priya <priya@example.com>"}, {"name": "Subject", "value": "Contract?"}]}})
        mails = google.inbox(Fake())
        self.assertEqual(calls[0]["format"], "metadata")                 # never "full" or "raw": no bodies
        self.assertEqual((mails[0]["from_name"], mails[0]["snippet"]), ("Priya", "Hi & hello"))

    def test_demo_day(self):
        with mock.patch.dict(os.environ, {"JARVIS_DEMO": "1"}):
            r = workspace._run("triage", "")
        self.assertIn("2 emails want a reply", r["answer"])


class PhoneTests(unittest.TestCase):
    def setUp(self):
        phone._state.update(last=0.0, pending={}, timer=None)

    def test_messages_carry_no_details(self):
        self.assertEqual(phone.message({"alert": 1}), "Jarvis: 1 security alert. Open Jarvis to see it.")
        self.assertNotIn("Trojan", phone.message({"alert": 3, "notice": 1}))

    def test_push_goes_to_the_private_topic(self):
        sent = []

        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout):
            sent.append((req.full_url, req.data.decode(), req.get_header("Priority")))
            return Resp()
        with mock.patch.object(vault, "secret", lambda name: "jg-test-topic" if name == "phone_topic" else ""):
            self.assertTrue(phone.push("Jarvis: 1 security alert. Open Jarvis to see it.", opener=opener))
        self.assertEqual(sent, [("https://ntfy.sh/jg-test-topic", "Jarvis: 1 security alert. Open Jarvis to see it.", "high")])

    def test_notify_pushes_only_the_count(self):
        with mock.patch.object(phone, "push") as push:
            phone.notify("alert", now=1000.0)
        push.assert_called_once_with("Jarvis: 1 security alert. Open Jarvis to see it.")

    def test_batching(self):
        with mock.patch.object(phone, "push") as push, mock.patch("threading.Timer") as timer:
            phone.notify("alert", now=10_000.0)                          # sent at once
            phone.notify("alert", now=10_010.0)                          # within 5 minutes: waits for the batch
            phone.notify("notice", now=10_020.0)
        self.assertEqual(push.call_count, 1)
        self.assertEqual(phone._state["pending"], {"alert": 1, "notice": 1})
        timer.assert_called_once()

    def test_only_https_servers(self):
        with mock.patch.object(config, "get", lambda k, d=None: {"ntfy_server": "http://example.com"} if k == "phone" else d):
            with self.assertRaises(modules.ModuleError):
                phone.server()


if __name__ == "__main__":
    unittest.main()
