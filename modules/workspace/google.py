"""Gmail and Google Calendar, read-only, through your own Google Cloud OAuth client.

  python -m modules.workspace.google path\\to\\client_secret.json     sign in once (opens the browser)

The client file and the token are stored encrypted in data/ (vault). Scopes: gmail.readonly and calendar.readonly,
so Jarvis can read but never send, delete or change anything. Only senders, subjects, short previews and dates are
read: never message bodies or attachments.
Needs: pip install google-api-python-client google-auth-oauthlib
"""
import datetime as dt
import email.utils
import html
import json
import re
import sys
import threading

import modules
from core import config, vault

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/calendar.readonly"]
INBOX_QUERY = "in:inbox newer_than:2d (is:unread OR is:important OR is:starred)"
MAX_EMAILS = 40
_lock = threading.Lock()


def _libs():
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
        return Request, Credentials, InstalledAppFlow, build
    except ImportError:
        raise modules.ModuleError("Google needs two packages: pip install google-api-python-client google-auth-oauthlib")


def _token_path():
    return config.data_path("google_token.json")


def credentials():
    Request, Credentials, _, _ = _libs()
    data = vault.read_json(_token_path(), None)
    if not data:
        raise modules.ModuleError("Google isn't connected yet: python -m modules.workspace.google <client file> (see docs/modules/workspace.md).")
    creds = Credentials.from_authorized_user_info(data, SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                raise modules.ModuleError("Google needs signing in again: python -m modules.workspace.google <client file>")
            vault.write_json(_token_path(), json.loads(creds.to_json()))
        else:
            raise modules.ModuleError("Google needs signing in again: python -m modules.workspace.google <client file>")
    return creds


def services():
    _, _, _, build = _libs()
    creds = credentials()
    return build("gmail", "v1", credentials=creds, cache_discovery=False), build("calendar", "v3", credentials=creds, cache_discovery=False)


# ---------- Mail ----------

ACTION_RE = re.compile(r"\b(?:invoice|payment|due|overdue|verify|verification|confirm|sign|signature|deadline|expires?|renew|action required)\b", re.I)
AUTO_RE = re.compile(r"(?:no-?reply|notifications?|mailer-daemon|newsletter|marketing|updates?)@", re.I)


def categorize(m):
    """("needs_reply" | "action" | "fyi", why)"""
    if m["list_unsubscribe"] or m["precedence"] in ("bulk", "list") or m["auto_submitted"] not in ("", "no") or AUTO_RE.search(m["from_addr"]):
        return ("action", "automated, but it asks for something") if ACTION_RE.search(m["subject"]) else ("fyi", "automated or a newsletter")
    if ACTION_RE.search(m["subject"] + " " + m["snippet"]):
        return "action", "asks you to do something"
    return "needs_reply", "a person wrote to you"


def inbox(gmail):
    me = gmail.users().getProfile(userId="me").execute().get("emailAddress", "").lower()
    ids = [x["id"] for x in gmail.users().messages().list(userId="me", q=INBOX_QUERY, maxResults=MAX_EMAILS).execute().get("messages", [])]
    out = []
    for mid in ids:
        r = gmail.users().messages().get(userId="me", id=mid, format="metadata",
                                         metadataHeaders=["From", "Subject", "List-Unsubscribe", "Precedence", "Auto-Submitted"]).execute()
        h = {x["name"].lower(): x["value"] for x in r.get("payload", {}).get("headers", [])}
        name, addr = email.utils.parseaddr(h.get("from", ""))
        if addr.lower() == me:
            continue
        m = {"from_name": name or addr, "from_addr": addr, "subject": h.get("subject", "(no subject)"),
             "snippet": html.unescape(r.get("snippet", ""))[:160], "list_unsubscribe": bool(h.get("list-unsubscribe")),
             "precedence": h.get("precedence", "").lower(), "auto_submitted": h.get("auto-submitted", "").lower(),
             "received": dt.datetime.fromtimestamp(int(r.get("internalDate", "0")) / 1000).strftime("%Y-%m-%d %H:%M")}
        m["category"], m["why"] = categorize(m)
        out.append(m)
    return out


# ---------- Calendar ----------

def _when(v):
    if "dateTime" in v:
        return dt.datetime.fromisoformat(v["dateTime"].replace("Z", "+00:00")).astimezone().strftime("%H:%M")
    return "all day"


def today(calendar):
    start = dt.datetime.combine(dt.date.today(), dt.time()).astimezone()
    items = calendar.events().list(calendarId="primary", timeMin=start.isoformat(), timeMax=(start + dt.timedelta(days=1)).isoformat(),
                                   singleEvents=True, orderBy="startTime", maxResults=50).execute().get("items", [])
    return [{"title": e.get("summary") or "(no title)", "start": _when(e.get("start", {})), "end": _when(e.get("end", {})),
             "calendar": "google"} for e in items if e.get("status") != "cancelled"]


# ---------- Signing in ----------

def login(client_file):
    _, _, InstalledAppFlow, _ = _libs()
    with open(client_file, encoding="utf-8") as f:
        client = json.load(f)
    flow = InstalledAppFlow.from_client_config(client, SCOPES)
    creds = flow.run_local_server(port=0, open_browser=True, prompt="consent")
    vault.write_json(_token_path(), json.loads(creds.to_json()))
    print("Google is connected (read-only). The token is stored encrypted in data/. "
          "You can delete the client file you downloaded now; the token is all Jarvis needs.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("python -m modules.workspace.google path\\to\\client_secret.json")
    try:
        login(sys.argv[1])
    except modules.ModuleError as e:
        sys.exit(str(e))
