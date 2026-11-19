"""Links and leaks. A link is never opened: its address is examined, and its domain's age is asked of the registry
(RDAP). A password is checked against Have I Been Pwned by k-anonymity: the browser hashes it and only the first
5 characters of the SHA-1 hash reach the internet. An e-mail address needs a Have I Been Pwned API key
(python -m core.vault set hibp_api_key)."""
import datetime as dt
import json
import re
import urllib.error
import urllib.parse
import urllib.request

import modules
from core import vault

from .common import clean, finding, first_sentence, report, row, verdict

UA = "JarvisGalaxy/1.0"
BRANDS = ("paypal", "apple", "icloud", "microsoft", "outlook", "office", "google", "gmail", "amazon", "netflix", "facebook", "instagram",
          "whatsapp", "linkedin", "dropbox", "docusign", "adobe", "steam", "steamcommunity", "discord", "roblox", "epicgames", "spotify",
          "ebay", "coinbase", "binance", "kraken", "metamask", "dhl", "ups", "fedex", "usps", "royalmail", "sparkasse", "volksbank",
          "commerzbank", "deutschebank", "postbank", "n26", "revolut", "barclays", "hsbc", "lloyds", "natwest", "santander", "chase",
          "wellsfargo", "bankofamerica", "citibank", "americanexpress", "mastercard", "klarna", "vodafone")
CONFUSABLE = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"), ("9", "g"))
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
              "t.ly", "tiny.cc", "s.id", "lnkd.in", "qrco.de"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "cam", "icu",
              "sbs", "cfd", "lol", "bond", "quest", "buzz", "cyou", "shop", "live", "online", "site"}
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp", "co.in", "com.br", "com.tr", "co.za", "com.mx",
             "com.cn", "com.hk", "co.kr", "com.sg", "co.at", "or.at", "co.ie", "gov.ie"}
BAIT_RE = re.compile(r"\b(?:log-?in|sign-?in|verify|account|update|secure|wallet|password|confirm|unlock|suspend\w*|billing|invoice|payment|refund)\b", re.I)


def registered_domain(host):
    parts = host.lower().rstrip(".").split(".")
    return ".".join(parts[-3:]) if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL else ".".join(parts[-2:])


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(host):
    """The brand a host imitates, or ""."""
    reg = registered_domain(host)
    label = reg.split(".")[0]

    def unconfuse(s):
        for a, b in CONFUSABLE:
            s = s.replace(a, b)
        return s
    plain = unconfuse(label.replace("-", ""))
    parts = [unconfuse(p) for p in label.split("-")]          # paypa1-login -> ["paypal", "login"]
    for brand in BRANDS:
        if label == brand:
            return ""
        if len(brand) >= 4 and (plain == brand or (len(brand) >= 6 and _lev(plain, brand) <= 1)):
            return brand
        if len(brand) >= 5 and brand in parts:
            return brand
    sub = host.lower()[:-len(reg)].split(".") if host.lower().endswith(reg) else []
    return next((b for b in BRANDS if len(b) >= 4 and b in sub), "")


def registered_on(domain):
    """The domain's registration date (YYYY-MM-DD) from RDAP, "" when unknown, None when there's no record."""
    try:
        req = urllib.request.Request("https://rdap.org/domain/" + urllib.parse.quote(domain), headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read(1_000_000))
    except urllib.error.HTTPError as e:
        return None if e.code == 404 else ""
    except (urllib.error.URLError, OSError, ValueError):
        return ""
    for e in data.get("events") or []:
        if isinstance(e, dict) and e.get("eventAction") == "registration":
            return str(e.get("eventDate", ""))[:10]
    return ""


def check_link(url, age_lookup=True):
    raw = url.strip()
    parsed = urllib.parse.urlsplit(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise modules.ModuleError("That doesn't look like a link I can read.")
    try:
        shown = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        shown = host
    ip = bool(re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host))
    reg = host if ip else registered_domain(host)
    f, rows = [], [row("Address", clean(raw, 300)), row("Real host", shown), row("Registered domain", reg)]
    if "@" in (parsed.netloc or ""):
        f.append(finding("high", f"The link hides its real destination behind an “@”: it really goes to {host}."))
    if ip:
        f.append(finding("high", "The link goes to a bare IP address instead of a name. Real companies don't send you those."))
    if "xn--" in host or any(ord(c) > 127 for c in parsed.netloc or ""):
        f.append(finding("high", f"The address uses look-alike international letters: it really reads {host}."))
    brand = "" if ip else lookalike(host)
    if brand:
        f.append(finding("high", f"The domain imitates {brand}, but {reg} isn't {brand}'s."))
    if reg in SHORTENERS:
        f.append(finding("medium", "It's a link shortener, so the destination is hidden. I won't open it to find out."))
    tld = reg.rsplit(".", 1)[-1]
    if not ip and tld in RISKY_TLDS:
        f.append(finding("low", f"The .{tld} ending is cheap and common in scams. Not proof, just a nudge."))
    if raw.lower().startswith("http://"):
        f.append(finding("low", "The link isn't encrypted (http, not https)."))
    if host.count(".") >= 4:
        f.append(finding("low", "Unusually many sub-domains, a trick to push the real domain out of view."))
    if BAIT_RE.search(parsed.path + " " + parsed.query + " " + host) and (brand or tld in RISKY_TLDS):
        f.append(finding("medium", "It combines login or payment words with a doubtful domain, the classic phishing recipe."))
    if age_lookup and not ip:
        created = registered_on(reg)
        rows.append(row("Domain registered", created or ("no record" if created is None else "unknown")))
        if created:
            days = (dt.date.today() - dt.date.fromisoformat(created)).days
            if days < 30:
                f.append(finding("high", f"The domain is only {days} days old. Phishing sites rarely live longer than a few weeks."))
            elif days < 180:
                f.append(finding("medium", f"The domain is only {days} days old."))
        elif created is None:
            f.append(finding("medium", "The domain has no registration record: it may not exist (any more)."))
    rows.append(row("Opened?", "No. Only the address was examined."))
    v = verdict(f, ("no red flags", "suspicious", "likely phishing"))
    answer = (f"That looks like phishing. {first_sentence(f)} Don't click it." if v == "likely phishing" else
              f"I'd be careful with that one. {first_sentence(f)}" if v == "suspicious" else
              "No red flags I can see. That isn't a guarantee: if it wants a password or money, go to the site yourself.")
    return report("link", "Phishing check", shown, v, [{"title": "The link", "rows": rows}], f, answer, badge="NOT OPENED")


# ---------- Breaches ----------

PREFIX_RE = re.compile(r"^[0-9A-F]{5}$")


def pwned_range(payload):
    """POST /api/security/breach-range {"prefix"}: the padded Pwned Passwords range for the browser to match itself."""
    prefix = str((payload or {}).get("prefix") or "").upper()
    if not PREFIX_RE.match(prefix):
        raise modules.ModuleError("That isn't a 5-character hash prefix.")
    try:
        req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"User-Agent": UA, "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"range": r.read(3_000_000).decode("ascii", "replace")}
    except (urllib.error.URLError, OSError):
        raise modules.ModuleError("Have I Been Pwned couldn't be reached just now.")


def breach_email(email):
    key = vault.secret("hibp_api_key")
    if not key:
        raise modules.ModuleError("Checking an e-mail address needs a Have I Been Pwned API key: python -m core.vault set hibp_api_key. "
                                  "Passwords need no key: say “check my password”.")
    try:
        req = urllib.request.Request(f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false",
                                     headers={"User-Agent": UA, "hibp-api-key": key})
        with urllib.request.urlopen(req, timeout=10) as r:
            breaches = json.loads(r.read(3_000_000))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise modules.ModuleError({401: "Have I Been Pwned refused the API key.", 429: "Have I Been Pwned says slow down; try in a minute."}
                                      .get(e.code, f"Have I Been Pwned answered {e.code}."))
        breaches = []
    except (urllib.error.URLError, OSError, ValueError):
        raise modules.ModuleError("Have I Been Pwned couldn't be reached just now.")
    breaches = sorted(breaches, key=lambda b: b.get("BreachDate", ""), reverse=True)
    pw = [b for b in breaches if "Passwords" in (b.get("DataClasses") or [])]
    f = ([finding("high", f"{len(pw)} of these breaches included passwords. Change them there, and wherever you reused them.")] if pw else
         [finding("medium", f"The address is in {len(breaches)} breach(es). Expect more phishing aimed at it.")] if breaches else [])
    rows = [row(clean(b.get("Title") or b.get("Name"), 50), f"{b.get('BreachDate', '?')} · " + ", ".join((b.get("DataClasses") or [])[:5]),
                "high" if b in pw else "medium") for b in breaches[:30]]
    answer = (f"That address is in {len(breaches)} known breach{'es' if len(breaches) != 1 else ''}. {first_sentence(f)}" if breaches
              else "Good news: that address isn't in any known breach.")
    return report("breach", "Breach check", email, "breached" if breaches else "not found",
                  [{"title": f"Breaches ({len(breaches)})", "rows": rows or [row("Result", "not in any known breach")]}], f, answer, badge="HAVE I BEEN PWNED")
