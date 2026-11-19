"""Passive recon of a domain or an IP: registration (RDAP), DNS, the TLS certificate, the network owner.

Nothing is scanned or brute-forced; the only contact with the target is one ordinary TLS handshake on port 443.
Registrant names, e-mails, phones and addresses are never shown. Private, loopback and reserved addresses are never
looked up anywhere.
"""
import concurrent.futures
import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

import modules
from modules.security.common import clean, finding, first_sentence, report, row

UA = "JarvisGalaxy/1.0"
TIMEOUT = 8
LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".home", ".corp", ".localhost", ".test", ".invalid", ".example")


def _json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read(1_500_000))


def _days(iso):
    try:
        return (dt.date.fromisoformat(iso[:10]) - dt.date.today()).days
    except (TypeError, ValueError):
        return None


def check_domain(name):
    name = (name or "").strip().lower().rstrip(".")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        raise modules.ModuleError(f"{name} isn't a valid domain name.")
    if "." not in name or name == "localhost" or name.endswith(LOCAL_SUFFIXES):
        raise modules.ModuleError(f"{name} isn't a public domain, so there's nothing to look up.")
    return name


def _vcard(entity, field):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return item
    return None


def _entities(data, role):
    out = []
    for e in data.get("entities") or []:
        if isinstance(e, dict):
            if role in (e.get("roles") or []):
                out.append(e)
            out += _entities(e, role)
    return out


def registration(domain):
    """Registrar, dates, name servers, status, DNSSEC, registrant country. Never the registrant's contacts."""
    try:
        data = _json("https://rdap.org/domain/" + urllib.parse.quote(domain))
    except urllib.error.HTTPError as e:
        return {"error": "no registration record" if e.code == 404 else f"the registry answered {e.code}"}
    except (urllib.error.URLError, OSError, ValueError):
        return {"error": "the registry couldn't be reached"}
    ev = {e.get("eventAction"): str(e.get("eventDate", ""))[:10] for e in data.get("events") or [] if isinstance(e, dict)}
    registrar = next(((_vcard(e, "fn") or [0, 0, 0, ""])[3] for e in _entities(data, "registrar") if _vcard(e, "fn")), "")
    country = ""
    for e in _entities(data, "registrant"):
        adr = _vcard(e, "adr")
        if adr and isinstance(adr[1], dict) and adr[1].get("cc"):
            country = adr[1]["cc"]
    sec = data.get("secureDNS") or {}
    return {"registrar": clean(registrar, 80), "created": ev.get("registration", ""), "expires": ev.get("expiration", ""),
            "name_servers": sorted({str(n.get("ldhName", "")).lower() for n in data.get("nameservers") or [] if n.get("ldhName")})[:8],
            "dnssec": "signed" if sec.get("delegationSigned") else "unsigned" if "delegationSigned" in sec else "", "country": clean(country, 10)}


def dns_records(domain):
    """{type: [values]}; MX, TXT, NS, CAA and DMARC need dnspython (pip install dnspython), A/AAAA work without it."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return {}, "the name doesn't resolve"
        return {"A": sorted({i[4][0] for i in infos if i[0] == socket.AF_INET}), "AAAA": sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})}, \
            "MX, TXT, NS and CAA need dnspython: pip install dnspython"
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    out = {}
    for kind in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            ans = r.resolve(domain, kind, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return {}, "the domain doesn't exist"
        except (dns.exception.DNSException, OSError):
            continue
        vals = []
        for rd in ans:
            if kind == "MX":
                host = str(rd.exchange).rstrip(".")
                vals.append(f"{rd.preference} {host}" if host else "null MX (accepts no mail)")
            elif kind == "TXT":
                vals.append(clean("".join(s.decode("utf-8", "replace") for s in rd.strings), 300))
            else:
                vals.append(str(rd).rstrip("."))
        if vals:
            out[kind] = sorted(vals)[:12]
    try:
        out["DMARC"] = [clean("".join(s.decode() for s in rd.strings), 300) for rd in r.resolve("_dmarc." + domain, "TXT")]
    except (dns.exception.DNSException, OSError):
        pass
    return {k: v for k, v in out.items() if v}, ""


def tls(host):
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as t:
                cert, version = t.getpeercert(), t.version()
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": clean(e.verify_message or str(e), 120)}
    except (ssl.SSLError, OSError):
        return {"ok": False, "error": "no HTTPS answer on port 443", "unreachable": True}
    name = lambda seq: {k: v for rdn in seq or () for k, v in rdn}
    until = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").date().isoformat()
    return {"ok": True, "subject": name(cert.get("subject")).get("commonName", ""), "issuer": name(cert.get("issuer")).get("organizationName", ""),
            "until": until, "days": _days(until), "names": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"], "version": version}


def domain(name):
    name = check_domain(name)
    with concurrent.futures.ThreadPoolExecutor(3) as pool:
        reg_f, dns_f, tls_f = pool.submit(registration, name), pool.submit(dns_records, name), pool.submit(tls, name)
        reg, (recs, dns_note), cert = reg_f.result(), dns_f.result(), tls_f.result()
    f = []
    rows = [row(k, v) for k, v in (("Registrar", reg.get("registrar")), ("Registered", reg.get("created")), ("Expires", reg.get("expires")),
                                   ("Name servers", ", ".join(reg.get("name_servers") or [])), ("DNSSEC", reg.get("dnssec")),
                                   ("Registrant country", reg.get("country")), ("Record", reg.get("error"))) if v]
    age = _days(reg.get("created", ""))
    if age is not None and -age < 90:
        f.append(finding("medium", f"The domain was registered only {-age} days ago. Brand-new domains are a common sign of phishing."))
    dns_rows = [row(k, "\n".join(v)) for k, v in recs.items() if k != "DMARC"] + ([row("Note", dns_note)] if dns_note else [])
    if recs.get("MX") and not any(m.startswith("null MX") for m in recs["MX"]):
        spf = [t for t in recs.get("TXT", []) if t.lower().startswith("v=spf1")]
        if not spf and not dns_note:
            f.append(finding("medium", "It receives mail but has no SPF record, so others can more easily send mail as it."))
        if spf and re.search(r"\+all\b", spf[0]):
            f.append(finding("high", "Its SPF record ends in +all: anyone may send mail as this domain."))
        if not recs.get("DMARC") and not dns_note:
            f.append(finding("medium", "No DMARC policy: receivers aren't told what to do with forged mail."))
        dns_rows.append(row("DMARC", (recs.get("DMARC") or ["missing"])[0]))
    if cert["ok"]:
        risk = "high" if (cert["days"] or 0) < 0 else "medium" if (cert["days"] or 99) < 14 else ""
        tls_rows = [row("Subject", cert["subject"]), row("Issuer", cert["issuer"]), row("Valid until", f"{cert['until']} ({cert['days']} days)", risk),
                    row("Covers", ", ".join(cert["names"][:6]) + (f" (+{len(cert['names']) - 6})" if len(cert["names"]) > 6 else "")),
                    row("Protocol", cert["version"])]
        if risk == "medium":
            f.append(finding("medium", f"The certificate expires in {cert['days']} days."))
    else:
        tls_rows = [row("Result", cert["error"], "" if cert.get("unreachable") else "high")]
        if not cert.get("unreachable"):
            f.append(finding("high", f"The certificate didn't verify: {cert['error']}. Browsers will warn visitors."))
    sections = [{"title": "Registration (RDAP)", "rows": rows or [row("Record", "none")], "note": "Registrant names and contacts are left out by design."},
                {"title": "DNS records", "rows": dns_rows or [row("Records", "none came back")]}, {"title": "TLS certificate", "rows": tls_rows}]
    v = "no issues" if not any(x["level"] in ("high", "medium") for x in f) else "worth a look"
    answer = f"The recon on {name} is in the drawer. " + (f"Worth a look: {first_sentence(f)}" if v == "worth a look" else "Nothing in the public records looks amiss.")
    return report("domain", "Domain recon", name, v, sections, f, answer,
                  {"domain": name, "registration": reg, "dns": recs, "tls": {k: v for k, v in cert.items() if k != "names"}}, badge="PASSIVE")


def ip(addr):
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        raise modules.ModuleError(f"{addr} isn't an IP address.")
    if not a.is_global:
        kind = "loopback" if a.is_loopback else "private" if a.is_private else "reserved"
        return report("ip", "IP intel", str(a), "local", [{"title": "Address", "rows": [row("Address", str(a)), row("Scope", kind)]}],
                      [finding("info", f"{a} is a {kind} address: it has no public record, and nothing was sent off this PC.")],
                      f"That's a {kind} address, so there's no public record, and nothing left this PC.", {"scope": kind}, badge="LOCAL ONLY")
    try:
        ptr = socket.gethostbyaddr(str(a))[0].rstrip(".")
    except (OSError, UnicodeError):
        ptr = ""
    try:
        data = _json("https://rdap.org/ip/" + str(a))
        org = next(((_vcard(e, "fn") or [0, 0, 0, ""])[3] for role in ("registrant", "administrative") for e in _entities(data, role) if _vcard(e, "fn")), "")
        abuse = next(((_vcard(e, "email") or [0, 0, 0, ""])[3] for e in _entities(data, "abuse") if _vcard(e, "email")), "")
        net = {"network": clean(data.get("name") or "", 60), "org": clean(org, 80), "country": data.get("country", ""),
               "range": f"{data.get('startAddress', '')} – {data.get('endAddress', '')}".strip(" –"), "abuse": clean(abuse, 80)}
    except (urllib.error.URLError, OSError, ValueError):
        net = {}
    rows = [row("Address", str(a)), row("Reverse DNS", ptr or "none")] + [row(k.capitalize(), v) for k, v in net.items() if v]
    return report("ip", "IP intel", str(a), "looked up", [{"title": "Who runs it", "rows": rows}], [],
                  f"{a} belongs to {net.get('org') or net.get('network') or 'an unnamed network'}" + (f" in {net['country']}" if net.get("country") else "") + ".",
                  {"address": str(a), "reverse_dns": ptr, **net}, badge="PASSIVE")
