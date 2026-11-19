"""Is this file safe? What it really is, where Windows says it came from, its digital signature, and a local Microsoft
Defender scan. The file is never uploaded; with a key (abusech_auth_key or virustotal_api_key in the vault) only its
SHA-256 fingerprint is looked up."""
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

import modules
from core import vault

from .common import NO_WINDOW, clean, finding, first_sentence, ps, report, row, verdict

MAX_BYTES = 4 * 1024 ** 3
EXEC = {".exe", ".msi", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk",
        ".jar", ".reg", ".cpl", ".msc", ".iso", ".img", ".vhd", ".vhdx", ".appx", ".msix", ".chm"}
DOCS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".mov", ".csv", ".zip"}
MACRO = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"}
MAGIC = ((b"MZ", "Windows program"), (b"%PDF", "PDF"), (b"PK\x03\x04", "ZIP container"), (b"\xd0\xcf\x11\xe0", "old Office / MSI file"),
         (b"\x7fELF", "Linux program"), (b"Rar!", "RAR archive"), (b"7z\xbc\xaf", "7-Zip archive"), (b"\x89PNG", "PNG image"),
         (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"), (b"{\\rtf", "RTF document"))
ZONES = {"0": "this computer", "1": "local network", "2": "a trusted site", "3": "the internet", "4": "a restricted site"}


def motw(path):
    """Where Windows says the file came from (its Mark of the Web), {} when it has none."""
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as f:
            return dict(line.strip().split("=", 1) for line in f if "=" in line)
    except OSError:
        return {}


def signature(path):
    p = path.replace("'", "''")
    return ps(f"$s = Get-AuthenticodeSignature -LiteralPath '{p}'; [ordered]@{{ status = [string]$s.Status; signer = [string]$s.SignerCertificate.Subject }} "
              "| ConvertTo-Json -Compress", 30) or {}


def defender_scan(path):
    exe = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    if not os.path.isfile(exe):
        return "unavailable", "Defender's scanner isn't installed"
    try:
        r = subprocess.run([exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"], capture_output=True, timeout=180, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable", "the scan didn't finish in time"
    if r.returncode == 2:
        m = re.search(r"Threat\s*:\s*(.+)", r.stdout.decode("utf-8", "replace"))
        return "threat", m.group(1).strip() if m else "a threat"
    return ("clean", "no threats found") if r.returncode == 0 else ("unavailable", f"exit code {r.returncode}")


def hash_lookups(sha):
    out = []
    key = vault.secret("abusech_auth_key")
    if key:
        try:
            req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode(),
                                         headers={"Auth-Key": key, "User-Agent": "JarvisGalaxy/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                d = json.loads(r.read())
            hit = d.get("query_status") == "ok" and d.get("data")
            out.append(("MalwareBazaar", f"known malware: {d['data'][0].get('signature') or 'listed'}" if hit else "not in the malware database",
                        "high" if hit else ""))
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            out.append(("MalwareBazaar", "couldn't be reached", ""))
    key = vault.secret("virustotal_api_key")
    if key:
        try:
            req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": key})
            with urllib.request.urlopen(req, timeout=10) as r:
                stats = json.loads(r.read())["data"]["attributes"]["last_analysis_stats"]
            bad, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            out.append(("VirusTotal", f"{bad} engines say malicious, {sus} suspicious", "high" if bad >= 3 else "medium" if bad or sus else ""))
        except urllib.error.HTTPError as e:
            out.append(("VirusTotal", "never seen before" if e.code == 404 else f"answered {e.code}", ""))
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            out.append(("VirusTotal", "couldn't be reached", ""))
    return out


def check_file(path, scan=True):
    path = os.path.abspath(os.path.expandvars(os.path.expanduser(str(path).strip().strip("\"'"))))
    if not os.path.isfile(path):
        raise modules.ModuleError(f"I can't find a file at {path}.")
    size = os.path.getsize(path)
    if size > MAX_BYTES:
        raise modules.ModuleError("That file is over 4 GB; leave that one to a full Defender scan.")
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        head = fh.read(64)
        h.update(head)
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    sha, name = h.hexdigest(), os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    kind = next((n for m, n in MAGIC if head.startswith(m)), "")
    f = []
    rows = [row("File", name), row("Size", f"{size / 1024:.0f} KB" if size < 1e6 else f"{size / 1e6:.1f} MB"), row("Really is", kind or "unrecognised type"), row("SHA-256", sha)]
    if "\u202e" in name:
        f.append(finding("high", "The name hides a right-to-left trick character: the extension you see isn't the real one."))
    parts = name.lower().split(".")
    if len(parts) >= 3 and "." + parts[-1] in EXEC and "." + parts[-2] in DOCS:
        f.append(finding("high", f"A double extension: it looks like a .{parts[-2]} but it's a .{parts[-1]} that runs code."))
    if kind == "Windows program" and ext in DOCS:
        f.append(finding("high", f"It's named {ext} but is really a Windows program."))
    if ext in EXEC:
        f.append(finding("info", f"{ext} files run code when opened, so where it came from matters."))
    if ext in MACRO:
        f.append(finding("medium", "An Office file that can carry macros. Don't click “Enable content” unless you expected it."))
    z = motw(path)
    where = z.get("HostUrl") or z.get("ReferrerUrl") or ""
    rows.append(row("Came from", (ZONES.get(z.get("ZoneId", ""), "unknown") + (f": {clean(where, 160)}" if where else "")) if z else
                    "no download mark (made here, unpacked, or copied)"))
    if ext in EXEC or kind in ("Windows program", "old Office / MSI file"):
        sig = signature(path)
        st = sig.get("status", "")
        from .pc import signer_name
        signer = signer_name(sig.get("signer"))
        rows.append(row("Digital signature", {"Valid": f"valid, signed by {signer}", "NotSigned": "not signed", "HashMismatch": "BROKEN: changed after signing",
                                              "NotTrusted": f"untrusted signer ({signer})"}.get(st, st or "unknown"),
                        "high" if st in ("HashMismatch", "NotTrusted") else "medium" if st == "NotSigned" else ""))
        if st in ("HashMismatch", "NotTrusted"):
            f.append(finding("high", "Its signature is broken or untrusted: the file was changed, or someone pretends to be the publisher."))
        elif st == "NotSigned" and kind == "Windows program":
            f.append(finding("medium", "The program isn't signed, so there's no proof who made it."))
    if scan:
        st, detail = defender_scan(path)
        rows.append(row("Microsoft Defender", detail, "high" if st == "threat" else ""))
        if st == "threat":
            f.append(finding("high", f"Defender recognises it as {detail}. Don't open it."))
    for source, what, level in hash_lookups(sha):
        rows.append(row(source, what, level))
        if level:
            f.append(finding(level, f"{source}: {what}."))
    v = verdict(f, ("looks clean", "be careful", "dangerous"))
    answer = (f"Don't open that file. {first_sentence(f)}" if v == "dangerous" else f"Nothing malicious found, but be careful. {first_sentence(f)}"
              if v == "be careful" else "That file looks clean: Defender found nothing, and nothing about it is off.")
    return report("file", "File check", name, v, [{"title": "The file", "rows": rows,
                  "note": "The file was never uploaded; at most its fingerprint is looked up, and only with a key."}], f, answer, badge="LOCAL SCAN")
