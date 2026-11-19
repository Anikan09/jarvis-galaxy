"""Read-only checks of this PC: how Windows is set up, how safe the Wi-Fi is, and which programs are online right now.
Nothing is changed, nothing needs admin rights, nothing is captured."""
import concurrent.futures
import ipaddress
import os
import re
import socket
import subprocess

import modules

from .common import NO_WINDOW, as_list, clean, finding, first_sentence, ps, reg, reg_exists, report, row, startup_items, verdict

# ---------- The PC ----------

PC_SCRIPT = r"""
$o = [ordered]@{}
try { $m = Get-MpComputerStatus -ErrorAction Stop
      $o.defender = [ordered]@{ av = $m.AntivirusEnabled; realtime = $m.RealTimeProtectionEnabled; tamper = $m.IsTamperProtected;
        sig_age = $m.AntivirusSignatureAge; full_age = $m.FullScanAge; mode = [string]$m.AMRunningMode } } catch { $o.defender = $null }
try { $o.av_products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch { $o.av_products = @() }
try { $o.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = [string]$_.Name; on = [bool]$_.Enabled } }) } catch { $o.firewall = $null }
try { $h = Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
      $o.patch_days = [int]((Get-Date) - $h.InstalledOn).TotalDays } catch { $o.patch_days = $null }
try { $o.accounts = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID -like '*-500' -or $_.SID -like '*-501' } | ForEach-Object {
        [ordered]@{ kind = $(if ($_.SID -like '*-500') { 'administrator' } else { 'guest' }); on = [bool]$_.Enabled } }) } catch { $o.accounts = @() }
try { $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
      $o.me_admin = [bool](Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Stop | Where-Object { $_.SID.Value -eq $me }) } catch { $o.me_admin = $null }
try { $o.encryption = (New-Object -ComObject Shell.Application).NameSpace("$env:SystemDrive\").Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch { $o.encryption = $null }
$o | ConvertTo-Json -Depth 4 -Compress
"""
ENCRYPTION = {1: "on", 3: "encrypting", 6: "on", 2: "off", 0: "not available", 4: "decrypting", 5: "suspended"}
SHADY_START_RE = re.compile(r"\\(?:temp|tmp)\\|\\appdata\\local\\temp\\|-enc(?:odedcommand)?\s|frombase64string|\bmshta\b|\bwscript\b|\bcscript\b|\.vbs\b|\\users\\public\\", re.I)


def pc_check():
    if os.name != "nt":
        raise modules.ModuleError("The PC check is for Windows.")
    s = ps(PC_SCRIPT) or {}
    f, rows = [], []
    d = s.get("defender")
    passive = bool(d) and "passive" in str(d.get("mode", "")).lower()
    others = [p for p in s.get("av_products") or [] if "defender" not in p.lower()]
    if d:
        on = bool(d.get("av") and d.get("realtime"))
        rows.append(row("Microsoft Defender", "on" if on else "passive (another antivirus is in charge)" if passive else "OFF", "" if on or passive else "high"))
        if not on and not passive:
            f.append(finding("high", "Defender's real-time protection is off. Fix: Windows Security → Virus & threat protection → Manage settings."))
        if d.get("tamper") is False and not passive:
            f.append(finding("medium", "Tamper Protection is off, so malware could switch Defender off. Turn it on in the same settings page."))
        age = d.get("sig_age")
        if isinstance(age, int) and age > 3 and not passive:
            f.append(finding("medium", f"Defender's definitions are {age} days old. Windows Security → Protection updates → Check for updates."))
        full = d.get("full_age")
        never = not isinstance(full, int) or full > 100000
        rows.append(row("Last full scan", "never" if never else f"{full} day(s) ago"))
        if never and not passive:
            f.append(finding("low", "A full Defender scan has never run. Worth one now and then: Windows Security → Scan options → Full scan."))
    elif not others:
        f.append(finding("high", "I couldn't read any antivirus status. Check Windows Security → Virus & threat protection."))
    if others:
        rows.append(row("Other antivirus", ", ".join(others[:3])))
    off = [p["name"] for p in as_list(s.get("firewall")) if not p.get("on")]
    if s.get("firewall") is not None:
        rows.append(row("Firewall", "OFF for " + ", ".join(off) if off else "on for all networks", "high" if off else ""))
        if off:
            f.append(finding("high", f"The firewall is off for {', '.join(off)} networks. Windows Security → Firewall & network protection."))
    days = s.get("patch_days")
    if isinstance(days, int):
        rows.append(row("Last Windows update", f"{days} days ago", "high" if days > 45 else "medium" if days > 30 else ""))
        if days > 30:
            f.append(finding("high" if days > 45 else "medium", f"The last Windows update was {days} days ago. Settings → Windows Update."))
    if reg_exists("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"):
        f.append(finding("low", "Updates are waiting for a restart to finish installing."))
    enc = ENCRYPTION.get(s.get("encryption"), "unknown")
    rows.append(row("Drive encryption", enc, "" if enc in ("on", "encrypting") else "medium"))
    if enc not in ("on", "encrypting"):
        f.append(finding("medium", "The system drive isn't encrypted by Windows, so a thief can read it. Options: BitLocker (Windows Pro), "
                                   "Device encryption, or VeraCrypt."))
    sb = reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    rows.append(row("Secure Boot", {1: "on", 0: "off"}.get(sb, "unknown"), "medium" if sb == 0 else ""))
    if sb == 0:
        f.append(finding("medium", "Secure Boot is off. Turn it on in the BIOS/UEFI settings."))
    lua = reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    prompt = reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
    uac = lua != 0 and prompt != 0
    rows.append(row("User Account Control", "on" if uac else "weakened", "" if uac else "high"))
    if not uac:
        f.append(finding("high", "User Account Control is off or never asks, so programs get admin rights silently. Search 'UAC' and restore the default."))
    rdp = reg("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    rows.append(row("Remote Desktop", "ON" if rdp == 0 else "off", "medium" if rdp == 0 else ""))
    if rdp == 0:
        f.append(finding("medium", "Remote Desktop accepts connections. If you don't use it: Settings → System → Remote Desktop → off."))
    smb1 = reg("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") == 1 or \
        reg("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start") in (1, 2, 3)
    rows.append(row("SMBv1", "ON" if smb1 else "off", "high" if smb1 else ""))
    if smb1:
        f.append(finding("high", "SMBv1, the old protocol WannaCry spread through, is on. Turn Windows features on or off → untick SMB 1.0."))
    for a in s.get("accounts") or []:
        if a.get("on"):
            f.append(finding("high" if a["kind"] == "guest" else "medium", f"The built-in {a['kind']} account is enabled. Disable it unless you need it."))
    if s.get("me_admin"):
        rows.append(row("Your account", "administrator", "low"))
        f.append(finding("low", "You use an administrator account every day. A standard account for daily use stops a lot of malware."))
    start = startup_items()
    shady = [(n, c) for n, c in start if SHADY_START_RE.search(c)]
    for n, c in shady[:5]:
        f.append(finding("medium", f"Start-up item “{n}” runs from an unusual place: {clean(c, 120)}. Look it up before removing it."))
    sections = [{"title": "Protection", "rows": rows},
                {"title": f"Starts with Windows ({len(start)})", "rows": [row(clean(n, 50), clean(c, 140), "medium" if (n, c) in shady else "")
                                                                         for n, c in start[:25]] or [row("Nothing", "")],
                 "note": "Read-only: nothing was changed, and no admin rights were used."}]
    v = verdict(f, ("secure", "needs attention", "at risk"))
    serious = len([x for x in f if x["level"] in ("high", "medium")])
    answer = ("Your PC passes every check I can make without admin rights." if not serious else
              f"I found {serious} thing{'s' if serious > 1 else ''} worth fixing. The first: {first_sentence(f)} The fixes are in the drawer.")
    return report("pc", "PC security", os.environ.get("COMPUTERNAME", "This PC"), v, sections, f, answer)


# ---------- Wi-Fi ----------

AUTH_KEYS = ("authentication", "authentifizierung", "authentification")
WEAK = {"open": "high", "offen": "high", "ouvert": "high", "wep": "high", "shared": "high", "wpa-personal": "medium", "wpa-enterprise": "medium"}


def _netsh(*args):
    try:
        r = subprocess.run(["netsh", "wlan", *args], capture_output=True, timeout=20, creationflags=NO_WINDOW)
        return r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _fields(block):
    out = {}
    for line in block.splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip().lower() not in out:
            out[k.strip().lower()] = v.strip()
    return out


def parse_networks(text):
    nets = []
    for block in re.split(r"\n(?=SSID \d+\s*:)", text):
        m = re.match(r"SSID \d+\s*:\s*(.*)", block.strip())
        if m:
            f = _fields(block)
            nets.append({"ssid": m.group(1).strip(), "auth": next((f[k] for k in AUTH_KEYS if k in f), ""),
                         "bssids": len(re.findall(r"BSSID \d+\s*:", block))})
    return nets


def auth_risk(auth):
    return WEAK.get((auth or "").lower().split()[0] if auth else "", "")


def wifi():
    if os.name != "nt":
        raise modules.ModuleError("The Wi-Fi check is for Windows.")
    iface = _fields(_netsh("show", "interfaces"))
    ssid = iface.get("ssid", "")
    if not ssid:
        raise modules.ModuleError("This PC isn't on Wi-Fi right now.")
    auth = next((iface[k] for k in AUTH_KEYS if k in iface), "")
    f, risk = [], auth_risk(auth)
    if risk == "high":
        f.append(finding("high", f"Your Wi-Fi uses {auth.split()[0]}: anyone nearby can read or join it. Switch the router to WPA2 or WPA3."))
    elif risk == "medium":
        f.append(finding("medium", "Your Wi-Fi uses old WPA, which can be cracked. Switch the router to WPA2 (AES) or WPA3."))
    elif "tkip" in iface.get("cipher", "").lower():
        f.append(finding("medium", "The network uses TKIP, which is outdated. Set the router to AES (CCMP) only."))
    nearby = parse_networks(_netsh("show", "networks", "mode=bssid"))
    for n in nearby:
        if n["ssid"] == ssid and auth_risk(n["auth"]) and not risk:
            f.append(finding("high", f"A network nearby uses your network's name with {n['auth'] or 'no'} security: a possible evil twin. Don't join it."))
    saved = []
    for name in re.findall(r":\s*(.+?)\s*$", _netsh("show", "profiles").split("User profiles")[-1], re.M)[:30]:
        p = _fields(_netsh("show", "profile", f"name={name}"))
        p_auth = next((p[k] for k in AUTH_KEYS if k in p), "")
        auto = bool(re.search(r"auto", p.get("connection mode", ""), re.I))
        bad = auth_risk(p_auth) == "high" and auto
        if bad:
            f.append(finding("medium", f"Your PC joins the open network “{name}” by itself. Anyone can create one with that name: set it to manual."))
        saved.append(row(clean(name, 40), f"{p_auth or '?'}" + (" · joins automatically" if auto else ""), "medium" if bad else ""))
    sections = [{"title": "Your Wi-Fi", "rows": [row("Network", ssid), row("Security", f"{auth} · {iface.get('cipher', '')}".strip(" ·"), risk)]},
                {"title": f"Networks nearby ({len(nearby)})", "rows": [row(clean(n["ssid"] or "(hidden)", 40), f"{n['auth'] or '?'} · {n['bssids']} access point(s)",
                                                                          auth_risk(n["auth"])) for n in nearby[:20]] or [row("None listed", "")]},
                {"title": f"Saved networks ({len(saved)})", "rows": saved, "note": "Saved Wi-Fi passwords are never read."}]
    v = verdict(f, ("secure", "needs attention", "at risk"))
    answer = f"Your Wi-Fi uses {auth.split()[0] if auth else 'unknown security'}. " + (first_sentence(f) or "No problems found.")
    return report("wifi", "Wi-Fi security", ssid, v, sections, f, answer)


# ---------- What is this PC talking to? ----------

CONN_SCRIPT = r"""
$procs = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = @($_.ProcessName, $_.Path) }
@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0|::$)' } | ForEach-Object {
  $p = $procs[[int]$_.OwningProcess]
  [ordered]@{ name = $(if ($p) { $p[0] } else { '?' }); path = $(if ($p) { [string]$p[1] } else { '' }); remote = [string]$_.RemoteAddress; port = [int]$_.RemotePort } }) | ConvertTo-Json -Compress
"""
SIG_SCRIPT = r"""@(@({paths}) | ForEach-Object { $s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue
  [ordered]@{ path = $_; status = [string]$s.Status; signer = [string]$s.SignerCertificate.Subject } }) | ConvertTo-Json -Compress"""
ODD_DIR_RE = re.compile(r"\\(?:temp|tmp)\\|\\appdata\\local\\temp\\|\\downloads\\|\\users\\public\\", re.I)
ODD_PORTS = {4444: "Metasploit's default", 1337: "a port malware likes", 31337: "a classic backdoor port", 6667: "IRC, used by old botnets",
             5555: "Android debugging", 9001: "Tor", 23: "Telnet, unencrypted"}


def signer_name(subject):
    m = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject or "")
    return (m.group(1) or m.group(2)).strip() if m else ""


def _who(ip):
    try:
        if not ipaddress.ip_address(ip).is_global:
            return "your local network"
    except ValueError:
        return ip
    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".")
    except (OSError, UnicodeError):
        return ip


def connections():
    if os.name != "nt":
        raise modules.ModuleError("This check reads Windows' connection table.")
    rows = as_list(ps(CONN_SCRIPT))
    remotes = sorted({r["remote"] for r in rows})[:60]
    with concurrent.futures.ThreadPoolExecutor(32) as pool:
        names = dict(zip(remotes, pool.map(_who, remotes)))
    paths = sorted({r["path"] for r in rows if r.get("path")})[:40]
    sigs = {r["path"]: r for r in as_list(ps(SIG_SCRIPT.replace("{paths}", ",".join("'" + p.replace("'", "''") + "'" for p in paths)), 90))} if paths else {}
    groups = {}
    for r in rows:
        groups.setdefault((r["name"], r.get("path") or ""), []).append(r)
    f, out = [], []
    for (name, path), conns in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        risk, sig = "", sigs.get(path, {})
        if path and ODD_DIR_RE.search(path):
            risk = "medium"
            f.append(finding("medium", f"{name} is online and runs from an unusual folder: {clean(path, 120)}."))
        if sig.get("status") in ("NotSigned", "HashMismatch", "NotTrusted"):
            risk = risk or ("medium" if sig["status"] == "NotSigned" else "high")
            f.append(finding("medium" if sig["status"] == "NotSigned" else "high",
                             f"{name} is online and its program is " + ("not signed." if sig["status"] == "NotSigned" else "signed, but the signature is broken.")))
        for c in conns:
            if c["port"] in ODD_PORTS:
                lvl = "high" if c["port"] in (4444, 1337, 31337) else "medium"
                risk = lvl if lvl == "high" else risk or lvl
                f.append(finding(lvl, f"{name} is connected to port {c['port']} ({ODD_PORTS[c['port']]}) at {c['remote']}."))
        ends = list(dict.fromkeys(names.get(c["remote"], c["remote"]) for c in conns))
        detail = f"{len(conns)} connection{'s' if len(conns) != 1 else ''} → " + ", ".join(clean(e, 50) for e in ends[:4]) + \
                 (f" +{len(ends) - 4}" if len(ends) > 4 else "") + (f" · signed by {clean(signer_name(sig.get('signer')), 40)}" if signer_name(sig.get("signer")) else "")
        out.append(row(name, detail, risk))
    v = verdict(f, ("all ordinary", "worth a look", "worth a look"))
    answer = ("Nothing is talking to the internet right now." if not groups else
              f"{len(groups)} programs are online. " + (f"One to look at: {first_sentence(f)}" if f else "All of them look ordinary."))
    return report("connections", "Connections", "This PC", v, [{"title": f"Programs online ({len(groups)})", "rows": out[:30] or [row("None", "")],
                  "note": "Read from Windows' connection table. Only remote addresses are looked up (reverse DNS)."}], f, answer)
