"""Your own network: which devices are on it (and which are new), and which doors your own devices leave open.

Devices: read from this PC's own neighbour table, named by local DNS, maker from the public IEEE list (downloaded once,
refreshed every 90 days). "Look harder" first sends one empty packet to each address of your own private subnet
(at most 254), so every device that's on shows up; no ports are probed. Devices are remembered per network,
encrypted, so new ones stand out.

Ports: ordinary connection attempts to 26 common ports, only on your own private network (or, in lab mode, your
lab_targets). Any other address is refused in code.
"""
import concurrent.futures
import csv
import io
import ipaddress
import json
import os
import re
import socket
import time
import urllib.request

import modules
from core import config, modes, vault

from .common import as_list, clean, finding, first_sentence, ps, report, row, verdict

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_MAX_AGE = 90 * 86400
MAX_HOSTS = 254
VIRTUAL_RE = re.compile(r"wireguard|nordlynx|tap-|\btun\b|vpn|virtual|hyper-v|vmware|virtualbox|loopback|bluetooth|wsl|docker|vethernet|tailscale", re.I)
ADAPTER_SCRIPT = r"""@(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | ForEach-Object {
  [ordered]@{ alias = $_.InterfaceAlias; desc = $_.InterfaceDescription; index = $_.InterfaceIndex; ip = @($_.IPv4Address)[0].IPAddress;
              prefix = @($_.IPv4Address)[0].PrefixLength; gateway = @($_.IPv4DefaultGateway)[0].NextHop } }) | ConvertTo-Json -Compress"""
NEIGHBOUR_SCRIPT = r"""@(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex {index} -ErrorAction SilentlyContinue |
  Where-Object { $_.State -notin 'Unreachable','Incomplete' } | ForEach-Object { [ordered]@{ ip = $_.IPAddress; mac = $_.LinkLayerAddress } }) | ConvertTo-Json -Compress"""
PORTS = {21: ("FTP", "medium", "file transfer without encryption"), 22: ("SSH", "", "remote login (encrypted)"),
         23: ("Telnet", "high", "remote login without encryption, a favourite of IoT malware"), 25: ("SMTP", "low", "a mail server"),
         53: ("DNS", "", "name lookups"), 80: ("HTTP", "low", "a web page, often an admin login"), 139: ("NetBIOS", "low", "old Windows sharing"),
         443: ("HTTPS", "", "an encrypted web page"), 445: ("SMB", "low", "Windows file sharing"), 554: ("RTSP", "medium", "a camera stream, often without a password"),
         1883: ("MQTT", "medium", "smart-home messages, often without a password"), 3306: ("MySQL", "medium", "a database"),
         3389: ("Remote Desktop", "medium", "remote control of a Windows PC"), 5000: ("Web/NAS", "low", "often a NAS admin page"),
         5001: ("Web/NAS TLS", "low", "often a NAS admin page"), 5432: ("PostgreSQL", "medium", "a database"),
         5900: ("VNC", "high", "remote screen control, often weakly protected"), 6379: ("Redis", "high", "a database that usually has no password"),
         7547: ("TR-069", "medium", "the provider's remote management"), 8080: ("HTTP-alt", "low", "a second web page"),
         8443: ("HTTPS-alt", "low", "a second admin page"), 8888: ("HTTP-alt", "low", "a web interface"), 9100: ("Printer", "low", "raw printing"),
         27017: ("MongoDB", "high", "a database that's often open"), 49000: ("TR-064", "", "a router's control interface"),
         1900: ("UPnP", "low", "device discovery")}
ROUTER_NORMAL = {53, 80, 443, 1900, 5000, 8080, 8443, 49000}


# ---------- Makers ----------

_oui = None


def oui_table(download=True):
    global _oui
    if _oui is not None:
        return _oui
    path = config.data_path("oui.json")
    if download and not (os.path.isfile(path) and time.time() - os.path.getmtime(path) < OUI_MAX_AGE):
        try:
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": "JarvisGalaxy/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                text = r.read(8_000_000).decode("utf-8", "replace")
            table = {x[1].upper(): x[2].strip() for x in csv.reader(io.StringIO(text)) if len(x) > 2 and len(x[1]) == 6}
            if len(table) > 10000:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(table, f)
        except Exception:
            pass                                       # offline: older copy, or no makers
    try:
        with open(path, encoding="utf-8") as f:
            _oui = json.load(f)
    except (OSError, ValueError):
        _oui = {}
    return _oui


def norm_mac(mac):
    h = re.sub(r"[^0-9A-Fa-f]", "", str(mac or "")).upper()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def randomised(mac):
    return bool(mac) and int(mac[1], 16) & 0x2 == 2


def maker(mac, table=None):
    if not mac:
        return ""
    if randomised(mac):
        return "private address (usually a phone or laptop)"
    return clean((table if table is not None else oui_table()).get(mac.replace(":", "")[:6], ""), 50) or "unknown maker"


# ---------- Seeing the network ----------

def adapters():
    return [a for a in as_list(ps(ADAPTER_SCRIPT)) if a.get("ip") and not VIRTUAL_RE.search(f"{a.get('alias', '')} {a.get('desc', '')}")]


def neighbours(a):
    net = ipaddress.ip_network(f"{a['ip']}/{a['prefix']}", strict=False)
    out = {}
    for r in as_list(ps(NEIGHBOUR_SCRIPT.replace("{index}", str(int(a["index"]))))):
        try:
            ip = ipaddress.ip_address(r.get("ip", ""))
        except ValueError:
            continue
        mac = norm_mac(r.get("mac"))
        if ip in net and ip not in (net.network_address, net.broadcast_address) and mac and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") \
                and not mac.startswith(("01:00:5E", "33:33")):
            out[str(ip)] = mac
    return out


def knock(a):
    """One empty UDP packet to each address of your own private subnet, so every device that's on answers the PC's ARP."""
    net = ipaddress.ip_network(f"{a['ip']}/{a['prefix']}", strict=False)
    if not net.is_private:
        raise modules.ModuleError("That network isn't a private home network, so I won't knock on its doors.")
    if net.num_addresses > MAX_HOSTS + 2:
        net = ipaddress.ip_network(f"{a['ip']}/24", strict=False)
    hosts = [str(h) for h in net.hosts() if str(h) != a["ip"]][:MAX_HOSTS]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for h in hosts:
            try:
                s.sendto(b"", (h, 9))                  # port 9, "discard": nothing listens, nothing happens
            except OSError:
                pass
    time.sleep(2.5)
    return len(hosts)


def _name(ip):
    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".")
    except (OSError, UnicodeError):
        return ""


# ---------- Remembering devices ----------

def _known_path():
    return config.data_path("known_devices.json")


def remember(network_id, seen, now=None, path=None):
    now = now or time.strftime("%Y-%m-%d %H:%M")
    path = path or _known_path()
    known = vault.read_json(path, {}) or {}
    first = network_id not in known
    net = known.setdefault(network_id, {"first": now, "devices": {}})
    new = []
    for mac, d in seen.items():
        rec = net["devices"].get(mac)
        if rec is None:
            rec = net["devices"][mac] = {"first": now, "label": ""}
            if not first:
                new.append(mac)
        rec.update(last=now, ip=d["ip"], name=d.get("name") or rec.get("name", ""))
    vault.write_json(path, known)
    return net, new, first


def label_device(target, label, path=None):
    label = clean(label, 40).strip(" .\"'“”")
    path = path or _known_path()
    known = vault.read_json(path, {}) or {}
    for net in known.values():
        for mac, rec in net.get("devices", {}).items():
            if mac == norm_mac(target) or rec.get("ip") == target:
                rec["label"] = label
                vault.write_json(path, known)
                return mac
    raise modules.ModuleError(f"I don't know a device at {target} yet. Ask what's on your Wi-Fi first.")


def devices(harder=False):
    if os.name != "nt":
        raise modules.ModuleError("The network look is for Windows.")
    found = adapters()
    if not found:
        raise modules.ModuleError("This PC isn't on a network right now (VPN adapters don't count).")
    a = found[0]
    knocked = knock(a) if harder else 0
    table = neighbours(a)
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        names = dict(zip(table, pool.map(_name, table)))
    gw_mac = table.get(a["gateway"], "")
    net, new, first = remember(gw_mac or f"gw-{a['gateway']}", {mac: {"ip": ip, "name": names.get(ip, "")} for ip, mac in table.items()})
    oui = oui_table()
    rows = []
    for ip, mac in sorted(table.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))):
        rec = net["devices"].get(mac, {})
        title = rec.get("label") or rec.get("name") or ("Router" if ip == a["gateway"] else ip)
        rows.append(row(clean(title, 50), " · ".join(x for x in (ip if title != ip else "", maker(mac, oui), mac, f"first seen {rec.get('first', '')[:10]}") if x),
                        "medium" if mac in new else ""))
    f = [finding("medium", f"New device since the last look: {names.get(net['devices'][m]['ip']) or net['devices'][m]['ip']} ({maker(m, oui)}). "
                           "If you don't recognise it, check your router's device list.") for m in new]
    if first:
        f.append(finding("info", f"First look at this network: {len(table)} device(s) remembered. Next time, new ones are flagged."))
    if not harder and len(table) <= 3:
        f.append(finding("info", "Only a few devices so far. Say “look harder” to find everything that's switched on."))
    netw = ipaddress.ip_network(f"{a['ip']}/{a['prefix']}", strict=False)
    sections = [{"title": "Network", "rows": [row("Network", f"{netw} via {a['alias']}"), row("This PC", a["ip"]),
                                              row("Router", f"{a['gateway']} · {maker(gw_mac, oui) if gw_mac else '?'}")]},
                {"title": f"Devices ({len(table)})", "rows": rows or [row("Nothing", "no devices in the neighbour table")],
                 "note": (f"Looked harder: one empty packet to each of {knocked} addresses on your subnet; no ports probed. " if harder
                          else "Passive: nothing was sent to any device. ") + "Name one: “name the device 192.168.1.23 Kitchen speaker”."}]
    v = "first look" if first else "new devices" if new else "all known"
    n = len(table)
    answer = (f"{n} devices on the network, and {len(new)} I haven't seen before." if new else
              f"I can see {n} device{'s' if n != 1 else ''} and I've made a note of {'them' if n != 1 else 'it'}." if first else
              f"{n} device{'s' if n != 1 else ''} on the network, all familiar.")
    return report("network", "Network devices", str(netw), v, sections, f, answer, {"devices": n, "new": len(new)}, badge="YOUR NETWORK")


# ---------- Ports ----------

def own_networks():
    nets = []
    for a in adapters():
        try:
            net = ipaddress.ip_network(f"{a['ip']}/{a['prefix']}", strict=False)
        except ValueError:
            continue
        if net.is_private:
            nets.append((net, a))
    return nets


def allowed(ip, nets):
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        raise modules.ModuleError(f"{ip} isn't an IP address.")
    if addr.is_loopback or modes.in_lab(str(addr)) or any(addr in net for net, _ in nets):
        return str(addr)
    raise modules.ModuleError(f"{addr} isn't on your own network, so I won't check its ports. This tool is for your own devices only.")


def _open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.7):
            return True
    except OSError:
        return False


def ports(target=None):
    nets = own_networks()
    if target == "router":
        target = nets[0][1]["gateway"] if nets else None
    if target:
        targets = [allowed(target, nets)]
    else:
        targets = [ip for net, a in nets for ip in neighbours(a)]
        if not targets:
            raise modules.ModuleError("I don't know any devices on your network yet. Ask what's on your Wi-Fi first, and say look harder.")
    targets = targets[:64]
    with concurrent.futures.ThreadPoolExecutor(min(128, len(targets) * len(PORTS))) as pool:
        futures = {(ip, p): pool.submit(_open, ip, p) for ip in targets for p in PORTS}
    found = {}
    for (ip, p), fut in futures.items():
        if fut.result():
            found.setdefault(ip, []).append(p)
    gateways = {a["gateway"] for _, a in nets}
    f, rows = [], []
    for ip in targets:
        open_ = sorted(found.get(ip, []))
        router = ip in gateways
        worst = ""
        for p in open_:
            name, risk, why = PORTS[p]
            if router and p in ROUTER_NORMAL:
                risk = ""
            if risk in ("high", "medium"):
                f.append(finding(risk, f"{ip}{' (router)' if router else ''} answers on port {p} ({name}): {why}. Switch it off if you don't use it; "
                                       "otherwise give it a strong password."))
                worst = "high" if risk == "high" or worst == "high" else "medium"
        rows.append(row(ip + (" (router)" if router else ""), ", ".join(f"{p} {PORTS[p][0]}" for p in open_) or "no common doors open", worst))
    v = verdict(f, ("secure", "needs attention", "at risk"))
    answer = f"I checked {len(targets)} device{'s' if len(targets) != 1 else ''}. " + (f"Worth fixing: {first_sentence(f)}" if f else "No risky doors open.")
    return report("ports", "Open ports", f"{len(targets)} device(s)", v, [{"title": "Open doors", "rows": rows,
                  "note": f"Connection attempts to {len(PORTS)} common ports, on your own network only. Nothing was logged into."}], f, answer,
                  badge="YOUR NETWORK ONLY")
