"""Demo mode: believable results for the made-up coffee roaster, so screenshots never show a real PC or network."""
import time

from .common import finding, report, row


def _pc():
    f = [finding("medium", "The last Windows update was 34 days ago. Settings → Windows Update."),
         finding("low", "You use an administrator account every day. A standard account for daily use stops a lot of malware.")]
    return report("pc", "PC security", "ROASTERY-LAPTOP", "needs attention", [{"title": "Protection", "rows": [
        row("Microsoft Defender", "on"), row("Firewall", "on for all networks"), row("Last Windows update", "34 days ago", "medium"),
        row("Drive encryption", "on"), row("Secure Boot", "on"), row("User Account Control", "on"), row("Remote Desktop", "off"),
        row("SMBv1", "off"), row("Your account", "administrator", "low")]}], f,
        "I found 1 thing worth fixing. The first: The last Windows update was 34 days ago. The fixes are in the drawer.")


def _network():
    rows = [row("Router", "192.168.178.1 · AVM GmbH · first seen 2026-09-02"), row("Office printer", "192.168.178.20 · HP Inc. · first seen 2026-09-02"),
            row("Kitchen speaker", "192.168.178.31 · Sonos, Inc. · first seen 2026-09-14"),
            row("Priya's phone", "192.168.178.44 · private address (usually a phone or laptop)"),
            row("Till tablet", "192.168.178.52 · Samsung Electronics · first seen 2026-10-01"),
            row("ESP_3A9F21", "192.168.178.57 · Espressif Inc. · first seen today", "medium")]
    return report("network", "Network devices", "192.168.178.0/24", "new devices", [{"title": "Devices (6)", "rows": rows}],
                  [finding("medium", "New device since the last look: ESP_3A9F21 (Espressif Inc., often a smart plug or sensor).")],
                  "6 devices on the network, and 1 I haven't seen before.", {"devices": 6, "new": 1}, badge="YOUR NETWORK")


def _wifi():
    f = [finding("high", "A network nearby uses your network's name with Open security: a possible evil twin. Don't join it.")]
    return report("wifi", "Wi-Fi security", "Roastery-Office", "at risk", [{"title": "Your Wi-Fi", "rows": [row("Network", "Roastery-Office"),
                  row("Security", "WPA2-Personal · CCMP")]}, {"title": "Networks nearby (3)", "rows": [row("Roastery-Office", "WPA2-Personal · 2 access point(s)"),
                  row("Roastery-Office", "Open · 1 access point(s)", "high"), row("Bakery-Guest", "WPA2-Personal · 1 access point(s)")]}], f,
                  "Your Wi-Fi uses WPA2-Personal. A network nearby uses your network's name with Open security: a possible evil twin.")


def _connections():
    f = [finding("medium", "upd_helper is online and runs from an unusual folder: AppData\\Local\\Temp\\upd_helper.exe.")]
    return report("connections", "Connections", "This PC", "worth a look", [{"title": "Programs online (4)", "rows": [
        row("chrome", "14 connections → Google, Cloudflare · signed by Google LLC"), row("Teams", "4 connections → Microsoft · signed by Microsoft Corporation"),
        row("Spotify", "2 connections → Google · signed by Spotify AB"), row("upd_helper", "1 connection → an Amazon cloud server", "medium")]}], f,
        "4 programs are online. One to look at: upd_helper is online and runs from an unusual folder.")


def _ports():
    f = [finding("high", "192.168.178.57 answers on port 23 (Telnet): remote login without encryption, a favourite of IoT malware.")]
    return report("ports", "Open ports", "6 device(s)", "at risk", [{"title": "Open doors", "rows": [
        row("192.168.178.1 (router)", "53 DNS, 80 HTTP, 443 HTTPS"), row("192.168.178.20", "80 HTTP, 9100 Printer", "low"),
        row("192.168.178.57", "23 Telnet, 80 HTTP", "high")]}], f, "I checked 6 devices. Worth fixing: 192.168.178.57 answers on port 23 (Telnet).",
        badge="YOUR NETWORK ONLY")


def _alerts():
    a = [("09:41", "high", "Someone opened your decoy file Passwords.txt at 09:41. If that wasn't you, someone is going through your files."),
         ("yesterday", "medium", "A new service was installed: PrinterHelperSvc. Fine if you just installed something.")]
    return report("alerts", "Security alerts", "This PC", "recent alerts", [{"title": "Recent alerts (2)", "rows": [row(t, x, l) for t, l, x in a]}],
                  [finding(l, x) for _, l, x in a], f"2 recent security alerts. The latest: {a[0][2]}", badge="WATCHING")


def _tripwire():
    return report("tripwire", "Tripwires", "1 decoy file", "triggered", [{"title": "Tripwires", "rows": [
        row("Passwords.txt", "Desktop · armed 2026-11-02 · opened today 09:41", "high")]}],
        [finding("high", "Passwords.txt was opened 1 time(s).")], "One tripwire, and it went off this morning at 09:41.", badge="LOCAL ONLY")


def summary():
    hist = [90 - (1 if i % 7 == 3 else 0) - (6 if i >= 30 else 0) for i in range(48)]
    return {"score": 84, "grade": "good", "at": time.strftime("%H:%M"), "change": -6, "change_why": "Network",
            "top": ["A new device joined the Wi-Fi, and it answers on Telnet."], "history": hist}


def _score():
    s = summary()
    return report("score", "Security score", "84/100", "good", [{"title": "Where the points went", "rows": [
        row("Windows", "-8 of 45", "medium"), row("Wi-Fi", "-15 of 20", "high"), row("Network", "-6 of 15", "medium"),
        row("Alerts", "-15 of 30", "medium"), row("Programs", "-6 of 15", "medium")]}], [finding("high", s["top"][0])],
        "Your security score is 84 out of 100, good. That's down 6 since yesterday, mostly Network.", badge="THIS PC")


TOOLS = {"pc": _pc, "network": _network, "wifi": _wifi, "connections": _connections, "ports": _ports, "alerts": _alerts,
         "tripwire": _tripwire, "score": _score}
