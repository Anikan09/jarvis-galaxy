# Security module

Your PC, your network and your files, checked and watched. Read-only, kept to what's yours, and honest about what
leaves the PC.

**Switch it on** in `config.json`:

```json
"modules": { "security": true }
```

Restart the server. A **Security** gauge appears in the HUD's left column, and these requests start working:

| Say | What happens | What leaves the PC |
|---|---|---|
| "Is my PC secure?" | Defender, firewall, updates, drive encryption, Secure Boot, UAC, Remote Desktop, SMBv1, built-in accounts, start-up programs. No admin rights, nothing changed. | Nothing |
| "Is my Wi-Fi secure?" | Your encryption (open, WEP, WPA, WPA2, WPA3), evil twins nearby, saved open networks that auto-join. Saved passwords are never read. | Nothing |
| "What's my PC talking to?" | Every program with an internet connection, who's on the other end, and the odd ones (running from Temp or Downloads, unsigned, malware-favourite ports). | Reverse-DNS lookups of the remote addresses |
| "What devices are on my Wi-Fi?" | The devices on your own network, their makers, and which are new. Add "look harder" to find everything that's switched on. "Name the device 192.168.1.23 Kitchen speaker" labels one. | Once: the public IEEE maker list is downloaded (refreshed every 90 days) |
| "Any open ports on my router?" / "Port check 192.168.1.40" | Which of 26 common services your own devices answer on (Telnet, admin pages, cameras, databases...). | Nothing beyond your own network |
| "Is this link safe? …" | Look-alike brands, hidden destinations, international look-alike letters, shorteners, fresh domains. **The link is never opened.** | The domain name, to the public RDAP registry (for its age) |
| "Has my password been leaked?" | Opens a box in the drawer. Your browser hashes the password; only 5 characters of the hash leave the PC, and your browser does the matching. Typed into the main box by mistake, it's never logged or remembered. | 5 hex characters, to Have I Been Pwned |
| "Have I been pwned me@example.com" | The breaches that address appears in. Needs a key: `python -m core.vault set hibp_api_key` (paid). | The address, to Have I Been Pwned |
| "Is this file safe? C:\…\setup.exe" | What it really is (`invoice.pdf.exe`, a program named `.jpg`), where it was downloaded from, its signature, and a local Defender scan. | Nothing; with a key (`abusech_auth_key` or `virustotal_api_key`), the SHA-256 fingerprint only, never the file |
| "Any security alerts?" | The recent alerts from the watcher below. | Nothing |
| "Set a tripwire" / "Set a bank tripwire" / "Show my tripwires" / "Remove the tripwire" | A decoy file (fake passwords, bank details or a wallet phrase) in Downloads. When anyone opens it the normal way, you get an alert. Move it to your Desktop if you like: it's watched by name. Never open it yourself. | Nothing |
| "What's my security score?" | The breakdown behind the gauge; "…again" works it out fresh. | As the checks above |

## Running in the background

While the server runs, the module watches without being asked, and an alert is **spoken** in an open HUD tab or
shown as a **Windows notification** when none is open:

- **Every 5 minutes:** Microsoft Defender detections, Defender or the firewall switched off, new services (once per
  name, so updaters reinstalling their drivers don't nag), new start-up programs, new scheduled tasks outside
  Microsoft's folder, and three or more failed Windows logins. The very first check only takes stock.
- **Every 30 seconds:** tripwires.
- **Every hour:** the security score (0–100) and its history, for the gauge. High findings cost 15 points, medium 6,
  low 2, and each area can only lose so much.

Demo mode (`--demo`) shows made-up results and never watches the real PC.

## Hard limits, enforced in code

- The port check refuses any address outside your own private network. In lab mode it also accepts your
  `lab_targets`, and nothing else.
- "Look harder" sends one empty packet to each address of your own private subnet (at most 254) and refuses on a
  network that isn't private. No ports are probed.
- Links are never opened. Files are never uploaded.
- A tripwire is only ever deleted if it's still Jarvis's own decoy (it carries a private marker), never a file of yours.

## Honest limits

- Tripwires catch people using your Windows account (an unlocked laptop), not other accounts or programs that read
  a file without opening it the normal way.
- "No red flags" isn't a guarantee: if a link wants a password or money, go to the site yourself.
- A flagged program is a reason to look, not proof of malware.
- Malware already running as you can hide from checks that run as you.
