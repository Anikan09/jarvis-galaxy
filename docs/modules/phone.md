# Phone module

Getting Jarvis onto your phone can mean anything from a buzz to full control of your PC. The further you go, the more you open up, so this module only builds the safe end.

| Level | What you get | Risk | Status |
|---|---|---|---|
| **1. Alerts only** | Security alerts, tripwires and notices pushed to your phone. The message never says *what* happened: "Jarvis: 1 security alert. Open Jarvis to see it." | **Low.** Jarvis stays unreachable from outside; the push service only learns that something happened. | **Built** |
| **2. Read-only dashboard** | Score, alerts, devices and calendar from anywhere, over Tailscale, with a passkey login. Nothing can be changed from the phone. | **Medium**: see below. | Planned |
| **3. Full control** | Chat, approvals and desktop control from the phone. | **High**: everything below, plus whoever holds your unlocked phone mid-session holds your PC. | **Not built, on purpose** |

## Level 1: set it up

1. Install the **ntfy** app (Android or iOS; it's open source).
2. In `config.json`: `"modules": { "phone": true }`. To use your own ntfy server instead of ntfy.sh: `"phone": { "ntfy_server": "https://ntfy.example.com" }` (https only).
3. `python -m modules.phone setup` makes a long random topic, stores it encrypted, shows it to you, and sends a test.
4. Subscribe to that topic in the app. **Treat the topic like a password**: on a public ntfy server, anyone who knows it can read the pushes (which, by design, say nothing anyway).

The phone buzzes at most every 5 minutes; anything in between is counted into the next push.

## The risks of levels 2 and 3

1. **Jarvis stops being local-only.** Today it accepts connections from its own PC only. Remote access makes every bug in its login reachable from your private network.
2. **Your Tailscale account becomes a key.** Whoever takes over the account you sign into Tailscale with can add a device. Mitigations: device approval, two-factor on that account, Tailscale's "tailnet lock".
3. **Both login factors on one device.** The authenticator codes live on the phone; if its browser also remembers the password, a stolen unlocked phone has both. A passkey or hardware key fixes that properly.
4. **The encrypted drive stays open.** If Jarvis lives on an encrypted drive, it has to stay mounted while you're away, which removes much of the protection against a stolen laptop.
5. **Certificates publish your machine's name.** Browsers need https for the microphone; Tailscale's certificates put the machine's tailnet name into public certificate-transparency logs.
6. **Level 3 only:** a stolen unlocked phone mid-session could read your mail and drive your PC.
