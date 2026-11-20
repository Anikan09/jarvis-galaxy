# How I built my own Jarvis

I've always wanted my own Jarvis: a butler that knows my notes, answers when I talk to it, and keeps an eye on my PC. Someone I can ask questions, who helps me with coding, and who makes my day-to-day life a little easier. So I built one, together with Claude Code. This is the story of how, and the mistakes worth knowing about if you build your own.

## The idea

I didn't want another chatbot in a browser tab. I wanted three things:

1. **It knows my stuff.** My notes, not the whole internet's opinion.
2. **I can see what it knows.** Not a list of files, but a galaxy: every note a star, every link between notes a line of light. When it answers, the notes it used light up and the camera flies to them.
3. **It's locked down like a vault.** An assistant that reads your notes is worth breaking into, so security came first, not last.

Some of the feature ideas, like the galaxy, the voice and flying to a source, came from [zubair-trabzada](https://github.com/zubair-trabzada)'s Claude projects and his community, [AI Workshop](https://www.skool.com/aiworkshop-lite). The code is my own, written from scratch.

## How it works

It's deliberately simple:

- **A small Python server** on my own PC, using only Python's standard library: no frameworks, nothing to install for the core. It listens on `127.0.0.1` only, so nothing on my network can reach it.
- **A web page as the HUD.** Plain HTML, CSS and JavaScript, no build step. The galaxy is [3d-force-graph](https://github.com/vasturiano/3d-force-graph) on top of [three.js](https://threejs.org).
- **Claude Code as the brain.** Jarvis runs the Claude Code CLI on my own Claude account. I don't need an API key, and nothing is shared or proxied. The CLI runs with no tools unless a feature needs one, so the brain can't touch my files.
- **The browser's own voice.** Speech out and speech in come from Chrome or Edge, so there's no extra service.
- **A private brain for when I want it.** With Ollama running a local model, "private mode" keeps every question on the PC.

I'm really interested in cybersecurity, and that's why so much of Jarvis is about security. So on top of that sit optional modules: a security toolkit (a security score, Wi-Fi and network checks, phishing and leaked-password checks, decoy "tripwire" files that tell me when someone snoops), OSINT lookups for domains and IPs, a read-only morning briefing from Gmail and my calendars, and content-free alerts to my phone.

## Locking it down

This was the part I cared about most, and the part I'd tell anyone building something similar to take seriously:

- **Password + authenticator app** before anything loads, even the page itself. Five wrong tries and the door shuts, for longer each time.
- **Everything stored is encrypted** with my Windows login (DPAPI). Copy the folder to another PC and it's just noise.
- **No secrets on the command line, ever.** Setup asks for the password in a hidden prompt, in my own terminal.
- **Host and Origin checks**, so a malicious website can't talk to the server through the browser (DNS rebinding).
- **A strict Content-Security-Policy**, and the 3D libraries load with pinned hashes, so a tampered file gets refused.
- **Honest limits.** If malware is already running as me, it can read what I can. The docs say so plainly.

## Making it public

My own Jarvis has my notes, my settings and my history in it, so I couldn't just push it to GitHub. Instead I wrote **Jarvis Galaxy** as a separate project, from scratch, feature by feature. Nothing was copied over from my personal one.

It comes with a **demo mode**: a made-up coffee roaster, "Ember & Oak", with fictional notes, devices and emails, so anyone can look around before connecting anything real. Every screenshot and the GIF in the README come from that demo.

Before publishing I went through a checklist: a secret scanner over the whole git history, a scan for personal data in every commit, commits only from GitHub's no-reply address, and a fresh clone set up from zero as if I were a stranger.

## What went wrong (the useful part)

- **The setup test found two real bugs in ten minutes.** My authenticator app refused the setup key with "illegal character", because I showed it in groups of four with spaces. And the voice spoke English with a German accent: my Windows is set to German, and the browser picked a German voice before its English ones had loaded. **Lesson: install your own project from scratch, like a stranger would, before anyone else does.**
- **"Female" contains "male".** The code meant to pick a male voice happily picked a female one. Tiny bug, very funny once you see it.
- **A test that couldn't fail.** One of my privacy tests is supposed to catch personal email addresses in the repo. An edit made through the shell had turned a `\b` in its pattern into an invisible backspace character, so the test could never match anything, and it passed for days without really checking. **Lesson: test your tests.** Now the test proves its own pattern works before it scans, and another test fails if any file contains an invisible control character.
- **Demo mode wrote into the real demo files.** Saying "remember that…" in the demo created a note inside the repo's own demo folder. Now the demo works on a copy.
- **Old plans lie.** My design document still described features I'd planned and never built. A last review before publishing caught it. Read your own docs the way a newcomer would.

## What's next

Ideas for later versions: a wake word, encrypted backups, a read-only phone dashboard (if I can make it safe enough), and maybe Mac and Linux support.

## Build your own

Everything is in this repo, MIT-licensed. Start with the [setup guide](setup.md), try `python -m core.server --demo` first, and read the [FAQ](FAQ.md) for how to make it yours: the colours, the name, the voice, even the personality. If you build something cool with it, I'd love to see it.
