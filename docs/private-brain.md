# The private brain

A local AI model, running on your own PC through [Ollama](https://ollama.com), for questions that should never leave it.

- **"Private mode on"**: every answer comes from the local model until you say "private mode off". Anything that needs
  the internet brain (web research, for now) is **declined**, never quietly sent. A green PRIVATE tag shows in the HUD.
- **"Answer this offline: …"**: one question to the local model; everything else stays as it was.
- **Fallback**: if Claude can't be reached, simple questions go to the local model, and the answer says so
  (`private_brain.fallback` in `config.json`).

Local models are much weaker than Claude: think of it as a private fallback, not a replacement.

## Setup

1. Install Ollama from **ollama.com** (only from there).
2. Pull a model. `qwen2.5:7b` (about 4.7 GB) handles English and German well and fits an 8 GB graphics card:
   ```powershell
   ollama pull qwen2.5:7b
   ```
   Smaller cards or none: try `qwen2.5:3b`. Set `private_brain.model` in `config.json` to match.
3. Say "private mode on".

## Keep it private

- Ollama listens on `127.0.0.1` by default. **Never set `OLLAMA_HOST=0.0.0.0`**: that opens it to your whole network,
  with no password.
- Jarvis refuses to talk to an Ollama that isn't on this PC, whatever `config.json` says.
