"""The one gateway to the brain. Every call goes through call(), which applies:

- private mode (or "answer this offline: ..."): the local model answers; anything that needs tools is declined, never sent;
- expert and lab mode: their rule is added to the system prompt;
- the fallback: if Claude can't be reached, a tool-free question goes to the local model when it's ready.

The brain is the Claude Code CLI on the user's own Claude account (claude -p). The prompt goes in on stdin, never on
the command line; the CLI runs in a neutral folder with no tools unless a call asks for some, no MCP servers, no
user settings or hooks, and no saved session. API keys in the environment are dropped, so the CLI uses the
logged-in subscription.
"""
import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading

from . import config, localbrain, modes

TIMEOUT = 180
SLOTS = threading.BoundedSemaphore(2)
CLI_CWD = os.path.join(tempfile.gettempdir(), "jarvis-galaxy-brain")
_local = threading.local()

ONCE_PATTERN = r"""^\s*(?:(?:please|jarvis)[\s,]+)?(?:answer\s+(?:this\s+)?(?:offline|privately|locally)|ask\s+(?:the\s+)?(?:local|private|offline)\s+(?:brain|model))[\s:,]+(.+)$"""
ONCE_RE = re.compile(ONCE_PATTERN, re.I)


class BrainError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def persona():
    c = config.load()
    name, title, lang = c["assistant_name"], c["address_user_as"], c["language"]
    return f"""You are {name}, the user's personal butler: dry, impeccably polite and British, with a light wit. Your replies are spoken aloud as well as shown on screen.
- Address the user as "{title}" at most once per reply, and not in every reply.
- Plain text only: no markdown, lists or emoji. Short sentences.
- Reply in {lang}, unless the user clearly writes in another language.
- Never invent facts about the user. If you don't know, say so with good grace."""


@contextlib.contextmanager
def offline():
    """Inside this block, this thread's calls go to the local model (for "answer this offline: ...")."""
    _local.forced = True
    try:
        yield
    finally:
        _local.forced = False


def local_wanted():
    return modes.private() or getattr(_local, "forced", False)


def call(prompt, system="", tools="", timeout=TIMEOUT):
    full = (system or persona()) + modes.rule()
    if local_wanted():
        if tools:
            raise BrainError(409, "Private mode is on, and that needs the internet brain. Say private mode off, and ask again.")
        try:
            return localbrain.ask(prompt, full, timeout)
        except localbrain.LocalError as e:
            raise BrainError(503, str(e))
    try:
        return _cli(prompt, full, tools, timeout)
    except BrainError as e:
        if e.status not in (502, 504) or tools or not localbrain.fallback_enabled() or not localbrain.status()["model_ready"]:
            raise
        try:
            return localbrain.ask(prompt, full, timeout)
        except localbrain.LocalError:
            raise e


def _cli(prompt, system, tools, timeout):
    exe = shutil.which("claude")
    if not exe:
        raise BrainError(503, "The claude command wasn't found: install Claude Code and log in (see docs/setup.md).")
    cmd = [exe, "-p", "--system-prompt", system, "--tools", tools, *(["--allowedTools", tools] if tools else []),
           "--strict-mcp-config", "--setting-sources", "", "--no-session-persistence", "--output-format", "json"]
    if config.get("model"):
        cmd += ["--model", str(config.get("model"))]
    env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
    os.makedirs(CLI_CWD, exist_ok=True)
    if not SLOTS.acquire(timeout=timeout):
        raise BrainError(503, "Still busy with earlier questions; try again in a moment.")
    try:
        proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=CLI_CWD,
                              env=env, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise BrainError(504, f"The brain took longer than {timeout} seconds.")
    finally:
        SLOTS.release()
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        data = {}
    text = str(data.get("result") or "").strip()
    if proc.returncode != 0 or data.get("is_error") or not text:
        detail = text or (proc.stderr.strip().splitlines() or ["no output"])[-1]
        if re.search(r"log ?in|logged|auth", detail, re.I):
            detail += " (run claude in a terminal and use /login)"
        raise BrainError(502, f"Claude Code error: {detail[:300]}")
    return text


def used_local():
    return localbrain.consume_used()
