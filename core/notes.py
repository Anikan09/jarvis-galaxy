"""The notes: a folder of Markdown files (it works as an Obsidian vault too), the index Jarvis answers from, and the
3D galaxy the HUD draws. Notes link with [[wikilinks]]; notes that share several rare words get a faint link as well.

Nothing here leaves the PC. The galaxy is served behind the lock (GET /api/graph), never written to a public file.
"""
import hashlib
import math
import os
import re
import threading
import time

from . import config

STOP = set("""a an and are as at be but by for from has have i if in into is it its me my no not of on or our so than that the
their them then there these they this to too us was we were what when where which who why will with you your about after
again all also am any because been before being both can could did do does doing down during each few further had having he
her here hers him his how just more most nor now off once only other out over own same she should some such through under
until up very while would yourself der die das und ist nicht ein eine mit von zu den im""".split())
WIKILINK_RE = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]*)?(?:\|[^\]]+)?\]\]")
WORD_RE = re.compile(r"[a-zA-ZÀ-ÿ0-9][a-zA-ZÀ-ÿ0-9'-]{1,}")
MAX_CHARS = 4000
SHARED_MIN = 3
_lock = threading.Lock()
_cache = {"sig": None, "notes": [], "graph": None}


def tokens(text):
    return [w.lower().strip("'-") for w in WORD_RE.findall(text or "") if w.lower() not in STOP and len(w) > 2]


def _files(folder):
    for root, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for f in sorted(files):
            if f.lower().endswith(".md"):
                yield os.path.join(root, f)


def _signature(folder):
    h = hashlib.sha1()
    for p in _files(folder):
        try:
            h.update(f"{p}|{os.path.getmtime(p)}".encode())
        except OSError:
            pass
    return h.hexdigest()


def _read(folder):
    notes = []
    for p in _files(folder):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        rel = os.path.relpath(p, folder).replace("\\", "/")
        m = re.search(r"^#\s+(.+)$", text, re.M)
        title = (m.group(1).strip() if m else os.path.splitext(os.path.basename(p))[0])[:120]
        group = rel.split("/")[0] if "/" in rel else "notes"
        notes.append({"id": len(notes), "title": title, "path": rel, "group": group, "text": text[:MAX_CHARS],
                      "links": sorted({x.strip() for x in WIKILINK_RE.findall(text)}), "tokens": tokens(text)})
    return notes


def all_notes():
    folder = config.notes_dir()
    os.makedirs(folder, exist_ok=True)
    sig = _signature(folder)
    with _lock:
        if sig != _cache["sig"]:
            _cache.update(sig=sig, notes=_read(folder), graph=None)
        return _cache["notes"]


def version():
    all_notes()
    return _cache["sig"]


# ---------- Ranking (BM25) ----------

def rank(question, k=6):
    """The notes most relevant to a question, best first."""
    notes = all_notes()
    q = set(tokens(question))
    if not notes or not q:
        return []
    n = len(notes)
    df = {t: sum(1 for x in notes if t in x["tokens"]) for t in q}
    avg = sum(len(x["tokens"]) for x in notes) / n or 1
    scored = []
    for x in notes:
        tf = {}
        for t in x["tokens"]:
            if t in q:
                tf[t] = tf.get(t, 0) + 1
        s = 0.0
        for t, f in tf.items():
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            s += idf * f * 2.2 / (f + 1.2 * (0.25 + 0.75 * len(x["tokens"]) / avg))
        s += 2.0 * len(q & set(tokens(x["title"])))                   # a title match counts extra
        if s > 0:
            scored.append((s, x))
    return [x for _, x in sorted(scored, key=lambda p: -p[0])[:k]]


# ---------- The galaxy ----------

def graph():
    """{"nodes": [...], "links": [...], "version"} for the HUD."""
    notes = all_notes()
    with _lock:
        if _cache["graph"] is not None:
            return _cache["graph"]
    by_title = {x["title"].lower(): x["id"] for x in notes}
    by_name = {os.path.splitext(os.path.basename(x["path"]))[0].lower(): x["id"] for x in notes}
    links = {}
    for x in notes:
        for target in x["links"]:
            j = by_title.get(target.lower(), by_name.get(target.lower()))
            if j is not None and j != x["id"]:
                links[tuple(sorted((x["id"], j)))] = "link"
    n = len(notes) or 1
    df = {}
    for x in notes:
        for t in set(x["tokens"]):
            df[t] = df.get(t, 0) + 1
    rare = [{t for t in set(x["tokens"]) if 1 < df[t] <= max(2, n // 6)} for x in notes]
    for i in range(len(notes)):
        for j in range(i + 1, len(notes)):
            if (i, j) not in links and len(rare[i] & rare[j]) >= SHARED_MIN:
                links[(i, j)] = "shared"
    degree = [0] * len(notes)
    for a, b in links:
        degree[a] += 1
        degree[b] += 1
    body = lambda t: re.sub(r"^#.*$", "", t, count=1, flags=re.M).strip()
    result = {"version": _cache["sig"],
              "nodes": [{"id": x["id"], "label": x["title"], "group": x["group"], "degree": degree[x["id"]],
                         "excerpt": body(x["text"])[:600]} for x in notes],
              "links": [{"source": a, "target": b, "kind": k} for (a, b), k in links.items()]}
    with _lock:
        _cache["graph"] = result
    return result


# ---------- "Remember that ..." ----------

def title_for(text):
    words = re.sub(r"[^\w\s'-]", " ", text).split()
    while len(words) > 1 and words[0].lower() in ("that", "the", "a", "an"):
        words = words[1:]                                          # only the leading filler
    words = words[:9]
    while len(words) > 2 and words[-1].lower() in STOP:
        words = words[:-1]                                         # don't end on "is", "the", "because"
    title = " ".join(words).strip()
    return (title[:1].upper() + title[1:])[:70] or "Note"


def remember(text, now=None):
    """Write captures/<Title>.md, linked to the note it relates to most. Returns (note title, related title or None)."""
    folder = os.path.join(config.notes_dir(), "captures")
    os.makedirs(folder, exist_ok=True)
    title = title_for(text)
    safe = re.sub(r'[<>:"/\\|?*]+', "", title).strip(" .") or "Note"
    path = os.path.join(folder, safe + ".md")
    n = 2
    while os.path.exists(path):
        path = os.path.join(folder, f"{safe} {n}.md")
        n += 1
    related = next((x for x in rank(text, 1)), None)
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))
    body = f"# {title}\n\n{text.strip()}\n\n" + (f"Related: [[{related['title']}]]\n\n" if related else "") + f"Captured {stamp}.\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return title, related["title"] if related else None
