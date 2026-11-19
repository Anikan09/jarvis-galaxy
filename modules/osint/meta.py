"""What a photo or PDF gives away if you share it: GPS, camera serial numbers, author names, software, user folders,
saved revisions, comments and attachments. Reads the file on this PC; uploads and changes nothing.
PDFs need nothing extra. Photos need Pillow (pip install pillow)."""
import io
import os
import re
import zlib

import modules
from modules.security.common import clean, finding, report, row

MAX_BYTES = 60 * 1024 * 1024
IMAGES = (".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic", ".gif", ".bmp")
USER_PATH_RE = re.compile(r"(?:[A-Za-z]:\\Users\\|/Users/|/home/)([^\\/\s]+)", re.I)
EXIF_TAGS = ((0x013B, "Artist", "medium"), (0xA430, "Camera owner", "medium"), (0xA431, "Camera serial number", "medium"),
             (0xA435, "Lens serial number", "medium"), (0x013C, "Host computer", "medium"), (0x9C9D, "Author (Windows)", "medium"),
             (0x8298, "Copyright", "low"), (0x010E, "Description", "low"), (0x9286, "User comment", "low"), (0x010F, "Camera make", ""),
             (0x0110, "Camera model", ""), (0x0131, "Software", ""), (0x9003, "Taken", "low"))
SUB_IFD = {0xA430, 0xA431, 0xA435, 0x9286, 0x9003}
PDF_KEYS = (("Author", "medium"), ("Creator", ""), ("Producer", ""), ("CreationDate", "low"), ("ModDate", "low"), ("Title", "low"),
            ("Subject", "low"), ("Keywords", "low"), ("Company", "medium"), ("LastModifiedBy", "medium"))


def _num(x):
    try:
        if isinstance(x, tuple) and len(x) == 2:
            return x[0] / x[1] if x[1] else None
        return float(x)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _dms(v, ref):
    parts = [_num(p) for p in (v if hasattr(v, "__len__") else (v,))][:3]
    if not parts or parts[0] is None:
        return None
    d, m, s = (parts + [0.0, 0.0])[:3]
    val = parts[0] + (m or 0) / 60 + (s or 0) / 3600
    return -val if str(ref or "").upper()[:1] in ("S", "W") else val


def _text(v):
    if isinstance(v, bytes):
        v = v[8:].decode("utf-16-le" if v[:7] == b"UNICODE" else "ascii", "replace") if v[:8] in (b"ASCII\0\0\0", b"UNICODE\0") else \
            (v.decode("utf-16-le", "replace") if len(v) % 2 == 0 and b"\0" in v else v.decode("utf-8", "replace"))
    return clean(str(v).strip("\0 "), 200)


def _user_folders(rows):
    names = {m.group(1) for r in rows for m in USER_PATH_RE.finditer(r["v"])}
    return [row("User folder in a path", ", ".join(sorted(names)), "high")] if names else []


def image_rows(data):
    try:
        from PIL import ExifTags, Image
    except ImportError:
        raise modules.ModuleError("Reading photos needs Pillow: pip install pillow")
    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        raise modules.ModuleError("I couldn't open that as an image.")
    exif = img.getexif()
    sub = exif.get_ifd(ExifTags.IFD.Exif) if exif else {}
    gps = exif.get_ifd(ExifTags.IFD.GPSInfo) if exif else {}
    rows = []
    lat, lon = (_dms(gps.get(2), gps.get(1)), _dms(gps.get(4), gps.get(3))) if gps else (None, None)
    if lat is not None and lon is not None and (abs(lat) > 1e-6 or abs(lon) > 1e-6):
        rows.append(row("GPS position", f"{lat:.6f}, {lon:.6f} (https://www.google.com/maps?q={lat:.6f},{lon:.6f})", "high"))
    for tag, label, risk in EXIF_TAGS:
        v = (sub if tag in SUB_IFD else exif).get(tag) if exif else None
        if v not in (None, "", b"") and _text(v):
            rows.append(row(label, _text(v), risk))
    try:
        thumb = exif.get_ifd(ExifTags.IFD.IFD1) if exif else {}
    except (AttributeError, KeyError):
        thumb = {}
    if thumb:
        rows.append(row("Embedded thumbnail", "a small preview that can still show the original if the photo was cropped", "medium"))
    for key, value in (img.info or {}).items():
        if isinstance(key, str) and key.lower() in ("author", "comment", "parameters", "prompt", "workflow", "software"):
            rows.append(row(f"{key} (embedded text)", clean(value if isinstance(value, str) else value.decode("utf-8", "replace"), 200),
                            "medium" if key.lower() != "software" else ""))
    return [row("Format", f"{img.format} · {img.width}×{img.height}"), row("EXIF", "present" if exif else "none")], rows


def _pdf_literal(buf, i):
    out, depth = bytearray(), 1
    esc = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b", ord("f"): b"\f"}
    while i < len(buf) and depth:
        c = buf[i]
        if c == 0x5C and i + 1 < len(buf):
            n = buf[i + 1]
            if n in esc:
                out += esc[n]
                i += 2
            elif 0x30 <= n <= 0x37:
                m = re.match(rb"[0-7]{1,3}", buf[i + 1:i + 4])
                out.append(int(m.group(0), 8) & 0xFF)
                i += 1 + len(m.group(0))
            else:
                out.append(n)
                i += 2
            continue
        depth += c == 0x28
        depth -= c == 0x29
        if depth:
            out.append(c)
        i += 1
    return bytes(out)


def _pdf_info(chunk):
    found = {}
    for key, _ in PDF_KEYS:
        m = re.search(rb"/" + key.encode() + rb"\s*(\(|<(?!<))", chunk)
        if not m:
            continue
        if m.group(1) == b"(":
            raw = _pdf_literal(chunk, m.end())
        else:
            hexed = re.sub(rb"\s+", b"", chunk[m.end():chunk.find(b">", m.end())])
            try:
                raw = bytes.fromhex(hexed.decode("ascii") + ("0" if len(hexed) % 2 else ""))
            except ValueError:
                continue
        text = raw.decode("utf-16", "replace") if raw[:2] in (b"\xfe\xff", b"\xff\xfe") else raw.decode("latin-1")
        if clean(text):
            found[key] = clean(text, 200)
    return found


def _pdf_date(s):
    m = re.match(r"D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?", s.strip())
    return f"{m.group(1)}-{m.group(2) or '01'}-{m.group(3) or '01'}" + (f" {m.group(4)}:{m.group(5) or '00'}" if m.group(4) else "") if m else s


def pdf_rows(data):
    if not data.startswith(b"%PDF"):
        raise modules.ModuleError("That doesn't look like a PDF inside.")
    info = _pdf_info(data)
    if not info.get("Author"):                                   # PDF 1.5+ hides the info in compressed object streams
        for n, m in enumerate(re.finditer(rb"stream\r?\n", data)):
            if n > 400:
                break
            end = data.find(b"endstream", m.end())
            if end > 0 and b"/FlateDecode" in data[max(0, m.start() - 400):m.start()]:
                try:
                    for k, v in _pdf_info(zlib.decompressobj().decompress(data[m.end():end], 4_000_000)).items():
                        info.setdefault(k, v)
                except zlib.error:
                    pass
    rows = [row({"CreationDate": "Created", "ModDate": "Modified", "Creator": "Made with"}.get(k, k), _pdf_date(info[k]) if k.endswith("Date") else info[k], r)
            for k, r in PDF_KEYS if info.get(k)]
    if data.count(b"%%EOF") > 1:
        rows.append(row("Saved revisions", f"{data.count(b'%%EOF')} versions in one file: deleted text may still be recoverable", "medium"))
    if b"/EmbeddedFile" in data:
        rows.append(row("Attachments", "files are embedded inside this PDF", "medium"))
    if re.search(rb"/Subtype\s*/(?:Text|FreeText|Popup)\b", data):
        rows.append(row("Comments", "it carries review comments or sticky notes", "medium"))
    return [row("Format", "PDF " + data[5:8].decode("ascii", "replace"))], rows


def check(path):
    path = os.path.abspath(os.path.expandvars(os.path.expanduser(str(path).strip().strip("\"'"))))
    if not os.path.isfile(path):
        raise modules.ModuleError(f"I can't find a file at {path}.")
    if not path.lower().endswith(IMAGES + (".pdf",)):
        raise modules.ModuleError("I check photos and PDFs.")
    if os.path.getsize(path) > MAX_BYTES:
        raise modules.ModuleError("That file is over 60 MB.")
    with open(path, "rb") as f:
        data = f.read()
    about, rows = pdf_rows(data) if path.lower().endswith(".pdf") else image_rows(data)
    rows += _user_folders(rows)
    rows.sort(key=lambda r: {"high": 0, "medium": 1, "low": 2}.get(r["risk"], 3))
    f = [finding(r["risk"], f"{r['k']}: {r['v']}") for r in rows if r["risk"] in ("high", "medium")]
    name = os.path.basename(path)
    sections = [{"title": "File", "rows": [row("File", name)] + about},
                {"title": "Metadata", "rows": rows or [row("Result", "nothing here identifies you, a place or a device")]}]
    if f:
        sections.append({"title": "Before you share", "rows": [row("Tip", "Re-export a copy without metadata: for photos, Properties → Details → "
                                                                          "Remove Properties; for PDFs, Print to PDF or your editor's Sanitize option.")]})
    labels = [x["text"].split(":", 1)[0].lower() for x in f]
    answer = ("That file looks clean: nothing in its metadata names you, a place or a device." if not f else
              "Before you share that, it gives away its " + (labels[0] if len(labels) == 1 else ", ".join(labels[:-1][:3]) + " and " + labels[-1]) + ".")
    return report("metadata", "Metadata check", name, "safe to share" if not f else "reveals details", sections, f, answer, badge="LOCAL ONLY")
