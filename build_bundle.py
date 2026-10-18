#!/usr/bin/env python3
"""Build the Net Watch helper bundle reproducibly, and keep the netwatch-setup bootstrap pins in step with it.

Same inputs give the same bytes on any machine with the same zlib: files sorted by name, flat layout, USTAR format,
mode 0644, uid and gid 0, empty owner names, fixed mtime, gzip header mtime 0 and no file name, level 9.
The tarball holds every helper (flat), every guide as docs/NAME.md, and SHA256SUMS (per-file, covered by the bundle hash).
dist/SHA256SUMS also lists the tarball itself.

Usage:
  build_bundle.py [--src DIR] [--docs DIR] [--out DIR]   build (default: helpers/*.py and docs/*.md next to tools/,
                                                        or in this folder's repo layout)
  build_bundle.py --update-skill            build, then rewrite the pins in skills/netwatch-setup/SKILL.md
  build_bundle.py --check                   exit 1 if dist/ or the skill pins differ from a fresh build (writes nothing)
"""
import glob
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile

VERSION = "v1.3.1"
NAME = f"netwatch-helpers-{VERSION}.tar.gz"
MTIME = 1792195200  # 2026-10-17T00:00:00Z
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = HERE if os.path.isdir(os.path.join(HERE, "helpers")) else os.path.dirname(HERE)  # repo layout or bot bundle
SETUP = os.path.join(ROOT, "skills", "netwatch-setup", "SKILL.md")
# Owner-specific markers (names, hostnames, ids) are kept out of this file: one regex per line in private-markers.txt next to
# this script (never committed) and/or NW_PRIVATE_MARKERS="a|b". Any IPv4 literal outside GENERIC_IPS is refused as well.
_MK = [m for m in os.environ.get("NW_PRIVATE_MARKERS", "").split("|") if m]
if os.path.isfile(os.path.join(HERE, "private-markers.txt")):
    _MK += [ln.strip() for ln in open(os.path.join(HERE, "private-markers.txt"), encoding="utf-8") if ln.strip() and not ln.startswith("#")]
PERSONAL = re.compile("|".join(_MK) if _MK else r"(?!x)x", re.I)
GENERIC_IPS = {"0.0.0.0", "10.0.0.0", "100.64.0.0", "172.16.0.0", "172.17.0.0", "192.0.2.1", "192.168.0.0", "239.255.255.250"}


def opt(k, d):
    return sys.argv[sys.argv.index(k) + 1] if k in sys.argv else d


def sources(src, docs):
    files = {os.path.basename(p): open(p, "rb").read() for p in sorted(glob.glob(os.path.join(src, "*.py")))
             if os.path.isfile(p) and "__pycache__" not in p}  # never bundle caches (glob *.py skips folders and .pyc)
    if not files:
        sys.exit("no helpers found under " + src)
    for p in sorted(glob.glob(os.path.join(docs, "*.md"))):
        files["docs/" + os.path.basename(p)] = open(p, "rb").read()
    for n in files:
        if not re.fullmatch(r"(docs/)?[a-z0-9_-]+\.(py|md)", n):
            sys.exit("file name not allowed in the bundle: " + n)
    return files


def privacy(files):
    bad = []
    for n, b in files.items():
        t = b.decode("utf-8")
        if PERSONAL.search(t):
            bad.append(f"{n}: personal marker {PERSONAL.search(t).group(0)!r}")
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t):
            if ip not in GENERIC_IPS:
                bad.append(f"{n}: IP literal {ip}")
    return bad


def build(files):
    sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted(files.items())).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for n, b in sorted(list(files.items()) + [("SHA256SUMS", sums)]):
            ti = tarfile.TarInfo(n)
            ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(b), 0o644, MTIME, 0, 0, "", ""
            tf.addfile(ti, io.BytesIO(b))
    gz = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz, compresslevel=9, mtime=0) as g:
        g.write(raw.getvalue())
    tgz = gz.getvalue()
    return tgz, sums + f"{hashlib.sha256(tgz).hexdigest()}  {NAME}\n".encode()


def pinned_skill(text, files, tgz):
    h = hashlib.sha256(tgz).hexdigest()
    kb = max(1, round(len(tgz) / 1024))
    if 'BUNDLE_SHA256 = "' not in text or "Bundle SHA-256: `" not in text or "(about " not in text:
        sys.exit("netwatch-setup lacks the bootstrap pins (BUNDLE_SHA256, Bundle SHA-256 line, size)")
    t = re.sub(r'BUNDLE_SHA256 = "[0-9a-f]*"', f'BUNDLE_SHA256 = "{h}"', text, count=1)
    t = re.sub(r"Bundle SHA-256: `[0-9a-f]*`", f"Bundle SHA-256: `{h}`", t, count=1)
    t = re.sub(r"releases/download/v[0-9.]+/netwatch-helpers-v[0-9.]+\.tar\.gz", f"releases/download/{VERSION}/{NAME}", t)
    t = re.sub(r"\.tar\.gz \(about [0-9]+ KB\)", f".tar.gz (about {kb} KB)", t, count=1)
    return t


def main():
    src = opt("--src", os.path.join(ROOT, "helpers"))
    docs = opt("--docs", os.path.join(ROOT, "docs"))
    out = opt("--out", os.path.join(ROOT, "dist"))
    files = sources(src, docs)
    m = re.search(rb'^NW_VERSION = "(v[0-9.]+)"', files.get("nw_common.py", b""), re.M)
    if not m or m.group(1).decode() != VERSION:
        sys.exit(f"nw_common.NW_VERSION must equal {VERSION} (the installed version the release checker compares)")
    bad = privacy(files)
    if bad:
        sys.exit("refusing to bundle personal data:\n" + "\n".join(bad))
    tgz, sums = build(files)
    tp, sp = os.path.join(out, NAME), os.path.join(out, "SHA256SUMS")
    if "--check" in sys.argv:
        stale = []
        if not os.path.isfile(tp) or open(tp, "rb").read() != tgz:
            stale.append(tp)
        if not os.path.isfile(sp) or open(sp, "rb").read() != sums:
            stale.append(sp)
        if os.path.isfile(SETUP) and src == os.path.join(ROOT, "helpers") and docs == os.path.join(ROOT, "docs"):
            t = open(SETUP, encoding="utf-8").read()
            if pinned_skill(t, files, tgz) != t:
                stale.append("netwatch-setup pins")
        print("STALE " + " ".join(stale) if stale else "CURRENT " + hashlib.sha256(tgz).hexdigest())
        sys.exit(1 if stale else 0)
    os.makedirs(out, exist_ok=True)
    open(tp, "wb").write(tgz)
    open(sp, "wb").write(sums)
    if "--update-skill" in sys.argv:
        t = open(SETUP, encoding="utf-8").read()
        open(SETUP, "w", encoding="utf-8").write(pinned_skill(t, files, tgz))
    print(f"BUILT {tp} {len(tgz)} bytes sha256 {hashlib.sha256(tgz).hexdigest()} ({sum(n.endswith('.py') for n in files)} helpers, {sum(n.endswith('.md') for n in files)} guides)")


if __name__ == "__main__":
    main()
