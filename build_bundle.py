#!/usr/bin/env python3
"""Build the Net Watch helper bundle reproducibly, and keep the netwatch-setup bootstrap pins in step with it.

Same inputs give the same bytes on any machine with the same zlib: files sorted by name, flat layout, USTAR format,
mode 0644, uid and gid 0, empty owner names, fixed mtime, gzip header mtime 0 and no file name, level 9.
The tarball holds every helper plus SHA256SUMS (per-file). dist/SHA256SUMS also lists the tarball itself.

Usage:
  build_bundle.py [--src DIR] [--out DIR]   build (default src: the bundle's skills folder, every */*.py)
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

VERSION = "v1.0.0"
NAME = f"netwatch-helpers-{VERSION}.tar.gz"
MTIME = 1792195200  # 2026-10-17T00:00:00Z
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
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


def sources(src):
    pats = [os.path.join(src, "*", "*.py"), os.path.join(src, "*.py")]
    files = sorted({p for pat in pats for p in glob.glob(pat)}, key=os.path.basename)
    names = [os.path.basename(p) for p in files]
    if len(names) != len(set(names)):
        sys.exit("duplicate helper names: " + ", ".join(sorted({n for n in names if names.count(n) > 1})))
    if not files:
        sys.exit("no helpers found under " + src)
    return {os.path.basename(p): open(p, "rb").read() for p in files}


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
    body = "".join(f'    "{n}": "{hashlib.sha256(b).hexdigest()}",\n' for n, b in sorted(files.items()))
    t = re.sub(r'BUNDLE_SHA256 = "[0-9a-f]*"', f'BUNDLE_SHA256 = "{h}"', text, count=1)
    t, k = re.subn(r"FILES = \{\n.*?\}\n", lambda _m: "FILES = {\n" + body + "}\n", t, count=1, flags=re.S)
    if not k or 'BUNDLE_SHA256 = "' not in t or "Bundle SHA-256: `" not in t:
        sys.exit("netwatch-setup lacks the bootstrap pins (BUNDLE_SHA256, FILES, Bundle SHA-256 line)")
    t = re.sub(r"Bundle SHA-256: `[0-9a-f]*`", f"Bundle SHA-256: `{h}`", t, count=1)
    return t


def main():
    src = opt("--src", os.path.join(ROOT, "skills"))
    out = opt("--out", os.path.join(ROOT, "dist"))
    files = sources(src)
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
        if os.path.isfile(SETUP) and src == os.path.join(ROOT, "skills"):
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
    print(f"BUILT {tp} {len(tgz)} bytes sha256 {hashlib.sha256(tgz).hexdigest()} ({len(files)} helpers)")


if __name__ == "__main__":
    main()
