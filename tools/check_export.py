#!/usr/bin/env python3
"""Check the helper bootstrap inside an exported Net Watch template. Stdlib only.

  check_export.py EXPORT_FILE [--bundle TARBALL] [--expect-sha256 HEX] [--skill SKILL.md] [--run]

EXPORT_FILE is template text as exported or copied (Markdown, plain text, or JSON that holds the
skill text as strings). The tool finds the `cat > /workspace/nw_bootstrap.py <<'PY' ... PY` block,
prints its pinned URL, pinned bundle SHA-256, and the SHA-256 of the script itself, then:
  --bundle TARBALL      the pinned SHA-256 must equal the tarball's SHA-256
  --expect-sha256 HEX   the pinned SHA-256 must equal HEX (for example from the release notes)
  --skill SKILL.md      the exported script must be byte-identical to the one in that skill source
  --run                 with --bundle: run the extracted script with --file TARBALL into a temp folder
                        and require "BOOTSTRAP OK" (nothing outside the temp folder is written)
Exit 0 when every requested check passes, 1 when one fails, 2 when no bootstrap block is found.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

BLOCK = re.compile(r"cat > /workspace/nw_bootstrap\.py <<'PY'\n(.*?\n)PY\n", re.S)


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)


def extract(text):
    """Return the bootstrap script text, or None. Accepts raw text or JSON exports."""
    text = text.replace("\r\n", "\n")
    m = BLOCK.search(text)
    if m:
        return m.group(1)
    try:
        data = json.loads(text)
    except ValueError:
        return None
    for s in strings(data):
        m = BLOCK.search(s.replace("\r\n", "\n"))
        if m:
            return m.group(1)
    return None


def pins(script):
    u = re.search(r'^URL = "([^"]+)"', script, re.M)
    h = re.search(r'^BUNDLE_SHA256 = "([0-9a-f]{64})"', script, re.M)
    return (u.group(1) if u else ""), (h.group(1) if h else "")


def sha_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__.strip())
        return 2
    def opt(k):
        return argv[argv.index(k) + 1] if k in argv[:-1] else None
    src = argv[0]
    with open(src, encoding="utf-8", errors="replace") as f:
        script = extract(f.read())
    if script is None:
        print(f"EXPORT NO-BOOTSTRAP: no bootstrap block found in {os.path.basename(src)}")
        return 2
    url, pin = pins(script)
    ver = re.search(r"/download/(v[0-9.]+)/netwatch-helpers-(v[0-9.]+)\.tar\.gz$", url)
    print(f"export url={url or '-'}")
    print(f"export bundle_sha256={pin or '-'}")
    print(f"export script_sha256={hashlib.sha256(script.encode('utf-8')).hexdigest()}")
    fails = []
    if not url or not pin:
        fails.append("URL or BUNDLE_SHA256 pin missing")
    if not ver or ver.group(1) != ver.group(2):
        fails.append("URL tag and file name versions differ")
    bundle = opt("--bundle")
    if bundle:
        got = sha_file(bundle)
        print(f"bundle {os.path.basename(bundle)} sha256={got}")
        if got != pin:
            fails.append("pinned SHA-256 does not match the bundle")
    exp = opt("--expect-sha256")
    if exp and exp.lower() != pin:
        fails.append("pinned SHA-256 does not match --expect-sha256")
    skill = opt("--skill")
    if skill:
        with open(skill, encoding="utf-8") as f:
            ref = extract(f.read())
        if ref != script:
            fails.append("exported script differs from the skill source")
    if "--run" in argv:
        if not bundle:
            fails.append("--run needs --bundle")
        else:
            with tempfile.TemporaryDirectory() as td:
                sp = os.path.join(td, "nw_bootstrap.py")
                with open(sp, "w", encoding="utf-8") as f:
                    f.write(script)
                r = subprocess.run([sys.executable, sp, "--file", bundle, "--out", os.path.join(td, "out")],
                                   capture_output=True, text=True, timeout=120)
                line = (r.stdout + r.stderr).strip().splitlines()
                print("run " + (line[-1] if line else "(no output)"))
                if r.returncode != 0 or "BOOTSTRAP OK" not in r.stdout:
                    fails.append("extracted bootstrap did not print BOOTSTRAP OK")
    for f_ in fails:
        print(f"FAIL {f_}")
    print("EXPORT OK" if not fails else f"EXPORT FAIL count={len(fails)}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
